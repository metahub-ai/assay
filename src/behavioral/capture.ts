/**
 * Runtime capture orchestration — starts and collects the ground-truth
 * recorders (`tcpdump` for network, `strace` for syscalls) inside the
 * sandbox around a behavioral run.
 *
 * Everything here is BEST-EFFORT and degrades honestly. A sandbox
 * without tcpdump, without root, or without ptrace still runs the eval
 * exactly as before — the ledger just reports `captured.network=false`
 * with a note saying why. Capture must never be the reason an eval
 * fails: the run is the product, the ledger is evidence about it.
 *
 * Privilege model, per adapter:
 *   - podman/docker: commands exec as in-container root → tcpdump and
 *     package install work directly.
 *   - E2B: the default user is unprivileged but has passwordless sudo,
 *     so root-needing steps are retried with `sudo` when the plain
 *     attempt fails.
 *
 * strace needs no privileges at all (ptrace of own children), which is
 * why syscall capture usually survives even when network capture
 * doesn't.
 */
import type { Sandbox } from "../ports.js";
import { buildLedger, type RawCapture, type RuntimeLedger } from "./ledger.js";

/** In-sandbox scratch dir for capture artifacts. */
const CAP_DIR = "/tmp/.assay-cap";

/** Refuse to pull captures bigger than this back out of the sandbox. */
const MAX_PCAP_BYTES = 8 * 1024 * 1024;

export interface CaptureHandle {
  /** Network capture (tcpdump) is running. */
  network: boolean;
  /** strace is available; `wrap()` will instrument commands. */
  syscalls: boolean;
  notes: string[];
  /**
   * Wrap an artifact-executing shell command with strace so its whole
   * process tree is recorded. Identity function when strace is
   * unavailable — callers wrap unconditionally.
   */
  wrap(cmd: string): string;
}

const STRACE_EVENTS =
  "connect,openat,open,creat,unlink,unlinkat,rename,renameat2,execve,clone,fork,vfork";

function shellSingleQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Probe for a tool; when absent, try to install it (plain, then sudo).
 * Debian-based images only — that covers node:20 (podman default) and
 * the E2B code-interpreter base. Failure is a note, not an error.
 */
async function ensureTool(sandbox: Sandbox, tool: string, notes: string[]): Promise<boolean> {
  const probe = await sandbox.exec(`command -v ${tool} >/dev/null 2>&1 && echo yes || echo no`, {
    timeoutMs: 15_000,
  });
  if (probe.stdout.includes("yes")) return true;
  const install = `sh -c 'apt-get install -y -qq ${tool} >/dev/null 2>&1 || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq ${tool} >/dev/null 2>&1)'`;
  const plain = await sandbox.exec(install, { timeoutMs: 120_000 });
  if (plain.exitCode !== 0) {
    await sandbox.exec(`sudo ${install}`, { timeoutMs: 120_000 }).catch(() => undefined);
  }
  const recheck = await sandbox.exec(`command -v ${tool} >/dev/null 2>&1 && echo yes || echo no`, {
    timeoutMs: 15_000,
  });
  const ok = recheck.stdout.includes("yes");
  if (!ok) notes.push(`${tool}: not present and could not be installed — capture degraded`);
  return ok;
}

/**
 * Start capture. Call after the sandbox exists, BEFORE the harness runs
 * anything of the artifact's. Returns a handle the harnesses use to
 * wrap artifact-executing commands.
 */
export async function startCapture(sandbox: Sandbox): Promise<CaptureHandle> {
  const notes: string[] = [];
  let network = false;
  let syscalls = false;

  try {
    await sandbox.exec(`mkdir -p ${CAP_DIR}`, { timeoutMs: 15_000 });

    // Install BOTH recorders before starting either, so capture never
    // records its own tool-install traffic. In production the sandbox
    // template ships them pre-baked and these are instant no-ops; the
    // apt-get path only fires on a bare local image.
    const hasTcpdump = await ensureTool(sandbox, "tcpdump", notes);
    syscalls = await ensureTool(sandbox, "strace", notes);

    if (hasTcpdump) {
      // Root check decides whether sudo is needed to open the capture
      // socket. `-U` flushes per-packet so a kill loses nothing.
      const id = await sandbox.exec(`id -u`, { timeoutMs: 15_000 });
      const asRoot = id.stdout.trim() === "0";
      const tcpdumpCmd = `nohup tcpdump -i any -U -w ${CAP_DIR}/net.pcap >/dev/null 2>&1 & echo $!`;
      const start = await sandbox.exec(
        asRoot
          ? `sh -c ${shellSingleQuote(tcpdumpCmd)}`
          : `sudo sh -c ${shellSingleQuote(tcpdumpCmd)}`,
        { timeoutMs: 20_000 },
      );
      if (start.exitCode === 0 && start.stdout.trim().length > 0) {
        // Give tcpdump a beat to open the interface, then confirm the
        // process survived (a capture-permission failure exits fast).
        const alive = await sandbox.exec(
          `sleep 1; pgrep -x tcpdump >/dev/null 2>&1 && echo alive || echo dead`,
          { timeoutMs: 15_000 },
        );
        network = alive.stdout.includes("alive");
        if (!network) notes.push("tcpdump: started but exited — no capture permission?");
      } else {
        notes.push(`tcpdump: failed to start (exit ${start.exitCode})`);
      }
    }
  } catch (err) {
    notes.push(`capture setup failed: ${(err as Error).message}`);
  }

  let straceN = 0;
  return {
    network,
    syscalls,
    notes,
    wrap(cmd: string): string {
      if (!syscalls) return cmd;
      const log = `${CAP_DIR}/strace.${++straceN}.log`;
      return (
        `strace -f -qq -yy -s 256 -e trace=${STRACE_EVENTS} -o ${log} ` +
        `sh -c ${shellSingleQuote(cmd)}`
      );
    },
  };
}

/**
 * Stop the recorders and pull everything captured back to the host,
 * assembled into the normalized ledger.
 */
export async function collectCapture(
  sandbox: Sandbox,
  handle: CaptureHandle,
  workspace: string,
): Promise<RuntimeLedger> {
  const notes = [...handle.notes];
  const raw: RawCapture = {
    networkCaptured: false,
    syscallsCaptured: handle.syscalls,
    notes,
    straceLogs: [],
  };

  try {
    if (handle.network) {
      // SIGTERM lets tcpdump flush its buffer; -U made that mostly moot.
      await sandbox.exec(
        `sh -c 'pkill tcpdump 2>/dev/null; sudo pkill tcpdump 2>/dev/null; sleep 1; true'`,
        {
          timeoutMs: 20_000,
        },
      );
      const size = await sandbox.exec(`sh -c 'wc -c < ${CAP_DIR}/net.pcap 2>/dev/null || echo 0'`, {
        timeoutMs: 15_000,
      });
      const bytes = Number(size.stdout.trim()) || 0;
      if (bytes > 0 && bytes <= MAX_PCAP_BYTES) {
        // base64 through exec because `readFile` is text-typed and
        // would mangle binary. tr strips wrapping newlines portably.
        const b64 = await sandbox.exec(`sh -c 'base64 ${CAP_DIR}/net.pcap | tr -d "\\n"'`, {
          timeoutMs: 60_000,
        });
        if (b64.exitCode === 0 && b64.stdout.trim()) {
          raw.pcap = Uint8Array.from(Buffer.from(b64.stdout.trim(), "base64"));
          raw.networkCaptured = true;
        } else {
          notes.push("pcap: could not read capture back from the sandbox");
        }
      } else if (bytes > MAX_PCAP_BYTES) {
        notes.push(`pcap: capture too large to retrieve (${bytes} bytes > ${MAX_PCAP_BYTES})`);
      } else {
        notes.push("pcap: capture file empty or missing");
      }
    }

    if (handle.syscalls) {
      const list = await sandbox.exec(`sh -c 'ls ${CAP_DIR}/strace.*.log 2>/dev/null || true'`, {
        timeoutMs: 15_000,
      });
      const files = list.stdout
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      for (const f of files.slice(0, 50)) {
        const contents = await sandbox.readFile(f);
        if (contents) raw.straceLogs!.push(contents);
      }
      if (files.length === 0) {
        notes.push("strace: no logs found — no artifact command was wrapped");
      }
    }
  } catch (err) {
    notes.push(`capture collection failed: ${(err as Error).message}`);
  }

  return buildLedger(raw, workspace);
}
