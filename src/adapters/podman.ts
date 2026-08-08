/**
 * Podman sandbox adapter — a REAL local sandbox, self-registering, the
 * default when `EVAL_SANDBOX` is "podman" (the registry default).
 *
 * It shells out to the `podman` CLI via `node:child_process` (no new
 * dependency). `create()` starts a long-lived detached container that
 * sleeps forever; every operation maps to a `podman` subcommand:
 *
 *   - writeFiles → `podman cp` from a host tmp file
 *   - exec       → `podman exec [-w cwd] <id> sh -lc <cmd>`
 *   - readFile   → `podman exec <id> cat <path>` (null on miss)
 *   - close      → `podman rm -f <id>`
 *
 * This is excluded from unit-test coverage (it requires a live podman
 * binary + image), but it's the LOCAL demo path — no credentials, no
 * cloud. The vendor-agnostic engine never imports this file directly;
 * it self-registers on import and the worker imports it by default.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExecResult, Sandbox, SandboxProvider, SandboxSpec } from "../ports.js";
import { registerSandboxProvider } from "../ports.js";

const DEFAULT_IMAGE = "node:20";

interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

/**
 * Container runtimes this adapter can drive.
 *
 * Every subcommand used here — `run -d`, `cp`, `exec`, `rm -f`, `info`
 * — is spelled identically by both, so supporting Docker costs a
 * parameter rather than an adapter. Not supporting it cost far more:
 * Docker is what most developers already have, and telling them to go
 * install a second container runtime to try the behavioral tier is a
 * reason not to try it.
 */
export type ContainerCli = "podman" | "docker";

/** Run a container CLI with args, capturing stdio + a timeout. */
function cli(
  bin: ContainerCli,
  args: string[],
  opts?: { timeoutMs?: number; input?: string },
): Promise<RunResult> {
  return new Promise<RunResult>((resolve, reject) => {
    const child = spawn(bin, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;
    if (opts?.timeoutMs && opts.timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, opts.timeoutMs);
    }
    child.stdout.on("data", (c: Buffer) => {
      stdout += c.toString();
    });
    child.stderr.on("data", (c: Buffer) => {
      stderr += c.toString();
    });
    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      // ENOENT → the podman binary isn't installed; surface a clear error.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(
          new Error(
            `${bin} was not found on PATH. Install Docker (https://docs.docker.com/get-docker/) ` +
              "or Podman (https://podman.io/) for a free local sandbox, or set E2B_API_KEY " +
              "to run in the cloud instead.",
          ),
        );
        return;
      }
      reject(err);
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolve({ exitCode: code ?? 0, stdout, stderr, timedOut });
    });
    if (opts?.input !== undefined) {
      child.stdin.write(opts.input);
    }
    child.stdin.end();
  });
}

class ContainerSandbox implements Sandbox {
  private closed = false;

  constructor(
    private readonly id: string,
    private readonly bin: ContainerCli,
  ) {}

  async writeFiles(files: { path: string; contents: string }[]): Promise<void> {
    const dir = mkdtempSync(join(tmpdir(), "assay-sandbox-"));
    try {
      for (const f of files) {
        const host = join(dir, "payload");
        writeFileSync(host, f.contents);
        // Ensure the parent dir exists in the container, then copy in.
        const parent = f.path.replace(/\/[^/]*$/, "") || "/";
        await cli(this.bin, ["exec", this.id, "mkdir", "-p", parent]);
        const cp = await cli(this.bin, ["cp", host, `${this.id}:${f.path}`]);
        if (cp.exitCode !== 0) {
          throw new Error(`podman cp failed for ${f.path}: ${cp.stderr.trim()}`);
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  async exec(
    cmd: string,
    opts?: { cwd?: string; timeoutMs?: number; env?: Record<string, string> },
  ): Promise<ExecResult> {
    const start = Date.now();
    const args = ["exec"];
    if (opts?.cwd) args.push("-w", opts.cwd);
    for (const [k, v] of Object.entries(opts?.env ?? {})) args.push("-e", `${k}=${v}`);
    args.push(this.id, "sh", "-lc", cmd);
    const r = await cli(this.bin, args, opts?.timeoutMs ? { timeoutMs: opts.timeoutMs } : {});
    return {
      exitCode: r.timedOut ? 124 : r.exitCode,
      stdout: r.stdout,
      stderr: r.stderr,
      durationMs: Date.now() - start,
      timedOut: r.timedOut,
    };
  }

  async readFile(path: string): Promise<string | null> {
    const r = await cli(this.bin, ["exec", this.id, "cat", path]);
    if (r.exitCode !== 0) return null;
    return r.stdout;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await cli(this.bin, ["rm", "-f", this.id]).catch(() => undefined);
  }
}

function providerFor(bin: ContainerCli): SandboxProvider {
  return {
    name: bin,
    async create(spec: SandboxSpec): Promise<Sandbox> {
      const image = spec.image ?? DEFAULT_IMAGE;
      const args = ["run", "-d", "--rm"];
      // Egress control: when networkEgress is explicitly false, isolate.
      if (spec.networkEgress === false) args.push("--network=none");
      args.push(image, "sleep", "infinity");
      const run = await cli(
        bin,
        args,
        // Booting can pull an image — give it a generous wall-clock budget.
        { timeoutMs: spec.timeoutMs && spec.timeoutMs > 0 ? spec.timeoutMs : 300_000 },
      );
      if (run.exitCode !== 0 || !run.stdout.trim()) {
        throw new Error(`${bin} run failed (exit ${run.exitCode}): ${run.stderr.trim()}`);
      }
      const id = run.stdout.trim().split(/\s+/)[0]!;
      return new ContainerSandbox(id, bin);
    },
  };
}

export const podmanSandboxProvider = providerFor("podman");
export const dockerSandboxProvider = providerFor("docker");

/** Is this runtime installed and actually answering? */
export async function containerCliUsable(bin: ContainerCli, timeoutMs = 4_000): Promise<boolean> {
  try {
    // `info` rather than `--version`: a binary can be installed with no
    // running machine or daemon, and finding that out three minutes
    // into a behavioral run is the worst time to find it out.
    const r = await cli(bin, ["info"], { timeoutMs });
    return r.exitCode === 0 && !r.timedOut;
  } catch {
    return false;
  }
}

/** Register both local container providers. */
export function registerPodman(): void {
  registerSandboxProvider(podmanSandboxProvider);
  registerSandboxProvider(dockerSandboxProvider);
}

registerPodman();
