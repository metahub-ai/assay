/**
 * E2B sandbox adapter — real-shaped, env-gated, EXCLUDED from coverage.
 *
 * Static-imports the `e2b` SDK (a real dependency of this package). We
 * used to load lazily via `await import("e2b" as string)`, but tsx
 * serves .ts files via `data:` URLs at runtime, and ESM dynamic imports
 * from a data: URL can't resolve a bare specifier — that broke the
 * Railway worker boot. Static import is fine because this file is only
 * imported by the worker entry, which always has the SDK available.
 *
 * The engine never imports this file directly — only the worker does,
 * and the provider is registered only when `E2B_API_KEY` is set. The
 * default local `podman` path stays cloud-free.
 */
import { Sandbox as E2bSandboxApi } from "e2b";
import type { ExecResult, Sandbox, SandboxProvider, SandboxSpec } from "../ports.js";
import { registerSandboxProvider, SandboxInfraError } from "../ports.js";

/**
 * The e2b SDK throws `CommandExitError` for a command that ran to
 * completion with a non-zero exit — that is a REAL result from a live
 * sandbox, not an infra failure, so we duck-type it (it carries
 * exitCode/stdout/stderr) and return it as an ExecResult. Everything
 * else that `commands.run` throws (sandbox killed by its lifetime cap,
 * connection loss, API errors) means the sandbox itself is gone.
 */
function asCommandExit(err: unknown): { exitCode: number; stdout: string; stderr: string } | null {
  const e = err as { exitCode?: unknown; stdout?: unknown; stderr?: unknown };
  if (typeof e?.exitCode !== "number") return null;
  return {
    exitCode: e.exitCode,
    stdout: typeof e.stdout === "string" ? e.stdout : "",
    stderr: typeof e.stderr === "string" ? e.stderr : String((err as Error).message ?? ""),
  };
}

/**
 * E2B sandboxes execute as an unprivileged user whose home is
 * `/home/user`; the filesystem root is NOT writable, so the engine's
 * historical `/workspace` clone target failed with
 * `could not create work tree dir '/workspace': Permission denied` for
 * every kind that clones (mcp/agent/plugin). Skills never clone, which
 * is why this stayed invisible until a plugin was run on E2B.
 * Overridable for a custom template that lays out its home elsewhere.
 */
const E2B_WORKDIR = process.env.E2B_WORKDIR ?? "/home/user/workspace";

/** Exported for the adapter contract test (fake api injection). */
export class E2bSandbox implements Sandbox {
  readonly workdir = E2B_WORKDIR;
  constructor(private readonly api: E2bSandboxApi) {}

  async writeFiles(files: { path: string; contents: string }[]): Promise<void> {
    for (const f of files) await this.api.files.write(f.path, f.contents);
  }

  async exec(cmd: string, opts?: { cwd?: string; timeoutMs?: number }): Promise<ExecResult> {
    const start = Date.now();
    try {
      const r = await this.api.commands.run(cmd, opts);
      return {
        exitCode: r.exitCode,
        stdout: r.stdout,
        stderr: r.stderr,
        durationMs: Date.now() - start,
        timedOut: false,
      };
    } catch (err) {
      const exit = asCommandExit(err);
      if (exit) {
        return { ...exit, durationMs: Date.now() - start, timedOut: false };
      }
      const timedOut = /timeout|timed out/i.test((err as Error).message);
      if (timedOut) {
        // A per-command timeout is a real (bounded) execution outcome.
        return {
          exitCode: 124,
          stdout: "",
          stderr: (err as Error).message,
          durationMs: Date.now() - start,
          timedOut: true,
        };
      }
      // Sandbox-level death: surface it as infra, never as a transcript.
      throw new SandboxInfraError(
        `e2b exec failed (sandbox dead?): ${(err as Error).message}`,
        err,
      );
    }
  }

  async readFile(path: string): Promise<string | null> {
    try {
      return await this.api.files.read(path);
    } catch {
      return null;
    }
  }

  async close(): Promise<void> {
    await this.api.kill().catch(() => undefined);
  }
}

export const e2bSandboxProvider: SandboxProvider = {
  name: "e2b",
  // KNOWN LIMITATION: `spec.networkEgress` is not enforceable here — the
  // E2B create API has no egress toggle, so E2B sandboxes always have
  // network access. Only the podman adapter honors networkEgress:false
  // (via --network none). The judge's safety scan + allowedHosts is the
  // compensating control for undeclared egress on E2B.
  async create(spec: SandboxSpec): Promise<Sandbox> {
    // e2b exposes two static `create` overloads: `(opts)` for the
    // default template and `(template, opts)` for a named template.
    // We branch so each call matches one overload cleanly.
    const opts = {
      apiKey: process.env.E2B_API_KEY,
      ...(spec.timeoutMs ? { timeoutMs: spec.timeoutMs } : {}),
    };
    try {
      const api = spec.image
        ? await E2bSandboxApi.create(spec.image, opts)
        : await E2bSandboxApi.create(opts);
      return new E2bSandbox(api);
    } catch (err) {
      throw new SandboxInfraError(`e2b sandbox create failed: ${(err as Error).message}`, err);
    }
  },
};

/** Register the E2B provider iff its API key is present. */
export function registerE2bIfConfigured(): boolean {
  if (!process.env.E2B_API_KEY) return false;
  registerSandboxProvider(e2bSandboxProvider);
  return true;
}
