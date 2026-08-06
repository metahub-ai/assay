/**
 * Ports — the interfaces the framework depends on, so that it depends
 * on no vendor.
 *
 * The sandbox and LLM contracts here are NOT speculative: they are the
 * shapes that have been running the MetaHub behavioral pipeline in
 * production, ported across with their hard-won details intact. Where
 * an earlier draft of this file guessed differently (a single-file
 * `writeFile`, a `CommandResult` without timing), the production shape
 * won — those details exist because something broke without them.
 *
 * The one genuinely new port is `SourceReader`. The portal's detection
 * layer reads through the GitHub API, which means it cannot evaluate a
 * local directory — and therefore cannot give a publisher the same
 * answer locally that the registry shows. That parity is the most
 * important promise an open eval framework makes, so the transport has
 * to sit behind an interface.
 */
import type { LlmRole } from "./types.js";

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

/** One entry in an artifact's file tree. */
export interface TreeEntry {
  /** POSIX path relative to the artifact root. No leading slash. */
  path: string;
  type: "file" | "dir" | "symlink";
  /** Bytes. May be undefined when the transport doesn't report it. */
  size?: number;
  /**
   * For a symlink, its target as written — never resolved.
   *
   * Resolving would make the value depend on the host filesystem;
   * recording the literal text is what lets a check notice that
   * `creds -> /Users/you/.aws/credentials` is being shipped.
   */
  target?: string;
  /**
   * Whether the file carries an executable bit.
   *
   * Undefined when the transport does not report modes (the GitHub
   * contents API, some tarballs). Only the exec bit is modelled: the
   * rest of a POSIX mode is not preserved across the transports an
   * artifact travels through, so folding it into a digest would make
   * the digest depend on how the artifact was fetched.
   */
  executable?: boolean;
}

/**
 * Read-only access to the artifact's contents.
 *
 * Implementations: a local directory, a git checkout at a commit, an
 * extracted tarball, the GitHub contents API, an in-memory map for
 * tests. Every check reads through this and only this, which is what
 * makes `assay run ./my-skill` and the hosted evaluation the same code
 * path rather than two implementations that drift.
 */
export interface SourceReader {
  /** Full recursive tree. Implementations should cache. */
  listTree(): Promise<TreeEntry[]>;
  /** UTF-8 contents, or null when absent. Reads are memoized per run. */
  readFile(path: string): Promise<string | null>;
  /** Raw bytes, for binary inspection and digesting. */
  readBytes?(path: string): Promise<Uint8Array | null>;
  /**
   * Streaming read, for files too large to hold in memory.
   *
   * `digestTree` needs this: `readBytes` refuses anything over the size
   * ceiling, and the digest previously substituted the literal string
   * "unreadable" for those files — so two artifacts differing only in a
   * 3 MB bundle hashed identically. Bundled and minified artifacts
   * routinely exceed the ceiling.
   */
  stream?(path: string): Promise<NodeJS.ReadableStream | null>;
  /** True when the path exists (cheaper than reading). */
  exists(path: string): Promise<boolean>;
}

/** Outbound HTTP, granted only to checks declaring the `net` capability. */
export interface NetClient {
  /**
   * Constrained `fetch`. Implementations enforce an allowlist, apply
   * timeouts, and record every request into the report's evidence so
   * an external lookup that changed a verdict is visible.
   */
  fetch(
    url: string,
    init?: { method?: string; headers?: Record<string, string>; body?: string },
  ): Promise<{
    status: number;
    headers: Record<string, string>;
    text(): Promise<string>;
  }>;
}

// ---------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------

export interface SandboxSpec {
  /** Container image / template the vendor should boot. */
  image?: string;
  /** Whether the sandbox is allowed to reach the network. */
  networkEgress?: boolean;
  /** Hard wall-clock cap for the sandbox session. */
  timeoutMs?: number;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export interface Sandbox {
  /**
   * Absolute path of a directory this sandbox can actually WRITE to,
   * used as the clone/workspace root.
   *
   * Adapters must declare it because it is vendor-specific: podman runs
   * as root so `/workspace` at the filesystem root is fine, but an E2B
   * sandbox runs as an unprivileged user and `mkdir /workspace` fails
   * with EACCES. That difference silently broke every clone-requiring
   * kind on E2B while skills, which never clone, kept passing — which
   * is exactly the sort of bug a "just use /workspace" default hides.
   */
  readonly workdir?: string;
  /** Write a batch of files. Batched because a per-file round trip to a
   *  cloud sandbox costs 100–300ms each. */
  writeFiles(files: { path: string; contents: string }[]): Promise<void>;
  /** Run a shell command, capturing stdio + timing. */
  exec(cmd: string, opts?: { cwd?: string; timeoutMs?: number }): Promise<ExecResult>;
  /** Read a file back; null when it doesn't exist. */
  readFile(path: string): Promise<string | null>;
  /** Tear the sandbox down. Idempotent. */
  close(): Promise<void>;
}

export interface SandboxProvider {
  readonly name: string;
  create(spec: SandboxSpec): Promise<Sandbox>;
}

/**
 * Infrastructure failure of the sandbox itself — it died, was killed by
 * its provider-side lifetime cap, or the vendor API errored. Distinct
 * from a command failing INSIDE a healthy sandbox, which is a
 * legitimate `ExecResult` with a non-zero exit code.
 *
 * This class earns its place. Without it, an E2B outage or an exhausted
 * container quota is recorded as the artifact failing its behavioral
 * checks — a permanent public mark caused entirely by our
 * infrastructure. Checks that catch this must emit status `error`,
 * which the scorer excludes.
 *
 * Detected by BRAND, not `instanceof`: tsx/ESM can load a module twice
 * (data:-URL re-serving) and `instanceof` across module instances
 * silently returns false.
 */
export class SandboxInfraError extends Error {
  readonly isSandboxInfraError = true as const;
  constructor(
    message: string,
    override readonly cause?: unknown,
  ) {
    super(message);
    this.name = "SandboxInfraError";
  }
}

export function isSandboxInfraError(err: unknown): err is SandboxInfraError {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { isSandboxInfraError?: unknown }).isSandboxInfraError === true
  );
}

/** Runner handed to checks holding the `sandbox` capability. */
export interface SandboxRunner {
  provision(spec?: SandboxSpec): Promise<Sandbox>;
  /** Name of the resolved provider, for the report's environment. */
  readonly name: string;
}

// ---------------------------------------------------------------------
// LLM
// ---------------------------------------------------------------------

export interface LlmTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface LlmMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  /** Set on a "tool" message to correlate it with the call it answers. */
  toolCallId?: string;
}

export interface LlmToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export interface LlmResponse {
  text: string;
  toolCalls: LlmToolCall[];
  stopReason: "end" | "tool_use" | "max_tokens";
  usage?: { inputTokens: number; outputTokens: number };
}

/**
 * A model, addressed by ROLE rather than by name.
 *
 * The role split is not cosmetic. The `driver` stands in for the end
 * user's AI client while exercising the artifact — making it too strong
 * measures the wrong thing. The `judge` grades the resulting transcript
 * and must emit strict JSON, so its instruction-following quality
 * directly determines score reliability. Conflating them means a model
 * that is bad at following instructions also grades its own failure to
 * follow them, and it makes the obvious cost optimization impossible to
 * express. The pin for each role lands in `RunEnvironment.models`, so a
 * grade is always attributable.
 */
export interface LlmProvider {
  readonly name: string;
  /**
   * The concrete model this provider would use for a role.
   *
   * `ModelPin` exists because swapping the judge changes grades on
   * identical behavior, and that has to be visible rather than silent.
   * It was being filled in with the literal string
   * `"(adapter default)"`, which records nothing — two reports judged
   * by different models were indistinguishable, and `replay` could
   * re-grade with a different model than the run used without saying
   * so. The adapters always knew the answer; the interface had no way
   * to ask.
   */
  modelFor?(role: LlmRole): string | undefined;
  complete(input: {
    system?: string;
    messages: LlmMessage[];
    tools?: LlmTool[];
    maxTokens?: number;
    temperature?: number;
    role?: LlmRole;
  }): Promise<LlmResponse>;
}

// ---------------------------------------------------------------------
// Provider registries
// ---------------------------------------------------------------------

const sandboxProviders = new Map<string, SandboxProvider>();
const llmProviders = new Map<string, LlmProvider>();

/** Register a sandbox provider under its `name`. Last write wins. */
export function registerSandboxProvider(p: SandboxProvider): void {
  sandboxProviders.set(p.name, p);
}

/**
 * Resolve a sandbox provider by name.
 *
 * Unlike the portal's version this takes NO default from the
 * environment. A framework that silently picks a provider based on an
 * ambient env var makes the run environment invisible in the report,
 * which is the opposite of what this project is for — the caller names
 * what it wants and the choice is recorded.
 */
export function getSandboxProvider(name: string): SandboxProvider {
  const p = sandboxProviders.get(name);
  if (!p) {
    const known = [...sandboxProviders.keys()].join(", ") || "(none)";
    throw new Error(
      `assay: sandbox provider "${name}" is not registered. Known providers: ${known}.`,
    );
  }
  return p;
}

export function registerLlmProvider(p: LlmProvider): void {
  llmProviders.set(p.name, p);
}

export function getLlmProvider(name: string): LlmProvider {
  const p = llmProviders.get(name);
  if (!p) {
    const known = [...llmProviders.keys()].join(", ") || "(none)";
    throw new Error(`assay: LLM provider "${name}" is not registered. Known providers: ${known}.`);
  }
  return p;
}

/** Test-only: drop all registrations. */
export function _resetProviders(): void {
  sandboxProviders.clear();
  llmProviders.clear();
}

// ---------------------------------------------------------------------
// Caching
// ---------------------------------------------------------------------

/**
 * Optional result cache, keyed by content.
 *
 * The key is (subject digest, check id, check version, environment
 * digest) — which is exactly why those fields are mandatory in the
 * report. Content addressing means a cache hit is provably the same
 * computation rather than a guess based on a repo URL and a timestamp.
 */
export interface ResultCache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
}
