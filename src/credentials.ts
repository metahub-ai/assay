/**
 * Persisted setup: which sandbox, which model, and the key for it.
 *
 * The point is that a developer configures this once instead of
 * re-exporting environment variables on every invocation. That is the
 * difference between a tool people try and a tool people use.
 *
 * **Precedence is environment-first, always.** A key in the environment
 * overrides a key on disk, never the other way round. CI sets secrets
 * through the environment, and a stale credential file silently winning
 * over a rotated CI secret is the kind of bug that takes a day to find.
 *
 * **Where the secret lives, stated plainly.** The file is written at
 * mode 0600 under `~/.assay/`. That is what `aws configure`, `vercel`,
 * and `stripe` do, and it is a real trade: plaintext on disk is
 * readable by anything running as you, and by any backup that copies
 * your home directory. An OS-keychain backend is the better answer and
 * is not implemented. `assay setup` says this out loud rather than
 * burying it, because a security tool that quietly stores your API key
 * in plaintext has no business lecturing anyone about `.env` files.
 */
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export interface StoredConfig {
  /** Schema version, so a future change can migrate rather than crash. */
  version: 1;
  llm?: {
    provider: "anthropic" | "openai" | "openrouter" | "local";
    /** Omitted for `local`, which needs a base URL instead. */
    apiKey?: string;
    baseUrl?: string;
    model?: string;
  };
  sandbox?: {
    provider: "podman" | "e2b";
    apiKey?: string;
  };
  /**
   * Whether a plain `assay run` should include the behavioral tier.
   *
   * Recorded by `assay setup` so that default-on is a choice the user
   * made and can find, rather than an inference from whether stdout
   * happens to be a terminal. Absent means "not asked yet", which
   * `decideBehavioral` treats as yes — configuring a sandbox and a model
   * is itself an opt-in, and making the user say yes a second time on
   * every run is the complaint this whole mechanism exists to answer.
   */
  behavioralByDefault?: boolean;
  /** When setup last ran, for the "your config is ancient" nudge. */
  updatedAt?: string;
}

export function configDir(env: NodeJS.ProcessEnv = process.env): string {
  return env["ASSAY_HOME"] ?? join(homedir(), ".assay");
}

export function configPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(configDir(env), "config.json");
}

export async function loadStoredConfig(
  env: NodeJS.ProcessEnv = process.env,
): Promise<StoredConfig | null> {
  try {
    const raw = await readFile(configPath(env), "utf8");
    const parsed = JSON.parse(raw) as StoredConfig;
    return parsed?.version === 1 ? parsed : null;
  } catch {
    // Absent or unreadable are the same thing to a caller: no config.
    // A malformed one is NOT silently repaired — `assay setup` rewrites
    // it, and that is a deliberate action rather than a side effect.
    return null;
  }
}

export async function saveStoredConfig(
  config: StoredConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const path = configPath(env);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const body = JSON.stringify({ ...config, updatedAt: new Date().toISOString() }, null, 2);
  // Mode on the open, not a chmod after: writing world-readable first
  // and tightening later leaves a window where the key is exposed.
  await writeFile(path, `${body}\n`, { encoding: "utf8", mode: 0o600 });
  // Belt and braces for a pre-existing file, whose mode `writeFile`
  // does not change.
  await chmod(path, 0o600);
  return path;
}

/** True when the file is not readable by group or others. */
export async function configIsPrivate(env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  try {
    const info = await stat(configPath(env));
    return (info.mode & 0o077) === 0;
  } catch {
    return true;
  }
}

export interface ResolvedCredentials {
  llmProvider: string | null;
  sandbox: string | null;
  /** Where each value came from, so the CLI can say so. */
  source: { llm: "env" | "config" | null; sandbox: "env" | "config" | null };
}

const LLM_ENV: Record<string, string> = {
  ANTHROPIC_API_KEY: "anthropic",
  OPENAI_API_KEY: "openai",
  OPENROUTER_API_KEY: "openrouter",
  LOCAL_LLM_BASE_URL: "local",
};

/**
 * Merge environment and stored config, environment winning.
 *
 * Returns which source supplied each value so the CLI can tell the user
 * why it chose what it chose — "hidden state" is the single most common
 * complaint about tools that persist configuration.
 */
export function resolveCredentials(
  stored: StoredConfig | null,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedCredentials {
  const envLlm = Object.keys(LLM_ENV).find((k) => env[k]);
  const llmProvider = envLlm ? LLM_ENV[envLlm]! : (stored?.llm?.provider ?? null);
  const sandbox = env["E2B_API_KEY"] ? "e2b" : (stored?.sandbox?.provider ?? null);

  return {
    llmProvider,
    sandbox,
    source: {
      llm: envLlm ? "env" : stored?.llm?.provider ? "config" : null,
      sandbox: env["E2B_API_KEY"] ? "env" : stored?.sandbox?.provider ? "config" : null,
    },
  };
}

/**
 * Project stored credentials into the environment for this process.
 *
 * The adapters read `process.env`, so rather than threading credentials
 * through every call site this fills the gaps the environment left.
 * It never overwrites an existing variable — see the precedence rule.
 */
export function applyStoredConfig(
  stored: StoredConfig | null,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!stored) return;
  const set = (key: string, value: string | undefined) => {
    if (value && !env[key]) env[key] = value;
  };
  switch (stored.llm?.provider) {
    case "anthropic":
      set("ANTHROPIC_API_KEY", stored.llm.apiKey);
      set("EVAL_ANTHROPIC_MODEL", stored.llm.model);
      break;
    case "openai":
      set("OPENAI_API_KEY", stored.llm.apiKey);
      set("EVAL_OPENAI_MODEL", stored.llm.model);
      break;
    case "openrouter":
      set("OPENROUTER_API_KEY", stored.llm.apiKey);
      set("OPENROUTER_JUDGE_MODEL", stored.llm.model);
      break;
    case "local":
      set("LOCAL_LLM_BASE_URL", stored.llm.baseUrl);
      set("LOCAL_LLM_MODEL", stored.llm.model);
      break;
    default:
      break;
  }
  if (stored.sandbox?.provider === "e2b") set("E2B_API_KEY", stored.sandbox.apiKey);
}

/**
 * Why the behavioral tier is on or off for this invocation.
 *
 * A single vocabulary shared by the runner and the advice layer, so the
 * footer explains the same decision the run made rather than guessing at
 * it from a boolean.
 */
export type BehavioralMode =
  /** `--behavioral`. Explicit, wins everywhere including CI. */
  | "requested"
  /** `--no-behavioral`. Explicit, wins everywhere. */
  | "declined"
  /** Configured and interactive: it runs, and nobody had to ask. */
  | "default"
  /** `behavioralByDefault: false` in the stored config. */
  | "opted-out"
  /** No TTY. Stays opt-in — see `decideBehavioral`. */
  | "non-interactive"
  /** Wanted, but there is no usable sandbox and/or model. */
  | "unavailable";

/**
 * Decide whether a plain `assay run` includes the behavioral tier.
 *
 * The rule the product needs is "configure it once, then it just runs".
 * The rule it must not break is "a pipeline never starts spending money
 * because somebody set a key on that machine six months ago". Both fit,
 * because they disagree in exactly one place — a terminal.
 *
 *   1. An explicit flag always wins, in either direction.
 *   2. A recorded `behavioralByDefault: false` is a standing no.
 *   3. **No TTY means opt-in.** This is the guard, and it is not a
 *      heuristic for convenience: behavioral evaluation costs money per
 *      run and adds minutes, and CI runs on every commit. A human who
 *      wants it there types `--behavioral` once in a workflow file.
 *      Note that a stored `behavioralByDefault: true` does NOT override
 *      this — the preference is about the interactive default, and a
 *      credential file that happens to exist on a runner is not consent
 *      to bill that runner.
 *   4. Otherwise it runs. `assay setup` was the opt-in.
 *
 * Whether the sandbox and model are actually usable is settled later, by
 * trying to resolve them; a failure there degrades to `unavailable`
 * rather than failing the run, because a plain `assay run` must keep
 * working when the container runtime is simply not started.
 */
export function decideBehavioral(input: {
  /** `true` for `--behavioral`, `false` for `--no-behavioral`, absent for neither. */
  flag?: boolean | undefined;
  interactive: boolean;
  preference?: boolean | undefined;
}): BehavioralMode {
  if (input.flag === true) return "requested";
  if (input.flag === false) return "declined";
  if (input.preference === false) return "opted-out";
  if (!input.interactive) return "non-interactive";
  return "default";
}

/** Does this mode mean "try to run it"? */
export function behavioralWanted(mode: BehavioralMode): boolean {
  return mode === "requested" || mode === "default";
}

/**
 * Show enough of a secret to recognise it, never enough to use it.
 *
 * Four trailing characters is the convention (Stripe, AWS, GitHub) and
 * is sufficient for "is this the key I think it is?" without putting
 * the value in a terminal history or a screenshot.
 */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) return "•".repeat(secret.length);
  return `${"•".repeat(8)}${secret.slice(-4)}`;
}
