/**
 * Lazy provider bootstrap for the CLI.
 *
 * Two constraints shape this module, and they pull against each other.
 *
 * **`assay run` must stay dependency-free.** The default suite is
 * offline and deterministic; it would be absurd for it to fail to start
 * because a cloud adapter could not initialise. So no adapter is
 * imported until something actually needs a model.
 *
 * **No adapter needs an SDK.** Each speaks its vendor's HTTP API
 * directly through `./adapters/http.ts`. That is deliberate: when the
 * SDKs were optional peer dependencies, a tarball install could take a
 * key, accept it, and then fail the run until the user hand-installed
 * a package into assay's own lib directory. Registration is still
 * guarded per candidate so one broken adapter cannot take down the
 * others.
 *
 * The resolution order is deliberate and documented rather than
 * clever: an explicitly named provider always wins, and auto-detection
 * only picks something when exactly one is configured. Silently
 * choosing between two configured providers would make a published
 * grade depend on ambient environment state, which is precisely what
 * `RunEnvironment` exists to prevent.
 */
import { ensurePackage, hasPackage, isProvisionable, provisionHint } from "./vendor.js";
import {
  getLlmProvider,
  getSandboxProvider,
  type LlmProvider,
  type SandboxProvider,
} from "./ports.js";

/** A provider the CLI knows how to bring up, and what configures it. */
interface Candidate {
  name: string;
  /** Env var whose presence means "the user configured this". */
  env: string;
  load: () => Promise<boolean>;
}

const CANDIDATES: Candidate[] = [
  {
    name: "anthropic",
    env: "ANTHROPIC_API_KEY",
    load: async () => (await import("./adapters/anthropic.js")).registerAnthropicIfConfigured(),
  },
  {
    name: "openai",
    env: "OPENAI_API_KEY",
    load: async () => (await import("./adapters/openai.js")).registerOpenAiIfConfigured(),
  },
  {
    name: "openrouter",
    env: "OPENROUTER_API_KEY",
    load: async () => (await import("./adapters/openrouter.js")).registerOpenRouterIfConfigured(),
  },
  {
    name: "local",
    // Opt-in rather than always-on: the local adapter self-registers on
    // import and would otherwise silently win auto-detection on a
    // machine that merely has Ollama installed.
    env: "LOCAL_LLM_BASE_URL",
    load: async () => {
      (await import("./adapters/local-llm.js")).registerLocalLlm();
      return true;
    },
  },
];

export interface ProviderResolution {
  provider: LlmProvider;
  /** Which candidates were configured, for the error message and the report. */
  configured: string[];
}

export class NoProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoProviderError";
  }
}

/**
 * Bring up and resolve an LLM provider.
 *
 * `requested` names one explicitly. Without it, auto-detection succeeds
 * only when exactly one provider is configured — ambiguity is an error
 * a human resolves, not a coin we flip.
 */
export async function resolveLlmProvider(requested?: string): Promise<ProviderResolution> {
  const configured: string[] = [];

  for (const candidate of CANDIDATES) {
    const wanted = requested ? candidate.name === requested : process.env[candidate.env];
    if (!wanted) continue;
    try {
      if (await candidate.load()) configured.push(candidate.name);
    } catch (err) {
      // Adapters no longer depend on anything installable, so a failure
      // here is a real defect rather than the ordinary "peer not
      // installed" state. Surfacing it beats reporting "no provider is
      // configured", which used to send users to set a variable they
      // had already set correctly.
      throw new Error(
        `assay: failed to load the "${candidate.name}" adapter: ${(err as Error).message}`,
      );
    }
  }

  if (requested) {
    if (!configured.includes(requested)) {
      const env = CANDIDATES.find((c) => c.name === requested)?.env;
      throw new NoProviderError(
        env
          ? `Provider "${requested}" is not configured. Set ${env}.`
          : `Unknown provider "${requested}". Known: ${CANDIDATES.map((c) => c.name).join(", ")}.`,
      );
    }
    return { provider: getLlmProvider(requested), configured };
  }

  if (configured.length === 0) {
    throw new NoProviderError(
      "No model provider is configured. Set one of:\n" +
        CANDIDATES.map((c) => `  ${c.env.padEnd(22)} → --provider ${c.name}`).join("\n"),
    );
  }
  if (configured.length > 1) {
    // Picking for them would make the grade depend on ambient state.
    throw new NoProviderError(
      `Several providers are configured (${configured.join(", ")}). ` +
        `Name one with --provider so the report records which produced the verdict.`,
    );
  }
  return { provider: getLlmProvider(configured[0]!), configured };
}

// ── Sandboxes ────────────────────────────────────────────────────────

/**
 * Sandbox candidates.
 *
 * `podman` is deliberately first and needs no credential: behavioral
 * evaluation should be runnable on a laptop for free. A framework whose
 * headline capability requires a cloud account and a credit card is one
 * most people will never actually try, and "you can verify this
 * yourself" stops being true.
 */
const SANDBOXES: Candidate[] = [
  {
    name: "podman",
    // Availability is checked by running it, not by an env var — a
    // container runtime is either installed and answering, or it is not.
    env: "",
    load: async () => {
      (await import("./adapters/podman.js")).registerPodman();
      return true;
    },
  },
  {
    name: "docker",
    env: "",
    load: async () => {
      (await import("./adapters/podman.js")).registerPodman();
      return true;
    },
  },
  {
    name: "e2b",
    env: "E2B_API_KEY",
    load: async () => (await import("./adapters/e2b.js")).registerE2bIfConfigured(),
  },
];

export interface SandboxResolution {
  provider: SandboxProvider;
  name: string;
}

/**
 * The local container runtime this machine actually has.
 *
 * Checked in order, and it matters that Docker is checked at all:
 * supporting only podman meant a developer with Docker installed was
 * told "no sandbox usable — install podman", which is asking someone
 * to install a second container runtime to try a feature. Both speak
 * the same subcommands.
 */
export async function localRuntime(): Promise<"podman" | "docker" | null> {
  // Both at once, not one then the other.
  //
  // Sequential probing cost up to two full timeouts, and `docker info`
  // against a daemon that is installed but not running takes the whole
  // budget. That doubled `assay doctor`'s worst case and blew a 5s CI
  // test — on a runner where Docker is present but idle, which is
  // exactly the machine most people will run this on.
  const [podman, docker] = await Promise.all([
    podmanAvailable(PODMAN_PROBE_TIMEOUT_MS, "podman"),
    podmanAvailable(PODMAN_PROBE_TIMEOUT_MS, "docker"),
  ]);
  // Podman wins a tie only because it is the documented default; both
  // are equally supported.
  if (podman) return "podman";
  if (docker) return "docker";
  return null;
}

/**
 * Resolve a sandbox.
 *
 * Unlike the LLM side there IS a sensible default — a local container
 * runtime — so auto-detection prefers E2B when its key is present
 * (someone who configured it meant to use it) and otherwise falls back
 * to whichever local runtime is installed.
 */
export async function resolveSandbox(
  requested?: string,
  say: (s: string) => void = () => {},
): Promise<SandboxResolution> {
  // Auto-selection, in the order that costs the user least.
  //
  // A local runtime is free, so it wins whenever one is actually
  // answering. When neither Docker nor Podman is, fall back to E2B if a
  // key is configured — and say so, because silently starting a metered
  // cloud sandbox is not a thing to discover on an invoice.
  let wanted = requested;
  if (!wanted) {
    const local = await localRuntime();
    if (local) {
      wanted = local;
    } else if (process.env["E2B_API_KEY"]) {
      say(
        "  No local container runtime detected (Docker or Podman) — using the E2B cloud sandbox.\n",
      );
      wanted = "e2b";
    } else {
      wanted = "podman";
    }
  }
  const candidate = SANDBOXES.find((c) => c.name === wanted);
  if (!candidate) {
    throw new NoProviderError(
      `Unknown sandbox "${wanted}". Known: ${SANDBOXES.map((c) => c.name).join(", ")}.`,
    );
  }

  // Fetch the client BEFORE trying to load the adapter, rather than
  // catching the import failure and telling the user to go install it.
  // Someone who asked for a behavioral run has asked for everything it
  // needs; making them finish our installation by hand is not a step,
  // it is a defect.
  if (isProvisionable(wanted) && !hasPackage(wanted)) {
    const r = await ensurePackage(wanted, say);
    if (!r.ok) throw new NoProviderError(provisionHint(wanted, r.detail));
  }

  try {
    if (!(await candidate.load())) {
      throw new NoProviderError(
        `Sandbox "${wanted}" is not configured.` + (candidate.env ? ` Set ${candidate.env}.` : ""),
      );
    }
  } catch (err) {
    if (err instanceof NoProviderError) throw err;
    const message = (err as Error).message;
    if (/Cannot find (module|package)/i.test(message)) {
      throw new NoProviderError(provisionHint(wanted, "the package is still not resolvable"));
    }
    throw err;
  }
  return { provider: getSandboxProvider(wanted), name: wanted };
}

/** How long to wait for podman to say whether it is alive. */
// 2.5s. A healthy daemon answers `info` in well under a second; the
// only thing a longer budget buys is a longer wait before telling
// somebody their runtime is not running, which is the case where they
// most want a fast answer.
const PODMAN_PROBE_TIMEOUT_MS = 2_500;

/**
 * Is a local container runtime actually usable right now?
 *
 * Checked by invoking it rather than by looking for the binary: podman
 * can be installed but have no running machine, and discovering that
 * three minutes into a behavioral run is a bad experience.
 *
 * The timeout is load-bearing rather than defensive. `podman info`
 * against an installed binary with an unreachable socket does not fail
 * — it HANGS, which made `assay doctor` hang forever for exactly the
 * users whose setup is broken and who most need an answer. A CI runner
 * with podman installed and no machine running is that case, and it is
 * how this was found.
 */
export async function podmanAvailable(
  timeoutMs = PODMAN_PROBE_TIMEOUT_MS,
  bin: "podman" | "docker" = "podman",
): Promise<boolean> {
  const { spawn } = await import("node:child_process");
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    // `info` rather than `--version`: both runtimes install a binary
    // that answers `--version` with no machine or daemon running, and
    // discovering that three minutes into a behavioral run is the worst
    // possible time.
    const p = spawn(bin, ["info"], { stdio: "ignore" });
    const timer = setTimeout(() => {
      // Unreachable socket. Kill the probe so it cannot outlive us and
      // hold the event loop open.
      p.kill("SIGKILL");
      done(false);
    }, timeoutMs);
    p.on("error", () => done(false));
    p.on("close", (code) => done(code === 0));
  });
}
