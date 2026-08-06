/**
 * `assay setup` — the one-time configuration wizard.
 *
 * The problem it solves is narrow and real. Everything in the default
 * suite is offline and needs nothing, but the behavioral tier needs a
 * sandbox to run the artifact in and a model to drive and judge it.
 * Before this, that meant reading the docs, learning four environment
 * variable names, and exporting them again in every new shell. Most
 * people bounce off that, which means most people never see the part of
 * the tool that is actually interesting.
 *
 * Three principles shaped it:
 *
 * **Nothing here is required.** The wizard is skippable at every step
 * and `assay run` works with none of it. Setup that gates the basic
 * function of a tool is a tollbooth.
 *
 * **Verify before saving.** Every credential is tested against the
 * provider's cheapest endpoint. Storing a typo'd key and surfacing it as
 * a 401 in the middle of a three-minute behavioral run is a bad trade
 * against one extra second here.
 *
 * **Say where the secret went.** The final screen prints the path and
 * the mode. A tool that stores your API key without telling you where
 * has not earned the trust it is asking for.
 */
import { podmanAvailable } from "./providers.js";
import { askSecret, ask, confirm, isInteractive, select } from "./prompt.js";
import { assayLibRoot, ensurePackage, hasPackage } from "./vendor.js";
import {
  loadStoredConfig,
  maskSecret,
  saveStoredConfig,
  type StoredConfig,
} from "./credentials.js";
import { createTheme, type Theme } from "./term.js";

/** How long to wait for a credential check before giving up on it. */
const VERIFY_TIMEOUT_MS = 10_000;

export interface VerifyResult {
  ok: boolean;
  detail: string;
}

/**
 * Test a credential against the provider's cheapest endpoint.
 *
 * Model listing, not a completion: it is free, fast, and answers exactly
 * the question asked — is this key live? Spending tokens to find out
 * would be a surprising charge for running a setup wizard.
 *
 * This uses global `fetch` rather than the capability-gated client in
 * `net.ts` on purpose. That client exists to constrain *checks*, which
 * are untrusted third-party code. This is first-party code running a
 * host the user just typed a key for, at their explicit request.
 */
export async function verifyCredential(
  provider: string,
  key: string,
  baseUrl?: string,
): Promise<VerifyResult> {
  const endpoints: Record<string, { url: string; headers: Record<string, string> }> = {
    anthropic: {
      url: "https://api.anthropic.com/v1/models?limit=1",
      headers: { "x-api-key": key, "anthropic-version": "2023-06-01" },
    },
    openai: {
      url: "https://api.openai.com/v1/models",
      headers: { authorization: `Bearer ${key}` },
    },
    openrouter: {
      // This endpoint also reports remaining credit, which is the other
      // thing someone wants to know before starting a paid run.
      url: "https://openrouter.ai/api/v1/key",
      headers: { authorization: `Bearer ${key}` },
    },
    e2b: {
      url: "https://api.e2b.dev/templates",
      headers: { "X-API-KEY": key },
    },
    local: {
      url: `${(baseUrl ?? "").replace(/\/+$/, "")}/models`,
      headers: {},
    },
  };

  const target = endpoints[provider];
  if (!target) return { ok: true, detail: "no verification available for this provider" };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
  try {
    const res = await fetch(target.url, { headers: target.headers, signal: controller.signal });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, detail: "the provider rejected that key (401/403)" };
    }
    if (!res.ok) {
      // A 500 from the vendor is not evidence the key is bad, and
      // refusing to save on their outage would be our bug, not theirs.
      return { ok: true, detail: `could not confirm — provider returned HTTP ${res.status}` };
    }
    if (provider === "openrouter") {
      const body = (await res.json()) as { data?: { limit_remaining?: number | null } };
      const left = body.data?.limit_remaining;
      if (typeof left === "number") {
        return { ok: true, detail: `key is live — $${left.toFixed(2)} of credit remaining` };
      }
    }
    return { ok: true, detail: "key is live" };
  } catch (err) {
    const message = (err as Error).name === "AbortError" ? "timed out" : (err as Error).message;
    return { ok: true, detail: `could not confirm — ${message}` };
  } finally {
    clearTimeout(timer);
  }
}

/** Variables that would override anything the wizard writes. */
export const SHADOWING_VARS = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "OPENROUTER_API_KEY",
  "LOCAL_LLM_BASE_URL",
  "E2B_API_KEY",
];

const LLM_CHOICES = [
  { value: "anthropic", label: "Anthropic", hint: "Claude — console.anthropic.com" },
  { value: "openai", label: "OpenAI", hint: "platform.openai.com" },
  { value: "openrouter", label: "OpenRouter", hint: "one key, many models" },
  { value: "local", label: "Local / self-hosted", hint: "Ollama, vLLM, LM Studio" },
  { value: "skip", label: "Skip for now", hint: "deterministic checks still work" },
] as const;

const DEFAULT_MODELS: Record<string, string> = {
  anthropic: "claude-sonnet-4-5",
  openai: "gpt-4.1",
  openrouter: "anthropic/claude-sonnet-4.5",
  local: "llama3.1",
};

export interface SetupOptions {
  theme?: Theme;
  /** Write target for the wizard's own narration. */
  out?: (s: string) => void;
}

/**
 * Run the wizard. Returns the saved config, or null if the user bailed.
 */
export async function runSetup(opts: SetupOptions = {}): Promise<StoredConfig | null> {
  const t = opts.theme ?? createTheme();
  const say = opts.out ?? ((s: string) => process.stdout.write(s));

  if (!isInteractive()) {
    say(
      `${t.warn("assay setup needs an interactive terminal.")}\n\n` +
        "  In CI, configure these through the environment instead:\n" +
        `    ${t.code("ANTHROPIC_API_KEY")} / ${t.code("OPENAI_API_KEY")} / ${t.code("OPENROUTER_API_KEY")}\n` +
        `    ${t.code("E2B_API_KEY")}  (or install podman for a local sandbox)\n\n` +
        `  Run ${t.code("assay doctor")} to see what the current environment provides.\n`,
    );
    return null;
  }

  const existing = await loadStoredConfig();

  say(`\n${t.heading("assay setup")}\n\n`);
  // Borrowed from `gh auth login`, which refuses to write a token that
  // an environment variable would shadow. Saving a key into a file that
  // can never win is a silent no-op, and the user finds out later by
  // watching the "wrong" key get used.
  const shadowed = SHADOWING_VARS.filter((v) => process.env[v]);
  if (shadowed.length) {
    say(
      `  ${t.warn("Note:")} ${shadowed.join(", ")} ${shadowed.length === 1 ? "is" : "are"} already set in this environment.\n` +
        `  ${t.muted("Environment variables always win, so anything saved here for the")}\n` +
        `  ${t.muted("same provider will be ignored until you unset them.")}\n`,
    );
  }
  say(
    `  ${t.muted("Configures the optional behavioral tier: a sandbox to run an")}\n` +
      `  ${t.muted("artifact in, and a model to drive and judge it. The default")}\n` +
      `  ${t.muted("checks need none of this and already work.")}\n`,
  );

  if (existing) {
    say(`\n  ${t.muted("Existing configuration found — this will replace it.")}\n`);
  }

  const config: StoredConfig = { version: 1 };

  // ── Sandbox ────────────────────────────────────────────────────────
  // Probed before asking, so the menu reflects this machine rather than
  // offering a choice that cannot work.
  const hasPodman = await podmanAvailable();

  const sandbox = await select<"podman" | "e2b" | "skip">(
    t.bold("Where should artifacts run during behavioral evaluation?"),
    [
      {
        value: "podman",
        label: "This computer (podman)",
        hint: hasPodman ? t.pass("detected — free") : t.warn("not detected — install podman first"),
      },
      { value: "e2b", label: "E2B cloud sandbox", hint: t.muted("needs an API key, metered") },
      { value: "skip", label: "Skip for now", hint: t.muted("decide at run time") },
    ],
    { defaultIndex: hasPodman ? 0 : 1, render: t.accent },
  );

  if (sandbox === "podman") {
    config.sandbox = { provider: "podman" };
    if (!hasPodman) {
      say(
        `\n  ${t.warn("podman is not running.")} Saved anyway — install it and\n` +
          `  ${t.muted("run")} ${t.code("podman machine start")} ${t.muted("before a behavioral run.")}\n`,
      );
    }
  } else if (sandbox === "e2b") {
    const key = await askSecret(`  E2B API key ${t.muted("(input hidden)")}`);
    if (key) {
      say(`  ${t.muted("Checking…")}\n`);
      const v = await verifyCredential("e2b", key);
      say(`  ${v.ok ? t.pass("✔") : t.fail("✘")} ${v.detail}\n`);
      if (!v.ok && !(await confirm("  Save it anyway?", false))) return null;
      config.sandbox = { provider: "e2b", apiKey: key };

      // E2B is the one adapter that still needs a package — its process
      // API is streaming RPC rather than a plain endpoint. Fetch it
      // here rather than sending the user away to run npm by hand: a
      // release tarball ships no node_modules, so without this the
      // sandbox reads as configured and fails at the first run.
      if (!hasPackage("e2b")) {
        const r = await ensurePackage("e2b", (m) => say(t.muted(m)));
        if (r.ok) {
          say(`  ${t.pass("✔")} E2B client ready\n`);
        } else {
          say(
            `  ${t.fail("✘")} Could not install it — ${r.detail ?? "unknown error"}\n` +
              `  ${t.muted("Key saved. Install it with")} ` +
              `${t.code(`npm install --prefix ${assayLibRoot()} e2b`)}${t.muted(", or use podman.")}\n`,
          );
        }
      }
    }
  }

  // ── Model ──────────────────────────────────────────────────────────
  const llm = await select<string>(
    t.bold("Which model should drive and judge behavioral runs?"),
    LLM_CHOICES.map((c) => ({ value: c.value as string, label: c.label, hint: t.muted(c.hint) })),
    { render: t.accent },
  );

  if (llm !== "skip") {
    let baseUrl: string | undefined;
    let key = "";
    if (llm === "local") {
      baseUrl = await ask("  Base URL", "http://localhost:11434/v1");
    } else {
      key = await askSecret(`  API key ${t.muted("(input hidden)")}`);
    }

    if (key || baseUrl) {
      say(`  ${t.muted("Checking…")}\n`);
      const v = await verifyCredential(llm, key, baseUrl);
      say(`  ${v.ok ? t.pass("✔") : t.fail("✘")} ${v.detail}\n`);
      if (!v.ok && !(await confirm("  Save it anyway?", false))) return null;

      const model = await ask("  Model", DEFAULT_MODELS[llm] ?? "");
      config.llm = {
        provider: llm as NonNullable<StoredConfig["llm"]>["provider"],
        ...(key ? { apiKey: key } : {}),
        ...(baseUrl ? { baseUrl } : {}),
        ...(model ? { model } : {}),
      };
    }
  }

  // ── The default ────────────────────────────────────────────────────
  //
  // Asked only when both halves are configured, because otherwise there
  // is nothing to default to. Recording the answer rather than inferring
  // it from a TTY check is the difference between a choice the user made
  // and one we made for them: it is greppable in the config file,
  // reported by `assay doctor`, and reversible by re-running this
  // wizard. Y is the default because someone who just configured a
  // sandbox and a model has already said what they want.
  if (config.llm && config.sandbox) {
    say(
      `\n  ${t.muted("Behavioral runs cost model tokens and add minutes. They are worth")}\n` +
        `  ${t.muted("it — static checks cannot tell whether an artifact does what it")}\n` +
        `  ${t.muted("claims — but it should be your call, not a surprise.")}\n` +
        `  ${t.muted("Either way, CI stays opt-in and `--no-behavioral` always skips.")}\n\n`,
    );
    config.behavioralByDefault = await confirm(
      "  Include behavioral evaluation in every `assay run`?",
    );
  }

  // ── Persist ────────────────────────────────────────────────────────
  const path = await saveStoredConfig(config);

  say(`\n  ${t.pass("Saved.")}\n\n`);
  say(`  ${t.muted("Location")}  ${path}\n`);
  say(`  ${t.muted("Mode")}      0600 ${t.muted("— readable only by you")}\n`);
  // Said plainly rather than buried: the key is in a file, in the clear.
  say(
    `  ${t.muted("Contents")}  ${t.warn("API keys are stored in plaintext.")} ${t.muted("Delete the file")}\n` +
      `            ${t.muted("to revoke, or use environment variables instead.")}\n\n`,
  );

  if (config.llm) {
    const shown = config.llm.apiKey ? maskSecret(config.llm.apiKey) : (config.llm.baseUrl ?? "");
    say(
      `  ${t.muted("Model")}     ${config.llm.provider} · ${config.llm.model ?? "default"} · ${shown}\n`,
    );
  }
  if (config.sandbox) {
    const shown = config.sandbox.apiKey ? ` · ${maskSecret(config.sandbox.apiKey)}` : "";
    say(`  ${t.muted("Sandbox")}   ${config.sandbox.provider}${shown}\n`);
  }

  const ready = Boolean(config.llm && config.sandbox);
  say(`\n  ${t.bold("Next")}\n`);
  if (ready && config.behavioralByDefault !== false) {
    // No second flag to type. That was the whole point of asking.
    say(
      `    ${t.code("assay run <path-or-url>")}${t.muted("  — full evaluation, behavioral included")}\n`,
    );
    say(
      `    ${t.code("assay run <path-or-url> --no-behavioral")}${t.muted("  — static only, seconds")}\n`,
    );
  } else if (ready) {
    say(
      `    ${t.code("assay run <path-or-url>")}${t.muted("  — deterministic checks, seconds")}\n`,
    );
    say(`    ${t.code("assay run <path-or-url> --behavioral")}${t.muted("  — full evaluation")}\n`);
  } else {
    say(
      `    ${t.code("assay run <path-or-url>")}${t.muted("  — deterministic checks, seconds")}\n`,
    );
    say(
      `    ${t.muted("Behavioral runs need both a sandbox and a model — rerun")} ${t.code("assay setup")}\n`,
    );
  }
  say("\n");

  return config;
}
