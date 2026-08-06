/**
 * The credential store.
 *
 * Two properties here are security properties rather than conveniences,
 * and both have bitten real tools:
 *
 * **The file must not be readable by anyone else.** Asserted against the
 * actual mode on disk, not against the flag we passed to `writeFile` —
 * an existing file keeps its old mode through a write, so the flag alone
 * does not prove anything.
 *
 * **The environment must win.** CI supplies secrets through the
 * environment; a stale file quietly overriding a rotated CI secret is a
 * failure that presents as "the key is wrong" and takes a day to find.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyStoredConfig,
  behavioralWanted,
  configIsPrivate,
  configPath,
  decideBehavioral,
  loadStoredConfig,
  maskSecret,
  resolveCredentials,
  saveStoredConfig,
  type StoredConfig,
} from "../src/credentials";

const dirs: string[] = [];
function sandboxEnv(): NodeJS.ProcessEnv {
  const dir = mkdtempSync(join(tmpdir(), "assay-cfg-"));
  dirs.push(dir);
  return { ASSAY_HOME: dir };
}

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const CONFIG: StoredConfig = {
  version: 1,
  llm: { provider: "anthropic", apiKey: "sk-ant-secret-value", model: "claude-sonnet-4-5" },
  sandbox: { provider: "e2b", apiKey: "e2b_key_value" },
};

describe("persistence", () => {
  it("round-trips a config", async () => {
    const env = sandboxEnv();
    await saveStoredConfig(CONFIG, env);
    const loaded = await loadStoredConfig(env);
    expect(loaded).toMatchObject({ llm: { provider: "anthropic" }, sandbox: { provider: "e2b" } });
  });

  it("stamps updatedAt", async () => {
    const env = sandboxEnv();
    await saveStoredConfig(CONFIG, env);
    expect((await loadStoredConfig(env))?.updatedAt).toMatch(/^\d{4}-/);
  });

  it("writes the file readable only by its owner", async () => {
    const env = sandboxEnv();
    const path = await saveStoredConfig(CONFIG, env);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(await configIsPrivate(env)).toBe(true);
  });

  // `writeFile`'s mode applies only on creation, so a pre-existing
  // world-readable file would silently keep its mode without the chmod.
  it("tightens the mode of a pre-existing loose file", async () => {
    const env = sandboxEnv();
    const path = configPath(env);
    writeFileSync(path, "{}");
    chmodSync(path, 0o644);
    await saveStoredConfig(CONFIG, env);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("returns null when there is no config", async () => {
    expect(await loadStoredConfig(sandboxEnv())).toBeNull();
  });

  it("returns null for malformed JSON rather than throwing at startup", async () => {
    const env = sandboxEnv();
    writeFileSync(configPath(env), "{ not json");
    expect(await loadStoredConfig(env)).toBeNull();
  });

  it("rejects a config from an unknown schema version", async () => {
    const env = sandboxEnv();
    writeFileSync(configPath(env), JSON.stringify({ version: 99, llm: {} }));
    expect(await loadStoredConfig(env)).toBeNull();
  });
});

describe("precedence", () => {
  it("prefers an environment key over a stored one", () => {
    const r = resolveCredentials(CONFIG, { OPENAI_API_KEY: "x" });
    expect(r.llmProvider).toBe("openai");
    expect(r.source.llm).toBe("env");
  });

  it("falls back to the stored provider when the environment is bare", () => {
    const r = resolveCredentials(CONFIG, {});
    expect(r.llmProvider).toBe("anthropic");
    expect(r.source.llm).toBe("config");
  });

  it("reports nothing configured when neither has anything", () => {
    expect(resolveCredentials(null, {})).toMatchObject({
      llmProvider: null,
      sandbox: null,
      source: { llm: null, sandbox: null },
    });
  });

  it("lets an E2B key in the environment select the sandbox", () => {
    const stored: StoredConfig = { version: 1, sandbox: { provider: "podman" } };
    expect(resolveCredentials(stored, { E2B_API_KEY: "k" }).sandbox).toBe("e2b");
  });
});

/**
 * Whether a plain `assay run` includes the behavioral tier.
 *
 * The product complaint was real: `assay setup` configures a sandbox and
 * a model, `assay doctor` shows two green ticks, and then the tool still
 * demanded `--behavioral --transcripts ./transcripts` on every run. That
 * is making the user say yes twice.
 *
 * The reason it was ever opt-in is also real, and is the one thing here
 * that must not be traded away: a behavioral run costs model tokens and
 * adds minutes, and CI runs on every commit. So the answer differs in
 * exactly one place — whether a human is watching.
 */
describe("decideBehavioral", () => {
  const tty = { interactive: true };
  const ci = { interactive: false };

  it("runs by default in a terminal once setup has been through", () => {
    expect(decideBehavioral(tty)).toBe("default");
    expect(behavioralWanted(decideBehavioral(tty))).toBe(true);
  });

  // The guard. A pipeline that has credentials because somebody set them
  // once must not silently start billing per commit.
  it("stays opt-in without a terminal", () => {
    expect(decideBehavioral(ci)).toBe("non-interactive");
    expect(behavioralWanted(decideBehavioral(ci))).toBe(false);
  });

  it("still runs in CI when asked for by name", () => {
    expect(decideBehavioral({ ...ci, flag: true })).toBe("requested");
    expect(behavioralWanted(decideBehavioral({ ...ci, flag: true }))).toBe(true);
  });

  it("--no-behavioral wins everywhere, including a configured terminal", () => {
    for (const preference of [undefined, true, false]) {
      expect(decideBehavioral({ ...tty, flag: false, preference })).toBe("declined");
      expect(decideBehavioral({ ...ci, flag: false, preference })).toBe("declined");
    }
  });

  it("--behavioral beats a stored opt-out", () => {
    expect(decideBehavioral({ ...tty, flag: true, preference: false })).toBe("requested");
  });

  it("honours a recorded opt-out when no flag was given", () => {
    expect(decideBehavioral({ ...tty, preference: false })).toBe("opted-out");
    expect(behavioralWanted(decideBehavioral({ ...tty, preference: false }))).toBe(false);
  });

  // A credential file that happens to exist on a runner is not consent
  // to bill that runner, so the stored yes does not reach past the TTY
  // check. Only the flag does.
  it("does not let a stored yes override the CI guard", () => {
    expect(decideBehavioral({ ...ci, preference: true })).toBe("non-interactive");
  });

  it("treats an unanswered preference as yes — setup was the opt-in", () => {
    expect(decideBehavioral({ ...tty, preference: undefined })).toBe("default");
  });
});

describe("applyStoredConfig", () => {
  it("fills empty variables from the stored config", () => {
    const env: NodeJS.ProcessEnv = {};
    applyStoredConfig(CONFIG, env);
    expect(env["ANTHROPIC_API_KEY"]).toBe("sk-ant-secret-value");
    expect(env["EVAL_ANTHROPIC_MODEL"]).toBe("claude-sonnet-4-5");
    expect(env["E2B_API_KEY"]).toBe("e2b_key_value");
  });

  it("never overwrites a variable that is already set", () => {
    const env: NodeJS.ProcessEnv = { ANTHROPIC_API_KEY: "from-ci" };
    applyStoredConfig(CONFIG, env);
    expect(env["ANTHROPIC_API_KEY"]).toBe("from-ci");
  });

  it("maps a local provider to its base URL", () => {
    const env: NodeJS.ProcessEnv = {};
    applyStoredConfig(
      { version: 1, llm: { provider: "local", baseUrl: "http://x/v1", model: "llama3.1" } },
      env,
    );
    expect(env["LOCAL_LLM_BASE_URL"]).toBe("http://x/v1");
    expect(env["LOCAL_LLM_MODEL"]).toBe("llama3.1");
  });

  it("does nothing for a null config", () => {
    const env: NodeJS.ProcessEnv = {};
    applyStoredConfig(null, env);
    expect(Object.keys(env)).toHaveLength(0);
  });

  it("does not set a podman key, because there is none", () => {
    const env: NodeJS.ProcessEnv = {};
    applyStoredConfig({ version: 1, sandbox: { provider: "podman" } }, env);
    expect(env["E2B_API_KEY"]).toBeUndefined();
  });
});

describe("maskSecret", () => {
  it("shows only the last four characters", () => {
    expect(maskSecret("sk-ant-api03-abcdefgh")).toBe("••••••••efgh");
  });

  // A short secret has too little entropy left to reveal any of it.
  it("reveals nothing at all from a short secret", () => {
    expect(maskSecret("abc123")).toBe("••••••");
  });
});
