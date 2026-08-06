/**
 * Onboarding: `doctor`, `init`, and the next-steps footer.
 *
 * These exist because of a concrete failure in use. A first run printed
 * `behavior  n/a  0% measured` and stopped — the headline capability of
 * the framework sitting at zero, with nothing on screen saying which
 * flag or which environment variable would change that. The reader had
 * to go read a README to discover the tool could do the thing it is
 * for.
 *
 * So the assertions here are about whether the output TEACHES, not
 * whether it is correct. Correct and useless was the starting state.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readEnvState, renderSuggestions, suggestNextSteps } from "../src/guidance";
import { cli } from "../src/cli";
import { scoreReport } from "../src/score";
import type { AssayReport, CheckReport } from "../src/types";

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "assay-guidance-"));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const results: CheckReport[] = [
  {
    checkId: "description-quality",
    checkVersion: "1.0.0",
    title: "Description",
    category: "documentation",
    determinism: "deterministic",
    weight: 3,
    axis: "care",
    status: "warn",
    summary: "thin",
    remediation: "Say what it does and when to use it.",
  },
  {
    checkId: "deps-no-known-vulns",
    checkVersion: "1.0.0",
    title: "Vulns",
    category: "supply-chain",
    determinism: "sampled",
    weight: 4,
    axis: "safety",
    status: "skip",
    summary: "Not run — requires net, unavailable in this environment.",
  },
];

const report = (over: Partial<AssayReport> = {}): AssayReport => {
  const effective = over.results ?? results;
  return {
    schemaVersion: "1",
    subject: {
      kind: "skill",
      name: "demo",
      source: { type: "directory", path: "." },
      digest: { sha256: "a".repeat(64) },
    },
    suite: { id: "t", version: "1.0.0", checksDigest: "d" },
    environment: { runner: "assay/test" },
    startedAt: "2026-08-01T00:00:00.000Z",
    finishedAt: "2026-08-01T00:01:00.000Z",
    ...over,
    results: effective,
    score: scoreReport(effective),
  };
};

describe("readEnvState", () => {
  it("recognises each supported provider", () => {
    expect(readEnvState({ ANTHROPIC_API_KEY: "x" })).toMatchObject({
      hasModelKey: true,
      modelHint: "anthropic",
    });
    expect(readEnvState({ LOCAL_LLM_BASE_URL: "http://x" }).modelHint).toBe("local");
  });

  it("reports nothing configured honestly", () => {
    expect(readEnvState({})).toMatchObject({ hasModelKey: false, modelHint: null });
  });

  it("notices a cloud sandbox key", () => {
    expect(readEnvState({ E2B_API_KEY: "x" }).sandboxHint).toBe("e2b");
  });
});

describe("suggestNextSteps", () => {
  const opts = { ranBehavioral: false, artifactPath: "./my-skill", hasTranscripts: false };

  // The failure this whole module exists to fix.
  it("leads with the unmeasured behavior axis", () => {
    const s = suggestNextSteps(report(), readEnvState({}), opts);
    expect(s[0]!.title).toMatch(/behavior axis/);
  });

  // Pointing at `assay setup` rather than a raw `export` matters: setup
  // verifies the key before saving it and persists it, so the question
  // does not come back on the next shell.
  it("sends an unconfigured user to setup, not to a raw export", () => {
    const s = suggestNextSteps(report(), readEnvState({}), opts);
    expect(s[0]!.command).toMatch(/assay setup/);
    // And NOT back to `--behavioral` afterwards. Setup is the opt-in;
    // asking for the flag on top of it is the "say yes twice" that
    // default-on exists to remove.
    expect(s[0]!.command).not.toMatch(/--behavioral/);
    expect(s[0]!.why).toMatch(/by default/);
  });

  it("skips the export line when a key is already set, and says which", () => {
    const s = suggestNextSteps(report(), readEnvState({ OPENAI_API_KEY: "x" }), opts);
    expect(s[0]!.command).not.toMatch(/export/);
    expect(s[0]!.why).toMatch(/openai/);
  });

  it("stops suggesting behavioral once it has run", () => {
    const s = suggestNextSteps(report(), readEnvState({}), { ...opts, ranBehavioral: true });
    expect(s.some((x) => /behavior axis/.test(x.title))).toBe(false);
  });

  // A verdict nobody can re-derive is the thing this project is against.
  it("pushes for transcripts when a behavioral run had none", () => {
    const s = suggestNextSteps(report(), readEnvState({}), { ...opts, ranBehavioral: true });
    expect(s[0]!.title).toMatch(/Record transcripts/);
  });

  it("names the checks that were skipped for want of network", () => {
    const s = suggestNextSteps(report(), readEnvState({}), opts);
    const net = s.find((x) => /network access/.test(x.title));
    expect(net?.why).toMatch(/deps-no-known-vulns/);
  });

  it("points at the most serious finding, not an arbitrary one", () => {
    const withBlocking: CheckReport[] = [
      ...results,
      {
        checkId: "no-sensitive-files",
        checkVersion: "1.0.0",
        title: "Secrets",
        category: "safety",
        determinism: "deterministic",
        weight: 5,
        axis: "safety",
        blocking: true,
        status: "fail",
        summary: "leaked",
        remediation: "Remove and rotate it.",
      },
    ];
    const s = suggestNextSteps(report({ results: withBlocking }), readEnvState({}), opts);
    expect(s.find((x) => /Fix/.test(x.title))?.title).toMatch(/no-sensitive-files/);
  });

  it("suggests regression tracking when there is room", () => {
    const s = suggestNextSteps(report(), readEnvState({}), opts);
    expect(s.some((x) => /Track this over time/.test(x.title))).toBe(true);
  });
});

/**
 * The advice has to explain the decision the run actually made.
 *
 * Before behavioral could run by default there was one answer — "pass
 * --behavioral" — and it was right in every case. Now it is wrong in
 * most of them: redundant for someone who just turned it off on purpose,
 * misleading for someone whose pipeline has no terminal, and pointless
 * for someone who has configured nothing yet.
 */
describe("suggestNextSteps explains WHY behavior went unmeasured", () => {
  const base = { ranBehavioral: false, artifactPath: "./my-skill", hasTranscripts: false };
  const configured = readEnvState({ OPENROUTER_API_KEY: "x" });

  it("tells a user who typed --no-behavioral to drop the flag, not add one", () => {
    const s = suggestNextSteps(report(), configured, { ...base, behavioral: "declined" });
    expect(s[0]!.title).toMatch(/behavior axis/);
    expect(s[0]!.command).not.toMatch(/--behavioral/);
    expect(s[0]!.command).toBe("assay run ./my-skill --transcripts ./transcripts");
    expect(s[0]!.why).toMatch(/no-behavioral/);
  });

  // The guard, stated where somebody will actually read it.
  it("explains the CI carve-out rather than just naming a flag", () => {
    const s = suggestNextSteps(report(), configured, { ...base, behavioral: "non-interactive" });
    expect(s[0]!.command).toMatch(/--behavioral/);
    expect(s[0]!.why).toMatch(/terminal/);
    expect(s[0]!.why).toMatch(/opt-in/);
  });

  it("names the stored preference when that is what turned it off", () => {
    const s = suggestNextSteps(report(), configured, { ...base, behavioral: "opted-out" });
    expect(s[0]!.why).toMatch(/behavioralByDefault/);
    expect(s[0]!.why).toMatch(/assay setup/);
  });

  // A model key but no sandbox is a different problem from no model at
  // all, and "pass --behavioral" would not fix it.
  it("points at the sandbox when the model is already configured", () => {
    const s = suggestNextSteps(report(), configured, { ...base, behavioral: "unavailable" });
    expect(s[0]!.why).toMatch(/sandbox/);
    expect(s[0]!.why).toMatch(/assay doctor/);
  });

  // Quoting a flag the reader never typed reads as "you did this wrong".
  it("does not quote --behavioral back at a run that never asked for it", () => {
    const s = suggestNextSteps(report(), configured, {
      ...base,
      ranBehavioral: true,
      behavioral: "default",
    });
    const transcripts = s.find((x) => /Record transcripts/.test(x.title));
    expect(transcripts?.command).toBe("assay run ./my-skill --transcripts ./transcripts");
  });

  it("keeps the flag for a run that did ask for it", () => {
    const s = suggestNextSteps(report(), configured, {
      ...base,
      ranBehavioral: true,
      behavioral: "requested",
    });
    const transcripts = s.find((x) => /Record transcripts/.test(x.title));
    expect(transcripts?.command).toMatch(/--behavioral/);
  });

  /**
   * The property this must never lose.
   *
   * The rule that "an unmeasured axis outranks a missing homepage field"
   * once produced "run it in a container and see what it does" as the
   * FIRST advice for an artifact whose confirmed findings included
   * `curl … | bash` to a hardcoded IP. Default-on behavioral gives the
   * tool a way to do that instead of merely saying it, so the guard is
   * asserted from both sides.
   */
  it("never suggests running an artifact a blocking safety check condemned", () => {
    const malicious: CheckReport[] = [
      ...results,
      {
        checkId: "no-remote-code-execution",
        checkVersion: "1.0.0",
        title: "RCE",
        category: "safety",
        determinism: "deterministic",
        weight: 5,
        axis: "safety",
        blocking: true,
        status: "fail",
        summary: "curl | bash to a hardcoded IP",
        remediation: "Remove it.",
      },
    ];
    for (const behavioral of ["declined", "non-interactive", "default", "unavailable"] as const) {
      const s = suggestNextSteps(report({ results: malicious }), configured, {
        ...base,
        behavioral,
      });
      expect(s.some((x) => /behavior axis/.test(x.title))).toBe(false);
      expect(s[0]!.title).toMatch(/^Fix /);
    }
  });
});

describe("renderSuggestions", () => {
  it("renders nothing for an empty list", () => {
    expect(renderSuggestions([])).toBe("");
  });

  it("indents continuation lines so a multi-step command stays aligned", () => {
    const out = renderSuggestions([{ title: "t", command: "one\ntwo" }]);
    const lines = out.split("\n");
    const first = lines.find((l) => l.includes("$ one"))!;
    const second = lines.find((l) => l.trimStart() === "two")!;
    // Both indented into the block, rather than the second falling out
    // to the left margin.
    expect(second.startsWith("        ")).toBe(true);
    expect(first.startsWith("      $")).toBe(true);
  });

  it("wraps long rationale rather than running off the terminal", () => {
    const out = renderSuggestions([{ title: "t", why: "word ".repeat(40).trim() }]);
    for (const line of out.split("\n")) expect(line.length).toBeLessThan(90);
  });
});

describe("the onboarding commands", () => {
  let out: string;
  let err: string;
  const capture = () => {
    out = "";
    err = "";
    const so = process.stdout.write.bind(process.stdout);
    const se = process.stderr.write.bind(process.stderr);
    process.stdout.write = ((s: string) => ((out += s), true)) as typeof process.stdout.write;
    process.stderr.write = ((s: string) => ((err += s), true)) as typeof process.stderr.write;
    return () => {
      process.stdout.write = so;
      process.stderr.write = se;
    };
  };

  // Answering a bare invocation with "could not determine the artifact
  // kind for .." is a hostile first impression for a tool whose whole
  // job is to be trusted.
  it("answers a bare invocation with usage, not an error", async () => {
    const restore = capture();
    const code = await cli([]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/USAGE/);
    expect(out).toMatch(/assay doctor/);
    expect(err).toBe("");
  });

  // Doctor shells out to probe container runtimes, so this is not a
  // 5ms unit test. On a CI runner with Docker installed but idle, the
  // probe waits out its full budget — the default 5s timeout made this
  // fail for a reason that has nothing to do with what it asserts.
  it("doctor reports what is and is not available", { timeout: 20_000 }, async () => {
    const restore = capture();
    const code = await cli(["doctor"]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/static checks/);
    expect(out).toMatch(/behavioral evaluation/);
    expect(out).toMatch(/signing/);
    // Static checks always work; doctor must say so plainly.
    expect(out).toMatch(/no credentials needed/);
  });

  it("init scaffolds a config and an example eval file", async () => {
    const target = join(dir, "proj");
    mkdirSync(target, { recursive: true });
    const restore = capture();
    const code = await cli(["init", target]);
    restore();
    expect(code).toBe(0);
    const cfg = JSON.parse(readFileSync(join(target, "assay.config.json"), "utf8"));
    expect(cfg).toHaveProperty("settings");
    const evals = JSON.parse(readFileSync(join(target, "evals", "basic.json"), "utf8"));
    expect(evals[0]).toHaveProperty("prompt");
    expect(evals[0]).toHaveProperty("expect");
  });

  it("init never overwrites what is already there", async () => {
    const target = join(dir, "existing");
    mkdirSync(target, { recursive: true });
    writeFileSync(join(target, "assay.config.json"), '{"suite":"mine"}');
    const restore = capture();
    await cli(["init", target]);
    restore();
    expect(JSON.parse(readFileSync(join(target, "assay.config.json"), "utf8")).suite).toBe("mine");
    expect(out).toMatch(/already exists/);
  });
});
