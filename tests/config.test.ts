/**
 * Config, waivers, SARIF, and diff.
 *
 * The waiver tests carry the most weight. A waiver is an escape hatch
 * in a tool whose value depends on not having one, so the design is
 * that it must be *expensive to abuse* rather than merely available:
 * the reason is mandatory and published, the finding becomes `neutral`
 * rather than vanishing, and an expiry actually expires.
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, parseConfig, waiverFor } from "../src/config";
import { applyWaiver, runAssay } from "../src/run";
import { diffReports, toSarif } from "../src/formats";
import { scoreReport } from "../src/score";
import { isIgnored, loadIgnoreRules } from "../src/checks/gitignore";
import { CheckRegistry, defineCheck } from "../src/check";
import { cli } from "../src/cli";
import { MemorySource } from "../src/sources/memory";
import type { AssayReport, CheckReport, CheckResult, Subject } from "../src/types";

let root: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "assay-config-"));
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("parseConfig", () => {
  it("accepts a well-formed config", () => {
    const c = parseConfig(
      JSON.stringify({
        settings: { docsMinWords: 100 },
        disable: ["usage-examples"],
        suite: "mine",
        minScore: 70,
        waivers: [{ check: "no-install-scripts", reason: "Native module needs node-gyp." }],
      }),
    );
    expect(c.settings).toEqual({ docsMinWords: 100 });
    expect(c.disable).toEqual(["usage-examples"]);
    expect(c.minScore).toBe(70);
    expect(c.waivers).toHaveLength(1);
  });

  // A waiver nobody has to justify is an off switch.
  it("REFUSES a waiver with no reason", () => {
    expect(() => parseConfig(JSON.stringify({ waivers: [{ check: "x" }] }))).toThrow(/reason/);
  });

  it("refuses a waiver whose reason is too thin to be useful", () => {
    expect(() =>
      parseConfig(JSON.stringify({ waivers: [{ check: "x", reason: "nope" }] })),
    ).toThrow(/at least 10 characters/);
  });

  it("refuses a waiver with no check id", () => {
    expect(() =>
      parseConfig(JSON.stringify({ waivers: [{ reason: "a perfectly good reason here" }] })),
    ).toThrow(/missing "check"/);
  });

  it("throws on malformed JSON rather than falling back to defaults", () => {
    expect(() => parseConfig("{oops")).toThrow(/not valid JSON/);
  });

  it("throws when the top level is not an object", () => {
    expect(() => parseConfig("[]")).toThrow(/must contain a JSON object/);
  });
});

describe("loadConfig", () => {
  it("walks up from the artifact, so a monorepo can set policy at the root", async () => {
    const nested = join(root, "packages", "thing");
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(root, "assay.config.json"), JSON.stringify({ suite: "root-policy" }));
    const loaded = await loadConfig(nested);
    expect(loaded.config.suite).toBe("root-policy");
    expect(loaded.path).toBe(join(root, "assay.config.json"));
  });

  it("returns empty defaults when there is no config anywhere", async () => {
    const bare = mkdtempSync(join(tmpdir(), "assay-bare-"));
    const loaded = await loadConfig(bare);
    expect(loaded).toEqual({ config: {}, path: null });
    rmSync(bare, { recursive: true, force: true });
  });

  // The bug this guards: wrapping the read and the parse in one try
  // made a malformed config indistinguishable from a missing one, so a
  // broken policy file was silently skipped.
  it("PROPAGATES a malformed config instead of silently skipping it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-bad-cfg-"));
    writeFileSync(join(dir, "assay.config.json"), "{oops");
    await expect(loadConfig(dir)).rejects.toThrow(/not valid JSON/);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("waiverFor", () => {
  const config = parseConfig(
    JSON.stringify({
      waivers: [
        { check: "live", reason: "This one is deliberate and reviewed." },
        { check: "old", reason: "Was deliberate at the time.", expires: "2020-01-01" },
      ],
    }),
  );

  it("finds a live waiver", () => {
    expect(waiverFor(config, "live")?.expired).toBe(false);
  });

  it("reports an expired waiver as expired rather than absent", () => {
    expect(waiverFor(config, "old")?.expired).toBe(true);
  });

  it("returns null for an unwaived check", () => {
    expect(waiverFor(config, "other")).toBeNull();
  });
});

describe("applyWaiver", () => {
  const policy = parseConfig(
    JSON.stringify({
      waivers: [{ check: "c", reason: "Deliberate: native build step, reviewed 2026-08." }],
    }),
  );
  const failing: CheckResult = { status: "fail", summary: "found a thing" };

  it("turns a finding NEUTRAL and publishes the reason", () => {
    const out = applyWaiver("c", failing, policy, Date.now());
    expect(out.status).toBe("neutral");
    // Not dropped: a reader sees the judgement was excused, and by what
    // argument, and can weigh that themselves.
    expect(out.summary).toMatch(/^Waived:/);
    expect(out.detail).toMatch(/native build step/);
  });

  it("preserves the evidence, so the finding stays inspectable", () => {
    const withEvidence: CheckResult = {
      ...failing,
      evidence: [{ type: "file", path: "package.json" }],
    };
    expect(applyWaiver("c", withEvidence, policy, Date.now()).evidence).toHaveLength(1);
  });

  it("waives a warn as well as a fail", () => {
    expect(applyWaiver("c", { status: "warn", summary: "s" }, policy, Date.now()).status).toBe(
      "neutral",
    );
  });

  it("does NOT waive our own error — that would hide our failure behind their excuse", () => {
    expect(applyWaiver("c", { status: "error", summary: "s" }, policy, Date.now()).status).toBe(
      "error",
    );
  });

  it("leaves a pass alone", () => {
    expect(applyWaiver("c", { status: "pass", summary: "s" }, policy, Date.now()).status).toBe(
      "pass",
    );
  });

  it("stops excusing once the waiver expires, and says so", () => {
    const expiring = parseConfig(
      JSON.stringify({
        waivers: [
          { check: "c", reason: "Temporary, pending the 2.0 refactor.", expires: "2020-01-01" },
        ],
      }),
    );
    const out = applyWaiver("c", failing, expiring, Date.now());
    expect(out.status).toBe("fail");
    expect(out.detail).toMatch(/expired on 2020-01-01/);
  });

  it("is a no-op without a policy", () => {
    expect(applyWaiver("c", failing, undefined, Date.now())).toBe(failing);
  });
});

describe("runAssay honours policy", () => {
  const subject: Subject = {
    kind: "skill",
    name: "demo",
    source: { type: "directory", path: "." },
    digest: { sha256: "0".repeat(64) },
  };
  const failing = defineCheck({
    id: "always-fails",
    version: "1.0.0",
    title: "Always fails",
    category: "safety",
    axis: "safety",
    determinism: "deterministic",
    run: () => ({ status: "fail" as const, summary: "nope" }),
  });

  const run = (policy?: Parameters<typeof runAssay>[0]["policy"]) =>
    runAssay({
      subject,
      source: new MemorySource({ "a.txt": "x" }),
      registry: CheckRegistry.from([failing]),
      suite: { id: "t", version: "1.0.0" },
      environment: { runner: "assay/test" },
      ...(policy ? { policy } : {}),
    });

  it("applies waivers during the run, so every consumer gets them", async () => {
    const report = await run(
      parseConfig(
        JSON.stringify({
          waivers: [{ check: "always-fails", reason: "Known and accepted for now." }],
        }),
      ),
    );
    expect(report.results[0]!.status).toBe("neutral");
  });

  /**
   * A disabled check must still appear in the report.
   *
   * This test previously asserted the opposite — `toHaveLength(0)` —
   * and so codified the hole. Filtering the check out before the run
   * deleted its failure, raised the overall score, flipped the exit
   * code to 0, and produced a report that `assay verify` accepts
   * (verification recomputes the score from the results that survived).
   * `assay diff` then classified the deletion as `removed` rather than
   * a regression and also exited 0. Every downstream consistency check
   * agreed with the publisher.
   *
   * It sits beside a waiver system designed so that an excuse must be
   * published and must expire. An unlogged off-switch beside it defeats
   * that entirely.
   */
  it("records a disabled check rather than deleting it", async () => {
    const report = await run(parseConfig(JSON.stringify({ disable: ["always-fails"] })));
    expect(report.results).toHaveLength(1);
    expect(report.results[0]).toMatchObject({
      checkId: "always-fails",
      status: "neutral",
    });
  });

  it("says the check was disabled, and that no reason was given", async () => {
    const report = await run(parseConfig(JSON.stringify({ disable: ["always-fails"] })));
    expect(report.results[0]!.summary).toMatch(/[Dd]isabled by policy/);
    expect(report.results[0]!.detail).toMatch(/no stated reason and no expiry/);
  });

  // The point of recording it: a consumer diffing two reports sees the
  // check stop producing a verdict instead of seeing it vanish.
  it("leaves a disabled check visible to a diff", async () => {
    const before = await run(parseConfig("{}"));
    const after = await run(parseConfig(JSON.stringify({ disable: ["always-fails"] })));
    const d = diffReports(before, after);
    expect(d.removed).toHaveLength(0);
    expect(before.results[0]!.status).toBe("fail");
    expect(after.results[0]!.status).toBe("neutral");
  });
});

// ── SARIF ────────────────────────────────────────────────────────────

const results: CheckReport[] = [
  {
    checkId: "blocking-fail",
    checkVersion: "1.0.0",
    title: "Blocking",
    category: "safety",
    determinism: "deterministic",
    weight: 5,
    axis: "safety",
    blocking: true,
    status: "fail",
    summary: "leaked",
    remediation: "rotate it",
    evidence: [{ type: "file", path: ".env", line: 3 }],
    spec: "https://assay.dev/checks/x",
  },
  {
    checkId: "soft-warn",
    checkVersion: "1.0.0",
    title: "Soft",
    category: "care",
    determinism: "deterministic",
    weight: 1,
    axis: "care",
    status: "warn",
    summary: "thin",
  },
  {
    checkId: "our-error",
    checkVersion: "1.0.0",
    title: "Errored",
    category: "behavioral",
    determinism: "sampled",
    weight: 1,
    axis: "behavior",
    status: "error",
    summary: "sandbox died",
  },
  {
    checkId: "fine",
    checkVersion: "1.0.0",
    title: "Fine",
    category: "safety",
    determinism: "deterministic",
    weight: 1,
    axis: "safety",
    status: "pass",
    summary: "ok",
  },
];

function report(over: Partial<AssayReport> = {}): AssayReport {
  // The score is derived from the EFFECTIVE results, after the
  // override. Computing it from the outer constant first meant a
  // fixture with modified results still carried the original score,
  // so a score-delta assertion could never move.
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
}

describe("SARIF", () => {
  const sarif = () => JSON.parse(toSarif(report(), { toolVersion: "0.1.0" }));

  it("emits valid SARIF 2.1.0 with a driver and rules", () => {
    const s = sarif();
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0].tool.driver.name).toBe("assay");
    expect(s.runs[0].tool.driver.rules).toHaveLength(4);
  });

  // Emitting a row per pass buries the findings and gets the
  // integration muted.
  it("reports only findings, not passes", () => {
    expect(sarif().runs[0].results).toHaveLength(3);
  });

  it("maps a blocking failure to error and a soft one to warning", () => {
    const byRule = Object.fromEntries(
      sarif().runs[0].results.map((r: { ruleId: string; level: string }) => [r.ruleId, r.level]),
    );
    expect(byRule["blocking-fail"]).toBe("error");
    expect(byRule["soft-warn"]).toBe("warning");
  });

  // Our outage must not put a red mark on someone's pull request.
  it("maps OUR error to a note, not an error", () => {
    const byRule = Object.fromEntries(
      sarif().runs[0].results.map((r: { ruleId: string; level: string }) => [r.ruleId, r.level]),
    );
    expect(byRule["our-error"]).toBe("note");
  });

  it("anchors a finding to its file and line", () => {
    const first = sarif().runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === "blocking-fail",
    );
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe(".env");
    expect(first.locations[0].physicalLocation.region.startLine).toBe(3);
  });

  it("still gives a location to a finding with no file evidence", () => {
    // SARIF requires one; without it the result is dropped silently.
    const soft = sarif().runs[0].results.find((r: { ruleId: string }) => r.ruleId === "soft-warn");
    expect(soft.locations).toHaveLength(1);
  });

  it("carries the remediation into the message", () => {
    const first = sarif().runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === "blocking-fail",
    );
    expect(first.message.text).toMatch(/rotate it/);
  });
});

// ── diff ─────────────────────────────────────────────────────────────

describe("diffReports", () => {
  const worse = (): AssayReport =>
    report({
      results: results.map((r) => (r.checkId === "fine" ? { ...r, status: "fail" as const } : r)),
    });

  // `safety` is already floored by the blocking failure in the fixture,
  // so a further safety regression cannot move the score. Regress
  // `care` instead when the delta itself is what is under test.
  const careWorse = (): AssayReport =>
    report({
      results: results.map((r) =>
        r.checkId === "soft-warn" ? { ...r, status: "fail" as const } : r,
      ),
    });

  it("identifies a regression and its direction", () => {
    const d = diffReports(report(), worse());
    expect(d.regressions.map((r) => r.checkId)).toEqual(["fine"]);
    expect(d.regressions[0]).toMatchObject({ from: "pass", to: "fail", regression: true });
    expect(d.improvements).toHaveLength(0);
  });

  it("identifies an improvement", () => {
    const d = diffReports(worse(), report());
    expect(d.improvements.map((r) => r.checkId)).toEqual(["fine"]);
    expect(d.regressions).toHaveLength(0);
  });

  it("tracks added and removed checks", () => {
    const fewer = report({ results: results.slice(0, 2) });
    const d = diffReports(fewer, report());
    expect(d.added.map((r) => r.checkId)).toEqual(["our-error", "fine"]);
    expect(diffReports(report(), fewer).removed).toHaveLength(2);
  });

  // If the bytes are identical, any verdict change came from US.
  it("flags when the subject is unchanged, so drift is attributable", () => {
    expect(diffReports(report(), worse()).sameSubject).toBe(true);
    const other = report({
      subject: { ...report().subject, digest: { sha256: "b".repeat(64) } },
    });
    expect(diffReports(report(), other).sameSubject).toBe(false);
  });

  it("reports the score delta", () => {
    const d = diffReports(report(), careWorse());
    expect(d.scoreDelta).toBeLessThan(0);
  });

  /**
   * The name of this test used to be right and the assertion wrong: the
   * fixture moves `pass` → `skip`, which is judging → non-judging, and
   * it asserted an *improvement*. A failing check that stops running
   * therefore read as the artifact getting better. That is now
   * `coverageLost` (see below); a move between two genuinely non-judging
   * statuses is what "neither" was always meant to describe.
   */
  it("treats a move between non-judging statuses as neither", () => {
    const from = report({
      results: results.map((r) => (r.checkId === "fine" ? { ...r, status: "skip" as const } : r)),
    });
    const to = report({
      results: results.map((r) =>
        r.checkId === "fine" ? { ...r, status: "neutral" as const } : r,
      ),
    });
    const d = diffReports(from, to);
    expect(d.regressions).toHaveLength(0);
    expect(d.improvements).toHaveLength(0);
    expect(d.coverageLost).toHaveLength(0);
  });
});

describe("the CLI surface for policy and formats", () => {
  let dir: string;
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

  const CLEAN_SKILL =
    "---\nname: ok\ndescription: Use when the user wants tidy markdown tables from raw text\nallowed-tools: []\n---\n# OK\n" +
    "word ".repeat(80);

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-cli-policy-"));
    writeFileSync(join(dir, "SKILL.md"), CLEAN_SKILL);
    writeFileSync(join(dir, "LICENSE"), "MIT");
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("lists every check grouped by axis", async () => {
    const restore = capture();
    const code = await cli(["list"]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/integrity/);
    expect(out).toMatch(/no-sensitive-files/);
    expect(out).toMatch(/checks\./);
  });

  it("explains a check, including whether it is blocking", async () => {
    const restore = capture();
    const code = await cli(["explain", "no-sensitive-files"]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/blocking\s+yes/);
    expect(out).toMatch(/github\.com\/[^/]+\/assay\/blob\/main\/docs\/CHECKS\.md#/);
  });

  it("says so, helpfully, for an unknown check id", async () => {
    const restore = capture();
    const code = await cli(["explain", "nope"]);
    restore();
    expect(code).toBe(2);
    expect(err).toMatch(/assay list/);
  });

  it("emits SARIF when asked", async () => {
    const restore = capture();
    await cli(["run", dir, "--sarif"]);
    restore();
    const s = JSON.parse(out) as {
      version: string;
      runs: { tool: { driver: { name: string } } }[];
    };
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0]!.tool.driver.name).toBe("assay");
  });

  it("honours a config file found by walking up", async () => {
    writeFileSync(join(dir, "assay.config.json"), JSON.stringify({ suite: "house-style" }));
    const restore = capture();
    await cli(["run", dir, "--json"]);
    restore();
    expect((JSON.parse(out) as AssayReport).suite.id).toBe("house-style");
    rmSync(join(dir, "assay.config.json"));
  });

  it("--no-config ignores a config that is present", async () => {
    writeFileSync(join(dir, "assay.config.json"), JSON.stringify({ suite: "house-style" }));
    const restore = capture();
    await cli(["run", dir, "--json", "--no-config"]);
    restore();
    expect((JSON.parse(out) as AssayReport).suite.id).not.toBe("house-style");
    rmSync(join(dir, "assay.config.json"));
  });

  it("exits 2 on a malformed config rather than scoring against defaults", async () => {
    writeFileSync(join(dir, "assay.config.json"), "{oops");
    const restore = capture();
    const code = await cli(["run", dir]);
    restore();
    expect(code).toBe(2);
    expect(err).toMatch(/not valid JSON/);
    rmSync(join(dir, "assay.config.json"));
  });

  it("fails the run when the score is below a configured minimum", async () => {
    writeFileSync(join(dir, "assay.config.json"), JSON.stringify({ minScore: 99.9 }));
    const restore = capture();
    const code = await cli(["run", dir]);
    restore();
    expect(code).toBe(1);
    expect(err).toMatch(/is below the minimum 99\.9/);
    rmSync(join(dir, "assay.config.json"));
  });

  it("diffs two reports and exits 1 on a regression", async () => {
    const before = join(dir, "before.json");
    const after = join(dir, "after.json");
    let restore = capture();
    await cli(["run", dir, "--json"]);
    restore();
    writeFileSync(before, out);
    // Introduce a real regression: a leaked credential file.
    writeFileSync(join(dir, ".env"), "TOKEN=abc");
    restore = capture();
    await cli(["run", dir, "--json"]);
    restore();
    writeFileSync(after, out);

    restore = capture();
    const code = await cli(["diff", before, after]);
    restore();
    expect(code).toBe(1);
    expect(out).toMatch(/regressions/);
    expect(out).toMatch(/no-sensitive-files/);
    rmSync(join(dir, ".env"));
  });

  it("exits 0 when a diff shows only improvements", async () => {
    const restore = capture();
    const code = await cli(["diff", join(dir, "after.json"), join(dir, "before.json")]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/No regressions/);
  });

  it("emits a machine-readable diff with --json", async () => {
    const restore = capture();
    await cli(["diff", join(dir, "before.json"), join(dir, "after.json"), "--json"]);
    restore();
    const d = JSON.parse(out) as { regressions: unknown[]; sameSubject: boolean };
    expect(d.regressions.length).toBeGreaterThan(0);
    // The bytes changed, so the regression is the artifact's, not ours.
    expect(d.sameSubject).toBe(false);
  });

  it("exits 2 when diff is missing an argument", async () => {
    const restore = capture();
    expect(await cli(["diff", join(dir, "before.json")])).toBe(2);
    restore();
  });
});

/**
 * "Could not tell" must never render as "nothing changed".
 *
 * `diffReports` always modelled this correctly — a null surface means
 * the comparison did not happen — but the CLI collapsed it into "No
 * regressions, no surface changes." So a diff of two published versions
 * of `@modelcontextprotocol/server-everything`, whose surface static
 * capture cannot read at all (it ships only `dist/` and registers tools
 * dynamically), printed a clean bill of health for a rug-pull check
 * that never ran. That is the one failure mode that reads as success,
 * at the one place this tool exists to look.
 */
describe("surface comparability is reported, not assumed", () => {
  const withSurface = (names: string[]): AssayReport =>
    report({
      surface: {
        origin: "declared",
        entries: names.map((n) => ({
          name: n,
          descriptionDigest: `d-${n}`,
          descriptionLength: 10,
        })),
      },
    } as Partial<AssayReport>);

  it("flags when NEITHER report captured a surface", () => {
    const d = diffReports(report(), report());
    expect(d.surface).toBeNull();
    expect(d.surfaceUnavailable).toBe("both");
  });

  it("flags when only the BEFORE report captured one", () => {
    expect(diffReports(report(), withSurface(["a"])).surfaceUnavailable).toBe("before");
  });

  it("flags when only the AFTER report captured one", () => {
    expect(diffReports(withSurface(["a"]), report()).surfaceUnavailable).toBe("after");
  });

  // The whole point: a real comparison is distinguishable from no
  // comparison, rather than both arriving as `surface: null`.
  it("reports nothing unavailable when both captured one", () => {
    const d = diffReports(withSurface(["a"]), withSurface(["a"]));
    expect(d.surfaceUnavailable).toBeNull();
    expect(d.surface).not.toBeNull();
    expect(d.surface!.unchanged).toBe(true);
  });

  it("still detects a real surface change when both are present", () => {
    const d = diffReports(withSurface(["a"]), withSurface(["a", "b"]));
    expect(d.surfaceUnavailable).toBeNull();
    expect(d.surface!.unchanged).toBe(false);
  });
});

/**
 * A check that stops answering is not an improvement.
 *
 * Every non-judging status tied at severity 0, so `fail → skip` was
 * classified as an improvement and `pass → skip` as no change at all.
 * Combined with the `disable` hole, a check that quietly stops running —
 * network gone, docs moved so the behavioral tier skips, a config
 * switch — sailed through the CI gate the README recommends.
 */
describe("coverage loss is its own category", () => {
  const at = (status: CheckStatus): AssayReport =>
    report({ results: results.map((r) => (r.checkId === "fine" ? { ...r, status } : r)) });

  it.each(["skip", "error", "neutral"] as const)(
    "treats pass → %s as coverage lost, not as nothing",
    (to) => {
      const d = diffReports(at("pass"), at(to));
      expect(d.coverageLost.map((c) => c.checkId)).toContain("fine");
      expect(d.regressions).toHaveLength(0);
      expect(d.improvements).toHaveLength(0);
    },
  );

  // The one that actively misled: a failing check that stops running
  // used to read as the artifact getting better.
  it("does NOT call fail → skip an improvement", () => {
    const d = diffReports(at("fail"), at("skip"));
    expect(d.improvements).toHaveLength(0);
    expect(d.coverageLost.map((c) => c.checkId)).toContain("fine");
  });

  it("counts a check that vanished entirely", () => {
    const after = report({ results: results.filter((r) => r.checkId !== "fine") });
    const d = diffReports(at("pass"), after);
    expect(d.coverageLost.map((c) => c.checkId)).toContain("fine");
  });

  // Genuine verdict changes must still classify normally.
  it("still calls pass → fail a regression", () => {
    expect(diffReports(at("pass"), at("fail")).regressions.map((c) => c.checkId)).toContain("fine");
  });

  it("still calls fail → pass an improvement", () => {
    expect(diffReports(at("fail"), at("pass")).improvements.map((c) => c.checkId)).toContain(
      "fine",
    );
  });

  it("reports nothing lost when a check keeps judging", () => {
    expect(diffReports(at("pass"), at("warn")).coverageLost).toHaveLength(0);
  });
});

/**
 * `.gitignore` awareness for credential findings.
 *
 * `assay run .` in a real working tree failed BLOCKING on a local
 * `.env`, called it "committed", and advised "add the path to
 * .gitignore" — which the author had already done. First thing a
 * developer hits, and the tool's own remediation did not fix it.
 *
 * Downgraded, never suppressed: the matcher is deliberately partial, and
 * a wrong match must not be able to hide a real leak.
 */
describe("gitignore matching", () => {
  const rules = (body: string) =>
    loadIgnoreRules({
      listTree: async () => [{ path: ".gitignore", type: "file" as const }],
      readFile: async () => body,
      exists: async () => true,
    });

  it("matches a plain filename at any depth", async () => {
    const r = await rules(".env\n");
    expect(isIgnored(".env", r)).toBe(true);
    expect(isIgnored("packages/a/.env", r)).toBe(true);
  });

  it("matches a glob", async () => {
    const r = await rules("*.log\n");
    expect(isIgnored("debug.log", r)).toBe(true);
    expect(isIgnored("src/x.log", r)).toBe(true);
    expect(isIgnored("src/x.txt", r)).toBe(false);
  });

  it("honours a leading slash as an anchor", async () => {
    const r = await rules("/.env\n");
    expect(isIgnored(".env", r)).toBe(true);
    expect(isIgnored("nested/.env", r)).toBe(false);
  });

  it("matches everything under a directory rule", async () => {
    const r = await rules("secrets/\n");
    expect(isIgnored("secrets/key.pem", r)).toBe(true);
    expect(isIgnored("other/key.pem", r)).toBe(false);
  });

  it("ignores comments and blank lines", async () => {
    const r = await rules("# a comment\n\n.env\n");
    expect(isIgnored(".env", r)).toBe(true);
  });

  // Conservative by design: being wrong here could hide a real leak, so
  // anything whose semantics are subtle disables the whole file.
  it("gives up entirely on a file containing a negation", async () => {
    const r = await rules(".env\n!.env.keep\n");
    expect(r).toHaveLength(0);
    expect(isIgnored(".env", r)).toBe(false);
  });

  it("gives up on a ** pattern rather than guessing", async () => {
    const r = await rules("**/secret\n");
    expect(isIgnored("a/secret", r)).toBe(false);
  });

  it("reports nothing ignored when there is no ignore file", async () => {
    const empty = await loadIgnoreRules({
      listTree: async () => [],
      readFile: async () => null,
      exists: async () => false,
    });
    expect(empty).toHaveLength(0);
  });
});

/**
 * Suppressing a check must not raise coverage.
 *
 * `neutral` was excluded from both sides of the coverage fraction, on
 * the reasoning that a genuinely inapplicable check should not make
 * coverage look incomplete. That is right for "no package.json in a
 * Python server" and catastrophically wrong for "somebody switched this
 * off": disabling the checks that would fail you REMOVED them from the
 * denominator.
 *
 * Demonstrated end to end — an artifact shipping
 * `{"disable": ["no-sensitive-files", "deps-bounded", "deps-no-known-vulns"]}`
 * while committing an AWS key took safety coverage from 71% to a
 * reported "100% measured", and the overall from 47.5 to 68.2 with exit
 * 0. The subject supplied the policy that graded it.
 */
describe("suppressed checks stay in the coverage denominator", () => {
  const withStatus = (over: Partial<CheckReport>): CheckReport[] => [
    { ...results[0]!, checkId: "a", status: "pass", axis: "safety", weight: 1 },
    { ...results[0]!, checkId: "b", axis: "safety", weight: 1, ...over },
  ];

  it("a genuinely inapplicable check does not lower coverage", () => {
    const s = scoreReport(withStatus({ status: "neutral" }));
    expect(s.axes.safety.coverage).toBe(1);
  });

  it("a DISABLED check does lower coverage", () => {
    const s = scoreReport(withStatus({ status: "neutral", suppressed: true }));
    expect(s.axes.safety.coverage).toBe(0.5);
  });

  it("a WAIVED check does lower coverage", () => {
    const s = scoreReport(withStatus({ status: "neutral", suppressed: true }));
    expect(s.axes.safety.coverage).toBeLessThan(1);
  });

  // The two must be distinguishable, or the fix is cosmetic.
  it("distinguishes inapplicable from suppressed", () => {
    const inapplicable = scoreReport(withStatus({ status: "neutral" }));
    const suppressed = scoreReport(withStatus({ status: "neutral", suppressed: true }));
    expect(inapplicable.axes.safety.coverage).toBeGreaterThan(suppressed.axes.safety.coverage);
  });
});
