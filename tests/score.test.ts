/**
 * Scoring policy.
 *
 * These tests are the policy document in executable form. Each asserts
 * a property we would have to defend publicly: that infrastructure
 * failures don't count against publishers, that an unevaluated
 * artifact can't masquerade as a good one, and that a safety failure
 * can't be averaged away.
 */
import { describe, expect, it } from "vitest";
import { scoreReport } from "../src/score";
import { DEFAULT_CHECKS } from "../src/checks/index";
import type { CheckReport, CheckStatus, ScoreAxis } from "../src/types";

const r = (over: Partial<CheckReport> & { status: CheckStatus }): CheckReport => ({
  checkId: over.checkId ?? `c${Math.random().toString(36).slice(2, 8)}`,
  checkVersion: "1.0.0",
  title: "t",
  category: "structural",
  determinism: "deterministic",
  weight: 1,
  axis: "integrity" as ScoreAxis,
  summary: "s",
  ...over,
});

describe("status mapping", () => {
  it("scores all-pass as 100 with full coverage", () => {
    const s = scoreReport([r({ status: "pass" }), r({ status: "pass" })]);
    expect(s.axes.integrity.value).toBe(100);
    expect(s.axes.integrity.coverage).toBe(1);
  });

  it("treats warn as half credit, not as a failure", () => {
    const s = scoreReport([r({ status: "warn" })]);
    expect(s.axes.integrity.value).toBe(50);
  });

  it("honours an explicit graded score over the status mapping", () => {
    const s = scoreReport([r({ status: "warn", score: 0.9 })]);
    expect(s.axes.integrity.value).toBe(90);
  });

  it("clamps an out-of-range score rather than trusting it", () => {
    expect(scoreReport([r({ status: "pass", score: 5 })]).axes.integrity.value).toBe(100);
    expect(scoreReport([r({ status: "pass", score: -3 })]).axes.integrity.value).toBe(0);
  });

  it("weights checks relative to each other", () => {
    // One weight-3 failure against one weight-1 pass → 25.
    const s = scoreReport([r({ status: "fail", weight: 3 }), r({ status: "pass", weight: 1 })]);
    expect(s.axes.integrity.value).toBe(25);
  });

  it("reports but never scores a weight-0 check", () => {
    const s = scoreReport([r({ status: "fail", weight: 0 }), r({ status: "pass", weight: 1 })]);
    expect(s.axes.integrity.value).toBe(100);
    expect(s.axes.integrity.checkIds).toHaveLength(2);
  });
});

describe("error and skip handling", () => {
  it("never counts our own error against the subject", () => {
    const s = scoreReport([r({ status: "pass" }), r({ status: "error" })]);
    // The passing check stands alone; the error neither scores nor
    // drags the value down.
    expect(s.axes.integrity.value).toBe(100);
    // But coverage falls, so the report is honest about what it missed.
    expect(s.axes.integrity.coverage).toBe(0.5);
  });

  it("lowers coverage for a skipped check", () => {
    const s = scoreReport([r({ status: "pass" }), r({ status: "skip" })]);
    expect(s.axes.integrity.coverage).toBe(0.5);
  });

  it("excludes neutral from both score and coverage", () => {
    const s = scoreReport([r({ status: "pass" }), r({ status: "neutral" })]);
    expect(s.axes.integrity.value).toBe(100);
    // A genuinely inapplicable check is not a gap in our evaluation.
    expect(s.axes.integrity.coverage).toBe(1);
  });

  it("reports no value and zero coverage when nothing could be evaluated", () => {
    const s = scoreReport([r({ status: "skip" }), r({ status: "error" })]);
    expect(s.axes.integrity.coverage).toBe(0);
    // `null`, not `0`. "We could not measure this" and "this scored
    // zero" are opposite facts, and a consumer ranking on the value
    // must not be able to read one as the other.
    expect(s.axes.integrity.value).toBeNull();
  });
});

describe("safety does not average", () => {
  it("floors the safety axis when a blocking safety check fails", () => {
    const s = scoreReport([
      r({ axis: "safety", status: "fail", blocking: true, weight: 1 }),
      r({ axis: "safety", status: "pass", weight: 9 }),
    ]);
    // Nine passing safety checks would otherwise average this to 90.
    expect(s.axes.safety.value).toBe(0);
  });

  it("does not floor on a non-blocking safety failure", () => {
    const s = scoreReport([
      r({ axis: "safety", status: "fail", weight: 1 }),
      r({ axis: "safety", status: "pass", weight: 9 }),
    ]);
    expect(s.axes.safety.value).toBe(90);
  });

  it("respects a configured non-zero floor", () => {
    const s = scoreReport([r({ axis: "safety", status: "fail", blocking: true })], {
      safetyFloor: 10,
    });
    expect(s.axes.safety.value).toBe(0);
  });

  it("leaves other axes averaging normally", () => {
    const s = scoreReport([
      r({ axis: "care", status: "fail", blocking: true, weight: 1 }),
      r({ axis: "care", status: "pass", weight: 9 }),
    ]);
    expect(s.axes.care.value).toBe(90);
  });
});

describe("overall", () => {
  it("withholds the scalar entirely when too little was measured", () => {
    const evaluated = scoreReport([
      r({ axis: "safety", status: "pass" }),
      r({ axis: "behavior", status: "pass" }),
      r({ axis: "integrity", status: "pass" }),
      r({ axis: "care", status: "pass" }),
    ]);
    const barely = scoreReport([
      r({ axis: "safety", status: "pass" }),
      r({ axis: "behavior", status: "skip" }),
      r({ axis: "integrity", status: "skip" }),
      r({ axis: "care", status: "skip" }),
    ]);
    expect(evaluated.overall).toBe(100);
    // Same passing safety check, but three axes unmeasured. Coverage
    // weighting alone would make those axes VANISH from the average and
    // hand back 100 — identical to the fully-evaluated artifact. There
    // is no honest scalar here, so there is no scalar.
    expect(barely.overall).toBeUndefined();
    expect(barely.axes.behavior.coverage).toBe(0);
  });

  it("still scores when coverage clears the floor", () => {
    const s = scoreReport([
      r({ axis: "safety", status: "pass" }),
      r({ axis: "behavior", status: "pass" }),
      r({ axis: "integrity", status: "skip" }),
      r({ axis: "care", status: "skip" }),
    ]);
    // safety(4) + behavior(3) = 7 of 10 weighted mass measured.
    expect(s.overall).toBe(100);
  });

  it("withholds the scalar when nothing was measured at all", () => {
    expect(scoreReport([r({ status: "error" })]).overall).toBeUndefined();
  });

  it("weights safety above care", () => {
    const safetyBad = scoreReport([
      r({ axis: "safety", status: "fail" }),
      r({ axis: "care", status: "pass" }),
    ]);
    const careBad = scoreReport([
      r({ axis: "safety", status: "pass" }),
      r({ axis: "care", status: "fail" }),
    ]);
    expect(safetyBad.overall!).toBeLessThan(careBad.overall!);
  });

  it("names the formula so the arithmetic is auditable", () => {
    expect(scoreReport([r({ status: "pass" })]).formula).toBe("assay-default@1.0.0");
    expect(scoreReport([r({ status: "pass" })], { formula: "custom@2" }).formula).toBe("custom@2");
  });

  it("is pure — same input, same output", () => {
    const input = [r({ checkId: "a", status: "pass" }), r({ checkId: "b", status: "warn" })];
    expect(scoreReport(input)).toEqual(scoreReport(input));
  });
});

describe("defensive handling of third-party reports", () => {
  it("degrades an unrecognized axis to integrity instead of throwing", () => {
    const rogue = r({ status: "pass" });
    (rogue as unknown as { axis: string }).axis = "vibes";
    const s = scoreReport([rogue]);
    expect(s.axes.integrity.value).toBe(100);
  });

  it("treats a missing weight as 1", () => {
    const noWeight = r({ status: "fail" });
    delete (noWeight as Partial<CheckReport>).weight;
    const s = scoreReport([noWeight, r({ status: "pass", weight: 1 })]);
    expect(s.axes.integrity.value).toBe(50);
  });

  it("survives a non-finite score", () => {
    expect(scoreReport([r({ status: "pass", score: NaN })]).axes.integrity.value).toBe(0);
  });

  it("reports an axis with no checks as unmeasured, not as zero", () => {
    const s = scoreReport([r({ axis: "safety", status: "pass" })]);
    expect(s.axes.behavior).toEqual({ value: null, coverage: 0, checkIds: [] });
  });
});

describe("invariants that make the number trustworthy", () => {
  const r = (over: Partial<CheckReport>): CheckReport =>
    ({
      checkId: "x",
      axis: "safety",
      status: "pass",
      title: "t",
      message: "m",
      ...over,
    }) as CheckReport;

  it("never lets a weight-0 blocking check defeat the safety floor", () => {
    // Weight 0 means "report it, don't score it". Combined with
    // `blocking: true` that is a contradiction — the check is the most
    // consequential kind we have, and also worth nothing. The floor at
    // line 129 only fires when something was scored, so a weight-0
    // blocking FAIL would leave safety null and the artifact unflagged.
    // No such check exists today; this test is what keeps it that way.
    for (const c of DEFAULT_CHECKS) {
      if (c.blocking) expect(c.weight ?? 1).toBeGreaterThan(0);
    }
  });

  it("cannot be raised by adding checks that could not run", () => {
    // The tempting bug: score what ran, ignore what didn't. That makes
    // an artifact we failed to evaluate look identical to one that
    // passed. Coverage must fall instead.
    const base = [r({ checkId: "a", status: "pass" })];
    const withSkips = [
      ...base,
      r({ checkId: "b", status: "skip" }),
      r({ checkId: "c", status: "error" }),
    ];

    const one = scoreReport(base).axes.safety;
    const many = scoreReport(withSkips).axes.safety;

    expect(many.value).toBe(one.value); // the value is unchanged...
    expect(many.coverage).toBeLessThan(one.coverage); // ...but honesty drops
  });

  it("is deterministic — the same report always yields the same number", () => {
    // A third party holding the report has to be able to recompute our
    // number and get ours. Any clock, map-ordering or randomness in
    // here would make the published score unverifiable.
    const report = [
      r({ checkId: "a", status: "pass", axis: "integrity" }),
      r({ checkId: "b", status: "warn", axis: "care" }),
      r({ checkId: "c", status: "fail", axis: "safety", blocking: true }),
    ];
    const runs = Array.from({ length: 20 }, () => JSON.stringify(scoreReport(report)));
    expect(new Set(runs).size).toBe(1);
  });

  it("declines to publish a headline it does not have the coverage for", () => {
    // One passing check out of a full suite is not a 100. It is "we
    // don't know", and `undefined` is the only honest way to say that.
    const thin = [
      r({ checkId: "a", status: "pass" }),
      r({ checkId: "b", status: "error" }),
      r({ checkId: "c", status: "error" }),
      r({ checkId: "d", status: "error" }),
    ];
    expect(scoreReport(thin).overall).toBeUndefined();
  });
});
