/**
 * Scoring.
 *
 * A scoring function on a public registry is a policy document, not a
 * utility. Whatever it rewards is what publishers will optimize for,
 * so the design constraints are less about arithmetic and more about
 * what the arithmetic incentivizes.
 *
 * Four rules this implements:
 *
 *  1. **Coverage is reported, never assumed.** If half the checks on an
 *     axis could not run, the axis says so. The dishonest alternative —
 *     scoring only what ran and presenting it as a full result — makes
 *     an unevaluated artifact indistinguishable from a good one, which
 *     is precisely the failure mode we are trying to fix.
 *
 *  2. **`error` never counts against the subject.** Our sandbox timing
 *     out is our problem. Folding it into a public score turns
 *     infrastructure flakiness into a permanent mark on someone's work.
 *
 *  3. **Safety does not average.** On the other three axes a weak check
 *     is offset by strong ones. Safety must not work that way: an
 *     artifact that exfiltrates credentials does not get to average
 *     that away against a tidy README. Any blocking safety failure
 *     floors the axis.
 *
 *  4. **The formula is versioned and published.** `ScoreCard.formula`
 *     names the exact weighting, and the whole computation runs off
 *     `CheckReport[]` — so anyone holding a report can recompute the
 *     score and get our number, or show that they don't.
 */
import type { AxisScore, CheckReport, CheckStatus, ScoreAxis, ScoreCard } from "./types.js";
import { SCORE_AXES } from "./types.js";

/** Identifier for the default weighting. Bump on any change here. */
export const DEFAULT_FORMULA = "assay-default@1.0.0";

/**
 * How each judging status maps to a 0..1 contribution.
 *
 * `warn` at 0.5 rather than 0 is deliberate: a warning is "this is
 * suboptimal", not "this is broken", and scoring it as a failure
 * collapses a distinction publishers rely on to prioritize.
 */
const STATUS_SCORE: Partial<Record<CheckStatus, number>> = {
  pass: 1,
  warn: 0.5,
  fail: 0,
};

/** Statuses that mean "we obtained a judgement about the subject". */
function isJudging(status: CheckStatus): boolean {
  return status === "pass" || status === "warn" || status === "fail";
}

/**
 * Statuses that count toward coverage's denominator.
 *
 * `neutral` is excluded from BOTH sides: a check that genuinely does
 * not apply (no `package.json` in a Python MCP server) should neither
 * raise nor lower the score, and should not make coverage look
 * incomplete. `skip` and `error` DO lower coverage — in those cases we
 * wanted an answer and failed to get one, and hiding that would be the
 * lie rule 1 exists to prevent.
 */
function countsForCoverage(r: { status: CheckStatus; suppressed?: boolean }): boolean {
  // A SUPPRESSED check counts in the denominator even though it is
  // neutral. Excluding it meant that switching off the checks which
  // would fail you raised your coverage — an artifact shipping
  // `disable: [...]` took safety from 71% to "100% measured" while
  // hiding a committed AWS key. Refusing to look is not the same as
  // there being nothing to see.
  if (r.suppressed) return true;
  return r.status !== "neutral";
}

export interface ScoreOptions {
  formula?: string;
  /**
   * Floor applied to the safety axis when a blocking safety check
   * fails. See rule 3.
   */
  safetyFloor?: number;
}

/**
 * Compute the scorecard from check reports.
 *
 * Pure and total: same input, same output, no clock, no config reads.
 * That matters because a third party re-deriving the score from a
 * published report must land on the same number.
 */
export function scoreReport(results: readonly CheckReport[], opts: ScoreOptions = {}): ScoreCard {
  const formula = opts.formula ?? DEFAULT_FORMULA;
  const safetyFloor = opts.safetyFloor ?? 0;

  const axes = {} as Record<ScoreAxis, AxisScore>;

  for (const axis of SCORE_AXES) {
    const inAxis = results.filter((r) => axisOf(r) === axis);

    let weightedScore = 0;
    let weightedTotal = 0;
    let considered = 0;
    let judged = 0;

    for (const r of inAxis) {
      const weight = r.weight ?? 1;
      if (countsForCoverage(r)) considered += weight;
      if (!isJudging(r.status)) continue;
      judged += weight;

      // An explicit 0..1 `score` wins over the status mapping, so a
      // graded check (documentation quality, say) isn't flattened to
      // pass/warn/fail.
      const value = typeof r.score === "number" ? clamp01(r.score) : (STATUS_SCORE[r.status] ?? 0);

      // Weight 0 = informational: reported, never scored.
      if (weight === 0) continue;
      weightedScore += value * weight;
      weightedTotal += weight;
    }

    let value = weightedTotal > 0 ? (weightedScore / weightedTotal) * 100 : 0;

    // Rule 3: a blocking safety failure floors the axis.
    if (axis === "safety") {
      const blockingFail = inAxis.some((r) => r.status === "fail" && isBlocking(r));
      if (blockingFail) value = Math.min(value, safetyFloor);
    }

    // An axis nothing judged has no value, and `0` is not a way to say
    // so. The human report is careful about this — it prints "— not
    // measured" — while the JSON published `"value": 0`, so a registry
    // ranking artifacts on `axes.behavior.value` read every artifact
    // that had not paid for a behavioral run as the worst possible one.
    // That is rule 1 of this module, broken by the surface machines
    // consume.
    axes[axis] = {
      value: weightedTotal > 0 ? round1(value) : null,
      coverage: considered > 0 ? round2(judged / considered) : 0,
      checkIds: inAxis.map((r) => r.checkId).sort(),
    };
  }

  return { formula, axes, overall: computeOverall(axes) };
}

/**
 * Minimum fraction of the weighted check mass that must have produced
 * a judgement before a headline scalar is meaningful.
 */
const MIN_OVERALL_COVERAGE = 0.5;

/**
 * Headline 0-100, or `undefined` when too little was measured to
 * justify one.
 *
 * Weighting each axis by its own coverage is not enough on its own: it
 * makes an unmeasured axis vanish from the average rather than count
 * against it, so an artifact where only the safety checks ran scores
 * identically to one that passed everything. That is the precise
 * dishonesty rule 1 exists to prevent, and it is worse in a scalar
 * than anywhere else because the scalar is what gets screenshotted.
 *
 * So there are two mechanisms, and they do different jobs:
 *   - per-axis coverage weighting, so a thinly-measured axis carries
 *     proportionally less influence over the number;
 *   - a global coverage floor, below which there IS no number. A UI
 *     showing "not enough signal to score" is honest; one showing 100
 *     because it only managed to run two checks is not.
 *
 * Consumers should still lead with the four axes. This exists so that
 * anyone who wants one scalar uses ours — defined, versioned, and
 * recomputable from the report — rather than inventing a worse one.
 */
function computeOverall(axes: Record<ScoreAxis, AxisScore>): number | undefined {
  // Safety is weighted hardest, then behavior — "does it hurt me" and
  // "does it work" dominate "is the README nice".
  const AXIS_WEIGHT: Record<ScoreAxis, number> = {
    safety: 4,
    behavior: 3,
    integrity: 2,
    care: 1,
  };

  let num = 0;
  let den = 0;
  let coveredWeight = 0;
  let totalWeight = 0;

  for (const axis of SCORE_AXES) {
    const a = axes[axis];
    const w = AXIS_WEIGHT[axis] * a.coverage;
    // A null value carries no weight; its absence is already reflected
    // in `coverage`, which is what drives the floor below.
    num += (a.value ?? 0) * w;
    den += w;
    coveredWeight += AXIS_WEIGHT[axis] * a.coverage;
    totalWeight += AXIS_WEIGHT[axis];
  }

  if (den <= 0) return undefined;
  // Below the floor we decline to publish a number at all rather than
  // publish a flattering one.
  if (coveredWeight / totalWeight < MIN_OVERALL_COVERAGE) return undefined;
  return round1(num / den);
}

function axisOf(r: CheckReport): ScoreAxis {
  // Defensive: a third-party report with an unrecognized axis degrades
  // to `integrity` rather than throwing mid-scoring.
  return (SCORE_AXES as readonly string[]).includes(r.axis) ? r.axis : "integrity";
}

function isBlocking(r: CheckReport): boolean {
  return r.blocking === true;
}

const clamp01 = (n: number) => (Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0);
const round1 = (n: number) => Math.round(n * 10) / 10;
const round2 = (n: number) => Math.round(n * 100) / 100;
