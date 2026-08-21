/**
 * Project a skill run onto the five named dimensions
 * (correctness · discoverability · effectiveness · efficiency · security),
 * aligned with NVIDIA SkillEvaluator's scorecard so the two can be read
 * side by side.
 *
 * This is a projection, not a second evaluation. Four of the five come
 * straight from signals the judge already produces; only discoverability
 * is a dedicated skill-only judgement (see `JudgeVerdict.discoverability`).
 * The basis is NORMAL cases only — adversarial probes and judge-outages
 * are excluded, exactly as the headline score already excludes them, so
 * a refusal-shaped probe cannot distort "how good is this skill".
 */
import type { BehavioralEvalResult, BehavioralTestResult, SkillScorecard } from "./types.js";

const round1 = (x: number) => Math.round(x * 10) / 10;
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;

/**
 * Compute the five-dimension scorecard for a skill run, or `undefined`
 * when there is no normal case to score it from.
 *
 * `uplift` is the aggregate uplift-vs-baseline measurement when it was
 * run; its delta becomes the scorecard's `lift`.
 */
export function computeSkillScorecard(
  tests: readonly BehavioralTestResult[],
  uplift?: BehavioralEvalResult["uplift"],
): SkillScorecard | undefined {
  // Normal, actually-judged cases only. A verdict the judge never
  // produced is not evidence, and adversarial probes are scored by a
  // different rubric — folding either in would move the scorecard for
  // reasons that say nothing about the skill.
  const basis = tests.filter((t) => !t.test.adversarial && !t.verdict.judgeFailed);
  if (basis.length === 0) return undefined;

  const correctness = round1(mean(basis.map((t) => t.verdict.scores.correctness)));
  const effectiveness = round1(mean(basis.map((t) => t.verdict.scores.instruction_adherence)));
  const efficiency = round1(mean(basis.map((t) => t.verdict.scores.latency)));
  const security = round1(mean(basis.map((t) => t.verdict.scores.safety)));

  // Discoverability comes from the cases the judge actually rated for it.
  // Every skill non-adversarial case requests it, so this is normally the
  // whole basis; if a run somehow carries none, fall back to effectiveness
  // (the nearest correlated signal) rather than fabricate a zero.
  const discoverabilityScores = basis
    .map((t) => t.verdict.discoverability)
    .filter((d): d is number => typeof d === "number");
  const discoverability =
    discoverabilityScores.length > 0 ? round1(mean(discoverabilityScores)) : effectiveness;

  return {
    correctness,
    discoverability,
    effectiveness,
    efficiency,
    security,
    ...(uplift ? { lift: uplift.delta } : {}),
    basis: basis.length,
  };
}
