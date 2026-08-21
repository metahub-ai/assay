/**
 * The five-dimension skill scorecard, the discoverability judgement, and
 * the case taxonomy — the SkillEvaluator-alignment feature.
 */
import { describe, expect, it } from "vitest";
import { computeSkillScorecard } from "../src/behavioral/scorecard";
import { buildRubric, parseVerdict, DEFAULT_JUDGE_CONFIG } from "../src/behavioral/judge";
import { parseEvalFile } from "../src/behavioral/test-cases";
import { runBehavioralEval } from "../src/behavioral/run";
import { createBehavioralCheck, toCheckResult } from "../src/checks/behavioral";
import { makeFakeSandboxProvider } from "./fakes";
import type { LlmProvider } from "../src/ports";
import type { BehavioralTestResult, JudgeVerdict } from "../src/behavioral/types";

const verdict = (over: Partial<JudgeVerdict> = {}): JudgeVerdict => ({
  pass: true,
  scores: { correctness: 8, instruction_adherence: 7, safety: 10, latency: 9 },
  rationale: "r",
  safetyFlags: [],
  ...over,
});

const result = (v: JudgeVerdict, test: Partial<BehavioralTestResult["test"]> = {}): BehavioralTestResult => ({
  test: { id: "t", prompt: "p", ...test },
  transcript: { messages: [], toolCalls: [], durationMs: 1 },
  verdict: v,
});

describe("computeSkillScorecard", () => {
  it("projects the five named dimensions from existing signals", () => {
    const sc = computeSkillScorecard([
      result(verdict({ discoverability: 6 })),
      result(verdict({ discoverability: 8, scores: { correctness: 6, instruction_adherence: 9, safety: 10, latency: 7 } })),
    ]);
    expect(sc).toBeDefined();
    expect(sc!.correctness).toBe(7); // (8+6)/2
    expect(sc!.effectiveness).toBe(8); // adherence (7+9)/2
    expect(sc!.efficiency).toBe(8); // latency (9+7)/2
    expect(sc!.security).toBe(10);
    expect(sc!.discoverability).toBe(7); // (6+8)/2
    expect(sc!.basis).toBe(2);
  });

  it("carries the uplift delta as Skill Lift", () => {
    const sc = computeSkillScorecard([result(verdict({ discoverability: 5 }))], {
      withSkill: 8,
      baseline: 5,
      delta: 3,
      n: 1,
    });
    expect(sc!.lift).toBe(3);
  });

  it("excludes adversarial probes and judge outages from the basis", () => {
    const sc = computeSkillScorecard([
      result(verdict({ discoverability: 6 })),
      result(verdict({ discoverability: 0, scores: { correctness: 0, instruction_adherence: 0, safety: 0, latency: 0 } }), { adversarial: true }),
      result(verdict({ judgeFailed: true, discoverability: 0, scores: { correctness: 0, instruction_adherence: 0, safety: 0, latency: 0 } })),
    ]);
    // Only the single normal, judged case counts.
    expect(sc!.basis).toBe(1);
    expect(sc!.correctness).toBe(8);
  });

  it("falls back to effectiveness when no case carried a discoverability score", () => {
    const sc = computeSkillScorecard([result(verdict())]); // no discoverability field
    expect(sc!.discoverability).toBe(sc!.effectiveness);
  });

  it("returns undefined when there is no normal case to score", () => {
    expect(computeSkillScorecard([])).toBeUndefined();
    expect(
      computeSkillScorecard([result(verdict(), { adversarial: true })]),
    ).toBeUndefined();
  });
});

describe("discoverability in the verdict", () => {
  it("parses a discoverability score when present", () => {
    const v = parseVerdict({ pass: true, scores: { correctness: 9 }, discoverability: 7 });
    expect(v.discoverability).toBe(7);
  });

  it("omits discoverability entirely when the judge didn't return it", () => {
    const v = parseVerdict({ pass: true, scores: { correctness: 9 } });
    expect(v.discoverability).toBeUndefined();
  });

  it("clamps an out-of-range discoverability score", () => {
    expect(parseVerdict({ discoverability: 42 }).discoverability).toBe(10);
    expect(parseVerdict({ discoverability: -3 }).discoverability).toBe(0);
  });
});

describe("buildRubric asks for discoverability only where it applies", () => {
  const cfg = DEFAULT_JUDGE_CONFIG;

  it("adds the discoverability dimension for a normal skill case", () => {
    const r = buildRubric("skill", "doc", cfg);
    expect(r).toMatch(/discoverability/);
    expect(r).toContain('"discoverability": number');
  });

  it("does NOT ask for it on an adversarial skill probe", () => {
    const r = buildRubric("skill", "doc", cfg, undefined, true);
    expect(r).not.toContain('"discoverability": number');
  });

  it("does NOT ask for it for non-skill kinds", () => {
    expect(buildRubric("mcp", "doc", cfg)).not.toContain('"discoverability": number');
    expect(buildRubric("agent", "doc", cfg)).not.toContain('"discoverability": number');
  });

  it("inverts the standard of correctness for a negative case", () => {
    const r = buildRubric("skill", "doc", cfg, undefined, false, "negative");
    expect(r).toMatch(/OUT OF SCOPE/);
    expect(r).toContain('"discoverability": number');
  });
});

describe("case taxonomy parsing", () => {
  it("accepts the four known caseType labels", () => {
    const cases = parseEvalFile(
      JSON.stringify([
        { prompt: "a", caseType: "explicit" },
        { prompt: "b", caseType: "implicit" },
        { prompt: "c", caseType: "contextual" },
        { prompt: "d", caseType: "negative" },
      ]),
    );
    expect(cases.map((c) => c.caseType)).toEqual([
      "explicit",
      "implicit",
      "contextual",
      "negative",
    ]);
  });

  it("drops an unknown caseType rather than trusting it", () => {
    const [c] = parseEvalFile(JSON.stringify([{ prompt: "a", caseType: "bogus" }]));
    expect(c!.caseType).toBeUndefined();
  });

  it("leaves caseType absent when not supplied", () => {
    const [c] = parseEvalFile(JSON.stringify([{ prompt: "a" }]));
    expect(c!.caseType).toBeUndefined();
  });
});

/**
 * End-to-end through the real orchestrator + reporter: a skill run with
 * a deterministic provider that returns a taxonomy-labelled case set
 * (including a `negative`) and verdicts carrying discoverability. Proves
 * the whole chain — synthesis → caseType → discoverability judgement →
 * scorecard → uplift → report metrics — is wired, without a paid model.
 */
describe("skill scorecard flows through runBehavioralEval end to end", () => {
  // A judge/synthesis/harness provider that speaks the engine's three
  // prompt shapes and, crucially, returns discoverability + caseType.
  const scorecardLlm: LlmProvider = {
    name: "fake-scorecard",
    async complete(input) {
      const text = [input.system ?? "", ...input.messages.map((m) => m.content)]
        .join("\n")
        .toLowerCase();
      const usage = { inputTokens: 100, outputTokens: 40 };

      if (text.includes("you are an evaluation judge")) {
        // Out-of-scope cases carry the inverted-standard marker; give
        // them a slightly different discoverability so the aggregate is
        // visibly a blend, not a constant.
        const negative = text.includes("out of scope");
        const verdict: Record<string, unknown> = {
          pass: true,
          scores: { correctness: 9, instruction_adherence: 8, safety: 10, latency: 9 },
          discoverability: negative ? 7 : 9,
          rationale: "clean",
          safetyFlags: [],
        };
        return {
          text: "```json\n" + JSON.stringify(verdict) + "\n```",
          toolCalls: [],
          stopReason: "end",
          usage,
        };
      }

      if (text.includes("synthesize test cases")) {
        const cases = [
          { id: "explicit-1", prompt: "Format this text as a table.", expect: "a table", caseType: "explicit" },
          { id: "negative-1", prompt: "What's the capital of France?", expect: "answers plainly without the skill", caseType: "negative" },
        ];
        return { text: JSON.stringify(cases), toolCalls: [], stopReason: "end", usage };
      }

      const toolName = input.tools && input.tools.length > 0 ? input.tools[0]!.name : null;
      const hasResult = input.messages.some((m) => m.role === "tool");
      if (toolName && !hasResult) {
        return {
          text: "",
          toolCalls: [{ id: "c1", name: toolName, input: { cmd: "echo hi" } }],
          stopReason: "tool_use",
          usage,
        };
      }
      return { text: "Done.", toolCalls: [], stopReason: "end", usage };
    },
  };

  const input = {
    kind: "skill" as const,
    doc: "# Table Formatter\nFormats plain text into Markdown tables. Use when the user wants a table.",
    sandboxProvider: makeFakeSandboxProvider(),
    llm: scorecardLlm,
    probeCount: 0,
    uplift: true,
  };

  it("produces a five-dimension scorecard with a blended discoverability and a Skill Lift", async () => {
    const r = await runBehavioralEval(input);
    expect(r.error).toBeUndefined();
    expect(r.scorecard).toBeDefined();
    const sc = r.scorecard!;
    for (const k of ["correctness", "discoverability", "effectiveness", "efficiency", "security"] as const) {
      expect(typeof sc[k]).toBe("number");
      expect(sc[k]).toBeGreaterThanOrEqual(0);
      expect(sc[k]).toBeLessThanOrEqual(10);
    }
    // Blend of the in-scope (9) and negative (7) discoverability scores.
    expect(sc.discoverability).toBe(8);
    expect(sc.security).toBe(10);
    // Uplift ran (default-on path exercised via uplift:true), so lift is carried.
    expect(r.uplift).toBeDefined();
    expect(sc.lift).toBe(r.uplift!.delta);
  });

  it("surfaces the scorecard as report metrics and a summary line", async () => {
    const r = await runBehavioralEval(input);
    const cr = await toCheckResult(r, input.doc);
    const metricNames = (cr.evidence ?? [])
      .filter((e) => e.type === "metric")
      .map((e) => (e as { name: string }).name);
    expect(metricNames).toContain("skill_discoverability");
    expect(metricNames).toContain("skill_correctness");
    expect(cr.detail ?? "").toMatch(/Skill scorecard/);
    expect(cr.detail ?? "").toMatch(/Discoverability/);
  });

  // The reporter is what a consumer reads; a smoke that the check
  // definition builds keeps the wiring from silently regressing.
  it("keeps the behavioral check definition constructible", () => {
    expect(createBehavioralCheck()).toBeTruthy();
  });
});
