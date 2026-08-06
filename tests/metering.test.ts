/**
 * Metering is what turns "the bill was $900" into "these 40 artifacts
 * cost $900 and this one cost $12". The failure modes are all
 * under-counting, and under-counting is invisible until the invoice
 * arrives — so each of these pins one way the count could silently be
 * too low.
 */
import { describe, expect, it } from "vitest";
import { meterLlm, estimateCost, type PriceTable } from "../src/metering";
import type { LlmProvider, LlmResponse } from "../src/ports";
import type { LlmRole } from "../src/types";

function fakeLlm(
  opts: { usage?: boolean; models?: Partial<Record<LlmRole, string>> } = {},
): LlmProvider {
  const { usage = true, models } = opts;
  return {
    name: "fake",
    ...(models ? { modelFor: (r: LlmRole) => models[r] } : {}),
    complete(): Promise<LlmResponse> {
      return Promise.resolve({
        text: "ok",
        toolCalls: [],
        stopReason: "end",
        ...(usage ? { usage: { inputTokens: 100, outputTokens: 20 } } : {}),
      } as LlmResponse);
    },
  };
}

const PRICES: PriceTable = {
  "openai/gpt-4o-mini": { inputPerMTok: 0.15, outputPerMTok: 0.6 },
  "anthropic/claude-haiku-4.5": { inputPerMTok: 1, outputPerMTok: 5 },
};

describe("counting", () => {
  it("keeps driver and judge apart", async () => {
    // They are deliberately different models at very different prices,
    // so one combined total cannot be converted to money at all.
    const m = meterLlm(
      fakeLlm({ models: { driver: "openai/gpt-4o-mini", judge: "anthropic/claude-haiku-4.5" } }),
    );
    await m.complete({ messages: [], role: "driver" });
    await m.complete({ messages: [], role: "driver" });
    await m.complete({ messages: [], role: "judge" });

    const u = m.usage();
    expect(u.calls).toBe(3);
    expect(u.inputTokens).toBe(300);
    expect(u.byRole.find((b) => b.role === "driver")?.calls).toBe(2);
    expect(u.byRole.find((b) => b.role === "judge")?.model).toBe("anthropic/claude-haiku-4.5");
  });

  it("counts an unlabelled call rather than dropping it", async () => {
    // `role` is optional on the port. A call without one is still real
    // spend; the tempting bug is to skip what you can't classify.
    const m = meterLlm(fakeLlm());
    await m.complete({ messages: [] });
    expect(m.usage().calls).toBe(1);
    expect(m.usage().inputTokens).toBe(100);
  });

  it("says so when a provider reports no usage instead of implying zero", async () => {
    // A local model or a proxy that omits usage would otherwise make a
    // real run look free. "We don't know" and "nothing was spent" are
    // different claims and must not collapse into the same numbers.
    const m = meterLlm(fakeLlm({ usage: false }));
    await m.complete({ messages: [], role: "driver" });
    await m.complete({ messages: [], role: "driver" });

    const u = m.usage();
    expect(u.unmeteredCalls).toBe(2);
    expect(u.inputTokens).toBe(0);
    expect(u.calls).toBe(0); // not 2 — nothing was actually counted
  });

  it("does not alter the request, so metering cannot change a grade", async () => {
    let seen: unknown = null;
    const inner: LlmProvider = {
      name: "spy",
      complete(input): Promise<LlmResponse> {
        seen = input;
        return Promise.resolve({ text: "", toolCalls: [], stopReason: "end" });
      },
    };
    const sent = { messages: [], role: "judge" as const, temperature: 0 };
    await meterLlm(inner).complete(sent);
    expect(seen).toEqual(sent);
  });
});

describe("costing", () => {
  it("prices each role against its own model", async () => {
    const m = meterLlm(
      fakeLlm({ models: { driver: "openai/gpt-4o-mini", judge: "anthropic/claude-haiku-4.5" } }),
    );
    await m.complete({ messages: [], role: "driver" });
    await m.complete({ messages: [], role: "judge" });

    // driver: 100/1e6*0.15 + 20/1e6*0.60 = 0.000027
    // judge:  100/1e6*1.00 + 20/1e6*5.00 = 0.0002
    const est = estimateCost(m.usage(), PRICES);
    expect(est.usd).toBeCloseTo(0.000227, 9);
    expect(est.unpriced).toEqual([]);
  });

  it("names unpriced models rather than costing them at zero", async () => {
    // Silently costing an unknown model at zero produces a projection
    // that is too low and gets believed. Naming it makes the estimate's
    // incompleteness impossible to miss.
    const m = meterLlm(fakeLlm({ models: { driver: "some/new-model" } }));
    await m.complete({ messages: [], role: "driver" });

    const est = estimateCost(m.usage(), PRICES);
    expect(est.usd).toBe(0);
    expect(est.unpriced).toEqual(["some/new-model"]);
  });

  it("keeps sub-cent precision so a catalog projection isn't all zeroes", async () => {
    // One eval costs a fraction of a cent. Rounding to cents reports
    // every single one as $0 — and 3,000 × $0 is a $0 budget.
    const m = meterLlm(fakeLlm({ models: { driver: "openai/gpt-4o-mini" } }));
    await m.complete({ messages: [], role: "driver" });
    expect(estimateCost(m.usage(), PRICES).usd).toBeGreaterThan(0);
  });
});
