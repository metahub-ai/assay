/**
 * The check-authoring contract.
 *
 * The tests that matter here are the ones asserting that a check
 * CANNOT lie about its determinism. That guarantee is the framework's
 * central claim to outsiders — if it is merely a convention, every
 * "reproducible" badge downstream is unfounded.
 */
import { describe, expect, it } from "vitest";
import { CheckRegistry, defineCheck } from "../src/check";
import type { CheckDefinition } from "../src/check";
import { DEFAULT_CHECKS } from "../src/checks/index";

const ok = (over: Partial<CheckDefinition> = {}): CheckDefinition =>
  defineCheck({
    id: "sample-check",
    version: "1.0.0",
    title: "Sample",
    category: "structural",
    axis: "integrity",
    determinism: "deterministic",
    run: () => ({ status: "pass", summary: "fine" }),
    ...over,
  } as CheckDefinition);

describe("defineCheck validation", () => {
  it("accepts a well-formed deterministic check", () => {
    expect(ok().id).toBe("sample-check");
  });

  it("accepts a namespaced third-party id", () => {
    expect(ok({ id: "acme/no-eval" }).id).toBe("acme/no-eval");
  });

  it.each([["NotKebab"], ["has_underscore"], ["trailing-"], ["a//b"], [""]])(
    "rejects malformed id %s",
    (id) => {
      expect(() => ok({ id })).toThrow(/invalid check id/);
    },
  );

  it("rejects a non-semver version", () => {
    expect(() => ok({ version: "1.0" })).toThrow(/non-semver/);
  });

  // The load-bearing invariant.
  it("REFUSES a deterministic check that requests any capability", () => {
    for (const cap of ["net", "llm", "sandbox", "clock"] as const) {
      expect(() => ok({ determinism: "deterministic", needs: [cap] })).toThrow(
        /must be a pure function/,
      );
    }
  });

  it("refuses a replayable check that needs neither llm nor sandbox", () => {
    expect(() => ok({ determinism: "replayable", needs: ["net"] })).toThrow(
      /declare "deterministic"/,
    );
  });

  it("allows replayable with llm or sandbox", () => {
    expect(ok({ determinism: "replayable", needs: ["llm"] }).determinism).toBe("replayable");
    expect(ok({ determinism: "replayable", needs: ["sandbox"] }).determinism).toBe("replayable");
  });

  it("allows sampled to declare anything, including a clock", () => {
    expect(ok({ determinism: "sampled", needs: ["clock", "net"] }).needs).toEqual(["clock", "net"]);
  });

  it("rejects a negative weight", () => {
    expect(() => ok({ weight: -1 })).toThrow(/negative weight/);
  });

  it("freezes the definition so a registry cannot be mutated after load", () => {
    const def = ok();
    expect(Object.isFrozen(def)).toBe(true);
  });
});

describe("CheckRegistry", () => {
  it("orders checks by id so suite digests are stable", () => {
    const reg = CheckRegistry.from([ok({ id: "zulu" }), ok({ id: "alpha" }), ok({ id: "mike" })]);
    expect(reg.all().map((c) => c.id)).toEqual(["alpha", "mike", "zulu"]);
  });

  it("rejects a duplicate id at a conflicting version", () => {
    const reg = CheckRegistry.from([ok({ id: "dup", version: "1.0.0" })]);
    expect(() => reg.add(ok({ id: "dup", version: "2.0.0" }))).toThrow(/conflicting versions/);
  });

  it("tolerates re-registering the identical check", () => {
    const reg = CheckRegistry.from([ok({ id: "same", version: "1.0.0" })]);
    expect(() => reg.add(ok({ id: "same", version: "1.0.0" }))).not.toThrow();
    expect(reg.all()).toHaveLength(1);
  });

  it("filters by kind, treating an absent appliesTo as universal", () => {
    const reg = CheckRegistry.from([
      ok({ id: "universal" }),
      ok({ id: "skill-only", appliesTo: { kinds: ["skill"] } }),
      ok({ id: "mcp-only", appliesTo: { kinds: ["mcp"] } }),
    ]);
    expect(reg.forKind("skill").map((c) => c.id)).toEqual(["skill-only", "universal"]);
    expect(reg.forKind("agent").map((c) => c.id)).toEqual(["universal"]);
  });

  it("supports a kind the framework has never heard of", () => {
    const reg = CheckRegistry.from([ok({ id: "custom", appliesTo: { kinds: ["workflow"] } })]);
    expect(reg.forKind("workflow").map((c) => c.id)).toEqual(["custom"]);
  });

  it("runnableWith excludes checks whose capabilities are unavailable", () => {
    const reg = CheckRegistry.from([
      ok({ id: "pure" }),
      ok({ id: "needs-net", determinism: "sampled", needs: ["net"] }),
      ok({ id: "needs-llm", determinism: "replayable", needs: ["llm"] }),
    ]);
    expect(reg.runnableWith([]).map((c) => c.id)).toEqual(["pure"]);
    expect(reg.runnableWith(["net"]).map((c) => c.id)).toEqual(["needs-net", "pure"]);
    expect(reg.runnableWith(["net", "llm"]).map((c) => c.id)).toEqual([
      "needs-llm",
      "needs-net",
      "pure",
    ]);
  });
});

describe("every check can explain itself", () => {
  it("has a rationale", () => {
    // `assay explain <id>` is the #1 action the report recommends, and
    // 26 of 42 checks answered it with a bare metadata table — a table
    // teaches nobody why they should care. The report routed users
    // straight into that hole, naming the worst finding and telling
    // them to explain it.
    const bare = DEFAULT_CHECKS.filter((c) => !c.rationale?.trim()).map((c) => c.id);
    expect(bare).toEqual([]);
  });

  it("has a documentation URL", () => {
    const undocumented = DEFAULT_CHECKS.filter((c) => !c.spec).map((c) => c.id);
    expect(undocumented).toEqual([]);
  });

  it("states what it inspects, or gives an example, when it can block a publish", () => {
    // A blocking check takes something away from a publisher. The least
    // it owes them is a concrete picture of the line it draws.
    const vague = DEFAULT_CHECKS.filter(
      (c) => c.blocking && !c.inspects && !c.examples?.failing,
    ).map((c) => c.id);
    expect(vague).toEqual([]);
  });
});
