import { describe, expect, it } from "vitest";
import { BUILTIN_SUITES, DEFAULT_SUITE_ID, isBuiltinSuite, resolveSuite } from "../src/suites";
import { DEFAULT_CHECKS } from "../src/checks/index";

describe("built-in suites", () => {
  it("exposes the three documented presets", () => {
    expect(Object.keys(BUILTIN_SUITES).sort()).toEqual([
      "assay:mcp-server",
      "assay:recommended",
      "assay:strict",
    ]);
  });

  it("recommended is the default and carries no gate", () => {
    const s = resolveSuite(DEFAULT_SUITE_ID);
    expect(s.id).toBe("assay:recommended");
    expect(s.checks).toEqual(DEFAULT_CHECKS);
    expect(s.policy).toBeUndefined();
  });

  it("strict runs the full set but adds a passing bar", () => {
    const s = resolveSuite("assay:strict");
    expect(s.checks).toEqual(DEFAULT_CHECKS);
    expect(s.policy?.minScore).toBe(85);
  });

  it("mcp-server is a curated, smaller composition without skill/agent/plugin checks", () => {
    const s = resolveSuite("assay:mcp-server");
    expect(s.checks.length).toBeGreaterThan(0);
    expect(s.checks.length).toBeLessThan(DEFAULT_CHECKS.length);
    // No kind-specific checks for other kinds leak in.
    for (const c of s.checks) {
      const kinds = c.appliesTo?.kinds;
      if (kinds) {
        expect(kinds).toContain("mcp");
      }
    }
  });

  it("every built-in suite is composed of registrable, unique checks", () => {
    for (const suite of Object.values(BUILTIN_SUITES)) {
      const ids = suite.checks.map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });
});

describe("resolveSuite", () => {
  it("defaults to recommended when nothing is named", () => {
    expect(resolveSuite(undefined).id).toBe("assay:recommended");
  });

  it("treats an unknown NON-reserved id as a cosmetic label over the default set", () => {
    const s = resolveSuite("acme-internal");
    expect(s.id).toBe("acme-internal");
    expect(s.checks).toEqual(DEFAULT_CHECKS);
    expect(s.policy).toBeUndefined();
  });

  it("rejects a typo'd reserved assay: id loudly instead of silently running default", () => {
    expect(() => resolveSuite("assay:strickt")).toThrow(/unknown built-in suite/);
  });

  it("isBuiltinSuite distinguishes reserved presets from labels", () => {
    expect(isBuiltinSuite("assay:strict")).toBe(true);
    expect(isBuiltinSuite("acme-internal")).toBe(false);
  });
});
