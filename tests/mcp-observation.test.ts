/**
 * The MCP protocol conformance scorer and the annotation truth-check.
 *
 * Both are pure functions over the handshake + catalog the driver
 * records, so they are exercised here without a sandbox. The
 * truth-check has two halves: declared-vs-description (precise, always
 * available) and declared-vs-observed (coarse, ledger-corroborated).
 */
import { describe, expect, it } from "vitest";
import {
  assessConformance,
  annotationTruth,
  type McpToolAnnotation,
} from "../src/behavioral/mcp-observation";

describe("assessConformance", () => {
  it("scores a clean, well-formed server at 100%", () => {
    const r = assessConformance({
      initialize: { protocolVersion: "2024-11-05", serverInfo: { name: "srv" } },
      tools: [{ name: "echo", hasInputSchema: true }],
      hasResources: false,
      hasPrompts: false,
    });
    expect(r.score).toBe(1);
    expect(r.checks.every((c) => c.ok)).toBe(true);
  });

  it("fails the handshake and version checks when initialize is absent", () => {
    const r = assessConformance({ tools: [], hasResources: false, hasPrompts: false });
    const byId = Object.fromEntries(r.checks.map((c) => [c.id, c.ok]));
    expect(byId["handshake"]).toBe(false);
    expect(byId["protocol-version"]).toBe(false);
    expect(byId["exposes-capability"]).toBe(false);
    expect(r.score).toBeLessThan(0.5);
  });

  it("flags a garbage protocol version", () => {
    const r = assessConformance({
      initialize: { protocolVersion: "banana", serverInfo: { name: "s" } },
      tools: [{ name: "t", hasInputSchema: true }],
      hasResources: false,
      hasPrompts: false,
    });
    expect(r.checks.find((c) => c.id === "protocol-version")?.ok).toBe(false);
  });

  it("counts a resources-only server as exposing a capability", () => {
    const r = assessConformance({
      initialize: { protocolVersion: "2024-11-05", serverInfo: { name: "s" } },
      tools: [],
      hasResources: true,
      hasPrompts: false,
    });
    expect(r.checks.find((c) => c.id === "exposes-capability")?.ok).toBe(true);
  });

  it("flags tools that omit an inputSchema", () => {
    const r = assessConformance({
      initialize: { protocolVersion: "2024-11-05", serverInfo: { name: "s" } },
      tools: [
        { name: "a", hasInputSchema: true },
        { name: "b", hasInputSchema: false },
      ],
      hasResources: false,
      hasPrompts: false,
    });
    expect(r.checks.find((c) => c.id === "tools-have-input-schema")?.ok).toBe(false);
  });
});

describe("annotationTruth", () => {
  const tool = (over: Partial<McpToolAnnotation>): McpToolAnnotation => ({
    name: "t",
    hasInputSchema: true,
    ...over,
  });

  it("catches a read-only tool whose description says it writes", () => {
    const f = annotationTruth([
      tool({ name: "save", readOnlyHint: true, description: "Writes the record to disk." }),
    ]);
    expect(f).toHaveLength(1);
    expect(f[0]!.fromRuntime).toBe(false);
    expect(f[0]!.contradiction).toMatch(/writes/i);
  });

  it("treats save / store / persist as state-changing", () => {
    const f = annotationTruth([
      tool({ name: "save_note", readOnlyHint: true, description: "Saves a note to disk." }),
    ]);
    expect(f).toHaveLength(1);
    expect(f[0]!.contradiction).toMatch(/saves/i);
  });

  it("leaves an honest read-only tool alone", () => {
    const f = annotationTruth([
      tool({ name: "get", readOnlyHint: true, description: "Returns the current value." }),
    ]);
    expect(f).toHaveLength(0);
  });

  it("corroborates via the ledger when a wholly read-only server mutated state", () => {
    const f = annotationTruth(
      [
        tool({ name: "a", readOnlyHint: true, description: "reads a value" }),
        tool({ name: "b", readOnlyHint: true, description: "lists values" }),
      ],
      { wroteOrDeletedFiles: true, spawnedProcesses: false, networked: false },
    );
    expect(f.some((x) => x.fromRuntime && x.contradiction.includes("wrote or deleted"))).toBe(true);
  });

  it("does NOT ledger-corroborate when some tool is annotated writable", () => {
    // A writable tool explains the observed writes, so the read-only
    // tools are not contradicted as a set.
    const f = annotationTruth(
      [
        tool({ name: "a", readOnlyHint: true, description: "reads a value" }),
        tool({ name: "b", readOnlyHint: false, description: "writes a value" }),
      ],
      { wroteOrDeletedFiles: true, spawnedProcesses: false, networked: false },
    );
    expect(f.some((x) => x.fromRuntime)).toBe(false);
  });

  it("returns nothing when there are no annotations to check", () => {
    expect(annotationTruth([tool({ name: "x", description: "does a thing" })])).toHaveLength(0);
  });
});
