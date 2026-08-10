/**
 * The declarative plugin loader.
 *
 * A plugin is JSON, so most of what matters is that a malformed one
 * fails LOUDLY at load — a rule that cannot compile must never be
 * silently absent, which is how a team ends up believing it has coverage
 * it does not. The other half is that a well-formed pattern check
 * behaves like a core check once compiled.
 */
import { describe, expect, it } from "vitest";
import { loadPlugins } from "../src/plugins";
import type { CheckContext } from "../src/check";
import type { Subject } from "../src/types";
import { MemorySource } from "../src/sources/memory";

const file = (obj: unknown, source = "acme.json") => ({ source, json: JSON.stringify(obj) });

const subject: Subject = {
  kind: "skill",
  name: "demo",
  source: { type: "directory", path: "/tmp/demo" },
  digest: { sha256: "0".repeat(64) },
};
function ctxFor(files: Record<string, string>): CheckContext {
  const noop = () => {};
  return {
    subject,
    source: new MemorySource(files),
    config: {},
    log: { debug: noop, info: noop, warn: noop, error: noop },
    signal: new AbortController().signal,
  };
}

describe("loadPlugins — pattern checks", () => {
  const spec = {
    checks: [
      {
        id: "acme/no-todo",
        title: "No TODO markers",
        axis: "care",
        files: "\\.(ts|md)$",
        pattern: "\\bTODO\\b",
        message: "Found a TODO marker.",
        remediation: "Resolve or remove it.",
        blocking: false,
      },
    ],
  };

  it("compiles a pattern check into a runnable CheckDefinition", () => {
    const { checks } = loadPlugins([file(spec)]);
    expect(checks).toHaveLength(1);
    expect(checks[0]!.id).toBe("acme/no-todo");
    expect(checks[0]!.axis).toBe("care");
    expect(checks[0]!.determinism).toBe("deterministic");
  });

  it("passes when nothing matches", async () => {
    const { checks } = loadPlugins([file(spec)]);
    const r = await checks[0]!.run(ctxFor({ "a.ts": "const x = 1;\n" }));
    expect(r.status).toBe("pass");
  });

  it("reports each matching line with file:line evidence", async () => {
    const { checks } = loadPlugins([file(spec)]);
    const r = await checks[0]!.run(
      ctxFor({ "a.ts": "ok\n// TODO fix this\nok\n", "b.png": "TODO" }),
    );
    expect(r.status).toBe("warn");
    expect(r.evidence?.[0]).toMatchObject({ type: "file", path: "a.ts", line: 2 });
    // b.png does not match the files regex, so it is not scanned.
    expect(r.detail).not.toMatch(/b\.png/);
  });

  it("fails (blocking) when the spec asks", async () => {
    const blocking = {
      checks: [{ ...spec.checks[0], id: "acme/no-secret", blocking: true, pattern: "SECRET" }],
    };
    const { checks } = loadPlugins([file(blocking)]);
    expect(checks[0]!.blocking).toBe(true);
    const r = await checks[0]!.run(ctxFor({ "a.ts": "const SECRET = 1;\n" }));
    expect(r.status).toBe("fail");
  });
});

describe("loadPlugins — probes", () => {
  it("compiles a probe, tagged adversarial and to its kind", () => {
    const { probes } = loadPlugins([
      file({
        probes: [
          {
            id: "acme/probe-x",
            kind: "mcp",
            prompt: "Do the forbidden thing.",
            expect: "Refuses.",
          },
        ],
      }),
    ]);
    expect(probes).toHaveLength(1);
    expect(probes[0]!.kind).toBe("mcp");
    expect(probes[0]!.probe.adversarial).toBe(true);
    expect(probes[0]!.probe.expect).toBe("Refuses.");
  });
});

describe("loadPlugins — validation fails loudly", () => {
  it("rejects a non-namespaced check id (would shadow a core check)", () => {
    expect(() =>
      loadPlugins([
        file({
          checks: [
            { id: "no-todo", title: "x", axis: "care", files: ".", pattern: "x", message: "m" },
          ],
        }),
      ]),
    ).toThrow(/must be namespaced/);
  });

  it("rejects the behavior axis (not declarative)", () => {
    expect(() =>
      loadPlugins([
        file({
          checks: [
            { id: "a/b", title: "x", axis: "behavior", files: ".", pattern: "x", message: "m" },
          ],
        }),
      ]),
    ).toThrow(/behavior is not declarative/);
  });

  it("rejects an invalid regex", () => {
    expect(() =>
      loadPlugins([
        file({
          checks: [{ id: "a/b", title: "x", axis: "care", files: "(", pattern: "x", message: "m" }],
        }),
      ]),
    ).toThrow(/not a valid regex/);
  });

  it("rejects a duplicate id across checks and probes", () => {
    expect(() =>
      loadPlugins([
        file({
          checks: [
            { id: "a/dup", title: "x", axis: "care", files: ".", pattern: "x", message: "m" },
          ],
          probes: [{ id: "a/dup", kind: "skill", prompt: "p" }],
        }),
      ]),
    ).toThrow(/duplicate id/);
  });

  it("rejects a probe with an unknown kind", () => {
    expect(() =>
      loadPlugins([file({ probes: [{ id: "a/p", kind: "wombat", prompt: "p" }] })]),
    ).toThrow(/"kind" must be one of/);
  });

  it("rejects malformed JSON with the source name", () => {
    expect(() => loadPlugins([{ source: "broken.json", json: "{ not json" }])).toThrow(
      /plugin broken\.json: not valid JSON/,
    );
  });

  it("notes a plugin that declares nothing", () => {
    const { notes } = loadPlugins([file({})]);
    expect(notes.some((n) => /declared neither/.test(n))).toBe(true);
  });
});
