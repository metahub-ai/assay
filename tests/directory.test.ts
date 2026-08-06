/**
 * The local-directory source and the CLI.
 *
 * The containment tests here are security tests, not hygiene. A check
 * is ordinary code from a stranger; if `readFile("../../../etc/passwd")`
 * works, then the capability model leaks — a check that declared no
 * capabilities at all could still read the host filesystem, and every
 * "deterministic" guarantee downstream becomes untrue.
 */
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DirectorySource, RUNTIME_IGNORE } from "../src/sources/directory";
import { MemorySource } from "../src/sources/memory";
import { findAgentMarkdown } from "../src/checks/docs-resolution";
import { digestTree } from "../src/digest";
import { blockingFailures, cli, detectKind, main } from "../src/cli";
import type { AssayReport } from "../src/types";

let root: string;
let outside: string;

beforeAll(() => {
  outside = mkdtempSync(join(tmpdir(), "assay-outside-"));
  writeFileSync(join(outside, "secret.txt"), "do not read me");

  root = mkdtempSync(join(tmpdir(), "assay-root-"));
  writeFileSync(join(root, "README.md"), "# Demo\nA demo artifact.");
  writeFileSync(join(root, "SKILL.md"), "---\nname: demo\n---\n# Demo");
  mkdirSync(join(root, "src"));
  writeFileSync(join(root, "src", "index.js"), "export default 1;");
  mkdirSync(join(root, "node_modules", "dep"), { recursive: true });
  writeFileSync(join(root, "node_modules", "dep", "index.js"), "module.exports={}");
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main");
  symlinkSync(join(outside, "secret.txt"), join(root, "escape-link"));
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});

describe("DirectorySource containment", () => {
  it.each([
    "../secret.txt",
    "../../etc/passwd",
    "src/../../secret.txt",
    "/etc/passwd",
    "C:\\Windows\\system32\\config\\sam",
  ])("refuses to read outside the root via %s", async (path) => {
    const s = new DirectorySource(root);
    expect(await s.readFile(path)).toBeNull();
    expect(await s.readBytes(path)).toBeNull();
    expect(await s.exists(path)).toBe(false);
  });

  it("records a symlink but never follows it", async () => {
    const s = new DirectorySource(root);
    const tree = await s.listTree();
    const link = tree.find((e) => e.path === "escape-link");
    expect(link?.type).toBe("symlink");
    // Following it would escape the root AND make the digest depend on
    // the host filesystem rather than the artifact.
    expect(await s.readFile("escape-link")).toBeNull();
  });

  it("allows ordinary nested reads", async () => {
    const s = new DirectorySource(root);
    expect(await s.readFile("src/index.js")).toContain("export default");
  });
});

describe("DirectorySource walking", () => {
  it("ignores .git and node_modules by default", async () => {
    const paths = (await new DirectorySource(root).listTree()).map((e) => e.path);
    expect(paths.some((p) => p.startsWith(".git"))).toBe(false);
    expect(paths.some((p) => p.startsWith("node_modules"))).toBe(false);
  });

  it("returns a deterministically ordered tree", async () => {
    const a = (await new DirectorySource(root).listTree()).map((e) => e.path);
    const b = (await new DirectorySource(root).listTree()).map((e) => e.path);
    expect(a).toEqual(b);
    expect(a).toEqual([...a].sort());
  });

  it("reports file sizes and directory entries", async () => {
    const tree = await new DirectorySource(root).listTree();
    expect(tree.find((e) => e.path === "src")?.type).toBe("dir");
    expect(tree.find((e) => e.path === "README.md")?.size).toBeGreaterThan(0);
  });

  it("honours a custom ignore list", async () => {
    const s = new DirectorySource(root, { ignore: ["src", ".git", "node_modules"] });
    expect((await s.listTree()).some((e) => e.path.startsWith("src"))).toBe(false);
  });

  it("refuses to read a file above the size ceiling", async () => {
    const s = new DirectorySource(root, { maxFileBytes: 4 });
    expect(await s.readFile("README.md")).toBeNull();
  });

  it("returns an empty tree for a path that does not exist", async () => {
    expect(await new DirectorySource(join(root, "nope")).listTree()).toEqual([]);
  });

  it("memoizes reads", async () => {
    const s = new DirectorySource(root);
    expect(await s.readFile("README.md")).toBe(await s.readFile("README.md"));
  });
});

describe("digest over a real directory", () => {
  it("is stable across instances", async () => {
    expect(await digestTree(new DirectorySource(root))).toBe(
      await digestTree(new DirectorySource(root)),
    );
  });

  it("does not depend on ignored developer-local state", async () => {
    // A fresh clone and a working checkout must digest identically,
    // otherwise a report is about a machine rather than an artifact.
    const before = await digestTree(new DirectorySource(root));
    writeFileSync(join(root, ".git", "index"), "junk");
    mkdirSync(join(root, "node_modules", "other"), { recursive: true });
    writeFileSync(join(root, "node_modules", "other", "x.js"), "1");
    expect(await digestTree(new DirectorySource(root))).toBe(before);
  });
});

describe("kind detection", () => {
  it("detects a skill from SKILL.md", async () => {
    expect(await detectKind(new DirectorySource(root))).toBe("skill");
  });

  it("detects a plugin from its manifest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-plugin-"));
    mkdirSync(join(dir, ".claude-plugin"));
    writeFileSync(join(dir, ".claude-plugin", "plugin.json"), "{}");
    expect(await detectKind(new DirectorySource(dir))).toBe("plugin");
    rmSync(dir, { recursive: true, force: true });
  });

  it("detects an MCP server from its SDK dependency", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-mcp-"));
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ dependencies: { "@modelcontextprotocol/sdk": "^1" } }),
    );
    expect(await detectKind(new DirectorySource(dir))).toBe("mcp");
    rmSync(dir, { recursive: true, force: true });
  });

  // `agent-shape-declared` could resolve a prompt-based agent perfectly
  // well while detection could not, so a real agent published on its own
  // answered "could not tell what kind of artifact this is" unless you
  // passed --kind. Both now share `findAgentMarkdown`.
  it("detects a prompt-based agent from a frontmattered markdown file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-agent-"));
    writeFileSync(
      join(dir, "reviewer.md"),
      "---\nname: reviewer\ndescription: Reviews code\n---\nYou are a reviewer.",
    );
    expect(await detectKind(new DirectorySource(dir))).toBe("agent");
    rmSync(dir, { recursive: true, force: true });
  });

  it("detects an agent in the conventional agents/ directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-agent2-"));
    mkdirSync(join(dir, "agents"));
    writeFileSync(join(dir, "agents", "debugger.md"), "---\nname: debugger\n---\nYou debug.");
    expect(await detectKind(new DirectorySource(dir))).toBe("agent");
    rmSync(dir, { recursive: true, force: true });
  });

  // Agent detection runs LAST for exactly this reason: real plugins ship
  // an `agents/` directory, and calling one of those an agent would
  // reclassify a large part of the ecosystem.
  it("still calls a plugin a plugin even when it bundles agents", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-plugagent-"));
    mkdirSync(join(dir, ".claude-plugin"));
    writeFileSync(join(dir, ".claude-plugin", "plugin.json"), '{"name":"x"}');
    mkdirSync(join(dir, "agents"));
    writeFileSync(join(dir, "agents", "helper.md"), "---\nname: helper\n---\nYou help.");
    expect(await detectKind(new DirectorySource(dir))).toBe("plugin");
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not mistake project meta for an agent", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-meta-"));
    for (const f of ["README.md", "CONTRIBUTING.md", "CLAUDE.md"]) {
      writeFileSync(join(dir, f), "---\ntitle: x\n---\nSome project documentation.");
    }
    expect(await detectKind(new DirectorySource(dir))).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("returns null rather than guessing when nothing matches", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-unknown-"));
    writeFileSync(join(dir, "notes.txt"), "hello");
    expect(await detectKind(new DirectorySource(dir))).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });

  it("survives an unparseable package.json", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-broken-"));
    writeFileSync(join(dir, "package.json"), "{oops");
    expect(await detectKind(new DirectorySource(dir))).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("blockingFailures", () => {
  const report = (results: unknown[]) => ({ results }) as AssayReport;

  it("counts only blocking failures", () => {
    expect(
      blockingFailures(
        report([
          { status: "fail", blocking: true },
          { status: "fail", blocking: false },
          { status: "warn", blocking: true },
          { status: "pass", blocking: true },
        ]),
      ),
    ).toHaveLength(1);
  });

  it("does not treat our own error as a blocking failure", () => {
    // An infrastructure error must never gate someone's publish.
    expect(blockingFailures(report([{ status: "error", blocking: true }]))).toHaveLength(0);
  });
});

describe("the CLI end to end", () => {
  let out: string;
  let err: string;
  const capture = () => {
    out = "";
    err = "";
    const so = process.stdout.write.bind(process.stdout);
    const se = process.stderr.write.bind(process.stderr);
    process.stdout.write = ((s: string) => ((out += s), true)) as typeof process.stdout.write;
    process.stderr.write = ((s: string) => ((err += s), true)) as typeof process.stderr.write;
    return () => {
      process.stdout.write = so;
      process.stderr.write = se;
    };
  };

  it("prints usage and exits 0 for --help", async () => {
    const restore = capture();
    const code = await main(["--help"]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/USAGE/);
  });

  it("rejects an unknown flag with exit 2", async () => {
    const restore = capture();
    const code = await main(["--nope"]);
    restore();
    expect(code).toBe(2);
    expect(err).toMatch(/unknown flag/);
  });

  it("exits 2 when the path cannot be read", async () => {
    const restore = capture();
    const code = await main([join(tmpdir(), "assay-does-not-exist-xyz")]);
    restore();
    expect(code).toBe(2);
  });

  it("exits 2 — rather than guessing — when the kind is undeterminable", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-nokind-"));
    writeFileSync(join(dir, "notes.txt"), "hello");
    const restore = capture();
    const code = await main([dir]);
    restore();
    expect(code).toBe(2);
    expect(err).toMatch(/--kind/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("evaluates a clean artifact and exits 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-clean-"));
    // A genuinely clean artifact: the expanded catalog requires a
    // description, a substantive body, and a declared tool scope.
    writeFileSync(
      join(dir, "SKILL.md"),
      "---\nname: ok\ndescription: Use when the user wants tidy markdown tables from raw text\nallowed-tools: []\n---\n# OK\n" +
        "word ".repeat(80),
    );
    writeFileSync(join(dir, "LICENSE"), "MIT");
    writeFileSync(join(dir, "README.md"), "# OK\n```sh\nassay run .\n```\n" + "word ".repeat(80));
    const restore = capture();
    const code = await main([dir]);
    restore();
    expect(code).toBe(0);
    // The headline number and every axis, with coverage beside each —
    // an axis rendered without its coverage is the specific dishonesty
    // the scorer exists to prevent.
    expect(out).toMatch(/OVERALL/);
    for (const axis of ["integrity", "safety", "care", "behavior"]) {
      expect(out).toContain(axis);
    }
    expect(out).toMatch(/measured|not measured/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("exits 1 on a blocking failure, and says which", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-leak-"));
    writeFileSync(join(dir, "SKILL.md"), "---\nname: leak\n---\n# Leak");
    writeFileSync(join(dir, ".env"), "TOKEN=abc");
    const restore = capture();
    const code = await main([dir]);
    restore();
    expect(code).toBe(1);
    expect(err).toMatch(/blocking check/);
    rmSync(dir, { recursive: true, force: true });
  });

  it("emits a machine-readable report with --json", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-json-"));
    writeFileSync(join(dir, "SKILL.md"), "---\nname: j\n---\n# J");
    const restore = capture();
    await main([dir, "--json"]);
    restore();
    const report = JSON.parse(out) as AssayReport;
    expect(report.schemaVersion).toBe("1");
    expect(report.subject.kind).toBe("skill");
    // The offline run must be recorded as such, so a reader can tell a
    // low score reflects the scan rather than the artifact.
    expect(report.environment.scanContext).toEqual({
      credentials: "anonymous",
      network: "none",
    });
    rmSync(dir, { recursive: true, force: true });
  });

  it("honours an explicit --kind over detection", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-kind-"));
    writeFileSync(join(dir, "SKILL.md"), "---\nname: k\n---\n# K");
    const restore = capture();
    await main([dir, "--kind", "plugin", "--json"]);
    restore();
    expect((JSON.parse(out) as AssayReport).subject.kind).toBe("plugin");
    rmSync(dir, { recursive: true, force: true });
  });

  it("--quiet hides passing checks", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-quiet-"));
    writeFileSync(join(dir, "SKILL.md"), "---\nname: q\n---\n# Q");
    writeFileSync(join(dir, "README.md"), "word ".repeat(80));
    const restore = capture();
    await main([dir, "--quiet"]);
    restore();
    expect(out).not.toMatch(/README present/);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("kind detection for non-Node artifacts", () => {
  // Detection looked only at package.json, so pointing Assay at a
  // reference server published by the people who define the protocol
  // produced "could not determine the artifact kind".
  it("detects a Python MCP server from pyproject.toml", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-pymcp-"));
    writeFileSync(
      join(dir, "pyproject.toml"),
      '[project]\nname = "mcp-server-fetch"\ndependencies = [\n  "mcp>=1.1.3",\n]\n',
    );
    expect(await detectKind(new DirectorySource(dir))).toBe("mcp");
    rmSync(dir, { recursive: true, force: true });
  });

  it("does not claim every pyproject.toml is an MCP server", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-py-"));
    writeFileSync(join(dir, "pyproject.toml"), '[project]\nname = "requests"\n');
    expect(await detectKind(new DirectorySource(dir))).toBeNull();
    rmSync(dir, { recursive: true, force: true });
  });
});

/**
 * Two ignore lists, because analysis and execution want opposite things.
 *
 * `DEFAULT_IGNORE` excludes build output — right for hashing, linting
 * and counting the author's work. `RUNTIME_IGNORE` must not, because a
 * package published to npm ships `dist/` and nothing else: filtering it
 * on the way into the sandbox delivered a package.json and a README and
 * no code, the server could not start, and the artifact was scored for
 * a failure the harness had created.
 */
describe("runtime vs analysis ignore lists", () => {
  it("excludes build output from ANALYSIS", () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-ign-"));
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "index.js"), "run();");
    writeFileSync(join(dir, "package.json"), "{}");
    const paths = new DirectorySource(dir);
    return paths.listTree().then((tree) => {
      expect(tree.map((e) => e.path)).not.toContain("dist/index.js");
      rmSync(dir, { recursive: true, force: true });
    });
  });

  it("KEEPS build output for EXECUTION", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-ign2-"));
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "index.js"), "run();");
    writeFileSync(join(dir, "package.json"), "{}");
    const tree = await new DirectorySource(dir, { ignore: RUNTIME_IGNORE }).listTree();
    expect(tree.map((e) => e.path)).toContain("dist/index.js");
    rmSync(dir, { recursive: true, force: true });
  });

  // Dependency trees and VCS metadata stay out of both: enormous, and
  // reconstructible by the install step.
  it.each(["node_modules", ".git"])("excludes %s from execution too", async (name) => {
    const dir = mkdtempSync(join(tmpdir(), "assay-ign3-"));
    mkdirSync(join(dir, name));
    writeFileSync(join(dir, name, "x.js"), "x");
    writeFileSync(join(dir, "package.json"), "{}");
    const tree = await new DirectorySource(dir, { ignore: RUNTIME_IGNORE }).listTree();
    expect(tree.map((e) => e.path)).not.toContain(`${name}/x.js`);
    rmSync(dir, { recursive: true, force: true });
  });
});

/**
 * Every CLI is expected to answer this, and this one did not:
 * `--version` reported "unknown flag" and `-v` was parsed as a positional
 * path, producing "No directory at ./-v".
 */
describe("version flag", () => {
  it.each(["--version", "-v", "version"])("%s prints the version and exits 0", async (flag) => {
    let captured = "";
    const original = process.stdout.write;

    (process.stdout as any).write = (s: string) => ((captured += s), true);
    let code: number;
    try {
      code = await cli([flag]);
    } finally {
      (process.stdout as any).write = original;
    }
    expect(code).toBe(0);
    expect(captured.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("agent discovery reaches real collection layouts", () => {
  it("finds an agent nested under plugins/<name>/agents/", async () => {
    // `wshobson/agents` and `VoltAgent/awesome-claude-code-subagents`
    // — two of the most-starred agent collections — both false-failed
    // `agent-shape-declared`, a BLOCKING check, because discovery
    // anchored `agents/` to the repository root.
    const src = new MemorySource({
      "plugins/accessibility/agents/reviewer.md":
        "---\nname: reviewer\ndescription: Reviews\n---\nBody",
      "README.md": "# Collection",
    });
    expect(await findAgentMarkdown(src)).toBe("plugins/accessibility/agents/reviewer.md");
  });

  it("finds an agent by its frontmatter shape when the directory is not conventional", async () => {
    const src = new MemorySource({
      "categories/01-core/api-designer.md":
        "---\nname: api-designer\ndescription: Designs APIs\n---\nBody",
      "README.md": "# Collection",
    });
    expect(await findAgentMarkdown(src)).toBe("categories/01-core/api-designer.md");
  });

  it("prefers the shallowest definition in a large collection", async () => {
    const src = new MemorySource({
      "agents/top.md": "---\nname: top\ndescription: d\n---\n",
      "plugins/x/agents/deep.md": "---\nname: deep\ndescription: d\n---\n",
    });
    expect(await findAgentMarkdown(src)).toBe("agents/top.md");
  });

  it("does not mistake project meta for an agent", async () => {
    // Without the name filter, any repo with a CONTRIBUTING.md would
    // "contain an agent" — a false positive in the other direction.
    const src = new MemorySource({
      "CONTRIBUTING.md": "---\nname: x\ndescription: y\n---\nHow to contribute",
      "AGENTS.md": "---\nname: x\ndescription: y\n---\nRepo instructions",
      "README.md": "# Project",
    });
    expect(await findAgentMarkdown(src)).toBeNull();
  });
});
