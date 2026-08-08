/**
 * The four kind-specific harnesses, driven offline against the fakes.
 *
 * These exist to prove the framework's own claim about itself: a
 * behavioral harness that can only be exercised against a live cloud
 * sandbox and a paid model is one nobody can audit, contribute to, or
 * run in CI. Every path below runs from an in-memory filesystem and a
 * rule-driven model in milliseconds.
 */
import { describe, expect, it } from "vitest";
import { runBehavioralEval } from "../src/behavioral/run";
import { runSkillCase } from "../src/behavioral/harness/skill";
import { runAgentCase } from "../src/behavioral/harness/agent";
import { runMcpCase } from "../src/behavioral/harness/mcp";
import { fakeLlmProvider, FakeSandbox, makeFakeSandboxProvider } from "./fakes";
import { SandboxInfraError } from "../src/ports";
import type { EvalTestCase } from "../src/behavioral/types";

const test: EvalTestCase = { id: "t1", prompt: "Do the primary thing." };

const base = {
  doc: "# Artifact\nDoes a thing.",
  llm: fakeLlmProvider,
  probeCount: 0,
  caseCount: 1,
};

describe("all four kinds run end to end", () => {
  it.each(["skill", "mcp", "agent", "plugin"] as const)("evaluates a %s", async (kind) => {
    const r = await runBehavioralEval({
      ...base,
      kind,
      sandboxProvider: makeFakeSandboxProvider(),
      // Non-skill kinds need files on disk, so exercise the clone path.
      ...(kind === "skill" ? {} : { repoUrl: "https://example.com/r.git", commit: "deadbee" }),
    });
    expect(r.error).toBeUndefined();
    expect(r.tests).toHaveLength(1);
    expect(r.tests[0]!.transcript.messages.length).toBeGreaterThan(0);
  });

  it("routes a prompt-based agent through the skill loop, not install-and-exec", async () => {
    const provider = makeFakeSandboxProvider();
    const r = await runBehavioralEval({
      ...base,
      kind: "agent",
      promptBased: true,
      sandboxProvider: provider,
    });
    expect(r.error).toBeUndefined();
    // The skill loop drives the model with tools; the exec path would
    // have shelled out to `npm install` instead.
    expect(r.tests[0]!.transcript.toolCalls.length).toBeGreaterThan(0);
  });
});

describe("workspace provisioning", () => {
  it("clones at the pinned commit", async () => {
    const sandbox = new FakeSandbox();
    const provider = { name: "fake", create: async () => sandbox };
    await runBehavioralEval({
      ...base,
      kind: "mcp",
      sandboxProvider: provider,
      repoUrl: "https://example.com/r.git",
      commit: "deadbee",
    });
    const cmds = sandbox.execLog.map((e) => e.cmd).join("\n");
    expect(cmds).toMatch(/git clone/);
    expect(cmds).toMatch(/git checkout "deadbee"/);
  });

  it("uses the adapter's declared workdir rather than assuming /workspace", async () => {
    // The E2B bug: `/workspace` is not writable for an unprivileged
    // user, which broke every clone-requiring kind while skills passed.
    const sandbox = new FakeSandbox();
    Object.defineProperty(sandbox, "workdir", { value: "/home/user/workspace" });
    const provider = { name: "fake", create: async () => sandbox };
    await runBehavioralEval({
      ...base,
      kind: "mcp",
      sandboxProvider: provider,
      repoUrl: "https://example.com/r.git",
    });
    expect(sandbox.execLog.map((e) => e.cmd).join("\n")).toContain("/home/user/workspace");
  });

  it("only makes a directory when there is no repo to clone", async () => {
    const sandbox = new FakeSandbox();
    const provider = { name: "fake", create: async () => sandbox };
    await runBehavioralEval({ ...base, kind: "skill", sandboxProvider: provider });
    const cmds = sandbox.execLog.map((e) => e.cmd).join("\n");
    expect(cmds).toMatch(/mkdir -p/);
    expect(cmds).not.toMatch(/git clone/);
  });

  it("surfaces a clone failure as an error result rather than throwing", async () => {
    const provider = {
      name: "fake",
      create: async () =>
        new FakeSandbox({
          rules: [
            {
              match: /git clone/,
              result: () => ({
                exitCode: 128,
                stdout: "",
                stderr: "repository not found",
                durationMs: 5,
                timedOut: false,
              }),
            },
          ],
        }),
    };
    const r = await runBehavioralEval({
      ...base,
      kind: "mcp",
      sandboxProvider: provider,
      repoUrl: "https://example.com/missing.git",
    });
    expect(r.error).toMatch(/git clone failed/);
  });
});

describe("skill harness", () => {
  it("round-trips tool calls through the sandbox", async () => {
    const sandbox = new FakeSandbox();
    const t = await runSkillCase({
      llm: fakeLlmProvider,
      sandbox,
      skillDoc: "# Skill\nDoes things.",
      cwd: "/workspace",
      test,
    });
    expect(t.toolCalls.length).toBeGreaterThan(0);
    expect(t.messages.some((m) => m.role === "tool")).toBe(true);
  });

  it("surfaces skill-declared allowed tools to the model", async () => {
    const sandbox = new FakeSandbox();
    const t = await runSkillCase({
      llm: {
        name: "tool-lister",
        complete: async (input) => ({
          text: (input.tools ?? []).map((x) => x.name).join(","),
          toolCalls: [],
          stopReason: "end",
        }),
      },
      sandbox,
      skillDoc: "doc",
      allowedTools: ["Grep", "WebFetch"],
      test,
    });
    expect(t.messages[t.messages.length - 1]!.content).toContain("tool_grep");
    expect(t.messages[t.messages.length - 1]!.content).toContain("tool_webfetch");
  });

  it("records a tool error as a result instead of aborting the case", async () => {
    const sandbox = new FakeSandbox();
    sandbox.exec = async () => {
      throw new Error("sandbox exec exploded");
    };
    const t = await runSkillCase({
      llm: fakeLlmProvider,
      sandbox,
      skillDoc: "doc",
      test,
    });
    expect(t.messages.some((m) => m.content.includes("tool error"))).toBe(true);
  });

  it("refuses a malformed tool argument instead of running [object Object]", async () => {
    const sandbox = new FakeSandbox();
    const ran: string[] = [];
    sandbox.exec = async (cmd: string) => {
      ran.push(cmd);
      return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
    };
    let turn = 0;
    const t = await runSkillCase({
      llm: {
        name: "malformed",
        complete: async () => {
          turn++;
          return turn === 1
            ? {
                text: "",
                // Providers really do send this when they ignore the
                // schema. `String()` would render it "[object Object]".
                toolCalls: [{ id: "c1", name: "bash", input: { cmd: { command: "ls" } } }],
                stopReason: "tool_use" as const,
              }
            : { text: "done", toolCalls: [], stopReason: "end" as const };
        },
      },
      sandbox,
      skillDoc: "doc",
      test,
    });
    expect(ran).toEqual([]);
    expect(t.messages.some((m) => m.content.includes('needs "cmd" as a string'))).toBe(true);
  });

  it("accepts an argv array as a command", async () => {
    const sandbox = new FakeSandbox();
    const ran: string[] = [];
    sandbox.exec = async (cmd: string) => {
      ran.push(cmd);
      return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
    };
    let turn = 0;
    await runSkillCase({
      llm: {
        name: "argv",
        complete: async () => {
          turn++;
          return turn === 1
            ? {
                text: "",
                toolCalls: [{ id: "c1", name: "bash", input: { cmd: ["ls", "-la"] } }],
                stopReason: "tool_use" as const,
              }
            : { text: "done", toolCalls: [], stopReason: "end" as const };
        },
      },
      sandbox,
      skillDoc: "doc",
      test,
    });
    expect(ran).toEqual(["ls -la"]);
  });

  it("writes and reads files through the sandbox", async () => {
    const sandbox = new FakeSandbox();
    let turn = 0;
    const t = await runSkillCase({
      llm: {
        name: "writer",
        complete: async () => {
          turn++;
          if (turn === 1) {
            return {
              text: "",
              toolCalls: [
                { id: "c1", name: "write_file", input: { path: "/out.txt", contents: "hello" } },
              ],
              stopReason: "tool_use" as const,
            };
          }
          if (turn === 2) {
            return {
              text: "",
              toolCalls: [{ id: "c2", name: "read_file", input: { path: "/out.txt" } }],
              stopReason: "tool_use" as const,
            };
          }
          return { text: "done", toolCalls: [], stopReason: "end" as const };
        },
      },
      sandbox,
      skillDoc: "doc",
      test,
    });
    expect(t.messages.some((m) => m.role === "tool" && m.content === "hello")).toBe(true);
  });
});

describe("agent harness", () => {
  it("installs, locates an entry, and records the invocation as a tool call", async () => {
    const sandbox = new FakeSandbox({ files: { "/workspace/agent.mjs": "export default {}" } });
    const t = await runAgentCase({ sandbox, cwd: "/workspace", test });
    expect(sandbox.execLog.some((e) => /npm install/.test(e.cmd))).toBe(true);
    // The invocation is recorded so the safety scan can see exactly
    // what was run.
    expect(t.toolCalls.some((c) => c.name === "run_agent")).toBe(true);
  });

  it("reports honestly when no entry file can be found", async () => {
    const sandbox = new FakeSandbox({
      rules: [
        {
          match: /test\s+-f/,
          result: () => ({
            exitCode: 1,
            stdout: "",
            stderr: "",
            durationMs: 1,
            timedOut: false,
          }),
        },
      ],
    });
    const t = await runAgentCase({ sandbox, cwd: "/workspace", test });
    expect(t.messages.some((m) => m.content.includes("entry file not found"))).toBe(true);
    expect(t.toolCalls).toHaveLength(0);
  });
});

describe("plugin harness", () => {
  const manifest = JSON.stringify({
    name: "demo-plugin",
    skills: ["skills/format"],
    commands: ["fmt"],
    mcpServers: { demo: { command: "node", args: ["server.js"] } },
  });

  it("loads the manifest, enumerates capabilities, and smoke-runs them", async () => {
    const provider = {
      name: "fake",
      create: async () =>
        new FakeSandbox({
          files: {
            "/workspace/.claude-plugin/plugin.json": manifest,
            "/workspace/skills/format/SKILL.md": "# Format\nFormats text.",
          },
        }),
    };
    const r = await runBehavioralEval({
      ...base,
      kind: "plugin",
      sandboxProvider: provider,
      repoUrl: "https://example.com/r.git",
    });
    expect(r.error).toBeUndefined();
    const text = r.tests[0]!.transcript.messages.map((m) => m.content).join("\n");
    expect(text).toMatch(/loaded manifest/);
    expect(text).toMatch(/demo-plugin/);
  });

  it("reports honestly when the manifest is missing", async () => {
    const provider = { name: "fake", create: async () => new FakeSandbox() };
    const r = await runBehavioralEval({
      ...base,
      kind: "plugin",
      sandboxProvider: provider,
      repoUrl: "https://example.com/r.git",
    });
    const text = r.tests[0]!.transcript.messages.map((m) => m.content).join("\n");
    expect(text).toMatch(/manifest not found/);
  });

  it("handles a manifest that declares nothing bundled", async () => {
    const provider = {
      name: "fake",
      create: async () =>
        new FakeSandbox({
          files: { "/workspace/plugin.json": JSON.stringify({ name: "empty" }) },
        }),
    };
    const r = await runBehavioralEval({
      ...base,
      kind: "plugin",
      sandboxProvider: provider,
      repoUrl: "https://example.com/r.git",
    });
    expect(r.error).toBeUndefined();
    const text = r.tests[0]!.transcript.messages.map((m) => m.content).join("\n");
    expect(text).toMatch(/skills=0 commands=0/);
  });
});

describe("mcp harness", () => {
  const driverOut = (o: unknown) => JSON.stringify(o);
  const withDriver = (stdout: string, exitCode = 0) =>
    new FakeSandbox({
      rules: [
        {
          match: /mcp-driver\.mjs/,
          result: () => ({ exitCode, stdout, stderr: "", durationMs: 5, timedOut: false }),
        },
      ],
    });

  it("records the handshake and the tool catalog", async () => {
    const sandbox = withDriver(
      driverOut({
        ok: true,
        initialize: { protocolVersion: "2024-11-05", serverInfo: { name: "srv" } },
        tools: [{ name: "echo" }, { name: "add" }],
        calls: [],
      }),
    );
    const t = await runMcpCase({ sandbox, cwd: "/workspace", test });
    const text = t.messages.map((m) => m.content).join("\n");
    expect(text).toMatch(/initialize: server=srv/);
    expect(text).toMatch(/tools\/list: echo, add/);
  });

  it("writes the driver into the sandbox before invoking it", async () => {
    const sandbox = withDriver(driverOut({ ok: true, tools: [], calls: [] }));
    await runMcpCase({ sandbox, cwd: "/workspace", test });
    expect(await sandbox.readFile("/workspace/mcp-driver.mjs")).toBeTruthy();
  });

  it("reports a failed handshake honestly instead of pretending it listed tools", async () => {
    const sandbox = withDriver(driverOut({ ok: false, error: "server exited immediately" }));
    const t = await runMcpCase({ sandbox, cwd: "/workspace", test });
    expect(t.messages.map((m) => m.content).join("\n")).toMatch(/failed during discovery/);
    expect(t.toolCalls).toHaveLength(0);
  });

  it("classifies an initialize timeout as an environment failure, not a verdict", async () => {
    // A server that never answers the handshake told us nothing about
    // itself — it may just need credentials the harness doesn't provide.
    // Returning a transcript here let the judge grade our own timeout:
    // 14 near-identical 2.5/10 verdicts in one production batch.
    const sandbox = withDriver(driverOut({ ok: false, error: "timeout: initialize" }));
    await expect(runMcpCase({ sandbox, cwd: "/workspace", test })).rejects.toThrow(
      SandboxInfraError,
    );
  });

  it("classifies a whole-driver timeout as an environment failure too", async () => {
    const sandbox = new FakeSandbox({
      rules: [
        {
          match: /mcp-driver\.mjs/,
          result: () => ({
            exitCode: -1,
            stdout: "",
            stderr: "",
            durationMs: 90_000,
            timedOut: true,
          }),
        },
      ],
    });
    await expect(runMcpCase({ sandbox, cwd: "/workspace", test })).rejects.toThrow(
      SandboxInfraError,
    );
  });

  it("a tools/list hang after a good handshake is the same environment failure", async () => {
    const sandbox = withDriver(driverOut({ ok: false, error: "timeout: tools/list" }));
    await expect(runMcpCase({ sandbox, cwd: "/workspace", test })).rejects.toThrow(
      SandboxInfraError,
    );
  });

  it("names the manifest's declared env vars in a timeout diagnosis", async () => {
    // "Declares OPENAI_API_KEY; likely not testable without credentials"
    // is a state an operator can classify; a bare timeout is retry bait.
    const sandbox = withDriver(driverOut({ ok: false, error: "timeout: initialize" }));
    await sandbox.writeFiles([
      {
        path: "/workspace/mcp.json",
        contents: JSON.stringify({
          mcpServers: { srv: { env: { OPENAI_API_KEY: "", SEARCH_TOKEN: "" } } },
        }),
      },
    ]);
    await expect(runMcpCase({ sandbox, cwd: "/workspace", test })).rejects.toThrow(
      /OPENAI_API_KEY, SEARCH_TOKEN/,
    );
  });

  it("falls back to the generic credentials hint when nothing is declared", async () => {
    const sandbox = withDriver(driverOut({ ok: false, error: "timeout: initialize" }));
    await expect(runMcpCase({ sandbox, cwd: "/workspace", test })).rejects.toThrow(
      /may need real credentials or environment/,
    );
  });

  it("handles unparseable driver output", async () => {
    const sandbox = withDriver("not json at all");
    const t = await runMcpCase({ sandbox, cwd: "/workspace", test });
    expect(t.messages.map((m) => m.content).join("\n")).toMatch(/no parseable output/);
  });

  it("reports a server that declares no tools", async () => {
    const sandbox = withDriver(driverOut({ ok: true, tools: [], calls: [] }));
    const t = await runMcpCase({ sandbox, cwd: "/workspace", test });
    expect(t.messages.map((m) => m.content).join("\n")).toMatch(/tools\/list: \(none\)/);
  });

  it("replays legacy single-call output when no model is wired", async () => {
    const sandbox = withDriver(
      driverOut({
        ok: true,
        tools: [{ name: "echo" }],
        calls: [{ tool: "echo", arguments: {}, result: { content: "hi" } }],
      }),
    );
    const t = await runMcpCase({ sandbox, cwd: "/workspace", test });
    expect(t.toolCalls.map((c) => c.name)).toEqual(["echo"]);
  });
});

/**
 * The MCP driver must live inside the declared workspace.
 *
 * It was hardcoded to `/workspace/mcp-driver.mjs` while the workspace is
 * vendor-declared: E2B runs unprivileged with a workdir of
 * `/home/user/workspace`, so writing to `/workspace` fails with EACCES.
 * `ports.ts` and the E2B adapter both document exactly this — "the sort
 * of bug a 'just use /workspace' default hides" — and this harness
 * reintroduced it, so MCP evaluation on E2B could not work.
 */
describe("MCP driver placement", () => {
  it("writes the driver under the sandbox's own workdir", async () => {
    const written: string[] = [];
    const sandbox = {
      workdir: "/home/user/workspace",
      async exec() {
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      },
      async writeFiles(files: { path: string }[]) {
        written.push(...files.map((f) => f.path));
      },
      async readFile() {
        return null;
      },
      async dispose() {},
    } as never;

    await runMcpCase({
      sandbox,
      cwd: "/home/user/workspace",
      test: { id: "t", prompt: "p" },
    });

    const driver = written.find((p) => p.endsWith("mcp-driver.mjs"));
    expect(driver).toBe("/home/user/workspace/mcp-driver.mjs");
    expect(driver).not.toMatch(/^\/workspace\//);
  });
});
