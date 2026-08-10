/**
 * Skill harness — runs a skill behaviorally.
 *
 * Build a system prompt from the skill's SKILL.md body, expose the
 * skill's allowed tools as `LlmTool`s backed by sandbox operations, then
 * loop: `llm.complete` → execute any tool calls in the sandbox → feed
 * results back → repeat until the model stops or we hit the turn cap.
 * Each test case produces one `Transcript`.
 *
 * Tools are deliberately backed by real sandbox ops (write/exec/read) so
 * the loop genuinely round-trips through the `Sandbox` interface. When a
 * `cwd` is supplied every command + relative path resolves under it
 * (e.g. the provisioned `/workspace` clone).
 */
import type { LlmMessage, LlmProvider, LlmTool, LlmToolCall } from "../../ports.js";
import type { Sandbox } from "../../ports.js";
import type { EvalTestCase, Transcript } from "../types.js";

const MAX_TURNS = 6;

/** The standard tool surface every skill run gets. */
const BASH_TOOL: LlmTool = {
  name: "bash",
  description: "Run a shell command in the sandbox and read its stdout/stderr/exit code.",
  inputSchema: { type: "object", properties: { cmd: { type: "string" } }, required: ["cmd"] },
};
const WRITE_TOOL: LlmTool = {
  name: "write_file",
  description: "Write a file into the sandbox.",
  inputSchema: {
    type: "object",
    properties: { path: { type: "string" }, contents: { type: "string" } },
    required: ["path", "contents"],
  },
};
const READ_TOOL: LlmTool = {
  name: "read_file",
  description: "Read a file back from the sandbox.",
  inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
};

/**
 * The tool surface the run exposes, ENFORCING the declared scope.
 *
 * Declared tools used to be metadata — the harness always granted the
 * full bash/write/read surface and merely *added* named aliases, so a
 * skill declaring `allowed-tools: [Read]` could still run a shell in the
 * evaluation. That is not what a real client does, and it is the single
 * largest safety gap the coverage audit found. Now:
 *
 *   - `undefined` (no declaration): permissive default — we cannot
 *     restrict a scope that was never stated.
 *   - `[]` (declared empty, "needs nothing"): NO tools. The run tests
 *     whether the artifact truly needs none.
 *   - `[Read, …]`: exactly the declared tools, mapped to the sandbox
 *     surface (Read→read_file, Write/Edit→write_file, Bash/Execute→bash);
 *     anything else becomes a named alias. Nothing outside the scope.
 */
export function baseTools(allowedTools?: string[]): LlmTool[] {
  if (allowedTools === undefined) return [BASH_TOOL, WRITE_TOOL, READ_TOOL];

  const lc = allowedTools.map((t) => t.toLowerCase().trim());
  const has = (...names: string[]) => names.some((n) => lc.includes(n));
  const tools: LlmTool[] = [];
  if (has("bash", "execute", "shell")) tools.push(BASH_TOOL);
  if (has("write", "edit", "multiedit")) tools.push(WRITE_TOOL);
  if (has("read")) tools.push(READ_TOOL);

  const GENERIC = new Set(["bash", "execute", "shell", "write", "edit", "multiedit", "read"]);
  for (const name of allowedTools) {
    if (GENERIC.has(name.toLowerCase().trim())) continue;
    tools.push({
      name: `tool_${slug(name)}`,
      description: `Declared allowed tool: ${name}.`,
      inputSchema: { type: "object", properties: { cmd: { type: "string" } } },
    });
  }
  return tools;
}

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/**
 * Coerce a tool argument to a string.
 *
 * Models do not reliably honour the schema: `cmd` arrives as an argv
 * array, or as `{command: "…"}`, or as a number. `String()` renders
 * every one of those as `[object Object]`, which the sandbox then runs
 * as a shell command — a nonsense action recorded in the transcript
 * and charged to the artifact's behavior score.
 *
 * So accept the shapes with one unambiguous reading, and return null
 * for the rest, which the caller turns into an error the model can see
 * and retry against. Being told "that argument was malformed" is a
 * fair turn; being silently misunderstood is not.
 */
function asString(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) return (v as string[]).join(" ");
  return null;
}

/** Execute one tool call against the sandbox, returning a text result. */
async function runTool(
  sandbox: Sandbox,
  call: LlmToolCall,
  cwd?: string,
  traceWrap?: (cmd: string) => string,
): Promise<string> {
  const input = call.input;
  if (call.name === "write_file") {
    const path = asString(input["path"]);
    const contents = asString(input["contents"] ?? "");
    if (path === null || contents === null) {
      return `error: write_file needs "path" and "contents" as strings.`;
    }
    await sandbox.writeFiles([{ path, contents }]);
    return `wrote ${path} (${contents.length} bytes)`;
  }
  if (call.name === "read_file") {
    const path = asString(input["path"]);
    if (path === null) return `error: read_file needs "path" as a string.`;
    const out = await sandbox.readFile(path);
    return out === null ? `(file not found: ${path})` : out;
  }
  // bash + any tool_* alias all run a command — this IS artifact
  // execution, so it goes through the runtime recorder when one is on.
  const cmd = asString(input["cmd"]);
  if (cmd === null) return `error: ${call.name} needs "cmd" as a string.`;
  const res = await sandbox.exec(traceWrap ? traceWrap(cmd) : cmd, {
    timeoutMs: 30_000,
    ...(cwd ? { cwd } : {}),
  });
  return [
    `exit=${res.exitCode}${res.timedOut ? " (timed out)" : ""}`,
    res.stdout ? `stdout:\n${res.stdout}` : "",
    res.stderr ? `stderr:\n${res.stderr}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

export interface SkillHarnessInput {
  llm: LlmProvider;
  sandbox: Sandbox;
  /** SKILL.md body (post-frontmatter) used as the system prompt. */
  skillDoc: string;
  /** `allowed-tools` from SKILL.md frontmatter. */
  allowedTools?: string[];
  /** Working dir for sandbox commands (e.g. the provisioned clone). */
  cwd?: string;
  /** Runtime-recorder wrapper for artifact-executing commands. */
  traceWrap?: import("../types.js").TraceWrap;
  /**
   * Run the SAME prompt WITHOUT the skill instructions — the baseline
   * arm of the uplift measurement. The system prompt becomes a plain
   * assistant so the judge can score what the bare model achieves, and
   * the difference is the value the skill actually adds.
   */
  baseline?: boolean;
  test: EvalTestCase;
}

/** Run one test case through the skill loop and return its transcript. */
export async function runSkillCase(input: SkillHarnessInput): Promise<Transcript> {
  const { llm, sandbox, skillDoc, test } = input;
  const tools = baseTools(input.allowedTools);
  const system = input.baseline
    ? [
        "You are a capable assistant with access to a sandbox and its tools.",
        "Accomplish the user's request as well as you can.",
      ].join("\n")
    : [
        "You are exercising a skill end-to-end. Follow the skill's instructions",
        "and use the available tools to accomplish the user's request.",
        "",
        "=== SKILL INSTRUCTIONS ===",
        skillDoc,
      ].join("\n");

  const messages: LlmMessage[] = [{ role: "user", content: test.prompt }];
  const allToolCalls: LlmToolCall[] = [];
  const start = Date.now();

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const res = await llm.complete({
      system,
      messages,
      tools,
      maxTokens: 2048,
      temperature: 0,
    });
    if (res.text) {
      messages.push({ role: "assistant", content: res.text });
    }
    if (res.stopReason !== "tool_use" || res.toolCalls.length === 0) {
      break;
    }
    for (const call of res.toolCalls) {
      allToolCalls.push(call);
      let result: string;
      try {
        result = await runTool(sandbox, call, input.cwd, input.traceWrap);
      } catch (err) {
        result = `tool error: ${(err as Error).message}`;
      }
      messages.push({ role: "tool", content: result, toolCallId: call.id });
    }
  }

  return { messages, toolCalls: allToolCalls, durationMs: Date.now() - start };
}
