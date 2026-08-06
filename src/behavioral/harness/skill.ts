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
function baseTools(allowedTools: string[]): LlmTool[] {
  const tools: LlmTool[] = [
    {
      name: "bash",
      description: "Run a shell command in the sandbox and read its stdout/stderr/exit code.",
      inputSchema: {
        type: "object",
        properties: { cmd: { type: "string" } },
        required: ["cmd"],
      },
    },
    {
      name: "write_file",
      description: "Write a file into the sandbox.",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" }, contents: { type: "string" } },
        required: ["path", "contents"],
      },
    },
    {
      name: "read_file",
      description: "Read a file back from the sandbox.",
      inputSchema: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
    },
  ];
  // Surface any skill-declared allowed tools as additional named tools so
  // the model's intent to use them is captured (and scannable for
  // safety). They share the bash-style command surface.
  for (const name of allowedTools) {
    const lc = name.toLowerCase();
    if (lc === "bash" || lc === "read" || lc === "write") continue;
    tools.push({
      name: `tool_${slug(name)}`,
      description: `Skill-declared allowed tool: ${name}.`,
      inputSchema: {
        type: "object",
        properties: { cmd: { type: "string" } },
      },
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
async function runTool(sandbox: Sandbox, call: LlmToolCall, cwd?: string): Promise<string> {
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
  // bash + any tool_* alias all run a command.
  const cmd = asString(input["cmd"]);
  if (cmd === null) return `error: ${call.name} needs "cmd" as a string.`;
  const res = await sandbox.exec(cmd, { timeoutMs: 30_000, ...(cwd ? { cwd } : {}) });
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
  test: EvalTestCase;
}

/** Run one test case through the skill loop and return its transcript. */
export async function runSkillCase(input: SkillHarnessInput): Promise<Transcript> {
  const { llm, sandbox, skillDoc, test } = input;
  const tools = baseTools(input.allowedTools ?? []);
  const system = [
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
        result = await runTool(sandbox, call, input.cwd);
      } catch (err) {
        result = `tool error: ${(err as Error).message}`;
      }
      messages.push({ role: "tool", content: result, toolCallId: call.id });
    }
  }

  return { messages, toolCalls: allToolCalls, durationMs: Date.now() - start };
}
