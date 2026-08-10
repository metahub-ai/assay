/**
 * Agent harness — runs a full agent behaviorally inside the sandbox.
 *
 * Agents bring their own runtime + tool surface, so unlike the skill
 * harness we don't drive a turn-by-turn LLM loop. Instead we provision
 * the agent in the sandbox working dir, install its dependencies, then
 * invoke its entry file with the test prompt and capture the run. The
 * prompt is passed three ways (argv, env, stdin) so the harness works
 * regardless of how the agent reads its input. The judge scores task
 * completion from the captured transcript downstream.
 */
import type { LlmMessage, LlmToolCall } from "../../ports.js";
import type { Sandbox } from "../../ports.js";
import type { EvalTestCase, Transcript } from "../types.js";
import { installDependencies } from "../install.js";

export interface AgentHarnessInput {
  sandbox: Sandbox;
  /** Working directory inside the sandbox. Defaults to /workspace. */
  cwd?: string;
  /** Command that installs deps; defaults to `npm install`. */
  installCmd?: string;
  /**
   * The agent's entry file relative to `cwd`. Defaults to a small set of
   * common conventions, the first of which exists is used.
   */
  entryFile?: string;
  /** Runtime-recorder wrapper for the agent invocation. */
  traceWrap?: import("../types.js").TraceWrap;
  test: EvalTestCase;
}

const DEFAULT_ENTRY_CANDIDATES = [
  "agent.mjs",
  "agent.js",
  "index.mjs",
  "index.js",
  "src/index.js",
  "dist/index.js",
];

/** Resolve the agent entry file: the configured one, else the first that exists. */
async function resolveEntry(
  sandbox: Sandbox,
  cwd: string,
  configured?: string,
): Promise<string | null> {
  const candidates = configured ? [configured] : DEFAULT_ENTRY_CANDIDATES;
  for (const c of candidates) {
    const probe = await sandbox.exec(`test -f ${JSON.stringify(c)} && echo FOUND || true`, { cwd });
    if (probe.stdout.includes("FOUND")) return c;
  }
  return null;
}

/** Run one test case by invoking the agent entry and capturing its run. */
export async function runAgentCase(input: AgentHarnessInput): Promise<Transcript> {
  const { sandbox, test } = input;
  const cwd = input.cwd ?? "/workspace";
  const messages: LlmMessage[] = [{ role: "user", content: test.prompt }];
  const toolCalls: LlmToolCall[] = [];
  const start = Date.now();

  // 1) install dependencies.
  const install = await installDependencies(sandbox, cwd, input.installCmd);
  messages.push({ role: "assistant", content: install.log });

  // 2) locate the entry file.
  const entry = await resolveEntry(sandbox, cwd, input.entryFile);
  if (!entry) {
    messages.push({
      role: "assistant",
      content: "agent entry file not found; tried common conventions",
    });
    return { messages, toolCalls, durationMs: Date.now() - start };
  }

  // 3) invoke the agent with the prompt via argv + env + stdin. The
  //    invocation is recorded as a tool call so the safety scan + judge
  //    can see exactly what was run.
  const cmd = `AGENT_PROMPT=${JSON.stringify(test.prompt)} node ${JSON.stringify(entry)} ${JSON.stringify(test.prompt)}`;
  toolCalls.push({
    id: "agent_run_1",
    name: "run_agent",
    input: { cmd, entry, prompt: test.prompt },
  });
  const fullCmd = `printf '%s' ${JSON.stringify(test.prompt)} | ${cmd}`;
  const run = await sandbox.exec(input.traceWrap ? input.traceWrap(fullCmd) : fullCmd, {
    cwd,
    timeoutMs: 120_000,
  });
  messages.push({
    role: "assistant",
    content: [
      `agent exit=${run.exitCode}${run.timedOut ? " (timed out)" : ""}`,
      run.stdout ? `stdout:\n${run.stdout}` : "",
      run.stderr ? `stderr:\n${run.stderr}` : "",
    ]
      .filter(Boolean)
      .join("\n"),
  });

  return { messages, toolCalls, durationMs: Date.now() - start };
}
