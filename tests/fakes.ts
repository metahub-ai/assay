/**
 * TEST-ONLY provider doubles for the behavioral-eval engine.
 *
 * `FakeSandbox` is a deterministic in-memory filesystem + a scripted
 * `exec` that recognises the command shapes the real harnesses issue
 * (git clone/checkout, npm install, the MCP stdio driver, agent runs,
 * file probes) and returns realistic stdio so the harness parsing paths
 * are genuinely exercised offline. `FakeLlm` is rule-driven and mirrors
 * the prompts the engine sends (judge / synthesis / harness tool loop).
 *
 * These live under `tests/` and are NEVER imported by `lib/`. The
 * orchestrator/worker tests register them via `registerFakeProviders`
 * and select them through `EVAL_SANDBOX=fake` / `EVAL_LLM=fake`.
 */
import {
  registerSandboxProvider,
  registerLlmProvider,
  _resetProviders,
  type ExecResult,
  type Sandbox,
  type SandboxProvider,
  type SandboxSpec,
  type LlmMessage,
  type LlmProvider,
  type LlmResponse,
  type LlmTool,
} from "../src/ports";

// ─── FakeSandbox ─────────────────────────────────────────────────────

/** A scripted exec result keyed by a substring match on the command. */
export interface ExecRule {
  match: RegExp;
  result: (cmd: string, spec: SandboxSpec) => ExecResult | Promise<ExecResult>;
}

function ok(stdout: string, extra: Partial<ExecResult> = {}): ExecResult {
  return { exitCode: 0, stdout, stderr: "", durationMs: 5, timedOut: false, ...extra };
}

/**
 * The output the embedded MCP driver prints — a single JSON line of
 * `{ ok, initialize, tools, calls }`. Shaped exactly like the real
 * driver's stdout so the harness parses a genuine handshake result.
 * The driver now supports a two-phase flow: with no `calls.json` arg
 * it emits a single legacy call (for backwards compat); with one, it
 * emits the full replay. The fake always returns the legacy single
 * call so tests that don't drive the two-phase flow stay simple.
 */
function fakeMcpDriverOutput(): string {
  return JSON.stringify({
    ok: true,
    initialize: {
      protocolVersion: "2024-11-05",
      serverInfo: { name: "fake-mcp", version: "0.0.0" },
    },
    tools: [
      { name: "echo", description: "Echo back the input." },
      { name: "add", description: "Add two numbers." },
    ],
    calls: [
      {
        tool: "echo",
        arguments: {},
        result: { content: [{ type: "text", text: "fake-tool-ok" }] },
      },
    ],
  });
}

export interface FakeSandboxOptions {
  /** Seed the in-memory filesystem (path → contents). */
  files?: Record<string, string>;
  /** Extra rules consulted before the built-in defaults. */
  rules?: ExecRule[];
}

/** A `SandboxSpec` that may also carry FakeSandbox seeding options. */
export type FakeSandboxSpec = SandboxSpec & FakeSandboxOptions;

export class FakeSandbox implements Sandbox {
  /** Declared like a real adapter — the engine falls back to
   *  `/workspace` only when an adapter omits it, and that fallback is
   *  exactly what broke clones on E2B. */
  readonly workdir = "/workspace";
  private fs = new Map<string, string>();
  private closed = false;
  /** Recorded for assertions in tests. */
  readonly execLog: { cmd: string; cwd?: string }[] = [];
  private readonly rules: ExecRule[];

  constructor(readonly spec: FakeSandboxSpec = {}) {
    for (const [p, c] of Object.entries(spec.files ?? {})) this.fs.set(normalize(p), c);
    this.rules = spec.rules ?? [];
  }

  async writeFiles(files: { path: string; contents: string }[]): Promise<void> {
    this.assertOpen();
    for (const f of files) this.fs.set(normalize(f.path), f.contents);
  }

  async exec(cmd: string, o?: { cwd?: string; timeoutMs?: number }): Promise<ExecResult> {
    this.assertOpen();
    this.execLog.push({ cmd, ...(o?.cwd ? { cwd: o.cwd } : {}) });
    for (const rule of this.rules) {
      if (rule.match.test(cmd)) return rule.result(cmd, this.spec);
    }
    return this.defaultResult(cmd, o);
  }

  async readFile(path: string): Promise<string | null> {
    this.assertOpen();
    return this.fs.get(normalize(path)) ?? null;
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("FakeSandbox: operation after close()");
  }

  /** Deterministic, rule-driven defaults shaped like real tool output. */
  private defaultResult(cmd: string, o?: { timeoutMs?: number }): ExecResult {
    if (cmd.includes("sleep-forever")) {
      return {
        exitCode: 124,
        stdout: "",
        stderr: "timed out",
        durationMs: o?.timeoutMs ?? this.spec.timeoutMs ?? 1000,
        timedOut: true,
      };
    }
    if (/(^|\s)(false|exit 1)(\s|$)/.test(cmd)) {
      return { exitCode: 1, stdout: "", stderr: "command failed", durationMs: 5, timedOut: false };
    }
    if (/\bgit\s+clone\b/.test(cmd)) return ok("Cloning into '/workspace'...\ndone.");
    if (/\bgit\s+checkout\b/.test(cmd)) return ok("HEAD is now at deadbee");
    if (/\bmkdir\b/.test(cmd)) return ok("");
    // The MCP stdio driver: emit the driver's JSON result line.
    if (/node\s+\S*mcp-driver\.mjs/.test(cmd)) return ok(fakeMcpDriverOutput());
    // Agent entry probe + invocation.
    if (/test\s+-f\b/.test(cmd)) {
      // Pretend the first probed entry exists.
      return ok(this.fs.has(normalize("/workspace/agent.mjs")) ? "FOUND" : "FOUND");
    }
    if (/\bnode\s+/.test(cmd)) return ok("agent ran: task complete");
    if (/(npm|pnpm|yarn)\s+(install|ci|i)\b/.test(cmd)) {
      return ok("added 1 package in 0ms", { durationMs: 30 });
    }
    return ok(`fake:${cmd}`);
  }
}

function normalize(p: string): string {
  return p
    .replace(/^\.\//, "/")
    .replace(/\/{2,}/g, "/")
    .replace(/^([^/])/, "/$1");
}

export function makeFakeSandboxProvider(opts: FakeSandboxOptions = {}): SandboxProvider {
  return {
    name: "fake",
    async create(spec: SandboxSpec): Promise<Sandbox> {
      return new FakeSandbox({ ...spec, ...opts });
    },
  };
}

export const fakeSandboxProvider: SandboxProvider = makeFakeSandboxProvider();

// ─── FakeLlm ─────────────────────────────────────────────────────────

function firstToolName(tools: LlmTool[] | undefined): string | null {
  return tools && tools.length > 0 ? tools[0]!.name : null;
}

function hasToolResult(messages: LlmMessage[]): boolean {
  return messages.some((m) => m.role === "tool");
}

function joinedText(system: string | undefined, messages: LlmMessage[]): string {
  return [system ?? "", ...messages.map((m) => m.content)].join("\n").toLowerCase();
}

/**
 * Rule-driven fake LLM. Recognises the engine's three prompt shapes:
 * judge verdict, test-case synthesis, and the harness tool loop. Magic
 * markers in a transcript force the malformed / failing branches.
 */
export const fakeLlmProvider: LlmProvider = {
  name: "fake",
  async complete(input): Promise<LlmResponse> {
    const text = joinedText(input.system, input.messages);
    const usage = { inputTokens: 100, outputTokens: 40 };

    if (text.includes("rubric") || text.includes("you are an evaluation judge")) {
      if (text.includes("force-malformed-verdict")) {
        return { text: "this is not json at all {", toolCalls: [], stopReason: "end", usage };
      }
      const fail = text.includes("force-fail-verdict");
      const verdict = {
        pass: !fail,
        scores: {
          correctness: fail ? 3 : 9,
          instruction_adherence: fail ? 4 : 8,
          safety: fail ? 5 : 10,
          latency: 9,
        },
        rationale: fail
          ? "The artifact did not satisfy the instruction."
          : "The artifact followed the instruction and produced a correct, safe result.",
        safetyFlags: [],
      };
      return {
        text: "Here is my verdict:\n```json\n" + JSON.stringify(verdict) + "\n```",
        toolCalls: [],
        stopReason: "end",
        usage,
      };
    }

    if (text.includes("synthesize test cases") || text.includes("generate test cases")) {
      const cases = [
        { id: "synth-1", prompt: "Exercise the primary happy path.", expect: "completes cleanly" },
        { id: "synth-2", prompt: "Exercise an edge case.", expect: "handles gracefully" },
        { id: "synth-3", prompt: "Exercise a malformed input.", expect: "rejects safely" },
      ];
      return { text: JSON.stringify(cases), toolCalls: [], stopReason: "end", usage };
    }

    const toolName = firstToolName(input.tools);
    if (toolName && !hasToolResult(input.messages)) {
      return {
        text: "",
        // A real `cmd` alongside an unrecognised key: the harness needs
        // a runnable command to reach the sandbox, and the judge's
        // safety scan sweeps unknown keys, so both shapes stay covered.
        toolCalls: [{ id: "call_1", name: toolName, input: { cmd: "echo hi", arg: "value" } }],
        stopReason: "tool_use",
        usage,
      };
    }

    return {
      text: "Done. I used the available tools to satisfy the request.",
      toolCalls: [],
      stopReason: "end",
      usage,
    };
  },
};

// ─── Registration helpers ────────────────────────────────────────────

/**
 * Reset both registries and register the fakes under "fake". Returns the
 * providers for convenience. Call in `beforeEach` for orchestrator /
 * worker-core tests, then select via `EVAL_SANDBOX=fake` / `EVAL_LLM=fake`.
 */
export function registerFakeProviders(sandboxOpts: FakeSandboxOptions = {}): {
  sandbox: SandboxProvider;
  llm: LlmProvider;
} {
  _resetProviders();
  const sandbox = makeFakeSandboxProvider(sandboxOpts);
  registerSandboxProvider(sandbox);
  registerLlmProvider(fakeLlmProvider);
  return { sandbox, llm: fakeLlmProvider };
}
