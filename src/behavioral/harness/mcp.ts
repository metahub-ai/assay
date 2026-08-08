/**
 * MCP protocol harness — fully real, no emulation.
 *
 * Installs + drives an MCP server inside the sandbox over a genuine
 * stdio JSON-RPC handshake. The harness writes a SELF-CONTAINED Node
 * driver (`mcp-driver.mjs`, raw newline-delimited JSON-RPC — no SDK)
 * into the sandbox, then runs it via `sandbox.exec`. The driver:
 *
 *   1. spawns the server command (`serverCmd`),
 *   2. sends `initialize` → waits for the result,
 *   3. sends the `notifications/initialized` notification,
 *   4. sends `tools/list` → waits for the result,
 *   5. **iterates the discovered tools (capped) and sends one
 *       `tools/call` per tool, with arguments synthesized by the
 *       host-side LLM from each tool's `inputSchema`**,
 *   6. prints a single JSON line of `{ ok, initialize, tools, calls }`
 *      to stdout and exits.
 *
 * The argument synthesis lives on the harness side (host) so we can
 * use the configured `LlmProvider` — the in-sandbox driver stays
 * SDK-free. We hand the driver a pre-baked `calls` array of
 * `{ name, arguments }` to execute, so it's still pure JSON-RPC.
 *
 * We parse that real stdout — nothing in the sandbox is emulated. The
 * server is a real child process speaking the MCP wire protocol.
 */
import { SandboxInfraError, type Sandbox } from "../../ports.js";
import { makeSurface } from "../../surface.js";
import type { EvalTestCase, Transcript } from "../types.js";
import { installDependencies } from "../install.js";
import type { LlmMessage, LlmProvider, LlmToolCall } from "../../ports.js";

/**
 * The driver is written beside the artifact, NOT at a fixed path.
 *
 * It used to be hardcoded to `/workspace/mcp-driver.mjs` while the
 * workspace is vendor-declared: E2B runs unprivileged with a workdir of
 * `/home/user/workspace`, so `mkdir /workspace` fails with EACCES.
 * `ports.ts` and the E2B adapter both document that at length — "which
 * is exactly the sort of bug a 'just use /workspace' default hides" —
 * and this file reintroduced it, so MCP evaluation on E2B could not
 * work at all.
 */
function driverPathFor(cwd: string): string {
  return `${cwd.replace(/\/+$/, "")}/mcp-driver.mjs`;
}
/**
 * Cap on how many tools the harness calls per test case. The
 * tools/list response can contain dozens — calling every one would
 * double the eval cost without proportional signal.
 */
const TOOL_CALL_CAP_DEFAULT = Math.max(1, Number(process.env.EVAL_MCP_TOOL_CALL_CAP ?? 5) || 5);

interface DriverTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

interface DriverCallResult {
  tool: string;
  arguments?: Record<string, unknown>;
  result?: unknown;
  error?: string;
}

interface DriverOutput {
  ok: boolean;
  error?: string;
  initialize?: { protocolVersion?: string; serverInfo?: { name?: string; version?: string } };
  tools?: DriverTool[];
  calls?: DriverCallResult[];
}

export interface McpHarnessInput {
  sandbox: Sandbox;
  /**
   * LLM provider used to synthesize realistic arguments for each
   * discovered tool from its `inputSchema`. Optional — when omitted
   * (e.g. some tests) we fall back to calling each tool with empty
   * args, preserving the original single-call behavior.
   */
  llm?: LlmProvider;
  /** Command that installs deps; defaults to `npm install`. */
  installCmd?: string;
  /** Command that launches the MCP server over stdio. */
  serverCmd?: string;
  /** Working directory inside the sandbox. Defaults to /workspace. */
  cwd?: string;
  test: EvalTestCase;
  /** Cap on how many tools to call. Defaults to EVAL_MCP_TOOL_CALL_CAP (5). */
  toolCallCap?: number;
}

/**
 * The stdio JSON-RPC driver, emitted into the sandbox verbatim. It is
 * a standalone ES module with zero dependencies — Node's
 * `child_process` + line buffering only.
 *
 *   argv[2] = serverCmd            (required)
 *   argv[3] = path to calls.json   (optional)
 *
 * When argv[3] is omitted: do init + tools/list, print
 *   { ok, initialize, tools }
 * and exit.
 *
 * When argv[3] is present and points at a JSON array of
 *   [{ name, arguments }, …]
 * the driver does init + replays the calls and prints
 *   { ok, initialize, tools, calls: [{ tool, arguments, result, error? }] }.
 *
 * The two-phase design lets the host LLM synthesize realistic
 * arguments from each tool's inputSchema between the two driver
 * invocations, while keeping the in-sandbox driver SDK-free.
 */
export const MCP_DRIVER_SOURCE = String.raw`
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";

const serverCmd = process.argv[2];
const callsPath = process.argv[3] || null;
if (!serverCmd) {
  process.stdout.write(JSON.stringify({ ok: false, error: "no server command" }) + "\n");
  process.exit(0);
}

const child = spawn("sh", ["-lc", serverCmd], { stdio: ["pipe", "pipe", "inherit"] });

let buf = "";
const pending = new Map();
let nextId = 1;

child.stdout.on("data", (chunk) => {
  buf += chunk.toString();
  let nl;
  while ((nl = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  }
});

function send(method, params, timeoutMs) {
  const id = nextId++;
  const payload = { jsonrpc: "2.0", id, method, params: params ?? {} };
  child.stdin.write(JSON.stringify(payload) + "\n");
  return new Promise((resolve, reject) => {
    const t = timeoutMs ?? 60000;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("timeout: " + method)); }, t);
    pending.set(id, { resolve: (m) => { clearTimeout(timer); resolve(m); } });
  });
}

function notify(method, params) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params: params ?? {} }) + "\n");
}

function readCalls() {
  if (!callsPath) return null;
  try {
    const raw = readFileSync(callsPath, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : null;
  } catch (err) {
    return { __error: String(err && err.message ? err.message : err) };
  }
}

async function main() {
  const out = { ok: false };
  try {
    const initRes = await send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "metahub-eval", version: "0.1.0" },
    });
    out.initialize = initRes.result ?? {};
    notify("notifications/initialized");
    const listRes = await send("tools/list", {});
    const tools = (listRes.result && listRes.result.tools) || [];
    out.tools = tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));

    const calls = readCalls();
    if (Array.isArray(calls)) {
      // Phase 2: replay the host-synthesized calls.
      out.calls = [];
      for (const c of calls) {
        const args = (c && typeof c === "object" && c.arguments && typeof c.arguments === "object") ? c.arguments : {};
        const name = c && c.name ? String(c.name) : null;
        if (!name) {
          out.calls.push({ tool: "<missing>", arguments: args, error: "no tool name" });
          continue;
        }
        try {
          const callRes = await send("tools/call", { name, arguments: args }, 30000);
          out.calls.push({ tool: name, arguments: args, result: callRes.result ?? callRes.error ?? null, ...(callRes.error ? { error: typeof callRes.error === 'object' && callRes.error && 'message' in callRes.error ? String(callRes.error.message) : String(callRes.error) } : {}) });
        } catch (err) {
          out.calls.push({ tool: name, arguments: args, error: String(err && err.message ? err.message : err) });
        }
      }
    } else if (tools.length > 0 && callsPath === null) {
      // No calls file passed — preserve the legacy "ping the first
      // tool with empty args" behavior so callers that don't go
      // through the two-phase flow still get a smoke signal.
      const first = tools[0];
      try {
        const callRes = await send("tools/call", { name: first.name, arguments: {} });
        out.calls = [{ tool: first.name, arguments: {}, result: callRes.result ?? callRes.error ?? null }];
      } catch (err) {
        out.calls = [{ tool: first.name, arguments: {}, error: String(err && err.message ? err.message : err) }];
      }
    }
    out.ok = true;
  } catch (err) {
    out.ok = false;
    out.error = String(err && err.message ? err.message : err);
  } finally {
    process.stdout.write(JSON.stringify(out) + "\n");
    child.kill("SIGKILL");
    process.exit(0);
  }
}

main();
`;

function parseDriverOutput(stdout: string): DriverOutput | null {
  // The driver prints exactly one JSON line of results; take the last
  // non-empty line so any incidental server logging on stdout is ignored.
  const lines = stdout
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i]!) as DriverOutput;
      if (parsed && typeof parsed === "object" && "ok" in parsed) return parsed;
    } catch {
      /* keep scanning earlier lines */
    }
  }
  return null;
}

/**
 * Build a tools/call argument map from a tool's `inputSchema`, either
 * by asking the LLM or via a deterministic shape-based stub. The LLM
 * gets the schema + the test prompt as context and is told to respond
 * with a single JSON object that satisfies the schema. Falls back to
 * the deterministic stub on any parse / transport failure so the
 * harness never blocks on the model.
 */
async function synthesizeToolArgs(
  llm: LlmProvider | undefined,
  tool: DriverTool,
  prompt: string,
): Promise<Record<string, unknown>> {
  const schema = tool.inputSchema ?? {};
  if (!llm) return deterministicArgsFromSchema(schema);
  try {
    const system = [
      "You are a test harness producing realistic JSON arguments for an MCP tool.",
      `Tool name: ${tool.name}`,
      tool.description ? `Tool description: ${tool.description}` : "",
      "Respond with ONLY a single JSON object that satisfies the inputSchema.",
      "If the schema is empty or the tool needs no arguments, respond with {}.",
      "Keep string values short and benign — this is a smoke call.",
    ]
      .filter(Boolean)
      .join("\n");
    const user = [
      "Test case prompt (context only, not the literal input):",
      prompt.slice(0, 1000),
      "",
      "inputSchema:",
      JSON.stringify(schema).slice(0, 2000),
    ].join("\n");
    const res = await llm.complete({
      system,
      messages: [{ role: "user", content: user }],
      maxTokens: 512,
      temperature: 0,
    });
    const m = res.text.match(/\{[\s\S]*\}/);
    if (!m) return deterministicArgsFromSchema(schema);
    const parsed = JSON.parse(m[0]) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : deterministicArgsFromSchema(schema);
  } catch {
    return deterministicArgsFromSchema(schema);
  }
}

/**
 * Build a minimally valid argument map from a JSON Schema without
 * calling the LLM. Used as the safety net so a flaky judge can't
 * starve the harness.
 */
export function deterministicArgsFromSchema(
  schema: Record<string, unknown>,
): Record<string, unknown> {
  const props = (schema["properties"] as Record<string, unknown> | undefined) ?? {};
  const required = Array.isArray(schema["required"])
    ? (schema["required"] as unknown[]).filter((x): x is string => typeof x === "string")
    : Object.keys(props);
  const out: Record<string, unknown> = {};
  for (const key of required) {
    const propSchema = (props[key] as { type?: string; default?: unknown }) ?? {};
    if (propSchema.default !== undefined) {
      out[key] = propSchema.default;
      continue;
    }
    switch (propSchema.type) {
      case "string":
        out[key] = "test";
        break;
      case "number":
      case "integer":
        out[key] = 1;
        break;
      case "boolean":
        out[key] = true;
        break;
      case "array":
        out[key] = [];
        break;
      case "object":
        out[key] = {};
        break;
      default:
        out[key] = null;
    }
  }
  return out;
}

/**
 * Work out the command that starts this server.
 *
 * `npx --yes -y .` was the only strategy, and it is fragile in two ways
 * that both bit the official `server-everything` package. It relies on
 * the bin file carrying its executable bit — normally set by a
 * `chmod +x` inside the package's own build script, which no longer runs
 * now that installs skip lifecycle scripts — and it can decide to
 * reinstall the local package, re-entering the very scripts we declined
 * to run.
 *
 * Invoking `node <entry>` directly avoids both. The entry comes from the
 * package's own `bin`/`main`, so this is not a guess. `npx` remains the
 * fallback for packages that genuinely need it.
 */
async function resolveServerCommand(sandbox: Sandbox, cwd: string): Promise<string> {
  const probe = await sandbox.exec(
    `node -e "const p=require('./package.json');` +
      `const b=p.bin&&(typeof p.bin==='string'?p.bin:Object.values(p.bin)[0]);` +
      `const f=b||p.main;` +
      `if(f&&require('fs').existsSync(f))console.log(f)"`,
    { cwd, timeoutMs: 20_000 },
  );
  const entry = probe.stdout.trim().split("\n").pop()?.trim();
  return entry ? `node ${JSON.stringify(entry)}` : "npx --yes -y .";
}

/**
 * Env vars the artifact's own manifests declare as required at runtime.
 *
 * Read from mcp.json / server.json "env" blocks — the two manifest
 * shapes this harness already recognizes. Used only to make an
 * initialize-timeout diagnosis specific: "the server may need
 * credentials" becomes "the server declares OPENAI_API_KEY and we
 * provide no credentials", which an operator can classify at a glance
 * as not-behaviorally-testable rather than retry it forever.
 *
 * Deliberately NOT used to skip the boot attempt: env declarations are
 * often optional-with-defaults, and pre-judging them would fail servers
 * that boot fine without keys.
 */
async function declaredEnvVars(sandbox: Sandbox, cwd: string): Promise<string[]> {
  const names = new Set<string>();
  for (const file of ["mcp.json", "server.json"]) {
    const raw = await sandbox.readFile(`${cwd}/${file}`);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as {
        env?: Record<string, unknown> | string[];
        mcpServers?: Record<string, { env?: Record<string, unknown> }>;
      };
      const collect = (env: Record<string, unknown> | string[] | undefined) => {
        if (!env) return;
        for (const k of Array.isArray(env) ? env : Object.keys(env)) {
          if (typeof k === "string" && /^[A-Z][A-Z0-9_]*$/.test(k)) names.add(k);
        }
      };
      collect(parsed.env);
      for (const server of Object.values(parsed.mcpServers ?? {})) collect(server.env);
    } catch {
      /* malformed manifest — the boot attempt will tell its own story */
    }
  }
  return [...names].sort();
}

/**
 * Throwaway credentials injected into the server's environment before the
 * handshake. Most MCP servers that "need credentials" only check a var is
 * PRESENT at boot and defer the real API call to tool-invocation time, so
 * booting them with obviously-fake values gets us past `initialize` to
 * list tools and run the safety scan — none of which need a valid key.
 * Safe because the values are worthless: a server that exfiltrates them
 * steals nothing. Seeded from a generic superset plus every name the
 * artifact's own manifest declares.
 */
const GENERIC_PLACEHOLDER_ENV: Record<string, string> = {
  OPENAI_API_KEY: "sk-placeholder00000000000000000000000000000000000000",
  ANTHROPIC_API_KEY: "sk-ant-placeholder00000000000000000000000000000000",
  GOOGLE_API_KEY: "placeholder-google-api-key",
  GEMINI_API_KEY: "placeholder-gemini-api-key",
  GROQ_API_KEY: "gsk_placeholder000000000000000000000000",
  MISTRAL_API_KEY: "placeholder-mistral-api-key",
  COHERE_API_KEY: "placeholder-cohere-api-key",
  OPENROUTER_API_KEY: "sk-or-placeholder000000000000000000000000",
  HF_TOKEN: "hf_placeholder0000000000000000000000000000",
  GITHUB_TOKEN: "ghp_placeholder0000000000000000000000000000",
  GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_placeholder0000000000000000000000000000",
  GITLAB_TOKEN: "glpat-placeholder0000000000000000000",
  SLACK_BOT_TOKEN: "xoxb-0000000000-0000000000-placeholder",
  SLACK_TOKEN: "xoxb-0000000000-0000000000-placeholder",
  NOTION_API_KEY: "secret_placeholder000000000000000000000000000",
  NOTION_TOKEN: "secret_placeholder000000000000000000000000000",
  LINEAR_API_KEY: "lin_api_placeholder00000000000000000000",
  STRIPE_API_KEY: "sk_test_placeholder0000000000000000000000",
  SENTRY_AUTH_TOKEN: "placeholder-sentry-auth-token",
  BRAVE_API_KEY: "placeholder-brave-api-key",
  TAVILY_API_KEY: "tvly-placeholder0000000000000000000000",
  SERPAPI_API_KEY: "placeholder-serpapi-key",
  PERPLEXITY_API_KEY: "pplx-placeholder0000000000000000000000",
  AWS_ACCESS_KEY_ID: "AKIAPLACEHOLDER000000",
  AWS_SECRET_ACCESS_KEY: "placeholderplaceholderplaceholderplaceholder",
  AWS_REGION: "us-east-1",
  DATABASE_URL: "postgres://user:pass@localhost:5432/placeholder",
  POSTGRES_URL: "postgres://user:pass@localhost:5432/placeholder",
  REDIS_URL: "redis://localhost:6379",
  API_KEY: "placeholder-api-key",
  API_TOKEN: "placeholder-api-token",
  API_BASE_URL: "http://localhost:8080",
};

function placeholderFor(name: string): string {
  if (/(_URL|_URI|_ENDPOINT)$/.test(name)) return "http://localhost:8080";
  if (/(_HOST|_HOSTNAME)$/.test(name)) return "localhost";
  if (/_PORT$/.test(name)) return "8080";
  if (/_REGION$/.test(name)) return "us-east-1";
  return `placeholder-${name.toLowerCase()}`;
}

function placeholderCredentialEnv(declared: string[]): Record<string, string> {
  const env: Record<string, string> = { ...GENERIC_PLACEHOLDER_ENV };
  for (const name of declared) if (!(name in env)) env[name] = placeholderFor(name);
  return env;
}

/** Drive the MCP server for one test case, capturing a real transcript. */
export async function runMcpCase(input: McpHarnessInput): Promise<Transcript> {
  const { sandbox, test } = input;
  const cwd = input.cwd ?? "/workspace";
  const cap = input.toolCallCap ?? TOOL_CALL_CAP_DEFAULT;
  const messages: LlmMessage[] = [{ role: "user", content: test.prompt }];
  const toolCalls: LlmToolCall[] = [];
  const start = Date.now();

  // 1) install dependencies.
  const install = await installDependencies(sandbox, cwd, input.installCmd);
  messages.push({ role: "assistant", content: install.log });

  // 2) work out how to actually start the server.
  const serverCmd = input.serverCmd ?? (await resolveServerCommand(sandbox, cwd));
  const driverPath = driverPathFor(cwd);

  // 3) write the stdio JSON-RPC driver.
  await sandbox.writeFiles([{ path: driverPath, contents: MCP_DRIVER_SOURCE }]);

  // Boot the server with throwaway credentials (generic set + whatever the
  // manifest declares) so presence-checks pass and the handshake proceeds.
  // `declared` is reused by the timeout diagnosis below.
  const declared = await declaredEnvVars(sandbox, cwd);
  const sandboxEnv = placeholderCredentialEnv(declared);

  // 4) Pass 1 — discovery. The driver does init + tools/list, prints
  //    the tool catalog, and exits. If no LLM is wired up (older
  //    tests), we degrade to the legacy "ping the first tool" output.
  const pass1 = await sandbox.exec(`node ${driverPath} ${JSON.stringify(serverCmd)}`, {
    cwd,
    timeoutMs: 90_000,
    env: sandboxEnv,
  });
  messages.push({
    role: "assistant",
    content: `driver pass1 exit=${pass1.exitCode}${pass1.timedOut ? " (timed out)" : ""}`,
  });
  const discovery = parseDriverOutput(pass1.stdout);
  if (!discovery || !discovery.ok) {
    const detail = discovery?.error || pass1.stderr || "no parseable output";
    // A handshake that TIMES OUT never told us anything about the
    // artifact: the server may need API keys we don't provide, the
    // resolved start command may be wrong, or the cold start may be
    // slower than our window. In a 200-artifact production batch this
    // one path produced 14 near-identical 2.5/10 verdicts — the judge
    // gravely scoring transcripts of our own timeout. Thrown as
    // SandboxInfraError so it lands as `infraFailure` (a job to retry),
    // never as a verdict about someone else's code — the same
    // classification a failed dependency install already gets.
    //
    // A NON-timeout failure stays in the transcript: a server that
    // exits immediately or prints garbage produced real, judgeable
    // evidence about itself.
    if (pass1.timedOut || /^timeout: /.test(discovery?.error ?? "")) {
      // Placeholder credentials were already injected before the handshake,
      // so a timeout here means presence-checks weren't enough — the server
      // likely validates its credentials at boot, or the start command is
      // wrong. Name the declared vars so an operator can classify it.
      const envHint =
        declared.length > 0
          ? `Placeholder credentials were injected, but the server still did not respond; it ` +
            `declares (${declared.join(", ")}) and likely validates them at boot — not ` +
            `behaviorally testable without real credentials.`
          : `Placeholder credentials were injected but did not satisfy the server; it may need ` +
            `real credentials or environment the harness cannot provide.`;
      throw new SandboxInfraError(
        `MCP discovery timed out before the server responded (${detail}). ` +
          `This is an environment failure, not an artifact defect. ${envHint}`,
      );
    }
    messages.push({
      role: "tool",
      // `??` was wrong here: an empty stderr is a STRING, so it won
      // the coalesce and the message ended as "failed during
      // discovery: " with no diagnostic at all — useless to whoever
      // has to fix the server. Empty must fall through too.
      content: `MCP driver failed during discovery: ${detail}`,
    });
    return { messages, toolCalls, durationMs: Date.now() - start };
  }
  if (discovery.initialize) {
    const name = discovery.initialize.serverInfo?.name ?? "(unknown)";
    messages.push({
      role: "tool",
      content: `initialize: server=${name} protocol=${discovery.initialize.protocolVersion ?? "?"}`,
    });
  }
  const tools = discovery.tools ?? [];
  messages.push({
    role: "tool",
    content: `tools/list: ${tools.map((t) => t.name).join(", ") || "(none)"}`,
  });
  // What the server ACTUALLY returned, which may differ from what its
  // source declares. Recorded so cross-version diffing can compare
  // runtime surfaces rather than only source-level ones.
  const observedSurface =
    tools.length > 0
      ? makeSurface(
          "observed",
          tools.map((t) => ({
            name: t.name,
            ...(t.description !== undefined ? { description: t.description } : {}),
          })),
        )
      : undefined;

  // If no LLM was wired AND we already executed the legacy single
  // call in pass1, surface that and return.
  if (!input.llm) {
    for (const c of discovery.calls ?? []) {
      toolCalls.push({
        id: `mcp_call_${toolCalls.length + 1}`,
        name: c.tool,
        input: c.arguments ?? {},
      });
      messages.push({
        role: "tool",
        content: `tools/call ${c.tool}: ${JSON.stringify(c.result ?? c.error ?? null)}`,
      });
    }
    return {
      messages,
      toolCalls,
      durationMs: Date.now() - start,
      ...(observedSurface ? { observedSurface } : {}),
    };
  }

  // 4) Synthesize args for up to `cap` tools using the host LLM. Done
  //    in parallel — these are independent prompts, and the cap keeps
  //    the fan-out bounded.
  const toolsToCall = tools.slice(0, cap);
  const synthesizedCalls = await Promise.all(
    toolsToCall.map(async (t) => ({
      name: t.name,
      arguments: await synthesizeToolArgs(input.llm, t, test.prompt),
    })),
  );

  // 5) Pass 2 — replay the synthesized calls. Driver re-spawns the
  //    server (cheap relative to LLM calls), executes each, prints
  //    results, exits.
  const callsPath = `${cwd.replace(/\/$/, "")}/mcp-calls.json`;
  await sandbox.writeFiles([{ path: callsPath, contents: JSON.stringify(synthesizedCalls) }]);
  const pass2 = await sandbox.exec(
    `node ${driverPath} ${JSON.stringify(serverCmd)} ${JSON.stringify(callsPath)}`,
    { cwd, timeoutMs: 180_000, env: sandboxEnv },
  );
  messages.push({
    role: "assistant",
    content: `driver pass2 exit=${pass2.exitCode}${pass2.timedOut ? " (timed out)" : ""}`,
  });
  const replay = parseDriverOutput(pass2.stdout);
  if (replay?.calls) {
    for (const c of replay.calls) {
      toolCalls.push({
        id: `mcp_call_${toolCalls.length + 1}`,
        name: c.tool,
        input: c.arguments ?? {},
      });
      const payload =
        c.error !== undefined
          ? `error: ${c.error}`
          : `result: ${JSON.stringify(c.result ?? null).slice(0, 500)}`;
      messages.push({
        role: "tool",
        content: `tools/call ${c.tool}(${JSON.stringify(c.arguments ?? {}).slice(0, 200)}): ${payload}`,
      });
    }
  } else if (!replay) {
    messages.push({
      role: "tool",
      content: `MCP driver pass2 produced no parseable output: ${pass2.stderr || "(empty)"}`,
    });
  }

  return {
    messages,
    toolCalls,
    durationMs: Date.now() - start,
    ...(observedSurface ? { observedSurface } : {}),
  };
}
