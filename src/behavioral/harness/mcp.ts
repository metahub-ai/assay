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
import { assessConformance } from "../mcp-observation.js";
import type { McpObservation, McpToolAnnotation } from "../mcp-observation.js";
import { detectTransport, MCP_HTTP_DRIVER_SOURCE } from "./transport.js";
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
  /** MCP tool annotations — the safety hints a client's approval UI
   *  reads (readOnlyHint, destructiveHint, idempotentHint, openWorldHint,
   *  title). Optional in the spec; captured so the truth-check can
   *  cross-examine them. */
  annotations?: Record<string, unknown>;
}

interface DriverCallResult {
  tool: string;
  arguments?: Record<string, unknown>;
  result?: unknown;
  error?: string;
}

interface DriverResource {
  uri?: string;
  name?: string;
  mimeType?: string;
}

interface DriverPrompt {
  name?: string;
  description?: string;
}

interface DriverFrame {
  dir: "in" | "out";
  kind: "request" | "response" | "notification" | "server-request";
  id?: number;
  method?: string;
  result?: string;
  error?: string;
}

interface DriverOutput {
  ok: boolean;
  error?: string;
  initialize?: { protocolVersion?: string; serverInfo?: { name?: string; version?: string } };
  tools?: DriverTool[];
  calls?: DriverCallResult[];
  /** resources/* surface, when the server implements it. */
  resources?: DriverResource[];
  resourceRead?: { uri?: string; ok: boolean };
  /** prompts/* surface, when the server implements it. */
  prompts?: DriverPrompt[];
  promptGet?: { name?: string; ok: boolean };
  /** Server -> client messages with no id (logging, progress, requests). */
  notifications?: { method?: string; params?: string; serverRequest?: boolean }[];
  /** The server's own stderr — logs, stack traces, echoed secrets. */
  stderr?: string;
  /** Bounded log of every JSON-RPC frame, both directions. */
  frames?: DriverFrame[];
  /** HTTP driver only: which transport ran and the endpoint it found. */
  transport?: string;
  endpoint?: string;
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
  /** Runtime-recorder wrapper for the driver invocations. */
  traceWrap?: import("../types.js").TraceWrap;
}

/**
 * The stdio JSON-RPC driver, emitted into the sandbox verbatim. It is
 * a standalone ES module with zero dependencies — Node's
 * `child_process` + line buffering only.
 *
 *   argv[2] = serverCmd            (required)
 *   argv[3] = path to calls.json   (optional)
 *
 * When argv[3] is omitted (phase 1, discovery): do init + tools/list,
 * then probe the OPTIONAL surface — resources/list (+ read the first),
 * prompts/list (+ get the first) — and ping the first tool. Prints
 *   { ok, initialize, tools, resources?, resourceRead?, prompts?,
 *     promptGet?, calls?, notifications?, stderr?, frames? }.
 *
 * When argv[3] is present and points at a JSON array of
 *   [{ name, arguments }, …]
 * the driver does init + replays the calls (phase 2) and prints
 *   { ok, initialize, tools, calls: [{ tool, arguments, result, error? }],
 *     notifications?, stderr?, frames? }.
 *
 * Beyond the tool catalog the driver captures, in BOTH phases: the
 * server's own stderr (`stderr` — logs, stack traces, echoed secrets),
 * every server -> client message with no matching request (`notifications`
 * — logging/progress, and sampling/roots/elicitation requests flagged
 * `serverRequest`), and a bounded log of every JSON-RPC frame in either
 * direction (`frames`). Optional-capability probes use a tolerant send,
 * so a tools-only server reports absence, never an error.
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

// stderr is PIPED, not inherited: a server's own logs are evidence
// (secrets echoed, stack traces, "connecting to X") and used to be
// thrown away into the parent's stderr.
const child = spawn("sh", ["-lc", serverCmd], { stdio: ["pipe", "pipe", "pipe"] });

let buf = "";
const pending = new Map();
let nextId = 1;
const notifications = [];   // server -> client messages with no id
const frames = [];          // every JSON-RPC frame, both directions, bounded
let serverStderr = "";
const MAX_FRAMES = 200, MAX_STDERR = 8192, MAX_PREVIEW = 300;
function preview(v) {
  try { const s = typeof v === "string" ? v : JSON.stringify(v); return s && s.length > MAX_PREVIEW ? s.slice(0, MAX_PREVIEW) + "..." : s; }
  catch { return "<unserializable>"; }
}
function pushFrame(f) { if (frames.length < MAX_FRAMES) frames.push(f); }

child.stderr.on("data", (c) => { if (serverStderr.length < MAX_STDERR) serverStderr += c.toString(); });

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
      pushFrame({ dir: "in", kind: "response", id: msg.id, ...(msg.error ? { error: preview(msg.error) } : { result: preview(msg.result) }) });
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    } else if (msg.method !== undefined && msg.id === undefined) {
      // server -> client notification (logging, progress, list-changed)
      notifications.push({ method: msg.method, params: preview(msg.params) });
      pushFrame({ dir: "in", kind: "notification", method: msg.method });
    } else if (msg.method !== undefined && msg.id !== undefined) {
      // server -> client REQUEST (sampling / roots / elicitation). We do
      // not implement these; record that the server asked for one.
      notifications.push({ method: msg.method, serverRequest: true });
      pushFrame({ dir: "in", kind: "server-request", id: msg.id, method: msg.method });
    }
  }
});

function send(method, params, timeoutMs) {
  const id = nextId++;
  const payload = { jsonrpc: "2.0", id, method, params: params ?? {} };
  pushFrame({ dir: "out", kind: "request", id, method });
  child.stdin.write(JSON.stringify(payload) + "\n");
  return new Promise((resolve, reject) => {
    const t = timeoutMs ?? 60000;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("timeout: " + method)); }, t);
    pending.set(id, { resolve: (m) => { clearTimeout(timer); resolve(m); } });
  });
}

// Tolerant send for OPTIONAL capabilities: a method-not-found (or any
// error/timeout) resolves to null rather than throwing, so probing
// resources/prompts on a server that implements only tools is a
// capability observation, not a failure.
async function trySend(method, params, timeoutMs) {
  try { const res = await send(method, params, timeoutMs ?? 15000); return res && !res.error && res.result ? res.result : null; }
  catch { return null; }
}

function notify(method, params) {
  pushFrame({ dir: "out", kind: "notification", method });
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
    // Paginate: a server with a large catalog returns tools/list in
    // pages, each carrying a nextCursor. Reading only the first page
    // truncated the catalog — the later tools (often the powerful ones a
    // server buries) were never evaluated. Bounded to 20 pages so a
    // server that echoes a stable cursor cannot spin the driver forever.
    const tools = [];
    let cursor = undefined;
    for (let page = 0; page < 20; page++) {
      const listRes = await send("tools/list", cursor ? { cursor } : {});
      const pageTools = (listRes.result && listRes.result.tools) || [];
      for (const t of pageTools) tools.push(t);
      const next = listRes.result && listRes.result.nextCursor;
      if (!next || next === cursor) break;
      cursor = next;
    }
    out.tools = tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations }));

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
    } else if (callsPath === null) {
      // Phase 1 discovery — enumerate the WHOLE protocol surface, not
      // just tools. resources/* and prompts/* are optional, so a server
      // that only does tools simply reports none.
      const resList = await trySend("resources/list", {});
      if (resList) {
        out.resources = (resList.resources || []).map((r) => ({ uri: r.uri, name: r.name, mimeType: r.mimeType }));
        if (out.resources.length > 0 && out.resources[0].uri) {
          const read = await trySend("resources/read", { uri: out.resources[0].uri });
          out.resourceRead = { uri: out.resources[0].uri, ok: !!read };
        }
      }
      const promptList = await trySend("prompts/list", {});
      if (promptList) {
        out.prompts = (promptList.prompts || []).map((p) => ({ name: p.name, description: p.description }));
        if (out.prompts.length > 0 && out.prompts[0].name) {
          const got = await trySend("prompts/get", { name: out.prompts[0].name, arguments: {} });
          out.promptGet = { name: out.prompts[0].name, ok: !!got };
        }
      }
      // Legacy smoke: ping the first tool with empty args so a caller
      // that never reaches phase 2 still gets a tool signal.
      if (tools.length > 0) {
        const first = tools[0];
        try {
          const callRes = await send("tools/call", { name: first.name, arguments: {} });
          out.calls = [{ tool: first.name, arguments: {}, result: callRes.result ?? callRes.error ?? null }];
        } catch (err) {
          out.calls = [{ tool: first.name, arguments: {}, error: String(err && err.message ? err.message : err) }];
        }
      }
    }
    out.ok = true;
  } catch (err) {
    out.ok = false;
    out.error = String(err && err.message ? err.message : err);
  } finally {
    if (notifications.length) out.notifications = notifications;
    if (serverStderr) out.stderr = serverStderr.slice(0, MAX_STDERR);
    if (frames.length) out.frames = frames;
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

/**
 * Turn the driver's extra protocol observations (resources, prompts,
 * notifications, server-initiated requests, and the server's own stderr)
 * into transcript lines. Only the ones present are emitted, so a
 * tools-only server adds nothing here. The server's stderr is included
 * because it is genuine self-evidence — a stack trace, a "connecting
 * to …" line, or a secret echoed to the log.
 */
function protocolMessages(out: DriverOutput): LlmMessage[] {
  const msgs: LlmMessage[] = [];
  if (out.resources) {
    const names = out.resources.map((r) => r.uri ?? r.name ?? "?").slice(0, 12);
    const read = out.resourceRead
      ? ` · read ${out.resourceRead.uri ?? "?"} -> ${out.resourceRead.ok ? "ok" : "error"}`
      : "";
    msgs.push({ role: "tool", content: `resources/list: ${names.join(", ") || "(none)"}${read}` });
  }
  if (out.prompts) {
    const names = out.prompts.map((p) => p.name ?? "?").slice(0, 12);
    const got = out.promptGet
      ? ` · get ${out.promptGet.name ?? "?"} -> ${out.promptGet.ok ? "ok" : "error"}`
      : "";
    msgs.push({ role: "tool", content: `prompts/list: ${names.join(", ") || "(none)"}${got}` });
  }
  if (out.notifications && out.notifications.length > 0) {
    const notes = out.notifications.filter((n) => !n.serverRequest);
    const reqs = out.notifications.filter((n) => n.serverRequest);
    if (notes.length > 0) {
      const methods = notes
        .map((n) => n.method)
        .filter(Boolean)
        .slice(0, 8);
      msgs.push({ role: "tool", content: `server notifications: ${methods.join(", ")}` });
    }
    if (reqs.length > 0) {
      const methods = [...new Set(reqs.map((n) => n.method).filter(Boolean))];
      msgs.push({
        role: "tool",
        content: `server->client requests (sampling/roots/elicitation): ${methods.join(", ")}`,
      });
    }
  }
  if (out.stderr && out.stderr.trim()) {
    msgs.push({ role: "tool", content: `server stderr:\n${out.stderr.slice(0, 800)}` });
  }
  return msgs;
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

  // 2b) Route by transport. An HTTP/Streamable-HTTP server binds a port
  //     and never answers the stdio handshake — pointing the stdio driver
  //     at it produced a bogus "server is dead" verdict. Detect it from
  //     the entry source and drive it over HTTP instead.
  if ((await detectServerTransport(sandbox, cwd, serverCmd)) === "http") {
    return runHttpMcpCase(input, cwd, serverCmd, messages, start);
  }

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
  //    Wrapped in the runtime recorder: the driver spawns the SERVER,
  //    so strace -f from here captures the artifact's whole tree.
  const pass1Cmd = `node ${driverPath} ${JSON.stringify(serverCmd)}`;
  const pass1 = await sandbox.exec(input.traceWrap ? input.traceWrap(pass1Cmd) : pass1Cmd, {
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
  // The rest of the protocol surface, so the judge and the report see a
  // server as more than its tools — resources, prompts, notifications,
  // and its own stderr. Only emitted when there is something to say.
  for (const m of protocolMessages(discovery)) messages.push(m);
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

  // Structured MCP observation: protocol conformance + the safety
  // annotations, cross-examined downstream against descriptions and the
  // runtime ledger.
  const mcp = buildMcpObservation(discovery);

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
      mcp,
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
  const pass2Cmd = `node ${driverPath} ${JSON.stringify(serverCmd)} ${JSON.stringify(callsPath)}`;
  const pass2 = await sandbox.exec(input.traceWrap ? input.traceWrap(pass2Cmd) : pass2Cmd, {
    cwd,
    timeoutMs: 180_000,
    env: sandboxEnv,
  });
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
  // Anything the server emitted WHILE serving the calls — a notification
  // fired mid-request, a sampling/elicitation request back to the client,
  // or a line on stderr — is behavior under load, so surface it too.
  if (replay) for (const m of protocolMessages(replay)) messages.push(m);

  return {
    messages,
    toolCalls,
    durationMs: Date.now() - start,
    ...(observedSurface ? { observedSurface } : {}),
    mcp,
  };
}

/**
 * Derive the structured MCP observation (conformance + tool annotations)
 * from a discovery-pass driver output. Pure; the scoring lives in
 * mcp-observation.ts so it is tested without a sandbox.
 */
function buildMcpObservation(out: DriverOutput): McpObservation {
  const bool = (v: unknown) => (typeof v === "boolean" ? v : undefined);
  const annotated: McpToolAnnotation[] = (out.tools ?? []).map((t) => {
    const a = (t.annotations ?? {}) as Record<string, unknown>;
    return {
      name: t.name,
      ...(t.description !== undefined ? { description: t.description } : {}),
      readOnlyHint: bool(a["readOnlyHint"]),
      destructiveHint: bool(a["destructiveHint"]),
      idempotentHint: bool(a["idempotentHint"]),
      openWorldHint: bool(a["openWorldHint"]),
      ...(typeof a["title"] === "string" ? { title: a["title"] as string } : {}),
      hasInputSchema:
        t.inputSchema !== undefined && t.inputSchema !== null && typeof t.inputSchema === "object",
    };
  });
  const conformance = assessConformance({
    ...(out.initialize ? { initialize: out.initialize } : {}),
    tools: annotated.map((t) => ({ name: t.name, hasInputSchema: t.hasInputSchema })),
    hasResources: (out.resources?.length ?? 0) > 0,
    hasPrompts: (out.prompts?.length ?? 0) > 0,
  });
  return { conformance, tools: annotated };
}

/**
 * Classify the server's transport from its entry source. Best-effort:
 * unreadable files or an unrecognized shape default to stdio (the safe,
 * common path).
 */
async function detectServerTransport(
  sandbox: Sandbox,
  cwd: string,
  serverCmd: string,
): Promise<"stdio" | "http"> {
  const m = /node\s+(?:"([^"]+)"|'([^']+)'|(\S+))/.exec(serverCmd);
  const entry = m ? m[1] || m[2] || m[3] : null;
  const candidates = [
    entry,
    "index.js",
    "index.mjs",
    "server.js",
    "src/index.js",
    "dist/index.js",
    "main.py",
    "server.py",
  ].filter((p): p is string => Boolean(p));
  const base = cwd.replace(/\/+$/, "");
  const files: { path: string; body: string }[] = [];
  const seen = new Set<string>();
  for (const p of candidates) {
    if (seen.has(p)) continue;
    seen.add(p);
    const abs = p.startsWith("/") ? p : `${base}/${p}`;
    const body = await sandbox.readFile(abs).catch(() => null);
    if (body) files.push({ path: p, body });
    if (files.length >= 4) break;
  }
  return detectTransport(files);
}

/**
 * Drive an HTTP/Streamable-HTTP MCP server. Single discovery pass
 * (initialize + tools/list + a first tool ping) — enough to capture the
 * surface, conformance and annotations; the two-pass LLM replay stays a
 * stdio feature for now. Reuses every downstream helper, so the
 * transcript, observation and ledger are identical in shape.
 */
async function runHttpMcpCase(
  input: McpHarnessInput,
  cwd: string,
  serverCmd: string,
  messages: LlmMessage[],
  start: number,
): Promise<Transcript> {
  const { sandbox } = input;
  const toolCalls: LlmToolCall[] = [];
  const driverPath = `${cwd.replace(/\/+$/, "")}/mcp-http-driver.mjs`;
  await sandbox.writeFiles([{ path: driverPath, contents: MCP_HTTP_DRIVER_SOURCE }]);

  const declared = await declaredEnvVars(sandbox, cwd);
  const env = placeholderCredentialEnv(declared);
  const port = "3939";
  const cmd = `node ${driverPath} ${JSON.stringify(serverCmd)} ${port}`;
  const run = await sandbox.exec(input.traceWrap ? input.traceWrap(cmd) : cmd, {
    cwd,
    timeoutMs: 120_000,
    env,
  });
  messages.push({
    role: "assistant",
    content: `HTTP driver exit=${run.exitCode}${run.timedOut ? " (timed out)" : ""}`,
  });

  const discovery = parseDriverOutput(run.stdout);
  if (!discovery || !discovery.ok) {
    const detail = discovery?.error || run.stderr || "no parseable output";
    // Same infra-vs-artifact honesty as stdio: a server that never opened
    // a port under placeholder credentials told us nothing about itself.
    if (run.timedOut || /did not open a port|no MCP endpoint/.test(discovery?.error ?? "")) {
      throw new SandboxInfraError(
        `MCP HTTP server did not become reachable (${detail}). ` +
          `This is an environment failure, not an artifact defect — it may need real ` +
          `credentials, a fixed port, or an endpoint path the driver did not try.`,
      );
    }
    messages.push({ role: "tool", content: `MCP HTTP driver failed during discovery: ${detail}` });
    return { messages, toolCalls, durationMs: Date.now() - start };
  }

  messages.push({
    role: "tool",
    content: `transport: streamable-http (endpoint ${discovery.endpoint ?? "?"})`,
  });
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
  for (const m of protocolMessages(discovery)) messages.push(m);

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
  const mcp = buildMcpObservation(discovery);

  for (const c of discovery.calls ?? []) {
    toolCalls.push({
      id: `mcp_call_${toolCalls.length + 1}`,
      name: c.tool,
      input: c.arguments ?? {},
    });
    messages.push({
      role: "tool",
      content: `tools/call ${c.tool}: ${JSON.stringify(c.result ?? c.error ?? null).slice(0, 300)}`,
    });
  }

  return {
    messages,
    toolCalls,
    durationMs: Date.now() - start,
    ...(observedSurface ? { observedSurface } : {}),
    mcp,
  };
}
