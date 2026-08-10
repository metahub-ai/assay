/**
 * MCP transport detection.
 *
 * The harness drove stdio only. That is the common case for a locally
 * installed server, but the June-2025 spec's Streamable HTTP transport
 * is how remote/hosted servers speak — and an HTTP-transport server
 * pointed at the stdio driver simply never answers the handshake, so it
 * was misgraded as a dead server rather than driven correctly.
 *
 * This classifies a server from its source so the harness can route it:
 * an HTTP server binds a port and mounts a transport (Streamable HTTP or
 * the older SSE); a stdio server reads JSON-RPC on stdin. A server that
 * supports both is driven over stdio (the simpler, more deterministic
 * path), so `http` is returned only when there is HTTP and no stdio.
 */
export type McpTransport = "stdio" | "http";

const HTTP_MARKERS = [
  /StreamableHTTPServerTransport/,
  /SSEServerTransport/,
  /\bexpress\s*\(/,
  // Both `http.createServer(` and a destructured `createServer(` from
  // node:http — the latter is common and was slipping through.
  /\bcreateServer\s*\(/,
  // Binding a port is the defining HTTP move.
  /\.listen\s*\(/,
  /\bapp\.(?:post|get|use)\s*\(/,
  /\bfastify\s*\(/,
  /\bnew\s+Hono\b/,
  // Importing the http(s) module or FastAPI/uvicorn (python).
  /from\s+["'`]node:https?["'`]|require\(\s*["'`]https?["'`]\s*\)/,
  /\b(FastAPI|uvicorn|starlette|aiohttp|flask)\b/i,
];

const STDIO_MARKERS = [
  /StdioServerTransport/,
  /process\.stdin\b/,
  /createInterface\s*\(\s*\{\s*input\s*:\s*process\.stdin/,
  /sys\.stdin\b/, // python
  /stdio_server\b/, // python mcp sdk
];

export function detectTransport(
  files: ReadonlyArray<{ path: string; body: string }>,
): McpTransport {
  let http = false;
  let stdio = false;
  for (const f of files) {
    if (!/\.(ts|js|mjs|cjs|py)$/.test(f.path)) continue;
    if (!http && HTTP_MARKERS.some((re) => re.test(f.body))) http = true;
    if (!stdio && STDIO_MARKERS.some((re) => re.test(f.body))) stdio = true;
  }
  return http && !stdio ? "http" : "stdio";
}

/**
 * The Streamable-HTTP driver, emitted into the sandbox verbatim.
 *
 *   argv[2] = serverCmd   (required) — boots the HTTP server
 *   argv[3] = port        (the driver sets PORT in the server's env)
 *
 * Zero dependencies: Node's global `fetch` + child_process. It boots the
 * server, waits for the port, discovers the MCP endpoint among the
 * common paths, and runs initialize → tools/list → first tools/call —
 * handling both a JSON response and a Streamable-HTTP SSE stream, and
 * echoing the `mcp-session-id` the server assigns. It prints the SAME
 * `{ ok, initialize, tools, calls, stderr }` line the stdio driver does,
 * so everything downstream (parse, observation, transcript) is shared.
 */
export const MCP_HTTP_DRIVER_SOURCE = String.raw`
import { spawn } from "node:child_process";

const serverCmd = process.argv[2];
const port = process.argv[3] || "3333";
if (!serverCmd) {
  process.stdout.write(JSON.stringify({ ok: false, error: "no server command" }) + "\n");
  process.exit(0);
}

const child = spawn("sh", ["-lc", serverCmd], {
  stdio: ["ignore", "pipe", "pipe"],
  env: { ...process.env, PORT: port, MCP_PORT: port, MCP_HTTP_PORT: port },
});
let serverStderr = "";
child.stderr.on("data", (c) => { if (serverStderr.length < 8192) serverStderr += c.toString(); });

const BASE = "http://127.0.0.1:" + port;
const PATHS = ["/mcp", "/", "/message", "/messages", "/rpc", "/sse"];
let endpoint = null, sessionId = null, nextId = 1;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try { await fetch(BASE + "/", { method: "GET" }); return true; } catch {}
    await sleep(200);
  }
  return false;
}

async function rpc(path, body, isNotification) {
  const headers = { "content-type": "application/json", accept: "application/json, text/event-stream" };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const res = await fetch(BASE + path, { method: "POST", headers, body: JSON.stringify(body) });
  const sid = res.headers.get("mcp-session-id");
  if (sid) sessionId = sid;
  if (isNotification) return null;
  const ct = res.headers.get("content-type") || "";
  const text = await res.text();
  if (ct.includes("text/event-stream")) {
    for (const line of text.split(/\r?\n/)) {
      const m = /^data:\s*(.*)$/.exec(line);
      if (m) { try { const j = JSON.parse(m[1]); if (j && (j.result || j.error)) return j; } catch {} }
    }
    return null;
  }
  try { return JSON.parse(text); } catch { return null; }
}

async function main() {
  const out = { ok: false, transport: "http" };
  try {
    if (!(await waitUp())) throw new Error("server did not open a port on " + port);
    const initReq = { jsonrpc: "2.0", id: nextId++, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "metahub-eval", version: "0.1.0" } } };
    for (const p of PATHS) {
      try {
        const r = await rpc(p, initReq);
        if (r && r.result && (r.result.protocolVersion || r.result.serverInfo || r.result.capabilities)) {
          endpoint = p; out.initialize = r.result; break;
        }
      } catch {}
    }
    if (!endpoint) throw new Error("no MCP endpoint answered initialize (tried " + PATHS.join(", ") + ")");
    await rpc(endpoint, { jsonrpc: "2.0", method: "notifications/initialized", params: {} }, true);
    const listRes = await rpc(endpoint, { jsonrpc: "2.0", id: nextId++, method: "tools/list", params: {} });
    const tools = (listRes && listRes.result && listRes.result.tools) || [];
    out.tools = tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations }));
    if (tools.length > 0) {
      try {
        const c = await rpc(endpoint, { jsonrpc: "2.0", id: nextId++, method: "tools/call", params: { name: tools[0].name, arguments: {} } });
        out.calls = [{ tool: tools[0].name, arguments: {}, result: (c && (c.result || c.error)) || null }];
      } catch (e) {
        out.calls = [{ tool: tools[0].name, arguments: {}, error: String(e && e.message ? e.message : e) }];
      }
    }
    out.ok = true;
  } catch (err) {
    out.ok = false;
    out.error = String(err && err.message ? err.message : err);
  } finally {
    if (serverStderr) out.stderr = serverStderr.slice(0, 8192);
    if (endpoint) out.endpoint = endpoint;
    process.stdout.write(JSON.stringify(out) + "\n");
    child.kill("SIGKILL");
    process.exit(0);
  }
}
main();
`;
