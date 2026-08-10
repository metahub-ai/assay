/**
 * MCP auth posture — the OAuth resource-server risks the June-2025 spec
 * revision exists to prevent. Heuristic and warn-level, so the other
 * half of the suite is "leaves a server that gets auth right, or does no
 * auth at all, alone".
 */
import { describe, expect, it } from "vitest";
import { mcpAuthPosture } from "../src/checks/kinds/mcp-auth";
import type { CheckContext, CheckDefinition } from "../src/check";
import type { CheckResult, Subject } from "../src/types";
import { MemorySource } from "../src/sources/memory";

const subject: Subject = {
  kind: "mcp",
  name: "demo",
  source: { type: "directory", path: "/tmp/demo" },
  digest: { sha256: "0".repeat(64) },
};
function ctxFor(files: Record<string, string>): CheckContext {
  const noop = () => {};
  return {
    subject,
    source: new MemorySource(files),
    config: {},
    log: { debug: noop, info: noop, warn: noop, error: noop },
    signal: new AbortController().signal,
  };
}
const run = (check: CheckDefinition, files: Record<string, string>): Promise<CheckResult> =>
  Promise.resolve(check.run(ctxFor(files)));

describe("mcp-auth-posture", () => {
  it("is neutral for a server that does no token handling", async () => {
    const r = await run(mcpAuthPosture, { "server.js": "server.tool('echo', () => 'hi');" });
    expect(r.status).toBe("neutral");
  });

  it("warns when a JWT is verified without an audience check", async () => {
    const r = await run(mcpAuthPosture, {
      "auth.js": "const claims = jwt.verify(bearerToken, publicKey);",
    });
    expect(r.status).toBe("warn");
    expect(r.detail).toMatch(/audience/);
  });

  it("warns when a token is decoded but never verified", async () => {
    const r = await run(mcpAuthPosture, {
      "auth.js": "const claims = jwt.decode(req.headers.authorization);",
    });
    expect(r.status).toBe("warn");
    expect(r.detail).toMatch(/without verifying/);
  });

  it("warns on token passthrough to an upstream service", async () => {
    const r = await run(mcpAuthPosture, {
      "server.js":
        "const token = req.headers.authorization;\n" +
        "await fetch(UPSTREAM, { headers: { authorization: `Bearer ${token}` } });",
    });
    expect(r.status).toBe("warn");
    expect(r.detail).toMatch(/passthrough/);
  });

  it("passes a server that verifies signature AND audience", async () => {
    const r = await run(mcpAuthPosture, {
      "auth.js": "const claims = jwt.verify(token, key, { audience: MY_SERVER_ID });",
    });
    expect(r.status).toBe("pass");
  });
});
