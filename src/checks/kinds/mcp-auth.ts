/**
 * MCP auth posture.
 *
 * The MCP spec's June-2025 revision made servers OAuth resource servers,
 * and the enterprise-blocking risks moved with it: a server that accepts
 * a bearer token but never checks who it was issued FOR (the `aud`
 * claim) is a confused deputy; one that decodes a token without
 * verifying its signature trusts anything shaped like a token; one that
 * forwards the caller's token to an upstream API leaks it out of scope
 * (token passthrough). None of these are visible to a check that reads
 * tool descriptions.
 *
 * This is a heuristic over source, so it WARNS rather than blocks, and
 * only fires when the server actually handles auth — a stdio server with
 * no token handling is neutral. Node/TypeScript-shaped (the TS SDK is
 * the common case); a Python server with bespoke auth may pass unseen,
 * which the summary is honest about.
 */
import { defineCheck } from "../../check.js";
import { skips } from "../code.js";
import type { CheckContext } from "../../check.js";
import type { CheckResult, Evidence } from "../../types.js";
import { checkSpecUrl } from "../../version.js";

/** The server touches tokens at all — nothing below matters otherwise. */
const HANDLES_AUTH =
  /\b(authorization|bearer|access[_-]?token|id[_-]?token|oauth|jwt|jsonwebtoken|jose)\b/i;

interface AuthFinding {
  path: string;
  what: string;
}

function scanAuth(path: string, body: string): AuthFinding[] {
  const out: AuthFinding[] = [];

  // A JWT is verified, but nothing constrains its audience — any valid
  // token for ANY service is accepted (confused deputy / token replay).
  if (/\bjwt\.verify\s*\(|\bjwtVerify\s*\(|\bverify(?:Jwt|Token)\s*\(/.test(body)) {
    if (!/\baudience\b|["'`]aud["'`]|\.aud\b/.test(body)) {
      out.push({
        path,
        what: "verifies a JWT without checking its audience (aud) — a token minted for another service is accepted",
      });
    }
  }

  // A token is DECODED (its claims read) but never verified — the
  // signature is never checked, so a forged token passes.
  const decodes = /\bjwt\.decode\s*\(|\bdecodeJwt\s*\(|\bdecodeProtectedHeader\s*\(/.test(body);
  const verifies = /\bjwt\.verify\s*\(|\bjwtVerify\s*\(|\bverify(?:Jwt|Token)\s*\(/.test(body);
  if (decodes && !verifies) {
    out.push({
      path,
      what: "decodes a token without verifying its signature — a forged token is trusted",
    });
  }

  // The caller's Authorization header is read AND an Authorization
  // header is set on an outbound request — the client's token is
  // forwarded upstream (token passthrough).
  const readsIncoming = /\b(req|request|headers|ctx|context)\b[^\n]{0,40}\bauthorization\b/i.test(
    body,
  );
  const sendsOutbound =
    /\b(fetch|axios|got|request|http[s]?\.request)\b[\s\S]{0,200}?authorization\s*:\s*[`'"]?\s*bearer/i.test(
      body,
    );
  if (readsIncoming && sendsOutbound) {
    out.push({
      path,
      what: "may forward the caller's token to an upstream service (token passthrough)",
    });
  }

  return out;
}

async function authSources(ctx: CheckContext): Promise<{ path: string; body: string }[]> {
  const tree = await ctx.source.listTree();
  const skip = skips(tree);
  const files = tree.filter(
    (e) => e.type === "file" && /\.(ts|js|mjs|cjs|py)$/.test(e.path) && !skip(e.path),
  );
  const out: { path: string; body: string }[] = [];
  for (const f of files.slice(0, 300)) {
    const body = await ctx.source.readFile(f.path);
    if (body) out.push({ path: f.path, body });
  }
  return out;
}

export const mcpAuthPosture = defineCheck({
  id: "mcp-auth-posture",
  version: "1.0.0",
  title: "Token handling validates audience and does not pass through",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 3,
  appliesTo: { kinds: ["mcp"] },
  spec: checkSpecUrl("mcp-auth-posture"),
  inspects: "Source that handles OAuth/bearer tokens, for audience checks and passthrough.",
  rationale:
    "An MCP server that authenticates callers is an OAuth resource server, and the spec's own security guidance turns on three things: it must reject tokens minted for a different audience, it must verify a token's signature before trusting its claims, and it must not forward the caller's token upstream. Missing any of these is the confused-deputy / token-passthrough class the June-2025 spec revision exists to prevent.",
  examples: {
    passing: "jwt.verify(token, key, { audience: EXPECTED_AUD })",
    failing: "jwt.decode(token)  // trusts the claims without verifying the signature",
  },
  async run(ctx): Promise<CheckResult> {
    const sources = await authSources(ctx);
    const handlesAuth = sources.filter((s) => HANDLES_AUTH.test(s.body));
    if (handlesAuth.length === 0) {
      return {
        status: "neutral",
        summary: "No token/OAuth handling found; auth posture is out of scope for this server.",
      };
    }
    const findings: AuthFinding[] = [];
    for (const s of handlesAuth) findings.push(...scanAuth(s.path, s.body));

    if (findings.length === 0) {
      return {
        status: "pass",
        summary: `Handles tokens in ${handlesAuth.length} file${handlesAuth.length === 1 ? "" : "s"}; no audience-check or passthrough problems found.`,
      };
    }
    const evidence: Evidence[] = [...new Set(findings.map((f) => f.path))]
      .slice(0, 5)
      .map((path) => ({ type: "file", path }));
    return {
      status: "warn",
      summary: `${findings.length} auth-posture concern${findings.length === 1 ? "" : "s"} in the server's token handling.`,
      detail:
        findings
          .slice(0, 8)
          .map((f) => `- \`${f.path}\` — ${f.what}`)
          .join("\n") +
        "\n\nHeuristic over source (Node/TypeScript-shaped); confirm against the server's real auth flow.",
      remediation:
        "Verify every token's signature AND audience against this server's own identifier, and never reuse the caller's token for outbound calls — mint or exchange a scoped one.",
      evidence,
    };
  },
});

export const MCP_AUTH_CHECKS = [mcpAuthPosture];
