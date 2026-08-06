/**
 * The OSV advisory lookup and the constrained network client.
 *
 * The net-client tests are security tests. A check is ordinary code
 * from a stranger, and if it can reach an arbitrary host then the
 * capability model is theatre — a `deterministic` claim elsewhere in
 * the suite means nothing when a `sampled` check can POST the
 * artifact's contents somewhere.
 */
import { describe, expect, it, vi } from "vitest";
import { concreteVersion, scanDependencies, severityOf, cvssBaseScore } from "../src/checks/osv";
import { createNetClient, NetAccessError } from "../src/net";
import { CORE_CHECKS } from "../src/checks/core";
import { MemorySource } from "../src/sources/memory";
import type { CheckContext, CheckDefinition } from "../src/check";
import type { NetClient } from "../src/ports";
import type { CheckResult } from "../src/types";

/** A NetClient that answers from a fixture map. */
function stubNet(routes: Record<string, unknown>): NetClient & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async fetch(url) {
      calls.push(url);
      const key = Object.keys(routes).find((k) => url.includes(k));
      const body = key ? routes[key] : null;
      return {
        status: body ? 200 : 404,
        headers: {},
        text: async () => JSON.stringify(body ?? {}),
      };
    },
  };
}

const LODASH_VULN = {
  id: "GHSA-35jh-r3h4-6jhm",
  summary: "Command Injection in lodash",
  database_specific: { severity: "HIGH" },
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
};

describe("concreteVersion", () => {
  it.each([
    ["^1.2.3", "1.2.3"],
    ["~4.17.20", "4.17.20"],
    [">=2.0.0 <3", "2.0.0"],
    ["1.2.3-beta.1", "1.2.3-beta.1"],
    ["4.17.20", "4.17.20"],
  ])("resolves %s to %s", (spec, expected) => {
    expect(concreteVersion(spec)).toBe(expected);
  });

  it.each(["*", "latest", "", "workspace:*"])("cannot resolve %s", (spec) => {
    expect(concreteVersion(spec)).toBeNull();
  });
});

describe("severity mapping", () => {
  it("prefers the curated GHSA label", () => {
    expect(severityOf({ id: "x", database_specific: { severity: "CRITICAL" } })).toBe("critical");
  });

  it("falls back to a numeric CVSS score", () => {
    expect(severityOf({ id: "x", severity: [{ type: "CVSS_V3", score: "9.8" }] })).toBe("critical");
    expect(severityOf({ id: "x", severity: [{ type: "CVSS_V3", score: "7.1" }] })).toBe("high");
    expect(severityOf({ id: "x", severity: [{ type: "CVSS_V3", score: "5.0" }] })).toBe("moderate");
    expect(severityOf({ id: "x", severity: [{ type: "CVSS_V3", score: "2.0" }] })).toBe("low");
  });

  // Publishing a severity nobody can reproduce is worse than admitting
  // we could not read it.
  it("reports unknown rather than guessing from a vector it cannot parse", () => {
    expect(
      severityOf({ id: "x", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L" }] }),
    ).toBe("unknown");
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:L")).toBeNull();
    expect(severityOf({ id: "x" })).toBe("unknown");
  });
});

describe("scanDependencies", () => {
  const routes = {
    querybatch: { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }, {}] },
    "vulns/GHSA-35jh-r3h4-6jhm": LODASH_VULN,
  };

  it("finds an advisory and reports its fixed version", async () => {
    const net = stubNet(routes);
    const r = await scanDependencies(net, { lodash: "4.17.20", safe: "^2.0.0" });
    expect(r.queried).toBe(2);
    expect(r.advisories).toHaveLength(1);
    expect(r.advisories[0]).toMatchObject({
      id: "GHSA-35jh-r3h4-6jhm",
      package: "lodash",
      severity: "high",
      fixed: "4.17.21",
    });
  });

  it("batches into one query rather than one per package", async () => {
    const net = stubNet(routes);
    await scanDependencies(net, { lodash: "4.17.20", safe: "^2.0.0", other: "^1.0.0" });
    expect(net.calls.filter((c) => c.includes("querybatch"))).toHaveLength(1);
  });

  // A package we could not resolve a version for is a package we did
  // NOT check, and reporting clean over it is the false-pass bug this
  // check already had once.
  it("names unresolvable ranges instead of silently omitting them", async () => {
    const net = stubNet({ querybatch: { results: [{}] } });
    const r = await scanDependencies(net, { pinned: "1.0.0", floating: "*" });
    expect(r.unresolvable).toEqual(["floating"]);
    expect(r.queried).toBe(1);
  });

  it("does not call OSV at all when nothing resolves", async () => {
    const net = stubNet({});
    const r = await scanDependencies(net, { a: "*", b: "latest" });
    expect(net.calls).toHaveLength(0);
    expect(r.advisories).toEqual([]);
  });

  // Losing a real advisory because one HTTP call failed is the worse
  // error, so it degrades rather than disappears.
  it("degrades an advisory to unknown severity when its detail lookup fails", async () => {
    const net = stubNet({ querybatch: { results: [{ vulns: [{ id: "GHSA-missing" }] }] } });
    const r = await scanDependencies(net, { lodash: "4.17.20" });
    expect(r.advisories).toHaveLength(1);
    expect(r.advisories[0]!.severity).toBe("unknown");
  });

  it("surfaces a failed batch query rather than reporting clean", async () => {
    const net: NetClient = {
      async fetch() {
        return { status: 503, headers: {}, text: async () => "" };
      },
    };
    await expect(scanDependencies(net, { lodash: "4.17.20" })).rejects.toThrow(/HTTP 503/);
  });
});

describe("the deps-no-known-vulns check", () => {
  const check = CORE_CHECKS.find((c) => c.id === "deps-no-known-vulns")!;
  const ctx = (files: Record<string, string>, net?: NetClient): CheckContext => {
    const noop = () => {};
    return {
      subject: {
        kind: "mcp",
        name: "d",
        source: { type: "directory", path: "." },
        digest: { sha256: "0".repeat(64) },
      },
      source: new MemorySource(files),
      config: {},
      log: { debug: noop, info: noop, warn: noop, error: noop },
      signal: new AbortController().signal,
      ...(net ? { net } : {}),
    };
  };
  const run = (c: CheckDefinition, x: CheckContext): Promise<CheckResult> =>
    Promise.resolve(c.run(x));

  const pkg = (deps: Record<string, string>) => JSON.stringify({ name: "d", dependencies: deps });

  it("fails on a high-severity advisory and links the evidence", async () => {
    const net = stubNet({
      querybatch: { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] },
      "vulns/GHSA-35jh-r3h4-6jhm": LODASH_VULN,
    });
    const r = await run(check, ctx({ "package.json": pkg({ lodash: "4.17.20" }) }, net));
    expect(r.status).toBe("fail");
    expect(r.detail).toMatch(/Fixed in 4\.17\.21/);
    expect(JSON.stringify(r.evidence)).toMatch(/osv\.dev\/vulnerability\/GHSA-35jh/);
  });

  it("only warns when every advisory is moderate or lower", async () => {
    const net = stubNet({
      querybatch: { results: [{ vulns: [{ id: "GHSA-low" }] }] },
      "vulns/GHSA-low": { id: "GHSA-low", database_specific: { severity: "LOW" }, summary: "meh" },
    });
    const r = await run(check, ctx({ "package.json": pkg({ x: "1.0.0" }) }, net));
    expect(r.status).toBe("warn");
  });

  it("passes cleanly when nothing is found", async () => {
    const net = stubNet({ querybatch: { results: [{}] } });
    const r = await run(check, ctx({ "package.json": pkg({ x: "1.0.0" }) }, net));
    expect(r.status).toBe("pass");
  });

  it("warns rather than passing when some ranges could not be checked", async () => {
    const net = stubNet({ querybatch: { results: [{}] } });
    const r = await run(check, ctx({ "package.json": pkg({ x: "1.0.0", y: "*" }) }, net));
    expect(r.status).toBe("warn");
    expect(r.detail).toMatch(/Not checked: y/);
  });

  // Our missing capability is not the artifact's problem.
  it("skips — never passes — when the run was granted no network", async () => {
    const r = await run(check, ctx({ "package.json": pkg({ lodash: "4.17.20" }) }));
    expect(r.status).toBe("skip");
  });

  it("is neutral for an artifact with no npm dependencies", async () => {
    const net = stubNet({});
    expect((await run(check, ctx({}, net))).status).toBe("neutral");
  });
});

describe("the constrained net client", () => {
  it("refuses a host that is not on the allowlist", async () => {
    const net = createNetClient();
    await expect(net.fetch("https://evil.example.com/x")).rejects.toThrow(NetAccessError);
  });

  it("refuses plaintext http", async () => {
    // Anything on the path could rewrite what a verdict is based on.
    const net = createNetClient({ allowedHosts: ["api.osv.dev"] });
    await expect(net.fetch("http://api.osv.dev/x")).rejects.toThrow(/Only https/);
  });

  it("refuses a malformed URL", async () => {
    await expect(createNetClient().fetch("not-a-url")).rejects.toThrow(/valid URL/);
  });

  it("allows a host the caller opted into", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("{}", { status: 200 }));
    const net = createNetClient({ allowedHosts: ["example.test"] });
    expect((await net.fetch("https://example.test/x")).status).toBe(200);
    spy.mockRestore();
  });

  it("records every request, so an external lookup is attributable", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("{}", { status: 200 }));
    const net = createNetClient({ allowedHosts: ["example.test"] });
    await net.fetch("https://example.test/a");
    expect(net.requests).toEqual([{ url: "https://example.test/a", method: "GET", status: 200 }]);
    spy.mockRestore();
  });

  // `redirect: "follow"` would let an allowed host bounce us anywhere.
  it("re-checks the allowlist on every redirect hop", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(null, { status: 302, headers: { location: "https://evil.example.com/x" } }),
      );
    const net = createNetClient({ allowedHosts: ["example.test"] });
    await expect(net.fetch("https://example.test/a")).rejects.toThrow(/not on the allowlist/);
    spy.mockRestore();
  });

  it("records a transport failure with its reason", async () => {
    const spy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ECONNREFUSED"));
    const net = createNetClient({ allowedHosts: ["example.test"] });
    await expect(net.fetch("https://example.test/a")).rejects.toThrow(/ECONNREFUSED/);
    expect(net.requests[0]).toMatchObject({ status: null, error: "ECONNREFUSED" });
    spy.mockRestore();
  });
});
