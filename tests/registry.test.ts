/**
 * Resolving an artifact through a MetaHub-compatible registry.
 *
 * Every test here runs offline against a stubbed `fetch`. The registry
 * is a network dependency, and a test suite that needs one is a test
 * suite that gets skipped.
 *
 * The behaviour worth protecting is the reason the feature exists at
 * all: the evaluation must be pinned to the commit the registry is
 * SERVING, not to whatever a branch points at today. Everything else
 * here is error handling.
 */
import { describe, expect, it } from "vitest";
import {
  DEFAULT_REGISTRY,
  gitCoordinatesFor,
  parseRegistrySpec,
  resolveRegistryArtifact,
  RegistryError,
  type RegistryArtifact,
} from "../src/sources/registry.js";
import { parseTarget } from "../src/target.js";

const ENTRY = {
  slug: "warden",
  kind: "skill",
  repoUrl: "https://github.com/getsentry/XcodeBuildMCP",
  repoBranch: "main",
  repoPath: ".agents/skills/warden",
  publishedSha: "c79f4eb9b7b96680d5a774acb0ae525416d254fb",
  version: "0.1.0",
  visibility: "public",
};

/** A fetch that answers only for the routes it is given. */
function stubFetch(routes: Record<string, { status?: number; body?: unknown; text?: string }>) {
  const calls: string[] = [];
  const impl = ((url: string) => {
    calls.push(url);
    const key = Object.keys(routes).find((k) => url.includes(k));
    const r = key ? routes[key]! : { status: 404 };
    const status = r.status ?? 200;
    return Promise.resolve({
      status,
      ok: status >= 200 && status < 300,
      json: () =>
        r.text !== undefined
          ? Promise.reject(new SyntaxError("not json"))
          : Promise.resolve(r.body),
    } as Response);
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("parsing a metahub: specifier", () => {
  it("takes a bare slug", () => {
    const s = parseRegistrySpec("metahub:warden");
    expect(s).toEqual({ slug: "warden", registry: DEFAULT_REGISTRY });
  });

  it("takes kind/slug", () => {
    const s = parseRegistrySpec("metahub:skill/warden");
    expect(s).toEqual({ slug: "warden", kind: "skill", registry: DEFAULT_REGISTRY });
  });

  it("accepts registry: as an alias, so the scheme is not vendor-locked", () => {
    expect(parseRegistrySpec("registry:mcp/thing").kind).toBe("mcp");
  });

  it("honours a self-hosted registry", () => {
    expect(parseRegistrySpec("metahub:warden", "https://reg.acme.dev").registry).toBe(
      "https://reg.acme.dev",
    );
  });

  it.each([
    ["metahub:", /No artifact named/],
    ["metahub:a/b/c", /Expected `metahub:<slug>`/],
    ["metahub:banana/x", /Unknown artifact kind "banana"/],
  ])("rejects %s", (raw, pattern) => {
    expect(() => parseRegistrySpec(raw)).toThrow(pattern);
  });
});

describe("metahub: reaches parseTarget as its own kind", () => {
  // Resolution needs the network, and `parseTarget` is synchronous and
  // pure — which is what lets the whole target grammar be unit-tested
  // without a server. So it parses here and resolves in `materialize`.
  it("parses without touching the network", () => {
    const t = parseTarget("metahub:skill/warden");
    expect(t.kind).toBe("registry");
    expect(t.location).toBe("warden");
    expect(t.registryKind).toBe("skill");
    expect(t.display).toBe("metahub:skill/warden");
  });

  it("a bare slug carries no kind", () => {
    expect(parseTarget("metahub:warden").registryKind).toBeUndefined();
  });

  it("does not shadow a local directory literally named metahub:x", () => {
    expect(parseTarget("./metahub:warden").kind).toBe("local");
  });
});

describe("resolving against a registry", () => {
  it("asks exactly once when the kind is known", async () => {
    const { impl, calls } = stubFetch({ "/skill/warden": { body: ENTRY } });
    const a = await resolveRegistryArtifact(
      { slug: "warden", kind: "skill", registry: DEFAULT_REGISTRY },
      impl,
    );
    expect(a.publishedSha).toBe(ENTRY.publishedSha);
    expect(calls).toHaveLength(1);
  });

  it("probes every kind concurrently when it is not", async () => {
    const { impl, calls } = stubFetch({ "/skill/warden": { body: ENTRY } });
    const a = await resolveRegistryArtifact({ slug: "warden", registry: DEFAULT_REGISTRY }, impl);
    expect(a.kind).toBe("skill");
    // Four probes, because the lookup endpoint is keyed by kind and
    // 404s on the wrong one. Concurrent, so it costs one round trip.
    expect(calls).toHaveLength(4);
  });

  it("accepts a response wrapped in { artifact }", async () => {
    const { impl } = stubFetch({ "/skill/warden": { body: { artifact: ENTRY } } });
    const a = await resolveRegistryArtifact(
      { slug: "warden", kind: "skill", registry: DEFAULT_REGISTRY },
      impl,
    );
    expect(a.repoUrl).toBe(ENTRY.repoUrl);
  });

  // The same slug can legitimately name a skill and a plugin. Picking
  // one would make the grade depend on our probe order.
  it("refuses to choose when a slug is ambiguous", async () => {
    const { impl } = stubFetch({
      "/skill/dual": { body: { ...ENTRY, slug: "dual", kind: "skill" } },
      "/plugin/dual": { body: { ...ENTRY, slug: "dual", kind: "plugin" } },
    });
    await expect(
      resolveRegistryArtifact({ slug: "dual", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/names 2 different artifacts[\s\S]*metahub:skill\/dual/);
  });

  it("says not-found, and where to search", async () => {
    const { impl } = stubFetch({});
    await expect(
      resolveRegistryArtifact({ slug: "nope", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/Nothing named "nope"[\s\S]*Search it:/);
  });

  it("names the kind when the kind was given", async () => {
    const { impl } = stubFetch({});
    await expect(
      resolveRegistryArtifact({ slug: "nope", kind: "mcp", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/No mcp named "nope"/);
  });

  // A transport failure is OUR problem. Reporting it as "not found"
  // would blame the user for our outage.
  it("distinguishes an unreachable registry from a missing artifact", async () => {
    const impl = (() => Promise.reject(new Error("ECONNREFUSED"))) as unknown as typeof fetch;
    await expect(
      resolveRegistryArtifact({ slug: "warden", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/Could not reach the registry[\s\S]*ECONNREFUSED/);
  });

  it("says so when the registry refuses us, rather than 'not found'", async () => {
    const { impl } = stubFetch({ "/skill/priv": { status: 403 } });
    await expect(
      resolveRegistryArtifact({ slug: "priv", kind: "skill", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/refused the request[\s\S]*Private and unlisted/);
  });

  // A Next.js site answers 200 with its SPA shell for an unknown route,
  // which is indistinguishable from a real endpoint until you parse it.
  it("detects an HTML page pretending to be an API", async () => {
    const { impl } = stubFetch({ "/skill/warden": { text: "<!DOCTYPE html>" } });
    await expect(
      resolveRegistryArtifact({ slug: "warden", kind: "skill", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/did not return JSON[\s\S]*MetaHub-compatible/);
  });

  it("refuses an entry that does not say where the artifact lives", async () => {
    const { impl } = stubFetch({ "/skill/warden": { body: { slug: "warden", kind: "skill" } } });
    await expect(
      resolveRegistryArtifact({ slug: "warden", kind: "skill", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toThrow(/does not say where the artifact lives/);
  });

  it("errors are RegistryError, so callers can tell them apart", async () => {
    const { impl } = stubFetch({});
    await expect(
      resolveRegistryArtifact({ slug: "nope", registry: DEFAULT_REGISTRY }, impl),
    ).rejects.toBeInstanceOf(RegistryError);
  });
});

describe("git coordinates — the whole point of resolving through a registry", () => {
  it("pins to the published sha, not the branch", () => {
    const g = gitCoordinatesFor(ENTRY as RegistryArtifact);
    expect(g.ref).toBe(ENTRY.publishedSha);
    expect(g.pinned).toBe(true);
    expect(g.subdir).toBe(".agents/skills/warden");
  });

  // Without this the tool grades whatever `main` is today, which is not
  // what anybody installed — the exact drift this feature exists to
  // close.
  it("prefers the sha even when a branch is also present", () => {
    const g = gitCoordinatesFor({ ...ENTRY, repoBranch: "main" } as RegistryArtifact);
    expect(g.ref).not.toBe("main");
  });

  it("falls back to the branch, and says it is not pinned", () => {
    const g = gitCoordinatesFor({ ...ENTRY, publishedSha: null } as RegistryArtifact);
    expect(g.ref).toBe("main");
    expect(g.pinned).toBe(false);
  });

  it("reports no ref at all rather than inventing one", () => {
    const g = gitCoordinatesFor({
      ...ENTRY,
      publishedSha: null,
      repoBranch: null,
    } as RegistryArtifact);
    expect(g.ref).toBeUndefined();
    expect(g.pinned).toBe(false);
  });

  it("handles a root-level artifact with no subdirectory", () => {
    const g = gitCoordinatesFor({ ...ENTRY, repoPath: null } as RegistryArtifact);
    expect(g.subdir).toBeUndefined();
  });

  it("normalises a leading ./ in repoPath", () => {
    const g = gitCoordinatesFor({ ...ENTRY, repoPath: "./src/thing" } as RegistryArtifact);
    expect(g.subdir).toBe("src/thing");
  });
});
