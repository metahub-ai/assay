/**
 * The starter checks, and the reference source they read through.
 *
 * Every check here is driven from a plain object literal — no network,
 * no fixtures directory, no GitHub. That is itself the design being
 * tested: if a check could only be exercised against a live repo, it
 * would be coupled to a transport and the framework would have failed
 * at the thing it exists for.
 */
import { describe, expect, it, vi } from "vitest";
import {
  CORE_CHECKS,
  depsNoKnownVulns,
  licensePresent,
  noSensitiveFiles,
  documentationPresent,
  recentlyMaintained,
} from "../src/checks/core";
import type { CheckContext, CheckDefinition } from "../src/check";
import { createBehavioralCheck } from "../src/checks/behavioral";
import { SandboxInfraError, type SandboxRunner } from "../src/ports";
import { fakeLlmProvider, makeFakeSandboxProvider } from "./fakes";
import { MemorySource } from "../src/sources/memory";

/** A `SandboxRunner` over the fake provider. */
function fakeRunner(): SandboxRunner {
  const provider = makeFakeSandboxProvider();
  return { name: provider.name, provision: (spec) => provider.create(spec ?? {}) };
}
import type { CheckResult, Subject } from "../src/types";

const subject: Subject = {
  kind: "skill",
  name: "demo",
  source: { type: "directory", path: "/tmp/demo" },
  digest: { sha256: "0".repeat(64) },
};

function ctxFor(
  files: Record<string, string>,
  config: Record<string, string | number | boolean> = {},
  extra: Partial<CheckContext> = {},
): CheckContext {
  const noop = () => {};
  return {
    subject,
    source: new MemorySource(files),
    config,
    log: { debug: noop, info: noop, warn: noop, error: noop },
    signal: new AbortController().signal,
    ...extra,
  };
}

const run = (check: CheckDefinition, ctx: CheckContext): Promise<CheckResult> =>
  Promise.resolve(check.run(ctx));

describe("no-sensitive-files", () => {
  it("passes a clean tree", async () => {
    const r = await run(noSensitiveFiles, ctxFor({ "index.js": "x", "README.md": "y" }));
    expect(r.status).toBe("pass");
  });

  it.each([
    [".env", "environment file"],
    ["config/.env.production", "environment file"],
    ["id_rsa", "SSH private key"],
    [".npmrc", "npm credentials file"],
    ["certs/server.pem", "private key or keystore"],
    ["service-account-prod.json", "service-account key"],
  ])("fails on %s", async (path) => {
    // Realistic contents. `.npmrc` and friends are judged on what is in
    // them, not only on the name, so the fixture has to carry an actual
    // credential for the blocking verdict to be the right one.
    const r = await run(
      noSensitiveFiles,
      ctxFor({ [path]: "//registry.npmjs.org/:_authToken=npm_" + "x".repeat(36) }),
    );
    expect(r.status).toBe("fail");
    expect(r.evidence).toContainEqual({ type: "file", path });
  });

  // The false positive this cost a real published plugin: a one-line
  // .npmrc reading `save-exact=true` was blocking, and took it from 90
  // to 44 FAIL with advice to rotate a credential that never existed.
  it("passes a .npmrc that holds configuration and no credential", async () => {
    const r = await run(
      noSensitiveFiles,
      ctxFor({ ".npmrc": "save-exact=true\nregistry=https://registry.npmjs.org/\n" }),
    );
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/none carrying a credential/);
  });

  it("still fails a .npmrc that holds a token", async () => {
    const r = await run(
      noSensitiveFiles,
      ctxFor({
        ".npmrc": "save-exact=true\n//registry.npmjs.org/:_authToken=npm_" + "x".repeat(36),
      }),
    );
    expect(r.status).toBe("fail");
  });

  it("treats an unreadable config-capable file as though it carried one", async () => {
    // Refusing to look is not evidence of safety, so a file we cannot
    // read keeps the blocking verdict rather than being excused by it.
    const unreadable = {
      listTree: () => Promise.resolve([{ path: ".npmrc", type: "file" as const }]),
      readFile: () => Promise.resolve(null),
      exists: () => Promise.resolve(true),
    };
    const r = await run(noSensitiveFiles, ctxFor({}, {}, { source: unreadable as never }));
    expect(r.status).toBe("fail");
  });

  it("allows .env.example — documentation, not a leak", async () => {
    const r = await run(noSensitiveFiles, ctxFor({ ".env.example": "API_KEY=" }));
    expect(r.status).toBe("pass");
  });

  // A report that quotes the secret it found has republished the secret.
  it("reports the path but NEVER the contents", async () => {
    const secret = "AWS_SECRET_ACCESS_KEY=hunter2";
    const r = await run(noSensitiveFiles, ctxFor({ ".env": secret }));
    expect(JSON.stringify(r)).not.toContain("hunter2");
  });

  it("gives an actionable remediation that mentions rotation", async () => {
    const r = await run(noSensitiveFiles, ctxFor({ ".env": "x" }));
    expect(r.remediation).toMatch(/rotate/i);
  });

  it("is blocking — this one should stop a publish", () => {
    expect(noSensitiveFiles.blocking).toBe(true);
  });
});

describe("license-present", () => {
  it.each(["LICENSE", "LICENSE.md", "license.txt", "License"])("accepts %s", async (path) => {
    const r = await run(licensePresent, ctxFor({ [path]: "MIT" }));
    expect(r.status).toBe("pass");
    expect(r.evidence).toContainEqual({ type: "file", path });
  });

  it("warns rather than fails when absent — it is a gap, not a defect", async () => {
    const r = await run(licensePresent, ctxFor({ "index.js": "x" }));
    expect(r.status).toBe("warn");
    expect(r.remediation).toBeTruthy();
  });
});

describe("documentation-present", () => {
  const words = (n: number) => "word ".repeat(n).trim();

  it("passes a substantive README", async () => {
    const r = await run(documentationPresent, ctxFor({ "SKILL.md": words(60) }));
    expect(r.status).toBe("pass");
    expect(r.summary).toMatch(/60 words/);
  });

  it("fails when there is no documentation at all", async () => {
    const r = await run(documentationPresent, ctxFor({ "index.js": "x" }));
    expect(r.status).toBe("fail");
  });

  it("warns on a thin README and grades it proportionally", async () => {
    const thin = await run(documentationPresent, ctxFor({ "SKILL.md": words(40) }));
    const thinner = await run(documentationPresent, ctxFor({ "SKILL.md": words(5) }));
    expect(thin.status).toBe("warn");
    expect(thinner.status).toBe("warn");
    // "40 words" and "5 words" are not the same problem.
    expect(thin.score!).toBeGreaterThan(thinner.score!);
  });

  it("honours a configured threshold", async () => {
    const body = { "SKILL.md": words(60) };
    expect((await run(documentationPresent, ctxFor(body, { docsMinWords: 100 }))).status).toBe(
      "warn",
    );
    expect((await run(documentationPresent, ctxFor(body, { docsMinWords: 10 }))).status).toBe(
      "pass",
    );
  });
});

describe("recently-maintained", () => {
  const NOW = Date.parse("2026-07-31T00:00:00.000Z");
  const daysAgo = (n: number) => NOW - n * 86_400_000;

  // The SourceRank/Scorecard mistake this check was rewritten to avoid.
  it("is weight 0 — reported, never scored", () => {
    expect(recentlyMaintained.weight).toBe(0);
  });

  it("never judges: a dormant artifact is neutral, not a failure", async () => {
    const r = await run(
      recentlyMaintained,
      ctxFor({}, { lastCommitMs: daysAgo(900) }, { now: () => NOW }),
    );
    expect(r.status).toBe("neutral");
    expect(r.summary).toMatch(/900 days ago/);
  });

  it("is neutral for fresh commits too — it grades nothing either way", async () => {
    const r = await run(
      recentlyMaintained,
      ctxFor({}, { lastCommitMs: daysAgo(3) }, { now: () => NOW }),
    );
    expect(r.status).toBe("neutral");
  });

  it("still emits the measurement as evidence", async () => {
    const r = await run(
      recentlyMaintained,
      ctxFor({}, { lastCommitMs: daysAgo(42) }, { now: () => NOW }),
    );
    expect(r.evidence).toContainEqual({
      type: "metric",
      name: "days_since_last_commit",
      value: 42,
      unit: "days",
    });
  });

  it("skips when the source reports no commit timestamp", async () => {
    const r = await run(recentlyMaintained, ctxFor({}, {}, { now: () => NOW }));
    expect(r.status).toBe("skip");
  });

  it("declares the clock capability, since its verdict moves without the artifact", () => {
    expect(recentlyMaintained.needs).toContain("clock");
  });
});

describe("deps-no-known-vulns", () => {
  const net = { fetch: async () => ({ status: 200, headers: {}, text: async () => "{}" }) };

  it("is NEUTRAL, not a pass, when there is no package.json to scan", async () => {
    // A Python MCP server has no npm deps. That is not a deficiency,
    // and it must not inflate coverage either.
    const r = await run(depsNoKnownVulns, ctxFor({}, {}, { net }));
    expect(r.status).toBe("neutral");
  });

  it("passes when no production dependencies are declared", async () => {
    const r = await run(depsNoKnownVulns, ctxFor({ "package.json": "{}" }, {}, { net }));
    expect(r.status).toBe("pass");
  });

  it("reports OUR failure as error when the manifest will not parse", async () => {
    const r = await run(depsNoKnownVulns, ctxFor({ "package.json": "{oops" }, {}, { net }));
    expect(r.status).toBe("error");
  });

  // The check is implemented now, so the guards that asserted it
  // reported `skip` have moved to tests/osv.test.ts, where the same
  // property is enforced against the real implementation: it must
  // never report a clean result for work it did not do. Specifically
  // it `skip`s without network, and `warn`s rather than passing when
  // some ranges could not be resolved to a concrete version.
  //
  // The original bug is worth remembering: it returned `pass` with
  // "Scanned N direct dependencies; no high or critical advisories"
  // and a fabricated OSV evidence URL, without ever calling ctx.net.
  it("still refuses to pass when it was granted no network", async () => {
    const pkg = JSON.stringify({ dependencies: { left: "^1.0.0" } });
    const r = await run(depsNoKnownVulns, ctxFor({ "package.json": pkg }));
    expect(r.status).toBe("skip");
    expect(r.status).not.toBe("pass");
  });
});

describe("behaves-as-documented (factory)", () => {
  it("declares the replayable tier and both capabilities it needs", () => {
    const check = createBehavioralCheck();
    expect(check.determinism).toBe("replayable");
    expect(check.needs).toEqual(expect.arrayContaining(["llm", "sandbox"]));
    expect(check.axis).toBe("behavior");
  });

  it("errors — not fails — when the behavioral capabilities are absent", async () => {
    const r = await run(createBehavioralCheck(), ctxFor({}));
    expect(r.status).toBe("error");
  });

  it("SKIPS when there is no documentation to check behavior against", async () => {
    // Judging anyway would grade the artifact against a standard we
    // invented for it.
    const r = await run(
      createBehavioralCheck(),
      ctxFor({}, {}, { llm: fakeLlmProvider, sandbox: fakeRunner() }),
    );
    expect(r.status).toBe("skip");
    expect(r.summary).toMatch(/no documented behavior/i);
  });

  it("runs for real and records a transcript digest per case", async () => {
    const r = await run(
      createBehavioralCheck({ probeCount: 0, caseCount: 2 }),
      ctxFor(
        { "SKILL.md": "# Formatter\nFormats text nicely." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(r.status).toBe("pass");
    const transcripts = (r.evidence ?? []).filter((e) => e.type === "transcript");
    expect(transcripts.length).toBeGreaterThan(0);
    for (const t of transcripts) {
      expect(t).toMatchObject({ sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    }
  });

  it("reports pass^k, not just pass@k — the honest reliability number", async () => {
    const r = await run(
      createBehavioralCheck({ probeCount: 0, caseCount: 2 }),
      ctxFor(
        { "SKILL.md": "# Formatter\nFormats text." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(r.samples?.passCaretK).toBeDefined();
    expect(r.samples!.passCaretK!).toBeLessThanOrEqual(r.samples!.passAtK!);
  });

  it("threads transcripts to a sink and cites the returned URI", async () => {
    const put = vi.fn(async (digest: string) => `https://store.example/${digest}`);
    const r = await run(
      createBehavioralCheck({ probeCount: 0, caseCount: 1, transcripts: { put } }),
      ctxFor(
        { "SKILL.md": "# Formatter\nFormats text." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(put).toHaveBeenCalled();
    const t = (r.evidence ?? []).find((e) => e.type === "transcript");
    expect(t && "uri" in t ? t.uri : null).toMatch(/^https:\/\/store\.example\//);
  });

  it("fails and explains when documented behavior is not reproduced", async () => {
    // The fake judge returns a failing verdict when it sees this marker.
    const r = await run(
      createBehavioralCheck({ probeCount: 0, caseCount: 2 }),
      ctxFor(
        { "SKILL.md": "# Skill\nforce-fail-verdict" },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(r.status).toBe("warn");
    expect(r.detail).toMatch(/did not satisfy/i);
    expect(r.remediation).toBeTruthy();
  });

  it("cites the behavioral score as a metric", async () => {
    const r = await run(
      createBehavioralCheck({ probeCount: 0, caseCount: 1 }),
      ctxFor(
        { "SKILL.md": "# Skill\nDoes a thing." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(r.evidence).toContainEqual(
      expect.objectContaining({ type: "metric", name: "behavioral_score" }),
    );
    expect(r.score).toBeGreaterThan(0);
  });

  it("reports adversarial resilience separately from the verdict", async () => {
    const r = await run(
      createBehavioralCheck({ probeCount: 3, caseCount: 1 }),
      ctxFor(
        { "SKILL.md": "# Skill\nDoes a thing." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(r.evidence).toContainEqual(expect.objectContaining({ name: "adversarial_resisted" }));
  });

  it("survives a transcript sink that throws, rather than losing the whole verdict", async () => {
    const r = await run(
      createBehavioralCheck({
        probeCount: 0,
        caseCount: 1,
        transcripts: {
          put: async () => {
            throw new Error("storage down");
          },
        },
      }),
      ctxFor(
        { "SKILL.md": "# Skill\nDoes a thing." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: fakeRunner(),
        },
      ),
    );
    expect(r.status).toBe("pass");
    // Digest still recorded; only the fetchable URI is missing.
    const t = (r.evidence ?? []).find((e) => e.type === "transcript");
    expect(t && "sha256" in t ? t.sha256 : null).toMatch(/^[0-9a-f]{64}$/);
  });

  it("records OUR sandbox dying as error, never as a failing verdict", async () => {
    const dying = {
      name: "dying",
      provision: async () => {
        throw new SandboxInfraError("sandbox killed");
      },
    };
    const r = await run(
      createBehavioralCheck({ probeCount: 0, caseCount: 1 }),
      ctxFor(
        { "SKILL.md": "# Formatter\nFormats text." },
        {},
        {
          llm: fakeLlmProvider,
          sandbox: dying as never,
        },
      ),
    );
    expect(r.status).toBe("error");
    expect(r.status).not.toBe("fail");
    expect(r.detail).toMatch(/not a defect in the artifact/i);
  });
});

describe("the starter suite", () => {
  it("exports every check exactly once", () => {
    const ids = CORE_CHECKS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every check a published spec URL — an undocumented check is unappealable", () => {
    for (const c of CORE_CHECKS) expect(c.spec, `${c.id} has no spec`).toBeTruthy();
  });

  // Documents a KNOWN GAP rather than asserting a virtue: the starter
  // suite has no `integrity` check at all, so that axis reports zero
  // coverage on every run. Recorded here and in the coverage-gap
  // document; the manifest/structural checks that fill it arrive with
  // the port of the static engine.
  it("covers only two axes today — integrity is unimplemented, behavior is a factory", () => {
    // `behaves-as-documented` is not in CORE_CHECKS because it needs
    // host wiring; see createBehavioralCheck.
    expect(new Set(CORE_CHECKS.map((c) => c.axis))).toEqual(new Set(["safety", "care"]));
  });

  it("deliberately omits slug-unique — that is a registry concern", () => {
    expect(CORE_CHECKS.map((c) => c.id)).not.toContain("slug-unique");
  });
});

describe("MemorySource", () => {
  it("synthesizes parent directories, as a real filesystem would", async () => {
    const tree = await new MemorySource({ "a/b/c.txt": "x" }).listTree();
    expect(tree.map((e) => e.path)).toEqual(["a", "a/b", "a/b/c.txt"]);
    expect(tree.find((e) => e.path === "a")!.type).toBe("dir");
  });

  it("reports byte size, not character count", async () => {
    const tree = await new MemorySource({ "é.txt": "é" }).listTree();
    expect(tree.find((e) => e.path === "é.txt")!.size).toBe(2);
  });

  it("returns null for a missing file rather than throwing", async () => {
    expect(await new MemorySource({}).readFile("nope.txt")).toBeNull();
    expect(await new MemorySource({}).readBytes("nope.txt")).toBeNull();
  });

  it("answers exists without reading", async () => {
    const s = new MemorySource({ "a.txt": "x" });
    expect(await s.exists("a.txt")).toBe(true);
    expect(await s.exists("b.txt")).toBe(false);
  });

  it("orders the tree deterministically", async () => {
    const a = await new MemorySource({ "z.txt": "1", "a.txt": "2" }).listTree();
    expect(a.map((e) => e.path)).toEqual(["a.txt", "z.txt"]);
  });
});
