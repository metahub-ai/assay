/**
 * The synthesized-case cache.
 *
 * The `CaseCache` port existed from the start and nothing ever passed
 * an implementation, so every run synthesized fresh test cases. Two runs
 * of one artifact were graded on different exams — which moved the
 * behavioral score and, worse, made `assay diff` meaningless for the
 * behavior axis, since comparing two reports cannot answer "did this
 * get worse" when the two runs asked different questions.
 *
 * Keying on the artifact digest gives both properties at once: the same
 * bytes always face the same questions, and any edit invalidates the
 * entry automatically.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readdirSync, rmSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { caseCacheSize, clearCaseCache, createCaseCache } from "../src/case-cache";
import type { EvalTestCase } from "../src/behavioral/types";

let dir: string;
const CASES: EvalTestCase[] = [
  { id: "c1", prompt: "Extract the text from invoice.pdf", expect: "the text is returned" },
  { id: "c2", prompt: "Merge two PDFs", expect: "one merged file" },
];
const KEY = "a".repeat(64);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "assay-cc-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Entry filenames are the sha256 of the key; mirror that here. */
const entryFor = (key: string) =>
  join(dir, `${createHash("sha256").update(key).digest("hex")}.json`);

describe("round trip", () => {
  it("returns the cases it stored", async () => {
    const cache = createCaseCache({ dir });
    await cache.set(KEY, CASES);
    expect(await cache.get(KEY)).toEqual(CASES);
  });

  it("misses on a different artifact digest", async () => {
    const cache = createCaseCache({ dir });
    await cache.set(KEY, CASES);
    // A changed artifact deserves new questions, and gets them for free.
    expect(await cache.get("b".repeat(64))).toBeNull();
  });

  it("misses when nothing was ever stored", async () => {
    expect(await createCaseCache({ dir }).get(KEY)).toBeNull();
  });

  it("can be disabled, for --no-cache", async () => {
    const cache = createCaseCache({ dir, enabled: false });
    await cache.set(KEY, CASES);
    expect(await cache.get(KEY)).toBeNull();
  });

  it("stores cases as readable JSON a publisher can inspect", async () => {
    await createCaseCache({ dir }).set(KEY, CASES);
    const body = readFileSync(join(dir, readdirSync(dir)[0]!), "utf8");
    expect(body).toContain("Extract the text from invoice.pdf");
    expect(body.split("\n").length).toBeGreaterThan(3);
  });

  it("keeps the cache directory owner-only", async () => {
    await createCaseCache({ dir: join(dir, "nested") }).set(KEY, CASES);
    expect(statSync(join(dir, "nested")).mode & 0o077).toBe(0);
  });
});

/**
 * A broken cache must never stop an evaluation. The worst it can cost is
 * the price of re-synthesizing.
 */
describe("degradation", () => {
  it("treats a corrupt entry as a miss", async () => {
    writeFileSync(entryFor(KEY), "{ not json");
    expect(await createCaseCache({ dir }).get(KEY)).toBeNull();
  });

  it("ignores an entry from an older cache version", async () => {
    writeFileSync(
      entryFor(KEY),
      JSON.stringify({ version: 0, key: KEY, writtenAt: new Date().toISOString(), cases: CASES }),
    );
    expect(await createCaseCache({ dir }).get(KEY)).toBeNull();
  });

  it("ignores a stale entry", async () => {
    const old = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
    writeFileSync(
      entryFor(KEY),
      JSON.stringify({ version: 1, key: KEY, writtenAt: old, cases: CASES }),
    );
    expect(await createCaseCache({ dir }).get(KEY)).toBeNull();
  });

  // A NaN age must not compare as fresh.
  it("ignores an entry with an unparseable timestamp", async () => {
    writeFileSync(
      entryFor(KEY),
      JSON.stringify({ version: 1, key: KEY, writtenAt: "not-a-date", cases: CASES }),
    );
    expect(await createCaseCache({ dir }).get(KEY)).toBeNull();
  });

  it("treats an empty case list as a miss rather than caching nothing", async () => {
    const cache = createCaseCache({ dir });
    await cache.set(KEY, []);
    expect(await cache.get(KEY)).toBeNull();
  });

  // A path UNDER a regular file: ENOTDIR immediately, on every platform.
  // The first version used `/proc/nonexistent/nope`, which does not
  // exist on macOS and so failed fast locally, while on Linux `/proc`
  // is real and the call hung until the test timed out — green here,
  // red in CI on both Node versions.
  it("does not throw when the directory cannot be written", async () => {
    const blocker = join(dir, "not-a-directory");
    writeFileSync(blocker, "x");
    const cache = createCaseCache({ dir: join(blocker, "nested") });
    await expect(cache.set(KEY, CASES)).resolves.toBeUndefined();
    expect(await cache.get(KEY)).toBeNull();
  });
});

describe("management", () => {
  it("counts and clears entries", async () => {
    const cache = createCaseCache({ dir });
    await cache.set(KEY, CASES);
    await cache.set("c".repeat(64), CASES);
    expect(await caseCacheSize(dir)).toBe(2);
    expect(await clearCaseCache(dir)).toBe(2);
    expect(await caseCacheSize(dir)).toBe(0);
  });

  it("reports zero for a directory that does not exist", async () => {
    expect(await caseCacheSize(join(dir, "nope"))).toBe(0);
    expect(await clearCaseCache(join(dir, "nope"))).toBe(0);
  });

  // The key reaches a filesystem path, so it is sanitized rather than
  // trusted even though it is a digest.
  it("cannot be made to escape its directory by a hostile key", async () => {
    const cache = createCaseCache({ dir });
    await cache.set("../../etc/passwd", CASES);
    expect(await caseCacheSize(dir)).toBeLessThanOrEqual(1);
    expect(await cache.get("../../etc/passwd")).not.toBeNull();
  });
});

/**
 * The cache key must cover everything that changes the case set.
 *
 * Keying on the artifact digest alone meant `--cases 5` silently reused
 * a cached set of 2 and ignored the flag — observed live: a run asking
 * for 3 cases produced 6 samples instead of 9.
 */
describe("cache key coverage", () => {
  it("separates entries by requested case count", async () => {
    const cache = createCaseCache({ dir });
    const digest = "d".repeat(64);
    await cache.set(`${digest}-c2-pd`, CASES);
    expect(await cache.get(`${digest}-c5-pd`)).toBeNull();
    expect(await cache.get(`${digest}-c2-pd`)).toEqual(CASES);
  });
});
