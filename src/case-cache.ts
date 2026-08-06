/**
 * On-disk cache of synthesized behavioral test cases.
 *
 * The `CaseCache` port has existed since the engine was written and
 * nothing ever passed one, so every run synthesized a fresh set of test
 * cases from the artifact's documentation. Two runs of the same
 * artifact therefore tested **different things**, which had two bad
 * consequences.
 *
 * The obvious one: the behavioral score moved. The PDF skill from
 * `anthropics/skills` scored 76 on one run and 41 on the next, with no
 * change to the artifact. Some of that came from elsewhere (see
 * `scoreResults`), but a large part was simply that run two asked
 * harder questions than run one.
 *
 * The subtle one is worse: it made `assay diff` meaningless for the
 * behavior axis. Comparing two reports is supposed to answer "did this
 * artifact get worse", and it cannot if the two runs were graded on
 * different exams.
 *
 * Keyed by the artifact digest, so:
 *   - the same bytes always face the same questions, and
 *   - any change to the artifact invalidates the cache automatically,
 *     which is exactly right — new content deserves new questions.
 *
 * Cases are stored as plain readable JSON on purpose. A publisher who
 * wants to see what they were tested on should be able to open the file,
 * and one who disagrees can edit it or commit it as an eval file.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { configDir } from "./credentials.js";
import type { EvalTestCase } from "./behavioral/types.js";
import type { CaseCache } from "./behavioral/run.js";

/** Bumped when the synthesized-case shape or prompt changes materially. */
const CACHE_VERSION = 1;

/** Entries older than this are re-synthesized. */
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

interface CacheFile {
  version: number;
  key: string;
  writtenAt: string;
  cases: EvalTestCase[];
}

export function caseCacheDir(env: NodeJS.ProcessEnv = process.env): string {
  return env["ASSAY_CASE_CACHE"] ?? join(configDir(env), "cases");
}

/**
 * A cache that persists under `~/.assay/cases`.
 *
 * Every failure path degrades to "no cached cases" rather than throwing.
 * A broken cache must never be able to stop an evaluation — the worst it
 * should cost is the price of re-synthesizing.
 */
export function createCaseCache(opts: { dir?: string; enabled?: boolean } = {}): CaseCache {
  const dir = opts.dir ?? caseCacheDir();
  const enabled = opts.enabled ?? true;

  return {
    async get(key: string): Promise<EvalTestCase[] | null> {
      if (!enabled) return null;
      try {
        const raw = await readFile(entryPath(dir, key), "utf8");
        const parsed = JSON.parse(raw) as CacheFile;
        if (parsed.version !== CACHE_VERSION) return null;
        const age = Date.now() - new Date(parsed.writtenAt).getTime();
        // A NaN age (corrupt timestamp) must not read as "fresh".
        if (!(age >= 0) || age > MAX_AGE_MS) return null;
        return Array.isArray(parsed.cases) && parsed.cases.length > 0 ? parsed.cases : null;
      } catch {
        return null;
      }
    },

    async set(key: string, cases: EvalTestCase[]): Promise<void> {
      if (!enabled || cases.length === 0) return;
      try {
        await mkdir(dir, { recursive: true, mode: 0o700 });
        const body: CacheFile = {
          version: CACHE_VERSION,
          key,
          writtenAt: new Date().toISOString(),
          cases,
        };
        await writeFile(entryPath(dir, key), `${JSON.stringify(body, null, 2)}\n`, "utf8");
      } catch {
        /* caching is an optimisation; never fail a run over it */
      }
    },
  };
}

function entryPath(dir: string, key: string): string {
  // Hashed rather than sanitized. Stripping non-hex characters looked
  // safe and silently collapsed distinct keys onto one file — the
  // digest+caseCount keys `…-c2-pd` and `…-c5-pd` both reduced to the
  // bare digest, so asking for more cases returned the cached smaller
  // set. Hashing is injective enough and cannot escape the directory.
  return join(dir, `${createHash("sha256").update(key).digest("hex")}.json`);
}

/** Remove every cached case set. Returns how many entries were dropped. */
export async function clearCaseCache(dir = caseCacheDir()): Promise<number> {
  try {
    const entries = await readdir(dir);
    let removed = 0;
    for (const name of entries.filter((n) => n.endsWith(".json"))) {
      await unlink(join(dir, name)).then(
        () => removed++,
        () => {},
      );
    }
    return removed;
  } catch {
    return 0;
  }
}

/** How many case sets are cached, for `assay doctor`. */
export async function caseCacheSize(dir = caseCacheDir()): Promise<number> {
  try {
    const entries = await readdir(dir);
    let n = 0;
    for (const name of entries.filter((e) => e.endsWith(".json"))) {
      const info = await stat(join(dir, name)).catch(() => null);
      if (info?.isFile()) n++;
    }
    return n;
  } catch {
    return 0;
  }
}
