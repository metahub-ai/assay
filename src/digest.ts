/**
 * Content addressing.
 *
 * Everything reproducible in this framework rests on being able to say
 * "this report is about THESE bytes". Naming a repo and a branch is not
 * enough — branches move, tags get re-pointed, and an artifact can be
 * swapped after it earns a good score (the rug-pull that package
 * registries keep re-learning). A digest makes the subject immutable
 * and makes caching provably correct rather than heuristic.
 *
 * The tree digest is a sorted Merkle-style fold over (path, sha256)
 * pairs. Deliberately transport-independent: a git checkout, an
 * extracted tarball, and a local directory holding identical content
 * all produce the same digest, so a publisher's local `assay run` and
 * the hosted evaluation agree on what they looked at.
 */
import { createHash } from "node:crypto";
import type { SourceReader } from "./ports.js";
import type { RunEnvironment } from "./types.js";

const sha256 = (input: string | Uint8Array): string =>
  createHash("sha256").update(input).digest("hex");

/**
 * Files excluded from the subject digest.
 *
 * These are developer-local or transport-injected artifacts whose
 * presence would make the same logical content hash differently
 * depending on how it was fetched. `.git` in particular differs
 * between a shallow clone and a full one.
 */
const DIGEST_EXCLUDES = [/^\.git\//, /^node_modules\//, /(^|\/)\.DS_Store$/, /^\.assay-cache\//];

function excluded(path: string): boolean {
  return DIGEST_EXCLUDES.some((re) => re.test(path));
}

/**
 * Merkle digest over an artifact's file tree.
 *
 * Sorting by path before folding is what makes this stable — a
 * filesystem's enumeration order is not a property of the content.
 */
/** sha256 of a file read incrementally, or null when unavailable. */
async function streamDigest(source: SourceReader, path: string): Promise<string | null> {
  try {
    const rs = await source.stream!(path);
    if (!rs) return null;
    const h = createHash("sha256");
    for await (const chunk of rs as AsyncIterable<Buffer | string>) h.update(chunk);
    return h.digest("hex");
  } catch {
    return null;
  }
}

export async function digestTree(source: SourceReader): Promise<string> {
  const tree = await source.listTree();
  const files = tree
    .filter((e) => e.type === "file" && !excluded(e.path))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  // Symlinks are part of the artifact and were not part of its digest.
  //
  // The filter was `type === "file"`, so adding, removing or repointing
  // a symlink changed nothing: a tree and the same tree plus
  // `creds -> /Users/you/.aws/credentials` produced one sha256. That
  // defeats `assay verify --artifact`, which certifies a directory as
  // matching a report, and `diff`'s "same artifact digest — any change
  // below is from Assay, not the artifact", which is a claim about the
  // whole tree.
  //
  // The target is hashed as written and never resolved: resolving would
  // make the digest depend on the host filesystem.
  const links = tree
    .filter((e) => e.type === "symlink" && !excluded(e.path))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const h = createHash("sha256");
  // v2: symlinks and the executable bit are now covered. A digest is a
  // claim about a tree, and the version prefix is what stops a v1
  // digest being compared against a v2 one and read as a modification.
  h.update(`assay-tree-v2\n${files.length}\n${links.length}\n`);
  for (const l of links) {
    h.update(`${l.path}\0symlink\0${l.target ?? ""}\n`);
  }
  for (const f of files) {
    const bytes = source.readBytes
      ? await source.readBytes(f.path)
      : await source.readFile(f.path).then((t) => (t == null ? null : Buffer.from(t, "utf8")));

    // A file listed but unreadable is recorded as such rather than
    // skipped — silently dropping it would let an unreadable file
    // change content without changing the digest.
    //
    // But "unreadable" is a CONSTANT, and substituting a constant has
    // exactly the effect the line above exists to prevent: every file
    // over the size ceiling hashed the same, so two artifacts differing
    // only in a 3 MB bundle produced one digest. Bundled and minified
    // artifacts routinely exceed the ceiling, so this was not a corner.
    // Stream it before giving up.
    let mark: string;
    if (bytes) {
      mark = sha256(bytes);
    } else {
      const streamed = source.stream ? await streamDigest(source, f.path) : null;
      // Only genuinely unreadable now — and the size is folded in so
      // two different unreadable files still differ.
      mark = streamed ?? `unreadable:${f.size ?? "?"}`;
    }
    // The executable bit is content.
    //
    // Two byte-identical copies of an `install.sh` containing `rm -rf /`
    // — one mode 644, one 755 — digested the same. Whether a script can
    // be executed is exactly the kind of change an integrity digest is
    // supposed to notice. Only this bit is folded in; a full POSIX mode
    // is not preserved by the transports an artifact travels through,
    // and hashing it would make the digest depend on how it was fetched.
    h.update(`${f.path}\0${mark}\0${f.executable ? "x" : "-"}\n`);
  }
  return h.digest("hex");
}

/**
 * Digest over the set of checks in a suite.
 *
 * Detects a suite whose composition changed without a version bump —
 * the failure mode that would quietly invalidate every historical
 * comparison.
 */
export function digestSuite(checks: readonly { id: string; version: string }[]): string {
  const canonical = [...checks]
    .map((c) => `${c.id}@${c.version}`)
    .sort()
    .join("\n");
  return sha256(`assay-suite-v1\n${canonical}`);
}

/**
 * Digest over the run environment.
 *
 * Part of the cache key: the same artifact judged by a different model
 * is a different computation and must not hit a cached result. This is
 * the bug that makes naive eval caches silently serve stale grades
 * after a model swap.
 */
export function digestEnvironment(env: RunEnvironment): string {
  const canonical = JSON.stringify({
    runner: env.runner,
    sandbox: env.sandbox ?? null,
    models: env.models ? sortKeys(env.models as Record<string, unknown>) : null,
    config: env.config ? sortKeys(env.config as Record<string, unknown>) : null,
  });
  return sha256(`assay-env-v1\n${canonical}`);
}

/**
 * Cache key for a single check result.
 *
 * Deterministic checks ignore the environment — that is the whole
 * point of the tier, and it means the large majority of checks cache
 * across model swaps and infrastructure changes.
 */
export function checkCacheKey(args: {
  subjectDigest: string;
  checkId: string;
  checkVersion: string;
  determinism: string;
  environmentDigest: string;
}): string {
  const envPart = args.determinism === "deterministic" ? "pure" : args.environmentDigest;
  return sha256(
    `assay-check-v1\n${args.subjectDigest}\n${args.checkId}@${args.checkVersion}\n${envPart}`,
  );
}

/**
 * Pre-Authentication Encoding, from DSSE.
 *
 *   "DSSEv1" ‖ SP ‖ LEN(type) ‖ SP ‖ type ‖ SP ‖ LEN(body) ‖ SP ‖ body
 *
 * Signing the payload TYPE alongside the payload is what makes
 * cross-type replay cryptographically impossible — a signature over an
 * Assay report can never be reinterpreted as a signature over some
 * other document. The length prefixes make the encoding unambiguous
 * without requiring canonical JSON at all: you sign the exact bytes you
 * transmit, which sidesteps every canonicalization-mismatch bug that
 * has historically plagued JWS.
 */
export function pae(payloadType: string, payload: string): Buffer {
  return Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${Buffer.byteLength(payload, "utf8")} ${payload}`,
    "utf8",
  );
}

/**
 * The exact bytes to sign for a report.
 *
 * Everything is covered EXCEPT `attestation` itself — a signature
 * cannot sign itself. In particular `startedAt`, `finishedAt` and
 * `validity` ARE signed.
 *
 * That is load-bearing and was wrong in the first draft of this file,
 * which stripped the timestamps on the reasoning that "two honest runs
 * of the same computation should produce the same bytes to sign."
 * That is a CACHE-KEY property, not a signing property, and adopting it
 * here left `finishedAt` unauthenticated — so an old report could be
 * restamped as fresh and still verify, defeating the entire staleness
 * defense that `Validity` exists to provide. Two runs at different
 * times are different attestations and must sign differently.
 */
export function canonicalizeForSigning(report: unknown): string {
  return JSON.stringify(sortDeep(report, SIGNING_EXCLUDED));
}

/** Only the signature envelope is outside its own coverage. */
const SIGNING_EXCLUDED = new Set(["attestation"]);

/**
 * Canonical form for COMPARING two reports — diffing runs, deciding
 * cache equivalence, detecting whether a re-run actually changed
 * anything.
 *
 * Here dropping wall-clock and timing noise is correct, because the
 * question is "is this the same computation?" rather than "who
 * attested to this, and when?" Keeping the two functions separate is
 * the fix for the bug described above.
 */
export function canonicalizeForComparison(report: unknown): string {
  return JSON.stringify(sortDeep(report, COMPARISON_EXCLUDED));
}

const COMPARISON_EXCLUDED = new Set([
  "attestation",
  "durationMs",
  "startedAt",
  "finishedAt",
  "validity",
]);

function sortDeep(value: unknown, exclude: ReadonlySet<string>): unknown {
  if (Array.isArray(value)) return value.map((v) => sortDeep(v, exclude));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      if (exclude.has(k)) continue;
      out[k] = sortDeep((value as Record<string, unknown>)[k], exclude);
    }
    return out;
  }
  return value;
}

function sortKeys(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) out[k] = obj[k];
  return out;
}
