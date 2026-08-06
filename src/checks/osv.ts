/**
 * Known-vulnerability lookup against OSV.dev.
 *
 * OSV rather than NVD, deliberately. NVD describes affected software
 * with CPE strings — a vendor/product taxonomy invented for enterprise
 * inventory, with no canonical mapping to an npm or PyPI name — so
 * "is my installed version affected?" comes back as yes/no/maybe.
 * OSV uses ecosystem-native identity and computable version ranges, and
 * publishes evaluation semantics, so the same question has an answer.
 *
 * It also matters that NVD is no longer a reliable enrichment source:
 * independent analyst scoring fell from ~85% of records in 2023 to
 * ~14% by 2026, and NIST stated in April 2026 that it will no longer
 * routinely provide a severity score when a CNA already supplied one.
 * Building on it today would be building on a receding surface.
 */
import type { NetClient } from "../ports.js";

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns";

export type Severity = "critical" | "high" | "moderate" | "low" | "unknown";

export interface Advisory {
  id: string;
  package: string;
  installed: string;
  severity: Severity;
  summary: string;
  /** Fixed version, when the advisory names one. */
  fixed?: string;
}

/**
 * Pull a concrete version out of a range spec.
 *
 * A range is what a manifest declares; a version is what OSV needs.
 * Taking the LOWER bound is the honest choice: `^1.2.3` resolves to
 * something ≥1.2.3, and querying the floor reports advisories that may
 * already be fixed in the installed tree — a false positive a reader
 * can dismiss. Querying an assumed-latest would do the opposite and
 * miss real ones, which is the error that matters.
 */
export function concreteVersion(spec: string): string | null {
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/.exec(spec);
  return m ? m[1]! : null;
}

interface OsvBatchResponse {
  results?: { vulns?: { id: string; modified?: string }[] }[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
}

export interface ScanResult {
  advisories: Advisory[];
  /** Packages we asked about, for an honest denominator. */
  queried: number;
  /** Packages whose declared range yielded no concrete version. */
  unresolvable: string[];
}

/**
 * Query OSV for a dependency map.
 *
 * Batched into one request rather than N: OSV rate-limits, and a
 * hundred serial round trips would make the check slow enough that
 * people disable it.
 */
export async function scanDependencies(
  net: NetClient,
  deps: Record<string, string>,
  ecosystem = "npm",
): Promise<ScanResult> {
  const names = Object.keys(deps);
  const queries: { name: string; version: string }[] = [];
  const unresolvable: string[] = [];

  for (const name of names) {
    const version = concreteVersion(deps[name] ?? "");
    if (version) queries.push({ name, version });
    else unresolvable.push(name);
  }
  if (queries.length === 0) {
    return { advisories: [], queried: 0, unresolvable };
  }

  const res = await net.fetch(OSV_BATCH, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      queries: queries.map((q) => ({
        package: { name: q.name, ecosystem },
        version: q.version,
      })),
    }),
  });
  if (res.status !== 200) {
    throw new Error(`OSV batch query failed with HTTP ${res.status}`);
  }

  const batch = JSON.parse(await res.text()) as OsvBatchResponse;
  const hits: { id: string; query: { name: string; version: string } }[] = [];
  // The batch response is positional — result[i] corresponds to
  // queries[i] — and carries only ids, so severity needs a second pass.
  (batch.results ?? []).forEach((result, i) => {
    const query = queries[i];
    if (!query) return;
    for (const v of result.vulns ?? []) hits.push({ id: v.id, query });
  });

  const advisories: Advisory[] = [];
  // Deduped: one advisory can match several versions of a package.
  const seen = new Set<string>();
  for (const hit of hits) {
    const key = `${hit.id}:${hit.query.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const detail = await fetchVuln(net, hit.id);
    advisories.push({
      id: hit.id,
      package: hit.query.name,
      installed: hit.query.version,
      severity: detail ? severityOf(detail) : "unknown",
      summary: detail?.summary ?? detail?.details?.slice(0, 160) ?? "(no summary published)",
      ...(detail ? pickFixed(detail, hit.query.name) : {}),
    });
  }

  return { advisories, queried: queries.length, unresolvable };
}

async function fetchVuln(net: NetClient, id: string): Promise<OsvVuln | null> {
  try {
    const res = await net.fetch(`${OSV_VULN}/${encodeURIComponent(id)}`);
    if (res.status !== 200) return null;
    return JSON.parse(await res.text()) as OsvVuln;
  } catch {
    // A detail lookup failing degrades that advisory to `unknown`
    // severity rather than dropping it. Losing a real advisory because
    // one HTTP call failed would be the worse error.
    return null;
  }
}

/**
 * Map an advisory to a severity band.
 *
 * Prefers the GHSA database-specific label when present because it is
 * a curated judgement, then falls back to parsing a CVSS vector. The
 * vector is authoritative but only tells us a number; the label tells
 * us what the people who reviewed it concluded.
 */
export function severityOf(vuln: OsvVuln): Severity {
  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label === "critical" || label === "high" || label === "moderate" || label === "low") {
    return label;
  }
  const vector = vuln.severity?.find((s) => s.type?.startsWith("CVSS"))?.score;
  if (vector) {
    const score = cvssBaseScore(vector);
    if (score !== null) {
      if (score >= 9) return "critical";
      if (score >= 7) return "high";
      if (score >= 4) return "moderate";
      return "low";
    }
  }
  return "unknown";
}

/**
 * Read a numeric base score out of a CVSS string.
 *
 * OSV sometimes carries a bare number and sometimes a full vector. We
 * do NOT recompute a score from vector metrics here — that is a real
 * algorithm with real edge cases, and getting it subtly wrong would
 * mean publishing a severity nobody can reproduce. An unparseable
 * vector becomes `unknown`, which is honest.
 */
export function cvssBaseScore(score: string): number | null {
  const bare = /^(\d+(?:\.\d+)?)$/.exec(score.trim());
  if (bare) return Number(bare[1]);
  return null;
}

function pickFixed(vuln: OsvVuln, pkg: string): { fixed?: string } {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name !== pkg) continue;
    for (const range of affected.ranges ?? []) {
      const fixed = range.events?.find((e) => e.fixed)?.fixed;
      if (fixed) return { fixed };
    }
  }
  return {};
}

/** Bands that should block a publish. */
export const BLOCKING_SEVERITIES: ReadonlySet<Severity> = new Set(["critical", "high"]);
