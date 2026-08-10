/**
 * Output formats and report diffing.
 *
 * SARIF exists because it is how a tool like this actually reaches
 * developers. GitHub code scanning ingests SARIF natively, which turns
 * `assay run` from something a person has to remember to invoke into
 * inline annotations on a pull request. The competitive research was
 * blunt about this: adoption of trust tooling tracks how little effort
 * it takes, not how good the analysis is.
 *
 * `diffReports` exists because CI asks a different question than a
 * publisher does. A publisher wants "how good is this?"; CI wants "did
 * this change make it worse?" A framework that only answers the first
 * forces every project to pick an absolute threshold on day one, which
 * is exactly the choice that makes teams turn a tool off.
 */
import { diffSurfaces, surfaceOf, type SurfaceDiff } from "./surface.js";
import type { AssayReport, CheckReport, CheckStatus } from "./types.js";
import { ASSAY_HOME } from "./version.js";

// ── SARIF ────────────────────────────────────────────────────────────

/** SARIF severity. `note` is the floor; SARIF has no "informational". */
type SarifLevel = "error" | "warning" | "note" | "none";

function sarifLevel(status: CheckStatus, blocking: boolean | undefined): SarifLevel {
  switch (status) {
    case "fail":
      return blocking ? "error" : "warning";
    case "warn":
      return "warning";
    // `error` is OUR failure, not the artifact's. Reporting it as a
    // SARIF error would put a red mark on someone's pull request for
    // our outage, so it is a note.
    case "error":
      return "note";
    default:
      return "none";
  }
}

/**
 * Render a report as SARIF 2.1.0.
 *
 * Only judging statuses become results. Emitting a SARIF entry for
 * every `pass` would bury the findings that matter under hundreds of
 * green rows, which is how code-scanning integrations get muted.
 */
/**
 * Weight → CVSS-shaped score, for GitHub's severity buckets.
 *
 * 9.0 critical · 7.0 high · 4.0 medium · 1.0 low. A blocking check is
 * never below high: blocking means it stops a publish.
 */
function severityFor(r: { weight?: number; blocking?: boolean }): string {
  const w = r.weight ?? 1;
  if (r.blocking) return w >= 5 ? "9.0" : "7.0";
  if (w >= 4) return "5.0";
  if (w >= 2) return "3.0";
  return "1.0";
}

export function toSarif(report: AssayReport, opts: { toolVersion?: string } = {}): string {
  const reported = report.results.filter(
    (r) => r.status === "fail" || r.status === "warn" || r.status === "error",
  );

  const rules = [...new Map(report.results.map((r) => [r.checkId, r])).values()].map((r) => ({
    id: r.checkId,
    name: r.title,
    shortDescription: { text: r.title },
    // The RULE's description, not this run's outcome.
    //
    // `summary` is per-result ("All 2 dependency ranges are bounded"),
    // and GitHub caches `fullDescription` against the rule and shows it
    // on the rule page — so the rule "Dependency ranges are bounded"
    // was permanently documented by whatever the first scanned repo
    // happened to produce. The rationale is what belongs here; outcomes
    // live in `results[].message`.
    fullDescription: { text: r.title },
    ...(r.spec ? { helpUri: r.spec } : {}),
    properties: {
      category: r.category,
      axis: r.axis,
      determinism: r.determinism,
      // GitHub buckets this into critical/high/medium/low. It was the
      // constant 3.0 for everything except blocking safety checks, so a
      // hardcoded exfiltration destination and a missing CI file both
      // arrived as "medium" — which defeats the reason to emit SARIF at
      // all. Derived from weight, and only claimed for safety checks:
      // "CI is not configured" is not a security severity.
      ...(r.axis === "safety" ? { "security-severity": severityFor(r) } : {}),
      // Deduped: axis and category coincide for safety checks (both
      // "safety"), and a rule tagged ["safety","safety"] reads as a bug
      // in the code-scanning UI's tag filter.
      tags: [...new Set([r.axis, r.category])],
    },
  }));

  const results = reported.map((r) => ({
    ruleId: r.checkId,
    level: sarifLevel(r.status, r.blocking),
    message: {
      text: r.remediation ? `${r.summary}\n\n${r.remediation}` : r.summary,
    },
    locations: locationsFor(r),
    properties: { checkVersion: r.checkVersion, status: r.status },
  }));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "assay",
              informationUri: ASSAY_HOME,
              ...(opts.toolVersion ? { version: opts.toolVersion } : {}),
              rules,
            },
          },
          results,
          properties: {
            subjectDigest: report.subject.digest.sha256,
            suite: `${report.suite.id}@${report.suite.version}`,
            score: report.score,
          },
        },
      ],
    },
    null,
    2,
  );
}

/**
 * SARIF requires a location on every result. Findings with file
 * evidence point at the file; the rest are anchored to the artifact
 * root so the result still renders rather than being dropped.
 */
function locationsFor(r: CheckReport): unknown[] {
  const files = (r.evidence ?? []).filter((e) => e.type === "file");
  if (files.length === 0) {
    return [{ physicalLocation: { artifactLocation: { uri: "." } } }];
  }
  return files.map((e) => {
    const file = e as { path: string; line?: number };
    return {
      physicalLocation: {
        artifactLocation: { uri: file.path },
        ...(file.line ? { region: { startLine: file.line } } : {}),
      },
    };
  });
}

// ── Diff ─────────────────────────────────────────────────────────────

export interface CheckDelta {
  checkId: string;
  title: string;
  from: CheckStatus | null;
  to: CheckStatus | null;
  /** True when the change is in the worse direction. */
  regression: boolean;
}

export interface ReportDiff {
  /**
   * Changes to the tool surface between the two versions. This is the
   * rug-pull signal, and it is listed first because it is the one a
   * reviewer must look at even when every check still passes — the
   * point of the attack is that the checks DO still pass.
   */
  surface: SurfaceDiff | null;
  /**
   * Why `surface` is null, when it is.
   *
   * A null surface diff means "we could not tell", and that is NOT the
   * same claim as "nothing changed" — but the renderer used to collapse
   * both into "No regressions, no surface changes." A reader saw a
   * clean bill of health for a comparison that never happened, at the
   * one place the tool exists to look.
   *
   * Real and common: a package published to npm ships only `dist/`, and
   * static capture cannot read tool names that are registered
   * dynamically. `@modelcontextprotocol/server-everything` is exactly
   * that shape.
   */
  surfaceUnavailable: "before" | "after" | "both" | null;
  /** Checks that got worse. The reason CI runs this. */
  regressions: CheckDelta[];
  improvements: CheckDelta[];
  added: CheckDelta[];
  removed: CheckDelta[];
  /**
   * Checks that produced a verdict before and do not now.
   *
   * `pass|warn|fail` → `skip|error|neutral|removed`. Not a regression in
   * the artifact and not an improvement — a loss of *coverage*, which
   * used to be invisible because every non-judging status tied at
   * severity 0. `fail → skip` therefore counted as an improvement, and
   * `pass → skip` as nothing at all.
   *
   * That is how a check which quietly stops running — network gone,
   * docs moved so the behavioral tier skips, a config `disable` — sails
   * through the CI gate the README recommends.
   */
  coverageLost: CheckDelta[];
  scoreDelta: number | null;
  /** True when the subject bytes are identical, so any delta is OURS. */
  sameSubject: boolean;
}

/** How bad a JUDGING status is. Higher is worse. */
const SEVERITY: Record<CheckStatus, number> = {
  pass: 0,
  neutral: 0,
  skip: 0,
  error: 0,
  warn: 1,
  fail: 2,
};

/** Statuses that represent an actual verdict about the artifact. */
const JUDGING: ReadonlySet<CheckStatus> = new Set<CheckStatus>(["pass", "warn", "fail"]);

/**
 * Compare two reports.
 *
 * `sameSubject` is load-bearing rather than decorative: if the digests
 * match, the artifact did not change, so any difference in verdict came
 * from US — a check version bump, a config change, or judge drift. That
 * is a completely different conversation from "the author broke
 * something", and conflating the two would make the diff useless in
 * exactly the case where it matters most.
 */
export function diffReports(before: AssayReport, after: AssayReport): ReportDiff {
  const beforeById = new Map(before.results.map((r) => [r.checkId, r]));
  const afterById = new Map(after.results.map((r) => [r.checkId, r]));

  const regressions: CheckDelta[] = [];
  const improvements: CheckDelta[] = [];
  const added: CheckDelta[] = [];
  const removed: CheckDelta[] = [];
  const coverageLost: CheckDelta[] = [];

  for (const [id, a] of afterById) {
    const b = beforeById.get(id);
    if (!b) {
      added.push({ checkId: id, title: a.title, from: null, to: a.status, regression: false });
      continue;
    }
    if (b.status === a.status) continue;

    // Neither side is a verdict — `skip → neutral` and the like say
    // nothing about the artifact in either direction. Without this they
    // fell through to `improvements`, because equal severities are "not
    // a regression".
    if (!JUDGING.has(b.status) && !JUDGING.has(a.status)) continue;

    // A check that judged before and does not now is neither better nor
    // worse — it stopped answering, and that is its own category.
    if (JUDGING.has(b.status) && !JUDGING.has(a.status)) {
      coverageLost.push({
        checkId: id,
        title: a.title,
        from: b.status,
        to: a.status,
        regression: false,
      });
      continue;
    }

    const delta: CheckDelta = {
      checkId: id,
      title: a.title,
      from: b.status,
      to: a.status,
      regression: SEVERITY[a.status] > SEVERITY[b.status],
    };
    (delta.regression ? regressions : improvements).push(delta);
  }
  for (const [id, b] of beforeById) {
    if (!afterById.has(id)) {
      const delta: CheckDelta = {
        checkId: id,
        title: b.title,
        from: b.status,
        to: null,
        regression: false,
      };
      removed.push(delta);
      // A check that disappeared entirely also stopped answering.
      if (JUDGING.has(b.status)) coverageLost.push(delta);
    }
  }

  const scoreDelta =
    before.score.overall !== undefined && after.score.overall !== undefined
      ? Math.round((after.score.overall - before.score.overall) * 10) / 10
      : null;

  const beforeSurface = surfaceOf(before);
  const afterSurface = surfaceOf(after);

  const surfaceUnavailable =
    !beforeSurface && !afterSurface
      ? ("both" as const)
      : !beforeSurface
        ? ("before" as const)
        : !afterSurface
          ? ("after" as const)
          : null;

  return {
    // Only meaningful when both runs captured one; a null here means
    // "we could not tell", never "nothing changed" — which is why
    // `surfaceUnavailable` records the reason and the renderer must say so.
    surface: beforeSurface && afterSurface ? diffSurfaces(beforeSurface, afterSurface) : null,
    surfaceUnavailable,
    coverageLost,
    regressions,
    improvements,
    added,
    removed,
    scoreDelta,
    sameSubject: before.subject.digest.sha256 === after.subject.digest.sha256,
  };
}
