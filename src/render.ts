/**
 * Human-readable report rendering.
 *
 * The information hierarchy is the whole design, and it is ordered by
 * what someone actually needs, in the order they need it:
 *
 *   1. What did I evaluate, and exactly which bytes?
 *   2. What is the verdict, and how much of it was measured?
 *   3. What is wrong, worst first, with the file and the fix?
 *   4. What passed. (Dimmed. It matters — this is a trust tool and
 *      "everything I checked" is the claim — but it is not news.)
 *   5. What to do next.
 *
 * The rule the previous renderer broke was putting a flat, alphabetised
 * list of every check ahead of the score, so the two failures were four
 * screens up from the number people scroll to. Sorting by category name
 * is convenient for the program and useless to the reader.
 *
 * Coverage is printed beside every axis, never hidden. A score of 0 at
 * 0% coverage means "we could not tell", and rendering that identically
 * to a measured 0 is the specific dishonesty the scorer exists to
 * prevent — so an unmeasured axis gets a dash, not a number.
 */
import {
  padEndVisible,
  scoreBar,
  statusGlyph,
  truncateVisible,
  wrapText,
  type StatusKind,
  type Theme,
} from "./term.js";
import type { AssayReport, CheckReport, Evidence } from "./types.js";

export interface RenderOptions {
  quiet: boolean;
  theme: Theme;
  /** Where the artifact came from, when it was not a local path. */
  provenance?: { kind: string; spec: string; resolved?: string; integrity?: string } | undefined;
  policyPath?: string | null;
  durationMs?: number;
  /** The directory name, when it disagrees with the declared name. */
  nameMismatch?: string | undefined;
}

/** Failures before warnings before everything else. */
const SEVERITY: Record<string, number> = {
  fail: 0,
  error: 1,
  warn: 2,
  skip: 3,
  neutral: 4,
  pass: 5,
};

const AXIS_ORDER = ["integrity", "safety", "care", "behavior"];

/**
 * The 95% half-interval on the behavior axis (0-100 scale), or null when
 * the run couldn't bound it (a single sample, where the half-width is a
 * meaningless 100). Read from the behavioral check's own evidence so
 * render never recomputes what the engine already published.
 */
function behavioralHalfWidth(report: AssayReport): number | null {
  const beh = report.results.find((r) => r.checkId === "behaves-as-documented");
  const m = beh?.evidence?.find(
    (e): e is Extract<Evidence, { type: "metric" }> =>
      e.type === "metric" && e.name === "score_95ci_halfwidth",
  );
  return m && typeof m.value === "number" && m.value > 0 && m.value < 100 ? m.value : null;
}

/**
 * Indented to the content margin.
 *
 * Rules used to start at column 0 while every other line starts at 2, so
 * every divider stuck out to the left of the page.
 */
function rule(t: Theme, width = t.width): string {
  return `  ${t.muted((t.unicode ? "─" : "-").repeat(Math.max(10, width - 4)))}`;
}

export function renderReport(report: AssayReport, opts: RenderOptions): string {
  const t = opts.theme;

  /**
   * `--quiet` is documented as "only print failures" and printed thirty
   * lines for an artifact with none: it filtered the findings list and
   * left the banner, the score table, both rules, the summary and the
   * whole `next` block untouched.
   */
  if (opts.quiet) {
    const notable = report.results.filter((r) => r.status === "fail" || r.status === "warn");
    if (notable.length === 0) return "";
    const q: string[] = [""];
    for (const r of [...notable].sort(
      (a, b) =>
        Number(b.blocking === true) - Number(a.blocking === true) ||
        (a.status === b.status ? 0 : a.status === "fail" ? -1 : 1),
    )) {
      q.push(...renderFinding(r, t, true));
    }
    q.push(`  ${summaryLine(report, t, opts.durationMs)}`, "");
    return q.join("\n");
  }

  const out: string[] = [""];

  // ── 1. Subject ─────────────────────────────────────────────────────
  out.push(
    `  ${t.heading(report.subject.name)}  ${t.muted(report.subject.kind)}` +
      // Not cosmetic. An artifact whose folder says one thing and whose
      // manifest says another is the shape of a package pretending to
      // be a package you meant to install.
      (opts.nameMismatch
        ? `  ${t.warn(`${t.glyph("warn")} directory is named "${opts.nameMismatch}"`)}`
        : ""),
  );
  const digest = `${report.subject.digest.sha256.slice(0, 16)}${t.ellipsis}`;
  const origin = opts.provenance?.resolved ?? opts.provenance?.spec;
  out.push(`  ${t.muted(digest)}${origin ? t.muted(`  ${t.dot}  ${origin}`) : ""}`);
  if (opts.provenance?.integrity) {
    // Worth its own line: we checked the registry's hash rather than
    // trusting the bytes we were handed.
    out.push(
      `  ${t.pass("✓")} ${t.muted(`registry integrity verified (${opts.provenance.integrity.split("-")[0]})`)}`,
    );
  }
  out.push("");

  // ── 2. Verdict ─────────────────────────────────────────────────────
  out.push(rule(t));
  out.push("");
  const overall = report.score.overall;
  if (overall === undefined) {
    out.push(`  ${t.bold("OVERALL")}   ${t.warn("not enough was measured to publish a score")}`);
    out.push(
      `  ${t.muted(wrapText("Too many checks were skipped for an aggregate to mean anything. Granting more capability (--net, --behavioral) raises coverage.", t.width - 4, "  "))}`,
    );
  } else {
    const blocking = report.results.filter((r) => r.status === "fail" && r.blocking === true);
    // The colour follows the VERDICT, not the score band.
    //
    // These were computed independently — colour from the number, word
    // from the blocking failures — so they were free to disagree, and
    // did: an 86.1 with a blocking failure rendered the bar and the
    // number in green with a single red `FAIL` at the far right. At a
    // glance, and in a screenshot, that line reads "green, 86, good".
    const grade =
      blocking.length > 0 ? t.fail : overall >= 80 ? t.pass : overall >= 50 ? t.warn : t.fail;
    // A word before the number. The eye lands on it first, and it says
    // the thing the number only implies.
    const verdict =
      blocking.length > 0 ? t.fail("FAIL") : overall >= 50 ? t.pass("PASS") : t.warn("WEAK");

    // A blocking SAFETY failure is not a low score, and must not be
    // read as one. The red-team fixture — a hardcoded reverse shell, a
    // split credential and a base64 payload behind eval — headlined
    // `40.8/100`, the same neighbourhood as "unfinished but
    // salvageable", with integrity 92.9 and care 88.5 as the visually
    // dominant bars. Nowhere did a word appear meaning "do not install
    // this". Averaging a zeroed safety axis against a tidy README is
    // exactly the arithmetic that produced that sentence.
    const unsafe = blocking.filter((r) => r.axis === "safety");
    if (unsafe.length > 0) {
      out.push(
        `  ${t.fail(t.bold("UNSAFE"))}    ${t.fail(
          `${unsafe.length} blocking safety check${unsafe.length === 1 ? "" : "s"} failed ${t.dash} do not install this artifact`,
        )}`,
      );
      const note = wrapText(
        "The score below is advisory only. Integrity and care do not offset a safety failure.",
        t.width - 14,
        "            ",
      );
      out.push(`  ${t.muted(`          ${note}`)}`);
      out.push("");
    }

    // Coverage ON the headline. It was printed beside every axis and
    // omitted from the aggregate — the one number people screenshot —
    // so a run with a quarter of safety and ALL of behavior unmeasured
    // published a bare `100/100`. That is the same dishonesty the dash
    // on an unmeasured axis exists to prevent, at the only place it
    // really matters.
    out.push(
      `  ${t.bold("OVERALL")}   ${scoreBar(t, overall, true, 20)}  ` +
        `${grade(t.bold(String(overall)))}${t.muted("/100")}   ${verdict}`,
    );

    // Count what actually happened, rather than averaging axis coverage.
    //
    // The old line read "73% of the suite could be measured" and was
    // arithmetic on four axis coverages including `behavior`, which is 0
    // on every offline run. So no offline run could print above 75%, the
    // number barely moved between wildly different artifacts (73, 73,
    // 67, 66), and it did not match the footer's own tallies. It used
    // "the suite" to mean "the axis list".
    const judged = report.results.filter(
      (r) => r.status === "pass" || r.status === "warn" || r.status === "fail",
    ).length;
    const skipped = report.results.filter((r) => r.status === "skip").length;
    const na = report.results.filter((r) => r.status === "neutral").length;
    const behaviorMeasured = (report.score.axes.behavior?.coverage ?? 0) > 0;
    const parts = [`${judged} of ${judged + skipped} checks judged`];
    if (skipped > 0) parts.push(`${skipped} skipped`);
    if (na > 0) parts.push(`${na} n/a`);
    if (!behaviorMeasured) parts.push("behavior not measured");
    out.push(`  ${t.muted(`          ${parts.join(`  ${t.dot}  `)}`)}`);
  }
  out.push("");

  // The behavior axis comes from a stochastic driver, so its number is
  // an estimate. Pull the 95% half-interval (on the 0-100 scale) from the
  // behavioral check's evidence and show it inline — a bare "93" invites
  // the exact over-reading this tool exists to prevent. Absent when the
  // run had too few samples to bound it (n=1 → total uncertainty, which
  // an honest "±50" would only clutter the line).
  const behaviorCi = behavioralHalfWidth(report);
  for (const axis of AXIS_ORDER) {
    const a = report.score.axes[axis as keyof typeof report.score.axes];
    if (!a) continue;
    const measured = a.coverage > 0 && a.value !== null;
    // Axis values can be fractional (87.5), so a fixed 3-wide column
    // ragged the whole table. One decimal, dropped when it is `.0`.
    const shown =
      a.value === null ? "" : Number.isInteger(a.value) ? String(a.value) : a.value.toFixed(1);
    // Through the theme, so `ASSAY_ASCII=1` reaches it too — this was
    // the last hardcoded non-ASCII character in the report.
    const value = measured ? shown.padStart(5) : t.muted(t.dash.padStart(5));
    const cov = measured
      ? t.muted(`${String(Math.round(a.coverage * 100)).padStart(3)}% measured`)
      : t.muted("  not measured");
    const ci =
      axis === "behavior" && measured && behaviorCi !== null
        ? t.muted(`  ± ${behaviorCi.toFixed(0)}`)
        : "";
    out.push(
      `  ${t.muted(axis.padEnd(10))}${scoreBar(t, a.value ?? 0, measured, 20)}  ${value}${ci}   ${cov}`,
    );
  }
  // Say it where the dash is.
  //
  // An unmeasured behavior axis is the single most consequential gap in
  // a report — it means nothing here tested what the artifact actually
  // does — and the only place it was explained was a suggestion at the
  // very bottom, past the whole findings list. The dash needs its own
  // sentence, next to the dash.
  //
  // Not shown when safety blocks: nothing should nudge anyone toward
  // executing an artifact the tool has just identified as malicious.
  const behaviorUnmeasured = (report.score.axes.behavior?.coverage ?? 0) === 0;
  const safetyBlocks = report.results.some(
    (r) => r.status === "fail" && r.blocking === true && r.axis === "safety",
  );
  if (behaviorUnmeasured && !safetyBlocks) {
    out.push("");
    out.push(
      `  ${t.muted(
        wrapText(
          // No longer "then add --behavioral": once setup has been
          // through, that is what `assay run` does on its own, and
          // teaching a flag the reader will never need to type again is
          // how a tool ends up asking for consent twice.
          "Nothing here ran the artifact. `assay setup` configures a sandbox and a model once, after which behavioral evaluation is part of a plain `assay run` — see `assay doctor`.",
          t.width - 6,
          "  ",
        ),
      )}`,
    );
  }

  out.push("");
  if (overall !== undefined) {
    // It used to float unlabelled under the table, reading as a package
    // name or a version — while being the only provenance for how four
    // axes became one number.
    out.push(`  ${t.muted(`scoring   ${report.score.formula}`)}`);
  }
  out.push("");

  // ── 3 & 4. Findings ────────────────────────────────────────────────
  const shown = opts.quiet
    ? report.results.filter((r) => r.status === "fail" || r.status === "warn")
    : report.results;

  /**
   * Worst first, and blocking above everything.
   *
   * Results arrive sorted by check id, and the renderer preserved that —
   * so on an artifact with a committed AWS key the order was
   * `description-quality`, `documentation-present`, `mcp-launchable`,
   * `no-sensitive-files`: the leaked credential printed BELOW "add a
   * description". This module's own docstring says sorting by name is
   * "convenient for the program and useless to the reader", and then the
   * findings did exactly that.
   */
  const bySeverity = (a: CheckReport, b: CheckReport): number =>
    Number(b.blocking === true) - Number(a.blocking === true) ||
    (b.weight ?? 1) - (a.weight ?? 1) ||
    AXIS_ORDER.indexOf(a.axis) - AXIS_ORDER.indexOf(b.axis) ||
    (a.checkId < b.checkId ? -1 : 1);

  const problems = shown
    .filter((r) => r.status === "fail" || r.status === "error")
    .sort(bySeverity);
  const warnings = shown.filter((r) => r.status === "warn").sort(bySeverity);
  // A check switched OFF by policy is not a check that did not apply.
  // Both arrive as `neutral`, so a disabled blocking safety check
  // rendered as a muted dash identical to "no package.json here" — and
  // the reason the publisher was required to write was nowhere on
  // screen. `suppressed` already distinguishes them on the result; only
  // the renderer was ignoring it.
  const suppressed = shown.filter((r) => r.suppressed === true);
  const rest = shown.filter(
    (r) => !["fail", "error", "warn"].includes(r.status) && r.suppressed !== true,
  );

  if (problems.length) {
    out.push(rule(t));
    out.push("");
    out.push(`  ${t.fail(t.bold("NEEDS FIXING"))}`);
    out.push("");
    for (const r of problems) out.push(...renderFinding(r, t, true));
  }

  if (warnings.length) {
    out.push(rule(t));
    out.push("");
    out.push(`  ${t.warn(t.bold("WORTH A LOOK"))}`);
    out.push("");
    for (const r of warnings) out.push(...renderFinding(r, t, true));
  }

  if (suppressed.length) {
    out.push(rule(t));
    out.push("");
    out.push(`  ${t.warn(t.bold("SWITCHED OFF BY POLICY"))}`);
    out.push(
      `  ${t.muted("These did not judge this artifact. They still count against coverage.")}`,
    );
    out.push("");
    for (const r of suppressed) {
      out.push(`    ${t.muted(t.dot)} ${r.title}`);
      out.push(`      ${wrapText(r.summary, t.width - 8, "      ")}`);
      // The reason is the entire point of requiring one.
      if (r.detail) {
        for (const para of r.detail.split("\n\n")) {
          if (para.trim())
            out.push(`      ${t.muted(wrapText(para.trim(), t.width - 8, "      "))}`);
        }
      }
      out.push("");
    }
  }

  if (rest.length) {
    out.push(rule(t));
    out.push("");
    // Grouped by axis rather than the check's own category string: the
    // axis is what the score is built from, so the reader can trace a
    // number back to the checks that produced it.
    const byAxis = new Map<string, CheckReport[]>();
    for (const r of rest) {
      const list = byAxis.get(r.axis) ?? [];
      list.push(r);
      byAxis.set(r.axis, list);
    }
    for (const axis of AXIS_ORDER) {
      const group = byAxis.get(axis);
      if (!group?.length) continue;
      out.push(`  ${t.muted(axis.toUpperCase())}`);
      for (const r of [...group].sort((a, b) => SEVERITY[a.status]! - SEVERITY[b.status]!)) {
        out.push(...renderFinding(r, t, false));
      }
      out.push("");
    }
  }

  // ── 5. Footer ──────────────────────────────────────────────────────
  out.push(rule(t));
  out.push("");
  out.push(`  ${summaryLine(report, t, opts.durationMs)}`);
  if (opts.policyPath) out.push(`  ${t.muted(`policy: ${opts.policyPath}`)}`);
  out.push("");
  return out.join("\n");
}

function renderFinding(r: CheckReport, t: Theme, detailed: boolean): string[] {
  const lines: string[] = [];
  // An informational check is REPORTED, never scored, so it returns
  // `neutral` whether or not it found the thing. That made one glyph
  // mean two opposite outcomes: a repo with CI and twenty test files
  // rendered identically to one with neither. Weight 0 gets its own
  // mark — "noted", as distinct from "does not apply".
  const glyph =
    r.weight === 0 ? t.muted(t.unicode ? "\u24D8" : "i") : statusGlyph(t, r.status as StatusKind);
  const title = detailed ? t.bold(r.title) : r.title;

  if (detailed) {
    // Only on an actual failure. `blocking` is a property of the check
    // definition, so a WARNING from a blocking check was labelled
    // "(blocking)" too — which reads as "this is stopping your build"
    // when it is not, and is exactly backwards for a finding that was
    // downgraded precisely because it does not block.
    const blocks = r.blocking === true && r.status === "fail";
    lines.push(`    ${glyph} ${title}${blocks ? ` ${t.fail("(blocking)")}` : ""}`);
    lines.push(`      ${wrapText(r.summary, t.width - 8, "      ")}`);

    // `detail` is where a check says WHICH thing it found — "an AWS
    // access key id, split across parts", "`reqeusts` is 2 characters
    // from `requests`". It was computed on every finding and printed on
    // none of them, so the terminal said "2 credentials" and left the
    // reader to open four files for what the scanner already knew. The
    // JSON carried it, which made the machine surface strictly more
    // useful than the human one — backwards for a reporting tool.
    //
    // Only on findings: a passing check's detail is noise, and the wall
    // of passes is meant to scan as a block.
    if (r.detail && (r.status === "fail" || r.status === "warn")) {
      // Check authors write prose, and prose has em dashes and curly
      // quotes in it. Everything else in the report routes punctuation
      // through the theme; this text arrives from outside it, so
      // `ASSAY_ASCII=1` has to be honoured here explicitly.
      const text = t.unicode
        ? r.detail
        : r.detail
            .replace(/[—–]/g, "-")
            .replace(/[‘’]/g, "'")
            .replace(/[“”]/g, '"')
            .replace(/…/g, "...")
            .replace(/[^\x20-\x7e\n\t]/g, "");
      for (const line of text.split("\n")) {
        if (!line.trim()) {
          lines.push("");
          continue;
        }
        lines.push(`      ${t.muted(wrapText(line, t.width - 8, "      "))}`);
      }
    }
  } else {
    // The one-line form is column-aligned so a wall of passes scans as a
    // block rather than as ragged prose. The title is truncated as well
    // as padded — a single long check name would otherwise shove every
    // summary on its row out of the column.
    // Proportional, not a constant. At 60 columns a fixed 38 left the
    // summary 16 characters wide while padding short titles with air.
    const TITLE_COL = Math.max(20, Math.min(38, Math.floor(t.width * 0.45)));
    const label = padEndVisible(
      `${glyph} ${t.muted(truncateVisible(title, TITLE_COL - 2, t.ellipsis))}`,
      TITLE_COL,
    );
    lines.push(
      `    ${label} ${t.muted(truncateVisible(r.summary, Math.max(16, t.width - TITLE_COL - 6), t.ellipsis))}`,
    );
    return lines;
  }

  // Evidence repeats what `detail` already said, when detail bullets
  // name the same locations — `scripts/upload.js:2` appearing twice,
  // four lines apart, reads as two findings.
  const detailShown = Boolean(r.detail) && detailed && (r.status === "fail" || r.status === "warn");
  const covered = (e: Evidence): boolean =>
    detailShown &&
    e.type === "file" &&
    (r.detail ?? "").includes(`${e.path}${e.line ? `:${e.line}` : ""}`);

  for (const e of r.evidence ?? []) {
    if (covered(e)) continue;
    if (e.type === "file") {
      // `path:line` because every terminal and editor turns that into a
      // jump. The whole value of evidence is getting to the line.
      lines.push(`      ${t.code(`${e.path}${e.line ? `:${e.line}` : ""}`)}`);
      if (e.excerpt)
        lines.push(`        ${t.muted(truncate(e.excerpt.trim(), t.width - 10, t.ellipsis))}`);
    } else if (e.type === "url") {
      lines.push(`      ${t.code(e.url)}${e.note ? t.muted(` — ${e.note}`) : ""}`);
    } else if (e.type === "metric") {
      // Units are free-form strings from checks ("of 3", "0-10", "ms"),
      // so concatenating produced "1of 3" and "5.30-10". A space fixes
      // every case except the symbols that are conventionally tight.
      const unit = e.unit ? (/^[%°]/.test(e.unit) ? e.unit : ` ${e.unit}`) : "";
      lines.push(`      ${t.muted(`${e.name}: ${e.value}${unit}`)}`);
    } else if (e.type === "transcript") {
      lines.push(
        `      ${t.muted(`transcript ${e.sha256.slice(0, 12)}${t.ellipsis} (${e.turns} turns)`)}`,
      );
    }
  }
  if (r.remediation) {
    lines.push(`      ${t.accent(t.arrow)} ${wrapText(r.remediation, t.width - 10, "        ")}`);
  }
  lines.push("");
  return lines;
}

function summaryLine(report: AssayReport, t: Theme, durationMs?: number): string {
  const tally = new Map<string, number>();
  for (const r of report.results) tally.set(r.status, (tally.get(r.status) ?? 0) + 1);
  // Plurals are given explicitly rather than by appending an "s", which
  // produced "14 passs · 2 skippeds · 3 n/as".
  const part = (key: string, one: string, many: string, paint: (s: string) => string) => {
    const n = tally.get(key) ?? 0;
    return n ? paint(`${n} ${n === 1 ? one : many}`) : null;
  };
  const parts = [
    part("fail", "failure", "failures", t.fail),
    part("error", "check error", "check errors", t.warn),
    part("warn", "warning", "warnings", t.warn),
    part("pass", "pass", "passed", t.pass),
    part("skip", "skipped", "skipped", t.muted),
    part("neutral", "n/a", "n/a", t.muted),
  ].filter(Boolean);

  const secs = durationMs ? t.muted(` in ${(durationMs / 1000).toFixed(1)}s`) : "";
  return `${parts.join(t.muted(` ${t.dot} `))}${secs}`;
}

/** Flatten whitespace, then truncate by terminal cells. */
function truncate(s: string, width: number, ellipsis = "…"): string {
  return truncateVisible(s.replace(/\s+/g, " ").trim(), width, ellipsis);
}
