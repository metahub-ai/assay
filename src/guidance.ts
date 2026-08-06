/**
 * Telling the developer what to do next.
 *
 * This module exists because of a specific failure observed in use: a
 * first run prints `behavior  n/a  0% measured` and then stops. The
 * headline capability of the whole framework is sitting at zero, and
 * nothing on screen says how to change that — not which flag, not which
 * environment variable, not that it is even possible.
 *
 * A tool that reports a gap it knows how to close, and does not say so,
 * has chosen to be correct instead of useful. The fix is not more
 * documentation; it is that the output itself teaches.
 *
 * Every suggestion here is derived from the actual report, so it is
 * never generic advice — if `safety` came back at 71% coverage, the
 * reason is a specific check that could not run, and that is what gets
 * named.
 */
import type { BehavioralMode } from "./credentials.js";
import type { AssayReport, CheckReport } from "./types.js";

export interface Suggestion {
  /** One line, imperative. */
  title: string;
  /** The literal command to run, when there is one. */
  command?: string;
  /** Why it matters, in one sentence. */
  why?: string;
}

export interface EnvState {
  hasModelKey: boolean;
  modelHint: string | null;
  sandboxHint: string | null;
}

/** What the environment can currently support, for accurate advice. */
export function readEnvState(env: NodeJS.ProcessEnv = process.env): EnvState {
  const models: [string, string][] = [
    ["ANTHROPIC_API_KEY", "anthropic"],
    ["OPENAI_API_KEY", "openai"],
    ["OPENROUTER_API_KEY", "openrouter"],
    ["LOCAL_LLM_BASE_URL", "local"],
  ];
  const found = models.find(([k]) => env[k]);
  return {
    hasModelKey: Boolean(found),
    modelHint: found ? found[1] : null,
    sandboxHint: env["E2B_API_KEY"] ? "e2b" : null,
  };
}

/**
 * Derive next steps from a report.
 *
 * Ordered by how much they would change what the reader knows, not by
 * how easy they are. An unmeasured behavior axis is worth more than a
 * missing homepage field, so it comes first even though it is more work.
 */
/** `.` when it is the cwd, else a relative path when that is shorter. */
function shortestPath(p: string): string {
  if (!p.startsWith("/")) return p;
  const cwd = process.cwd();
  if (p === cwd) return ".";
  const rel = p.startsWith(`${cwd}/`) ? p.slice(cwd.length + 1) : null;
  return rel && rel.length < p.length ? rel : p;
}

export function suggestNextSteps(
  report: AssayReport,
  env: EnvState,
  opts: {
    ranBehavioral: boolean;
    artifactPath: string;
    hasTranscripts: boolean;
    /**
     * Why behavioral was or was not part of this run.
     *
     * Without it this module gave one answer — "pass --behavioral" — to
     * five different situations, and once behavioral runs by default
     * that answer is wrong in most of them: it is redundant advice for
     * someone who just turned it off on purpose, and it is the wrong
     * next step for someone who has configured nothing. Defaults to
     * `unavailable`, the state a caller that knows nothing is in.
     */
    behavioral?: BehavioralMode;
  },
): Suggestion[] {
  const out: Suggestion[] = [];
  // The shortest form that still works. `run` already resolved the
  // target, and echoing the resolved absolute path put a 184-character
  // line into a report whose every other line respects 80 columns —
  // twice, since two suggestions quote it.
  const path = shortestPath(opts.artifactPath);

  /**
   * A blocking safety failure outranks everything, including this
   * module's own "more information beats less" rule.
   *
   * The rule is right in general and produced an actively dangerous
   * instruction here: for an artifact whose confirmed findings include
   * `curl … | bash` to a hardcoded IP, the first recommended action was
   * "run it in a container and see what it does", with the security
   * findings third. The comparison the rule makes — an unmeasured axis
   * beats a missing homepage field — was never a comparison against a
   * live reverse shell.
   *
   * Nobody should be told to execute a payload the tool has just
   * identified. When safety blocks, the only next step is the fix list.
   */
  const unsafe = report.results.some(
    (r) => r.status === "fail" && r.blocking === true && r.axis === "safety",
  );

  const mode = opts.behavioral ?? "unavailable";
  // Naming the flag only where it is still needed. Repeating
  // `--behavioral` at somebody who has already configured it, and for
  // whom it now runs by default, is the exact "say yes twice" this
  // module would otherwise be teaching.
  const rerun = mode === "declined" ? `assay run ${path}` : `assay run ${path} --behavioral`;

  // 1. The big one: behavior unmeasured.
  if (!unsafe && !opts.ranBehavioral && report.score.axes.behavior.coverage === 0) {
    const title = "Measure the behavior axis — it is currently unmeasured";
    out.push(
      mode === "declined"
        ? {
            title,
            command: `${rerun} --transcripts ./transcripts`,
            why: "`--no-behavioral` skipped it this run. Drop the flag and it runs again — it is on by default once a sandbox and a model are configured.",
          }
        : mode === "non-interactive"
          ? {
              title,
              command: `${rerun} --transcripts ./transcripts`,
              why: "Without a terminal the behavioral tier stays opt-in, so a pipeline never starts spending model tokens because a key happens to be set on the runner. Ask for it by name and it runs.",
            }
          : mode === "opted-out"
            ? {
                title,
                command: `${rerun} --transcripts ./transcripts`,
                why: "`behavioralByDefault` is false in your saved config, so it is off unless asked for. Re-run `assay setup` to turn it back on for every run.",
              }
            : env.hasModelKey
              ? {
                  title,
                  command: `${rerun} --transcripts ./transcripts`,
                  why: `Runs the artifact in a container and judges what it does. A model key is already set${env.modelHint ? ` (${env.modelHint})` : ""}, so what is missing is a usable sandbox — see \`assay doctor\`.`,
                }
              : {
                  title,
                  // `assay setup` rather than a raw export: it verifies
                  // the key against the provider before saving it, and it
                  // persists — so this is the last time the question comes
                  // up, including the last time a flag is needed.
                  command: `assay setup\nassay run ${path} --transcripts ./transcripts`,
                  why: "Static checks cannot tell whether an artifact does what it claims. That needs a model to drive it and a second model to judge the transcript. `assay setup` configures both once, and behavioral then runs by default.",
                },
    );
  }

  // 2. Behavioral ran but is unreplayable — the verdict has to be
  //    taken on trust, which is the thing this project is against.
  if (opts.ranBehavioral && !opts.hasTranscripts) {
    out.push({
      title: "Record transcripts so the verdict can be re-derived",
      // No `--behavioral` when it ran without being asked for: quoting a
      // flag the reader did not type reads as "you did this wrong".
      command:
        mode === "default"
          ? `assay run ${path} --transcripts ./transcripts`
          : `assay run ${path} --behavioral --transcripts ./transcripts`,
      why: "Without them nobody — including you — can check the grade later.",
    });
  }

  // 3. Checks that were skipped for want of a capability, named.
  const skippedForNet = report.results.filter(
    (r) => r.status === "skip" && /requires net/.test(r.summary),
  );
  if (skippedForNet.length > 0) {
    out.push({
      title: `${skippedForNet.length} check${skippedForNet.length === 1 ? "" : "s"} need${skippedForNet.length === 1 ? "s" : ""} network access`,
      why: `Skipped: ${skippedForNet.map((r) => r.checkId).join(", ")}. ${skippedForNet.length === 1 ? "It lowers" : "They lower"} axis coverage rather than failing.`,
    });
  }

  // 4. Cheap, specific fixes the report already found.
  const fixable = report.results.filter(
    (r) => (r.status === "fail" || r.status === "warn") && r.remediation,
  );
  if (fixable.length > 0) {
    const worst = pickWorst(fixable);
    out.push({
      title: `Fix ${fixable.length} finding${fixable.length === 1 ? "" : "s"} — start with \`${worst.checkId}\``,
      command: `assay explain ${worst.checkId}`,
      why: worst.remediation,
    });
  }

  // 5. Regression tracking, once there is something to compare against.
  if (out.length < 4) {
    out.push({
      title: "Track this over time",
      command: `assay run ${path} --json > baseline.json\nassay diff baseline.json new.json`,
      why: "`diff` exits non-zero only on a regression or a tool-surface change, which is what CI actually wants.",
    });
  }

  // When safety blocks, the fix list leads. Everything else in this
  // function is advice about learning more; that one is the only thing
  // worth doing next.
  if (unsafe) {
    const fixFirst = out.findIndex((s) => s.title.startsWith("Fix "));
    if (fixFirst > 0) out.unshift(...out.splice(fixFirst, 1));
  }
  return out;
}

/** Blocking failures first, then failures, then warnings. */
function pickWorst(findings: CheckReport[]): CheckReport {
  const rank = (r: CheckReport) =>
    (r.blocking ? 0 : 2) + (r.status === "fail" ? 0 : 1) - (r.weight ?? 1) / 100;
  return [...findings].sort((a, b) => rank(a) - rank(b))[0]!;
}

/**
 * `width` is passed in rather than hardcoded. It was fixed at 72, so at
 * `COLUMNS=40` the report body wrapped correctly to 36 columns and the
 * `next` block underneath it emitted 78-character lines — the one part
 * of the output that did not route through the theme.
 */
export function renderSuggestions(suggestions: readonly Suggestion[], width = 78): string {
  if (suggestions.length === 0) return "";
  const lines = ["", "  next", ""];
  for (const s of suggestions) {
    lines.push(`    → ${s.title}`);
    if (s.why) lines.push(`      ${wrap(s.why, width - 6, "      ")}`);
    if (s.command) {
      // Continuation lines are indented to match, so a multi-step
      // command reads as one block rather than falling out of the
      // layout at the left margin.
      const [first, ...rest] = s.command.split("\n");
      lines.push(`      $ ${first}`);
      for (const line of rest) lines.push(`        ${line.trim()}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

/** Soft-wrap prose so a long rationale does not run off the terminal. */
function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const out: string[] = [];
  let line = "";
  for (const w of words) {
    if (line.length + w.length + 1 > width) {
      out.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) out.push(line);
  return out.join(`\n${indent}`);
}
