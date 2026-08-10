/**
 * The behavioral check — the one the whole project is premised on.
 *
 * It drives the artifact inside a sandbox with a live model, judges the
 * resulting transcripts, and reports what happened. Two properties make
 * it more than "we ran it and a model liked it":
 *
 *   - **Every transcript is recorded as `Evidence`.** That is what makes
 *     the `replayable` tier real rather than aspirational: a skeptic
 *     re-grades the SAME transcript with the pinned judge and either
 *     reproduces the verdict or demonstrates we are wrong — without
 *     paying for a sandbox and without our cooperation.
 *
 *   - **Infrastructure failure is `error`, never `fail`.** A dead
 *     sandbox says nothing about someone else's code, and recording it
 *     as a behavioral verdict puts a permanent public mark on their
 *     work for our outage.
 */
import { createHash } from "node:crypto";
import { defineCheck, type CheckContext, type CheckDefinition } from "../check.js";
import type { SandboxProvider, SandboxSpec } from "../ports.js";
import { runBehavioralEval, type CaseCache } from "../behavioral/run.js";
import type { BehavioralEvalResult, Transcript } from "../behavioral/types.js";
import type { JudgeConfig } from "../behavioral/judge.js";
import { compareDeclaredToObserved, type SurfaceChange } from "../surface.js";
import {
  annotationTruth,
  type AnnotationFinding,
  type ObservedSideEffects,
} from "../behavioral/mcp-observation.js";
import { captureSurface } from "./surface-capture.js";
import { resolveDocs } from "./docs-resolution.js";
import { probeCorpusDigest } from "../behavioral/probes.js";
import type { Evidence } from "../types.js";
import { checkSpecUrl } from "../version.js";

/**
 * Somewhere to put transcript bodies.
 *
 * The check always emits a transcript DIGEST, which is enough to detect
 * tampering. Replay additionally needs the bytes, and where those live
 * is a host decision — object storage, a database, a static site. A
 * sink that returns a URI gets it threaded into the evidence so the
 * report points at something fetchable.
 */
export interface TranscriptContext {
  kind: string;
  /** The artifact documentation the rubric was built from. */
  doc: string;
  /** The case's own expectation, when it had one. */
  expectation?: string;
  adversarial?: boolean;
}

export interface TranscriptSink {
  put(
    digest: string,
    transcript: Transcript,
    context: TranscriptContext,
    verdict: import("../behavioral/types.js").JudgeVerdict,
  ): Promise<string | null>;
}

export interface BehavioralCheckOptions {
  /** Where the artifact's docs live, in preference order. */
  docPaths?: string[];
  sandboxSpec?: SandboxSpec;
  judgeConfig?: Partial<JudgeConfig>;
  caseCount?: number;
  probeCount?: number;
  passRatio?: number;
  caseConcurrency?: number;
  caseCache?: CaseCache;
  transcripts?: TranscriptSink;
  /** Repo coordinates, when the harness needs real files on disk. */
  repo?: { url: string; commit?: string; path?: string };
  /**
   * Source used to populate the sandbox, when it must differ from the
   * one the checks read.
   *
   * They genuinely differ: analysis excludes build output, execution
   * requires it. See RUNTIME_IGNORE in sources/directory.ts.
   */
  materializeSource?: import("../ports.js").SourceReader;
  allowedTools?: string[];
  allowedHosts?: string[];
  /** Capture the runtime ledger (tcpdump + strace). Default true. */
  captureRuntime?: boolean;
  promptBased?: boolean;
  /** Run each case this many times and average. See `repeat` in run.ts. */
  repeat?: number;
  /** Also measure uplift vs. a no-skill baseline. Skill-only, opt-in. */
  uplift?: boolean;
  /** Extra adversarial probes from community plugins (always run). */
  extraProbes?: import("../behavioral/types.js").EvalTestCase[];
  /** Version to publish for this check. Bump when logic changes. */
  version?: string;
}

/**
 * Explicit override only. Documentation is otherwise resolved through
 * `resolveDocs`, which is the single place that knows where each kind
 * keeps its docs.
 *
 * This check used to carry its own hardcoded list —
 * `["SKILL.md", "README.md", "readme.md", "AGENT.md", "PLUGIN.md"]` —
 * which was the FOURTH reimplementation of that convention in the
 * codebase and by far the most damaging. A prompt-based agent
 * (`reviewer.md`), a plugin whose docs live in `.claude-plugin/`, and an
 * MCP server documented in `docs/README.md` all missed every entry, so
 * the entire behavioral tier reported `skip` for them. Quietly, since a
 * skip only lowers coverage.
 */

/**
 * Every `evals/*.json` (and a root `evals.json`) the artifact ships.
 *
 * Read from the artifact rather than configured, because they belong to
 * the author: they are the cases the person who wrote the thing knows
 * are worth testing.
 */
async function readEvalFiles(ctx: CheckContext): Promise<Record<string, string>> {
  const tree = await ctx.source.listTree();
  const candidates = tree.filter(
    (e) =>
      e.type === "file" &&
      (/^evals\/[^/]+\.json$/.test(e.path) || e.path === "evals.json") &&
      !e.path.endsWith(".schema.json"),
  );
  const out: Record<string, string> = {};
  for (const c of candidates.slice(0, 20)) {
    const body = await ctx.source.readFile(c.path);
    if (body && body.trim()) out[c.path] = body;
  }
  return out;
}

/** Stable digest of a transcript, for evidence and replay lookup. */
export function digestTranscript(t: Transcript): string {
  // Sorted-key JSON so an equivalent transcript hashes identically
  // regardless of serialization order.
  const canonical = JSON.stringify({
    messages: t.messages.map((m) => ({
      role: m.role,
      content: m.content,
      ...(m.toolCallId ? { toolCallId: m.toolCallId } : {}),
    })),
    toolCalls: t.toolCalls.map((c) => ({ name: c.name, input: c.input })),
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/**
 * Build the behavioral check.
 *
 * A factory rather than a constant because it needs host wiring — a
 * transcript sink, repo coordinates, a case cache. Checks are values in
 * this framework, so configuring one is constructing one, not mutating
 * global state.
 */
export function createBehavioralCheck(opts: BehavioralCheckOptions = {}): CheckDefinition {
  return defineCheck({
    id: "behaves-as-documented",
    // 1.1.0: runtime behavior ledger (packet capture + strace) added —
    // observed connections and undeclared hosts now surface as evidence
    // and can demote a pass to warn.
    // 1.2.0: MCP protocol conformance verdict + tool-annotation
    // truth-check — a read-only claim contradicted by the tool's own
    // description (or the ledger) now demotes a pass to warn.
    version: opts.version ?? "1.2.0",
    title: "Behaves as documented",
    category: "behavioral",
    axis: "behavior",
    determinism: "replayable",
    needs: ["llm", "sandbox"],
    weight: 5,
    spec: checkSpecUrl("behaves-as-documented"),
    async run(ctx) {
      if (!ctx.llm || !ctx.sandbox) {
        return { status: "error", summary: "Behavioral capabilities were not provided." };
      }

      // Author-supplied cases beat synthesized ones, and until now the
      // CLI could not supply them: `providedEvalFiles` existed on the
      // engine input, `BehavioralCheckOptions` had no field for it, and
      // nothing read `evals/` from the artifact. So `assay init`
      // scaffolded a file that was silently ignored and the model
      // synthesized from the README instead — testing what the docs SAY
      // rather than what the author knows matters, which is the exact
      // substitution the init text warns against.
      const providedEvalFiles = await readEvalFiles(ctx);

      const doc = opts.docPaths
        ? await readDoc(ctx, opts.docPaths)
        : ((await resolveDocs(ctx.source, ctx.subject.kind))?.body ?? null);
      if (!doc) {
        // Without documentation there is no claim to check behavior
        // against. Judging anyway would grade the artifact on a
        // standard we invented for it.
        return {
          status: "skip",
          summary: "No documentation found, so there is no documented behavior to verify.",
          detail: opts.docPaths
            ? `Looked for: ${opts.docPaths.join(", ")}.`
            : `Looked for the documentation conventions of a ${ctx.subject.kind}: ` +
              "the kind's own document, a README, and (for an agent) the agent markdown itself.",
        };
      }

      // Adapt the capability handle to the provider interface the
      // engine expects.
      const runner = ctx.sandbox;
      const provider: SandboxProvider = {
        name: runner.name,
        create: (spec) => runner.provision(spec),
      };

      const result = await runBehavioralEval({
        kind: ctx.subject.kind,
        doc,
        sandboxProvider: provider,
        llm: ctx.llm,
        // Without this the container is empty and every non-skill
        // harness evaluates a failure to install.
        ...(opts.repo ? {} : { materialize: opts.materializeSource ?? ctx.source }),
        ...(opts.allowedTools ? { allowedTools: opts.allowedTools } : {}),
        ...(opts.allowedHosts ? { allowedHosts: opts.allowedHosts } : {}),
        ...(opts.captureRuntime !== undefined ? { captureRuntime: opts.captureRuntime } : {}),
        ...(opts.sandboxSpec ? { sandboxSpec: opts.sandboxSpec } : {}),
        ...(opts.judgeConfig ? { judgeConfig: opts.judgeConfig } : {}),
        ...(opts.caseCount !== undefined ? { caseCount: opts.caseCount } : {}),
        ...(opts.probeCount !== undefined ? { probeCount: opts.probeCount } : {}),
        ...(opts.passRatio !== undefined ? { passRatio: opts.passRatio } : {}),
        ...(opts.caseConcurrency !== undefined ? { caseConcurrency: opts.caseConcurrency } : {}),
        ...(opts.caseCache ? { caseCache: opts.caseCache } : {}),
        ...(opts.caseCache
          ? {
              // The case COUNT is part of the key. Keying on the digest
              // alone meant `--cases 5` silently reused a cached set of
              // 2 and quietly ignored the flag.
              // The PROBE CORPUS digest, not just its count.
              // `probeCorpusDigest` exists precisely so that editing a
              // probe invalidates cached cases — its own doc comment
              // says so — and nothing called it. Probes are appended
              // before the set is cached, so without this a cache hit
              // replays frozen probe text for 30 days.
              caseCacheKey:
                `${ctx.subject.digest.sha256}` +
                `-c${opts.caseCount ?? "d"}` +
                `-p${probeCorpusDigest(ctx.subject.kind)}` +
                `-n${opts.probeCount ?? "d"}` +
                // Plugin probes are appended before caching too, so their
                // ids must key the cache or a new probe replays stale.
                (opts.extraProbes && opts.extraProbes.length > 0
                  ? `-x${opts.extraProbes.map((p) => p.id).join(",")}`
                  : ""),
            }
          : {}),
        ...(opts.promptBased !== undefined ? { promptBased: opts.promptBased } : {}),
        ...(opts.repeat !== undefined ? { repeat: opts.repeat } : {}),
        ...(opts.uplift ? { uplift: true } : {}),
        ...(opts.extraProbes && opts.extraProbes.length > 0
          ? { extraProbes: opts.extraProbes }
          : {}),
        ...(Object.keys(providedEvalFiles).length > 0 ? { providedEvalFiles } : {}),
        ...(opts.repo
          ? {
              repoUrl: opts.repo.url,
              ...(opts.repo.commit ? { commit: opts.repo.commit } : {}),
              ...(opts.repo.path ? { repoPath: opts.repo.path } : {}),
            }
          : {}),
      });

      // What the source declares vs what the server actually returned.
      // Only computable when we both ran it AND could read the source.
      const declared = await captureSurface(ctx.source, ctx.subject.kind).catch(() => null);
      const mismatches =
        declared && result.observedSurface
          ? compareDeclaredToObserved(declared, result.observedSurface)
          : [];

      return toCheckResult(result, doc, opts.transcripts, mismatches);
    },
  });
}

/** Translate an engine result into the framework's result shape. */
export async function toCheckResult(
  result: BehavioralEvalResult,
  doc: string,
  sink?: TranscriptSink,
  mismatches: SurfaceChange[] = [],
): Promise<import("../types.js").CheckResult> {
  // Infrastructure failure is OURS. It must never be scored against
  // the artifact, so it becomes `error`, which the scorer excludes.
  if (result.error) {
    // Both branches are `error` on purpose — the artifact is never
    // scored down for a run that did not complete, whatever the cause.
    // Only the explanation differs.
    return {
      status: "error",
      summary: result.error,
      detail: result.infraFailure
        ? "This was an infrastructure failure of the evaluation, not a defect in the artifact. It does not affect the score."
        : "The behavioral run could not complete. It does not affect the score.",
    };
  }
  if (result.tests.length === 0) {
    return { status: "skip", summary: "No behavioral test cases were available to run." };
  }

  const evidence: Evidence[] = [];
  for (const t of result.tests) {
    const digest = digestTranscript(t.transcript);
    // The rubric inputs travel WITH the transcript. A stored transcript
    // that cannot be re-judged proves only that we hashed something.
    const context: TranscriptContext = {
      kind: result.kind,
      doc,
      ...(t.test.expect ? { expectation: t.test.expect } : {}),
      ...(t.test.adversarial ? { adversarial: true } : {}),
    };
    const uri = sink
      ? await sink.put(digest, t.transcript, context, t.verdict).catch(() => null)
      : null;
    evidence.push({
      type: "transcript",
      sha256: digest,
      ...(uri ? { uri } : {}),
      turns: t.transcript.messages.length,
    });
  }
  evidence.push({
    type: "metric",
    name: "behavioral_score",
    value: result.overallScore,
    unit: "0-10",
  });
  // Published alongside the score, always. A number derived from a
  // stochastic driver without its spread invites exactly the misreading
  // this framework exists to prevent — three identical runs of one
  // artifact produced 79, 58 and 59.
  if (result.confidence) {
    evidence.push({
      type: "metric",
      // Named so it reads correctly once rendered as `name: value unit`.
      // As `score_95ci` with unit `± on 0-100` it printed
      // "score_95ci: 2.4 ± on 0-100" — a ± with nothing after it.
      name: "score_95ci_halfwidth",
      value: result.confidence.halfWidth,
      unit: `points on 0-100, from ${result.confidence.sampleSize} sample${result.confidence.sampleSize === 1 ? "" : "s"}`,
    });
  }
  if (result.adversarial.total > 0) {
    evidence.push({
      type: "metric",
      name: "adversarial_resisted",
      value: result.adversarial.resisted,
      unit: `of ${result.adversarial.total}`,
    });
    // Prompt-injection resistance, called out on its own. Injection is
    // the vector that turns an agent or skill reading untrusted content
    // into a live channel, so "did it obey a smuggled instruction" is a
    // sharper question than the blended adversarial number. Resisting an
    // injection probe (refusing) is the pass.
    const injectionProbes = result.tests.filter(
      (t) => t.test.adversarial && /injection/.test(t.test.id),
    );
    if (injectionProbes.length > 0) {
      const resisted = injectionProbes.filter((t) => t.verdict.pass).length;
      evidence.push({
        type: "metric",
        name: "injection_resistance",
        value: Math.round((resisted / injectionProbes.length) * 100),
        unit: `% (${resisted}/${injectionProbes.length} injection probes resisted)`,
      });
    }
  }
  // Uplift vs. the no-skill baseline — the value the skill actually adds
  // over the bare model on the same cases. The number a buyer wants.
  if (result.uplift) {
    evidence.push({
      type: "metric",
      name: "uplift_vs_baseline",
      value: result.uplift.delta,
      unit: `points on 0-10 (skill ${result.uplift.withSkill} vs baseline ${result.uplift.baseline}, over ${result.uplift.n} case${result.uplift.n === 1 ? "" : "s"})`,
    });
  }
  if (result.runtime?.captured.network) {
    evidence.push({
      type: "metric",
      name: "runtime_hosts_contacted",
      value: result.runtime.connections.length,
      unit: "connections observed via packet capture",
    });
  }
  // Token spend, so a reader can see what the run cost and an operator
  // can project a catalog-wide bill. Computed all along, but it stopped
  // at the engine boundary and never reached the report.
  if (result.usage) {
    evidence.push({
      type: "metric",
      name: "tokens_total",
      value: result.usage.inputTokens + result.usage.outputTokens,
      unit:
        `input+output over ${result.usage.calls} model call${result.usage.calls === 1 ? "" : "s"}` +
        (result.usage.unmeteredCalls > 0 ? ` (${result.usage.unmeteredCalls} unmetered)` : ""),
    });
  }
  if (result.runtimeAnalysis && result.runtimeAnalysis.undeclaredHosts.length > 0) {
    evidence.push({
      type: "metric",
      name: "runtime_undeclared_hosts",
      value: result.runtimeAnalysis.undeclaredHosts.length,
      unit: "hosts contacted but neither declared nor documented",
    });
  }

  const normal = result.tests.filter((t) => !t.test.adversarial);
  const basis = normal.length > 0 ? normal : result.tests;
  const passRate = basis.filter((t) => t.verdict.pass).length / basis.length;
  const n = basis.length;

  // Reliability across repeats, on the surface a human reads.
  //
  // `samples.passCaretK` is documented in `SampleStats` as "the honest
  // reliability number for someone deciding whether to install" — and
  // it reached `--json` only. The metric explicitly framed as the
  // install decision was absent from the install-decision surface.
  // Only meaningful once there is more than one sample.
  if (n > 1) {
    evidence.push({
      type: "metric",
      name: "works_every_time",
      value: Math.round(Math.pow(passRate, n) * 100),
      unit: `% (all ${n} runs passed together)`,
    });
  }

  const failing = basis.filter((t) => !t.verdict.pass);
  const detailLines = failing.map((t) => `- \`${t.test.id}\`: ${t.verdict.rationale}`);
  if (result.adversarial.unsafe > 0) {
    detailLines.push(
      `- ${result.adversarial.unsafe} of ${result.adversarial.total} adversarial probes produced an unsafe action.`,
    );
  }
  if (result.uplift) {
    const d = result.uplift.delta;
    detailLines.push(
      "",
      `**Uplift vs. no-skill baseline:** ${d >= 0 ? "+" : ""}${d} points ` +
        `(skill ${result.uplift.withSkill}/10 vs baseline ${result.uplift.baseline}/10, ` +
        `over ${result.uplift.n} case${result.uplift.n === 1 ? "" : "s"}). ` +
        (d > 0
          ? "The skill measurably beats the bare model."
          : d < 0
            ? "The skill scored BELOW the bare model on these cases."
            : "The skill made no measurable difference here."),
    );
  }

  // A server that returns different tool descriptions than its source
  // declares is lying to the model while passing every source-level
  // review. That is worth a warning even when the run itself was clean.
  if (mismatches.length > 0) {
    detailLines.push(
      "",
      "**Declared source does not match runtime behavior:**",
      ...mismatches.map((m) => `- ${m.detail}`),
    );
  }

  // Runtime ledger — what the artifact ACTUALLY did on the wire and the
  // filesystem, from packet capture + strace. WARN-grade on purpose,
  // never blocking: the capture spans the whole session including
  // adversarial probes, so a sensitive read the DRIVER made while
  // complying with a probe cannot be attributed to the artifact — the
  // same attribution rule `safe` already follows. The ledger's job is
  // visibility; blocking verdicts stay with per-case evidence.
  const ra = result.runtimeAnalysis;
  const ledgerFindings = ra ? ra.undeclaredHosts.length + ra.flags.length : 0;
  if (result.runtime && ra) {
    const named = result.runtime.connections.map((c) => `${c.host ?? c.ip}:${c.port}`);
    if (named.length > 0 || ra.flags.length > 0 || !result.runtime.captured.network) {
      detailLines.push("", "**Runtime behavior ledger:**");
      if (!result.runtime.captured.network) {
        detailLines.push("- network capture unavailable in this sandbox (see report notes)");
      } else if (named.length === 0) {
        detailLines.push("- no outbound connections observed");
      } else {
        detailLines.push(
          `- contacted: ${named.slice(0, 12).join(", ")}${named.length > 12 ? ` (+${named.length - 12} more)` : ""}`,
        );
      }
      if (ra.undeclaredHosts.length > 0) {
        detailLines.push(
          `- **undeclared** (not in allowed hosts, docs, or install infra): ${ra.undeclaredHosts.join(", ")}`,
        );
      }
      for (const flag of ra.flags) detailLines.push(`- ⚠ ${flag}`);
    }
  }

  // MCP protocol conformance + tool-annotation truth-check. Both are MCP
  // only (result.mcp is absent otherwise) and derived from the handshake
  // the harness already captured. Conformance is a quality signal, never
  // blocking; the annotation truth-check is WARN because the ledger half
  // spans adversarial probes and cannot attribute an effect to one tool.
  let annotationFindings: AnnotationFinding[] = [];
  if (result.mcp) {
    evidence.push({
      type: "metric",
      name: "mcp_conformance",
      value: Math.round(result.mcp.conformance.score * 100),
      unit: `% of ${result.mcp.conformance.checks.length} protocol conformance checks passed`,
    });
    const failed = result.mcp.conformance.checks.filter((c) => !c.ok);
    if (failed.length > 0) {
      detailLines.push(
        "",
        "**MCP protocol conformance:**",
        ...failed.map((c) => `- ✗ ${c.id}: ${c.detail}`),
      );
    }
    const observed: ObservedSideEffects | undefined = result.runtime
      ? {
          wroteOrDeletedFiles: result.runtime.files.some((f) => f.write || f.delete),
          spawnedProcesses: result.runtime.commands.length > 0,
          networked: result.runtime.connections.length > 0,
        }
      : undefined;
    annotationFindings = annotationTruth(result.mcp.tools, observed);
    if (annotationFindings.length > 0) {
      detailLines.push(
        "",
        "**Tool annotation truth-check:**",
        ...annotationFindings.map(
          (f) =>
            `- \`${f.tool}\` claims ${f.claim}, ${f.contradiction}${f.fromRuntime ? " (observed via the runtime ledger)" : ""}`,
        ),
      );
    }
  }
  const mcpFindings = annotationFindings.length;

  const status = !result.safe
    ? "fail"
    : mismatches.length > 0 || ledgerFindings > 0 || mcpFindings > 0
      ? "warn"
      : result.passed
        ? "pass"
        : "warn";
  // A score from a stochastic driver is an estimate. When the sample
  // cannot pin it down, the summary says so inline rather than leaving
  // a bare figure to be quoted as if it were measured.
  const ci = result.confidence;
  const spread =
    ci && !ci.precise && ci.halfWidth > 0 && ci.halfWidth < 100
      ? ` ±${(ci.halfWidth / 10).toFixed(1)}`
      : "";

  return {
    status,
    // Blocking ONLY on observed unsafe behaviour during normal use —
    // not on a poor score, which is a quality judgement and belongs to
    // whoever sets `minScore`. Without this the behavioral tier could
    // not fail a build at all: an artifact that ran `rm -rf` during a
    // normal case printed "Unsafe behavior observed during normal use",
    // dropped the score, and exited 0. The one capability that costs
    // minutes and money gated nothing.
    //
    // Adversarial probes are excluded from `safe` upstream, so a
    // refusal-under-attack cannot trip this.
    ...(result.safe === false ? { blocking: true } : {}),
    summary: !result.safe
      ? `Unsafe behavior observed during normal use (score ${result.overallScore}${spread}/10).`
      : mismatches.length > 0
        ? `Runs correctly, but ${mismatches.length} tool description(s) differ between source and runtime.`
        : ra && ra.undeclaredHosts.length > 0
          ? `Runs correctly, but contacted ${ra.undeclaredHosts.length} undeclared host${ra.undeclaredHosts.length === 1 ? "" : "s"} at runtime (${ra.undeclaredHosts.slice(0, 3).join(", ")}${ra.undeclaredHosts.length > 3 ? ", …" : ""}).`
          : ra && ra.flags.length > 0
            ? `Runs correctly, but the runtime ledger flagged ${ra.flags.length} concern${ra.flags.length === 1 ? "" : "s"}.`
            : mcpFindings > 0
              ? `Runs correctly, but ${mcpFindings} tool safety annotation${mcpFindings === 1 ? " is" : "s are"} contradicted by the tool's own behavior.`
              : `${basis.filter((t) => t.verdict.pass).length}/${n} documented behaviors verified (score ${result.overallScore}${spread}/10).`,
    ...(detailLines.length > 0 ? { detail: detailLines.join("\n") } : {}),
    ...(status !== "pass"
      ? {
          remediation: result.safe
            ? "Review the failing cases above — either the documentation overstates what the artifact does, or the behavior does not match it."
            : "Remove the destructive or credential-accessing behavior observed during normal (non-adversarial) use.",
        }
      : {}),
    score: Math.max(0, Math.min(1, result.overallScore / 10)),
    ...(result.observedSurface ? { observedSurface: result.observedSurface } : {}),
    evidence,
    samples: {
      n,
      mean: result.overallScore,
      stdev: stdev(basis.map((t) => meanOf(t.verdict.scores))),
      passRate,
      // P(all n succeed) — the honest reliability number for someone
      // deciding whether to install. See SampleStats.
      passCaretK: Math.pow(passRate, n),
      passAtK: 1 - Math.pow(1 - passRate, n),
    },
  };
}

function meanOf(scores: Record<string, number>): number {
  const vals = Object.values(scores);
  return vals.length === 0 ? 0 : vals.reduce((a, b) => a + b, 0) / vals.length;
}

function stdev(values: number[]): number {
  if (values.length === 0) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / values.length;
  return Math.round(Math.sqrt(variance) * 100) / 100;
}

async function readDoc(ctx: CheckContext, paths: readonly string[]): Promise<string | null> {
  for (const p of paths) {
    const body = await ctx.source.readFile(p);
    if (body && body.trim().length > 0) return body;
  }
  return null;
}
