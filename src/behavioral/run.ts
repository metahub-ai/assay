/**
 * Behavioral orchestrator. Given an artifact and its source context it:
 *
 *   1. loads or synthesizes the test cases,
 *   2. provisions a sandbox and materializes the artifact into it,
 *   3. dispatches to the kind-specific harness,
 *   4. judges each transcript, and
 *   5. aggregates.
 *
 * It NEVER throws: a provider or provisioning failure is wrapped into a
 * well-formed result. Crucially it distinguishes an INFRASTRUCTURE
 * failure from an artifact failure via `infraFailure`, because the
 * caller must report the former as `error` — our sandbox dying is not
 * evidence about someone else's code.
 *
 * Ported from the production pipeline. Two things are deliberately left
 * behind: the Postgres-backed case cache (a host concern — the
 * framework exposes a `CaseCache` port instead) and badge derivation (a
 * marketplace concern).
 */
import type { ArtifactKind } from "../types.js";
import {
  isSandboxInfraError,
  type SourceReader,
  type LlmProvider,
  type Sandbox,
  type SandboxProvider,
  type SandboxSpec,
} from "../ports.js";
import { meterLlm } from "../metering.js";
import { startCapture, collectCapture, type CaptureHandle } from "./capture.js";
import { analyzeLedger } from "./ledger.js";
import { judgeTranscript, type JudgeConfig } from "./judge.js";
import { scoreResults, verdictMean, DEFAULT_PASS_RATIO } from "./score.js";
import { loadTestCases } from "./test-cases.js";
import { runSkillCase } from "./harness/skill.js";
import { runMcpCase } from "./harness/mcp.js";
import { runAgentCase } from "./harness/agent.js";
import { runPluginCase } from "./harness/plugin.js";
import type { BehavioralEvalResult, BehavioralTestResult, EvalTestCase } from "./types.js";

/**
 * Fallback workspace root, used only when an adapter doesn't declare
 * its own writable `workdir`. Adapters SHOULD declare one — this
 * default is only safe on root-running sandboxes like podman.
 */
const DEFAULT_WORKSPACE = "/workspace";

/**
 * Optional cache for synthesized cases.
 *
 * Cases are LLM-synthesized, so re-evaluating the same commit would
 * otherwise run DIFFERENT prompts and produce an incomparable score.
 * The framework defines the port; the host decides where it lives.
 */
export interface CaseCache {
  get(key: string): Promise<EvalTestCase[] | null>;
  set(key: string, cases: EvalTestCase[]): Promise<void>;
}

export interface RunBehavioralInput {
  kind: ArtifactKind;
  /** Artifact doc — system prompt and synthesis context. */
  doc: string;
  sandboxProvider: SandboxProvider;
  llm: LlmProvider;
  /** `allowed-tools` from the manifest, surfaced to the skill harness. */
  allowedTools?: string[];
  /** Hosts the artifact legitimately talks to. */
  allowedHosts?: string[];
  triggers?: string[];
  description?: string;
  /** Pre-fetched `evals/*.json` contents keyed by path. */
  providedEvalFiles?: Record<string, string>;
  caseCount?: number;
  /** Adversarial probes to layer on. 0 opts out. */
  probeCount?: number;
  /** Extra adversarial probes from community plugins (always run). */
  extraProbes?: import("./types.js").EvalTestCase[];
  sandboxSpec?: SandboxSpec;
  /**
   * Prompt-based agent (a Claude-Code-style `.claude/agents/<name>.md`):
   * the markdown body IS the agent, so it runs through the LLM-loop
   * harness like a skill rather than the install-and-exec path.
   */
  promptBased?: boolean;
  /**
   * Local source to copy into the sandbox, for harnesses that need real
   * files on disk.
   *
   * Without this, a run against a local directory provisions an EMPTY
   * workspace: `npm install` fails with ENOENT, the MCP driver times
   * out on initialize, and the judge scores a transcript of that
   * failure as though it said something about the artifact. Skills
   * happen to survive it — their harness drives the model from the doc
   * and never touches the filesystem — which is exactly why the bug
   * was invisible.
   */
  materialize?: SourceReader;
  /** Repo to clone for harnesses that need real files on disk. */
  repoUrl?: string;
  /** Commit to check out. Required when `repoUrl` is set. */
  commit?: string;
  /** Sub-path within the repo where the artifact lives. */
  repoPath?: string;
  judgeConfig?: Partial<JudgeConfig>;
  passRatio?: number;
  /** Concurrency for prompt-driven cases. */
  caseConcurrency?: number;
  /**
   * How many times to run each case.
   *
   * The driver is a language model, so the same prompt against the same
   * artifact does not produce the same run. With a single sample and a
   * handful of cases, one case flipping moves the headline score by tens
   * of points — the PDF skill scored 79, 58 and 59 on three identical
   * invocations for exactly this reason. Repeating each case and taking
   * the mean is the standard answer, and it costs k× to buy it.
   */
  repeat?: number;
  /**
   * Also run each normal case WITHOUT the skill and report the delta —
   * the uplift-vs-baseline measurement. Skill-only, opt-in (roughly
   * doubles the normal-case cost).
   */
  uplift?: boolean;
  caseCache?: CaseCache;
  /** Cache key; required for the cache to be consulted. */
  caseCacheKey?: string;
  /**
   * Capture ground-truth runtime behavior (tcpdump + strace) during the
   * run. Default true — capture is best-effort and degrades to notes,
   * so the only reason to disable it is a sandbox where the setup cost
   * (a one-time apt-get) is unwelcome.
   */
  captureRuntime?: boolean;
}

function failedResult(
  input: RunBehavioralInput,
  providers: { sandbox: string; llm: string },
  error: string,
  infraFailure: boolean,
): BehavioralEvalResult {
  return {
    kind: input.kind,
    provider: providers,
    tests: [],
    overallScore: 0,
    passed: false,
    safe: false,
    adversarial: { total: 0, resisted: 0, unsafe: 0 },
    generatedAt: new Date().toISOString(),
    error,
    infraFailure,
  };
}

/**
 * Clone the artifact at the pinned commit into the sandbox's writable
 * root. Throws on failure so the orchestrator can wrap it.
 */
async function provisionWorkspace(sandbox: Sandbox, input: RunBehavioralInput): Promise<string> {
  // Vendor-declared writable root. `/workspace` is NOT writable on an
  // E2B sandbox (unprivileged user), which failed every clone there.
  const workspace = sandbox.workdir ?? DEFAULT_WORKSPACE;
  if (!input.repoUrl) {
    await sandbox.exec(`mkdir -p ${workspace}`, { timeoutMs: 30_000 });
    if (input.materialize) await copyInto(sandbox, workspace, input.materialize);
    return workspace;
  }
  await sandbox.exec(`mkdir -p ${workspace} && rm -rf ${workspace}`, { timeoutMs: 30_000 });

  // Blobless shallow clone plus a targeted fetch of the pinned commit:
  // a few hundred KB instead of the whole history. Fall back to a plain
  // full clone when the remote or an old git rejects the filtered
  // fetch — correctness over savings.
  const ref = input.commit ? JSON.stringify(input.commit) : "";
  const clone = await sandbox.exec(
    `git clone --depth 1 --filter=blob:none ${JSON.stringify(input.repoUrl)} ${workspace}` +
      (ref ? ` && cd ${workspace} && (git fetch --depth 1 origin ${ref} || git fetch origin)` : ""),
    { timeoutMs: 180_000 },
  );
  if (clone.exitCode !== 0) {
    const full = await sandbox.exec(
      `rm -rf ${workspace} && git clone ${JSON.stringify(input.repoUrl)} ${workspace}`,
      { timeoutMs: 180_000 },
    );
    if (full.exitCode !== 0) {
      throw new Error(`git clone failed (exit ${full.exitCode}): ${full.stderr.trim()}`);
    }
  }
  if (input.commit) {
    const checkout = await sandbox.exec(`git checkout ${JSON.stringify(input.commit)}`, {
      cwd: workspace,
      timeoutMs: 60_000,
    });
    if (checkout.exitCode !== 0) {
      throw new Error(`git checkout ${input.commit} failed: ${checkout.stderr.trim()}`);
    }
  }
  return input.repoPath ? `${workspace}/${input.repoPath.replace(/^\/+|\/+$/g, "")}` : workspace;
}

/** Ceiling on what we push into a sandbox, per file and in total. */
const MAX_MATERIALIZE_BYTES = 32 * 1024 * 1024;
const MAX_MATERIALIZE_FILES = 5_000;

/**
 * Copy a local artifact into the sandbox.
 *
 * Batched into one `writeFiles` call because a per-file round trip to a
 * cloud sandbox costs 100–300ms each, and a few hundred files would
 * otherwise dominate the run. Binary files are skipped rather than
 * corrupted: the harnesses read source and manifests, and silently
 * mangling a `.png` into UTF-8 would be worse than omitting it.
 */
async function copyInto(sandbox: Sandbox, workspace: string, source: SourceReader): Promise<void> {
  const tree = await source.listTree();
  const files: { path: string; contents: string }[] = [];
  let bytes = 0;
  for (const entry of tree) {
    if (entry.type !== "file") continue;
    if (files.length >= MAX_MATERIALIZE_FILES || bytes >= MAX_MATERIALIZE_BYTES) break;
    const contents = await source.readFile(entry.path);
    if (contents === null) continue;
    bytes += contents.length;
    files.push({ path: `${workspace}/${entry.path}`, contents });
  }
  if (files.length > 0) await sandbox.writeFiles(files);
}

/**
 * Sandbox lifetime computed from the actual work plan rather than a
 * flat timeout.
 *
 * A fixed 5-minute cap was far below the real budget for non-skill
 * kinds — `npm install` at 180s plus driver passes can reach ~450s PER
 * CASE, serially — so the provider auto-killed the sandbox mid-run and
 * the death was recorded as a failing eval. That is the single most
 * expensive class of false negative this pipeline can produce.
 */
export function computeSandboxTimeoutMs(
  kind: ArtifactKind,
  caseCount: number,
  promptBased = false,
): number {
  const PER_CASE_MS: Record<string, number> = {
    // Skills run cases concurrently; sandbox execs are 30s-capped tool
    // calls, so the per-case budget stays small.
    skill: 90_000,
    // npm install (180s) + two driver passes (90s + 180s), serial.
    mcp: 480_000,
    agent: 300_000,
    plugin: 400_000,
  };
  const clone = 180_000 + 60_000;
  const slack = 120_000;
  // A prompt-based agent costs what a skill costs (LLM loop, no
  // install/exec), not what a code-based agent costs.
  const perCase = promptBased ? PER_CASE_MS["skill"]! : (PER_CASE_MS[kind] ?? 300_000);
  // Prompt-driven cases run concurrently — budget ~3 waves, not N serial.
  const effectiveCases =
    kind === "skill" || promptBased ? Math.min(3, Math.max(1, caseCount)) : caseCount;
  const total = clone + perCase * Math.max(1, effectiveCases) + slack;
  return Math.min(45 * 60_000, Math.max(5 * 60_000, total));
}

/** Bounded-concurrency map — avoids hammering the judge with N×turns. */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]!, i);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function runBehavioralEval(raw: RunBehavioralInput): Promise<BehavioralEvalResult> {
  // Metering wraps the provider once, here, so every LLM call the run
  // makes is counted no matter which harness makes it. Doing it at the
  // adapters instead would mean a newly-added adapter is silently
  // unmetered, and a run that reports no cost is indistinguishable from
  // one that was free.
  const metered = meterLlm(raw.llm);
  const input: RunBehavioralInput = { ...raw, llm: metered };
  const providers = { sandbox: input.sandboxProvider.name, llm: input.llm.name };
  let sandbox: Sandbox | null = null;
  try {
    let cases: EvalTestCase[] | null = null;
    if (input.caseCache && input.caseCacheKey) {
      cases = await input.caseCache.get(input.caseCacheKey);
    }
    if (!cases) {
      cases = await loadTestCases({
        llm: input.llm,
        doc: input.doc,
        kind: input.kind,
        ...(input.providedEvalFiles ? { providedEvalFiles: input.providedEvalFiles } : {}),
        ...(input.triggers ? { triggers: input.triggers } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
        ...(input.caseCount !== undefined ? { count: input.caseCount } : {}),
        ...(input.probeCount !== undefined ? { probeCount: input.probeCount } : {}),
        ...(input.extraProbes ? { extraProbes: input.extraProbes } : {}),
      });
      if (input.caseCache && input.caseCacheKey) {
        await input.caseCache.set(input.caseCacheKey, cases);
      }
    }

    // Provisioning needs egress; the harness run is isolated afterwards
    // unless the caller overrides.
    sandbox = await input.sandboxProvider.create(
      input.sandboxSpec ?? {
        networkEgress: true,
        timeoutMs: computeSandboxTimeoutMs(
          input.kind,
          cases.length * Math.max(1, Math.floor(input.repeat ?? 1)),
          input.promptBased === true,
        ),
      },
    );

    const cwd = await provisionWorkspace(sandbox, input);

    // Ground-truth recorders start BEFORE any artifact code runs, so
    // install-time behavior is captured too (install traffic to package
    // registries is infra-allowlisted at analysis time, not hidden).
    let capture: CaptureHandle | null = null;
    if (input.captureRuntime !== false) {
      capture = await startCapture(sandbox);
    }

    // Skill cases are independent prompt runs sharing no state, so the
    // only contention is the filesystem. Give each its own subdirectory
    // and run them concurrently — wall clock drops from sum(case) to
    // max(case), the dominant per-job cost.
    //
    // Non-skill kinds stay SERIAL: their harnesses spawn long-running
    // servers that would collide on ports and process namespace if run
    // in parallel against one sandbox.
    const promptDriven = input.kind === "skill" || input.promptBased === true;

    // Repeat each case k times. The ids stay distinguishable so a
    // transcript can be traced back to which attempt produced it, while
    // `sampleOf` keeps the grouping for the variance calculation.
    const repeat = Math.max(1, Math.floor(input.repeat ?? 1));
    const sampled: EvalTestCase[] =
      repeat === 1
        ? cases
        : cases.flatMap((c) =>
            Array.from({ length: repeat }, (_, r) => ({ ...c, id: `${c.id}#${r + 1}` })),
          );
    const judgeOne = async (test: EvalTestCase, caseCwd: string): Promise<BehavioralTestResult> => {
      const transcript = await runCaseForKind(input, sandbox!, input.llm, caseCwd, test, capture);
      const verdict = await judgeTranscript({
        llm: input.llm,
        kind: input.kind,
        doc: input.doc,
        transcript,
        config: {
          ...(input.judgeConfig ?? {}),
          ...(input.allowedHosts ? { allowedHosts: input.allowedHosts } : {}),
        },
        ...(test.expect ? { expectation: test.expect } : {}),
        ...(test.adversarial ? { adversarial: true } : {}),
      });
      return { test, transcript, verdict };
    };

    let tests: BehavioralTestResult[];
    if (promptDriven && sampled.length > 1) {
      // Pre-create one subdir per case in a single batched exec — each
      // cloud-sandbox round trip is 100–300ms of pure overhead.
      //
      // And POPULATE each one with the artifact. They used to be created
      // empty, so every relative path in a skill's own instructions
      // resolved nowhere — which is precisely the skills that ship
      // helper scripts (`pdf`, `pptx`, `docx`, `xlsx` all run
      // `python scripts/...`). The artifact was materialised once at
      // `cwd` and then every case ran somewhere else.
      //
      // Copied rather than symlinked so a case that writes cannot
      // corrupt the pristine tree or another case's view of it.
      const subDirs = sampled.map((_, i) => `${cwd}/case-${i}`);
      const populate = subDirs
        .map(
          (d) =>
            `mkdir -p ${JSON.stringify(d)} && ` +
            `(cp -R ${JSON.stringify(`${cwd}/.`)} ${JSON.stringify(d)} 2>/dev/null || true) && ` +
            // Remove the sibling case dirs that the copy just pulled in.
            `rm -rf ${JSON.stringify(`${d}/case-`)}*`,
        )
        .join(" ; ");
      await sandbox.exec(populate, { timeoutMs: 120_000 });
      // Bounded concurrency: an unbounded Promise.all fired N cases ×
      // up to 6 turns at the judge simultaneously, which is how runs
      // tripped provider rate limits.
      tests = await mapWithConcurrency(
        sampled,
        Math.max(1, input.caseConcurrency ?? 3),
        (test, i) => judgeOne(test, subDirs[i]!),
      );
    } else {
      tests = [];
      for (const test of sampled) tests.push(await judgeOne(test, cwd));
    }

    const score = scoreResults(tests, input.passRatio ?? DEFAULT_PASS_RATIO);

    // Uplift vs. no-skill baseline — the one number a buyer actually
    // wants: does this skill beat the bare model? Opt-in (it re-runs each
    // normal case without the skill instructions, so it roughly doubles
    // the normal-case cost) and skill-only. The baseline is judged
    // against the SAME documentation rubric, so the delta is "how much
    // closer to the documented behavior the skill gets you".
    let uplift: BehavioralEvalResult["uplift"];
    if (input.uplift && input.kind === "skill" && tests.length > 0) {
      const normal = tests.filter((t) => !t.test.adversarial);
      const seen = new Set<string>();
      const unique = normal.filter((t) =>
        seen.has(t.test.prompt) ? false : (seen.add(t.test.prompt), true),
      );
      const withSkill = unique.map((t) => verdictMean(t.verdict));
      const baseline: number[] = [];
      for (const t of unique) {
        const bt = await runSkillCase({
          llm: input.llm,
          sandbox,
          skillDoc: input.doc,
          cwd,
          baseline: true,
          ...(input.allowedTools ? { allowedTools: input.allowedTools } : {}),
          test: t.test,
        });
        const v = await judgeTranscript({
          llm: input.llm,
          kind: input.kind,
          doc: input.doc,
          transcript: bt,
          config: {
            ...(input.judgeConfig ?? {}),
            ...(input.allowedHosts ? { allowedHosts: input.allowedHosts } : {}),
          },
          ...(t.test.expect ? { expectation: t.test.expect } : {}),
        });
        if (!v.judgeFailed) baseline.push(verdictMean(v));
      }
      if (withSkill.length > 0 && baseline.length > 0) {
        const mean = (a: number[]) => a.reduce((x, y) => x + y, 0) / a.length;
        const r1 = (x: number) => Math.round(x * 10) / 10;
        const w = mean(withSkill);
        const b = mean(baseline);
        uplift = { withSkill: r1(w), baseline: r1(b), delta: r1(w - b), n: baseline.length };
      }
    }

    // Every case sees the same server, so the first surface any harness
    // observed is the surface. Taking the first rather than merging is
    // deliberate: if two cases somehow saw DIFFERENT surfaces that is a
    // finding in itself, and silently unioning them would hide it.
    const observedSurface = tests.find((t) => t.transcript.observedSurface)?.transcript
      .observedSurface;
    // The MCP observation (conformance + annotations) is the same across
    // cases — it comes from the one handshake — so the first is
    // representative.
    const mcp = tests.find((t) => t.transcript.mcp)?.transcript.mcp;

    // Collect the ledger AFTER the harness is done — collection kills
    // the recorders. Best-effort: a collection failure becomes notes on
    // the ledger, never a failed eval.
    let runtime;
    let runtimeAnalysis;
    if (capture) {
      runtime = await collectCapture(sandbox, capture, cwd);
      runtimeAnalysis = analyzeLedger(runtime, {
        ...(input.allowedHosts ? { declaredHosts: input.allowedHosts } : {}),
        docText: input.doc,
      });
    }
    return {
      kind: input.kind,
      provider: providers,
      tests,
      overallScore: score.overallScore,
      passed: score.passed,
      safe: score.safe,
      adversarial: score.adversarial,
      confidence: score.confidence,
      ...(observedSurface ? { observedSurface } : {}),
      ...(mcp ? { mcp } : {}),
      ...(uplift ? { uplift } : {}),
      ...(runtime ? { runtime } : {}),
      ...(runtimeAnalysis ? { runtimeAnalysis } : {}),
      usage: metered.usage(),
      generatedAt: new Date().toISOString(),
    };
  } catch (err) {
    // The distinction that matters: our sandbox dying is not evidence
    // about the artifact, and the caller must not record it as one.
    // A run that died halfway still spent money on the calls it made,
    // and dropping that usage would understate the catalog's true cost
    // by exactly the failures — the runs an operator most wants to
    // account for.
    return {
      ...failedResult(
        input,
        providers,
        `Behavioral eval failed: ${(err as Error).message}`,
        isSandboxInfraError(err),
      ),
      usage: metered.usage(),
    };
  } finally {
    // Best-effort teardown — never let a close error mask the result.
    if (sandbox) await sandbox.close().catch(() => undefined);
  }
}

async function runCaseForKind(
  input: RunBehavioralInput,
  sandbox: Sandbox,
  llm: LlmProvider,
  cwd: string,
  test: EvalTestCase,
  capture: CaptureHandle | null,
) {
  // Harnesses wrap the commands that EXECUTE the artifact with this, so
  // the artifact's whole process tree lands in the strace ledger.
  const traceWrap = capture ? (cmd: string) => capture.wrap(cmd) : undefined;
  const skillArgs = {
    llm,
    sandbox,
    skillDoc: input.doc,
    cwd,
    ...(input.allowedTools ? { allowedTools: input.allowedTools } : {}),
    ...(traceWrap ? { traceWrap } : {}),
    test,
  };
  switch (input.kind) {
    case "mcp":
      return runMcpCase({ llm, sandbox, cwd, test, ...(traceWrap ? { traceWrap } : {}) });
    case "agent":
      // A prompt-based agent has no entry file to install and execute —
      // it is a system prompt plus a tool scope, so it runs the same
      // LLM-with-sandbox-tools loop a skill does.
      return input.promptBased
        ? runSkillCase(skillArgs)
        : runAgentCase({ sandbox, cwd, test, ...(traceWrap ? { traceWrap } : {}) });
    case "plugin":
      return runPluginCase({
        llm,
        sandbox,
        cwd,
        skillDoc: input.doc,
        test,
        ...(traceWrap ? { traceWrap } : {}),
      });
    case "skill":
    default:
      return runSkillCase(skillArgs);
  }
}
