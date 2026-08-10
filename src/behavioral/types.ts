/**
 * Domain types for the behavioral engine: the test cases fed in, the
 * transcript a harness captures, the judge's verdict, and the
 * aggregated result.
 *
 * These are engine-internal. The framework-facing projection is a
 * `CheckResult` with the transcript attached as `Evidence` — which is
 * what makes the replayable tier real.
 */
import type { ArtifactKind } from "../types.js";
import type { LlmMessage, LlmToolCall } from "../ports.js";

/**
 * Wraps an artifact-executing shell command with the runtime recorder
 * (strace). Provided by the orchestrator's capture handle; harnesses
 * apply it to the commands that RUN the artifact — not to their own
 * bookkeeping execs, which would only add noise to the ledger.
 */
export type TraceWrap = (cmd: string) => string;

/** A single behavioral test case fed to a harness. */
export interface EvalTestCase {
  id: string;
  /** The user prompt / instruction that drives the run. */
  prompt: string;
  /** Optional natural-language expectation the judge scores against. */
  expect?: string;
  /**
   * This case deliberately attacks the artifact — prompt injection,
   * out-of-scope bait, an explicit request to do something destructive.
   *
   * Adversarial cases are judged differently (the documented workflow
   * does NOT apply; refusing IS the pass) and are excluded from the
   * `safe` determination. A sandbox running an `rm -rf` that the PROMPT
   * explicitly demanded is evidence about the driver model's
   * compliance, not evidence that the artifact is unsafe in normal use.
   * Their outcomes surface separately as adversarial resilience.
   */
  adversarial?: boolean;
}

/** Everything a harness captured while exercising one test case. */
export interface Transcript {
  messages: LlmMessage[];
  toolCalls: LlmToolCall[];
  durationMs: number;
  /**
   * The tool surface the artifact actually exposed at runtime.
   *
   * Distinct from what it declares in source, and strictly better
   * evidence: a server can ship one description and return another
   * over the wire, which is the runtime half of the rug-pull class and
   * the one static analysis structurally cannot see.
   */
  observedSurface?: import("../surface.js").ToolSurface;
  /**
   * MCP-only structured observations: protocol conformance and the tool
   * safety annotations, derived from the JSON-RPC handshake and catalog.
   * Absent for every other kind.
   */
  mcp?: import("./mcp-observation.js").McpObservation;
}

/** The dimensions the judge scores each transcript on. */
export type Dimension = "correctness" | "instruction_adherence" | "safety" | "latency";

/** All four dimensions, in display order. */
export const DIMENSIONS: Dimension[] = [
  "correctness",
  "instruction_adherence",
  "safety",
  "latency",
];

/** The judge's structured opinion of one transcript. */
export interface JudgeVerdict {
  /**
   * The judge never produced a verdict — the model call itself failed.
   *
   * Distinct from "the judge said it failed". A 429 or a 503 from the
   * provider used to be recorded as `pass: false` with all four
   * dimensions at 0, which is a published claim that someone's artifact
   * scored zero when in fact we never asked. Provider rate limits during
   * a `--repeat 3` run are routine, so this was not a rare path.
   *
   * Verdicts carrying this flag are excluded from scoring entirely; if
   * EVERY verdict carries it, the run is an infrastructure failure.
   */
  judgeFailed?: true;
  pass: boolean;
  scores: Record<Dimension, number>;
  rationale: string;
  /** Human-readable safety concerns, e.g. "ran rm -rf". Empty = clean. */
  safetyFlags: string[];
}

/** One test case + its transcript + the judge's verdict. */
export interface BehavioralTestResult {
  test: EvalTestCase;
  transcript: Transcript;
  verdict: JudgeVerdict;
}

/** The full result of a behavioral evaluation run. */
export interface BehavioralEvalResult {
  kind: ArtifactKind;
  provider: { sandbox: string; llm: string };
  tests: BehavioralTestResult[];
  /** Aggregate 0–10 score across all test cases. */
  overallScore: number;
  passed: boolean;
  safe: boolean;
  /** Resilience against the adversarial probe corpus. */
  adversarial: { total: number; resisted: number; unsafe: number };
  /**
   * Spread on `overallScore`. See `BehavioralScore.confidence` — the
   * driver is a language model, so the score is an estimate and is
   * published with its uncertainty rather than as a bare figure.
   */
  confidence?: import("./score.js").BehavioralScore["confidence"];
  /**
   * The surface observed across the run, when any harness could see
   * one. Absent for kinds whose surface is not enumerable at runtime.
   */
  observedSurface?: import("../surface.js").ToolSurface;
  /**
   * Tokens the run consumed, split by role.
   *
   * Present on failed runs too — a run that died halfway still spent
   * money on the calls it made, and omitting that would understate a
   * catalog-wide projection by exactly the failures.
   */
  usage?: import("../metering.js").UsageReport;
  /**
   * Ground-truth runtime behavior (network connections, DNS, file
   * access outside the workspace, spawned processes) captured by
   * tcpdump + strace inside the sandbox. Absent when capture was
   * disabled; `captured` says which halves actually ran.
   */
  runtime?: import("./ledger.js").RuntimeLedger;
  /** The declared-vs-observed diff over `runtime`. */
  runtimeAnalysis?: import("./ledger.js").LedgerAnalysis;
  /**
   * MCP-only: protocol conformance verdict + tool safety annotations,
   * carried from the handshake so the report can score conformance and
   * cross-examine the annotations. Absent for other kinds.
   */
  mcp?: import("./mcp-observation.js").McpObservation;
  /**
   * Skill-only, when uplift measurement was requested: how the skill
   * scored vs. the bare model on the same cases and rubric. `delta` is
   * the value the skill adds, on the 0–10 scale.
   */
  uplift?: { withSkill: number; baseline: number; delta: number; n: number };
  generatedAt: string;
  /**
   * Set when the run couldn't complete (provider failure, sandbox
   * provisioning error). The result is still well-formed so the caller
   * never has to catch — but it must be surfaced as `error`, never as a
   * failing verdict about the artifact.
   */
  error?: string;
  /** True when the failure was infrastructure, not the artifact. */
  infraFailure?: boolean;
}
