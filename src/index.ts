/**
 * Assay — an open framework for evaluating AI artifacts.
 *
 * Public surface. Everything exported here is contract; anything
 * reachable only by deep import is not.
 */
export * from "./types.js";
// `LlmRole` is re-exported by types.js; ports.js only imports it.
export type {
  Logger,
  TreeEntry,
  SourceReader,
  NetClient,
  ExecResult,
  Sandbox,
  SandboxSpec,
  SandboxProvider,
  SandboxRunner,
  LlmMessage,
  LlmToolCall,
  LlmTool,
  LlmResponse,
  LlmProvider,
  ResultCache,
} from "./ports.js";
export {
  SandboxInfraError,
  isSandboxInfraError,
  registerSandboxProvider,
  getSandboxProvider,
  registerLlmProvider,
  getLlmProvider,
  _resetProviders,
} from "./ports.js";
export { defineCheck, CheckRegistry, WELL_KNOWN_CATEGORIES } from "./check.js";
export type { CheckContext, CheckDefinition } from "./check.js";
export { runAssay, deriveValidity } from "./run.js";
export type { RunOptions } from "./run.js";
export { scoreReport, DEFAULT_FORMULA } from "./score.js";
export type { ScoreOptions } from "./score.js";
export {
  digestTree,
  digestSuite,
  digestEnvironment,
  checkCacheKey,
  canonicalizeForSigning,
  canonicalizeForComparison,
  pae,
} from "./digest.js";
export {
  DEFAULT_CHECKS,
  CORE_CHECKS,
  INTEGRITY_CHECKS,
  DOCUMENTATION_CHECKS,
  SUPPLY_CHAIN_CHECKS,
  SKILL_CHECKS,
  MCP_CHECKS,
  AGENT_CHECKS,
  PLUGIN_CHECKS,
} from "./checks/index.js";
export { parseFrontmatter, parseList, countWords, readManifest } from "./checks/manifest.js";
export { createBehavioralCheck, digestTranscript } from "./checks/behavioral.js";
export type { BehavioralCheckOptions, TranscriptSink } from "./checks/behavioral.js";
// Behavioral engine — exported so a host can drive it directly, and so
// third-party checks can reuse the judge and scorer.
export { runBehavioralEval, computeSandboxTimeoutMs } from "./behavioral/run.js";
export type { RunBehavioralInput, CaseCache } from "./behavioral/run.js";
export {
  judgeTranscript,
  safetyScan,
  parseVerdict,
  extractVerdictJson,
  clampMiddle,
  transcriptToText,
  buildRubric,
  DEFAULT_JUDGE_CONFIG,
} from "./behavioral/judge.js";
export type { JudgeConfig } from "./behavioral/judge.js";
export { scoreResults, verdictMean, DEFAULT_PASS_RATIO } from "./behavioral/score.js";
export type { BehavioralScore } from "./behavioral/score.js";
export { loadTestCases, parseEvalFile, extractJsonArray } from "./behavioral/test-cases.js";
export { getProbeCases, probeCorpusDigest, PROBE_CAP_DEFAULT } from "./behavioral/probes.js";
export { DIMENSIONS } from "./behavioral/types.js";
export type {
  EvalTestCase,
  Transcript,
  Dimension,
  JudgeVerdict,
  BehavioralTestResult,
  BehavioralEvalResult,
} from "./behavioral/types.js";
export { MemorySource } from "./sources/memory.js";
export { DirectorySource } from "./sources/directory.js";
export type { DirectorySourceOptions } from "./sources/directory.js";
export { ASSAY_VERSION } from "./version.js";

// ── attestation ──────────────────────────────────────────────────────
export { generateKeyPair, keyidFor, signReport, verifyReport, PAYLOAD_TYPE } from "./attest.js";
export type { KeyPair, VerificationResult, VerificationFinding, VerifyOptions } from "./attest.js";

// ── transcripts and replay ───────────────────────────────────────────
export { FileTranscriptSink, loadTranscript, replayTranscript } from "./transcripts.js";
export type { StoredTranscript, ReplayOutcome } from "./transcripts.js";
export type { TranscriptContext } from "./checks/behavioral.js";
