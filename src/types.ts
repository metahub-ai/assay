/**
 * Assay core types — the wire format of an artifact evaluation.
 *
 * This file is the contract. Everything else in the framework is an
 * implementation detail that can change; these shapes are what a
 * registry renders, what a CI job asserts against, and what a third
 * party re-verifies. Treat additions as cheap and removals as breaking.
 *
 * The design goal that drives every decision here is FALSIFIABILITY. A
 * score nobody can check is marketing. So every result carries enough
 * information for a stranger to answer three questions without our
 * cooperation:
 *
 *   1. What exactly was evaluated?      → `Subject.digest`
 *   2. What code produced this verdict? → `checkId` + `checkVersion` + `suite`
 *   3. Why should I believe it?         → `evidence` + `determinism`
 *
 * The current portal schema (`EvalCheck` in @metahub/shared) answers
 * none of the three: it is `{id, label, status, message}` with no
 * version, no evidence, and no way to distinguish "the artifact failed"
 * from "our checker crashed".
 */

/**
 * Artifact kinds. Open by construction — a `string` with well-known
 * constants rather than a closed union.
 *
 * The portal's `ArtifactKind` is a fixed 4-member union, which means a
 * third party cannot evaluate a kind we didn't anticipate without
 * patching a shared package. For a framework meant to outlive our
 * current catalog (Claude skills, MCP servers, agents, plugins — none
 * of which existed 3 years ago), that ceiling is the wrong default.
 */
export type ArtifactKind = (typeof WELL_KNOWN_KINDS)[number] | (string & {});

export const WELL_KNOWN_KINDS = ["skill", "mcp", "agent", "plugin"] as const;

/**
 * Outcome of a single check.
 *
 * `error` exists because the portal schema's biggest correctness bug is
 * that it cannot express "we failed, not you". When a sandbox times out
 * or an LLM provider 500s today, the artifact is recorded as *failing*
 * a behavioral check — an infrastructure hiccup becomes a permanent
 * public mark against someone's work. `error` is never counted against
 * a subject and never blocks a publish; it is an operational signal.
 *
 * `neutral` is for "we looked, this genuinely does not apply, and that
 * is not a deficiency" (a Python MCP server has no `package.json` to
 * validate). Distinct from `skip`, which means we did not look.
 */
export type CheckStatus = "pass" | "warn" | "fail" | "neutral" | "skip" | "error";

/** Statuses that reflect a judgement about the subject. */
export const JUDGING_STATUSES: readonly CheckStatus[] = ["pass", "warn", "fail"];

/**
 * How reproducible a check's verdict is. This is the framework's
 * central idea, so it is worth being precise about what each tier
 * PROMISES rather than what it happens to do.
 *
 * - `deterministic` — a pure function of the subject bytes and the
 *   check version. Re-running in 2030 on the same digest yields a
 *   byte-identical result. Enforced, not asserted: a deterministic
 *   check may not declare any capability (see `Capability`), so it
 *   *cannot* reach the network, a model, a clock, or an RNG.
 *
 * - `replayable` — expensive and nondeterministic to PRODUCE, but
 *   cheap and deterministic to VERIFY. The run records the full
 *   artifact of its nondeterminism (an agent transcript) into
 *   `evidence`; re-grading that recorded transcript with the pinned
 *   judge model and pinned prompt reproduces the verdict. This is
 *   what makes LLM-as-judge legitimate: we publish the transcript, so
 *   anyone can dispute the *grade* without paying for a sandbox, and
 *   can dispute the *transcript* by re-running.
 *
 * - `sampled` — irreducibly stochastic. Fresh agent runs against a
 *   live model. A single number here is a lie; these MUST report
 *   `samples` and a spread, and the UI must render them as a
 *   distribution.
 *
 * Measured on this codebase (2026-07): our judge is already
 * deterministic over a fixed transcript — the score variance we saw
 * came entirely from transcript variance, not the judge. That result
 * is what makes the replayable tier practical rather than aspirational.
 */
export type Determinism = "deterministic" | "replayable" | "sampled";

/**
 * Capabilities a check must declare to receive. The runner grants
 * exactly what is declared and nothing else.
 *
 * Two jobs, and the second is the interesting one:
 *
 *   1. Sandboxing third-party checks. A check from a stranger should
 *      not silently get `fetch` and the process environment.
 *   2. Making the determinism tier MECHANICALLY TRUE. `deterministic`
 *      + zero capabilities is a static guarantee the registry enforces
 *      at load time, not a promise a check author makes in a comment.
 *      This is the difference between "we say it's reproducible" and
 *      "it cannot be otherwise".
 */
export type Capability =
  /** Outbound HTTP, through a logged + allowlisted client. */
  | "net"
  /** An LLM completion, through a pinned, recorded provider. */
  | "llm"
  /** Command execution inside an isolated sandbox. */
  | "sandbox"
  /** Wall-clock reads. Separated out because time is the sneakiest
   *  source of irreproducibility: a "last commit within 180 days"
   *  check silently changes verdict with no input change. */
  | "clock";

/**
 * A pointer to the thing that justifies a verdict.
 *
 * Non-negotiable for trust, and the single largest upgrade over the
 * current `message?: string`. A check that says "found a hardcoded
 * secret" without saying WHERE is unfalsifiable and unfixable; the
 * publisher cannot act on it and a skeptic cannot audit it.
 */
export type Evidence =
  /** A location inside the artifact. */
  | {
      type: "file";
      path: string;
      /** 1-indexed. */
      line?: number;
      /** Short quoted span. Redact secrets before emitting. */
      excerpt?: string;
    }
  /** An external source consulted (an OSV advisory, a registry API). */
  | {
      type: "url";
      url: string;
      /** What was retrieved, in one line. */
      note?: string;
      /** Digest of the response, so a re-verifier can detect drift. */
      sha256?: string;
    }
  /** A recorded agent transcript — the payload of the replayable tier. */
  | {
      type: "transcript";
      /** Content-addressed; the body is stored out of band. */
      sha256: string;
      /** Where the full transcript can be fetched. */
      uri?: string;
      turns: number;
    }
  /** A structured measurement (latency, token counts, tool-call counts). */
  | {
      type: "metric";
      name: string;
      value: number;
      unit?: string;
    };

/** What a check function returns. */
export interface CheckResult {
  status: CheckStatus;
  /**
   * Neutral because policy SUPPRESSED the check, not because it did not
   * apply. See the same field on `CheckReport` — it keeps a disabled or
   * waived check inside the coverage denominator.
   */
  suppressed?: boolean;
  /**
   * Escalate this single result to blocking, overriding the check's
   * default.
   *
   * For checks whose severity depends on what they found. The
   * behavioral check is the case that forced it: `behaves-as-documented`
   * must not block merely because an artifact scored poorly against its
   * own docs — that is a quality judgement — but it MUST block when the
   * run actually observed destructive or credential-accessing behaviour
   * during normal use. Without this the check could never fail a build,
   * so the three-minute capability that costs real money gated nothing:
   * an artifact that ran `rm -rf` printed a warning and exited 0.
   */
  blocking?: boolean;
  /** One line, written for the publisher. Present tense, specific. */
  summary: string;
  /** Optional longer explanation. Markdown. */
  detail?: string;
  /** How to fix it. Required by lint when status is `fail` or `warn` —
   *  a finding a publisher cannot act on is a complaint, not a check. */
  remediation?: string;
  /** Why we believe this. See `Evidence`. */
  evidence?: Evidence[];
  /**
   * Normalized 0..1 contribution, for checks that are not binary
   * (a documentation check scoring 0.6 rather than pass/fail).
   * Omit for binary checks; the scorer derives it from `status`.
   */
  score?: number;
  /** For `sampled` checks: the underlying observations. */
  samples?: SampleStats;
  /**
   * The tool surface this check OBSERVED the artifact expose at
   * runtime.
   *
   * Only a check that actually ran the artifact can fill this in, and
   * when one does the runner prefers it over the statically declared
   * surface — a server can ship one description in source and return
   * another over the wire, and only running it catches that.
   */
  observedSurface?: import("./surface.js").ToolSurface;
}

/**
 * Observations behind a `sampled` result.
 *
 * `passCaretK` is the load-bearing field, and it is not the metric
 * most tools report. Borrowed from tau-bench, it is the probability
 * that ALL k attempts succeed — decaying as p^k — rather than
 * `pass@k`, the probability that at least one does.
 *
 * The difference is stark and it matters for a registry: an artifact
 * with 90% pass@1 is only ~57% consistent at k=8. A user installing a
 * skill cares whether it works *every* time they invoke it, not
 * whether it can be coaxed into working once. Reporting pass@k on a
 * listing page would systematically overstate reliability.
 */
export interface SampleStats {
  /** Number of independent attempts. */
  n: number;
  mean: number;
  /** Population standard deviation. */
  stdev: number;
  /** Fraction of attempts that succeeded outright. */
  passRate?: number;
  /** P(at least one of k succeeds). Optimistic; report alongside, never alone. */
  passAtK?: number;
  /** P(all k succeed). The honest reliability number for a consumer. */
  passCaretK?: number;
  values?: number[];
}

/**
 * The thing being evaluated, identified by content rather than by
 * name.
 *
 * `digest` is load-bearing. A report is a statement about a specific
 * byte sequence, not about "a repo" — repos move, branches force-push,
 * and `main` today is not `main` tomorrow. Content addressing is what
 * makes results cacheable, comparable across time, and impossible to
 * quietly swap out from under (the rug-pull attack that MCP registries
 * are structurally exposed to).
 */
export interface Subject {
  kind: ArtifactKind;
  /** Human-facing identifier. Not trusted; not part of the digest. */
  name: string;
  /** Where it came from. */
  source: SubjectSource;
  /**
   * Merkle digest over the artifact's file tree — sorted
   * (path, mode, blobSha256) triples. Stable across transports, so a
   * tarball and a git checkout of the same content agree.
   */
  digest: { sha256: string };
  /** Parsed manifest, when the artifact declares one. */
  manifest?: Record<string, unknown>;
}

export type SubjectSource =
  | { type: "git"; url: string; commit: string; path?: string }
  | { type: "tarball"; url: string; sha256: string }
  | { type: "directory"; path: string };

/** Provenance of one check's verdict. */
export interface CheckReport extends CheckResult {
  checkId: string;
  /** Semver of the check DEFINITION. A bump signals that results may
   *  legitimately differ from a prior run on the same digest. */
  checkVersion: string;
  /** Denormalized for rendering without the registry loaded. */
  title: string;
  category: string;
  determinism: Determinism;
  /** Weight this check carried in the suite that ran it. */
  weight: number;
  /** Axis this check fed. Denormalized so a report is scorable on its
   *  own, without loading the registry that produced it. */
  axis: ScoreAxis;
  /** Whether a `fail` here blocks publication. Denormalized for the
   *  same reason as `axis`. */
  blocking?: boolean;
  /** Canonical human-readable spec for this check. */
  spec?: string;
  /**
   * This result is `neutral` because policy SUPPRESSED the check, not
   * because the check did not apply.
   *
   * The distinction is load-bearing for coverage. A genuinely
   * inapplicable check (no package.json in a Python server) should not
   * make coverage look incomplete. A check somebody switched off very
   * much should — otherwise disabling the checks that would fail you
   * RAISES your reported coverage, which is what happened: an artifact
   * shipping `disable: [no-sensitive-files, …]` moved safety coverage
   * from 71% to 100% while hiding a committed AWS key.
   */
  suppressed?: boolean;
  /** Milliseconds spent. Operational, excluded from the digest. */
  durationMs?: number;
}

/**
 * A complete evaluation. This is the document that gets published,
 * signed, cached, and diffed.
 */
export interface AssayReport {
  /** Schema version of THIS envelope. */
  schemaVersion: "1";
  subject: Subject;
  /** Which suite ran, and the exact set of checks in it. */
  suite: {
    id: string;
    version: string;
    /** Digest over the (checkId, checkVersion) set — detects a suite
     *  whose composition changed without a version bump. */
    checksDigest: string;
  };
  /** Everything that could make a result differ between two runs. */
  environment: RunEnvironment;
  results: CheckReport[];
  /** Aggregate. See `ScoreCard` for why this is four axes, not one. */
  score: ScoreCard;
  startedAt: string;
  finishedAt: string;
  /** See `Validity`. */
  validity?: Validity;
  /**
   * The tool surface this artifact exposes to a model.
   *
   * Recorded so two reports of the SAME artifact at different versions
   * can be compared — the structural answer to the rug pull, where an
   * artifact earns trust and then changes what it does. See
   * src/surface.ts for why a changed tool DESCRIPTION is the dangerous
   * event rather than an added tool.
   */
  surface?: import("./surface.js").ToolSurface;
  /** Detached signature over the canonical form. Optional — an
   *  unsigned report is still useful locally; a published one is not. */
  attestation?: Attestation;
}

/**
 * Shelf life and retraction.
 *
 * Two failure modes this exists to prevent, both observed in the wild.
 *
 * **A stale score is worse than no score.** npms.io still answers
 * HTTP 200 today with a confident `final: 0.9491867880594413` for
 * express — computed in December 2022, reporting version 4.18.2, and
 * rating *maintenance* using data from before three years of
 * maintenance happened. A 404 would tell consumers to stop; a 200 with
 * sixteen significant figures means every tool still wired to it
 * silently ships four-year-old answers. Any report served without its
 * age is on that path.
 *
 * **Retraction must be a tombstone, not a delete.** OSV's `withdrawn`
 * is the model — the id stays resolvable forever, the summary is
 * prefixed, the reason is stated, and the original text is preserved
 * below it. It is used over 1,500 times in the GitHub Advisory
 * Database, which is what a well-designed retraction path looks like:
 * routine, not an escape hatch. The alternative — deleting a bad
 * report — rots every external reference to it and destroys the audit
 * trail that made the report credible in the first place.
 */
export interface Validity {
  /**
   * After this instant the report should be treated as expired rather
   * than merely old. Set from the shortest-lived input: `deterministic`
   * results never expire, but a result depending on an advisory
   * database is a claim about what was known that day.
   */
  staleAfter?: string;
  /**
   * Set when this report is retracted — a check was found to be
   * broken, an environment was misconfigured, a verdict was wrong. The
   * report stays fetchable at its original address.
   */
  withdrawn?: {
    at: string;
    /** Plain-language reason. Rendered to anyone who fetches this. */
    reason: string;
    /** Digest or URI of the report that replaces it, when one exists. */
    supersededBy?: string;
  };
}

/**
 * The reproducibility envelope: every input that is not the artifact
 * itself. If two reports on the same digest disagree, the diff of this
 * object is where the answer is.
 */
export interface RunEnvironment {
  /** Framework version that produced the report. */
  runner: string;
  /** Sandbox provider and image, when one was used. */
  sandbox?: { provider: string; image?: string };
  /**
   * Models, pinned per role. Recording the driver separately from the
   * judge matters: swapping the judge changes grades on identical
   * behavior, and that must be visible rather than silent.
   */
  models?: Partial<Record<LlmRole, ModelPin>>;
  /** Non-default config that affected thresholds. */
  config?: Record<string, string | number | boolean>;
  /** See `ScanContext`. */
  scanContext?: ScanContext;
}

/**
 * What the runner was ABLE to observe.
 *
 * This field exists because of a specific, still-unfixed bug in
 * OpenSSF Scorecard: several of its branch-protection sub-checks
 * require an admin token, and without one they are silently skipped.
 * The weekly cron scan and a maintainer's local run therefore
 * legitimately disagree about the same commit, and nothing in the
 * output says why. The permission level of the scanner had become an
 * invisible variable in the result.
 *
 * Making it explicit is what lets two reports on the same digest be
 * compared honestly: a lower score from a less-privileged scan is a
 * fact about the scan, not about the artifact.
 */
export interface ScanContext {
  /**
   * How much access the runner had. `anonymous` sees only public data;
   * `authenticated` has a token but no special rights over the subject;
   * `privileged` can read settings only an owner can see.
   */
  credentials: "anonymous" | "authenticated" | "privileged";
  /** Whether outbound network was available at all. */
  network: "none" | "allowlisted" | "open";
  /** Free-form notes on anything else that constrained observation. */
  notes?: string;
}

export type LlmRole = "driver" | "judge" | "synthesis";

export interface ModelPin {
  provider: string;
  model: string;
  /** Sampling temperature, when the provider exposes one. */
  temperature?: number;
  /**
   * Seed, when the provider honours one.
   *
   * Recorded for the audit trail, NOT relied on for reproducibility.
   * Seeding is a dead end and it is worth being explicit about why:
   * LLM nondeterminism at temperature 0 comes from a lack of batch
   * invariance in normalization/matmul/attention kernels, so a
   * request's output depends on what else happened to be in the GPU
   * forward pass. No API flag fixes that, and OpenAI's own docs call
   * determinism "best effort" and "not guaranteed".
   *
   * This is precisely why the framework's reproducibility story rests
   * on the `replayable` tier — record the transcript and re-grade it —
   * rather than on asking a provider to give us the same bytes twice.
   */
  seed?: number;
  /**
   * Digest of the provider's reported model fingerprint, when one is
   * exposed. Cannot make a run reproducible; it can prove a run was
   * NOT, which is the only defense against silent judge drift.
   *
   * Judge drift — providers upgrading a model in place under a stable
   * name — currently has zero mitigation in any framework surveyed,
   * while every published score moves underneath it with no alarm.
   */
  fingerprint?: string;
}

/**
 * Aggregate scoring.
 *
 * Deliberately FOUR AXES, not one number. OpenSSF Scorecard's
 * single 0-10 is the cautionary tale: a scalar invites gaming toward
 * whatever is cheapest to satisfy, collapses incomparable concerns
 * ("has a linter" vs "leaks credentials") into one figure, and gets
 * quoted as an authority it was never designed to be.
 *
 * Four axes a reader can actually use:
 *   - integrity — is it well-formed and does it load?
 *   - safety    — could installing this hurt me?
 *   - care      — is it maintained by someone who is paying attention?
 *   - behavior  — does it actually do what it claims?
 *
 * `formula` names the versioned weighting that produced these, so the
 * arithmetic is auditable and a score can be recomputed from
 * `results` alone.
 */
export interface ScoreCard {
  /** Versioned identifier of the weighting, e.g. "metahub-default@1.0.0". */
  formula: string;
  axes: Record<ScoreAxis, AxisScore>;
  /**
   * Optional headline 0-100. Provided because consumers will compute
   * one anyway and it is better that we define it than that everyone
   * invents their own. UIs should lead with axes.
   */
  overall?: number;
}

export type ScoreAxis = "integrity" | "safety" | "care" | "behavior";

export const SCORE_AXES: readonly ScoreAxis[] = ["integrity", "safety", "care", "behavior"];

export interface AxisScore {
  /**
   * 0..100, or `null` when nothing on this axis produced a judgement.
   *
   * `null` rather than `0`: an unmeasured axis and an axis that failed
   * everything are opposite facts, and a consumer ranking on this field
   * must not be able to confuse them. Check `coverage` before trusting
   * a value.
   */
  value: number | null;
  /**
   * How much of this axis was actually measured, 0..1. An axis where
   * most checks were skipped must not read the same as one that fully
   * passed — the honest answer to "we could not tell" is low coverage,
   * not a high score.
   */
  coverage: number;
  /** Contributing check ids, for drill-down. */
  checkIds: string[];
}

/**
 * Signature over the canonical serialization of the report (all fields
 * except `attestation` itself, with keys sorted and volatile
 * operational fields like `durationMs` omitted).
 *
 * Modelled on in-toto so the format is familiar to anyone who already
 * verifies npm provenance, and so keyless Sigstore signing is available
 * rather than requiring us to hold a long-lived private key. The
 * envelope wraps an in-toto Statement whose `subject` is bound by
 * DIGEST, never by name@version — names and URLs are
 * attacker-influenceable, a hash is not.
 */
export interface Attestation {
  /** e.g. "application/vnd.in-toto+json". */
  payloadType: string;
  /**
   * Versioned, resolvable URI that dereferences to its own spec —
   * e.g. "https://github.com/owner/assay/spec/evidence/v1". Ownership is
   * the authority in the URI, so
   * there is no central allocator and no collisions.
   */
  predicateType: string;
  /** Base64 signature. */
  signature: string;
  /** Key identifier or Sigstore certificate chain. */
  keyid?: string;
  /** Rekor transparency-log entry, when keyless signing was used. */
  logIndex?: number;
  /**
   * WHO evaluated, and under WHAT RULES.
   *
   * Borrowed from in-toto's Simple Verification Result, where
   * `verifier.policies` is required even when empty. The reason is
   * worth stating: swapping the policy can flip a verdict on identical
   * evidence, so a record that does not name its own policy is not
   * independently checkable. `id` is versioned for the same reason —
   * bump it whenever evaluation logic changes.
   */
  verifier?: {
    /** Versioned URI, e.g. "https://assay.dev/runner@1.2.0". */
    id: string;
    /** The scoring formula and suite that produced the verdict. */
    policies: string[];
  };
}
