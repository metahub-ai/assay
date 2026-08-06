/**
 * The runner.
 *
 * Small on purpose. Its job is to enforce the guarantees the rest of
 * the framework advertises, and enforcement is only credible if it is
 * short enough to read in one sitting:
 *
 *   - a check receives exactly the capabilities it declared,
 *   - a check that throws produces `error`, never `fail`,
 *   - a check that hangs is cancelled rather than hanging the run,
 *   - every result is stamped with the provenance a verifier needs.
 *
 * The third one is not defensive padding. A behavioral check drives a
 * live model inside a sandbox; without a hard per-check ceiling, one
 * pathological artifact stalls the queue for everyone behind it —
 * which is the exact failure mode that left artifacts un-evaluated in
 * production.
 */
import type { CheckContext, CheckDefinition, CheckRegistry } from "./check.js";
import type { AssayConfig } from "./config.js";
import { waiverFor } from "./config.js";
import { captureSurface } from "./checks/surface-capture.js";
import { digestSuite } from "./digest.js";
import type { LlmProvider, Logger, NetClient, SandboxRunner, SourceReader } from "./ports.js";
import { scoreReport } from "./score.js";
import type {
  AssayReport,
  Capability,
  CheckReport,
  CheckResult,
  Determinism,
  RunEnvironment,
  Subject,
  Validity,
} from "./types.js";

export interface RunOptions {
  subject: Subject;
  source: SourceReader;
  registry: CheckRegistry;
  suite: { id: string; version: string };
  environment: RunEnvironment;
  config?: Record<string, string | number | boolean>;
  log?: Logger;
  /** Capability implementations. A capability with no implementation is
   *  simply unavailable, and checks needing it are excluded. */
  capabilities?: {
    net?: NetClient;
    llm?: LlmProvider;
    sandbox?: SandboxRunner;
    now?: () => number;
  };
  /** Per-check wall-clock ceiling. Default 5 minutes. */
  checkTimeoutMs?: number;
  /**
   * Override the per-tier shelf life, in days. `null` means "never
   * expires". See `deriveValidity`.
   */
  shelfLife?: Partial<Record<Determinism, number | null>>;
  /** Abort the whole run. */
  signal?: AbortSignal;
  /**
   * Project policy. Waivers turn a finding into `neutral` WITH the
   * published reason attached — never a silent drop. See src/config.ts
   * for why that distinction is the whole design.
   */
  policy?: AssayConfig;
  /** Where the policy came from, so a disabled check can name it. */
  policyPath?: string | null;
  /** Injectable clock, so waiver expiry is testable. */
  now?: () => number;
  /**
   * Veto a check immediately before it runs, given every result decided
   * so far. Return a reason to skip it, or `null` to let it run.
   *
   * This exists for one case, and it is a safety case: behavioral
   * evaluation EXECUTES the artifact, and when it was turned on by
   * default rather than asked for by name, an artifact the static
   * checks have just flagged as malicious must not then be run. The
   * expensive checks are ordered last (see below) precisely so that
   * verdict is already available here.
   */
  gate?: (check: CheckDefinition, decidedSoFar: readonly CheckReport[]) => string | null;
}

const DEFAULT_CHECK_TIMEOUT_MS = 5 * 60_000;

export async function runAssay(opts: RunOptions): Promise<AssayReport> {
  const startedAt = new Date().toISOString();
  const log = opts.log ?? nullLogger();
  const timeoutMs = opts.checkTimeoutMs ?? DEFAULT_CHECK_TIMEOUT_MS;

  const granted = grantedCapabilities(opts.capabilities);
  const disabled = new Set(opts.policy?.disable ?? []);
  const forKind = opts.registry.forKind(opts.subject.kind);
  const applicable = forKind.filter((c) => !disabled.has(c.id));
  const suppressed = forKind.filter((c) => disabled.has(c.id));

  // Checks whose capabilities we cannot satisfy are EXCLUDED, not
  // failed. Failing them would defame the artifact for our own missing
  // API key; excluding them shows up honestly as reduced axis coverage.
  const runnable: CheckDefinition[] = [];
  const unmet: CheckDefinition[] = [];
  for (const c of applicable) {
    const needs = c.needs ?? [];
    (needs.every((n) => granted.has(n)) ? runnable : unmet).push(c);
  }
  if (unmet.length > 0) {
    log.info("assay: skipping checks with unmet capabilities", {
      count: unmet.length,
      ids: unmet.map((c) => c.id),
    });
  }

  const results: CheckReport[] = [];

  // Cheap, offline checks first; anything that drives a model or a
  // sandbox last.
  //
  // The registry is ordered by id for a stable suite digest, which put
  // `behaves-as-documented` — the one check that EXECUTES the artifact —
  // near the front of the alphabet and therefore near the front of the
  // run. So the framework was spending minutes and money running code it
  // had not finished inspecting, and `gate` could not see a safety
  // verdict that had not happened yet.
  //
  // Execution order is not reported: results are sorted by id below, and
  // the suite digest is computed from `applicable`. So this is invisible
  // in the output and only changes what is known when.
  const costly = (c: CheckDefinition) =>
    (c.needs ?? []).includes("sandbox") || (c.needs ?? []).includes("llm");
  const ordered = [...runnable.filter((c) => !costly(c)), ...runnable.filter(costly)];

  for (const check of ordered) {
    if (opts.signal?.aborted) {
      results.push(stamp(check, { status: "skip", summary: "Run aborted before this check ran." }));
      continue;
    }
    const veto = opts.gate?.(check, results) ?? null;
    if (veto !== null) {
      results.push(stamp(check, { status: "skip", summary: veto }));
      continue;
    }
    const t0 = Date.now();
    const raw = await runOne(check, opts, granted, log, timeoutMs);
    const result = applyWaiver(check.id, raw, opts.policy, opts.now?.() ?? Date.now());
    results.push({ ...stamp(check, result), durationMs: Date.now() - t0 });
  }

  // Excluded checks are recorded explicitly. A report that silently
  // omits them is indistinguishable from one where they passed.
  for (const check of unmet) {
    results.push(
      stamp(check, {
        status: "skip",
        summary: `Not run — requires ${(check.needs ?? []).join(", ")}, unavailable in this environment.`,
      }),
    );
  }

  // Policy-disabled checks are recorded too, and for a sharper reason
  // than the unmet ones.
  //
  // They used to be filtered out before the loop and never appear at
  // all — so disabling a blocking safety check deleted the failure,
  // raised the overall score, flipped the exit code to 0, and left a
  // report that `assay verify` accepts, because verification recomputes
  // the score from the results that survived. `assay diff` classified
  // the deletion as `removed` rather than a regression and also exited
  // 0. Every downstream consistency check agreed with the publisher.
  //
  // This sits beside a waiver system whose whole design is that an
  // excuse must be published and expire. An unlogged off-switch next to
  // it defeated the point.
  for (const check of suppressed) {
    results.push(
      stamp(check, {
        status: "neutral",
        suppressed: true,
        summary: "Disabled by policy — this check did not run.",
        detail:
          `Listed in \`disable\` in ${opts.policyPath ?? "the project config"}. ` +
          "Unlike a waiver, a disabled check carries no stated reason and no expiry.",
      }),
    );
  }

  results.sort((a, b) => (a.checkId < b.checkId ? -1 : a.checkId > b.checkId ? 1 : 0));

  // Captured on EVERY run, not only behavioral ones — the rug-pull
  // signal should not require a sandbox and an API key to compute.
  //
  // But an OBSERVED surface always wins when a check produced one. What
  // a server declares in source and what it returns over the wire can
  // differ, and only running it settles which is true.
  const observed = results.find((r) => r.observedSurface)?.observedSurface;
  const surface =
    observed ?? (await captureSurface(opts.source, opts.subject.kind).catch(() => null));

  const finishedAt = new Date().toISOString();
  return {
    schemaVersion: "1",
    subject: opts.subject,
    suite: {
      id: opts.suite.id,
      version: opts.suite.version,
      checksDigest: digestSuite(applicable.map((c) => ({ id: c.id, version: c.version }))),
    },
    environment: opts.environment,
    results,
    score: scoreReport(results),
    startedAt,
    finishedAt,
    validity: deriveValidity(results, finishedAt, opts.shelfLife),
    ...(surface ? { surface } : {}),
  };
}

/**
 * Apply a waiver to a finding.
 *
 * A waived finding becomes `neutral` and carries the reason forward
 * into the report. It is NOT dropped: a consumer reading the result
 * sees that a judgement was excused and by what argument, and can
 * weigh that for themselves. Silently suppressing it would make the
 * report a negotiated document rather than an observation.
 *
 * Waivers only apply to `warn` and `fail`. Waiving a `pass` is
 * meaningless, and waiving an `error` would hide OUR failure behind
 * the publisher's excuse.
 */
/**
 * Match a POSIX path against a glob: `*` within a segment, `**` across
 * segments, `?` for one character.
 *
 * Deliberately small. A waiver scope has to be predictable to the
 * person writing it, and every extra piece of syntax is another way for
 * a scope to be wider than its author believed.
 */
export function matchesGlob(path: string, glob: string): boolean {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const pattern = escaped
    // `**/` may match zero segments, so `a/**/b` matches `a/b`.
    .replace(/\*\*\//g, " SLASHSTAR ")
    .replace(/\*\*/g, " GLOBSTAR ")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replace(/ SLASHSTAR /g, "(?:.*/)?")
    .replace(/ GLOBSTAR /g, ".*");
  return new RegExp(`^${pattern}$`).test(path);
}

export function applyWaiver(
  checkId: string,
  result: CheckResult,
  policy: AssayConfig | undefined,
  now: number,
): CheckResult {
  if (!policy) return result;
  if (result.status !== "warn" && result.status !== "fail") return result;
  const active = waiverFor(policy, checkId, now);
  if (!active) return result;

  // Path scoping, which was parsed, typed, documented — and never read.
  //
  // `waiverFor` matched on `check` alone, so
  // `{"check":"no-hardcoded-secrets","paths":["tests/fixtures/**"]}`
  // waived the check across the ENTIRE artifact. A user narrowing a
  // waiver as carefully as they knew how got the widest possible one,
  // and nothing said so. In the one feature designed to be expensive to
  // abuse, that is the wrong direction to fail.
  const scope = active.waiver.paths;
  if (scope && scope.length > 0) {
    const paths = (result.evidence ?? [])
      .map((e) => (e as { path?: string }).path)
      .filter((p): p is string => typeof p === "string");

    if (paths.length === 0) {
      // Nothing to scope against. Applying the waiver would silently
      // ignore the scope; refusing says so.
      return {
        ...result,
        detail:
          `${result.detail ? `${result.detail}\n\n` : ""}` +
          `A path-scoped waiver for this check was NOT applied: this finding reports no file paths to scope against.`,
      };
    }
    const outside = paths.filter((p) => !scope.some((g) => matchesGlob(p, g)));
    if (outside.length > 0) {
      return {
        ...result,
        detail:
          `${result.detail ? `${result.detail}\n\n` : ""}` +
          `A waiver scoped to ${scope.join(", ")} does not cover ${outside.length} of ${paths.length} finding(s): ` +
          `${outside.slice(0, 5).join(", ")}.`,
      };
    }
  }

  if (active.expired) {
    // An expired waiver stops excusing the finding, and says so — the
    // point of an expiry is that it forces a re-decision.
    return {
      ...result,
      detail:
        `${result.detail ? `${result.detail}\n\n` : ""}A waiver for this check ` +
        `${active.waiver.expires ? `expired on ${active.waiver.expires}` : "has expired"}.`,
    };
  }
  return {
    status: "neutral",
    suppressed: true,
    summary: `Waived: ${result.summary}`,
    detail:
      `Reason given: ${active.waiver.reason}` +
      (active.waiver.expires ? `\n\nWaiver expires ${active.waiver.expires}.` : ""),
    ...(result.evidence ? { evidence: result.evidence } : {}),
  };
}

/**
 * Default shelf life per determinism tier, in days.
 *
 * A `deterministic` result is a pure function of bytes that will not
 * exist differently tomorrow — it never expires. Everything else is a
 * claim about what was observable on a particular day: a `sampled`
 * check may have consulted an advisory database that has since learned
 * about a new CVE, and a `replayable` one used a model the provider
 * may have since replaced.
 */
const DEFAULT_SHELF_LIFE_DAYS: Record<Determinism, number | null> = {
  deterministic: null,
  replayable: 180,
  sampled: 30,
};

/**
 * Compute the report's shelf life from its SHORTEST-LIVED result.
 *
 * A report is only as fresh as its most perishable component: one
 * advisory-dependent check expiring in 30 days makes the whole document
 * a 30-day document, however many permanent results sit beside it.
 *
 * `skip`/`error` results are ignored — they produced no claim, so they
 * have nothing to expire.
 */
export function deriveValidity(
  results: readonly CheckReport[],
  finishedAt: string,
  override?: Partial<Record<Determinism, number | null>>,
): Validity | undefined {
  const shelf = { ...DEFAULT_SHELF_LIFE_DAYS, ...(override ?? {}) };
  let shortest: number | null = null;

  for (const r of results) {
    if (r.status === "skip" || r.status === "error") continue;
    const days = shelf[r.determinism];
    if (days == null) continue;
    shortest = shortest == null ? days : Math.min(shortest, days);
  }

  if (shortest == null) return undefined;
  const base = Date.parse(finishedAt);
  if (!Number.isFinite(base)) return undefined;
  return { staleAfter: new Date(base + shortest * 86_400_000).toISOString() };
}

/**
 * Run one check with its capability sandbox and timeout.
 *
 * Every failure mode here collapses to `error`, which the scorer
 * ignores. A crash in our checker is information about us, not about
 * the artifact.
 */
async function runOne(
  check: CheckDefinition,
  opts: RunOptions,
  granted: Set<Capability>,
  log: Logger,
  timeoutMs: number,
): Promise<CheckResult> {
  const needs = new Set(check.needs ?? []);
  const timer = new AbortController();
  const onAbort = () => timer.abort();
  opts.signal?.addEventListener("abort", onAbort, { once: true });
  const timeout = setTimeout(() => timer.abort(), timeoutMs);

  // The capability grant. A check gets a field only if it declared the
  // capability AND the runner has an implementation — so an undeclared
  // capability is `undefined` at runtime, not merely against the rules.
  const ctx: CheckContext = {
    subject: opts.subject,
    source: opts.source,
    config: Object.freeze({ ...(opts.config ?? {}) }),
    log,
    signal: timer.signal,
    net: needs.has("net") ? opts.capabilities?.net : undefined,
    llm: needs.has("llm") ? opts.capabilities?.llm : undefined,
    sandbox: needs.has("sandbox") ? opts.capabilities?.sandbox : undefined,
    now: needs.has("clock") ? (opts.capabilities?.now ?? Date.now) : undefined,
  };

  try {
    const result = await Promise.race([
      Promise.resolve(check.run(ctx)),
      new Promise<never>((_, reject) => {
        timer.signal.addEventListener(
          "abort",
          () => reject(new Error(`check timed out after ${timeoutMs}ms`)),
          { once: true },
        );
      }),
    ]);
    return validateResult(check, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log.warn("assay: check errored", { checkId: check.id, error: message });
    return {
      status: "error",
      summary: `Check did not complete: ${message}`,
      detail:
        "This is a failure of the evaluation, not of the artifact. It does not affect the score.",
    };
  } finally {
    clearTimeout(timeout);
    opts.signal?.removeEventListener("abort", onAbort);
  }
}

/**
 * Guard against a check returning something unusable.
 *
 * Third-party checks are ordinary code we do not control; a typo'd
 * status must not silently become a passing grade.
 */
function validateResult(check: CheckDefinition, result: CheckResult): CheckResult {
  const VALID = new Set(["pass", "warn", "fail", "neutral", "skip", "error"]);
  if (!result || typeof result !== "object" || !VALID.has(result.status)) {
    return {
      status: "error",
      summary: `Check ${check.id} returned a malformed result.`,
    };
  }
  return result;
}

/** Attach provenance. Everything a verifier needs to re-derive this. */
function stamp(check: CheckDefinition, result: CheckResult): CheckReport {
  return {
    ...result,
    checkId: check.id,
    checkVersion: check.version,
    title: check.title,
    category: check.category,
    determinism: check.determinism,
    weight: check.weight ?? 1,
    axis: check.axis,
    // A result may escalate itself; it may not de-escalate a check the
    // suite declared blocking.
    blocking: result.blocking === true ? true : check.blocking,
    spec: check.spec,
  };
}

function grantedCapabilities(caps: RunOptions["capabilities"]): Set<Capability> {
  const set = new Set<Capability>();
  if (caps?.net) set.add("net");
  if (caps?.llm) set.add("llm");
  if (caps?.sandbox) set.add("sandbox");
  // The clock is always available — it is a capability so that
  // `deterministic` checks are statically denied it, not because
  // reading time needs an implementation.
  set.add("clock");
  return set;
}

function nullLogger(): Logger {
  const noop = () => {};
  return { debug: noop, info: noop, warn: noop, error: noop };
}
