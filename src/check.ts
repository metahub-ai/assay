/**
 * The check-authoring API.
 *
 * The problem this solves: in the portal today, adding a check means
 * appending an object literal to a 700-line function inside a Next.js
 * app that imports Postgres. There are 70 such sites. A category is
 * assigned by a hardcoded `switch` in a *different package*, so a
 * check id we don't know about silently lands in "kind-specific". No
 * one outside this repo can write a check, and no check can be
 * versioned, tested, or reasoned about on its own.
 *
 * A check here is a standalone, versioned, independently testable
 * module. That is the whole point — it is what turns "trust our
 * score" into "read the check that produced it".
 */
import type { ArtifactKind, Capability, CheckResult, Determinism, Subject } from "./types.js";
import type { Logger, LlmProvider, NetClient, SandboxRunner, SourceReader } from "./ports.js";

/**
 * What a check receives. Capability fields are present only when the
 * check declared them in `needs` — an undeclared capability is
 * `undefined` at runtime, not merely discouraged.
 */
export interface CheckContext {
  readonly subject: Subject;
  /** Read-only view of the artifact's files. */
  readonly source: SourceReader;
  /**
   * Resolved thresholds. An explicit object rather than `process.env`
   * reads: the portal's thresholds are module-level consts captured at
   * IMPORT time, which makes them untestable without module resets and
   * invisible in the report. Config that affects a verdict belongs in
   * the report's `environment.config`.
   */
  readonly config: Readonly<Record<string, string | number | boolean>>;
  readonly log: Logger;
  /** Cooperative cancellation — budget exhaustion, operator abort. */
  readonly signal: AbortSignal;

  // ---- capabilities, granted only when declared ----
  readonly net?: NetClient;
  readonly llm?: LlmProvider;
  readonly sandbox?: SandboxRunner;
  /** Current time. A capability so that `deterministic` checks cannot
   *  read it, and so tests can inject a fixed clock. */
  readonly now?: () => number;
}

export interface CheckDefinition {
  /** Stable, kebab-case, globally unique. Namespace third-party checks
   *  (`acme/no-eval`) to avoid collisions with core ids. */
  id: string;
  /**
   * Semver of this check's LOGIC. Bump when a verdict could change on
   * unchanged input; that is the signal downstream caches and diffs
   * key on. Publishing a changed check without a bump is the one thing
   * that would make historical reports untrustworthy.
   */
  version: string;
  /** Short human title, rendered in UIs. */
  title: string;
  /**
   * Free-form category. A string, not a closed union, so a third party
   * can group their checks without patching the framework. Well-known
   * values live in `WELL_KNOWN_CATEGORIES`.
   */
  category: string;
  determinism: Determinism;
  /** Capabilities required. MUST be empty when determinism is
   *  `deterministic` — enforced at registration. */
  needs?: Capability[];
  /** Which subjects this applies to. Omit `kinds` for all kinds. */
  appliesTo?: { kinds?: ArtifactKind[] };
  /**
   * Relative weight within its axis. Whole small numbers; the scorer
   * normalizes. Weight 0 means informational — reported, never scored.
   */
  weight?: number;
  /** Which score axis this feeds. */
  axis: import("./types.js").ScoreAxis;
  /** URL of the human-readable spec. Every check should be documented
   *  publicly; a check with no spec is unappealable. */
  spec?: string;
  /**
   * Why this check exists, in the publisher's terms.
   *
   * `assay explain` is the #1 action the report recommends, and it used
   * to print a metadata table — axis, weight, determinism — which
   * teaches nobody anything and sends you to a URL. What someone wants
   * at that moment is why they should care and what "fixed" looks like.
   */
  rationale?: string;
  /** What the check reads. One line. */
  inspects?: string;
  /** A minimal example either side of the line. */
  examples?: { passing?: string; failing?: string };
  /**
   * Whether a `fail` should block publication. Kept as check metadata
   * rather than a registry-side env list so the blocking set is
   * reviewable in the same PR as the check itself.
   */
  blocking?: boolean;
  run(ctx: CheckContext): Promise<CheckResult> | CheckResult;
}

/** Categories the core suite uses. Not exhaustive, not enforced. */
export const WELL_KNOWN_CATEGORIES = [
  "structural",
  "documentation",
  "safety",
  "supply-chain",
  "kind-specific",
  "maintenance",
  "behavioral",
] as const;

const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const ID_RE = /^(?:[a-z0-9]+(?:-[a-z0-9]+)*\/)?[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * Validate and freeze a check definition.
 *
 * The validation is deliberately strict and happens at definition
 * time, not at run time. A malformed check should fail to load, loudly,
 * in the authoring PR — not produce a subtly wrong verdict months
 * later on someone's artifact.
 */
export function defineCheck(def: CheckDefinition): CheckDefinition {
  if (!ID_RE.test(def.id)) {
    throw new Error(
      `assay: invalid check id ${JSON.stringify(def.id)} — expected kebab-case, optionally namespaced as "vendor/check-name"`,
    );
  }
  if (!SEMVER_RE.test(def.version)) {
    throw new Error(`assay: check ${def.id} has non-semver version ${JSON.stringify(def.version)}`);
  }
  const needs = def.needs ?? [];

  // The load-bearing invariant. A `deterministic` check that could
  // reach the network or a model is not deterministic, and a claim the
  // framework cannot enforce is one a verifier cannot rely on.
  if (def.determinism === "deterministic" && needs.length > 0) {
    throw new Error(
      `assay: check ${def.id} declares determinism "deterministic" but requests capabilities [${needs.join(", ")}]. ` +
        `A deterministic check must be a pure function of the subject; declare "replayable" or "sampled" instead.`,
    );
  }
  // Symmetrically: a check that reaches a model but claims only
  // replayability must actually record what it saw. We cannot verify
  // that statically, so it is stated in the spec and asserted by the
  // conformance suite instead.
  if (def.determinism === "replayable" && !needs.includes("llm") && !needs.includes("sandbox")) {
    throw new Error(
      `assay: check ${def.id} declares "replayable" but needs neither "llm" nor "sandbox" — ` +
        `if it is a pure function, declare "deterministic".`,
    );
  }
  if ((def.weight ?? 1) < 0) {
    throw new Error(`assay: check ${def.id} has negative weight`);
  }
  return Object.freeze({ ...def, needs: Object.freeze([...needs]) as Capability[] });
}

/**
 * An immutable, ordered set of checks.
 *
 * Registries are values, not module-level singletons: a test, a CLI
 * run, and a hosted worker can each hold a different one, and a suite
 * is reproducible because its composition is explicit rather than
 * whatever happened to be imported.
 */
export class CheckRegistry {
  readonly #byId = new Map<string, CheckDefinition>();

  static from(checks: readonly CheckDefinition[]): CheckRegistry {
    const reg = new CheckRegistry();
    for (const c of checks) reg.add(c);
    return reg;
  }

  add(check: CheckDefinition): this {
    const existing = this.#byId.get(check.id);
    if (existing && existing.version !== check.version) {
      throw new Error(
        `assay: duplicate check id ${check.id} with conflicting versions ` +
          `(${existing.version} vs ${check.version})`,
      );
    }
    this.#byId.set(check.id, check);
    return this;
  }

  get(id: string): CheckDefinition | undefined {
    return this.#byId.get(id);
  }

  /** Deterministically ordered by id, so suite digests are stable. */
  all(): CheckDefinition[] {
    return [...this.#byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  /** Checks applicable to a kind. */
  forKind(kind: ArtifactKind): CheckDefinition[] {
    return this.all().filter((c) => {
      const kinds = c.appliesTo?.kinds;
      return !kinds || kinds.includes(kind);
    });
  }

  /**
   * Checks runnable given the capabilities actually available.
   *
   * This is how `assay run --offline` degrades honestly: instead of
   * failing network-dependent checks (which would defame the artifact
   * for our own missing API key), they are excluded and the affected
   * axis reports reduced `coverage`.
   */
  runnableWith(granted: readonly Capability[]): CheckDefinition[] {
    const have = new Set(granted);
    return this.all().filter((c) => (c.needs ?? []).every((n) => have.has(n)));
  }
}
