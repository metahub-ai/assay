/**
 * Framework version, stamped into every report's `environment.runner`
 * and `suite.version`.
 *
 * Hard-coded rather than read from package.json at runtime: a report
 * must record which code produced it, and resolving that lazily from
 * disk breaks the moment the package is bundled.
 *
 * MUST match `version` in package.json and the release tag; the release
 * workflow refuses to publish when they disagree. A build that
 * misreports its own version stamps a provenance into every report that
 * is not true of the code that produced it, and for a tool whose whole
 * claim is that a grade is attributable, that is not a cosmetic slip.
 */
export const ASSAY_VERSION = "0.2.3";

/**
 * The project's canonical home.
 *
 * Every URI the tool publishes derives from this: check `spec` links,
 * SARIF `helpUri` (which GitHub code scanning renders as a clickable
 * "learn more" on each finding), the in-toto `predicateType`, and the
 * config `$schema`.
 *
 * It must be an authority the project actually controls. A plausible
 * project domain is very often owned by someone else — `assay.dev`
 * resolves to an unrelated site about laboratory assay development —
 * and pointing there would ship two dozen links to a stranger in every
 * report, while claiming an in-toto predicate type under an authority
 * that could redefine it. GitHub is owned; a domain is aspirational
 * until it is bought.
 *
 * Defined in one place so that moving the project, or buying a domain
 * later, is a one-line change rather than a grep across forty call
 * sites.
 */
export const ASSAY_HOME = "https://github.com/metahub-ai/assay";

/** Where a check's documentation lives. `id` is the check id. */
export function checkSpecUrl(id: string): string {
  return `${ASSAY_HOME}/blob/main/docs/CHECKS.md#${id}`;
}
