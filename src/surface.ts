/**
 * Tool surface capture and cross-version diffing.
 *
 * This is the structural answer to the **rug pull** — an artifact that
 * earns trust and then changes what it does. It is not hypothetical:
 * `postmark-mcp` shipped fifteen clean, functional versions before one
 * line started BCC'ing every email to an attacker, and Cursor's
 * MCPoison (CVE-2025-54136) is the same class with a CVE number
 * attached. Every trust layer the industry relies on passed
 * `postmark-mcp` right up to the moment it didn't.
 *
 * Provenance cannot catch this, because the provenance is genuine.
 * Reputation cannot, because the reputation was earned. What catches it
 * is noticing that **the thing changed** — specifically that the
 * surface a model is asked to trust changed — and saying so.
 *
 * For an MCP server the surface is its tool names and descriptions,
 * which matters more than it sounds: a tool description is text the
 * model reads and acts on, so editing it after approval is a code
 * change to the agent's instructions that no code review sees. For a
 * skill or agent it is the declared tool scope, which is a privilege
 * grant.
 *
 * No registry currently publishes this as a signal.
 */
import { createHash } from "node:crypto";
import type { AssayReport } from "./types.js";

/** One capability an artifact exposes to a model. */
export interface SurfaceEntry {
  /** Tool name, or the declared scope entry. */
  name: string;
  /**
   * Digest of the description the model reads. Stored hashed rather
   * than verbatim so a surface record stays small, and so comparing two
   * versions never requires shipping both descriptions around.
   */
  descriptionDigest?: string;
  /** Character length, so "expanded a lot" is visible without the text. */
  descriptionLength?: number;
}

export interface ToolSurface {
  /** Where it came from: statically declared, or observed at runtime. */
  origin: "declared" | "observed";
  entries: SurfaceEntry[];
}

export function digestDescription(text: string): string {
  return createHash("sha256").update(text.trim()).digest("hex").slice(0, 16);
}

export function makeSurface(
  origin: ToolSurface["origin"],
  tools: readonly { name: string; description?: string }[],
): ToolSurface {
  return {
    origin,
    entries: tools
      .map((t) => ({
        name: t.name,
        ...(t.description !== undefined
          ? {
              descriptionDigest: digestDescription(t.description),
              descriptionLength: t.description.trim().length,
            }
          : {}),
      }))
      // Sorted so two captures of the same surface compare equal
      // regardless of enumeration order.
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
  };
}

export type SurfaceChangeKind =
  | "tool-added"
  | "tool-removed"
  | "description-changed"
  | "description-grew"
  /** The two surfaces were captured differently and are not comparable. */
  | "origin-mismatch"
  /** What the artifact RETURNED differs from what it DECLARES. */
  | "declared-vs-observed";

export interface SurfaceChange {
  kind: SurfaceChangeKind;
  name: string;
  detail: string;
  /**
   * Whether this warrants re-reviewing the artifact before trusting it
   * again. Not every change is suspicious — but every one of these is
   * something a consumer approved once and did not approve again.
   */
  requiresReview: boolean;
}

export interface SurfaceDiff {
  changes: SurfaceChange[];
  /** True when the two surfaces are byte-identical. */
  unchanged: boolean;
  /**
   * False when the two captures are not comparable — one declared, one
   * observed. Callers must not read `unchanged: false` as "it changed"
   * in that case; it means "we cannot tell".
   */
  comparable: boolean;
}

/**
 * Compare two captured surfaces.
 *
 * Deliberately reports description changes as prominently as added
 * tools. The instinct is that a new tool is the dangerous event, but
 * the tool-poisoning literature says otherwise: the payload goes in a
 * description, because that is what the model reads and what no diff
 * review looks at. `postmark-mcp` did not add a tool.
 */
export function diffSurfaces(before: ToolSurface, after: ToolSurface): SurfaceDiff {
  // Comparing a declared surface to an observed one is comparing two
  // different measurements. The extraction differs, so nearly every
  // entry would look changed and the result would be a stream of false
  // rug-pull alerts — which is worse than no signal, because people
  // learn to ignore it.
  if (before.origin !== after.origin) {
    return {
      comparable: false,
      unchanged: false,
      changes: [
        {
          kind: "origin-mismatch",
          name: "(surface)",
          detail:
            `One surface was ${before.origin}, the other ${after.origin}. ` +
            "These are different measurements and are not comparable — re-run both the same way.",
          requiresReview: false,
        },
      ],
    };
  }

  const changes: SurfaceChange[] = [];
  const beforeByName = new Map(before.entries.map((e) => [e.name, e]));
  const afterByName = new Map(after.entries.map((e) => [e.name, e]));

  for (const [name, a] of afterByName) {
    const b = beforeByName.get(name);
    if (!b) {
      changes.push({
        kind: "tool-added",
        name,
        detail: `"${name}" was not present in the earlier version.`,
        requiresReview: true,
      });
      continue;
    }
    if (b.descriptionDigest && a.descriptionDigest && b.descriptionDigest !== a.descriptionDigest) {
      const from = b.descriptionLength ?? 0;
      const to = a.descriptionLength ?? 0;
      // A description that roughly doubles is called out separately:
      // injected instructions have to go somewhere, and they make the
      // text longer.
      const grew = to > from * 1.5 && to - from > 80;
      changes.push({
        kind: grew ? "description-grew" : "description-changed",
        name,
        detail: grew
          ? `"${name}" description grew from ${from} to ${to} characters. A model reads this text and acts on it.`
          : `"${name}" description changed (${from} → ${to} characters). A model reads this text and acts on it.`,
        requiresReview: true,
      });
    }
  }

  for (const [name] of beforeByName) {
    if (!afterByName.has(name)) {
      changes.push({
        kind: "tool-removed",
        name,
        detail: `"${name}" is no longer exposed.`,
        // A removal breaks consumers but does not deceive them.
        requiresReview: false,
      });
    }
  }

  changes.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { changes, unchanged: changes.length === 0, comparable: true };
}

/**
 * Compare what an artifact DECLARES against what it was observed to
 * RETURN, within a single run.
 *
 * This is the runtime half of tool poisoning, and the half static
 * analysis structurally cannot see: a server whose source ships one
 * description and whose `tools/list` returns another is lying to
 * exactly the audience that matters — the model — while passing every
 * source-level review.
 *
 * A mismatch is not automatically malicious. Descriptions get built at
 * runtime, pulled from config, or localised. But it is always something
 * a reader deserves to know, because the source they audited is not
 * what the model will read.
 */
export function compareDeclaredToObserved(
  declared: ToolSurface,
  observed: ToolSurface,
): SurfaceChange[] {
  const out: SurfaceChange[] = [];
  const declaredByName = new Map(declared.entries.map((e) => [e.name, e]));

  for (const seen of observed.entries) {
    const source = declaredByName.get(seen.name);
    if (!source) {
      out.push({
        kind: "declared-vs-observed",
        name: seen.name,
        detail: `"${seen.name}" is exposed at runtime but not declared in source.`,
        requiresReview: true,
      });
      continue;
    }
    if (
      source.descriptionDigest &&
      seen.descriptionDigest &&
      source.descriptionDigest !== seen.descriptionDigest
    ) {
      out.push({
        kind: "declared-vs-observed",
        name: seen.name,
        detail:
          `"${seen.name}" returns a different description than its source declares ` +
          `(${source.descriptionLength ?? 0} → ${seen.descriptionLength ?? 0} characters). ` +
          "The model reads the runtime text, not the source.",
        requiresReview: true,
      });
    }
  }
  return out.sort((a, b) => (a.name < b.name ? -1 : 1));
}

/** Pull a captured surface out of a report, if it recorded one. */
export function surfaceOf(report: AssayReport): ToolSurface | null {
  return report.surface ?? null;
}
