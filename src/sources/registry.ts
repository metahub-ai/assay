/**
 * Resolving an artifact through a MetaHub-compatible registry.
 *
 * `metahub:skill/warden` is not a new transport. The registry does not
 * host artifact bytes — it holds a catalog entry that names where the
 * bytes are, and the important field is `publishedSha`: the exact
 * commit the registry is serving right now.
 *
 * That distinction is the whole reason this exists. `assay run
 * owner/repo//path` grades whatever `main` happens to be at the moment
 * you ask, which is not what anybody installed. Resolving through the
 * registry pins the evaluation to the commit a consumer actually
 * receives, so the grade and the install cannot drift apart.
 *
 * The registry is also authoritative about the artifact's KIND, so
 * detection stops being a guess for these targets.
 */

/** Default registry. Overridable for self-hosted deployments. */
export const DEFAULT_REGISTRY = "https://developer.metahub.ai";

/** Artifact kinds a registry can serve, in probe order. */
export const REGISTRY_KINDS = ["skill", "mcp", "agent", "plugin"] as const;
export type RegistryKind = (typeof REGISTRY_KINDS)[number];

/** What a catalog entry has to give us to be usable. */
export interface RegistryArtifact {
  slug: string;
  kind: RegistryKind;
  /** Where the bytes actually live. */
  repoUrl: string;
  /** Subdirectory within the repository, when the artifact is not the root. */
  repoPath?: string | null;
  repoBranch?: string | null;
  /**
   * The commit the registry is serving. This is the point of resolving
   * through a registry at all, so a missing one is reported rather than
   * silently degraded to a branch name.
   */
  publishedSha?: string | null;
  version?: string | null;
  name?: string | null;
  visibility?: string | null;
}

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

/** How long to wait on the catalog before giving up. */
const TIMEOUT_MS = 15_000;

/**
 * A parsed `metahub:` specifier.
 *
 * `metahub:skill/warden` names the kind and costs one request.
 * `metahub:warden` does not, and costs up to four — the lookup endpoint
 * is keyed by kind and 404s on the wrong one, so there is no way to ask
 * "whatever kind this slug is" in a single call.
 */
export interface RegistrySpec {
  slug: string;
  kind?: RegistryKind;
  registry: string;
}

export function parseRegistrySpec(raw: string, registry = DEFAULT_REGISTRY): RegistrySpec {
  const body = raw.slice(raw.indexOf(":") + 1).trim();
  if (!body) throw new RegistryError("No artifact named. Try `metahub:skill/some-slug`.");

  const parts = body.split("/").filter(Boolean);
  if (parts.length > 2) {
    throw new RegistryError(
      `Not a registry artifact: "${body}". Expected \`metahub:<slug>\` or \`metahub:<kind>/<slug>\`.`,
    );
  }

  if (parts.length === 2) {
    const [kind, slug] = parts as [string, string];
    if (!(REGISTRY_KINDS as readonly string[]).includes(kind)) {
      throw new RegistryError(
        `Unknown artifact kind "${kind}". Expected one of: ${REGISTRY_KINDS.join(", ")}.`,
      );
    }
    return { slug, kind: kind as RegistryKind, registry };
  }
  return { slug: parts[0]!, registry };
}

/** One catalog lookup. Returns null for a clean 404, throws otherwise. */
async function lookup(
  registry: string,
  kind: RegistryKind,
  slug: string,
  fetchImpl: typeof fetch,
): Promise<RegistryArtifact | null> {
  const url = `${registry.replace(/\/+$/, "")}/api/public/artifacts/${kind}/${encodeURIComponent(slug)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetchImpl(url, {
      signal: controller.signal,
      // The catalog rejects some default agents outright — a bare
      // `Python-urllib/3.9` gets a 403 — so identify ourselves.
      headers: { accept: "application/json", "user-agent": "assay" },
    });
  } catch (err) {
    const msg =
      (err as Error).name === "AbortError"
        ? `timed out after ${TIMEOUT_MS}ms`
        : (err as Error).message;
    throw new RegistryError(`Could not reach the registry at ${registry} — ${msg}`);
  } finally {
    clearTimeout(timer);
  }

  if (res.status === 404) return null;
  if (res.status === 401 || res.status === 403) {
    throw new RegistryError(
      `The registry refused the request for ${kind}/${slug} (HTTP ${res.status}). ` +
        `Private and unlisted artifacts are not reachable without credentials.`,
    );
  }
  if (!res.ok) {
    throw new RegistryError(`Registry returned HTTP ${res.status} for ${kind}/${slug}.`);
  }

  let body: unknown;
  try {
    body = await res.json();
  } catch {
    // A Next.js app serving its SPA shell for an unknown route answers
    // 200 with HTML, which is indistinguishable from a real endpoint
    // until you try to parse it.
    throw new RegistryError(
      `${registry} did not return JSON. Is it a MetaHub-compatible registry?`,
    );
  }

  const record = (body as { artifact?: unknown })?.artifact ?? body;
  const a = record as Partial<RegistryArtifact>;
  if (!a || typeof a.repoUrl !== "string" || !a.repoUrl) {
    throw new RegistryError(
      `The registry entry for ${kind}/${slug} does not say where the artifact lives ` +
        `(no repoUrl), so there is nothing to evaluate.`,
    );
  }
  return {
    slug: a.slug ?? slug,
    kind: (a.kind as RegistryKind) ?? kind,
    repoUrl: a.repoUrl,
    repoPath: a.repoPath ?? null,
    repoBranch: a.repoBranch ?? null,
    publishedSha: a.publishedSha ?? null,
    version: a.version ?? null,
    name: a.name ?? null,
    visibility: a.visibility ?? null,
  };
}

/**
 * Resolve a `metahub:` specifier to a catalog entry.
 *
 * When the kind is known this is one request. When it is not, all four
 * are tried at once rather than in sequence — four concurrent requests
 * cost the same wall-clock as one, and a user typing a bare slug should
 * not pay four times the latency for our lookup shape.
 */
export async function resolveRegistryArtifact(
  spec: RegistrySpec,
  fetchImpl: typeof fetch = fetch,
): Promise<RegistryArtifact> {
  if (spec.kind) {
    const found = await lookup(spec.registry, spec.kind, spec.slug, fetchImpl);
    if (found) return found;
    throw new RegistryError(
      `No ${spec.kind} named "${spec.slug}" in the registry at ${spec.registry}.\n` +
        `  Search it:  ${spec.registry.replace(/\/+$/, "")}/api/public/artifacts/search?q=${encodeURIComponent(spec.slug)}`,
    );
  }

  const settled = await Promise.allSettled(
    REGISTRY_KINDS.map((k) => lookup(spec.registry, k, spec.slug, fetchImpl)),
  );

  const hits = settled
    .filter((r): r is PromiseFulfilledResult<RegistryArtifact | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is RegistryArtifact => v !== null);

  if (hits.length === 1) return hits[0]!;

  // Ambiguity is a human's decision, not a coin flip: the same slug can
  // legitimately name a skill and a plugin.
  if (hits.length > 1) {
    throw new RegistryError(
      `"${spec.slug}" names ${hits.length} different artifacts in the registry. Say which:\n` +
        hits.map((h) => `  assay run metahub:${h.kind}/${h.slug}`).join("\n"),
    );
  }

  // Every lookup failed. If they failed for a REASON — the registry is
  // unreachable, or refused us — say that instead of "not found", which
  // would blame the user for our transport problem.
  const rejected = settled.find((r) => r.status === "rejected");
  if (rejected && rejected.status === "rejected") throw rejected.reason as Error;

  throw new RegistryError(
    `Nothing named "${spec.slug}" in the registry at ${spec.registry}.\n` +
      `  Tried: ${REGISTRY_KINDS.join(", ")}.\n` +
      `  Search it:  ${spec.registry.replace(/\/+$/, "")}/api/public/artifacts/search?q=${encodeURIComponent(spec.slug)}`,
  );
}

/**
 * The git coordinates to fetch, from a catalog entry.
 *
 * Prefers `publishedSha` over `repoBranch` deliberately. A branch name
 * resolves to whatever it points at today; the published sha is what
 * the registry is actually serving, which is the only ref that makes
 * the grade and the install the same thing.
 */
export function gitCoordinatesFor(a: RegistryArtifact): {
  url: string;
  ref?: string;
  subdir?: string;
  pinned: boolean;
} {
  const ref = a.publishedSha ?? a.repoBranch ?? undefined;
  return {
    url: a.repoUrl,
    ...(ref ? { ref } : {}),
    ...(a.repoPath ? { subdir: a.repoPath.replace(/^\.?\//, "") } : {}),
    pinned: Boolean(a.publishedSha),
  };
}
