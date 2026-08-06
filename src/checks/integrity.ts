/**
 * Integrity — "is this thing well-formed, and does it declare a
 * coherent identity?"
 *
 * This is the axis a consumer never thinks about until it fails: an
 * artifact whose manifest does not parse, or whose declared entry point
 * does not exist, will not load no matter how good its documentation
 * is. These checks are cheap, deterministic, and unambiguous, which is
 * exactly what makes them a good floor.
 *
 * Note what is NOT here: uniqueness of the name. Uniqueness is a
 * property of a *registry*, not of an artifact — the same skill is
 * simultaneously unique on one registry and taken on another — and it
 * is the only thing that would force this layer to talk to a database.
 * Keeping it out is what lets `assay run` work offline.
 */
import { defineCheck } from "../check.js";
import type { CheckContext } from "../check.js";
import type { CheckResult, Evidence } from "../types.js";
import { findAgentMarkdown } from "./docs-resolution.js";
import {
  AGENT_MANIFESTS,
  PLUGIN_MANIFESTS,
  SEMVER_RE,
  SLUG_RE,
  parseFrontmatter,
  readManifest,
} from "./manifest.js";
import { checkSpecUrl } from "../version.js";

/** "a plugin" but "an agent" — this string is the first output a new
 *  user sees, so it should read like English. */
function article(kind: string): string {
  return /^[aeiou]/i.test(kind) ? "an" : "a";
}

/** Where each kind declares its identity. */
const MANIFEST_PATHS: Record<string, readonly string[]> = {
  skill: ["SKILL.md"],
  mcp: ["package.json", "pyproject.toml", "mcp.json"],
  agent: [...AGENT_MANIFESTS],
  plugin: [...PLUGIN_MANIFESTS],
};

/**
 * The identity an artifact declares about itself, normalized across
 * the four kinds so the checks below do not each re-implement
 * "where does a skill keep its name".
 */
export interface DeclaredIdentity {
  manifestPath: string | null;
  /** True when the manifest exists but could not be parsed. */
  malformed: boolean;
  name?: string;
  version?: string;
  description?: string;
  homepage?: string;
  entry?: string;
}

export async function readIdentity(ctx: CheckContext): Promise<DeclaredIdentity> {
  const kind = ctx.subject.kind;
  const paths = MANIFEST_PATHS[kind] ?? ["package.json"];

  if (kind === "skill") {
    const body = await ctx.source.readFile("SKILL.md");
    if (body === null) return { manifestPath: null, malformed: false };
    const fm = parseFrontmatter(body);
    return {
      manifestPath: "SKILL.md",
      // A SKILL.md with no frontmatter at all is missing its identity
      // block, not malformed markdown.
      malformed: false,
      ...(fm.fields["name"] ? { name: fm.fields["name"] } : {}),
      ...(fm.fields["version"] ? { version: fm.fields["version"] } : {}),
      ...(fm.fields["description"] ? { description: fm.fields["description"] } : {}),
      ...(fm.fields["homepage"] ? { homepage: fm.fields["homepage"] } : {}),
    };
  }

  const manifest = await readManifest(ctx.source, paths);
  if (!manifest) {
    // A prompt-based agent has no JSON manifest by design — the
    // markdown body IS the agent. `agent-shape-declared` already knew
    // this; `manifest-present` did not, so every real prompt-based
    // agent failed a BLOCKING check. One resolver now, so the two
    // cannot disagree again.
    if (kind === "agent") {
      const md = await findAgentMarkdown(ctx.source);
      if (md) {
        const raw = (await ctx.source.readFile(md)) ?? "";
        const fm = parseFrontmatter(raw);
        return {
          manifestPath: md,
          malformed: false,
          ...(fm.fields["name"] ? { name: fm.fields["name"] } : {}),
          ...(fm.fields["description"] ? { description: fm.fields["description"] } : {}),
        };
      }
    }
    return { manifestPath: null, malformed: false };
  }
  if (!manifest.data) return { manifestPath: manifest.path, malformed: true };

  const d = manifest.data;
  const str = (k: string): string | undefined =>
    typeof d[k] === "string" ? (d[k] as string) : undefined;
  // npm's overwhelmingly common form is `"bin": {"name": "path"}`, and
  // reading only the string form left `entry-resolves` — a weight-4
  // BLOCKING integrity check — silently `neutral` on most Node MCP
  // servers, so it neither failed nor reduced coverage.
  // `behavioral/install.ts` already resolved the object form, so the two
  // disagreed about the same field.
  const bin = d["bin"];
  const binEntry =
    typeof bin === "string"
      ? bin
      : bin && typeof bin === "object"
        ? Object.values(bin as Record<string, unknown>).find(
            (v): v is string => typeof v === "string",
          )
        : undefined;
  const entry = str("main") ?? str("entry") ?? str("entrypoint") ?? binEntry;

  return {
    manifestPath: manifest.path,
    malformed: false,
    ...(str("name") ? { name: str("name")! } : {}),
    ...(str("version") ? { version: str("version")! } : {}),
    ...(str("description") ? { description: str("description")! } : {}),
    ...(str("homepage") ? { homepage: str("homepage")! } : {}),
    ...(entry ? { entry } : {}),
  };
}

export const manifestPresent = defineCheck({
  id: "manifest-present",
  version: "1.0.0",
  title: "Manifest present and parseable",
  category: "structural",
  axis: "integrity",
  determinism: "deterministic",
  weight: 5,
  blocking: true,
  spec: checkSpecUrl("manifest-present"),
  inspects:
    "The kind's manifest file — package.json, SKILL.md frontmatter, .claude-plugin/plugin.json — parsed, not merely present.",
  rationale:
    "Everything downstream reads the manifest: the name a consumer installs under, the entry point a client executes, the dependency set. When it is missing or unparseable the artifact cannot be installed at all, and every other check is guessing at an artifact it cannot identify.",
  async run(ctx): Promise<CheckResult> {
    const id = await readIdentity(ctx);
    const expected = MANIFEST_PATHS[ctx.subject.kind] ?? ["package.json"];

    if (id.manifestPath === null) {
      return {
        status: "fail",
        summary: `No manifest found for ${article(ctx.subject.kind)} ${ctx.subject.kind} artifact.`,
        detail: `Looked for: ${expected.join(", ")}.`,
        remediation: `Add ${expected[0]} declaring at least a name and description.`,
      };
    }
    if (id.malformed) {
      return {
        status: "fail",
        summary: `${id.manifestPath} exists but does not parse.`,
        detail: "A client that cannot read the manifest cannot install the artifact at all.",
        remediation: `Fix the syntax in ${id.manifestPath}.`,
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    return {
      status: "pass",
      summary: `Manifest found at ${id.manifestPath}.`,
      evidence: [{ type: "file", path: id.manifestPath }],
    };
  },
});

export const nameDeclared = defineCheck({
  id: "name-declared",
  version: "1.0.0",
  title: "Name declared and well-formed",
  category: "structural",
  axis: "integrity",
  determinism: "deterministic",
  weight: 3,
  spec: checkSpecUrl("name-declared"),
  rationale:
    "The name is the identity a consumer types and a registry indexes. Without a well-formed one the artifact gets installed under whatever the directory happened to be called, which is exactly how a package ends up sitting where a consumer expected a different package.",
  async run(ctx): Promise<CheckResult> {
    const id = await readIdentity(ctx);
    if (id.manifestPath === null || id.malformed) {
      // manifest-present already reported this; saying it twice would
      // double-penalize one defect.
      return { status: "skip", summary: "No parseable manifest to read a name from." };
    }
    if (!id.name) {
      return {
        status: "fail",
        summary: "No name declared.",
        remediation: `Add a "name" field to ${id.manifestPath}.`,
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    // npm scopes are legitimate and common for MCP servers.
    const bare = id.name.replace(/^@[^/]+\//, "");
    if (!SLUG_RE.test(bare)) {
      return {
        status: "warn",
        summary: `Name "${id.name}" is not lowercase kebab-case.`,
        detail:
          "Client install paths, URLs, and directory names are derived from the name, and mixed case or spaces behave differently across filesystems.",
        remediation: "Use lowercase letters, digits, and hyphens.",
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    return {
      status: "pass",
      summary: `Name "${id.name}" is well-formed.`,
      evidence: [{ type: "file", path: id.manifestPath }],
    };
  },
});

export const versionFormat = defineCheck({
  id: "version-format",
  version: "1.0.0",
  title: "Version is semver",
  category: "structural",
  axis: "integrity",
  determinism: "deterministic",
  weight: 2,
  spec: checkSpecUrl("version-format"),
  rationale:
    "A version is what lets a consumer tell a patch from a rewrite, and what lets a grade be attributed to a release. Without one, no report can say which bytes scored what — the evaluation and the thing evaluated come apart.",
  async run(ctx): Promise<CheckResult> {
    const id = await readIdentity(ctx);
    if (id.manifestPath === null || id.malformed) {
      return { status: "skip", summary: "No parseable manifest to read a version from." };
    }
    if (!id.version) {
      // A skill is not npm. `version` is not part of the Agent Skills
      // frontmatter spec, and Anthropic's own pdf/pptx/xlsx skills omit
      // it — so this warned on every skill that follows the standard,
      // which is the "defaming legitimate work" pattern this catalog
      // has already had to correct eight times.
      if (ctx.subject.kind === "skill") {
        return {
          status: "neutral",
          summary: "Skills do not declare a version — the frontmatter spec has no such field.",
        };
      }
      return {
        status: "warn",
        summary: "No version declared.",
        detail:
          "Without a version, consumers cannot tell whether an update changed anything, and an evaluation cannot be attributed to a release.",
        remediation: `Add a "version" field to ${id.manifestPath}.`,
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    if (!SEMVER_RE.test(id.version)) {
      return {
        status: "warn",
        summary: `Version "${id.version}" is not semver.`,
        remediation: "Use MAJOR.MINOR.PATCH so consumers can reason about compatibility.",
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    return { status: "pass", summary: `Version ${id.version}.` };
  },
});

export const entryResolves = defineCheck({
  id: "entry-resolves",
  version: "1.0.0",
  title: "Declared entry point exists",
  category: "structural",
  axis: "integrity",
  determinism: "deterministic",
  weight: 4,
  blocking: true,
  appliesTo: { kinds: ["mcp", "agent"] },
  spec: checkSpecUrl("entry-resolves"),
  inspects:
    "The path the manifest names as its entry point, resolved against the files that actually ship.",
  rationale:
    "The manifest points at a file that has to exist for the artifact to load. When it does not, the failure lands on the consumer at install time, and the manifest was the only place it could have been caught first.",
  async run(ctx): Promise<CheckResult> {
    const id = await readIdentity(ctx);
    if (!id.entry) {
      return {
        status: "neutral",
        summary: "No entry point declared; the client's default resolution applies.",
      };
    }
    const clean = id.entry.replace(/^\.\//, "");
    if (await ctx.source.exists(clean)) {
      return {
        status: "pass",
        summary: `Entry point ${clean} exists.`,
        evidence: [{ type: "file", path: clean }],
      };
    }
    // A build step can legitimately produce the entry, so say so rather
    // than accusing the publisher of a broken package outright.
    const built = /^(dist|build|out|lib)\//.test(clean);
    return {
      status: built ? "warn" : "fail",
      summary: `Declared entry point ${clean} is not present.`,
      detail: built
        ? "It sits under a build directory, so it is probably produced by a build step — but a consumer installing from source will not have it."
        : "The manifest points at a file that does not exist, so the artifact will fail to load.",
      remediation: built
        ? "Ship the built output, or declare a prepare/build script that produces it."
        : `Fix the entry path in ${id.manifestPath ?? "the manifest"}, or add the missing file.`,
      evidence: [{ type: "file", path: id.manifestPath ?? "" }],
    };
  },
});

/**
 * Declared files must actually be there.
 *
 * A `files` allowlist that names a directory the package does not have
 * produces a published tarball missing the thing it advertises — a
 * failure mode that only shows up after publish, when it is expensive.
 */
export const declaredFilesExist = defineCheck({
  id: "declared-files-exist",
  version: "1.0.0",
  title: "Declared files exist",
  category: "structural",
  axis: "integrity",
  determinism: "deterministic",
  weight: 1,
  spec: checkSpecUrl("declared-files-exist"),
  rationale:
    "A files allowlist is a promise about what ships. An entry resolving to nothing means either the promise is stale or the build does not produce what the manifest claims — and a consumer installing from source gets the gap, not the promise.",
  async run(ctx): Promise<CheckResult> {
    const manifest = await readManifest(ctx.source, ["package.json"]);
    const files = manifest?.data?.["files"];
    if (!Array.isArray(files) || files.length === 0) {
      return { status: "neutral", summary: "No files allowlist declared." };
    }
    const missing: string[] = [];
    for (const f of files) {
      if (typeof f !== "string") continue;
      // Globs and negations are resolved by the packer, not by us.
      if (/[*?![\]]/.test(f)) continue;
      const clean = f.replace(/^\.\//, "").replace(/\/$/, "");
      if (clean && !(await ctx.source.exists(clean))) missing.push(clean);
    }
    if (missing.length === 0) {
      return { status: "pass", summary: `All ${files.length} declared file entries resolve.` };
    }
    const evidence: Evidence[] = [{ type: "file", path: "package.json" }];
    return {
      status: "warn",
      summary: `${missing.length} declared file entr${missing.length === 1 ? "y does" : "ies do"} not exist.`,
      detail: missing.map((m) => `- \`${m}\``).join("\n"),
      remediation:
        "Remove the stale entries, or add the missing paths — the published tarball will not contain them.",
      evidence,
    };
  },
});

export const INTEGRITY_CHECKS = [
  manifestPresent,
  nameDeclared,
  versionFormat,
  entryResolves,
  declaredFilesExist,
];
