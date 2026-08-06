/**
 * Where an artifact's documentation actually lives.
 *
 * This module exists because of a specific, embarrassing audit result:
 * `readme-present` failed **all ten official Anthropic skills**, all
 * ten prompt-based agents, and eight of ten real plugins — because it
 * demanded a root `README.md`.
 *
 * For a skill, `SKILL.md` IS the documentation. For a prompt-based
 * agent, the agent markdown is. For a plugin, the manifest plus the
 * bundled docs are. Requiring a second file the format never asked for
 * is a defect in the check, not in the artifact.
 *
 * The general lesson, worth keeping in front of anyone adding a check:
 * encoding one ecosystem's convention as if it were universal is how a
 * trust tool ends up defaming legitimate work.
 */
import type { SourceReader } from "../ports.js";
import type { ArtifactKind } from "../types.js";

/**
 * Documentation candidates per kind, in preference order.
 *
 * `README` stays in every list — it is genuinely conventional and often
 * present — but it is never the ONLY acceptable answer except for
 * kinds whose format has no document of its own.
 */
const DOC_CANDIDATES: Record<string, readonly string[]> = {
  skill: ["SKILL.md", "README.md", "readme.md"],
  plugin: ["README.md", "readme.md", "PLUGIN.md", ".claude-plugin/README.md"],
  agent: ["README.md", "readme.md", "AGENT.md"],
  mcp: ["README.md", "readme.md", "docs/README.md"],
};

const FALLBACK = ["README.md", "readme.md", "SKILL.md", "AGENT.md", "docs/README.md"] as const;

export interface ResolvedDocs {
  path: string;
  body: string;
}

/**
 * Find the artifact's primary documentation.
 *
 * For an agent this additionally searches the markdown-agent layouts,
 * because a prompt-based agent's definition file is its documentation —
 * there is no separate one and there should not be.
 */
export async function resolveDocs(
  source: SourceReader,
  kind: ArtifactKind,
): Promise<ResolvedDocs | null> {
  for (const path of DOC_CANDIDATES[kind] ?? FALLBACK) {
    const body = await source.readFile(path);
    if (body && body.trim().length > 0) return { path, body };
  }

  if (kind === "agent") {
    const md = await findAgentMarkdown(source);
    if (md) {
      const body = await source.readFile(md);
      if (body && body.trim().length > 0) return { path: md, body };
    }
  }
  return null;
}

/**
 * Directories where a markdown-defined agent conventionally lives, at
 * ANY depth.
 *
 * Anchoring these to the repository root was a real false-negative: the
 * two most-starred agent collections nest their agents under
 * `plugins/<name>/agents/` and under category directories, so
 * `agent-shape-declared` — a BLOCKING check — failed the most common
 * layout there is, and the artifact could not even be auto-detected.
 */
const AGENT_DIR = /(^|\/)(\.claude\/)?(agents|subagents)\//;

/** Files that are project meta, not an agent definition. */
const NOT_AN_AGENT =
  /^(README|CONTRIBUTING|LICENSE|CHANGELOG|CODE_OF_CONDUCT|SECURITY|ARCHITECTURE|CLAUDE|AGENTS|GEMINI)\.md$/i;

/**
 * Locate a prompt-based agent definition.
 *
 * Accepts both the nested convention (`agents/reviewer.md`, the shape
 * real plugins use) and a bare markdown file at the artifact root, which
 * is what you get when a single agent is published on its own.
 *
 * Project-meta files are excluded by name. Without that, pointing Assay
 * at any repository containing a `CONTRIBUTING.md` would "detect" an
 * agent — a false positive in the opposite direction.
 */
export async function findAgentMarkdown(source: SourceReader): Promise<string | null> {
  const tree = await source.listTree();
  const markdown = tree.filter((e) => e.type === "file" && e.path.endsWith(".md"));

  const inConventionalDir = markdown
    .filter((e) => AGENT_DIR.test(e.path))
    .filter((e) => !NOT_AN_AGENT.test(e.path.split("/").pop() ?? ""))
    // Shallowest first, then alphabetical: in a collection, the
    // top-level layout is the more representative one.
    .sort(
      (a, b) => a.path.split("/").length - b.path.split("/").length || (a.path < b.path ? -1 : 1),
    );
  if (inConventionalDir.length > 0) return inConventionalDir[0]!.path;

  // A single agent published on its own: one markdown file at the root
  // that is not project meta, and that carries frontmatter.
  const atRoot = markdown.filter((e) => !e.path.includes("/") && !NOT_AN_AGENT.test(e.path));
  for (const candidate of atRoot.sort((a, b) => (a.path < b.path ? -1 : 1))) {
    const body = await source.readFile(candidate.path);
    if (body && /^---\r?\n/.test(body)) return candidate.path;
  }

  // Last resort: the SHAPE rather than the location. An agent
  // definition is markdown whose frontmatter declares a name and a
  // description, and a collection is free to file that wherever it
  // likes. Bounded, because this reads file bodies.
  const candidates = markdown
    .filter((e) => !NOT_AN_AGENT.test(e.path.split("/").pop() ?? ""))
    .sort(
      (a, b) => a.path.split("/").length - b.path.split("/").length || (a.path < b.path ? -1 : 1),
    )
    .slice(0, 200);
  for (const candidate of candidates) {
    const body = await source.readFile(candidate.path);
    if (!body) continue;
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(body);
    if (fm && /^\s*name\s*:/m.test(fm[1]!) && /^\s*description\s*:/m.test(fm[1]!)) {
      return candidate.path;
    }
  }
  return null;
}
