/**
 * Static capture of an artifact's declared tool surface.
 *
 * Works offline, which matters: the rug-pull signal should not require
 * a sandbox and an API key to compute. A behavioral run can replace
 * this with the surface it *observed*, which is strictly better — a
 * server can declare one thing in source and return another over the
 * wire, and only running it catches that — but the declared surface is
 * available on every run and catches source-level edits.
 */
import type { SourceReader } from "../ports.js";
import type { ArtifactKind } from "../types.js";
import { makeSurface, type ToolSurface } from "../surface.js";
import { parseFrontmatter, parseList, readManifest, PLUGIN_MANIFESTS } from "./manifest.js";

/** Registration shapes the MCP SDKs actually use. */
const REGISTRATION =
  /\.(?:tool|registerTool|setRequestHandler)\s*\(\s*["'`]([^"'`]+)["'`]\s*(?:,\s*["'`]([^"'`]*)["'`])?/g;

export async function captureSurface(
  source: SourceReader,
  kind: ArtifactKind,
): Promise<ToolSurface | null> {
  if (kind === "mcp") return captureMcp(source);
  if (kind === "skill") return captureSkill(source);
  if (kind === "plugin") return capturePlugin(source);
  return null;
}

async function captureMcp(source: SourceReader): Promise<ToolSurface | null> {
  const tree = await source.listTree();
  const sources = tree.filter(
    (e) =>
      e.type === "file" &&
      /\.(ts|js|mjs|py)$/.test(e.path) &&
      !/(^|\/)(dist|build|node_modules|tests?)\//.test(e.path),
  );
  const tools: { name: string; description?: string }[] = [];
  for (const f of sources.slice(0, 200)) {
    const body = await source.readFile(f.path);
    if (!body) continue;
    for (const m of body.matchAll(REGISTRATION)) {
      tools.push({ name: m[1]!, ...(m[2] !== undefined ? { description: m[2] } : {}) });
    }
  }
  return tools.length > 0 ? makeSurface("declared", dedupe(tools)) : null;
}

/**
 * A skill's surface is its declared tool scope — a privilege grant, so
 * a change to it is exactly as consequential as a new MCP tool.
 */
async function captureSkill(source: SourceReader): Promise<ToolSurface | null> {
  const raw = await source.readFile("SKILL.md");
  if (!raw) return null;
  const fm = parseFrontmatter(raw);
  const declared = parseList(fm.fields["allowed-tools"] ?? fm.fields["allowedTools"]);
  return declared.length > 0
    ? makeSurface(
        "declared",
        declared.map((name) => ({ name })),
      )
    : null;
}

/** A plugin's surface is what its manifest says it bundles. */
async function capturePlugin(source: SourceReader): Promise<ToolSurface | null> {
  const manifest = await readManifest(source, PLUGIN_MANIFESTS);
  if (!manifest?.data) return null;
  const tools: { name: string }[] = [];
  for (const key of ["skills", "commands", "subagents", "agents", "mcpServers"]) {
    const v = manifest.data[key];
    if (Array.isArray(v)) {
      for (const item of v) if (typeof item === "string") tools.push({ name: `${key}:${item}` });
    } else if (v && typeof v === "object") {
      for (const name of Object.keys(v)) tools.push({ name: `${key}:${name}` });
    }
  }
  return tools.length > 0 ? makeSurface("declared", tools) : null;
}

/** Last declaration wins, matching how a duplicate registration behaves. */
function dedupe(tools: { name: string; description?: string }[]) {
  return [...new Map(tools.map((t) => [t.name, t])).values()];
}
