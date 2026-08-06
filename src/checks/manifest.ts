/**
 * Shared manifest reading.
 *
 * Checks across every category need "what does this artifact declare
 * about itself", and each re-parsing `package.json` would mean N
 * chances to disagree about what a malformed manifest means. One
 * reader, one answer.
 *
 * Everything here is deliberately tolerant: a manifest that does not
 * parse is a *finding* for the check that cares about it, never an
 * exception that kills the run.
 */
import type { SourceReader } from "../ports.js";

export interface ParsedManifest {
  path: string;
  /** null when the file exists but does not parse. */
  data: Record<string, unknown> | null;
  raw: string;
}

/**
 * Read and parse the first manifest that exists, in preference order.
 *
 * Format is chosen by EXTENSION, not assumed. An audit found Assay
 * reporting "pyproject.toml exists but does not parse" for every Python
 * MCP server — it parses fine, as TOML; we were calling `JSON.parse` on
 * it and reporting our own exception as the artifact's defect.
 * Accusing valid work of being malformed because we used the wrong
 * parser is the most damaging mistake a trust tool can make.
 */
export async function readManifest(
  source: SourceReader,
  paths: readonly string[],
): Promise<ParsedManifest | null> {
  for (const path of paths) {
    const raw = await source.readFile(path);
    if (raw === null) continue;
    return { path, data: parseManifest(path, raw), raw };
  }
  return null;
}

function parseManifest(path: string, raw: string): Record<string, unknown> | null {
  if (path.endsWith(".toml")) return parseTomlSurface(raw);
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * Extract the handful of top-level fields we care about from a TOML
 * manifest, without taking a TOML dependency.
 *
 * Deliberately shallow. Assay needs name, version, and description from
 * a `pyproject.toml`; it does not need to model TOML's type system, and
 * pulling a full parser into a security tool to read three strings adds
 * a parser CVE surface for no benefit. Anything it cannot read comes
 * back absent, which downstream checks report honestly.
 */
export function parseTomlSurface(raw: string): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  let section = "";
  let found = false;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed === "") continue;
    const header = /^\[([^\]]+)\]$/.exec(trimmed);
    if (header) {
      section = header[1]!;
      found = true;
      continue;
    }
    // Only [project] and [tool.poetry] carry the identity fields.
    if (section !== "project" && section !== "tool.poetry") continue;
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*(.+)$/.exec(trimmed);
    if (!kv) continue;
    const value = kv[2]!.trim().replace(/^(['"])([\s\S]*)\1$/, "$2");
    if (out[kv[1]!] === undefined) out[kv[1]!] = value;
  }
  // A file with no section headers at all is not TOML we understand.
  return found ? out : null;
}

export const PACKAGE_JSON = ["package.json"] as const;
export const PLUGIN_MANIFESTS = [
  ".claude-plugin/plugin.json",
  "plugin.json",
  ".claude/plugin.json",
] as const;
export const AGENT_MANIFESTS = ["agent.json", ".claude/agent.json"] as const;

/** YAML frontmatter split out of a markdown document. */
export interface Frontmatter {
  /** Raw key/value pairs. Values stay strings; callers coerce. */
  fields: Record<string, string>;
  /** Document body with the frontmatter block removed. */
  body: string;
  /** True when a `---` fence was present at all. */
  present: boolean;
}

/**
 * Parse the leading `---` frontmatter block of a markdown file.
 *
 * A deliberately small parser rather than a YAML dependency: artifact
 * frontmatter in practice is flat `key: value` plus the occasional
 * inline list, and pulling in a full YAML engine to read five fields
 * would add a parser CVE surface to a security tool. Anything it
 * cannot understand is reported as absent rather than guessed at.
 */
export function parseFrontmatter(text: string): Frontmatter {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!match) return { fields: {}, body: text, present: false };

  const fields: Record<string, string> = {};
  let currentKey: string | null = null;
  const listItems: string[] = [];

  const flushList = () => {
    if (currentKey && listItems.length > 0) {
      fields[currentKey] = listItems.join(", ");
      listItems.length = 0;
    }
  };

  // Block-scalar state. `description: >` and `description: |` are
  // ordinary YAML and the parser used to store the literal ">" as the
  // value — so a CORRECT skill reported "Description is 1 word", lost
  // most of its care axis, and scored below a lorem-ipsum stub. That is
  // the same monoculture defamation this module's other comments exist
  // to prevent: encoding one syntax as if it were the only one.
  let blockKey: string | null = null;
  let blockFold = false;
  let blockIndent = 0;
  const blockLines: string[] = [];

  const flushBlock = () => {
    if (blockKey && blockLines.length > 0) {
      // `>` folds newlines into spaces, `|` keeps them. Either way the
      // consumers here want the text, not the layout.
      const joined = blockFold
        ? blockLines.join(" ").replace(/\s+/g, " ").trim()
        : blockLines.join("\n").trim();
      if (joined) fields[blockKey] = joined;
    }
    blockKey = null;
    blockLines.length = 0;
  };

  const lines = match[1]!.split(/\r?\n/);
  for (const line of lines) {
    if (blockKey) {
      const indent = line.search(/\S/);
      // A blank line inside a block scalar is content, not a terminator.
      if (line.trim() === "") {
        blockLines.push("");
        continue;
      }
      if (indent >= blockIndent) {
        blockLines.push(line.slice(blockIndent));
        continue;
      }
      flushBlock();
    }

    if (/^\s*#/.test(line) || line.trim() === "") continue;
    const listItem = /^\s*-\s+(.*)$/.exec(line);
    if (listItem && currentKey) {
      listItems.push(stripQuotes(listItem[1]!.trim()));
      continue;
    }
    const kv = /^([A-Za-z0-9_-]+)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    flushList();
    currentKey = kv[1]!;
    const value = kv[2]!.trim();

    // `>`, `>-`, `|`, `|+` and friends open a block scalar whose body is
    // the following more-indented lines.
    const block = /^([|>])([+-]?\d*)$/.exec(value);
    if (block) {
      blockKey = currentKey;
      blockFold = block[1] === ">";
      const next = lines[lines.indexOf(line) + 1];
      blockIndent = next && next.search(/\S/) > 0 ? next.search(/\S/) : 2;
      continue;
    }

    if (value !== "") fields[currentKey] = stripQuotes(value);
  }
  flushBlock();
  flushList();

  return { fields, body: text.slice(match[0].length), present: true };
}

function stripQuotes(s: string): string {
  const m = /^(['"])([\s\S]*)\1$/.exec(s);
  return m ? m[2]! : s;
}

/** Split an inline or comma-separated frontmatter list into items. */
export function parseList(value: string | undefined): string[] {
  if (!value) return [];
  const inner = /^\[([\s\S]*)\]$/.exec(value.trim());
  const body = inner ? inner[1]! : value;
  return body
    .split(",")
    .map((s) => stripQuotes(s.trim()))
    .filter(Boolean);
}

/**
 * Word count that does not silently score CJK text as near-empty.
 *
 * Whitespace splitting reports a 400-character Chinese description as
 * one word, which would fail every length threshold for reasons that
 * have nothing to do with quality.
 */
export function countWords(text: string): number {
  const cjk = (text.match(/[぀-ヿ㐀-䶿一-鿿豈-﫿]/g) ?? []).length;
  const latin = text
    .replace(/[぀-ヿ㐀-䶿一-鿿豈-﫿]/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean).length;
  return latin + cjk;
}

/** Strict-ish semver, accepting a leading `v`. */
export const SEMVER_RE = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** Lowercase kebab slug, the shape every client convention agrees on. */
export const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
