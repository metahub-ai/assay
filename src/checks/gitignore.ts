/**
 * Minimal `.gitignore` matching, used to soften — never to suppress —
 * findings about files that will not be published.
 *
 * The motivating bug: `assay run .` in a working tree failed blocking on
 * a local `.env`, reported it as "committed", and told the author to
 * "add the path to .gitignore" — which they already had. That is the
 * first thing a real developer hits, and the tool's own advice did not
 * fix it.
 *
 * **This deliberately does not implement gitignore fully.** Negations,
 * `**` spans and per-directory precedence all have corner cases, and a
 * wrong match here would HIDE a real credential leak, which is much the
 * worse direction to be wrong in. So the rule is:
 *
 *   - matching is conservative and syntactically simple;
 *   - a match NEVER removes a finding, it only downgrades its severity
 *     and corrects the wording;
 *   - anything unparseable is treated as "not ignored".
 *
 * Shelling out to `git check-ignore` would be more correct, but a check
 * runs under a capability model that grants no subprocess, and reaching
 * around that for convenience would undercut the guarantee.
 */
import type { SourceReader } from "../ports.js";

/** One usable pattern from a `.gitignore`, with its directory scope. */
interface Rule {
  /** Directory the rule was declared in, "" for the root. */
  base: string;
  /** Pattern with any leading `/` and trailing `/` stripped. */
  pattern: string;
  /** Anchored to `base` rather than matching at any depth. */
  anchored: boolean;
  /** Only matches directories (`build/`). */
  dirOnly: boolean;
}

const IGNORE_FILES = [".gitignore", ".npmignore"];

/** Read every ignore file in the tree and parse it into rules. */
export async function loadIgnoreRules(source: SourceReader): Promise<Rule[]> {
  const tree = await source.listTree();
  const files = tree.filter(
    (e) => e.type === "file" && IGNORE_FILES.includes(e.path.split("/").pop() ?? ""),
  );

  const rules: Rule[] = [];
  for (const f of files) {
    const body = await source.readFile(f.path);
    if (!body) continue;
    const base = f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : "";
    for (const raw of body.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      // A negation means the author is carving an exception, and getting
      // that wrong could hide a real finding. Bail out of the whole file
      // rather than apply half its logic.
      if (line.startsWith("!")) return [];
      const dirOnly = line.endsWith("/");
      const anchored = line.startsWith("/");
      const pattern = line.replace(/^\/+/, "").replace(/\/+$/, "");
      if (!pattern) continue;
      rules.push({ base, pattern, anchored, dirOnly });
    }
  }
  return rules;
}

/** Translate a gitignore glob into a regex over one path segment span. */
function toRegExp(pattern: string): RegExp | null {
  // Refuse anything with `**`, whose semantics depend on position.
  if (pattern.includes("**")) return null;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]");
  try {
    return new RegExp(`^${escaped}$`);
  } catch {
    return null;
  }
}

/**
 * Would git ignore this path?
 *
 * Conservative: `false` whenever the answer is not clear.
 */
export function isIgnored(path: string, rules: readonly Rule[]): boolean {
  for (const rule of rules) {
    // A rule only governs its own directory and below.
    if (rule.base && !path.startsWith(`${rule.base}/`)) continue;
    const rel = rule.base ? path.slice(rule.base.length + 1) : path;
    const re = toRegExp(rule.pattern);
    if (!re) continue;

    if (rule.anchored) {
      // Anchored rules match from the base only. A dir-only rule matches
      // the directory and everything under it.
      const first = rel.split("/")[0]!;
      if (re.test(rel)) return true;
      if (rule.dirOnly && re.test(first)) return true;
      continue;
    }

    // Unanchored rules match any segment at any depth. For a dir-only
    // rule, matching a non-final segment means the file is inside it.
    const segments = rel.split("/");
    for (let i = 0; i < segments.length; i++) {
      const isLast = i === segments.length - 1;
      if (!re.test(segments[i]!)) continue;
      if (rule.dirOnly ? !isLast : true) return true;
    }
  }
  return false;
}

/** Convenience: the subset of `paths` git would ignore. */
export async function ignoredPaths(
  source: SourceReader,
  paths: readonly string[],
): Promise<Set<string>> {
  const rules = await loadIgnoreRules(source);
  if (rules.length === 0) return new Set();
  return new Set(paths.filter((p) => isIgnored(p, rules)));
}
