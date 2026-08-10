/**
 * Declarative check + probe authoring — the community-contribution path.
 *
 * A check inside the framework is TypeScript with a `run(ctx)`. That is
 * the right surface for the core suite and the wrong one for the world:
 * when the next SKILL.md-poisoning technique or tool-description trick
 * lands, the person who spots it should be able to ship a rule the same
 * day, as data, without learning the engine's internals or waiting on a
 * release. This module is that data path.
 *
 * A plugin is a JSON file (JSON, not YAML, to keep the framework
 * dependency-free — no parser CVE surface on a security tool) declaring:
 *
 *   - **pattern checks**: "a regex over files matching a glob is a
 *     finding" — the Semgrep shape, which covers a large fraction of
 *     real static rules. Compiled here into ordinary CheckDefinitions,
 *     so a plugin check is indistinguishable from a core one downstream
 *     (same scoring, same SARIF, same digest).
 *
 *   - **probes**: an adversarial prompt (+ optional expectation) added to
 *     the behavioral corpus for one kind. Judged by the same inverted
 *     rubric as the built-in probes — refusing is the pass.
 *
 * Everything here is pure over parsed JSON: the CLI reads the files and
 * hands their contents in. Validation is strict and happens at load
 * time — a malformed plugin fails loudly rather than silently scoring
 * nothing, the same contract `defineCheck` holds for core checks.
 */
import { defineCheck, type CheckDefinition } from "./check.js";
import type { CheckResult, Evidence, ScoreAxis } from "./types.js";
import type { EvalTestCase } from "./behavioral/types.js";

/** A probe carried by a plugin, tagged with the kind it targets. */
export interface ExternalProbe {
  kind: string;
  probe: EvalTestCase;
}

export interface LoadedPlugins {
  checks: CheckDefinition[];
  probes: ExternalProbe[];
  /** Non-fatal remarks (e.g. a plugin that declared nothing). */
  notes: string[];
}

/** A plugin file's raw contents + where it came from, for error text. */
export interface PluginFile {
  source: string;
  json: string;
}

const DECLARATIVE_AXES: ScoreAxis[] = ["integrity", "safety", "care"];
const CORE_KINDS = ["skill", "mcp", "agent", "plugin"];
const REGEX_FLAGS = /^[gimsuy]*$/;

function fail(source: string, msg: string): never {
  throw new Error(`plugin ${source}: ${msg}`);
}

/** A namespaced id keeps a plugin from shadowing a core check/probe. */
function requireNamespaced(source: string, kind: string, id: unknown): string {
  if (typeof id !== "string" || !id.includes("/")) {
    fail(source, `${kind} id ${JSON.stringify(id)} must be namespaced, e.g. "acme/no-todo".`);
  }
  return id as string;
}

function compileRegex(source: string, field: string, pat: unknown, flags?: unknown): RegExp {
  if (typeof pat !== "string" || pat === "") fail(source, `${field} must be a non-empty regex.`);
  if (flags !== undefined && (typeof flags !== "string" || !REGEX_FLAGS.test(flags))) {
    fail(source, `${field} flags ${JSON.stringify(flags)} are not valid regex flags.`);
  }
  try {
    return new RegExp(pat as string, (flags as string) ?? "");
  } catch (err) {
    fail(source, `${field} is not a valid regex: ${(err as Error).message}`);
  }
}

/**
 * Compile one pattern-check spec into a CheckDefinition.
 *
 * The compiled check lists the tree, keeps files whose path matches
 * `files`, and reports every line matching `pattern`. A hit is a `fail`
 * when the spec is blocking, else a `warn`; no hits is a `pass`.
 */
function compilePatternCheck(source: string, raw: unknown): CheckDefinition {
  if (!raw || typeof raw !== "object") fail(source, "each check must be an object.");
  const s = raw as Record<string, unknown>;
  const id = requireNamespaced(source, "check", s["id"]);
  if (typeof s["title"] !== "string" || s["title"] === "")
    fail(source, `check ${id} needs a title.`);
  if (typeof s["message"] !== "string" || s["message"] === "")
    fail(source, `check ${id} needs a message (shown when it matches).`);
  const axis = s["axis"];
  if (typeof axis !== "string" || !DECLARATIVE_AXES.includes(axis as ScoreAxis)) {
    fail(
      source,
      `check ${id} axis must be one of ${DECLARATIVE_AXES.join(", ")} (behavior is not declarative).`,
    );
  }
  const fileRe = compileRegex(source, `check ${id} "files"`, s["files"]);
  // Validate the content pattern once here; the run compiles a
  // non-global copy per line so `lastIndex` never leaks between lines.
  compileRegex(source, `check ${id} "pattern"`, s["pattern"], s["flags"]);
  const lineFlags = ((s["flags"] as string) ?? "").replace(/g/g, "");
  const linePattern = s["pattern"] as string;

  const appliesToRaw = s["appliesTo"];
  const appliesTo =
    appliesToRaw === undefined
      ? undefined
      : Array.isArray(appliesToRaw) && appliesToRaw.every((k) => typeof k === "string")
        ? (appliesToRaw as string[])
        : fail(source, `check ${id} "appliesTo" must be an array of kinds.`);

  const weight = s["weight"];
  if (weight !== undefined && (typeof weight !== "number" || weight < 0)) {
    fail(source, `check ${id} "weight" must be a non-negative number.`);
  }

  return defineCheck({
    id,
    version: typeof s["version"] === "string" ? (s["version"] as string) : "1.0.0",
    title: s["title"] as string,
    category: typeof s["category"] === "string" ? (s["category"] as string) : "plugin",
    axis: axis as ScoreAxis,
    determinism: "deterministic",
    weight: (weight as number | undefined) ?? 1,
    ...(s["blocking"] === true ? { blocking: true } : {}),
    ...(appliesTo ? { appliesTo: { kinds: appliesTo } } : {}),
    ...(typeof s["spec"] === "string" ? { spec: s["spec"] as string } : {}),
    ...(typeof s["rationale"] === "string" ? { rationale: s["rationale"] as string } : {}),
    async run(ctx): Promise<CheckResult> {
      const tree = await ctx.source.listTree();
      const hits: { path: string; line: number }[] = [];
      for (const e of tree) {
        if (e.type !== "file" || !fileRe.test(e.path)) continue;
        const body = await ctx.source.readFile(e.path);
        if (!body) continue;
        const lines = body.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          if (new RegExp(linePattern, lineFlags).test(lines[i]!)) {
            hits.push({ path: e.path, line: i + 1 });
            if (hits.length >= 100) break;
          }
        }
        if (hits.length >= 100) break;
      }
      if (hits.length === 0) {
        return { status: "pass", summary: `No matches for ${id}.` };
      }
      const evidence: Evidence[] = hits
        .slice(0, 10)
        .map((h) => ({ type: "file", path: h.path, line: h.line }));
      return {
        status: s["blocking"] === true ? "fail" : "warn",
        summary: s["message"] as string,
        detail: hits
          .slice(0, 10)
          .map((h) => `- \`${h.path}:${h.line}\``)
          .join("\n"),
        ...(typeof s["remediation"] === "string"
          ? { remediation: s["remediation"] as string }
          : {}),
        evidence,
      };
    },
  });
}

function compileProbe(source: string, raw: unknown): ExternalProbe {
  if (!raw || typeof raw !== "object") fail(source, "each probe must be an object.");
  const p = raw as Record<string, unknown>;
  const id = requireNamespaced(source, "probe", p["id"]);
  const kind = p["kind"];
  if (typeof kind !== "string" || !CORE_KINDS.includes(kind)) {
    fail(source, `probe ${id} "kind" must be one of ${CORE_KINDS.join(", ")}.`);
  }
  if (typeof p["prompt"] !== "string" || p["prompt"] === "") {
    fail(source, `probe ${id} needs a non-empty "prompt".`);
  }
  if (p["expect"] !== undefined && typeof p["expect"] !== "string") {
    fail(source, `probe ${id} "expect" must be a string.`);
  }
  return {
    kind: kind as string,
    probe: {
      id,
      prompt: p["prompt"] as string,
      ...(typeof p["expect"] === "string" ? { expect: p["expect"] as string } : {}),
      adversarial: true,
    },
  };
}

/**
 * Parse, validate, and compile a set of plugin files. Throws on the
 * first malformed plugin — a rule that cannot load is never silently
 * skipped, or a consumer would believe they have coverage they do not.
 */
export function loadPlugins(files: PluginFile[]): LoadedPlugins {
  const checks: CheckDefinition[] = [];
  const probes: ExternalProbe[] = [];
  const notes: string[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    let data: unknown;
    try {
      data = JSON.parse(file.json);
    } catch (err) {
      fail(file.source, `not valid JSON: ${(err as Error).message}`);
    }
    if (!data || typeof data !== "object") fail(file.source, "must be a JSON object.");
    const obj = data as Record<string, unknown>;

    const rawChecks = obj["checks"];
    if (rawChecks !== undefined) {
      if (!Array.isArray(rawChecks)) fail(file.source, `"checks" must be an array.`);
      for (const c of rawChecks) {
        const compiled = compilePatternCheck(file.source, c);
        if (seen.has(compiled.id)) fail(file.source, `duplicate id "${compiled.id}".`);
        seen.add(compiled.id);
        checks.push(compiled);
      }
    }

    const rawProbes = obj["probes"];
    if (rawProbes !== undefined) {
      if (!Array.isArray(rawProbes)) fail(file.source, `"probes" must be an array.`);
      for (const p of rawProbes) {
        const compiled = compileProbe(file.source, p);
        if (seen.has(compiled.probe.id)) fail(file.source, `duplicate id "${compiled.probe.id}".`);
        seen.add(compiled.probe.id);
        probes.push(compiled);
      }
    }

    if (rawChecks === undefined && rawProbes === undefined) {
      notes.push(`plugin ${file.source} declared neither checks nor probes.`);
    }
  }

  return { checks, probes, notes };
}
