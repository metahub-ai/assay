/**
 * Source the behavioral test cases for a run. Two strategies, in order:
 *
 *   1. **Author-provided** — parse cases out of the repo's
 *      `evals/*.json`. Each file is either a bare array of cases or an
 *      object with a `cases`/`tests` array.
 *
 *   2. **Synthesized** — otherwise ask the driver model to synthesize
 *      cases from the artifact's triggers, description, and docs.
 *
 * When neither yields a case (docs too thin to synthesize from), fall
 * back to a single generic smoke case rather than failing the run: a
 * load-and-respond check still confirms the artifact runs and keeps it in
 * behavioral coverage instead of dropping it entirely.
 */
import type { ArtifactKind } from "../types.js";
import type { LlmProvider } from "../ports.js";
import type { EvalTestCase } from "./types.js";
import { getProbeCases, PROBE_CAP_DEFAULT } from "./probes.js";

export const DEFAULT_CASE_COUNT = 5;

/** Generic fallback used when synthesis yields nothing — see loadTestCases. */
const SMOKE_CASE: EvalTestCase = {
  id: "smoke-load",
  prompt:
    "Perform this artifact's most basic advertised action and confirm it responds without error.",
};

interface RawCase {
  id?: unknown;
  prompt?: unknown;
  expect?: unknown;
}

/** Parse cases out of a single `evals/*.json` file's contents. */
export function parseEvalFile(contents: string): EvalTestCase[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch {
    return [];
  }
  const arr: unknown[] = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object"
      ? ((parsed as { cases?: unknown[]; tests?: unknown[] }).cases ??
        (parsed as { tests?: unknown[] }).tests ??
        [])
      : [];
  const out: EvalTestCase[] = [];
  for (const [i, raw] of arr.entries()) {
    if (!raw || typeof raw !== "object") continue;
    const c = raw as RawCase;
    if (typeof c.prompt !== "string" || c.prompt.trim().length === 0) continue;
    out.push({
      id: typeof c.id === "string" && c.id ? c.id : `case-${i + 1}`,
      prompt: c.prompt,
      ...(typeof c.expect === "string" ? { expect: c.expect } : {}),
    });
  }
  return out;
}

export interface LoadTestCasesInput {
  llm: LlmProvider;
  /** Pre-fetched `evals/*.json` contents, keyed by path. */
  providedEvalFiles?: Record<string, string>;
  /** Artifact doc used as synthesis context. */
  doc: string;
  triggers?: string[];
  description?: string;
  /** Target case count for synthesis. */
  count?: number;
  /** Drives which probe corpus is appended. */
  kind?: ArtifactKind;
  /**
   * How many adversarial probes to append. Defaults to all probes for
   * the kind. 0 opts out — useful when an artifact ships its own corpus.
   */
  probeCount?: number;
  /**
   * Extra adversarial probes from community plugins, appended AFTER the
   * built-in corpus and the probe cap — a user who declared a plugin
   * opted in, so its probes always run.
   */
  extraProbes?: EvalTestCase[];
}

/**
 * Pull a JSON array out of a reply that may wrap it in prose or a
 * fenced block.
 *
 * Smaller local models often don't honor "respond with ONLY JSON", so
 * synthesis parsing has to be as forgiving as the judge's — otherwise a
 * chatty model fails the whole run for a formatting preference.
 */
export function extractJsonArray(text: string): string {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced && fenced[1] && fenced[1].includes("[")) return fenced[1].trim();
  const first = text.indexOf("[");
  const last = text.lastIndexOf("]");
  if (first !== -1 && last > first) return text.slice(first, last + 1);
  return text;
}

/**
 * Synthesize cases via the driver model. Returns whatever parses,
 * possibly empty; transport errors propagate so a broken provider
 * surfaces as an honest failure rather than a fabricated case.
 */
async function synthesizeCases(input: LoadTestCasesInput): Promise<EvalTestCase[]> {
  const count = input.count ?? DEFAULT_CASE_COUNT;
  const system = [
    "Synthesize test cases for a behavioral evaluation.",
    `Produce up to ${count} concrete user prompts that exercise this artifact.`,
    "Respond with ONLY a JSON array of {id, prompt, expect} objects.",
  ].join("\n");
  const user = [
    `Description: ${input.description ?? "(none)"}`,
    `Triggers: ${(input.triggers ?? []).join(", ") || "(none)"}`,
    "Documentation:",
    input.doc.slice(0, 3000),
  ].join("\n");
  const res = await input.llm.complete({
    system,
    messages: [{ role: "user", content: user }],
    maxTokens: 1024,
    temperature: 0,
    role: "synthesis",
  });
  return parseEvalFile(extractJsonArray(res.text)).slice(0, count);
}

/**
 * Resolve the cases for a run. Author-provided win; otherwise
 * synthesize. Throws when neither yields a real case.
 */
export async function loadTestCases(input: LoadTestCasesInput): Promise<EvalTestCase[]> {
  const provided = input.providedEvalFiles ?? {};
  const fromFiles: EvalTestCase[] = [];
  for (const path of Object.keys(provided).sort()) {
    if (!/(^|\/)evals\/.+\.json$/i.test(path) && !/(^|\/)evals\.json$/i.test(path)) continue;
    fromFiles.push(...parseEvalFile(provided[path]!));
  }

  let base: EvalTestCase[];
  if (fromFiles.length > 0) {
    base = fromFiles;
  } else {
    const synthesized = await synthesizeCases(input);
    // Docs too thin to synthesize from: fall back to one generic smoke
    // case rather than dropping the artifact from behavioral coverage.
    base = synthesized.length > 0 ? synthesized : [SMOKE_CASE];
  }

  // Probes run AFTER the author/synth cases, so a flaky synthesized
  // case doesn't hide a real safety finding behind it.
  const probeCap = input.probeCount ?? PROBE_CAP_DEFAULT;
  // Plugin probes always run (the user opted in by declaring the plugin),
  // stamped adversarial so they are judged by the inverted rubric and
  // kept out of the `safe` determination — same as built-in probes.
  const extra = (input.extraProbes ?? []).map((p) => ({ ...p, adversarial: true as const }));
  if (input.kind && probeCap > 0) {
    return [...base, ...getProbeCases(input.kind).slice(0, probeCap), ...extra];
  }
  return [...base, ...extra];
}
