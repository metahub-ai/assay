/**
 * Project configuration and waivers.
 *
 * Waivers are the single most important adoption feature in this file,
 * and the reasoning is worth stating because it cuts against instinct
 * for a security tool.
 *
 * Every check will eventually be wrong about somebody. A native module
 * genuinely needs a build script; a vendored fixture genuinely looks
 * like a credential file. Without a way to say "yes, deliberately,
 * here's why", the publisher's only options are to live with a
 * permanent red mark or stop running the tool. They pick the second
 * one, and then the tool protects nobody.
 *
 * So waivers exist — but they are designed to be *expensive to abuse*
 * rather than merely available:
 *
 *   - a **reason is mandatory**, and it is published in the report;
 *   - a waived check is reported as `neutral` with the reason attached,
 *     never silently dropped;
 *   - waivers can **expire**, and an expired one stops applying;
 *   - the report records that a waiver was applied, so a consumer
 *     reading it can weigh the excuse for themselves.
 *
 * That is the OpenSSF Best Practices Badge insight: a self-assertion
 * with a mandatory public justification behaves very differently from
 * an unchecked opt-out.
 */
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

export interface Waiver {
  /** Check id being waived. */
  check: string;
  /** Why. Mandatory, and published in the report. */
  reason: string;
  /** ISO date after which the waiver stops applying. */
  expires?: string;
  /** Optional path scoping, for checks that report per-file findings. */
  paths?: string[];
}

export interface AssayConfig {
  /** Thresholds passed through to checks as `ctx.config`. */
  settings?: Record<string, string | number | boolean>;
  /** Checks to skip entirely. Prefer a waiver — a skip says nothing. */
  disable?: string[];
  waivers?: Waiver[];
  /** Suite identifier recorded in the report. */
  suite?: string;
  /** Fail the run when the overall score is below this. */
  minScore?: number;
}

export const CONFIG_FILENAMES = ["assay.config.json", ".assayrc.json", ".assayrc"] as const;

export interface LoadedConfig {
  config: AssayConfig;
  /** Where it was found. null when defaults are in use. */
  path: string | null;
}

/**
 * Find and read config, walking up from `start` toward the filesystem
 * root.
 *
 * Walking up matters for monorepos: `assay run packages/my-skill`
 * should honour a policy set at the repository root rather than
 * requiring a config file beside every artifact.
 */
export async function loadConfig(start: string): Promise<LoadedConfig> {
  let dir = resolve(start);
  for (;;) {
    for (const name of CONFIG_FILENAMES) {
      const candidate = join(dir, name);
      let raw: string;
      try {
        raw = await readFile(candidate, "utf8");
      } catch {
        continue; // Not here — keep looking.
      }
      // Parsing is deliberately OUTSIDE the try above. Wrapping both
      // together made a malformed config indistinguishable from a
      // missing one, so a broken policy file was silently skipped —
      // precisely the "believes it has protection it does not have"
      // failure this function's contract promises to avoid.
      return { config: parseConfig(raw, candidate), path: candidate };
    }
    const parent = dirname(dir);
    if (parent === dir) return { config: {}, path: null };
    dir = parent;
  }
}

/**
 * Parse and validate. A malformed config is an ERROR, not a silent
 * fallback to defaults — quietly ignoring a policy file is how a team
 * ends up believing they have protection they do not have.
 */
export function parseConfig(raw: string, path = "config"): AssayConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`${path} is not valid JSON: ${(err as Error).message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${path} must contain a JSON object.`);
  }
  const o = parsed as Record<string, unknown>;
  const config: AssayConfig = {};

  // Reject keys we do not understand.
  //
  // This module's own preamble says quietly ignoring a policy file is
  // how a team ends up believing it has protection it does not have —
  // and unknown keys were being ignored quietly. `{"minscore": 80}`,
  // `{"waiver": [...]}` and `{"minScore": "80"}` all parsed cleanly and
  // did nothing. A misspelled gate is an absent gate.
  const KNOWN = ["$schema", "settings", "disable", "waivers", "suite", "minScore"];
  const unknown = Object.keys(o).filter((k) => !KNOWN.includes(k));
  if (unknown.length > 0) {
    const near = (k: string) => KNOWN.find((v) => v.toLowerCase() === k.toLowerCase());
    throw new Error(
      `${path}: unknown key${unknown.length === 1 ? "" : "s"} ${unknown.map((k) => `"${k}"`).join(", ")}. ` +
        unknown
          .map((k) => {
            const guess = near(k);
            return guess ? `Did you mean "${guess}"? ` : "";
          })
          .join("") +
        `Known keys: ${KNOWN.filter((k) => k !== "$schema").join(", ")}.`,
    );
  }

  if (o["settings"] !== undefined) {
    if (typeof o["settings"] !== "object" || o["settings"] === null) {
      throw new Error(`${path}: "settings" must be an object.`);
    }
    config.settings = o["settings"] as Record<string, string | number | boolean>;
  }
  if (o["disable"] !== undefined) {
    if (!Array.isArray(o["disable"])) throw new Error(`${path}: "disable" must be an array.`);
    config.disable = o["disable"].filter((x): x is string => typeof x === "string");
  }
  if (o["suite"] !== undefined) {
    if (typeof o["suite"] !== "string") throw new Error(`${path}: "suite" must be a string.`);
    config.suite = o["suite"];
  }
  if (o["minScore"] !== undefined) {
    // `"80"` used to be discarded in silence, leaving the gate off.
    if (typeof o["minScore"] !== "number" || Number.isNaN(o["minScore"])) {
      throw new Error(`${path}: "minScore" must be a number, not ${typeof o["minScore"]}.`);
    }
    config.minScore = o["minScore"];
  }
  if (o["waivers"] !== undefined) {
    if (!Array.isArray(o["waivers"])) throw new Error(`${path}: "waivers" must be an array.`);
    config.waivers = o["waivers"].map((w, i) => {
      if (!w || typeof w !== "object") throw new Error(`${path}: waiver ${i} is not an object.`);
      const rec = w as Record<string, unknown>;
      if (typeof rec["check"] !== "string" || rec["check"] === "") {
        throw new Error(`${path}: waiver ${i} is missing "check".`);
      }
      // The mandatory reason is the whole design. A waiver nobody has
      // to justify is an off switch.
      if (typeof rec["reason"] !== "string" || rec["reason"].trim().length < 10) {
        throw new Error(
          `${path}: waiver for "${rec["check"]}" needs a "reason" of at least 10 characters. ` +
            `It is published in the report, so write it for whoever reads the result.`,
        );
      }
      return {
        check: rec["check"],
        reason: rec["reason"],
        ...(typeof rec["expires"] === "string" ? { expires: rec["expires"] } : {}),
        ...(Array.isArray(rec["paths"])
          ? { paths: rec["paths"].filter((p): p is string => typeof p === "string") }
          : {}),
      };
    });
  }
  return config;
}

export interface ActiveWaiver {
  waiver: Waiver;
  expired: boolean;
}

/** Resolve the waiver applying to a check, if any. */
export function waiverFor(
  config: AssayConfig,
  checkId: string,
  now: number = Date.now(),
): ActiveWaiver | null {
  const waiver = config.waivers?.find((w) => w.check === checkId);
  if (!waiver) return null;
  const expired = waiver.expires !== undefined && Date.parse(waiver.expires) < now;
  return { waiver, expired };
}
