/**
 * Named suites — the ESLint `extends` mechanic for Assay.
 *
 * A suite bundles two things: WHICH checks compose the registry, and a
 * built-in POLICY overlay (thresholds, gates) merged UNDER the user's
 * own config. `--suite assay:strict` is therefore a real change in what
 * runs and what gates the exit code — not just a label in the report.
 *
 * Suites are values assembled from the category modules, mirroring
 * `checks/index.ts`: a consumer can read exactly what a suite contains
 * and reproduce it, and the report's suite digest is meaningful because
 * the composition is explicit rather than "whatever was imported".
 */
import type { CheckDefinition } from "./check.js";
import type { AssayConfig } from "./config.js";
import {
  DEFAULT_CHECKS,
  CORE_CHECKS,
  INTEGRITY_CHECKS,
  DOCUMENTATION_CHECKS,
  SUPPLY_CHAIN_CHECKS,
  CODE_CHECKS,
  MCP_CHECKS,
  MCP_SURFACE_CHECKS,
  MCP_AUTH_CHECKS,
} from "./checks/index.js";
import { CONTENT_CHECKS } from "./checks/content.js";

export interface SuiteDefinition {
  /** Stable id. Built-ins are namespaced `assay:*`. */
  id: string;
  /** Short human title. */
  title: string;
  /** One line: who it is for. */
  description: string;
  /**
   * The checks composing this suite. The runner still filters by each
   * check's `appliesTo`, so a suite that lists every kind's checks is
   * fine — an MCP run simply never sees the skill checks.
   */
  checks: readonly CheckDefinition[];
  /**
   * Config overlay merged BENEATH the user's own config — the user's
   * `assay.config.json` and CLI flags always win. Only the fields a
   * preset deliberately sets appear here; everything else is inherited.
   */
  policy?: Pick<AssayConfig, "minScore">;
}

/** The suite used when neither the CLI nor the config names one. */
export const DEFAULT_SUITE_ID = "assay:recommended";

export const BUILTIN_SUITES: Readonly<Record<string, SuiteDefinition>> = {
  "assay:recommended": {
    id: "assay:recommended",
    title: "Recommended",
    description: "The balanced default — every core check, no score gate.",
    checks: DEFAULT_CHECKS,
  },
  "assay:strict": {
    id: "assay:strict",
    title: "Strict",
    description: "Recommended checks, plus a passing bar: the run fails below 85 / 100.",
    checks: DEFAULT_CHECKS,
    policy: { minScore: 85 },
  },
  "assay:mcp-server": {
    id: "assay:mcp-server",
    title: "MCP server",
    description:
      "Curated for MCP servers: integrity, supply-chain, secrets, code, and the MCP-specific checks.",
    // Deliberately omits the skill/agent/plugin kind checks. They would
    // self-exclude on an MCP subject anyway, but naming the set makes
    // `assay list --suite assay:mcp-server` and the suite digest reflect
    // exactly what an MCP server is graded on.
    checks: [
      ...CORE_CHECKS,
      ...INTEGRITY_CHECKS,
      ...DOCUMENTATION_CHECKS,
      ...SUPPLY_CHAIN_CHECKS,
      ...CONTENT_CHECKS,
      ...CODE_CHECKS,
      ...MCP_CHECKS,
      ...MCP_SURFACE_CHECKS,
      ...MCP_AUTH_CHECKS,
    ],
  },
};

export function isBuiltinSuite(id: string): boolean {
  return Object.prototype.hasOwnProperty.call(BUILTIN_SUITES, id);
}

/**
 * Resolve a suite id to its definition.
 *
 * An unknown id is NOT an error: a free-form label (`acme-internal`)
 * stays a label, runs the default check set, and carries no overlay —
 * preserving the pre-suite behavior where `--suite` was purely cosmetic.
 * Only the reserved `assay:*` namespace is validated, so a typo like
 * `assay:strickt` fails loudly instead of silently running recommended.
 */
export function resolveSuite(id: string | undefined): SuiteDefinition {
  if (!id) return BUILTIN_SUITES[DEFAULT_SUITE_ID]!;
  const builtin = BUILTIN_SUITES[id];
  if (builtin) return builtin;
  if (id.startsWith("assay:")) {
    const known = Object.keys(BUILTIN_SUITES).join(", ");
    throw new Error(`unknown built-in suite "${id}". Reserved suites are: ${known}.`);
  }
  return { id, title: id, description: "Custom suite label.", checks: DEFAULT_CHECKS };
}
