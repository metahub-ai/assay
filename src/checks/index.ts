/**
 * The default suite.
 *
 * Assembled from category modules rather than declared as one flat
 * list, so a consumer can compose their own suite from the parts they
 * trust — `CheckRegistry.from([...INTEGRITY_CHECKS, ...myChecks])` is
 * the intended shape. A registry that can only be used whole is a
 * registry nobody can adapt.
 */
import { CORE_CHECKS } from "./core.js";
import { INTEGRITY_CHECKS } from "./integrity.js";
import { DOCUMENTATION_CHECKS } from "./documentation.js";
import { SUPPLY_CHAIN_CHECKS } from "./supply-chain.js";
import { CONTENT_CHECKS } from "./content.js";
import { CODE_CHECKS } from "./code.js";
import { DESTRUCTIVE_SCOPE_CHECKS } from "./destructive-scope.js";
import { SKILL_CHECKS } from "./kinds/skill.js";
import { SKILL_SAFETY_CHECKS } from "./kinds/skill-safety.js";
import { MCP_CHECKS } from "./kinds/mcp.js";
import { MCP_SURFACE_CHECKS } from "./kinds/mcp-surface.js";
import { MCP_AUTH_CHECKS } from "./kinds/mcp-auth.js";
import { AGENT_CHECKS } from "./kinds/agent.js";
import { AGENT_SAFETY_CHECKS } from "./kinds/agent-safety.js";
import { PLUGIN_CHECKS } from "./kinds/plugin.js";
import type { CheckDefinition } from "../check.js";

export { CORE_CHECKS } from "./core.js";
export { INTEGRITY_CHECKS } from "./integrity.js";
export { DOCUMENTATION_CHECKS } from "./documentation.js";
export { SUPPLY_CHAIN_CHECKS } from "./supply-chain.js";
export { CODE_CHECKS } from "./code.js";
export { DESTRUCTIVE_SCOPE_CHECKS } from "./destructive-scope.js";
export { SKILL_CHECKS } from "./kinds/skill.js";
export { SKILL_SAFETY_CHECKS } from "./kinds/skill-safety.js";
export { MCP_CHECKS } from "./kinds/mcp.js";
export { MCP_SURFACE_CHECKS } from "./kinds/mcp-surface.js";
export { MCP_AUTH_CHECKS } from "./kinds/mcp-auth.js";
export { AGENT_CHECKS } from "./kinds/agent.js";
export { AGENT_SAFETY_CHECKS } from "./kinds/agent-safety.js";
export { PLUGIN_CHECKS } from "./kinds/plugin.js";

/**
 * Every deterministic check, across all kinds. The runner filters by
 * `appliesTo`, so handing it the whole set is correct — a skill run
 * simply never sees the MCP checks.
 */
export const DEFAULT_CHECKS: readonly CheckDefinition[] = [
  ...CORE_CHECKS,
  ...INTEGRITY_CHECKS,
  ...DOCUMENTATION_CHECKS,
  ...SUPPLY_CHAIN_CHECKS,
  ...CONTENT_CHECKS,
  ...CODE_CHECKS,
  ...DESTRUCTIVE_SCOPE_CHECKS,
  ...SKILL_CHECKS,
  ...SKILL_SAFETY_CHECKS,
  ...MCP_CHECKS,
  ...MCP_SURFACE_CHECKS,
  ...MCP_AUTH_CHECKS,
  ...AGENT_CHECKS,
  ...AGENT_SAFETY_CHECKS,
  ...PLUGIN_CHECKS,
];
