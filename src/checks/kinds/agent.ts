/**
 * Agent checks.
 *
 * Two genuinely different shapes ship under the same word, and
 * conflating them produces nonsense verdicts:
 *
 *  - **Code-based** — an `agent.json` plus an executable entry point.
 *    It has dependencies, a runtime, and an install step.
 *  - **Prompt-based** — a Claude-Code-style `.claude/agents/<name>.md`
 *    where the markdown body IS the agent. There is no entry file, no
 *    package to install, and demanding one would fail every artifact of
 *    this shape for a defect it cannot have.
 *
 * Every check here establishes which shape it is looking at before
 * judging.
 */
import { defineCheck } from "../../check.js";
import type { CheckResult } from "../../types.js";
import { findAgentMarkdown } from "../docs-resolution.js";
import {
  AGENT_MANIFESTS,
  countWords,
  parseFrontmatter,
  parseList,
  readManifest,
} from "../manifest.js";
import { checkSpecUrl } from "../../version.js";

/** Tools that grant real blast radius — a shell, a writer, or the network.
 *  Declared explicitly is fine; an installer just deserves to SEE them. */
const ELEVATED_TOOLS = new Set([
  "bash",
  "write",
  "edit",
  "multiedit",
  "execute",
  "webfetch",
  "websearch",
  "notebookedit",
]);

function elevatedIn(tools: string[]): string[] {
  return tools.filter((t) => ELEVATED_TOOLS.has(t.toLowerCase().trim()));
}

// Detection lives in one place (../docs-resolution) so `manifest-present`
// and `agent-shape-declared` cannot drift apart again — they disagreed
// once, and every real prompt-based agent failed a blocking check.

export const agentShapeDeclared = defineCheck({
  id: "agent-shape-declared",
  version: "1.0.0",
  title: "Agent definition present",
  category: "kind-specific",
  axis: "integrity",
  determinism: "deterministic",
  weight: 5,
  blocking: true,
  appliesTo: { kinds: ["agent"] },
  spec: checkSpecUrl("agent-shape-declared"),
  inspects:
    "Agent markdown with frontmatter, or a manifest with an entry point; either shape counts.",
  rationale:
    "An agent is either a prompt with frontmatter or a program with an entry point. When neither shape is present there is nothing to run and nothing to review, and whatever the repository contains, it is not an installable agent.",
  async run(ctx): Promise<CheckResult> {
    const manifest = await readManifest(ctx.source, AGENT_MANIFESTS);
    if (manifest?.data) {
      return {
        status: "pass",
        summary: `Code-based agent declared in ${manifest.path}.`,
        evidence: [{ type: "file", path: manifest.path }],
      };
    }
    if (manifest && !manifest.data) {
      return {
        status: "fail",
        summary: `${manifest.path} does not parse.`,
        remediation: `Fix the JSON syntax in ${manifest.path}.`,
        evidence: [{ type: "file", path: manifest.path }],
      };
    }
    const prompt = await findAgentMarkdown(ctx.source);
    if (prompt) {
      return {
        status: "pass",
        summary: `Prompt-based agent defined in ${prompt}.`,
        evidence: [{ type: "file", path: prompt }],
      };
    }
    return {
      status: "fail",
      summary: "No agent definition found.",
      detail: `Looked for ${AGENT_MANIFESTS.join(", ")}, and for markdown with frontmatter under agents/ or at the root.`,
      remediation: "Add an agent.json, or a markdown agent definition under `.claude/agents/`.",
    };
  },
});

export const agentInstructions = defineCheck({
  id: "agent-instructions",
  version: "1.0.0",
  title: "Agent declares substantive instructions",
  category: "kind-specific",
  axis: "care",
  determinism: "deterministic",
  weight: 3,
  appliesTo: { kinds: ["agent"] },
  spec: checkSpecUrl("agent-instructions"),
  rationale:
    "The instructions are the agent. A short or empty prompt means the behavior comes entirely from the base model, and whatever specialisation the agent claims is not actually in the artifact a consumer installed.",
  async run(ctx): Promise<CheckResult> {
    const prompt = await findAgentMarkdown(ctx.source);
    if (prompt) {
      const raw = (await ctx.source.readFile(prompt)) ?? "";
      const { body } = parseFrontmatter(raw);
      const words = countWords(body);
      const min = Number(ctx.config["agentPromptMinWords"] ?? 40);
      if (words < min) {
        return {
          status: "warn",
          summary: `Agent prompt is ${words} words — thinner than the ${min}-word floor.`,
          score: Math.max(0, Math.min(1, words / min)) * 0.8,
          detail: "For a prompt-based agent the body IS the agent; a stub cannot behave reliably.",
          remediation:
            "Describe the agent's role, its boundaries, and what good output looks like.",
          evidence: [{ type: "file", path: prompt }],
        };
      }
      return { status: "pass", summary: `Agent prompt is ${words} words.` };
    }

    const manifest = await readManifest(ctx.source, AGENT_MANIFESTS);
    const instructions = manifest?.data?.["instructions"];
    if (typeof instructions === "string" && countWords(instructions) >= 20) {
      return { status: "pass", summary: "Agent declares instructions." };
    }
    if (typeof instructions === "string") {
      return {
        status: "warn",
        summary: `Instructions are only ${countWords(instructions)} words.`,
        remediation: "Expand the agent's system instructions.",
        evidence: manifest ? [{ type: "file", path: manifest.path }] : [],
      };
    }
    return {
      status: "warn",
      summary: "No instructions declared.",
      detail: "An agent without a system prompt inherits whatever the client supplies.",
      remediation: 'Add an "instructions" field to agent.json.',
    };
  },
});

export const agentToolScope = defineCheck({
  id: "agent-tool-scope",
  version: "1.0.0",
  title: "Agent tool scope declared",
  category: "kind-specific",
  axis: "safety",
  determinism: "deterministic",
  weight: 2,
  appliesTo: { kinds: ["agent"] },
  spec: checkSpecUrl("agent-tool-scope"),
  rationale:
    "Declared tools are the agent's blast radius. Without a declared scope an installer cannot tell whether this agent reads files, runs shell commands, or reaches the network — and that is the decision they are being asked to make.",
  async run(ctx): Promise<CheckResult> {
    const prompt = await findAgentMarkdown(ctx.source);
    if (prompt) {
      const raw = (await ctx.source.readFile(prompt)) ?? "";
      const rawTools = parseFrontmatter(raw).fields["tools"];
      if (rawTools === undefined) {
        return {
          status: "warn",
          summary: "No tool scope declared.",
          detail: "The agent inherits whatever the client grants — the broadest possible scope.",
          remediation: "Declare `tools:` in the frontmatter with the minimum set needed.",
          evidence: [{ type: "file", path: prompt }],
        };
      }
      return scopeResult(parseList(rawTools), prompt);
    }
    const manifest = await readManifest(ctx.source, AGENT_MANIFESTS);
    const tools = manifest?.data?.["tools"];
    if (Array.isArray(tools) && tools.length > 0) {
      return scopeResult(
        tools.filter((t): t is string => typeof t === "string"),
        manifest!.path,
      );
    }
    return {
      status: "warn",
      summary: "No tool scope declared.",
      detail: "The agent inherits whatever the client grants — the broadest possible scope.",
      remediation: 'Add a "tools" array to agent.json.',
      evidence: manifest ? [{ type: "file", path: manifest.path }] : [],
    };
  },
});

/**
 * Grade a declared tool scope. An explicit scope is good; elevated tools
 * in it are surfaced, never penalized — an agent that legitimately needs
 * a shell should not score below one that needs none, but a consumer is
 * entitled to see the blast radius before installing.
 */
function scopeResult(tools: string[], path: string): CheckResult {
  if (tools.length === 0) {
    return {
      status: "pass",
      summary: "Declares an empty tool scope — needs no tools at all.",
      detail: "The tightest scope an agent can declare, and stated explicitly.",
      evidence: [{ type: "file", path }],
    };
  }
  const elevated = elevatedIn(tools);
  if (elevated.length > 0) {
    return {
      status: "pass",
      summary: `Declares ${tools.length} tool${tools.length === 1 ? "" : "s"}, including elevated: ${elevated.join(", ")}.`,
      detail:
        "Declared explicitly, which is what we want — surfaced here so a consumer can see the blast radius (a shell, a file writer, or the network) before installing.",
      evidence: [{ type: "file", path }],
    };
  }
  return { status: "pass", summary: `Declares ${tools.length} tool scope entries.` };
}

export const AGENT_CHECKS = [agentShapeDeclared, agentInstructions, agentToolScope];
