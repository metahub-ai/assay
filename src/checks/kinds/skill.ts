/**
 * Skill checks.
 *
 * A skill is prose that a model reads and acts on, which makes its
 * failure modes different from a library's. There is no compiler to
 * catch a skill that is ambiguous, no type error for one whose
 * description does not say when to invoke it. So the checks here are
 * mostly about whether the document can actually do its job as an
 * instruction to a model.
 *
 * This is also the least-governed artifact class in the ecosystem. The
 * official validator for the Agent Skills standard checks frontmatter
 * syntax and naming — and nothing else — against a standard adopted by
 * 40+ clients. Snyk's audit of 3,984 skills found 13.4% carried a
 * critical issue.
 */
import { defineCheck } from "../../check.js";
import type { CheckResult } from "../../types.js";
import { countWords, parseFrontmatter, parseList } from "../manifest.js";
import { checkSpecUrl } from "../../version.js";

const SKILL_DOC = "SKILL.md";

export const skillFrontmatter = defineCheck({
  id: "skill-frontmatter",
  version: "1.0.0",
  title: "SKILL.md declares valid frontmatter",
  category: "kind-specific",
  axis: "integrity",
  determinism: "deterministic",
  weight: 4,
  blocking: true,
  appliesTo: { kinds: ["skill"] },
  spec: checkSpecUrl("skill-frontmatter"),
  inspects:
    "The YAML block at the top of SKILL.md, and whether it declares a usable name and description.",
  rationale:
    "The frontmatter is what makes a directory a skill: the client reads the name and description from it to decide whether to load the skill at all. When it is malformed the skill never runs, and no amount of good prose below it compensates.",
  async run(ctx): Promise<CheckResult> {
    const body = await ctx.source.readFile(SKILL_DOC);
    if (body === null) {
      return {
        status: "fail",
        summary: "No SKILL.md found.",
        remediation: "Add a SKILL.md with `name` and `description` frontmatter.",
      };
    }
    const fm = parseFrontmatter(body);
    if (!fm.present) {
      return {
        status: "fail",
        summary: "SKILL.md has no frontmatter block.",
        detail: "A client reads `name` and `description` from frontmatter to register the skill.",
        remediation: "Add a `---` delimited block at the top declaring name and description.",
        evidence: [{ type: "file", path: SKILL_DOC, line: 1 }],
      };
    }
    const missing = ["name", "description"].filter((k) => !fm.fields[k]);
    if (missing.length > 0) {
      return {
        status: "fail",
        summary: `Frontmatter is missing: ${missing.join(", ")}.`,
        remediation: `Add ${missing.map((m) => `\`${m}\``).join(" and ")} to the frontmatter block.`,
        evidence: [{ type: "file", path: SKILL_DOC, line: 1 }],
      };
    }
    return { status: "pass", summary: "Frontmatter declares name and description." };
  },
});

export const skillBody = defineCheck({
  id: "skill-body",
  version: "1.0.0",
  title: "SKILL.md body is substantive",
  category: "kind-specific",
  axis: "care",
  determinism: "deterministic",
  weight: 3,
  appliesTo: { kinds: ["skill"] },
  spec: checkSpecUrl("skill-body"),
  rationale:
    "The body is the instruction the model follows once the skill has triggered. A stub body means the skill fires and then contributes nothing — worse than not triggering, because it displaces whatever the model would have done unaided.",
  async run(ctx): Promise<CheckResult> {
    const raw = await ctx.source.readFile(SKILL_DOC);
    if (raw === null) return { status: "skip", summary: "No SKILL.md to inspect." };
    const { body } = parseFrontmatter(raw);
    const words = countWords(body);
    const min = Number(ctx.config["skillBodyMinWords"] ?? 50);
    if (words < min) {
      return {
        status: "warn",
        summary: `Skill body is ${words} words — thinner than the ${min}-word floor.`,
        score: Math.max(0, Math.min(1, words / min)) * 0.8,
        detail:
          "The body IS the skill — it is the instruction the model follows. A stub cannot produce reliable behavior.",
        remediation:
          "Describe the workflow, the inputs it expects, and what good output looks like.",
        evidence: [{ type: "file", path: SKILL_DOC }],
      };
    }
    const sections = (body.match(/^##\s+/gm) ?? []).length;
    return {
      status: "pass",
      summary: `Body is ${words} words across ${sections} section${sections === 1 ? "" : "s"}.`,
      evidence: [{ type: "metric", name: "skill_body_words", value: words }],
    };
  },
});

/**
 * Does the description say WHEN to use the skill, not just what it is?
 *
 * This is the single highest-leverage thing about a skill's metadata. A
 * client picks between dozens of skills using descriptions alone; one
 * that reads "Formats text" gives a model nothing to route on, while
 * "Use when the user pastes tabular data and wants a markdown table"
 * does.
 *
 * Deliberately a heuristic over trigger phrasing rather than an LLM
 * judgement, so it stays deterministic and free.
 */
export const skillTriggers = defineCheck({
  id: "skill-triggers",
  version: "1.0.0",
  title: "Description says when to use the skill",
  category: "kind-specific",
  axis: "care",
  determinism: "deterministic",
  weight: 2,
  appliesTo: { kinds: ["skill"] },
  spec: checkSpecUrl("skill-triggers"),
  inspects: "The `description:` field in SKILL.md frontmatter.",
  rationale:
    "A client routes between skills on this text alone. A description that says what the skill IS, without saying WHEN to reach for it, never gets selected — the skill can be perfect and still never run.",
  examples: {
    passing:
      "description: Converts pasted tabular data into a markdown table. Use when the user pastes CSV or spreadsheet rows.",
    failing: "description: A markdown table utility.",
  },
  async run(ctx): Promise<CheckResult> {
    const raw = await ctx.source.readFile(SKILL_DOC);
    if (raw === null) return { status: "skip", summary: "No SKILL.md to inspect." };
    const description = parseFrontmatter(raw).fields["description"];
    if (!description) {
      return { status: "skip", summary: "No description to inspect." };
    }
    const TRIGGER_CUES =
      /\b(when|whenever|if the user|use this|use when|for (?:tasks|cases|requests)|invoke|trigger|applies? to|helpful for|useful (?:when|for))\b/i;
    if (TRIGGER_CUES.test(description)) {
      return { status: "pass", summary: "Description states when the skill applies." };
    }
    return {
      status: "warn",
      summary: "Description says what the skill is, but not when to use it.",
      detail: `Current: "${description}"`,
      remediation:
        'Add the triggering condition — e.g. "Use when the user pastes tabular data and wants a markdown table." A client routes on this text.',
      evidence: [{ type: "file", path: SKILL_DOC, line: 1 }],
    };
  },
});

/**
 * Declared tool scope.
 *
 * `allowed-tools` is a privilege declaration. Its absence means the
 * skill inherits whatever the client grants, which is the broadest
 * possible scope — and a skill that declares `Bash` deserves to say so
 * on its listing.
 */
export const skillAllowedTools = defineCheck({
  id: "skill-allowed-tools",
  version: "1.0.0",
  title: "Tool scope declared",
  category: "kind-specific",
  axis: "safety",
  determinism: "deterministic",
  weight: 2,
  appliesTo: { kinds: ["skill"] },
  spec: checkSpecUrl("skill-allowed-tools"),
  inspects: "The `allowed-tools:` field in SKILL.md frontmatter.",
  rationale:
    "Without a declared scope the skill inherits whatever the client grants — the broadest possible privilege — and nothing on the listing tells a consumer that. An explicitly EMPTY list is the strongest answer available, not a missing one.",
  examples: {
    passing: "allowed-tools: []        or   allowed-tools: [Read, Grep]",
    failing: "(the field is absent)",
  },
  async run(ctx): Promise<CheckResult> {
    const raw = await ctx.source.readFile(SKILL_DOC);
    if (raw === null) return { status: "skip", summary: "No SKILL.md to inspect." };
    const fm = parseFrontmatter(raw);
    const rawField = fm.fields["allowed-tools"] ?? fm.fields["allowedTools"];
    const declared = parseList(rawField);

    // An ABSENT field and an EXPLICITLY EMPTY one are opposite claims,
    // and collapsing them into `declared.length === 0` warned at the
    // author for doing exactly what this check's own remediation text
    // asks. `allowed-tools: []` is the tightest scope expressible — a
    // deliberate "this needs nothing" — and is the best possible answer.
    const declaredEmpty = rawField !== undefined && declared.length === 0;
    if (declaredEmpty) {
      return {
        status: "pass",
        summary: "Declares an empty tool scope — needs no tools at all.",
        detail:
          "The tightest scope a skill can declare, and stated explicitly rather than left to inference.",
        evidence: [{ type: "file", path: SKILL_DOC, line: 1 }],
      };
    }

    if (declared.length === 0) {
      return {
        status: "warn",
        summary: "No tool scope declared.",
        detail:
          "Without `allowed-tools` the skill inherits whatever the client grants — the broadest possible scope, and nothing on the listing tells a consumer that.",
        remediation:
          "Declare `allowed-tools` with the minimum set the skill actually needs. If it needs none, declare an empty list explicitly.",
        evidence: [{ type: "file", path: SKILL_DOC, line: 1 }],
      };
    }

    const POWERFUL = new Set(["bash", "write", "edit", "webfetch", "websearch", "execute"]);
    const powerful = declared.filter((t) => POWERFUL.has(t.toLowerCase()));
    if (powerful.length > 0) {
      // Reported, never penalised: a skill that legitimately needs a
      // shell should not score below one that needs nothing. The point
      // is that a consumer can see it.
      return {
        status: "pass",
        summary: `Declares ${declared.length} tool${declared.length === 1 ? "" : "s"}, including elevated: ${powerful.join(", ")}.`,
        detail:
          "Declared explicitly, which is what we want — surfaced here so a consumer can see the scope before installing.",
        evidence: [{ type: "file", path: SKILL_DOC, line: 1 }],
      };
    }
    return { status: "pass", summary: `Declares ${declared.length} tool scope entries.` };
  },
});

export const SKILL_CHECKS = [skillFrontmatter, skillBody, skillTriggers, skillAllowedTools];
