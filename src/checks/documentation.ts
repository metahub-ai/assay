/**
 * Documentation and maintenance checks.
 *
 * These carry deliberately LOW weight. Documentation quality is easy to
 * measure and easy to fake, which is exactly the combination that
 * wrecked Libraries.io's SourceRank — nine free points for adding a
 * README, a LICENSE, and a `v1.0.0` tag. Measuring it is still worth
 * doing, because a consumer genuinely cannot use an artifact they
 * cannot understand; letting it dominate a score is not.
 *
 * The one that earns real weight is `description-quality`, because for
 * an AI artifact the description is not decoration — it is the text a
 * model reads to decide whether to invoke the thing. Glama's published
 * research found tools with well-written descriptions are selected by
 * models substantially more often. A vague description is a functional
 * defect, not a cosmetic one.
 */
import { defineCheck } from "../check.js";
import type { CheckResult } from "../types.js";
import { readIdentity } from "./integrity.js";
import { countWords } from "./manifest.js";
import { checkSpecUrl } from "../version.js";

export const descriptionQuality = defineCheck({
  id: "description-quality",
  version: "1.0.0",
  title: "Description is substantive",
  category: "documentation",
  axis: "care",
  determinism: "deterministic",
  weight: 3,
  spec: checkSpecUrl("description-quality"),
  rationale:
    "The description is the only thing a model reads when deciding whether to reach for this artifact at all. Too thin and it never triggers; too vague and it triggers on the wrong task. This is the highest-leverage sentence in the whole artifact.",
  async run(ctx): Promise<CheckResult> {
    const id = await readIdentity(ctx);
    if (id.manifestPath === null || id.malformed) {
      return { status: "skip", summary: "No parseable manifest to read a description from." };
    }
    if (!id.description) {
      return {
        status: "fail",
        summary: "No description declared.",
        detail:
          "For an AI artifact the description is the text a model reads to decide whether to invoke it. Without one, a client cannot route to it at all.",
        remediation: `Add a "description" to ${id.manifestPath} saying what it does and when to reach for it.`,
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    const words = countWords(id.description);
    const min = Number(ctx.config["descriptionMinWords"] ?? 8);
    if (words < min) {
      return {
        status: "warn",
        summary: `Description is ${words} word${words === 1 ? "" : "s"} — thinner than the ${min}-word floor.`,
        // Graded, so "7 words" and "1 word" are not the same finding.
        score: Math.max(0, Math.min(1, words / min)) * 0.8,
        detail: `Current: "${id.description}"`,
        remediation:
          "Say what it does AND when to use it. A model choosing between tools has only this text to go on.",
        evidence: [{ type: "file", path: id.manifestPath }],
      };
    }
    return { status: "pass", summary: `Description is ${words} words.` };
  },
});

export const usageExamples = defineCheck({
  id: "usage-examples",
  version: "1.0.0",
  title: "Documentation shows usage",
  category: "documentation",
  axis: "care",
  determinism: "deterministic",
  weight: 1,
  spec: checkSpecUrl("usage-examples"),
  rationale:
    "An example is the fastest correct answer to how do I call this. Prose describing an interface is not the same as showing one invocation, and a reader who has to reconstruct the call from paragraphs usually reconstructs it wrong.",
  async run(ctx): Promise<CheckResult> {
    const candidates = ["README.md", "readme.md", "SKILL.md", "docs/README.md"];
    for (const path of candidates) {
      const body = await ctx.source.readFile(path);
      if (!body) continue;
      const fences = (body.match(/^```/gm) ?? []).length;
      // Fences come in pairs; one lone fence is a formatting bug.
      if (fences >= 2) {
        return {
          status: "pass",
          summary: `Documentation includes ${Math.floor(fences / 2)} code example${fences >= 4 ? "s" : ""}.`,
          evidence: [{ type: "file", path }],
        };
      }
      return {
        status: "warn",
        summary: "Documentation has no code examples.",
        detail:
          "A worked example is the fastest way for both a human and a model to understand the invocation shape.",
        remediation: "Add at least one fenced example showing a real invocation.",
        evidence: [{ type: "file", path }],
      };
    }
    return { status: "skip", summary: "No documentation file found to inspect." };
  },
});

export const homepageDeclared = defineCheck({
  id: "homepage-declared",
  version: "1.0.0",
  title: "Homepage or repository declared",
  category: "documentation",
  axis: "care",
  determinism: "deterministic",
  weight: 1,
  spec: checkSpecUrl("homepage-declared"),
  rationale:
    "Where to file a bug, read the source, and see who publishes it. Its absence is not dangerous — it is the difference between an artifact somebody can follow up on and one that arrives anonymously.",
  async run(ctx): Promise<CheckResult> {
    const id = await readIdentity(ctx);
    if (id.homepage) {
      return { status: "pass", summary: "Homepage declared." };
    }
    const raw = id.manifestPath ? await ctx.source.readFile(id.manifestPath) : null;
    if (raw && /"repository"\s*:/.test(raw)) {
      return { status: "pass", summary: "Repository declared." };
    }
    return {
      status: "warn",
      summary: "No homepage or repository declared.",
      detail:
        "Consumers deciding whether to trust an artifact need somewhere to read the source and file issues.",
      remediation: `Add a "homepage" or "repository" field to ${id.manifestPath ?? "the manifest"}.`,
    };
  },
});

/**
 * Tests as an INFORMATIONAL signal, at weight 0.
 *
 * "Has tests" is the canonical gameable check — an empty `test/`
 * directory satisfies it, and OpenSSF Scorecard's equivalent is
 * routinely cited as an example of measuring what is easy rather than
 * what matters. It is reported because a reader genuinely wants to
 * know, and scored at zero because the presence of a directory says
 * nothing about whether anything is verified.
 */
export const testsPresent = defineCheck({
  id: "tests-present",
  version: "1.0.0",
  title: "Test suite present",
  category: "maintenance",
  axis: "care",
  determinism: "deterministic",
  weight: 0,
  spec: checkSpecUrl("tests-present"),
  rationale:
    "Tests are evidence the author checked their own work. Reported and never scored: plenty of correct artifacts are small enough not to need any, and scoring this would push people to add a file that asserts nothing in order to move a number.",
  async run(ctx): Promise<CheckResult> {
    const tree = await ctx.source.listTree();
    const testFiles = tree.filter(
      (e) =>
        e.type === "file" &&
        (/(^|\/)(tests?|__tests__|spec)\//i.test(e.path) ||
          /\.(test|spec)\.[jt]sx?$/.test(e.path) ||
          /(^|\/)test_[^/]+\.py$/.test(e.path)),
    );
    return testFiles.length > 0
      ? {
          status: "neutral",
          summary: `${testFiles.length} test file${testFiles.length === 1 ? "" : "s"} present.`,
          evidence: [{ type: "metric", name: "test_files", value: testFiles.length }],
        }
      : { status: "neutral", summary: "No test files found." };
  },
});

export const ciConfigured = defineCheck({
  id: "ci-configured",
  version: "1.0.0",
  title: "Continuous integration configured",
  category: "maintenance",
  axis: "care",
  determinism: "deterministic",
  weight: 0,
  spec: checkSpecUrl("ci-configured"),
  rationale:
    "CI is evidence the tests run somewhere other than the author's laptop. Informational for the same reason as tests — its absence is a fact about how the project is run, not a defect in the artifact a consumer installs.",
  async run(ctx): Promise<CheckResult> {
    const tree = await ctx.source.listTree();
    const ci = tree.find(
      (e) =>
        e.type === "file" &&
        (/^\.github\/workflows\/.+\.ya?ml$/.test(e.path) ||
          /^\.gitlab-ci\.ya?ml$/.test(e.path) ||
          /^\.circleci\/config\.ya?ml$/.test(e.path) ||
          /^\.travis\.ya?ml$/.test(e.path)),
    );
    return ci
      ? {
          status: "neutral",
          summary: "CI configured.",
          evidence: [{ type: "file", path: ci.path }],
        }
      : { status: "neutral", summary: "No CI configuration found." };
  },
});

export const DOCUMENTATION_CHECKS = [
  descriptionQuality,
  usageExamples,
  homepageDeclared,
  testsPresent,
  ciConfigured,
];
