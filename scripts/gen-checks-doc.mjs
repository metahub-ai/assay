/**
 * Generate `docs/CHECKS.md` from the check registry.
 *
 * Every check result publishes a `spec` URL, and SARIF republishes it
 * as `helpUri` — which GitHub code scanning renders as a clickable
 * "learn more" on every finding. Those URLs pointed at `assay.dev`, a
 * domain this project does not own; it resolves to an unrelated
 * WordPress site about laboratory assay development, so each report
 * shipped two dozen links to a stranger and a 404.
 *
 * They now point at anchors in this file. Generating it rather than
 * writing it means the documentation cannot drift from the checks: the
 * anchors are the check ids, and `npm run docs:checks` regenerates.
 *
 *   node scripts/gen-checks-doc.mjs [--check]
 *
 * `--check` verifies the committed file is current and exits non-zero
 * if not, so CI notices a check added without its documentation.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DEFAULT_CHECKS } from "../dist/checks/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const target = join(root, "docs", "CHECKS.md");

const AXIS_ORDER = ["integrity", "safety", "care", "behavior"];
const AXIS_BLURB = {
  integrity: "Is this artifact what it says it is, and is it internally coherent?",
  safety: "Could installing this hurt the person who installs it?",
  care: "Is this maintained by someone who intends to keep maintaining it?",
  behavior: "Does it actually do what its documentation claims?",
};

const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n+/g, " ");

let out = `<!--
  GENERATED FILE — do not edit by hand.
  Run \`npm run docs:checks\` after changing a check definition.
-->

# The checks

Every check in the default suite, generated from the registry so this
page cannot drift from the code.

Each one declares an **axis** (which part of the score it feeds), a
**weight** (how much it counts within that axis), whether it is
**blocking** (a failure stops a publish, regardless of score), and its
**determinism tier** — \`deterministic\` is a pure function of the bytes,
\`replayable\` used a model and records a transcript so a skeptic can
re-derive the verdict, \`sampled\` consulted something that changes over
time.

A check that cannot run reports \`skip\`, which lowers the axis's
coverage rather than silently vanishing. A check that does not apply
reports \`neutral\` and leaves coverage alone. Our own failures report
\`error\` and are never counted against the artifact.

> Disagree with a verdict on your artifact? Write a waiver rather than
> disabling the check — the reason is mandatory and published in the
> report, and \`disable\` costs you coverage while a waiver does not.
> \`assay explain <check-id>\` prints the waiver snippet for any check.

`;

const byAxis = new Map();
for (const c of DEFAULT_CHECKS) {
  byAxis.set(c.axis, [...(byAxis.get(c.axis) ?? []), c]);
}

out += `## At a glance\n\n`;
out += `| Check | Axis | Weight | Blocking | Applies to |\n|---|---|---|---|---|\n`;
for (const axis of AXIS_ORDER) {
  for (const c of (byAxis.get(axis) ?? []).sort((a, b) => a.id.localeCompare(b.id))) {
    out += `| [\`${c.id}\`](#${c.id}) | ${c.axis} | ${c.weight === 0 ? "info" : (c.weight ?? 1)} | ${c.blocking ? "yes" : "—"} | ${c.appliesTo?.kinds?.join(", ") ?? "all"} |\n`;
  }
}
out += `\n`;

for (const axis of AXIS_ORDER) {
  const checks = (byAxis.get(axis) ?? []).sort((a, b) => a.id.localeCompare(b.id));
  if (!checks.length) continue;
  out += `---\n\n## ${axis}\n\n${AXIS_BLURB[axis]}\n\n`;
  for (const c of checks) {
    out += `### ${c.id}\n\n`;
    out += `**${c.title}**\n\n`;
    if (c.inspects) out += `*What it looks at:* ${esc(c.inspects)}\n\n`;
    if (c.rationale) out += `${c.rationale}\n\n`;
    if (c.examples?.passing || c.examples?.failing) {
      out += `\`\`\`\n`;
      if (c.examples.passing) out += `✔  ${c.examples.passing}\n`;
      if (c.examples.failing) out += `✘  ${c.examples.failing}\n`;
      out += `\`\`\`\n\n`;
    }
    const bits = [
      `axis \`${c.axis}\``,
      `weight ${c.weight === 0 ? "0 (informational)" : (c.weight ?? 1)}`,
      `${c.blocking ? "**blocking**" : "non-blocking"}`,
      `\`${c.determinism}\``,
      `applies to ${c.appliesTo?.kinds?.join(", ") ?? "all kinds"}`,
    ];
    if (c.needs?.length) bits.push(`needs ${c.needs.map((n) => `\`${n}\``).join(", ")}`);
    out += `<sub>${bits.join(" · ")} · v${c.version}</sub>\n\n`;
  }
}

out += `---\n\n<sub>${DEFAULT_CHECKS.length} checks. Regenerate with \`npm run docs:checks\`.</sub>\n`;

if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(target, "utf8");
  } catch {
    // Absent is simply out of date.
  }
  if (current !== out) {
    process.stderr.write(
      "docs/CHECKS.md is out of date — run `npm run docs:checks` and commit the result.\n",
    );
    process.exit(1);
  }
  process.stdout.write("docs/CHECKS.md is current\n");
} else {
  writeFileSync(target, out);
  process.stdout.write(`wrote docs/CHECKS.md (${DEFAULT_CHECKS.length} checks)\n`);
}
