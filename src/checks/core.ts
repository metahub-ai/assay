/**
 * A starter set of core checks.
 *
 * Not the full catalog — the portal has ~44 checks that will port here.
 * These six exist to exercise every determinism tier and every
 * capability against a real API, so the design is validated by code
 * rather than by assertion. Each is the shape a third-party check
 * takes: a standalone module, independently versioned and testable.
 *
 * Note what is NOT here: `slug-unique`. Uniqueness within a namespace
 * is a property of a *registry*, not of an artifact — the same skill is
 * simultaneously unique on one registry and taken on another. It is
 * also the only reason the portal's static checks touch Postgres.
 * Moving it out is what makes this whole layer runnable offline, which
 * is what makes local and hosted results comparable.
 */
import { defineCheck } from "../check.js";
import type { CheckContext } from "../check.js";
import { resolveDocs } from "./docs-resolution.js";
import { PLUGIN_MANIFESTS, countWords, readManifest } from "./manifest.js";
import { BLOCKING_SEVERITIES, scanDependencies } from "./osv.js";
import { ignoredPaths } from "./gitignore.js";
import type { Evidence } from "../types.js";
import { checkSpecUrl } from "../version.js";

/** Files whose presence in a published artifact is a credential leak. */
const SENSITIVE_PATTERNS: ReadonlyArray<{ re: RegExp; what: string }> = [
  { re: /(^|\/)\.env(\.[A-Za-z0-9_-]+)?$/, what: "environment file" },
  { re: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/, what: "SSH private key" },
  { re: /(^|\/)\.npmrc$/, what: "npm credentials file" },
  { re: /(^|\/)\.pypirc$/, what: "PyPI credentials file" },
  { re: /(^|\/)credentials(\.json)?$/, what: "credentials file" },
  { re: /\.(pem|p12|pfx|keystore)$/, what: "private key or keystore" },
  { re: /(^|\/)service-account.*\.json$/, what: "service-account key" },
];

/** `.env.example` and friends are documentation, not leaks. */
const SENSITIVE_ALLOW = /(^|\/)\.env\.(example|sample|template)$/;

/**
 * Files whose NAME is credential-shaped but whose contents usually are
 * not.
 *
 * `.npmrc` is the clear case: the overwhelmingly common use is project
 * configuration — `save-exact=true`, `registry=`, `engine-strict=` —
 * and only a minority carry `_authToken`. Blocking on the filename
 * alone took a real published plugin from 90 to 44 and FAIL over a
 * one-line file reading `save-exact=true`, with a remediation telling
 * the author to rotate a credential that was never there.
 *
 * These get their contents read before the finding blocks. Everything
 * else still matches on name, because a file called `id_rsa` has no
 * innocent reading.
 */
const CONFIG_CAPABLE = /(^|\/)\.(npmrc|pypirc|yarnrc)$/;

/**
 * Keys that carry a secret in those files.
 *
 * Matched against the KEY, never reported with its value — the whole
 * point of this check is to notice a leak without republishing it.
 */
const CREDENTIAL_KEY =
  /(_authToken|_auth|_password|^\s*password\s*[:=]|^\s*token\s*[:=]|^\s*username\s*[:=]|NPM_TOKEN|:_secret)/im;

/**
 * Does a config-capable file actually contain a credential?
 *
 * An unreadable file is treated as though it does: refusing to look is
 * not evidence of safety, and this check must never let a wrong guess
 * hide a real leak.
 */
async function carriesCredential(ctx: CheckContext, path: string): Promise<boolean> {
  const body = await ctx.source.readFile(path);
  if (body === null) return true;
  return CREDENTIAL_KEY.test(body);
}

export const noSensitiveFiles = defineCheck({
  id: "no-sensitive-files",
  version: "1.0.0",
  title: "No credential files committed",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 5,
  blocking: true,
  spec: checkSpecUrl("no-sensitive-files"),
  inspects: "Every filename in the artifact.",
  rationale:
    "A credential that reaches a published artifact is compromised the moment it is published, and it stays in git history after you delete the file. This is the most common way a small project leaks production access.",
  examples: {
    passing: ".env.example  — a template with placeholder values",
    failing: ".env          — the real one, committed",
  },
  async run(ctx) {
    const tree = await ctx.source.listTree();
    const hits = tree.filter(
      (e) =>
        e.type === "file" &&
        !SENSITIVE_ALLOW.test(e.path) &&
        SENSITIVE_PATTERNS.some((p) => p.re.test(e.path)),
    );
    if (hits.length === 0) {
      return { status: "pass", summary: "No credential-shaped files found." };
    }
    // Paths only, never contents — a report that quotes the secret it
    // found has republished the secret.
    const evidence: Evidence[] = hits.map((h) => ({ type: "file", path: h.path }));

    // A gitignored file is present in the working tree but will not be
    // published, so "committed" is simply wrong about it — and the
    // remediation told the author to do the thing they had already done.
    // Downgraded rather than suppressed: the matcher is deliberately
    // conservative, and a wrong match must never be able to hide a real
    // leak. The finding stays visible either way.
    const ignored = await ignoredPaths(
      ctx.source,
      hits.map((h) => h.path),
    );
    // A config-capable file whose contents hold no credential is not a
    // leak. Checked before the blocking verdict, and only for the names
    // that have an innocent reading.
    const inert = new Set<string>();
    for (const h of hits) {
      if (CONFIG_CAPABLE.test(h.path) && !(await carriesCredential(ctx, h.path))) {
        inert.add(h.path);
      }
    }

    const published = hits.filter((h) => !ignored.has(h.path) && !inert.has(h.path));
    const describe = (h: { path: string }) => {
      const what = SENSITIVE_PATTERNS.find((p) => p.re.test(h.path))?.what ?? "sensitive file";
      const note = ignored.has(h.path)
        ? " (gitignored — not published)"
        : inert.has(h.path)
          ? " (no credential in it — configuration only)"
          : "";
      return `- \`${h.path}\` — ${what}${note}`;
    };

    // Everything that matched turned out to be configuration. Worth
    // saying, because the name is still a hazard the day someone adds a
    // token to it — but it does not block, and it does not tell anyone
    // to rotate a credential that does not exist.
    if (published.length === 0 && inert.size === hits.length) {
      return {
        status: "pass",
        summary: `${hits.length} credential-shaped file${hits.length === 1 ? "" : "s"}, none carrying a credential.`,
        detail: `${hits.map(describe).join("\n")}\n\nThese names commonly hold credentials, but these do not — they contain configuration only.`,
        evidence,
      };
    }

    if (published.length === 0) {
      return {
        status: "warn",
        summary: `${hits.length} credential-shaped file${hits.length === 1 ? "" : "s"} present locally, all gitignored.`,
        detail: `${hits.map(describe).join("\n")}\n\nThese are in the working tree but excluded from version control, so they will not reach a consumer.`,
        remediation:
          "Nothing is published, so this does not block. Confirm the ignore rules are committed, and that the credentials were never committed in an earlier revision.",
        evidence,
      };
    }

    return {
      status: "fail",
      summary: `${published.length} credential-shaped file${published.length === 1 ? "" : "s"} committed.`,
      detail: hits.map(describe).join("\n"),
      remediation:
        "Remove the file, rotate any credential it contained (assume it is compromised — it is in git history), and add the path to .gitignore.",
      evidence,
    };
  },
});

/**
 * A licence declared in a manifest field rather than a LICENSE file.
 *
 * npm treats `package.json`'s `license` as THE declaration and packing a
 * LICENSE file is optional, so demanding the file warned at properly
 * licensed published packages for following their own ecosystem's
 * convention. Python's `pyproject.toml` has the same shape.
 */
async function declaredLicense(ctx: CheckContext): Promise<{ value: string; path: string } | null> {
  for (const path of ["package.json", ".claude-plugin/plugin.json", "plugin.json", "agent.json"]) {
    const raw = await ctx.source.readFile(path);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw) as { license?: unknown };
      // npm also allows the deprecated object form `{type, url}`.
      const value =
        typeof parsed.license === "string"
          ? parsed.license
          : typeof (parsed.license as { type?: unknown })?.type === "string"
            ? String((parsed.license as { type: string }).type)
            : null;
      if (value && value.trim() && value.toUpperCase() !== "UNLICENSED") {
        return { value: value.trim(), path };
      }
    } catch {
      /* an unparseable manifest declares nothing */
    }
  }

  const py = await ctx.source.readFile("pyproject.toml");
  // Both `license = "MIT"` and PEP 621's `license = {text = "MIT"}`.
  const m = py?.match(/^\s*license\s*=\s*(?:\{[^}]*text\s*=\s*)?["']([^"']+)["']/m);
  if (m?.[1]?.trim()) return { value: m[1].trim(), path: "pyproject.toml" };

  return null;
}

export const licensePresent = defineCheck({
  id: "license-present",
  version: "1.0.0",
  title: "License declared",
  category: "safety",
  axis: "safety",
  determinism: "deterministic",
  weight: 3,
  spec: checkSpecUrl("license-present"),
  inspects: "A LICENSE file, or a `license` field in the manifest.",
  rationale:
    "Without a licence, default copyright applies and nobody may legally reuse the artifact — being public is not permission. Either form counts; npm treats the manifest field as the declaration and packing the file is optional.",
  examples: {
    passing: '"license": "MIT"   in package.json, or a LICENSE file',
    failing: "neither present",
  },
  async run(ctx) {
    const tree = await ctx.source.listTree();
    const license = tree.find((e) => /^LICENSE(\.(md|txt))?$/i.test(e.path));
    if (license) {
      return {
        status: "pass",
        summary: "License file present.",
        evidence: [{ type: "file", path: license.path }],
      };
    }

    // A declared `license` field is a licence. Demanding the FILE was
    // the SourceRank file-presence anti-pattern this project's own
    // design doc argues against — npm treats the manifest field as the
    // declaration, packing a LICENSE file is optional, and plenty of
    // correctly-licensed published packages ship only the field. The
    // check was warning at them for following their ecosystem's
    // convention.
    const declared = await declaredLicense(ctx);
    if (declared) {
      return {
        status: "pass",
        summary: `License declared as ${declared.value} in ${declared.path}.`,
        evidence: [{ type: "file", path: declared.path }],
      };
    }

    return {
      status: "warn",
      summary: "No license found.",
      detail:
        "Without a license, default copyright applies and the artifact is not legally reusable, regardless of it being published publicly. Neither a LICENSE file nor a declared license field was found.",
      remediation:
        "Add a LICENSE file at the artifact root, or declare a `license` field in the manifest. MIT and Apache-2.0 are the common choices.",
    };
  },
});

/**
 * Documentation, resolved per kind.
 *
 * Was `readme-present`, and it demanded a root README.md. That failed
 * all ten official Anthropic skills, ten of ten prompt-based agents,
 * and eight of ten real plugins — because for those kinds the
 * documentation is SKILL.md, the agent markdown, or the bundle itself.
 * New id, because the meaning changed rather than the implementation.
 */
export const documentationPresent = defineCheck({
  id: "documentation-present",
  version: "1.0.0",
  title: "Documentation present and substantive",
  category: "documentation",
  axis: "care",
  determinism: "deterministic",
  weight: 2,
  spec: checkSpecUrl("documentation-present"),
  rationale:
    "An artifact with no documentation cannot be chosen correctly by anybody: a model has nothing to match a task against, and a reviewer has nothing to check the behavior against. What counts as documentation depends on the format — for a skill, SKILL.md is it, and demanding a separate README would be inventing a requirement the format never had.",
  async run(ctx) {
    const docs = await resolveDocs(ctx.source, ctx.subject.kind);
    if (!docs) {
      // A bundle can be documented without a README of its own: a
      // substantive manifest description plus documented members
      // genuinely tells a reader what they are installing. Real,
      // well-maintained plugin corpora look exactly like this 80% of
      // the time, so calling it a FAILURE is disproportionate — a
      // README would help, and that is a warning.
      const bundle = await describeBundle(ctx);
      if (bundle) {
        return {
          status: "warn",
          summary: `No README, but the manifest describes the bundle (${bundle}).`,
          detail:
            "A reader can tell what this installs from the manifest and its bundled documentation, but there is no single place that introduces the bundle as a whole.",
          remediation: "Add a README summarising what the bundle is for and what it contains.",
          score: 0.7,
        };
      }
      return {
        status: "fail",
        summary: "No documentation found.",
        detail:
          "Nothing a human or a model could read to learn what this does. Looked for the conventional document for " +
          `${ctx.subject.kind === "agent" ? "an" : "a"} ${ctx.subject.kind} artifact, and for a README.`,
        remediation: "Add documentation describing what this does and when to use it.",
      };
    }
    const words = countWords(docs.body);
    const min = Number(ctx.config["docsMinWords"] ?? 50);
    if (words < min) {
      return {
        status: "warn",
        summary: `${docs.path} is ${words} words — thinner than the ${min}-word floor.`,
        // Graded rather than a flat 0.5, so "48 words" and "3 words"
        // are not treated as the same problem.
        score: Math.max(0, Math.min(1, words / min)) * 0.8,
        remediation: "Describe what the artifact does, when to reach for it, and a usage example.",
        evidence: [{ type: "file", path: docs.path }],
      };
    }
    return {
      status: "pass",
      summary: `Documentation present (${docs.path}, ${words} words).`,
      evidence: [{ type: "file", path: docs.path }],
    };
  },
});

/**
 * Demonstrates the `clock` capability — and, deliberately, a check
 * that reports without scoring.
 *
 * Recency is the textbook case for time being a declared capability:
 * this verdict changes with no change to the artifact. But it is also
 * the textbook case for NOT scoring a signal.
 *
 * Libraries.io's SourceRank awarded a point for a release within six
 * months and deducted one for outdated dependencies; OpenSSF
 * Scorecard's `Maintained` check still requires roughly a commit a
 * week for full marks. Both reward churn and punish completion: a
 * small, correct, dependency-free library decays toward a bad grade
 * forever, while a package cutting empty version bumps stays "fresh."
 * Ten years apart, the same mistake.
 *
 * The distinction worth preserving is between *"is anyone home if this
 * breaks?"* and *"is this any good?"* Those are different questions and
 * only the second belongs in a quality score. So this check runs, and
 * emits its measurement as evidence, at **weight 0** — reported, never
 * scored. There is precedent: CVSS v4.0 added a Supplemental metric
 * group that deliberately contributes nothing to the score, on exactly
 * the reasoning that some signals should inform a reader without being
 * aggregated into a verdict.
 *
 * It also never emits `fail`. Dormancy is a fact about a repository,
 * not a defect in an artifact.
 */
export const recentlyMaintained = defineCheck({
  id: "recently-maintained",
  version: "2.0.0",
  title: "Maintenance activity",
  category: "maintenance",
  axis: "care",
  determinism: "sampled",
  needs: ["clock"],
  // Informational. See the note above — this is a fact for the reader,
  // not a component of the grade.
  weight: 0,
  spec: checkSpecUrl("recently-maintained"),
  rationale:
    "A long-idle artifact is not a defect; plenty of good code is finished. It is context for a different question: when an advisory lands against a dependency, is anyone going to patch this? Reported and never scored, because old is not the same as bad.",
  async run(ctx) {
    const pushedMs = Number(ctx.config.lastCommitMs ?? 0);
    if (!pushedMs) {
      return { status: "skip", summary: "No commit timestamp available for this source." };
    }
    const days = Math.floor(((ctx.now?.() ?? 0) - pushedMs) / 86_400_000);
    const dormantAfter = Number(ctx.config.recencyDormantDays ?? 540);
    const evidence: Evidence[] = [
      { type: "metric", name: "days_since_last_commit", value: days, unit: "days" },
    ];
    if (days > dormantAfter) {
      return {
        status: "neutral",
        summary: `Last commit was ${days} days ago.`,
        detail:
          "Reported for context, not scored. Dormancy may mean the artifact is finished, or that " +
          "nobody is available to fix it — this check cannot distinguish those, so it does not judge.",
        evidence,
      };
    }
    return { status: "neutral", summary: `Last commit ${days} days ago.`, evidence };
  },
});

/**
 * Demonstrates the `net` capability — an external advisory lookup.
 *
 * `sampled` rather than `replayable` because the upstream advisory
 * database legitimately changes underneath us: the same artifact is
 * clean today and vulnerable tomorrow with no edit. Recording that
 * honestly, rather than pretending the verdict is a stable property of
 * the bytes, is the point of the tier system.
 */
export const depsNoKnownVulns = defineCheck({
  id: "deps-no-known-vulns",
  version: "1.0.0",
  title: "No known-vulnerable dependencies",
  category: "supply-chain",
  axis: "safety",
  determinism: "sampled",
  needs: ["net"],
  weight: 4,
  spec: checkSpecUrl("deps-no-known-vulns"),
  rationale:
    "A published advisory is the one supply-chain signal that is already public, already triaged, and already carries a fixed version. Needing the network is the reason this lowers coverage rather than failing when it cannot run — an offline verdict of clean would be a claim we did not check.",
  async run(ctx) {
    if (!ctx.net) {
      return { status: "skip", summary: "Network access was not granted to this run." };
    }
    const raw = await ctx.source.readFile("package.json");
    if (!raw) {
      return { status: "neutral", summary: "No package.json — no npm dependencies to scan." };
    }
    let deps: Record<string, string> = {};
    try {
      deps = (JSON.parse(raw) as { dependencies?: Record<string, string> }).dependencies ?? {};
    } catch {
      return { status: "error", summary: "package.json did not parse." };
    }
    const names = Object.keys(deps);
    if (names.length === 0) {
      return { status: "pass", summary: "No production dependencies declared." };
    }

    const result = await scanDependencies(ctx.net, deps);

    const evidence: Evidence[] = [
      {
        type: "url",
        url: "https://api.osv.dev/v1/querybatch",
        note: `queried ${result.queried} package(s)`,
      },
    ];
    if (result.unresolvable.length > 0) {
      // Named rather than silently dropped: a package we could not
      // resolve a version for is a package we did NOT check, and
      // reporting a clean result over it would be the false-pass bug
      // this check already had once.
      evidence.push({
        type: "metric",
        name: "unresolvable_ranges",
        value: result.unresolvable.length,
      });
    }

    if (result.advisories.length === 0) {
      const caveat =
        result.unresolvable.length > 0
          ? ` ${result.unresolvable.length} range(s) had no concrete version and were not checked.`
          : "";
      return {
        status: result.unresolvable.length > 0 ? "warn" : "pass",
        summary: `No known advisories across ${result.queried} direct dependencies.${caveat}`,
        ...(result.unresolvable.length > 0
          ? {
              detail: `Not checked: ${result.unresolvable.join(", ")}.`,
              remediation: "Pin these to a concrete version so they can be scanned.",
            }
          : {}),
        evidence,
      };
    }

    const blocking = result.advisories.filter((a) => BLOCKING_SEVERITIES.has(a.severity));
    for (const a of result.advisories.slice(0, 10)) {
      evidence.push({
        type: "url",
        url: `https://osv.dev/vulnerability/${a.id}`,
        note: `${a.package}@${a.installed} — ${a.severity}`,
      });
    }

    return {
      status: blocking.length > 0 ? "fail" : "warn",
      summary:
        blocking.length > 0
          ? `${blocking.length} high or critical advisor${blocking.length === 1 ? "y" : "ies"} across ${result.queried} dependencies.`
          : `${result.advisories.length} advisor${result.advisories.length === 1 ? "y" : "ies"} of moderate or lower severity.`,
      detail: result.advisories
        .map(
          (a) =>
            `- **${a.package}@${a.installed}** — ${a.severity} — [${a.id}](https://osv.dev/vulnerability/${a.id})` +
            `\n  ${a.summary}` +
            (a.fixed ? `\n  Fixed in ${a.fixed}.` : "\n  No fixed version published."),
        )
        .join("\n"),
      remediation: blocking.some((a) => a.fixed)
        ? "Upgrade the affected packages to the fixed versions listed above."
        : "Review each advisory — some have no published fix, and may need a workaround or a different dependency.",
      evidence,
    };
  },
});

// The behavioral check moved to ./behavioral.ts once it became real.
// It is a FACTORY, not a constant, because it needs host wiring (a
// transcript sink, repo coordinates, a case cache) — see
// `createBehavioralCheck`.

/** The starter suite. */
/**
 * Summarise a bundle from its manifest, when it has one worth reading.
 * Returns null when there is nothing substantive to fall back on.
 */
async function describeBundle(ctx: CheckContext): Promise<string | null> {
  if (ctx.subject.kind !== "plugin") return null;
  const manifest = await readManifest(ctx.source, PLUGIN_MANIFESTS);
  const description = manifest?.data?.["description"];
  if (typeof description !== "string" || countWords(description) < 8) return null;
  const tree = await ctx.source.listTree();
  const documented = tree.filter(
    (e) => e.type === "file" && /^(agents|commands|skills)\/.+\.(md|json)$/.test(e.path),
  ).length;
  return documented > 0
    ? `${countWords(description)}-word description, ${documented} documented members`
    : null;
}

export const CORE_CHECKS = [
  noSensitiveFiles,
  licensePresent,
  documentationPresent,
  recentlyMaintained,
  depsNoKnownVulns,
];
