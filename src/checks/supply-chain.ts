/**
 * Supply-chain checks.
 *
 * The headline one here is `no-install-scripts`, and it is worth
 * explaining why a lifecycle script rates as a *safety* finding rather
 * than a style note.
 *
 * Every wave of the Shai-Hulud npm worm — September 2025 through the
 * 2026 "mini" campaigns hitting Bitwarden's CLI, TanStack, Mastra, and
 * Red Hat packages — depended on exactly one mechanism: code that runs
 * automatically at install time, before anyone reads anything. The
 * November 2025 iteration moved from `postinstall` to `preinstall`
 * specifically to run ahead of security tooling.
 *
 * npm's own structural answer, after a decade of trying to scan its way
 * out, was to make lifecycle scripts **default-deny** in v12 and
 * require explicit approval. An artifact that needs one is asking for a
 * privilege the ecosystem has decided is not safe to grant silently, so
 * Assay surfaces it — not as a verdict that the artifact is malicious,
 * but as a fact a consumer deserves before installing.
 */
import { defineCheck } from "../check.js";
import type { CheckResult, Evidence } from "../types.js";
import { readManifest } from "./manifest.js";
import { checkSpecUrl } from "../version.js";

/** Scripts npm/pnpm/yarn run without the user asking. */
const AUTORUN_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "preprepare",
  "postprepare",
] as const;

/** Scripts that only run for the package's own author, not consumers. */
const AUTHOR_ONLY = new Set(["prepublishOnly", "prepack", "postpack"]);

export const noInstallScripts = defineCheck({
  id: "no-install-scripts",
  version: "1.0.0",
  title: "No automatic install-time scripts",
  category: "supply-chain",
  axis: "safety",
  determinism: "deterministic",
  weight: 4,
  spec: checkSpecUrl("no-install-scripts"),
  inspects: "`preinstall`, `install`, `postinstall` and `prepare` in package.json.",
  rationale:
    "These run automatically on `npm install`, before anyone has read a line of the code. It is the mechanism Shai-Hulud used, and the reason this tool installs dependencies with --ignore-scripts when it evaluates you.",
  examples: {
    passing: '"scripts": { "build": "tsc" }        — run on demand',
    failing: '"scripts": { "postinstall": "node setup.js" }',
  },
  async run(ctx): Promise<CheckResult> {
    const manifest = await readManifest(ctx.source, ["package.json"]);
    if (!manifest?.data) {
      return { status: "neutral", summary: "No package.json — no npm lifecycle scripts to run." };
    }
    const scripts = manifest.data["scripts"];
    if (!scripts || typeof scripts !== "object") {
      return { status: "pass", summary: "No scripts declared." };
    }
    const declared = scripts as Record<string, unknown>;
    const found = AUTORUN_SCRIPTS.filter(
      (name) => typeof declared[name] === "string" && !AUTHOR_ONLY.has(name),
    );
    if (found.length === 0) {
      return { status: "pass", summary: "No install-time scripts." };
    }
    const evidence: Evidence[] = found.map((name) => ({
      type: "file",
      path: "package.json",
      excerpt: `"${name}": ${JSON.stringify(declared[name])}`,
    }));
    return {
      status: "warn",
      summary: `Runs ${found.length} script${found.length === 1 ? "" : "s"} automatically at install time: ${found.join(", ")}.`,
      detail:
        "Install-time scripts execute before anyone inspects the package. This is the mechanism every wave of the Shai-Hulud npm worm relied on, and npm made lifecycle scripts default-deny in v12 as a result.\n\n" +
        "This is a fact a consumer deserves before installing, not an accusation — plenty of legitimate packages need a native build step.",
      remediation:
        "If the work can happen lazily at first use instead, move it there. If it genuinely cannot, document why in the README so consumers can make an informed decision.",
      evidence,
    };
  },
});

/**
 * Unbounded dependency ranges.
 *
 * `"*"` or `"latest"` means the artifact evaluated today is not the
 * artifact installed tomorrow — which defeats content addressing
 * downstream and is how a compromised transitive dependency reaches
 * users who changed nothing.
 */
export const depsPinned = defineCheck({
  id: "deps-bounded",
  version: "1.0.0",
  title: "Dependency ranges are bounded",
  category: "supply-chain",
  axis: "safety",
  determinism: "deterministic",
  weight: 2,
  spec: checkSpecUrl("deps-bounded"),
  inspects: "Every dependency specifier in package.json.",
  rationale:
    "An unbounded range means what you tested is not what your users get. A non-registry specifier — a URL, a git ref, a local path — is worse still: no integrity hash, no lockfile pin, no advisory coverage, and the target can change without the version changing.",
  examples: {
    passing: '"lodash": "^4.17.21"',
    failing: '"lodash": "*"   |   "dep": "https://cdn.example.com/dep.tgz"',
  },
  async run(ctx): Promise<CheckResult> {
    const manifest = await readManifest(ctx.source, ["package.json"]);
    const deps = manifest?.data?.["dependencies"];
    if (!deps || typeof deps !== "object") {
      return { status: "neutral", summary: "No production dependencies declared." };
    }
    // Every dependency kind that ends up installed, not just
    // `dependencies` — an optional or bundled dep runs the same code.
    const entries = Object.entries(deps as Record<string, unknown>);
    for (const field of ["optionalDependencies", "bundleDependencies", "bundledDependencies"]) {
      const extra = manifest?.data?.[field];
      if (extra && typeof extra === "object" && !Array.isArray(extra)) {
        entries.push(...Object.entries(extra as Record<string, unknown>));
      }
    }

    const nonRegistry: [string, string][] = [];
    const open: [string, string][] = [];
    for (const [name, raw] of entries) {
      if (typeof raw !== "string") continue;
      const spec = raw.trim();
      // A specifier that fetches from outside the registry is strictly
      // WORSE than `*`: no lockfile entry, no integrity hash, no OSV
      // coverage, and the target can change under you at any time. All
      // of these used to pass a check named "ranges are bounded".
      if (
        /^(file:|link:|git\+|git:|https?:|github:|gitlab:|bitbucket:|[\w.-]+\/[\w.-]+$)/i.test(spec)
      ) {
        nonRegistry.push([name, spec]);
      } else if (/^(\*|latest|x|)$/i.test(spec) || /^>=?[^<]*$/.test(spec)) {
        // `>=1.0.0` with no upper bound is genuinely unbounded and used
        // to pass, because only four exact literals were checked.
        open.push([name, spec]);
      }
    }

    if (nonRegistry.length === 0 && open.length === 0) {
      return { status: "pass", summary: `All ${entries.length} dependency ranges are bounded.` };
    }

    const list = (xs: [string, string][]) =>
      xs.map(([n, v]) => `- \`${n}\`: \`${v || "(empty)"}\``).join("\n");

    if (nonRegistry.length > 0) {
      return {
        status: "fail",
        summary: `${nonRegistry.length} dependenc${nonRegistry.length === 1 ? "y is" : "ies are"} fetched from outside the registry.`,
        detail:
          `${list(nonRegistry)}\n\nThese resolve to a URL, a git ref, or a local path rather than a published version. ` +
          `There is no integrity hash, no lockfile pin, and no advisory coverage, and the target can change without the version changing.` +
          (open.length > 0 ? `\n\nAlso unbounded:\n${list(open)}` : ""),
        remediation:
          "Depend on published versions from the registry. If a fork is genuinely required, publish it under your own scope and pin it.",
        evidence: [{ type: "file", path: "package.json" }],
      };
    }

    return {
      status: "warn",
      summary: `${open.length} dependenc${open.length === 1 ? "y has an" : "ies have"} unbounded range.`,
      detail: list(open),
      remediation:
        "Pin to a range with an upper bound (e.g. ^1.2.0). An unbounded range means what you tested is not what your users get.",
      evidence: [{ type: "file", path: "package.json" }],
    };
  },
});

/**
 * A lockfile is not required, but its ABSENCE plus dependencies means
 * nobody — including the author — can reproduce the tree that was
 * evaluated.
 */
export const lockfilePresent = defineCheck({
  id: "lockfile-present",
  version: "1.0.0",
  title: "Lockfile present",
  category: "supply-chain",
  axis: "care",
  determinism: "deterministic",
  weight: 1,
  spec: checkSpecUrl("lockfile-present"),
  rationale:
    "A lockfile pins the transitive tree, so what installs today is what was reviewed. Without one, a sub-dependency compromised an hour ago is what a fresh install silently picks up, and no direct dependency changed.",
  async run(ctx): Promise<CheckResult> {
    const manifest = await readManifest(ctx.source, ["package.json"]);
    const deps = manifest?.data?.["dependencies"];
    const count = deps && typeof deps === "object" ? Object.keys(deps).length : 0;
    if (count === 0) return { status: "neutral", summary: "No dependencies to lock." };

    const candidates = [
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "bun.lockb",
      "uv.lock",
      "poetry.lock",
      "requirements.txt",
    ];
    for (const path of candidates) {
      if (await ctx.source.exists(path)) {
        return {
          status: "pass",
          summary: `Lockfile present (${path}).`,
          evidence: [{ type: "file", path }],
        };
      }
    }
    return {
      status: "warn",
      summary: `${count} dependencies declared with no lockfile.`,
      detail:
        "Without one, the dependency tree resolved at install time may differ from the tree that was evaluated.",
      remediation: "Commit your package manager's lockfile.",
    };
  },
});

export const SUPPLY_CHAIN_CHECKS = [noInstallScripts, depsPinned, lockfilePresent];
