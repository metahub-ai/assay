#!/usr/bin/env node
/**
 * `assay` — run the framework against a local artifact.
 *
 * This exists to make one specific promise checkable rather than
 * rhetorical: the verdict you get here is produced by the same checks,
 * the same scorer, and the same `SourceReader` interface a hosted
 * evaluation uses. A publisher who disagrees with a registry's score
 * can run this and see exactly which check disagreed and why.
 *
 * Deliberately offline by default. Network, model, and sandbox access
 * are capabilities a check must declare, and the CLI grants none of
 * them unless asked — so `assay run` is safe to point at code you have
 * not read, and the checks that could not run are reported as reduced
 * coverage rather than silently skipped.
 */
import { access, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve as resolvePath } from "node:path";
import { readEnvState, renderSuggestions, suggestNextSteps } from "./guidance.js";
import { loadConfig, parseConfig, type AssayConfig } from "./config.js";
import { diffReports, toSarif } from "./formats.js";
import { createBehavioralCheck } from "./checks/behavioral.js";
import { createNetClient } from "./net.js";
import {
  hasAmbientIdentity,
  KeylessDuplicateError,
  rekorLogIndex,
  signKeyless,
  verifyKeyless,
  type SigstoreBundle,
} from "./keyless.js";
import { localRuntime, podmanAvailable, resolveLlmProvider, resolveSandbox } from "./providers.js";
import {
  FileTranscriptSink,
  loadTranscript,
  replayTranscript,
  type ReplayOutcome,
} from "./transcripts.js";
import { generateKeyPair, signReport, verifyReport } from "./attest.js";
import { CheckRegistry } from "./check.js";
import type { CheckDefinition } from "./check.js";
import { DEFAULT_CHECKS } from "./checks/index.js";
import { resolveSuite, DEFAULT_SUITE_ID } from "./suites.js";
import { loadPlugins, type PluginFile, type ExternalProbe } from "./plugins.js";
import { digestTree } from "./digest.js";
import { runAssay } from "./run.js";
import { DirectorySource, RUNTIME_IGNORE } from "./sources/directory.js";
import { readIdentity } from "./checks/integrity.js";
import type { CheckContext } from "./check.js";
import { findAgentMarkdown } from "./checks/docs-resolution.js";
import { parseFrontmatter, parseList } from "./checks/manifest.js";
import {
  applyStoredConfig,
  behavioralWanted,
  configIsPrivate,
  configPath as credentialFile,
  decideBehavioral,
  loadStoredConfig,
  type BehavioralMode,
  type StoredConfig,
} from "./credentials.js";
import { isInteractive } from "./prompt.js";
import { createCaseCache } from "./case-cache.js";
import { renderReport } from "./render.js";
import { runSetup } from "./setup.js";
import { createTheme, statusGlyph, wrapText, Spinner, type Theme } from "./term.js";
import { materialize, parseTarget, TargetError, type Materialized } from "./target.js";
import { ASSAY_HOME, ASSAY_VERSION } from "./version.js";
import type {
  AssayReport,
  ArtifactKind,
  CheckReport,
  RunEnvironment,
  ScanContext,
  SubjectSource,
} from "./types.js";
import type { LlmProvider } from "./ports.js";

interface Args {
  path: string;
  kind?: ArtifactKind;
  json: boolean;
  quiet: boolean;
  /** Suite id from `--suite`. Undefined means "not set on the CLI"; the
   *  effective suite is then the config's, else the built-in default. */
  suite?: string;
  help: boolean;
  sarif: boolean;
  config?: string;
  noConfig: boolean;
  /**
   * Tri-state, and it has to be.
   *
   * `true` = `--behavioral`, `false` = `--no-behavioral`, `undefined` =
   * neither was typed. A plain boolean cannot tell "the user said no"
   * apart from "the user said nothing", and those now mean opposite
   * things on a configured, interactive machine.
   */
  behavioral?: boolean;
  net: boolean;
  provider?: string;
  sandbox?: string;
  transcripts?: string;
  cases?: number;
  repeat?: number;
  uplift: boolean;
  noUplift: boolean;
  noCache: boolean;
  minScore?: number;
  allowedHosts?: string[];
}

const KINDS = ["skill", "mcp", "agent", "plugin"] as const;

/**
 * `--kind` was cast straight to `ArtifactKind`, so `--kind banana`
 * produced a plausible-looking report — a real header, a real axis
 * table, advice to try `--net` or `--behavioral` that could not
 * possibly help — and exit 0, so CI passed.
 */
function validKind(v: string | undefined): ArtifactKind {
  if (v && (KINDS as readonly string[]).includes(v)) return v as ArtifactKind;
  throw new Error(`unknown kind: ${v ?? "(missing)"}. Expected one of: ${KINDS.join(", ")}`);
}

/** A 0..100 threshold. */
function score0to100(v: string | undefined): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || n > 100) {
    throw new Error(`--min-score needs a number from 0 to 100, got: ${v ?? "(missing)"}`);
  }
  return n;
}

/** A count flag that must be a positive integer. */
function positiveInt(v: string | undefined, flag: string): number {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`${flag} needs a positive whole number, got: ${v ?? "(missing)"}`);
  }
  return n;
}

/**
 * Every flag `run` accepts, for the "did you mean" on a typo.
 *
 * Worth the maintenance because of one flag in particular:
 * `--no-behavioral` turns off something that now costs money and time by
 * default, so `--nobehavioral` silently doing nothing would be the
 * expensive kind of typo. The generic "unknown flag" already stops it;
 * this makes the message name the fix.
 */
const RUN_FLAGS = [
  "help",
  "json",
  "quiet",
  "sarif",
  "no-config",
  "behavioral",
  "no-behavioral",
  "net",
  "no-cache",
  "provider",
  "sandbox",
  "transcripts",
  "cases",
  "repeat",
  "uplift",
  "no-uplift",
  "min-score",
  "config",
  "kind",
  "suite",
] as const;

/**
 * The nearest known flag to a typo, or nothing.
 *
 * Punctuation-insensitive first, because that is how these are actually
 * mistyped: `--nobehavioral` and `--minscore` are one dash away from
 * real flags, and a prefix match cannot see it.
 */
function nearestFlag(name: string, known: readonly string[]): string | undefined {
  const norm = (s: string) => s.replace(/[^a-z0-9]/gi, "").toLowerCase();
  const n = norm(name);
  return (
    known.find((k) => norm(k) === n) ??
    known.find((k) => k.startsWith(name.slice(0, 3)) || name.startsWith(k))
  );
}

function unknownFlag(a: string, known: readonly string[]): Error {
  const name = a.replace(/^--?/, "").split("=")[0]!;
  const near = nearestFlag(name, known);
  return new Error(`unknown flag: ${a}${near ? `. Did you mean --${near}?` : ""}`);
}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = {
    path: ".",
    json: false,
    quiet: false,
    help: false,
    sarif: false,
    noConfig: false,
    net: false,
    noCache: false,
    uplift: false,
    noUplift: false,
  };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--help" || a === "-h") args.help = true;
    else if (a === "--json") args.json = true;
    else if (a === "--quiet" || a === "-q") args.quiet = true;
    else if (a === "--sarif") args.sarif = true;
    else if (a === "--no-config") args.noConfig = true;
    // `--no-behavioral` is sticky in either order: a command line
    // carrying both flags resolves to OFF regardless of which came last,
    // because the only safe reading of a contradiction is the one that
    // does not spend money or execute the artifact.
    else if (a === "--behavioral") args.behavioral = args.behavioral === false ? false : true;
    else if (a === "--no-behavioral") args.behavioral = false;
    else if (a === "--net") args.net = true;
    else if (a === "--no-cache") args.noCache = true;
    else if (a === "--provider") args.provider = argv[++i];
    else if (a === "--sandbox") args.sandbox = argv[++i];
    else if (a === "--transcripts") args.transcripts = argv[++i];
    // `Number()` with no validation: `--repeat abc` became NaN, which
    // made the sampled-case array empty, which made the run report
    // "No behavioral test cases were available" — after paying for a
    // sandbox.
    else if (a === "--cases") args.cases = positiveInt(argv[++i], "--cases");
    else if (a === "--repeat") args.repeat = positiveInt(argv[++i], "--repeat");
    else if (a === "--uplift") args.uplift = true;
    else if (a === "--no-uplift") args.noUplift = true;
    else if (a === "--allowed-hosts")
      args.allowedHosts = (argv[++i] ?? "")
        .split(",")
        .map((h) => h.trim())
        .filter(Boolean);
    // The most obvious CI flag in the tool, and it was config-file-only:
    // gating a pipeline on a score meant committing an assay.config.json.
    else if (a === "--min-score") args.minScore = score0to100(argv[++i]);
    else if (a.startsWith("--min-score=")) args.minScore = score0to100(a.slice(12));
    else if (a === "--config") args.config = argv[++i];
    else if (a.startsWith("--config=")) args.config = a.slice(9);
    else if (a === "--kind") args.kind = validKind(argv[++i]);
    else if (a.startsWith("--kind=")) args.kind = validKind(a.slice(7));
    else if (a === "--suite") args.suite = argv[++i] ?? args.suite;
    else if (a.startsWith("--suite=")) args.suite = a.slice(8);
    else if (a.startsWith("--")) throw unknownFlag(a, RUN_FLAGS);
    // A single dash is a flag too. `-j` for `--json` used to be taken as
    // a path and reported as "No directory at ./-j", which sends the
    // reader looking at the filesystem for a typo that is in the flag.
    else if (/^-[^-]/.test(a)) throw new Error(`unknown flag: ${a}`);
    else positional.push(a);
  }
  if (positional.length > 0) args.path = positional[0]!;
  // Two machine formats at once. One used to silently win, so a CI job
  // asking for both got a report in the format it was not parsing.
  if (args.json && args.sarif) {
    throw new Error("--json and --sarif both write the report to stdout. Pick one.");
  }
  return args;
}

const USAGE = `assay — evaluate an AI artifact

USAGE
  assay setup                       configure the sandbox and model (once)
  assay doctor                      what can I run right now?
  assay init    [path]              scaffold config + example eval cases
  assay run     <target> [options]  evaluate an artifact
  assay verify  <report.json>       check a report's score, digest, and signature
  assay diff    <before> <after>    what changed between two reports
  assay replay  <report.json>       re-judge recorded transcripts and compare
  assay list                        list the checks in the default suite
  assay explain <check-id>          why a check exists and what it looks at
  assay sign    <report.json>       sign a report with an ed25519 key
  assay keygen                      generate a signing keypair
  assay --version                   print the version and exit

TARGETS
  .                              a local directory
  ./packages/my-skill            an existing local path always wins
  owner/repo                     GitHub shorthand
  owner/repo#v1.2.0              pinned to a tag, branch, or commit (@ also works)
  owner/repo//skills/pdf         a subdirectory — note the DOUBLE slash
  ghe.example.com/owner/repo     another host (a dot means it is a host)
  https://github.com/owner/repo
  https://github.com/o/r/tree/main/sub    straight from the browser URL
  npm:package@2.1.0              from the registry, integrity checked
  npm:@scope/package

  Note the double slash: it separates the repository from a path inside
  it. A single slash cannot, because a git server may legitimately host
  a repo at /a.git/b — so owner/repo/skills/pdf is rejected with the
  correction rather than guessed at.

RUN OPTIONS
  --kind <kind>   skill | mcp | agent | plugin (auto-detected if omitted)
  --json          emit the full report as JSON on stdout
  --quiet, -q     only print findings (failures and warnings)
  --min-score <n> fail the run when the overall score is below n
  --sarif         emit SARIF 2.1.0 for GitHub code scanning
  --suite <id>    suite identifier recorded in the report
  --net           allow the advisory lookup (api.osv.dev). No model, no cost.
  --config <file> use this config instead of searching for one
  --no-config     ignore any assay.config.json

BEHAVIORAL OPTIONS (on by default once configured — costs money and time)
  Runs the artifact and judges what it does. After \`assay setup\` this
  happens on a plain \`assay run\`, because configuring a sandbox and a
  model IS the opt-in. Two exceptions, both deliberate:
    · without a terminal (CI, a pipe, no TTY) it stays opt-in, so a
      pipeline never starts billing per commit on inherited credentials
    · a blocking safety failure vetoes it, so an artifact that was just
      flagged as malicious is not then executed

  --behavioral         force it on, including in CI
  --no-behavioral      skip it, however this machine is configured
  --provider <name>    anthropic | openai | openrouter | local
  --sandbox <name>     docker | podman (local, free) | e2b (cloud, needs a key)
  --transcripts <dir>  record transcripts here so the verdict can be replayed
  --cases <n>          how many cases to synthesize (default 5)
  --repeat <k>         run each case k times and average (default 1).
  --uplift             also run each skill case with NO skill and report
                       the delta — does the skill beat the bare model?
                       (skill-only, roughly doubles normal-case cost). ON
                       by default for skills, since it feeds the scorecard's
                       effectiveness read and IS the Skill Lift number.
                       The driver is a model, so one sample per case is
                       noisy — k=3 roughly halves the interval, at k× cost
  --no-uplift          skip the uplift/Skill-Lift pass for a skill (halves
                       the cost; the scorecard then omits the lift line)
  --allowed-hosts <h>  comma-separated hosts the artifact legitimately
                       contacts; anything else it touches at runtime is
                       reported as undeclared
  --no-cache           re-synthesize test cases instead of reusing the
                       cached set for this artifact digest

REPLAY OPTIONS
  --transcripts <dir>  directory of stored transcripts (required)
  --provider <name>    anthropic | openai | openrouter | local
                       auto-detected when exactly one is configured

VERIFY OPTIONS
  --key <file>      public key (SPKI PEM) the report should be signed by
  --artifact <dir>  recompute the subject digest from this directory
  --require-signature  treat an unsigned report as a failure

SIGN OPTIONS
  --key <file>      private key (PKCS#8 PEM)
  --pub <file>      matching public key (SPKI PEM)
  --out <file>      write the signed report here (default: in place)
  --keyless         sign via Sigstore instead — no key to hold or leak.
                    Needs an OIDC identity: ambient in CI (id-token: write),
                    a browser flow locally. Writes <report>.sigstore.json

VERIFY OPTIONS (keyless)
  --bundle <file>   Sigstore bundle to verify against
  --identity <uri>  expected signer identity; without it a valid signature
                    only proves SOMEONE signed, which is not a guarantee
  --issuer <url>    expected OIDC issuer

EXIT CODES
  0  no blocking failure / verification passed
  1  a blocking check failed / verification failed
  2  the command itself could not complete

Until \`assay setup\` runs, \`assay run\` is offline: no network, model, or
sandbox access is granted, so checks needing those are reported as
reduced coverage rather than silently dropped. Afterwards the
behavioral tier joins in on an interactive terminal — see BEHAVIORAL
OPTIONS, and \`assay doctor\` for what this machine will actually do.
`;

/**
 * The sections of USAGE each command needs, so `assay sign --help`
 * answers about signing instead of reprinting ninety lines.
 *
 * Slicing the one USAGE string rather than maintaining a second copy:
 * two hand-written help texts drift, and the drift is invisible until a
 * user follows the stale one.
 */
const HELP_SECTIONS: Record<string, readonly string[]> = {
  run: ["USAGE", "TARGETS", "RUN OPTIONS", "BEHAVIORAL OPTIONS", "EXIT CODES"],
  verify: ["USAGE", "VERIFY OPTIONS", "VERIFY OPTIONS (keyless)", "EXIT CODES"],
  sign: ["USAGE", "SIGN OPTIONS", "EXIT CODES"],
  replay: ["USAGE", "REPLAY OPTIONS", "EXIT CODES"],
  diff: ["USAGE", "EXIT CODES"],
  keygen: ["USAGE", "SIGN OPTIONS"],
  list: ["USAGE"],
  explain: ["USAGE"],
  init: ["USAGE"],
  doctor: ["USAGE"],
  setup: ["USAGE"],
};

/** One-line statements of what each command is for. */
const HELP_SUMMARY: Record<string, string> = {
  run: "Evaluate an artifact and print a scored report.",
  verify: "Recheck a report's score, subject digest, and signature.",
  sign: "Sign a report so its origin can be established.",
  keygen: "Generate an ed25519 signing keypair.",
  replay: "Re-judge recorded transcripts and compare against the report.",
  diff: "Compare two reports and identify regressions.",
  list: "List the checks in the default suite.",
  explain: "Explain one check: what it looks at, and why.",
  init: "Scaffold assay.config.json and an example eval file.",
  doctor: "Report what can and cannot run in this environment.",
  setup: "Configure a sandbox and a model, interactively.",
};

/**
 * Print help for one command by extracting the relevant blocks of
 * USAGE. Headings are matched at the start of a line and run to the
 * next blank-line-separated heading.
 */
export function helpForCommand(command: string): number {
  const wanted = HELP_SECTIONS[command];
  if (!wanted) {
    write(USAGE);
    return 0;
  }

  const lines = USAGE.split("\n");
  const isHeading = (l: string) => /^[A-Z][A-Z ]+(\([^)]*\))?$/.test(l);

  const blocks = new Map<string, string[]>();
  let current: string | null = null;
  for (const line of lines) {
    if (isHeading(line)) {
      current = line;
      blocks.set(current, []);
      continue;
    }
    if (current) blocks.get(current)!.push(line);
  }

  const t = ui();
  write(`\n  ${t.heading(`assay ${command}`)}\n`);
  const summary = HELP_SUMMARY[command];
  if (summary) write(`  ${summary}\n`);

  for (const heading of wanted) {
    // Headings carry a parenthetical gloss that changes as the product
    // does — "BEHAVIORAL OPTIONS (opt-in …)" became "(on by default
    // …)". Keying on the exact line meant `assay run --help` silently
    // omitted the entire behavioral section, and would have gone on
    // omitting it now that `--no-behavioral` lives there. Match the
    // heading, not its subtitle.
    const key = blocks.has(heading)
      ? heading
      : [...blocks.keys()].find((k) => k.startsWith(`${heading} (`));
    const body = key ? blocks.get(key) : undefined;
    if (!body) continue;
    // The full USAGE block is right for `run`, but for a single command
    // the synopsis list should show only that command's line.
    const kept =
      heading === "USAGE"
        ? body.filter((l) => new RegExp(`^\\s+assay ${command}\\b`).test(l))
        : body;
    const trimmed = [...kept];
    while (trimmed.length && trimmed[trimmed.length - 1]!.trim() === "") trimmed.pop();
    if (!trimmed.length) continue;
    write(`\n  ${t.muted(heading === "USAGE" ? "SYNOPSIS" : (key ?? heading))}\n`);
    for (const l of trimmed) write(`  ${l}\n`);
  }
  write(`\n  ${t.muted("assay --help")} for the full reference.\n\n`);
  return 0;
}

/**
 * Guess the artifact kind from its shape.
 *
 * Ordering matters and mirrors the detection precedence used in
 * production: an explicit manifest beats a convention file, and a
 * SKILL.md beats a package.json because plenty of skills ship one.
 */
/**
 * What the report records about the run that produced it.
 *
 * Extracted so it can be tested directly: two of these fields were
 * declared in `RunEnvironment`, documented as load-bearing, and never
 * populated, and nothing failed when they were missing.
 *
 *  - `sandbox` — a behavioral report said an artifact had been RUN and
 *    not where. Podman on a laptop and an E2B cloud sandbox differ in
 *    kernel, egress and resource limits; two reports on one digest can
 *    legitimately disagree because of it.
 *  - `models` — the judge was recorded as the literal string
 *    "(adapter default)". Swapping the judge changes grades on
 *    identical behavior, and `replay` could re-grade with a different
 *    model than the run used without saying so. Both roles are pinned:
 *    the driver stands in for the end user's client, the judge grades
 *    the transcript.
 */
/**
 * The report's subject.source — recording WHAT was graded in a form that
 * pins it, not the ephemeral tmpdir it was cloned into.
 *
 * A git target records its resolved commit (`git rev-parse HEAD`, so a
 * moving ref becomes a fixed point); an npm target records its registry
 * integrity as a tarball hash. This closes the audit's reproducibility
 * gap: the resolved commit and integrity were computed and rendered to
 * the terminal, then dropped from the report — leaving `directory:
 * /tmp/...`, which reproduces nothing.
 */
export function subjectSource(fetched: Materialized, artifactPath: string): SubjectSource {
  const p = fetched.provenance;
  if (p.kind === "git" && p.url && p.resolved) {
    return { type: "git", url: p.url, commit: p.resolved };
  }
  // An npm/registry integrity is base64 sha512 ("sha512-…"); the tarball
  // variant's field is a hex sha256, so forcing it there would mislabel
  // the hash. Kept as directory until the schema carries the registry
  // integrity string verbatim (a follow-up, tracked in COVERAGE.md).
  return { type: "directory", path: artifactPath };
}

export function buildEnvironment(
  capabilities: { sandbox?: { name: string; image?: string }; llm?: LlmProvider },
  scanContext: ScanContext,
): RunEnvironment {
  return {
    runner: `assay/${ASSAY_VERSION}`,
    // Recorded so a reader can see what the run could observe, and that
    // a lower score may reflect the scan rather than the artifact.
    scanContext,
    ...(capabilities.sandbox ? { sandbox: { provider: capabilities.sandbox.name } } : {}),
    ...(capabilities.llm
      ? {
          models: {
            judge: {
              provider: capabilities.llm.name,
              model: capabilities.llm.modelFor?.("judge") ?? "(unreported)",
            },
            driver: {
              provider: capabilities.llm.name,
              model: capabilities.llm.modelFor?.("driver") ?? "(unreported)",
            },
            // Synthesis pins the model that WRITES the test cases. It was
            // absent, so a report could not show that its cases were
            // authored by the same model that then drove them — which is
            // exactly the kind of thing a reproducibility claim rests on.
            synthesis: {
              provider: capabilities.llm.name,
              model:
                capabilities.llm.modelFor?.("synthesis") ??
                capabilities.llm.modelFor?.("driver") ??
                "(unreported)",
            },
          },
        }
      : {}),
  };
}

export async function detectKind(source: DirectorySource): Promise<ArtifactKind | null> {
  if (await source.exists("SKILL.md")) return "skill";
  for (const p of [".claude-plugin/plugin.json", "plugin.json"]) {
    if (await source.exists(p)) return "plugin";
  }
  if (await source.exists("agent.json")) return "agent";

  // `server.json` — the manifest the official MCP registry publishes
  // against. Detection recognised the SDK dependency but not the
  // protocol's own manifest, so a server following the registry's
  // documented layout answered "could not tell what kind of artifact
  // this is".
  const serverRaw = await source.readFile("server.json");
  if (serverRaw) {
    try {
      const s = JSON.parse(serverRaw) as Record<string, unknown>;
      if (typeof s["name"] === "string" && ("packages" in s || "remotes" in s || "$schema" in s)) {
        return "mcp";
      }
    } catch {
      /* an unparseable manifest tells us nothing about the kind */
    }
  }

  const pkgRaw = await source.readFile("package.json");
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as Record<string, unknown>;
      const deps = {
        ...((pkg["dependencies"] as Record<string, string>) ?? {}),
        ...((pkg["devDependencies"] as Record<string, string>) ?? {}),
      };
      if ("@modelcontextprotocol/sdk" in deps || "mcp" in pkg) return "mcp";
      // A package whose own name says what it is. Plenty of servers
      // implement the protocol directly over stdio rather than taking
      // the SDK as a dependency, and those were invisible here.
      const name = typeof pkg["name"] === "string" ? pkg["name"] : "";
      const keywords = Array.isArray(pkg["keywords"]) ? (pkg["keywords"] as string[]) : [];
      if (/(^|[-@/])mcp([-/]|$)/.test(name) || keywords.some((k) => /^mcp$/i.test(k))) {
        return "mcp";
      }
    } catch {
      /* an unparseable manifest tells us nothing about the kind */
    }
  }

  // Python MCP servers. Detection previously looked only at
  // package.json, so pointing Assay at a reference server like
  // `modelcontextprotocol/servers/src/fetch` produced "could not
  // determine the artifact kind" — for an artifact published by the
  // people who define the protocol.
  const pyproject = await source.readFile("pyproject.toml");
  if (
    pyproject &&
    /^\s*(name\s*=\s*["'][^"']*mcp|dependencies\s*=|.*"mcp[>=~\]])/m.test(pyproject)
  ) {
    if (/\bmcp\b/.test(pyproject)) return "mcp";
  }

  // Prompt-based agents, LAST — after every manifest-bearing kind, so a
  // plugin with an `agents/` directory is still a plugin and a skill is
  // still a skill.
  //
  // This shares `findAgentMarkdown` with `agent-shape-declared` rather
  // than reimplementing the convention. The two disagreeing once
  // already made every real prompt-based agent fail a blocking check;
  // here the disagreement was quieter but the same shape — the check
  // could resolve `reviewer.md` perfectly well, and detection could
  // not, so a real agent published on its own answered "could not tell
  // what kind of artifact this is" unless you passed `--kind agent`.
  if (await findAgentMarkdown(source)) return "agent";

  return null;
}

/**
 * Write to stdout.
 *
 * A thin wrapper rather than direct calls so every command goes through
 * one place, and so `main()` stays usable as a library entry point —
 * an earlier version buffered here and flushed only on process exit,
 * which silently produced no output for anyone calling the function
 * directly.
 */
function write(s: string): void {
  process.stdout.write(s);
}

/**
 * Set the exit code without calling `process.exit()`.
 *
 * `process.exit()` does not wait for a pending stdout write to drain
 * when stdout is a pipe, which truncates large `--json` output for
 * anyone doing `assay run --json | jq`. Setting `exitCode` and letting
 * the event loop finish naturally cannot lose bytes.
 */
export function finish(code: number): void {
  process.exitCode = code;
}

/** Blocking failures, which are what the exit code reflects. */
export function blockingFailures(report: AssayReport): CheckReport[] {
  return report.results.filter((r) => r.status === "fail" && r.blocking === true);
}

export async function main(argv: readonly string[]): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    // One line, not the whole manual. Reprinting 90 lines of usage
    // scrolled the actual error off the screen.
    const t = ui();
    process.stderr.write(
      `${t.fail("assay:")} ${(err as Error).message}\n` +
        `  Run ${t.code("assay --help")} for usage.\n`,
    );
    return 2;
  }
  if (args.help) {
    write(USAGE);
    return 0;
  }

  const theme = createTheme();
  const startedAt = Date.now();

  // `cli()` already applied the stored config for every command. It is
  // repeated here because `main()` is exported and called directly by
  // tests and by library consumers, and `applyStoredConfig` never
  // overwrites an existing variable, so applying it twice is a no-op.
  // The value is kept rather than discarded: it also carries the
  // behavioral-by-default preference, which is a stated choice and not
  // something that can be recovered from `process.env`.
  const stored = await loadStoredConfig();
  applyStoredConfig(stored);

  // A local file, not a directory.
  //
  // `existsLocally` is a directory test, so an existing FILE fell
  // through to remote-shorthand parsing: `assay run my-skill/SKILL.md`
  // — what tab-completion gives you — parsed as `owner/repo`, tried to
  // clone `github.com/my-skill/SKILL.md`, and reported "it is private,
  // or the credentials are missing" about the user's own file.
  const asFile = await stat(args.path).catch(() => null);
  if (asFile?.isFile()) {
    const dir = dirname(resolvePath(args.path));
    process.stderr.write(
      `${theme.fail("assay:")} ${args.path} is a file. Assay evaluates the whole artifact directory.\n` +
        `  Try:  assay run ${dir === process.cwd() ? "." : dir}\n`,
    );
    return 2;
  }

  // Resolve whatever was typed: a path, a repo, a URL, an npm package.
  let fetched: Materialized;
  try {
    const target = parseTarget(args.path, await isDirectory(args.path));
    if (target.kind === "local") {
      fetched = await materialize(target);
    } else {
      // Cloning is the slowest thing that happens before any output, so
      // it is the one place a progress line genuinely earns its keep.
      const spinner = new Spinner(theme).start(`Fetching ${target.display}`);
      try {
        fetched = await materialize(target, (m) => spinner.update(m));
      } finally {
        spinner.stop();
      }
    }
  } catch (err) {
    if (err instanceof TargetError) {
      process.stderr.write(`${theme.fail("assay:")} ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  try {
    return await evaluate(args, fetched, theme, startedAt, stored);
  } finally {
    // A temp clone must not survive the process, including on a throw.
    await fetched.cleanup();
  }
}

/**
 * Do not execute an artifact the static checks have just condemned.
 *
 * `guidance.ts` already refuses to SUGGEST running a confirmed malicious
 * artifact. The case that produced that rule was one whose confirmed
 * findings included `curl … | bash` to a hardcoded IP, and whose first
 * recommended action was "run it in a container and see what it does".
 * Turning the behavioral tier on by default gives the tool a way to go
 * one worse — to actually do it, with nothing on screen offering to
 * decline — so the same rule has to hold at the point of execution and
 * not only at the point of advice.
 *
 * `runAssay` orders sandbox checks after every offline one precisely so
 * this verdict is already in hand when the question is asked.
 *
 * `--behavioral` is exempt, and that is deliberate. Someone who names
 * the flag has asked to watch a suspicious artifact run, in a sandbox,
 * which is what the sandbox is for; this must not become a way to stop a
 * security researcher from doing their job. The veto covers the case
 * where running it was OUR idea.
 */
export function safetyVeto(
  mode: BehavioralMode,
  check: { id: string; needs?: readonly string[] },
  soFar: readonly CheckReport[],
): string | null {
  if (mode !== "default") return null;
  if (!(check.needs ?? []).includes("sandbox")) return null;
  const blocked = soFar.some(
    (r) => r.status === "fail" && r.blocking === true && r.axis === "safety",
  );
  if (!blocked) return null;
  return (
    "Not run — a blocking safety check failed, and behavioral evaluation was not " +
    "explicitly requested. Assay will not execute an artifact it has just flagged. " +
    "Re-run with --behavioral to override."
  );
}

/**
 * The line that tells you a paid operation just started on its own.
 *
 * Nobody typed a flag for this run, and it costs model tokens and adds
 * minutes. Something that expensive starting unprompted has to announce
 * itself AND say how to stop it in the same breath — otherwise the first
 * experience of the new default is an unexplained three-minute wait, and
 * the fix for that is the reason people stop trusting a tool's defaults.
 */
export function defaultOnNote(theme: Theme): string {
  return (
    `  ${theme.muted("note: running by default because `assay setup` configured a sandbox")}\n` +
    `  ${theme.muted("      and a model. It spends model tokens and minutes —")}\n` +
    `  ${theme.muted("      `--no-behavioral` skips it, and `assay setup` can turn it off.")}\n`
  );
}

/**
 * What `assay doctor` says under the sandbox and model ticks.
 *
 * Extracted because it is the sentence that was wrong: two green ticks
 * followed by "ready when you ask for it — the behavioral tier is
 * opt-in" and a two-flag command line is the exact complaint that
 * changed the default. Doctor's whole job is to be believed, so what it
 * promises here has to be what `run` will do.
 */
export function behavioralReadyAdvice(opts: { ready: boolean; optedOut: boolean }): string {
  if (!opts.ready) {
    return "\n    → run `assay setup` to configure both. Static checks work regardless.\n\n";
  }
  if (opts.optedOut) {
    return (
      "\n    → configured, but you turned the default off — it is opt-in here:\n" +
      "        assay run . --behavioral      run it once\n" +
      "        assay setup                   turn the default back on\n\n"
    );
  }
  return (
    "\n    → behavioral runs by DEFAULT — a plain `assay run .` includes it.\n" +
    "        assay run . --no-behavioral   skip it for one run\n" +
    "      Without a terminal (CI, a pipe) it stays opt-in: pass --behavioral\n" +
    "      there, so a pipeline never starts billing on inherited credentials.\n\n"
  );
}

/**
 * Facts about the artifact that change how the behavioral harness must
 * drive it.
 *
 * Both were already computable and both were thrown away: the skill's
 * declared tool scope is parsed by two separate checks, and
 * `findAgentMarkdown` is called during kind detection.
 */
async function resolveBehavioralScope(
  source: DirectorySource,
  kind: ArtifactKind,
): Promise<{ allowedTools?: string[]; promptBased?: boolean }> {
  if (kind === "skill") {
    const raw = await source.readFile("SKILL.md");
    if (!raw) return {};
    const fm = parseFrontmatter(raw);
    const field = fm.fields["allowed-tools"] ?? fm.fields["allowedTools"];
    // Tri-state, and the empty case is the one that used to be lost: a
    // FIELD that is present-but-empty ("needs nothing") must reach the
    // harness as [] so the run is actually restricted to nothing, not
    // silently handed the permissive default. Absent → permissive.
    if (field === undefined) return {};
    return { allowedTools: parseList(field) };
  }
  if (kind === "agent") {
    // An agent with no executable entry point is a system prompt plus a
    // tool scope, and runs the same loop a skill does — including its
    // declared `tools:`, which the harness must ENFORCE, not just record.
    const hasManifest = await source.exists("agent.json");
    const md = !hasManifest ? await findAgentMarkdown(source) : null;
    if (md) {
      const raw = (await source.readFile(md)) ?? "";
      const field = parseFrontmatter(raw).fields["tools"];
      return field === undefined
        ? { promptBased: true }
        : { promptBased: true, allowedTools: parseList(field) };
    }
  }
  return {};
}

async function isDirectory(path: string): Promise<boolean> {
  const { stat } = await import("node:fs/promises");
  return stat(path)
    .then((s) => s.isDirectory())
    .catch(() => false);
}

async function evaluate(
  args: Args,
  fetched: Materialized,
  theme: ReturnType<typeof createTheme>,
  startedAt: number,
  stored: StoredConfig | null,
): Promise<number> {
  const artifactPath = fetched.dir;
  // RUNTIME_IGNORE, not the default. The default list drops `dist/`,
  // which is right for linting prose and catastrophic here: a package
  // published to npm ships `dist/` and nothing else, so the safety
  // checks were handed a package.json, a README, and no code. Identical
  // malicious bytes scored 90.7 under `dist/` and 30.1 under `src/` —
  // and the dominant MCP distribution form is the one that scored 90.7.
  // Checks that would otherwise double-report a generated copy skip it
  // themselves when a source tree exists.
  const source = new DirectorySource(artifactPath, { ignore: RUNTIME_IGNORE });
  let tree;
  try {
    tree = await source.listTree();
  } catch {
    process.stderr.write(`assay: cannot read ${artifactPath}\n`);
    return 2;
  }
  if (tree.length === 0) {
    process.stderr.write(`assay: ${args.path} is empty or unreadable\n`);
    return 2;
  }

  // `--kind` wins, then a registry's stated kind, then detection. A
  // catalog entry is a fact about what the artifact IS; detection is a
  // heuristic over file layout that can be fooled by a repository
  // holding several kinds at once.
  const kind =
    args.kind ??
    ((fetched.registryKind as ArtifactKind | undefined) || undefined) ??
    (await detectKind(source));
  if (!kind) {
    process.stderr.write(
      // Naming what was actually looked for, rather than a summary that
      // had drifted from the code. A user staring at this needs to know
      // which file would have made it work.
      `${theme.fail("assay:")} could not tell what kind of artifact this is.\n` +
        `  Looked in ${artifactPath} for:\n` +
        `    skill   SKILL.md\n` +
        `    plugin  .claude-plugin/plugin.json, plugin.json\n` +
        `    agent   agent.json, or a markdown file with agent frontmatter\n` +
        `    mcp     server.json, or a package.json naming the MCP SDK,\n` +
        `            or a pyproject.toml declaring mcp\n\n` +
        `  Name it explicitly:  ${theme.code("--kind skill|mcp|agent|plugin")}\n`,
    );
    return 2;
  }

  // Policy is loaded by walking up from the artifact, so a monorepo can
  // set one at the root instead of beside every package.
  let policy: AssayConfig = {};
  let policyPath: string | null = null;
  if (!args.noConfig) {
    try {
      const loaded = args.config
        ? {
            config: parseConfig(await readFile(args.config, "utf8"), args.config),
            path: args.config,
          }
        : // For a LOCAL target the config is the user's own project
          // policy and walking up from the artifact is right. For a
          // REMOTE one, the tree belongs to the stranger being audited —
          // so searching it lets the subject supply the rules it is
          // graded by. Demonstrated: an artifact shipping
          // `{"disable": ["no-sensitive-files", ...]}` took itself from
          // 47.5 with a committed AWS key to 68.2 and exit 0.
          //
          // Remote runs therefore search from the invoking directory
          // instead, which is the user's own context. `--config` still
          // works and is explicit, which is the point.
          await loadConfig(fetched.provenance.kind === "local" ? artifactPath : process.cwd());
      policy = loaded.config;
      policyPath = loaded.path;

      if (fetched.provenance.kind !== "local") {
        // Say so if the artifact was carrying one, rather than ignoring
        // it silently — a publisher who wonders why their waiver did
        // nothing deserves an answer.
        const carried = await new DirectorySource(artifactPath).exists("assay.config.json");
        if (carried) {
          process.stderr.write(
            `  ${theme.warn("note:")} the fetched artifact ships its own assay.config.json.
` +
              `  It was NOT applied — a subject does not supply the policy that grades it.
` +
              `  Pass --config explicitly if you intend to use it.

`,
          );
        }
      }
    } catch (err) {
      // A malformed policy file is an error, never a silent fallback —
      // quietly ignoring it is how a team believes it has protection
      // it does not have.
      const e = err as NodeJS.ErrnoException;
      // A missing --config is a typo, not a parse failure, and deserves
      // to be named as one rather than surfacing a raw libuv string.
      process.stderr.write(
        e.code === "ENOENT" && args.config
          ? `${theme.fail("assay:")} no config file at ${args.config}\n`
          : `assay: ${e.message}\n`,
      );
      return 2;
    }
  }

  // Resolved once, before the checks are assembled, because two of
  // these determine how the harness will drive the artifact.
  const behavioralScope = await resolveBehavioralScope(source, kind);

  // Behavioral evaluation runs by DEFAULT once `assay setup` has
  // configured a sandbox and a model — but only in a terminal.
  //
  // It used to be opt-in unconditionally, which made the user say yes
  // twice: once to the wizard, and again with `--behavioral
  // --transcripts ./transcripts` on every single run. Configuring a
  // thing is consent to use it.
  //
  // The terminal check is the part that has to stay. Behavioral costs
  // model tokens and adds minutes per run; CI runs on every commit, and
  // a pipeline that inherits credentials somebody set once must not
  // quietly start billing for them. See `decideBehavioral`.
  const mode = decideBehavioral({
    flag: args.behavioral,
    interactive: isInteractive(),
    preference: stored?.behavioralByDefault,
  });
  let behavioral: BehavioralMode = mode;

  // Resolve the suite. A CLI `--suite` wins over a config `suite`, which
  // wins over the built-in default. The suite decides WHICH checks
  // compose the registry, and contributes a policy overlay (thresholds)
  // that sits BENEATH the user's own config — so `assay:strict` gates at
  // 85 unless the user's config or `--min-score` says otherwise.
  const suiteId = args.suite ?? policy.suite ?? DEFAULT_SUITE_ID;
  const suite = resolveSuite(suiteId);
  policy = { ...suite.policy, ...policy };
  let checks = [...suite.checks];

  // Community plugins: declarative checks + probes from JSON files named
  // in the config, resolved relative to it. A malformed plugin is a hard
  // error — a rule that cannot load must never be silently absent.
  let externalProbes: ExternalProbe[] = [];
  if (policy.plugins && policy.plugins.length > 0) {
    if (!policyPath) {
      throw new Error(`"plugins" requires a config file to resolve paths against.`);
    }
    const baseDir = dirname(resolvePath(policyPath));
    const files: PluginFile[] = [];
    for (const rel of policy.plugins) {
      const abs = resolvePath(baseDir, rel);
      try {
        files.push({ source: rel, json: await readFile(abs, "utf8") });
      } catch {
        throw new Error(`plugin not found: ${rel} (resolved to ${abs}).`);
      }
    }
    const loaded = loadPlugins(files);
    checks.push(...loaded.checks);
    externalProbes = loaded.probes;
    if (!args.json && !args.sarif) {
      for (const note of loaded.notes) write(theme.muted(`  ${note}\n`));
    }
  }

  const capabilities: NonNullable<Parameters<typeof runAssay>[0]["capabilities"]> = {
    now: Date.now,
  };
  let scanContext: {
    credentials: "anonymous";
    network: "none" | "allowlisted" | "open";
  } = { credentials: "anonymous", network: "none" };

  if (behavioralWanted(mode)) {
    // Whether it was ASKED for decides what a failure to resolve means.
    // `--behavioral` and no model is a user error worth exiting on;
    // default-on and no model just means this machine cannot do it, and
    // a plain `assay run` must not start failing because the container
    // runtime is not started this morning.
    const explicit = mode === "requested";
    try {
      const llm = (await resolveLlmProvider(args.provider)).provider;
      // The progress writer is passed so that fetching a sandbox client
      // is something the user watches happen, not something that
      // happens to them.
      const sandbox = await resolveSandbox(args.sandbox, (s) => write(theme.muted(s)));
      if (
        (sandbox.name === "podman" || sandbox.name === "docker") &&
        !(await podmanAvailable(undefined, sandbox.name))
      ) {
        // Installed but not answering is the common case, and it is a
        // different problem from not installed at all — usually a
        // machine or daemon that is not started.
        throw new Error(
          `${sandbox.name} is installed but not responding.\n` +
            `  Start it:      ${theme.code(sandbox.name === "docker" ? "open -a Docker" : "podman machine start")}\n` +
            `  Or use E2B:    ${theme.code("assay setup")} ${theme.muted("and pick the cloud sandbox")}`,
        );
      }
      capabilities.llm = llm;
      capabilities.sandbox = {
        name: sandbox.name,
        provision: (spec) => sandbox.provider.create(spec ?? {}),
      };
      checks.push(
        createBehavioralCheck({
          // A skill declares `allowed-tools` and two checks already
          // parse it — but the harness always received the same three
          // generic tools, so every skill was driven identically
          // regardless of the scope it asked for.
          ...(behavioralScope.allowedTools ? { allowedTools: behavioralScope.allowedTools } : {}),
          // `detectKind` resolves a prompt-based agent and then discarded
          // the fact, so the engine routed every one to install-and-exec
          // and judged it on "agent entry file not found; tried common
          // conventions" — failing an entire artifact shape for a defect
          // it cannot have.
          ...(behavioralScope.promptBased ? { promptBased: true } : {}),
          // The checks read `source`, which excludes build output. The
          // sandbox needs it — a published npm package IS its `dist/`.
          materializeSource: new DirectorySource(artifactPath, { ignore: RUNTIME_IGNORE }),
          // Keyed by artifact digest, so the same bytes always face the
          // same questions. Without this every run synthesized fresh
          // cases and two runs of one artifact were graded on different
          // exams — which moved the score and made `assay diff`
          // meaningless for the behavior axis.
          caseCache: createCaseCache({ enabled: !args.noCache }),
          ...(args.cases !== undefined ? { caseCount: args.cases } : {}),
          ...(args.repeat !== undefined ? { repeat: args.repeat } : {}),
          // Uplift is the with/without "Skill Lift" measurement and it
          // powers the effectiveness read on the scorecard, so it is ON
          // by default for skills — the one kind it applies to — unless
          // explicitly waived with --no-uplift. Other kinds keep it
          // opt-in via --uplift (where it is a no-op anyway).
          ...((kind === "skill" ? !args.noUplift : args.uplift) ? { uplift: true } : {}),
          ...(externalProbes.length > 0
            ? { extraProbes: externalProbes.filter((p) => p.kind === kind).map((p) => p.probe) }
            : {}),
          ...(args.transcripts ? { transcripts: new FileTranscriptSink(args.transcripts) } : {}),
          // Declared hosts reach the safety scan AND the runtime
          // ledger's undeclared-host diff. CLI flag wins over config;
          // previously this option existed and nothing could set it.
          ...((args.allowedHosts ?? policy.allowedHosts)
            ? { allowedHosts: args.allowedHosts ?? policy.allowedHosts }
            : {}),
        }),
      );
      // Recorded so a reader can see the run had network and a model,
      // and attribute the verdict accordingly.
      scanContext = { credentials: "anonymous", network: "open" };
      process.stderr.write(
        `  ${theme.accent("behavioral evaluation")} ${theme.muted(`· ${sandbox.name} sandbox · ${llm.name} · a few minutes`)}\n`,
      );
      if (mode === "default") process.stderr.write(defaultOnNote(theme));
      if (!args.transcripts) {
        // Without a transcript store the verdict is unreplayable, which
        // quietly drops the whole point of the `replayable` tier: a
        // grade nobody can re-derive is a grade people have to take on
        // trust. Worth one line of stderr.
        process.stderr.write(
          "  note: no --transcripts directory, so this verdict cannot be replayed later\n",
        );
      }
    } catch (err) {
      // Asked for by name: a failure is the answer to what was asked,
      // and exiting is right. Turned on by default: it is our idea, not
      // theirs, and taking down a run of offline checks over it would
      // make `assay run` less reliable than it was before this feature.
      if (explicit) {
        process.stderr.write(`assay: ${(err as Error).message}\n`);
        return 2;
      }
      behavioral = "unavailable";
      // Withdraw the capabilities rather than the check. `runAssay`
      // records a check it cannot satisfy as an explicit skip, which is
      // the honest report: the axis lost coverage, and the report says
      // why instead of silently omitting it.
      delete capabilities.llm;
      delete capabilities.sandbox;
      if (!args.json && !args.sarif && !args.quiet) {
        process.stderr.write(
          `  ${theme.muted(`note: behavioral evaluation skipped — ${(err as Error).message.split("\n")[0]}`)}\n`,
        );
      }
    }
  }

  // `--net` grants ONLY the advisory lookup: no model, no sandbox, no
  // cost. A behavioral run implies it, since it already reaches the
  // network for a model.
  //
  // Decided AFTER the block above rather than before it, so that a
  // behavioral tier which failed to come up leaves the run exactly as
  // offline as a plain `assay run` — granting network on the strength of
  // an intention that did not happen would put a request on the wire
  // that nobody asked for.
  if (args.net || capabilities.llm) {
    capabilities.net = createNetClient();
    if (scanContext.network === "none") {
      scanContext = { credentials: "anonymous", network: "allowlisted" };
    }
  }

  // NOT `source` — that one excludes build output, which is right for
  // linting and catastrophic for hashing. See RUNTIME_IGNORE.
  const digest = await digestTree(new DirectorySource(artifactPath, { ignore: RUNTIME_IGNORE }));
  // Named after what the user asked for, not the temp directory it
  // landed in — `assay-git-x7f2` is not a useful heading.
  // `.` and `./` are the most common inputs and are useless as a
  // heading, so a local target is named after the resolved directory.
  const displayName =
    // A registry knows the artifact's name; do not re-derive it from
    // the specifier, which would render `metahub:warden` as the name.
    (fetched.registryName as string | undefined) ??
    (fetched.provenance.kind === "local"
      ? (artifactPath.replace(/\/+$/, "").split("/").pop() ?? args.path)
      : // The last path segment, minus any `#ref` or `@version` suffix —
        // otherwise the heading reads "pdf#main".
        (fetched.provenance.spec
          .split("/")
          .pop()
          ?.replace(/[#@].*$/, "") ?? args.path));

  /**
   * The name the artifact DECLARES, not the directory it arrived in.
   *
   * A supply-chain tool that titles its report from a folder name has a
   * spoofing surface: a repository directory called `pdf` reported as
   * `pdf` no matter what its manifest said, and the red-team fixture
   * headlined `evasive` while declaring `log-analyzer`. The declared
   * identity is the one a consumer installs under, so that is the
   * heading — and a disagreement between the two is itself worth
   * saying out loud.
   */
  let declaredName: string | null = null;
  try {
    const id = await readIdentity({ subject: { kind }, source } as unknown as CheckContext);
    declaredName = id.name ?? null;
  } catch {
    // Identity is a nicety here; the `name-declared` check reports on
    // it properly and a failure to read it must not stop the run.
  }
  const heading = declaredName ?? displayName;
  const nameMismatch =
    declaredName !== null && declaredName !== displayName ? displayName : undefined;

  // `--quiet` silences the progress line too. "Only print failures"
  // that prints a progress banner is not quiet.
  const spinner = args.json || args.sarif || args.quiet ? null : new Spinner(theme);
  // Count the checks that will actually run on THIS kind. `checks.length`
  // is the whole catalog, so a skill announced "Running 35 checks" and
  // returned 24 results — a reader counting the difference has to assume
  // eleven checks crashed and were dropped.
  const applicable = checks.filter(
    (c) => !c.appliesTo?.kinds || c.appliesTo.kinds.includes(kind),
  ).length;
  spinner?.start(`Running ${applicable} checks`);

  let vetoed: string | null = null;
  const gate = (check: (typeof checks)[number], soFar: readonly CheckReport[]): string | null => {
    const reason = safetyVeto(behavioral, check, soFar);
    if (reason !== null) vetoed = check.id;
    return reason;
  };

  const report = await runAssay({
    gate,
    subject: {
      kind,
      name: heading,
      source: subjectSource(fetched, artifactPath),
      digest: { sha256: digest },
    },
    source,
    registry: CheckRegistry.from(checks),
    suite: { id: suite.id, version: ASSAY_VERSION },
    policy,
    ...(policyPath ? { policyPath } : {}),
    ...(policy.settings ? { config: policy.settings } : {}),
    environment: buildEnvironment(capabilities, scanContext),
    capabilities,
  });
  spinner?.stop();

  const ranBehavioral = behavioralWanted(behavioral) && vetoed === null;
  if (vetoed !== null && !args.json && !args.sarif) {
    process.stderr.write(
      `\n  ${theme.warn("behavioral evaluation was NOT run.")}\n` +
        `  ${theme.muted("A blocking safety check failed, so the artifact was not executed.")}\n` +
        `  ${theme.muted("Override deliberately with")} ${theme.code("--behavioral")}${theme.muted(".")}\n`,
    );
  }

  if (args.sarif) {
    write(`${toSarif(report, { toolVersion: ASSAY_VERSION })}\n`);
  } else if (args.json) {
    // The verdict, stated rather than implied.
    //
    // A CI consumer had to reimplement `results.filter(r => r.status
    // === "fail" && r.blocking)` — the exact logic the CLI runs to pick
    // its own exit code — and any drift between the two becomes a gate
    // that disagrees with the tool it is gating.
    const blockingIds = report.results
      .filter((r) => r.status === "fail" && r.blocking === true)
      .map((r) => r.checkId);
    const overallScore = report.score.overall;
    write(
      `${JSON.stringify(
        {
          $schema: `${ASSAY_HOME}/blob/main/docs/REPORT_SCHEMA.md`,
          ...report,
          verdict:
            blockingIds.length > 0
              ? "fail"
              : overallScore !== undefined && overallScore >= 50
                ? "pass"
                : "weak",
          blocking: blockingIds,
          unsafe: report.results.some(
            (r) => r.status === "fail" && r.blocking === true && r.axis === "safety",
          ),
        },
        null,
        2,
      )}\n`,
    );
  } else {
    write(
      renderReport(report, {
        quiet: args.quiet,
        theme,
        provenance: fetched.provenance.kind === "local" ? undefined : fetched.provenance,
        policyPath,
        durationMs: Date.now() - startedAt,
        nameMismatch,
      }),
    );
    // Suppressed under `--quiet`: the next-steps block is teaching
    // material, and someone who asked for only failures has said they
    // do not want to be taught right now.
    if (!args.quiet)
      write(
        renderSuggestions(
          suggestNextSteps(report, readEnvState(), {
            ranBehavioral,
            artifactPath: args.path,
            hasTranscripts: Boolean(args.transcripts),
            behavioral,
          }),
          theme.width,
        ),
      );
  }

  // A configured minimum turns the score into a gate the project chose,
  // rather than one we imposed. `--min-score` wins over the config file:
  // the flag is the more specific, more deliberate statement.
  const minScore = args.minScore ?? policy.minScore;
  if (minScore !== undefined) {
    if (report.score.overall === undefined) {
      // Refusing to gate on a score that was never published, rather
      // than passing by default. Too little was measured to justify a
      // number, so it cannot clear a threshold either.
      process.stderr.write(
        `  No overall score was published — too little of the suite could be measured\n` +
          `  to justify one, so --min-score ${minScore} cannot be evaluated.\n\n`,
      );
      return 1;
    }
    if (report.score.overall < minScore) {
      process.stderr.write(
        `  Score ${report.score.overall} is below the minimum ${minScore}` +
          `${args.minScore !== undefined ? "" : " configured in assay.config.json"}.\n\n`,
      );
      return 1;
    }
  }

  const blocking = blockingFailures(report);
  if (blocking.length > 0 && !args.json && !args.sarif) {
    process.stderr.write(
      `  ${blocking.length} blocking check${blocking.length === 1 ? "" : "s"} failed.\n\n`,
    );
  }
  return blocking.length > 0 ? 1 : 0;
}

/** Dispatch a subcommand. `run` stays the default for a bare path. */
export async function cli(argv: readonly string[]): Promise<number> {
  // Typing the bare command is how people find out what a tool does.
  // Answering with "could not determine the artifact kind for .." is a
  // hostile first impression for something whose whole job is to be
  // trusted.
  if (argv.length === 0) {
    write(USAGE);
    write("\n  New here? Try:  assay run .   or   assay setup\n\n");
    return 0;
  }

  // Applied here rather than inside `run`, so EVERY command sees what
  // `assay setup` saved. It previously lived in `main()` alone, which
  // meant `assay replay` — the one command whose whole purpose is to
  // re-judge with a model — told you to set OPENROUTER_API_KEY minutes
  // after the wizard had confirmed your OpenRouter key was live.
  // `setup` itself is excluded: it must show the environment as it
  // really is, not as its own saved file makes it look.
  if (argv[0] !== "setup") applyStoredConfig(await loadStoredConfig());

  // Before anything else, and handled here rather than in `parseArgs`
  // so it works as a bare flag: `assay --version` used to answer
  // "unknown flag" and `assay -v` was read as a PATH and reported "No
  // directory at ./-v". Every CLI is expected to answer this.
  if (argv[0] === "--version" || argv[0] === "-v" || argv[0] === "version") {
    write(`${ASSAY_VERSION}\n`);
    return 0;
  }

  // `--help` on a subcommand, before dispatch. It used to reach the
  // command itself, where every command did something different and two
  // of them did something destructive: `assay init --help` scaffolded
  // files into the current directory, and `assay keygen --help`
  // generated and wrote a private key. Asking a tool how to use it must
  // never change anything on disk.
  if (argv.length > 1 && argv.slice(1).some((a) => a === "--help" || a === "-h")) {
    return helpForCommand(argv[0]!);
  }

  switch (argv[0]) {
    case "setup":
      return setupCommand();
    case "verify":
      return verifyCommand(argv.slice(1));
    case "sign":
      return signCommand(argv.slice(1));
    case "keygen":
      return keygenCommand(argv.slice(1));
    case "doctor":
      return doctorCommand();
    case "init":
      return initCommand(argv.slice(1));
    case "diff":
      return diffCommand(argv.slice(1));
    case "replay":
      return replayCommand(argv.slice(1));
    case "list":
      return listCommand(argv.slice(1));
    case "explain":
      return explainCommand(argv.slice(1));
    case "run":
      return main(argv.slice(1));
    default:
      return main(argv);
  }
}

async function setupCommand(): Promise<number> {
  try {
    return (await runSetup()) ? 0 : 1;
  } catch (err) {
    // Ctrl-C at a prompt is a normal way to leave, not a crash.
    if ((err as Error).message === "cancelled") {
      process.stderr.write("\n  Cancelled — nothing was saved.\n\n");
      return 1;
    }
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
}

/** Does this path exist? Used where absence is a normal, expected state. */
async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Read a `--name value` or `--name=value` flag.
 *
 * Throws when the flag is present but its value is missing or is itself
 * a flag. It used to return `argv[i + 1]` unguarded, and the failure
 * that produced was not cosmetic:
 *
 *     assay verify report.json --require-signature --key "$EXPECTED_KEY"
 *
 * With `EXPECTED_KEY` unset in CI, the shell passes nothing, `--key`
 * reads `undefined`, and pinned-key verification silently degrades to
 * "someone signed this" — reported as a warning, exit 0. The same shape
 * turned `--artifact` into a skipped digest recompute, and
 * `--transcripts --json` into a directory named `--json`.
 *
 * An absent value is always a mistake, and never one worth guessing at.
 */
function flag(argv: readonly string[], name: string): string | undefined {
  const inline = argv.find((a) => a.startsWith(`--${name}=`));
  if (inline !== undefined) {
    const value = inline.slice(name.length + 3);
    if (!value) throw new Error(`--${name} needs a value`);
    return value;
  }
  const i = argv.indexOf(`--${name}`);
  if (i === -1) return undefined;
  const value = argv[i + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new Error(
      `--${name} needs a value${value === undefined ? "" : `, got the flag ${value}`}`,
    );
  }
  return value;
}

/**
 * The first positional argument, ignoring flags AND their values.
 *
 * `argv.find(a => !a.startsWith("--"))` treated a flag's value as the
 * positional, so every natural flags-first ordering broke:
 *
 *     assay verify --key k.pub.pem signed.json
 *     assay replay --transcripts ./t report.json
 *
 * read `k.pub.pem` and `./t` as the report and failed with a JSON
 * parser error naming the wrong file — for `sign`, naming no file at
 * all. `--transcripts` is documented as required for `replay`, which
 * makes that ordering the more likely one, not the exotic one.
 */
function positional(argv: readonly string[], valueFlags: readonly string[]): string | undefined {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("-")) {
      // `--flag=value` carries its value; `--flag value` consumes the next token.
      if (!a.includes("=") && valueFlags.includes(a.replace(/^--/, ""))) i++;
      continue;
    }
    return a;
  }
  return undefined;
}

/**
 * Reject flags a command does not know.
 *
 * Only `run` validated its flags. Everywhere else a typo was accepted
 * in silence, and on `verify` that silence removed a CI gate: a single
 * missing character in `--require-signature` left an unsigned report
 * passing at exit 0, with output that looked like a successful
 * verification.
 */
function rejectUnknownFlags(argv: readonly string[], known: readonly string[]): void {
  for (const a of argv) {
    if (!a.startsWith("-")) continue;
    const name = a.replace(/^--?/, "").split("=")[0]!;
    if (!known.includes(name)) throw unknownFlag(a, known);
  }
}

/**
 * The theme every command shares.
 *
 * Only `run` used to consult it. Every other command hardcoded its own
 * glyphs, so the product shipped two check marks and two crosses (`✔`
 * vs `✓`, `✘` vs `✗`, `▲` vs `!` vs `⚠`) — and, far worse, `NO_COLOR`
 * and `ASSAY_ASCII` were no-ops for every command except `run`. A user
 * who set either got them honoured in one place out of eight.
 */
function ui(): Theme {
  return createTheme();
}

/** A verdict glyph for the non-`run` commands, from the same palette. */
function mark(t: Theme, level: "ok" | "warn" | "fail"): string {
  return statusGlyph(t, level === "ok" ? "pass" : level === "warn" ? "warn" : "fail");
}

const VERIFY_VALUE_FLAGS = ["key", "artifact", "bundle", "identity", "issuer"] as const;

export async function verifyCommand(argv: readonly string[]): Promise<number> {
  const theme = ui();
  let path: string | undefined;
  let keyPath: string | undefined;
  let artifactPath: string | undefined;
  try {
    rejectUnknownFlags(argv, [...VERIFY_VALUE_FLAGS, "require-signature", "json"]);
    path = positional(argv, VERIFY_VALUE_FLAGS);
    // Read here, inside the guard: a flag whose value is missing must
    // produce this command's own error, not an unhandled rejection.
    keyPath = flag(argv, "key");
    artifactPath = flag(argv, "artifact");
  } catch (err) {
    process.stderr.write(`${theme.fail("assay:")} ${(err as Error).message}\n`);
    return 2;
  }
  if (!path) {
    process.stderr.write("assay: verify needs a report file\n");
    return 2;
  }
  let report: AssayReport;
  try {
    report = JSON.parse(await readFile(path, "utf8")) as AssayReport;
  } catch (err) {
    process.stderr.write(`assay: cannot read ${path}: ${(err as Error).message}\n`);
    return 2;
  }

  // A keyless bundle is verified alongside the structural checks, not
  // instead of them — the score must still follow from the findings.
  const bundlePath = flag(argv, "bundle");
  let keylessLine: string | null = null;
  if (bundlePath) {
    try {
      const bundle = JSON.parse(await readFile(bundlePath, "utf8")) as SigstoreBundle;
      const identity = flag(argv, "identity");
      const issuer = flag(argv, "issuer");
      const outcome = await verifyKeyless(report, bundle, {
        ...(identity ? { certificateIdentityURI: identity } : {}),
        ...(issuer ? { certificateIssuer: issuer } : {}),
      });
      keylessLine = `${outcome.valid ? "ok" : "fail"}\t${outcome.message}`;
    } catch (err) {
      keylessLine = `fail\t${(err as Error).message}`;
    }
  }

  // A typo'd --artifact used to be reported as "this report is about a
  // different artifact", quoting the digest of the empty tree. That
  // blames the report for the user's typo, and in a dispute it is
  // exactly the wrong answer.
  if (artifactPath && !(await isDirectory(artifactPath))) {
    process.stderr.write(
      `${theme.fail("assay:")} no directory at ${artifactPath} — nothing to recompute the digest from.\n`,
    );
    return 2;
  }

  const result = await verifyReport(report, {
    ...(keyPath ? { publicKey: await readFile(keyPath, "utf8") } : {}),
    // Must match how `run` computed the digest, or verification of a
    // legitimate report fails.
    ...(artifactPath
      ? { source: new DirectorySource(artifactPath, { ignore: RUNTIME_IGNORE }) }
      : {}),
    requireSignature: argv.includes("--require-signature"),
  });

  if (keylessLine) {
    const [level, message] = keylessLine.split("\t");
    result.findings.push({
      level: level === "ok" ? "ok" : "fail",
      check: "keyless",
      message: message ?? "",
    });
    if (level !== "ok") result.valid = false;
  }

  if (argv.includes("--json")) {
    write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    write("\n");
    for (const f of result.findings) {
      write(
        `  ${mark(theme, f.level as "ok" | "warn" | "fail")} ${f.check.padEnd(10)} ${f.message}\n`,
      );
    }
    // A `warn` finding must not be swallowed by an affirmative verdict.
    //
    // `verify` used to print "Report verified." directly under
    // "Report is unsigned; its origin cannot be established", with the
    // affirmative line last and load-bearing, and exit 0. That is
    // precisely the failure-reads-as-success shape `diff` writes five
    // lines to avoid — the philosophy was applied in one command and
    // inverted in another.
    const unresolved = result.findings.filter((f) => f.level === "warn");
    const verdict = !result.valid
      ? theme.fail(theme.bold("Report FAILED verification."))
      : unresolved.length > 0
        ? theme.warn(
            `Checks passed, but ${unresolved.length} question${unresolved.length === 1 ? "" : "s"} remain${unresolved.length === 1 ? "s" : ""} — see above.`,
          )
        : theme.pass(theme.bold("Report verified."));
    write(`\n  ${verdict}\n\n`);
  }
  return result.valid ? 0 : 1;
}

const SIGN_VALUE_FLAGS = ["key", "pub", "out"] as const;

export async function signCommand(argv: readonly string[]): Promise<number> {
  const theme = ui();
  let path: string | undefined;
  try {
    rejectUnknownFlags(argv, [...SIGN_VALUE_FLAGS, "keyless"]);
    path = positional(argv, SIGN_VALUE_FLAGS);
    // Surface a missing value now rather than mid-signing.
    for (const f of SIGN_VALUE_FLAGS) flag(argv, f);
  } catch (err) {
    process.stderr.write(`${theme.fail("assay:")} ${(err as Error).message}\n`);
    return 2;
  }

  if (argv.includes("--keyless")) {
    if (!path) {
      process.stderr.write("assay: sign --keyless needs <report.json>\n");
      return 2;
    }
    try {
      const report = JSON.parse(await readFile(path, "utf8")) as AssayReport;
      if (!hasAmbientIdentity()) {
        write("  no ambient OIDC identity — a browser flow will open\n");
      }
      const bundle = await signKeyless(report);
      const bundlePath = `${path.replace(/\.json$/, "")}.sigstore.json`;
      await writeFile(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
      const idx = rekorLogIndex(bundle);
      write(`  ${mark(theme, "ok")} signed keylessly ${theme.arrow} ${bundlePath}\n`);
      if (idx !== undefined) {
        write(`    Rekor entry ${idx}  https://search.sigstore.dev/?logIndex=${idx}\n`);
      }
      write("    No private key was retained.\n");
      return 0;
    } catch (err) {
      process.stderr.write(`assay: ${(err as Error).message}\n`);
      // A duplicate is its own exit code. The report IS in the
      // transparency log — what did not happen is us getting a bundle
      // back — and a caller automating this needs to tell that apart
      // from "signing failed", which exit 2 would conflate.
      return err instanceof KeylessDuplicateError ? 3 : 2;
    }
  }

  const keyPath = flag(argv, "key");
  const pubPath = flag(argv, "pub");
  if (!path || !keyPath || !pubPath) {
    process.stderr.write(
      "assay: sign needs <report.json> --key <private.pem> --pub <public.pem>\n",
    );
    return 2;
  }
  try {
    const report = JSON.parse(await readFile(path, "utf8")) as AssayReport;
    const signed = signReport(report, {
      privateKey: await readFile(keyPath, "utf8"),
      publicKey: await readFile(pubPath, "utf8"),
    });
    await writeFile(flag(argv, "out") ?? path, `${JSON.stringify(signed, null, 2)}\n`, "utf8");
    const keyid = signed.attestation?.keyid;
    write(keyid ? `  Signed with keyid ${keyid}.\n` : "  Signed.\n");
    return 0;
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
}

export async function keygenCommand(argv: readonly string[]): Promise<number> {
  const theme = ui();
  let prefix: string;
  try {
    rejectUnknownFlags(argv, ["out", "force"]);
    prefix = flag(argv, "out") ?? "assay-key";
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
  const force = argv.includes("--force");

  // Refuse to clobber an existing key.
  //
  // Running this twice in one directory used to overwrite the private
  // key in place, with no prompt and no backup. Anyone who had signed a
  // release with the first key permanently lost the ability to sign as
  // that identity, and found out only when a verifier reported a keyid
  // mismatch. `ssh-keygen` asks; there is no reason to be less careful
  // with a key than ssh is.
  if (!force && (await exists(`${prefix}.pem`))) {
    process.stderr.write(
      `${theme.fail("assay:")} ${prefix}.pem already exists — refusing to overwrite a signing key.\n` +
        `  Anything signed with it could no longer be verified.\n\n` +
        `  Use the existing key:   assay sign <report> --key ${prefix}.pem --pub ${prefix}.pub.pem\n` +
        `  Generate another:       assay keygen --out ${prefix}-2\n` +
        `  Replace it deliberately: assay keygen --force\n`,
    );
    return 2;
  }

  const { privateKey, publicKey, keyid } = generateKeyPair();
  try {
    // 0600 on the private key: a signing key readable by every process
    // on the box is not a signing key.
    await writeFile(`${prefix}.pem`, privateKey, { encoding: "utf8", mode: 0o600 });
    await writeFile(`${prefix}.pub.pem`, publicKey, "utf8");
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
  write(
    `  keyid       ${keyid}\n` +
      `  private     ${prefix}.pem  (keep secret, mode 0600)\n` +
      `  public      ${prefix}.pub.pem  (publish this)\n`,
  );
  return 0;
}

export async function diffCommand(argv: readonly string[]): Promise<number> {
  const theme = ui();
  try {
    rejectUnknownFlags(argv, ["json"]);
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
  const [beforePath, afterPath] = argv.filter((a) => !a.startsWith("-"));
  if (!beforePath || !afterPath) {
    process.stderr.write("assay: diff needs <before.json> <after.json>\n");
    return 2;
  }
  let before: AssayReport;
  let after: AssayReport;
  try {
    before = JSON.parse(await readFile(beforePath, "utf8")) as AssayReport;
    after = JSON.parse(await readFile(afterPath, "utf8")) as AssayReport;
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }

  const d = diffReports(before, after);

  // One exit rule, shared by both output formats.
  //
  // The JSON path counted regressions and surface changes; the human
  // path also counted `coverageLost`. So the same two reports exited 1
  // for a human and 0 for `--json` — and `--json` is what CI consumes.
  // `coverageLost` exists precisely because a check that quietly stops
  // running sails through the gate the README recommends, and the
  // machine-readable path was the one letting it sail.
  const flagged = d.surface?.changes.filter((c) => c.requiresReview).length ?? 0;
  const failing = d.regressions.length + flagged + d.coverageLost.length > 0 ? 1 : 0;

  if (argv.includes("--json")) {
    write(`${JSON.stringify(d, null, 2)}\n`);
    return failing;
  }

  write("\n");

  // Surface changes print BEFORE anything else, and are the reason a
  // diff can fail while every check still passes. That is the whole
  // shape of a rug pull: the artifact still looks fine.
  const needsReview = d.surface?.changes.filter((c) => c.requiresReview) ?? [];
  if (d.surfaceUnavailable) {
    // The loudest thing on the page, because it is the one failure mode
    // that reads as success. Neither report captured a tool surface, so
    // this diff CANNOT detect a rug pull — and saying nothing here let
    // "No regressions, no surface changes" stand as a clean bill of
    // health for a comparison that never happened.
    const which =
      d.surfaceUnavailable === "both"
        ? "Neither report"
        : d.surfaceUnavailable === "before"
          ? "The BEFORE report"
          : "The AFTER report";
    write(`  ${theme.warn(`${theme.glyph("warn")} TOOL SURFACE NOT COMPARED`)}\n`);
    write(`    ${which} recorded a tool surface, so this diff cannot\n`);
    write("    detect a changed tool description — the rug-pull signal.\n\n");
    write("    Static capture reads tool names only where they are string\n");
    write("    literals in source. A package that ships only build output, or\n");
    write("    registers its tools dynamically, defeats it. Run with\n");
    write("    --behavioral to capture the surface the server actually\n");
    write("    returns over the wire, which is not defeated by either.\n\n");
  } else if (d.surface && !d.surface.comparable) {
    // "We cannot tell" must never render as "it changed".
    write("  · tool surface not comparable\n");
    for (const c of d.surface.changes) write(`      ${c.detail}\n`);
    write("\n");
  } else if (d.surface && !d.surface.unchanged) {
    write(`  ${theme.warn(`${theme.glyph("warn")} TOOL SURFACE CHANGED`)}\n`);
    for (const c of d.surface.changes) {
      write(
        `    ${c.requiresReview ? mark(theme, "warn") : theme.muted(theme.dot)} ${c.kind.padEnd(20)} ${c.detail}\n`,
      );
    }
    write(
      "\n    A model reads tool descriptions and acts on them, so editing one\n" +
        "    after approval changes the agent's instructions without changing\n" +
        "    any reviewed code. Re-review before trusting this version.\n\n",
    );
  }

  if (d.sameSubject) {
    // If the bytes are identical, any change came from US — a check
    // version bump, a config change, or judge drift. That is a very
    // different conversation from "the author broke something".
    write("  Same artifact digest — any change below is from Assay, not the artifact.\n\n");
  }
  const line = (c: { checkId: string; from: string | null; to: string | null }) =>
    `    ${c.checkId.padEnd(28)} ${c.from ?? "—"} → ${c.to ?? "—"}\n`;
  if (d.regressions.length > 0) {
    write("  regressions\n");
    for (const c of d.regressions) write(line(c));
    write("\n");
  }
  if (d.coverageLost.length > 0) {
    // Its own heading, above improvements, because it is the category
    // that used to hide as one. `fail → skip` scored as an improvement.
    write("  coverage lost — these produced a verdict before and do not now\n");
    for (const c of d.coverageLost) write(line(c));
    write("\n");
  }
  if (d.improvements.length > 0) {
    write("  improvements\n");
    for (const c of d.improvements) write(line(c));
    write("\n");
  }
  for (const [label, list] of [
    ["added", d.added],
    ["removed", d.removed],
  ] as const) {
    if (list.length > 0) {
      write(`  ${label}\n`);
      for (const c of list) write(line(c));
      write("\n");
    }
  }
  if (d.scoreDelta !== null) {
    const sign = d.scoreDelta > 0 ? "+" : "";
    write(`  score     ${sign}${d.scoreDelta}\n`);
  }
  const problems = failing;
  write(
    problems === 0
      ? d.surfaceUnavailable
        ? "  No regressions. Tool surface NOT compared — see above.\n\n"
        : "  No regressions, no surface changes.\n\n"
      : `  ${d.regressions.length} regression(s), ${needsReview.length} surface change(s) needing review` +
          (d.coverageLost.length > 0 ? `, ${d.coverageLost.length} check(s) stopped judging` : "") +
          ".\n\n",
  );
  return problems > 0 ? 1 : 0;
}

/**
 * Re-judge the transcripts a report recorded, and report whether the
 * verdicts reproduce.
 *
 * This is the operation the `replayable` determinism tier exists to
 * make possible: a skeptic re-derives the GRADE without a sandbox and
 * without our cooperation. It deliberately does NOT re-run the
 * artifact — that is a different, far more expensive dispute — so a
 * clean replay means "the judgement was fair given this transcript",
 * not "the transcript is what the artifact really did".
 *
 * Exits non-zero on disagreement, so it is usable as a scheduled check
 * against judge drift rather than only as a manual investigation.
 */
export async function replayCommand(argv: readonly string[]): Promise<number> {
  const theme = ui();
  let reportPath: string | undefined;
  let transcriptsDir: string | undefined;
  let providerName: string | undefined;
  try {
    rejectUnknownFlags(argv, ["transcripts", "provider", "json"]);
    reportPath = positional(argv, ["transcripts", "provider"]);
    transcriptsDir = flag(argv, "transcripts");
    providerName = flag(argv, "provider");
  } catch (err) {
    process.stderr.write(`${theme.fail("assay:")} ${(err as Error).message}\n`);
    return 2;
  }
  const dir = transcriptsDir;
  if (!reportPath || !dir) {
    process.stderr.write("assay: replay needs <report.json> --transcripts <dir>\n");
    return 2;
  }

  let report: AssayReport;
  try {
    report = JSON.parse(await readFile(reportPath, "utf8")) as AssayReport;
  } catch (err) {
    process.stderr.write(`assay: cannot read ${reportPath}: ${(err as Error).message}\n`);
    return 2;
  }

  // Transcript digests live in the evidence of behavioral results.
  const digests = report.results.flatMap((r) =>
    (r.evidence ?? [])
      .filter((e): e is Extract<typeof e, { type: "transcript" }> => e.type === "transcript")
      .map((e) => ({ checkId: r.checkId, digest: e.sha256 })),
  );
  if (digests.length === 0) {
    process.stderr.write(
      "assay: this report records no transcripts, so there is nothing to replay.\n" +
        "Behavioral evaluation must have run, with a transcript sink configured.\n",
    );
    return 2;
  }

  let provider;
  try {
    provider = (await resolveLlmProvider(providerName)).provider;
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }

  const outcomes: ReplayOutcome[] = [];
  const missing: string[] = [];
  for (const { digest } of digests) {
    const stored = await loadTranscript(dir, digest);
    if (!stored) {
      missing.push(digest);
      continue;
    }
    outcomes.push(await replayTranscript(stored, { llm: provider }));
  }

  if (argv.includes("--json")) {
    write(`${JSON.stringify({ outcomes, missing, provider: provider.name }, null, 2)}\n`);
  } else {
    write(`\n  replaying ${outcomes.length} transcript(s) with ${provider.name}\n\n`);
    for (const o of outcomes) {
      const glyph = o.agrees ? mark(theme, "ok") : mark(theme, "fail");
      const drift = o.drift > 0 ? `  drift ${o.drift.toFixed(1)}` : "";
      write(
        `    ${glyph} ${o.digest.slice(0, 12)}…  ${o.original ? (o.original.pass ? "pass" : "fail") : "—"} ${theme.arrow} ${o.replayed.pass ? "pass" : "fail"}${drift}\n`,
      );
      if (!o.agrees) write(`        ${o.replayed.rationale}\n`);
    }
    if (missing.length > 0) {
      write(`\n  ${missing.length} transcript(s) not found in ${dir}\n`);
    }
    const disagreed = outcomes.filter((o) => !o.agrees).length;
    write(
      disagreed === 0
        ? `\n  All verdicts reproduced.\n\n`
        : `\n  ${disagreed} verdict(s) did NOT reproduce.\n\n`,
    );
  }

  // A transcript we cannot find is our storage failing, not a
  // disagreement — but it still means the report is not fully
  // checkable, so it is not a success either.
  if (missing.length > 0 && outcomes.length === 0) return 2;
  return outcomes.some((o) => !o.agrees) ? 1 : 0;
}

/**
 * Answer "what can I actually run right now?"
 *
 * A developer should not have to read a README, guess at environment
 * variable names, and run a three-minute command to discover that they
 * are missing a key. This checks and reports.
 */
export async function doctorCommand(): Promise<number> {
  const theme = ui();
  // Doctor must report what a real run would see, and a real run applies
  // the stored config — otherwise it says "no model configured" to
  // someone who configured one two minutes ago.
  const stored = await loadStoredConfig();
  applyStoredConfig(stored);
  const env = readEnvState();
  write("\n  assay " + ASSAY_VERSION + "\n\n");

  write("  static checks\n");
  write(
    `    ${mark(theme, "ok")} ready ${theme.dash} ${DEFAULT_CHECKS.length} checks, no credentials needed\n\n`,
  );

  if (stored) {
    // Naming the file is the point: persisted state that a user cannot
    // locate is state they cannot change or revoke.
    write("  saved configuration\n");
    write(`    ${mark(theme, "ok")} ${credentialFile()}\n`);
    if (!(await configIsPrivate())) {
      write(
        `    ${mark(theme, "warn")} that file is readable by other users ${theme.dash} chmod 600 it\n`,
      );
    }
    write("\n");
  }

  write("  behavioral evaluation\n");

  // Resolve the sandbox the way a run resolves it, rather than
  // reporting whatever is merely AVAILABLE.
  //
  // These are different questions and the answers diverge. Doctor
  // checked podman first and announced it; `resolveSandbox` prefers e2b
  // whenever E2B_API_KEY is set — which `assay setup` sets, from the
  // stored config. So a machine with both told you "podman (local,
  // free)" and then billed an E2B run. Same defect as the model
  // provider had: the command whose entire job is to be believed was
  // the one that was wrong.
  const local = await localRuntime();
  let sandboxName: string | null = null;
  try {
    sandboxName = (await resolveSandbox()).name;
  } catch {
    sandboxName = null;
  }
  if (sandboxName === "podman" || sandboxName === "docker") {
    write(`    ${mark(theme, "ok")} sandbox   ${sandboxName} (local, free)\n`);
  } else if (sandboxName === "e2b") {
    write(`    ${mark(theme, "ok")} sandbox   e2b (cloud, metered)\n`);
    if (local) {
      // Naming the alternative, because "why is this costing money when
      // I have a container runtime?" is otherwise a mystery.
      write(`                ${local} is also available — use --sandbox ${local} for a free run\n`);
    }
  } else {
    write(`    ${mark(theme, "fail")} sandbox   none usable\n`);
    write("                install Docker or Podman for a free local sandbox,\n");
    write("                or run `assay setup` to use the E2B cloud sandbox\n");
  }
  // Actually resolve the provider rather than looking for an
  // environment variable.
  //
  // Doctor answers "what can I run right now?", so it has to ask the
  // question `run` asks, through the same function. Checking only for a
  // key meant doctor reported `✔ model openrouter` and `run
  // --behavioral`, in the same shell, answered "No model provider is
  // configured" — because the key was fine and the adapter's SDK was
  // absent. Two code paths, two answers, and the one whose entire job
  // is to be believed was the wrong one.
  let modelOk = false;
  let modelDetail: string | null = null;
  try {
    modelOk = Boolean((await resolveLlmProvider()).provider);
  } catch (err) {
    modelDetail = (err as Error).message;
  }

  if (modelOk) {
    write(`    ${mark(theme, "ok")} model     ${env.modelHint ?? "configured"}\n`);
  } else if (env.hasModelKey && modelDetail) {
    // A configured key that still cannot produce a provider. Say which
    // problem it is; "none configured" is false and unactionable here.
    write(
      `    ${mark(theme, "fail")} model     ${env.modelHint ?? "a model key"} configured, but not usable\n`,
    );
    for (const line of modelDetail.split("\n")) write(`                ${line.trim()}\n`);
  } else {
    write(`    ${mark(theme, "fail")} model     none configured\n`);
    write("                run `assay setup`, or set one of ANTHROPIC_API_KEY,\n");
    write("                OPENAI_API_KEY, OPENROUTER_API_KEY, LOCAL_LLM_BASE_URL\n");
  }

  write(
    behavioralReadyAdvice({
      ready: sandboxName !== null && modelOk,
      optedOut: stored?.behavioralByDefault === false,
    }),
  );

  write("  signing\n");
  write(
    `    ${mark(theme, "ok")} ready ${theme.dash} assay keygen, then assay sign / assay verify\n\n`,
  );
  return 0;
}

/**
 * Scaffold the two files that change how well Assay works on a project.
 *
 * Author-supplied eval cases matter more than the config: without them
 * a behavioral run synthesizes cases from the documentation, which is a
 * reasonable fallback but tests what the docs SAY rather than what the
 * author knows is important.
 */
export async function initCommand(argv: readonly string[]): Promise<number> {
  const theme = ui();
  try {
    rejectUnknownFlags(argv, []);
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
  const dir = argv.find((a) => !a.startsWith("-")) ?? ".";
  const configPath = join(dir, "assay.config.json");
  const evalsPath = join(dir, "evals", "basic.json");

  const config = {
    $schema: `${ASSAY_HOME}/blob/main/docs/config.schema.json`,
    settings: { docsMinWords: 50 },
    waivers: [],
  };
  const evals = [
    {
      id: "happy-path",
      prompt: "Replace with a real request a user would make of this artifact.",
      expect: "Describe what a correct response looks like. The judge scores against this.",
    },
  ];

  let wrote = 0;
  for (const [path, body] of [
    [configPath, config],
    [evalsPath, evals],
  ] as const) {
    try {
      await readFile(path, "utf8");
      write(`  · ${path} already exists, left alone\n`);
    } catch {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, `${JSON.stringify(body, null, 2)}\n`, "utf8");
      write(`  ${mark(theme, "ok")} wrote ${path}\n`);
      wrote++;
    }
  }
  if (wrote > 0) {
    write(
      "\n  Edit evals/basic.json with cases you care about — a behavioral run\n" +
        "  uses them instead of synthesizing from your docs, which tests what\n" +
        "  you know matters rather than what the documentation happens to say.\n\n",
    );
  }
  return 0;
}

export function listCommand(argv: readonly string[] = []): number {
  const theme = ui();
  let kind: ArtifactKind | undefined;
  let suiteChecks: readonly CheckDefinition[] = DEFAULT_CHECKS;
  let suiteLabel = "";
  try {
    rejectUnknownFlags(argv, ["kind", "json", "suite"]);
    const requested = flag(argv, "kind");
    if (requested) kind = validKind(requested);
    const suiteId = flag(argv, "suite");
    if (suiteId) {
      const suite = resolveSuite(suiteId);
      suiteChecks = suite.checks;
      suiteLabel = ` in ${suite.id}`;
    }
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }

  // "Which checks apply to a plugin?" had no answer short of running a
  // plugin through the tool and reading what came back. `--suite` narrows
  // it further, to exactly the set a named preset would run.
  const checks = kind
    ? suiteChecks.filter((c) => !c.appliesTo?.kinds || c.appliesTo.kinds.includes(kind!))
    : suiteChecks;

  if (argv.includes("--json")) {
    write(
      `${JSON.stringify(
        checks.map((c) => ({
          id: c.id,
          title: c.title,
          axis: c.axis,
          weight: c.weight ?? 1,
          blocking: Boolean(c.blocking),
          determinism: c.determinism,
          needs: c.needs ?? [],
          appliesTo: c.appliesTo?.kinds ?? null,
          spec: c.spec ?? null,
        })),
        null,
        2,
      )}\n`,
    );
    return 0;
  }

  const byAxis = new Map<string, typeof DEFAULT_CHECKS>();
  for (const c of checks) {
    byAxis.set(c.axis, [...(byAxis.get(c.axis) ?? []), c]);
  }
  write("\n");
  for (const axis of [...byAxis.keys()].sort()) {
    write(`  ${axis}\n`);
    for (const c of byAxis.get(axis)!) {
      const kinds = c.appliesTo?.kinds?.join(",") ?? "all";
      const weight = c.weight === 0 ? "info" : `w${c.weight ?? 1}`;
      write(
        `    ${c.id.padEnd(26)} ${weight.padEnd(5)} ${(c.blocking ? "blocking" : "").padEnd(9)} ${kinds}\n`,
      );
    }
    write("\n");
  }
  write(
    `  ${checks.length} check${checks.length === 1 ? "" : "s"}${kind ? ` for ${kind}` : ""}${suiteLabel}. ` +
      `${theme.muted("`assay explain <id>` for details.")}\n\n`,
  );
  return 0;
}

export function explainCommand(argv: readonly string[]): number {
  const theme = ui();
  try {
    rejectUnknownFlags(argv, ["json"]);
  } catch (err) {
    process.stderr.write(`assay: ${(err as Error).message}\n`);
    return 2;
  }
  const wantJson = argv.includes("--json");
  const id = argv.find((a) => !a.startsWith("-"));
  const check = DEFAULT_CHECKS.find((c) => c.id === id);
  if (!check) {
    process.stderr.write(
      id === undefined
        ? `assay: explain needs a check id. Run \`assay list\` to see them all.\n`
        : `assay: no check named "${id}". Run \`assay list\` to see them all.\n`,
    );
    return 2;
  }

  // `--json` was accepted and silently ignored: the output was always
  // the human-formatted block, so a tool asking for machine output got
  // prose it could not parse. Emit the check's full metadata instead.
  if (wantJson) {
    write(
      JSON.stringify(
        {
          id: check.id,
          version: check.version,
          title: check.title,
          axis: check.axis,
          category: check.category,
          weight: check.weight ?? 1,
          blocking: check.blocking ?? false,
          determinism: check.determinism,
          appliesTo: check.appliesTo?.kinds ?? null,
          capabilities: check.needs ?? [],
          ...(check.inspects ? { inspects: check.inspects } : {}),
          ...(check.rationale ? { rationale: check.rationale } : {}),
          ...(check.examples ? { examples: check.examples } : {}),
          ...(check.spec ? { spec: check.spec } : {}),
        },
        null,
        2,
      ) + "\n",
    );
    return 0;
  }
  const t = theme;
  const L = (k: string, v: string) => `    ${t.muted(k.padEnd(13))}${v}\n`;

  write(`\n  ${t.heading(check.id)}  ${t.muted(`v${check.version}`)}\n`);
  write(`  ${check.title}\n\n`);

  if (check.inspects) write(`  ${t.bold("What it looks at")}\n    ${check.inspects}\n\n`);
  if (check.rationale) {
    write(`  ${t.bold("Why")}\n    ${wrapText(check.rationale, t.width - 6, "    ")}\n\n`);
  }
  if (check.examples?.passing || check.examples?.failing) {
    write(`  ${t.bold("Examples")}\n`);
    if (check.examples.passing) {
      write(`    ${statusGlyph(t, "pass")} ${t.muted(check.examples.passing)}\n`);
    }
    if (check.examples.failing) {
      write(`    ${statusGlyph(t, "fail")} ${t.muted(check.examples.failing)}\n`);
    }
    write("\n");
  }

  write(`  ${t.bold("Details")}\n`);
  write(L("axis", check.axis));
  write(
    L(
      "weight",
      check.weight === 0 ? "0 (informational — reported, never scored)" : String(check.weight ?? 1),
    ),
  );
  write(L("blocking", check.blocking ? t.fail("yes — a failure stops a publish") : "no"));
  write(L("determinism", check.determinism));
  write(L("applies to", check.appliesTo?.kinds?.join(", ") ?? "all kinds"));
  write(L("capabilities", (check.needs ?? []).join(", ") || "none"));
  if (check.spec) write(L("spec", check.spec));

  // The escape hatch, spelled out. Somebody reading `explain` is often
  // there because they disagree, and a waiver they have to go and look
  // up is a waiver they will not write — they will disable the check.
  write(`\n  ${t.bold("If it is wrong about your artifact")}\n`);
  write(`    ${t.muted("assay.config.json")}\n`);
  write(
    `    ${t.code(`{ "waivers": [{ "check": "${check.id}", "reason": "…", "expires": "2027-01-01" }] }`)}\n`,
  );
  write(
    `    ${t.muted("The reason is mandatory and is published in the report. A waiver is")}\n` +
      `    ${t.muted("visible and expires; `disable` is neither, and now costs you coverage.")}\n\n`,
  );

  return 0;
}

// Only self-invoke when run as a program, so the module stays importable.
if (process.argv[1] && /assay(\.[cm]?js)?$|cli\.[cm]?js$/.test(process.argv[1])) {
  // `assay run --json | head` closes the pipe early. Without this Node
  // raises EPIPE and prints a stack trace, which makes a perfectly
  // ordinary shell idiom look like a crash in the tool.
  process.stdout.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EPIPE") process.exit(0);
    throw err;
  });
  cli(process.argv.slice(2))
    .then(finish)
    .catch((err: Error) => {
      process.stderr.write(`assay: ${err.message}\n`);
      finish(2);
    });
}
