/**
 * The argument layer, and what it lets through.
 *
 * Every case here was a real defect found by driving the built binary
 * as a user rather than calling functions as a test. They share one
 * shape: the CLI accepted something it did not understand and carried
 * on, and the resulting silence looked like success.
 *
 * Two of them are security-relevant, and neither would have failed any
 * previously existing test:
 *
 *   - `--key ""` (an unset CI secret) turned pinned-key verification
 *     into "somebody signed this", reported as a warning, exit 0.
 *   - `--require-signatures`, one character wrong, was ignored, so an
 *     unsigned report passed the gate at exit 0.
 *
 * And two were destructive: `assay init --help` scaffolded files into
 * the current directory, and `assay keygen --help` generated and wrote
 * a signing key. Asking a tool how to use it must not change anything.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cli } from "../src/cli.js";
import type { CheckReport } from "../src/types.js";

/** Run the CLI capturing both streams, so assertions can read them. */
async function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  let out = "";
  let err = "";
  const so = process.stdout.write.bind(process.stdout);
  const se = process.stderr.write.bind(process.stderr);
  process.stdout.write = ((s: string) => ((out += s), true)) as typeof process.stdout.write;
  process.stderr.write = ((s: string) => ((err += s), true)) as typeof process.stderr.write;
  try {
    const code = await cli(argv);
    return { code, out, err };
  } finally {
    process.stdout.write = so;
    process.stderr.write = se;
  }
}

describe("`--help` is safe on every command", () => {
  let dir: string;
  let cwd: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-help-"));
    cwd = process.cwd();
    process.chdir(dir);
  });
  afterAll(() => {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  });

  // The two that wrote to disk.
  it("`keygen --help` explains keygen and writes no key", async () => {
    const { code, out } = await run(["keygen", "--help"]);
    expect(code).toBe(0);
    expect(out).toMatch(/assay keygen/);
    expect(existsSync(join(dir, "assay-key.pem"))).toBe(false);
    expect(readdirSync(dir)).toHaveLength(0);
  });

  it("`init --help` explains init and scaffolds nothing", async () => {
    const { code, out } = await run(["init", "--help"]);
    expect(code).toBe(0);
    expect(out).toMatch(/assay init/);
    expect(readdirSync(dir)).toHaveLength(0);
  });

  // The five that answered "you are missing an argument", exit 2.
  it.each(["sign", "verify", "diff", "replay", "explain"])(
    "`%s --help` succeeds instead of erroring about a missing argument",
    async (cmd) => {
      const { code, out, err } = await run([cmd, "--help"]);
      expect(code).toBe(0);
      expect(err).toBe("");
      expect(out).toMatch(new RegExp(`assay ${cmd}`));
    },
  );

  it("shows only the requested command's options, not the whole manual", async () => {
    const { out } = await run(["sign", "--help"]);
    expect(out).toMatch(/SIGN OPTIONS/);
    // `sign` has nothing to do with fetching targets or running cases.
    expect(out).not.toMatch(/BEHAVIORAL OPTIONS/);
    expect(out).not.toMatch(/npm:@scope\/package/);
  });

  it("`-h` behaves the same as `--help`", async () => {
    const { code, out } = await run(["verify", "-h"]);
    expect(code).toBe(0);
    expect(out).toMatch(/assay verify/);
  });
});

describe("a flag missing its value is an error, never a silent skip", () => {
  let dir: string;
  let reportPath: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "assay-flagval-"));
    reportPath = join(dir, "r.json");
    writeFileSync(join(dir, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
    const { out } = await run(["run", dir, "--json"]);
    writeFileSync(reportPath, out);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // The CI case: `--key "$UNSET_SECRET"` passes no argument at all.
  it("`verify --key` with nothing after it fails rather than verifying nothing", async () => {
    const { code, err } = await run(["verify", reportPath, "--require-signature", "--key"]);
    expect(code).toBe(2);
    expect(err).toMatch(/--key needs a value/);
  });

  it("`verify --key --require-signature` does not read a flag as the key path", async () => {
    const { code, err } = await run(["verify", reportPath, "--key", "--require-signature"]);
    expect(code).toBe(2);
    expect(err).toMatch(/--key needs a value/);
  });

  it("`--artifact` with no value fails rather than skipping the digest recompute", async () => {
    const { code, err } = await run(["verify", reportPath, "--artifact"]);
    expect(code).toBe(2);
    expect(err).toMatch(/--artifact needs a value/);
  });

  it("`--transcripts --json` does not take `--json` as a directory name", async () => {
    const { code, err } = await run(["replay", reportPath, "--transcripts", "--json"]);
    expect(code).toBe(2);
    expect(err).toMatch(/--transcripts needs a value/);
  });
});

describe("unknown flags are rejected everywhere, not only on `run`", () => {
  let dir: string;
  let reportPath: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "assay-unknown-"));
    reportPath = join(dir, "r.json");
    writeFileSync(join(dir, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
    const { out } = await run(["run", dir, "--json"]);
    writeFileSync(reportPath, out);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // The gate that evaporated: one character, and the report is no
  // longer required to be signed.
  it("`--require-signatures` is rejected, not ignored", async () => {
    const { code, err } = await run(["verify", reportPath, "--require-signatures"]);
    expect(code).toBe(2);
    expect(err).toMatch(/unknown flag: --require-signatures/);
    expect(err).toMatch(/Did you mean --require-signature\?/);
  });

  it.each([
    ["list", ["list", "--nonsense"]],
    ["explain", ["explain", "no-sensitive-files", "--bogus"]],
    ["keygen", ["keygen", "--out-dir", "/tmp"]],
    ["diff", ["diff", "a.json", "b.json", "--bogus"]],
  ])("%s rejects a flag it does not know", async (_name, argv) => {
    const { code, err } = await run(argv);
    expect(code).toBe(2);
    expect(err).toMatch(/unknown flag/);
  });

  it("a single-dash typo is reported as a flag, not as a missing directory", async () => {
    const { code, err } = await run(["run", "-j", dir]);
    expect(code).toBe(2);
    expect(err).toMatch(/unknown flag: -j/);
    expect(err).not.toMatch(/No directory/);
  });
});

describe("flags may precede the positional argument", () => {
  let dir: string;
  let reportPath: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "assay-order-"));
    reportPath = join(dir, "r.json");
    writeFileSync(join(dir, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
    const { out } = await run(["run", dir, "--json"]);
    writeFileSync(reportPath, out);
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // `assay verify --key k.pub.pem report.json` used to read `k.pub.pem`
  // as the report and fail with a JSON parse error naming the wrong file.
  it("`verify --artifact <dir> <report>` finds the report", async () => {
    const { code, out, err } = await run(["verify", "--artifact", dir, reportPath]);
    // The digest will not match — the report file itself now sits in
    // the directory it describes. The point is that the REPORT was
    // read, so the failure is a digest mismatch reported by `verify`
    // and not a JSON parse error naming the key or transcripts path.
    expect(err).not.toMatch(/JSON/);
    expect(out).toMatch(/score\s+Score recomputes/);
    expect(out).toMatch(/different artifact/);
    expect(code).toBe(1);
  });

  it("`replay --transcripts <dir> <report>` finds the report", async () => {
    const { code, err } = await run(["replay", "--transcripts", dir, reportPath]);
    // No transcripts in this report, which is the honest answer — the
    // point is that it read the REPORT and not the transcripts dir.
    expect(err).toMatch(/records no transcripts/);
    expect(err).not.toMatch(/cannot read/);
    expect(code).toBe(2);
  });
});

describe("`keygen` will not destroy an existing key", () => {
  let dir: string;
  let cwd: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-keygen-"));
    cwd = process.cwd();
    process.chdir(dir);
  });
  afterAll(() => {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses to overwrite, and says how to proceed deliberately", async () => {
    const first = await run(["keygen"]);
    expect(first.code).toBe(0);
    const keyid = /keyid\s+([0-9a-f]{16})/.exec(first.out)?.[1];
    expect(keyid).toBeDefined();

    const second = await run(["keygen"]);
    expect(second.code).toBe(2);
    expect(second.err).toMatch(/already exists/);
    expect(second.err).toMatch(/--force/);

    // And the original key is intact — anything signed with it still verifies.
    const third = await run(["keygen"]);
    expect(third.code).toBe(2);
    const again = await run(["keygen", "--out", "other"]);
    expect(again.code).toBe(0);
    expect(existsSync(join(dir, "other.pem"))).toBe(true);
  });

  it("--force replaces it when that is what you meant", async () => {
    const { code } = await run(["keygen", "--out", "forced"]);
    expect(code).toBe(0);
    const { code: again } = await run(["keygen", "--out", "forced", "--force"]);
    expect(again).toBe(0);
  });
});

describe("run: targets and mutually exclusive output formats", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-target-"));
    writeFileSync(join(dir, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // Tab-completion gives you the file, not the directory.
  it("a local FILE is named as such, not cloned as a repository", async () => {
    const { code, err } = await run(["run", join(dir, "SKILL.md")]);
    expect(code).toBe(2);
    expect(err).toMatch(/is a file/);
    expect(err).toMatch(/directory/);
    // The old answer accused the user's own file of being private.
    expect(err).not.toMatch(/private|credentials/);
  });

  it("`--json --sarif` is refused rather than one silently winning", async () => {
    const { code, err } = await run(["run", dir, "--json", "--sarif"]);
    expect(code).toBe(2);
    expect(err).toMatch(/Pick one/);
  });

  it("a missing --config file is named as missing, not surfaced as ENOENT", async () => {
    const { code, err } = await run(["run", dir, "--config", "/nope/absent.json"]);
    expect(code).toBe(2);
    expect(err).toMatch(/no config file at/);
    expect(err).not.toMatch(/ENOENT/);
  });

  it("--artifact pointing nowhere blames the path, not the report", async () => {
    const { out } = await run(["run", dir, "--json"]);
    const reportPath = join(dir, "r.json");
    writeFileSync(reportPath, out);
    const { code, err } = await run(["verify", reportPath, "--artifact", join(dir, "absent")]);
    expect(code).toBe(2);
    expect(err).toMatch(/no directory at/);
    expect(err).not.toMatch(/different artifact/);
  });
});

/**
 * The off switch for a tier that is now on by default.
 *
 * `assay setup` configures a sandbox and a model; behavioral then runs
 * on a plain `assay run` in a terminal. That makes `--no-behavioral` the
 * flag that stops a slow, metered operation — so a typo in it silently
 * doing nothing is the expensive kind of typo, and the message has to
 * name the fix rather than just refuse.
 *
 * These run under vitest, where stdout is not a TTY, so every one of
 * them is also an assertion that the CI guard holds: none of them starts
 * a sandbox, and none of them needs one.
 */
describe("--no-behavioral", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-nobehavioral-"));
    writeFileSync(
      join(dir, "SKILL.md"),
      "---\nname: t\ndescription: Use when you need a thing done well and carefully\n---\n# t\n\nSome body text that is long enough to be substantive for the checks.\n",
    );
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("is accepted rather than rejected as unknown", async () => {
    const { code, err } = await run(["run", dir, "--no-behavioral"]);
    expect(err).not.toMatch(/unknown flag/);
    expect(code).toBe(0);
  });

  it("rejects the punctuation-free typo, and names the flag meant", async () => {
    const { code, err } = await run(["run", dir, "--nobehavioral"]);
    expect(code).toBe(2);
    expect(err).toMatch(/unknown flag: --nobehavioral/);
    expect(err).toMatch(/Did you mean --no-behavioral\?/);
  });

  it("still rejects a flag that resembles nothing", async () => {
    const { code, err } = await run(["run", dir, "--behavioural-mode"]);
    expect(code).toBe(2);
    expect(err).toMatch(/unknown flag/);
  });

  // A pipeline (or a test runner) has no TTY, so the tier stays opt-in
  // and nothing is spent. Asserted by the absence of any attempt: with
  // no model configured, wanting behavioral would have said so.
  it("leaves a non-interactive run offline without anyone typing a flag", async () => {
    const { code, err, out } = await run(["run", dir]);
    expect(code).toBe(0);
    expect(err).not.toMatch(/behavioral evaluation/);
    expect(err).not.toMatch(/No model provider is configured/);
    // And the footer explains the carve-out rather than only naming a flag.
    expect(out).toMatch(/behavior axis/);
  });

  it("`--behavioral` still forces it on, and says so when it cannot", async () => {
    const { code, err } = await run([
      "run",
      dir,
      "--behavioral",
      "--provider",
      "openai",
      "--sandbox",
      "podman",
    ]);
    // No OPENAI_API_KEY in the test environment, so this is the honest
    // failure of an explicit request — exit 2, not a silent downgrade.
    expect(code).toBe(2);
    expect(err).toMatch(/not configured/);
  });

  it("resolves a contradictory command line to OFF in either order", async () => {
    for (const argv of [
      ["run", dir, "--behavioral", "--no-behavioral"],
      ["run", dir, "--no-behavioral", "--behavioral"],
    ]) {
      const { code, err } = await run([...argv, "--provider", "openai"]);
      // Had `--behavioral` won, provider resolution would have failed at
      // exit 2 the way the test above does.
      expect(err).not.toMatch(/not configured/);
      expect(code).toBe(0);
    }
  });

  it("documents both flags in `assay run --help`", async () => {
    const { code, out } = await run(["run", "--help"]);
    expect(code).toBe(0);
    expect(out).toMatch(/--no-behavioral/);
    expect(out).toMatch(/--behavioral/);
    // The section had been unreachable: the heading carries a
    // parenthetical that no longer matched the lookup key.
    expect(out).toMatch(/BEHAVIORAL OPTIONS/);
  });
});

/**
 * The default itself, driven through `cli()` with a terminal faked.
 *
 * `isInteractive()` reads `process.stdin.isTTY && process.stdout.isTTY`,
 * which is false under vitest — which is exactly why every other test in
 * this file stayed offline while this feature landed. Setting both is
 * how the interactive half gets exercised at all.
 *
 * The sandbox is deliberately named as something that cannot exist, so
 * these assert the DECISION without provisioning a container: what
 * matters is whether resolution was attempted, and what a failure to
 * resolve costs the run.
 */
describe("behavioral runs by default once configured, but only in a terminal", () => {
  const HOME = join(tmpdir(), "assay-default-on-home");
  let dir: string;
  let tty: { in?: true; out?: true };

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-default-on-"));
    writeFileSync(
      join(dir, "SKILL.md"),
      "---\nname: t\ndescription: Use when you need a thing done well and carefully\n---\n# t\n\nSome body text that is long enough to be substantive for the checks.\n",
    );
    tty = { in: process.stdin.isTTY, out: process.stdout.isTTY } as typeof tty;
  });
  afterAll(() => {
    process.stdin.isTTY = tty.in as never;
    process.stdout.isTTY = tty.out as never;
    delete process.env["OPENROUTER_API_KEY"];
    rmSync(dir, { recursive: true, force: true });
    rmSync(HOME, { recursive: true, force: true });
  });

  /** Point ASSAY_HOME at a config a finished `assay setup` would leave. */
  function configure(over: Record<string, unknown> = {}) {
    mkdirSync(HOME, { recursive: true });
    writeFileSync(
      join(HOME, "config.json"),
      JSON.stringify({
        version: 1,
        llm: { provider: "openrouter", apiKey: "sk-or-test", model: "m" },
        sandbox: { provider: "podman" },
        ...over,
      }),
    );
    process.env["ASSAY_HOME"] = HOME;
    process.stdin.isTTY = true;
    process.stdout.isTTY = true;
  }

  // The complaint, fixed: setup was the yes, and nothing else is asked.
  it("tries to run it with no flag at all, and does not fail the run when it cannot", async () => {
    configure();
    const { code, err } = await run(["run", dir, "--sandbox", "does-not-exist"]);
    // It reached sandbox resolution — so the tier was ON without anyone
    // typing `--behavioral`.
    expect(err).toMatch(/behavioral evaluation skipped/);
    expect(err).toMatch(/Unknown sandbox/);
    // And a tier WE turned on must never take down a run of offline
    // checks that would otherwise have passed.
    expect(code).toBe(0);
  });

  it("`--no-behavioral` stops it from even trying", async () => {
    configure();
    const { code, err } = await run(["run", dir, "--no-behavioral", "--sandbox", "does-not-exist"]);
    expect(err).not.toMatch(/behavioral evaluation/);
    expect(err).not.toMatch(/Unknown sandbox/);
    expect(code).toBe(0);
  });

  it("a recorded `behavioralByDefault: false` stops it too", async () => {
    configure({ behavioralByDefault: false });
    const { code, err } = await run(["run", dir, "--sandbox", "does-not-exist"]);
    expect(err).not.toMatch(/Unknown sandbox/);
    expect(code).toBe(0);
  });

  // Same config, same machine, no terminal: the guard.
  it("stays off without a TTY even though everything is configured", async () => {
    configure();
    process.stdin.isTTY = false;
    process.stdout.isTTY = false;
    const { code, err } = await run(["run", dir, "--sandbox", "does-not-exist"]);
    expect(err).not.toMatch(/Unknown sandbox/);
    expect(code).toBe(0);
  });

  // …and the escape hatch out of the guard still works.
  it("`--behavioral` forces it on without a TTY, and a failure is fatal there", async () => {
    configure();
    process.stdin.isTTY = false;
    process.stdout.isTTY = false;
    const { code, err } = await run(["run", dir, "--behavioral", "--sandbox", "does-not-exist"]);
    expect(err).toMatch(/Unknown sandbox/);
    // Asked for by name, so the failure is the answer to the question —
    // not something to shrug off.
    expect(code).toBe(2);
  });
});

/**
 * The safety property default-on must not cost us.
 *
 * `guidance.ts` already refuses to SUGGEST running an artifact whose
 * confirmed findings include `curl … | bash` to a hardcoded IP. Running
 * the behavioral tier without being asked gives the tool a way to go one
 * worse and actually run it. So the refusal has to hold at the point of
 * execution, and only for the case where it was our idea.
 */
describe("a condemned artifact is not executed on our own initiative", () => {
  const sandboxCheck = { id: "behaves-as-documented", needs: ["llm", "sandbox"] };
  const staticCheck = { id: "no-sensitive-files", needs: [] };
  const condemned: CheckReport[] = [
    {
      checkId: "no-remote-code-execution",
      checkVersion: "1.0.0",
      title: "RCE",
      category: "safety",
      determinism: "deterministic",
      weight: 5,
      axis: "safety",
      blocking: true,
      status: "fail",
      summary: "curl | bash to a hardcoded IP",
    },
  ];

  it("vetoes the sandbox check when behavioral was on by default", async () => {
    const { safetyVeto } = await import("../src/cli.js");
    const reason = safetyVeto("default", sandboxCheck, condemned);
    expect(reason).toMatch(/will not execute an artifact it has just flagged/);
    expect(reason).toMatch(/--behavioral to override/);
  });

  // Not a way to stop a security researcher from doing their job: the
  // sandbox is what the sandbox is for, and they typed the flag.
  it("does not veto a run that asked for it by name", async () => {
    const { safetyVeto } = await import("../src/cli.js");
    expect(safetyVeto("requested", sandboxCheck, condemned)).toBeNull();
  });

  it("vetoes nothing when no blocking safety check failed", async () => {
    const { safetyVeto } = await import("../src/cli.js");
    const clean: CheckReport[] = [
      { ...condemned[0]!, status: "pass", summary: "clean" },
      // A blocking failure on a DIFFERENT axis is not grounds to refuse
      // to run it — a missing manifest field is not a reverse shell.
      { ...condemned[0]!, checkId: "name-declared", axis: "integrity", status: "fail" },
      // Nor is a non-blocking safety warning.
      { ...condemned[0]!, checkId: "soft", blocking: false, status: "fail" },
    ];
    expect(safetyVeto("default", sandboxCheck, clean)).toBeNull();
  });

  it("never touches a check that does not execute anything", async () => {
    const { safetyVeto } = await import("../src/cli.js");
    expect(safetyVeto("default", staticCheck, condemned)).toBeNull();
  });
});

describe("the messages that announce and explain the new default", () => {
  it("the progress note names the cost and the way out", async () => {
    const { defaultOnNote } = await import("../src/cli.js");
    const { createTheme } = await import("../src/term.js");
    const note = defaultOnNote(createTheme());
    expect(note).toMatch(/assay setup/);
    expect(note).toMatch(/tokens and minutes/);
    expect(note).toMatch(/--no-behavioral/);
  });

  it("doctor promises what run will actually do", async () => {
    const { behavioralReadyAdvice } = await import("../src/cli.js");
    const ready = behavioralReadyAdvice({ ready: true, optedOut: false });
    expect(ready).toMatch(/by DEFAULT/);
    expect(ready).toMatch(/--no-behavioral/);
    // The carve-out has to be on screen, or "by default" is a lie in CI.
    expect(ready).toMatch(/Without a terminal/);
    // The wording that is now false must be gone.
    expect(ready).not.toMatch(/ready when you ask for it/);
    expect(ready).not.toMatch(/the behavioral tier is opt-in/);

    expect(behavioralReadyAdvice({ ready: true, optedOut: true })).toMatch(
      /turned the default off/,
    );
    expect(behavioralReadyAdvice({ ready: false, optedOut: false })).toMatch(/assay setup/);
  });
});

describe("--min-score is reachable without a config file", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-minscore-"));
    writeFileSync(
      join(dir, "SKILL.md"),
      "---\nname: t\ndescription: Use when you need a thing done well and carefully\n---\n# t\n\nSome body text that is long enough to be substantive for the checks.\n",
    );
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("fails the run below the threshold", async () => {
    const { code, err } = await run(["run", dir, "--min-score", "99.9"]);
    expect(code).toBe(1);
    expect(err).toMatch(/below the minimum 99\.9/);
    // The flag was given directly, so the message must not blame a file.
    expect(err).not.toMatch(/assay\.config\.json/);
  });

  it("passes above the threshold", async () => {
    const { code } = await run(["run", dir, "--min-score", "1"]);
    expect(code).toBe(0);
  });

  it("rejects a value outside 0-100", async () => {
    const { code, err } = await run(["run", dir, "--min-score", "500"]);
    expect(code).toBe(2);
    expect(err).toMatch(/0 to 100/);
  });
});

describe("`list` can answer which checks apply to a kind", () => {
  it("filters by --kind", async () => {
    const all = await run(["list"]);
    const plugin = await run(["list", "--kind", "plugin"]);
    expect(plugin.code).toBe(0);
    expect(plugin.out).toMatch(/for plugin/);
    // Skill-only checks must not appear in a plugin listing.
    expect(all.out).toMatch(/skill-frontmatter/);
    expect(plugin.out).not.toMatch(/skill-frontmatter/);
  });

  it("emits JSON for tooling", async () => {
    const { code, out } = await run(["list", "--json"]);
    expect(code).toBe(0);
    const parsed = JSON.parse(out) as { id: string; axis: string; blocking: boolean }[];
    expect(parsed.length).toBeGreaterThan(20);
    expect(parsed.every((c) => typeof c.id === "string" && typeof c.blocking === "boolean")).toBe(
      true,
    );
  });

  it("rejects an unknown kind rather than listing everything", async () => {
    const { code, err } = await run(["list", "--kind", "banana"]);
    expect(code).toBe(2);
    expect(err).toMatch(/unknown kind/);
  });
});

describe("a report records where and with what it was produced", () => {
  // Both fields were declared in `RunEnvironment`, documented as
  // load-bearing, and never populated: a behavioral report said an
  // artifact had been run but not where, and named its judge as the
  // literal string "(adapter default)".
  it("names the sandbox provider and both model roles", async () => {
    const { buildEnvironment } = await import("../src/cli.js");
    const env = buildEnvironment(
      {
        sandbox: { name: "e2b" },
        llm: {
          name: "openrouter",
          modelFor: (role: string) => (role === "judge" ? "judge-v1" : "driver-v1"),
          complete: () => Promise.resolve({ text: "", toolCalls: [], stopReason: "end" as const }),
        },
      },
      { privileged: false },
    );
    expect(env.sandbox?.provider).toBe("e2b");
    expect(env.models?.judge).toEqual({ provider: "openrouter", model: "judge-v1" });
    expect(env.models?.driver).toEqual({ provider: "openrouter", model: "driver-v1" });
    expect(JSON.stringify(env)).not.toMatch(/adapter default/);
  });

  it("omits both when the run had neither capability", async () => {
    const { buildEnvironment } = await import("../src/cli.js");
    const env = buildEnvironment({}, { privileged: false });
    expect(env.sandbox).toBeUndefined();
    expect(env.models).toBeUndefined();
    expect(env.runner).toMatch(/^assay\//);
  });

  it("says so rather than inventing a name when an adapter cannot report one", async () => {
    const { buildEnvironment } = await import("../src/cli.js");
    const env = buildEnvironment(
      {
        llm: {
          name: "custom",
          complete: () => Promise.resolve({ text: "", toolCalls: [], stopReason: "end" as const }),
        },
      },
      { privileged: false },
    );
    expect(env.models?.judge?.model).toBe("(unreported)");
  });
});
