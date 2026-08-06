/**
 * Things the subject digest did not cover, and the policy layer did not
 * enforce.
 *
 * The digest is the foundation of every integrity claim this tool
 * makes: `assay verify --artifact` certifies a directory against a
 * report with it, `diff` opens with "same artifact digest — any change
 * below is from Assay, not the artifact", and the case cache is keyed
 * on it. Anything it does not cover is a change the tool will swear did
 * not happen.
 *
 * It covered file contents and nothing else.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digestTree } from "../src/digest.js";
import { DirectorySource, RUNTIME_IGNORE } from "../src/sources/directory.js";
import { CONTENT_CHECKS } from "../src/checks/content.js";
import { applyWaiver, matchesGlob } from "../src/run.js";
import { parseConfig } from "../src/config.js";
import type { CheckResult } from "../src/types.js";

function src(dir: string): DirectorySource {
  return new DirectorySource(dir, { ignore: RUNTIME_IGNORE });
}

describe("the subject digest covers symlinks", () => {
  let a: string;
  let b: string;

  beforeEach(() => {
    a = mkdtempSync(join(tmpdir(), "assay-dg-a-"));
    b = mkdtempSync(join(tmpdir(), "assay-dg-b-"));
    for (const d of [a, b]) {
      writeFileSync(join(d, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
    }
  });
  afterEach(() => {
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  });

  it("notices a symlink that one tree has and the other does not", async () => {
    // The attack this makes visible: an artifact that unpacks with a
    // link to the installing user's credentials.
    symlinkSync("/etc/passwd", join(b, "creds"));
    expect(await digestTree(src(a))).not.toBe(await digestTree(src(b)));
  });

  it("notices a symlink repointed at a different target", async () => {
    symlinkSync("./SKILL.md", join(a, "link"));
    symlinkSync("/etc/passwd", join(b, "link"));
    expect(await digestTree(src(a))).not.toBe(await digestTree(src(b)));
  });

  it("still matches when the trees genuinely agree", async () => {
    symlinkSync("./SKILL.md", join(a, "link"));
    symlinkSync("./SKILL.md", join(b, "link"));
    expect(await digestTree(src(a))).toBe(await digestTree(src(b)));
  });
});

describe("the subject digest covers the executable bit", () => {
  let a: string;
  let b: string;

  beforeEach(() => {
    a = mkdtempSync(join(tmpdir(), "assay-mode-a-"));
    b = mkdtempSync(join(tmpdir(), "assay-mode-b-"));
    for (const d of [a, b]) {
      writeFileSync(join(d, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
      writeFileSync(join(d, "install.sh"), "#!/bin/sh\nrm -rf /\n");
    }
  });
  afterEach(() => {
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  });

  it("distinguishes a script that can be run from one that cannot", async () => {
    chmodSync(join(a, "install.sh"), 0o644);
    chmodSync(join(b, "install.sh"), 0o755);
    expect(await digestTree(src(a))).not.toBe(await digestTree(src(b)));
  });
});

describe("no-escaping-symlinks", () => {
  let dir: string;
  const check = CONTENT_CHECKS.find((c) => c.id === "no-escaping-symlinks")!;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-link-"));
    writeFileSync(join(dir, "SKILL.md"), "---\nname: t\ndescription: x\n---\n# t\n");
    mkdirSync(join(dir, "docs"));
    writeFileSync(join(dir, "docs", "api.md"), "# api\n");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const run = async (): Promise<CheckResult> =>
    (await check.run({
      source: src(dir),
      subject: { kind: "skill", name: "t", digest: { sha256: "x" } },
      config: {},
    } as never)) as CheckResult;

  it("is neutral when there are no symlinks at all", async () => {
    const r = await run();
    expect(r.status).toBe("neutral");
  });

  it("passes a link that stays inside the artifact", async () => {
    symlinkSync("../docs/api.md", join(dir, "docs", "alias.md"));
    const r = await run();
    expect(r.status).toBe("pass");
  });

  it("fails an absolute target", async () => {
    symlinkSync("/etc/passwd", join(dir, "creds"));
    const r = await run();
    expect(r.status).toBe("fail");
    expect(r.summary).toMatch(/points? outside/);
  });

  it("fails a home-directory target", async () => {
    symlinkSync("~/.aws/credentials", join(dir, "aws"));
    const r = await run();
    expect(r.status).toBe("fail");
  });

  it("fails a relative target that climbs out of the root", async () => {
    symlinkSync("../../../etc/hosts", join(dir, "up"));
    const r = await run();
    expect(r.status).toBe("fail");
  });

  it("blocks — this is not advisory", () => {
    expect(check.blocking).toBe(true);
    expect(check.axis).toBe("safety");
  });
});

describe("a path-scoped waiver only covers those paths", () => {
  const finding = (paths: string[]): CheckResult => ({
    status: "fail",
    summary: "2 credentials found.",
    evidence: paths.map((p) => ({ type: "file" as const, path: p })),
  });

  const policy = {
    waivers: [
      {
        check: "no-hardcoded-secrets",
        reason: "Test fixtures deliberately contain credential-shaped strings.",
        paths: ["tests/fixtures/**"],
      },
    ],
  };

  it("waives a finding entirely inside the scope", () => {
    const r = applyWaiver(
      "no-hardcoded-secrets",
      finding(["tests/fixtures/aws.txt", "tests/fixtures/nested/gh.txt"]),
      policy,
      Date.now(),
    );
    expect(r.status).toBe("neutral");
    expect(r.suppressed).toBe(true);
  });

  // The bug: `paths` was parsed and never read, so this waived the
  // check across the whole artifact — including the real leak.
  it("does NOT waive a finding that reaches outside the scope", () => {
    const r = applyWaiver(
      "no-hardcoded-secrets",
      finding(["tests/fixtures/aws.txt", "src/config.ts"]),
      policy,
      Date.now(),
    );
    expect(r.status).toBe("fail");
    expect(r.detail).toMatch(/does not cover/);
    expect(r.detail).toMatch(/src\/config\.ts/);
  });

  it("does not silently ignore a scope it cannot apply", () => {
    const r = applyWaiver(
      "no-hardcoded-secrets",
      { status: "fail", summary: "something, with no file evidence" },
      policy,
      Date.now(),
    );
    expect(r.status).toBe("fail");
    expect(r.detail).toMatch(/no file paths to scope against/);
  });

  it("an unscoped waiver still applies everywhere, as before", () => {
    const unscoped = {
      waivers: [{ check: "no-hardcoded-secrets", reason: "Vendored under a corporate CLA." }],
    };
    const r = applyWaiver("no-hardcoded-secrets", finding(["src/config.ts"]), unscoped, Date.now());
    expect(r.status).toBe("neutral");
  });
});

describe("matchesGlob", () => {
  it.each([
    ["tests/fixtures/a.txt", "tests/fixtures/**", true],
    ["tests/fixtures/deep/a.txt", "tests/fixtures/**", true],
    // `a/**` covers what is INSIDE a, not a itself — git's semantics.
    // A waiver scope is matched against file paths, so a bare directory
    // never appears on the left here anyway.
    ["tests/fixtures", "tests/fixtures/**", false],
    ["src/a.txt", "tests/fixtures/**", false],
    ["a.ts", "*.ts", true],
    ["src/a.ts", "*.ts", false],
    ["src/a.ts", "src/*.ts", true],
    ["src/deep/a.ts", "src/*.ts", false],
    ["a1.ts", "a?.ts", true],
  ])("%s vs %s → %s", (path, glob, expected) => {
    expect(matchesGlob(path, glob)).toBe(expected);
  });
});

describe("a policy file with a key we do not understand is an error", () => {
  // A misspelled gate is an absent gate, and the silence was total.
  it.each([
    ['{"minscore": 80}', /unknown key.*minscore/i],
    ['{"waiver": []}', /unknown key/i],
    ['{"disabled": ["x"]}', /unknown key/i],
  ])("rejects %s", (raw, pattern) => {
    expect(() => parseConfig(raw)).toThrow(pattern);
  });

  it("suggests the key you meant when the case is wrong", () => {
    expect(() => parseConfig('{"minscore": 80}')).toThrow(/Did you mean "minScore"/);
  });

  it("rejects a threshold given as a string rather than discarding it", () => {
    expect(() => parseConfig('{"minScore": "80"}')).toThrow(/must be a number/);
  });

  it("still accepts a valid file, including $schema", () => {
    const c = parseConfig('{"$schema": "https://example/x.json", "minScore": 80}');
    expect(c.minScore).toBe(80);
  });
});
