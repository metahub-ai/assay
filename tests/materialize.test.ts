/**
 * Fetching a remote target.
 *
 * These run against a REAL git repository created in a temp directory
 * rather than a mock, because everything that has actually gone wrong
 * here is a property of git's behaviour, not of our call to it: that
 * `--branch` rejects a commit SHA, that a missing credential prompt
 * blocks forever, that a shallow clone still resolves HEAD. A stub for
 * `git` would assert our beliefs about git rather than test them.
 *
 * The npm side is stubbed, since the assertion there is about integrity
 * checking and version resolution, and a live registry would make that
 * a network test rather than a logic one.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { materialize, TargetError, type Target } from "../src/target";

const scratch: string[] = [];
function temp(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(d);
  return d;
}
afterEach(() => {
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const git = (cwd: string, ...args: string[]) =>
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@t",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@t",
    },
  }).trim();

/** A repo with two commits, a tag, and a nested skill directory. */
function makeRepo(): { path: string; head: string; first: string } {
  const dir = temp("assay-src-");
  git(dir, "init", "-q", "-b", "main");
  mkdirSync(join(dir, "skills", "pdf"), { recursive: true });
  writeFileSync(join(dir, "skills", "pdf", "SKILL.md"), "---\nname: pdf\n---\n# pdf\n");
  writeFileSync(join(dir, "README.md"), "v1");
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "first");
  const first = git(dir, "rev-parse", "HEAD");
  git(dir, "tag", "v1.0.0");
  writeFileSync(join(dir, "README.md"), "v2");
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "second");
  return { path: dir, head: git(dir, "rev-parse", "HEAD"), first };
}

const target = (over: Partial<Target> & { location: string }): Target => ({
  kind: "git",
  spec: "test/repo",
  display: "test/repo",
  ...over,
});

describe("materialize — git", () => {
  it("clones and records the resolved commit, not the ref asked for", async () => {
    const repo = makeRepo();
    const m = await materialize(target({ location: repo.path }));
    try {
      expect(existsSync(join(m.dir, "README.md"))).toBe(true);
      // The whole point: a report that says "main" is not reproducible.
      expect(m.provenance.resolved).toBe(repo.head);
      expect(m.provenance.kind).toBe("git");
    } finally {
      await m.cleanup();
    }
  });

  it("removes the temporary clone on cleanup", async () => {
    const repo = makeRepo();
    const m = await materialize(target({ location: repo.path }));
    const dir = m.dir;
    await m.cleanup();
    expect(existsSync(dir)).toBe(false);
  });

  it("checks out a tag", async () => {
    const repo = makeRepo();
    const m = await materialize(target({ location: repo.path, ref: "v1.0.0" }));
    try {
      expect(m.provenance.resolved).toBe(repo.first);
    } finally {
      await m.cleanup();
    }
  });

  // `git clone --depth 1 --branch <sha>` fails: --branch takes only a
  // branch or tag. A commit SHA is the most useful ref to pin to, so it
  // falls back to a full clone plus checkout.
  it("falls back to a full clone when the ref is a bare commit SHA", async () => {
    const repo = makeRepo();
    const m = await materialize(target({ location: repo.path, ref: repo.first }));
    try {
      expect(m.provenance.resolved).toBe(repo.first);
    } finally {
      await m.cleanup();
    }
  });

  it("narrows to a subdirectory", async () => {
    const repo = makeRepo();
    const m = await materialize(target({ location: repo.path, subdir: "skills/pdf" }));
    try {
      expect(existsSync(join(m.dir, "SKILL.md"))).toBe(true);
      expect(m.dir.endsWith(join("skills", "pdf"))).toBe(true);
    } finally {
      await m.cleanup();
    }
  });

  // A subdir comes out of a URL, so it is attacker-influenced input.
  it("refuses a subdirectory that escapes the clone", async () => {
    const repo = makeRepo();
    await expect(
      materialize(target({ location: repo.path, subdir: "../../../etc" })),
    ).rejects.toThrow(/escapes the repository/);
  });

  it("lists what is actually there when the subdirectory is missing", async () => {
    const repo = makeRepo();
    // A stale URL is the common way to land here, so the error has to
    // do better than "not found".
    await expect(
      materialize(target({ location: repo.path, subdir: "document-skills/pdf" })),
    ).rejects.toThrow(/Available under.*skills/s);
  });

  it("reports an unknown ref rather than silently taking the default branch", async () => {
    const repo = makeRepo();
    await expect(
      materialize(target({ location: repo.path, ref: "no-such-ref-anywhere" })),
    ).rejects.toThrow(/No such ref|not found/i);
  });

  it("fails clearly on a repository that does not exist", async () => {
    await expect(materialize(target({ location: "/nonexistent/repo.git" }))).rejects.toThrow(
      TargetError,
    );
  });

  it("reports progress so a slow clone does not look hung", async () => {
    const repo = makeRepo();
    const seen: string[] = [];
    const m = await materialize(target({ location: repo.path }), (msg) => seen.push(msg));
    await m.cleanup();
    expect(seen.join(" ")).toMatch(/Cloning/);
  });
});

// ── npm ──────────────────────────────────────────────────────────────

/** A real gzipped tar with a single `package/package.json` member. */
function fakeTarball(): Buffer {
  const dir = temp("assay-pack-");
  mkdirSync(join(dir, "package"));
  writeFileSync(join(dir, "package", "package.json"), JSON.stringify({ name: "x", version: "1" }));
  execFileSync("tar", ["-czf", join(dir, "p.tgz"), "-C", dir, "package"]);
  return readFileSync(join(dir, "p.tgz"));
}

function stubRegistry(body: Buffer, integrity?: string) {
  const manifest = {
    "dist-tags": { latest: "2.0.0" },
    versions: {
      "1.0.0": { dist: { tarball: "https://registry.test/x/-/x-1.0.0.tgz" } },
      "2.0.0": {
        dist: {
          tarball: "https://registry.test/x/-/x-2.0.0.tgz",
          ...(integrity ? { integrity } : {}),
        },
      },
    },
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    // `String()` on a Request yields "[object Object]"; take its url.
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.endsWith(".tgz")) return new Response(new Uint8Array(body), { status: 200 });
    return new Response(JSON.stringify(manifest), { status: 200 });
  });
}

const npmTarget = (ref?: string): Target => ({
  kind: "npm",
  spec: "npm:x",
  location: "x",
  display: "npm:x",
  ...(ref ? { ref } : {}),
});

describe("materialize — npm", () => {
  it("resolves the latest dist-tag and extracts the package", async () => {
    const body = fakeTarball();
    stubRegistry(body);
    const m = await materialize(npmTarget());
    try {
      expect(m.provenance.resolved).toBe("x@2.0.0");
      expect(existsSync(join(m.dir, "package.json"))).toBe(true);
    } finally {
      await m.cleanup();
    }
  });

  it("honours an explicit version", async () => {
    stubRegistry(fakeTarball());
    const m = await materialize(npmTarget("1.0.0"));
    try {
      expect(m.provenance.resolved).toBe("x@1.0.0");
    } finally {
      await m.cleanup();
    }
  });

  // This is a supply-chain tool. Accepting bytes that do not match the
  // registry's own hash would be indefensible.
  it("verifies the registry integrity hash and records it", async () => {
    const body = fakeTarball();
    const integrity = `sha512-${createHash("sha512").update(body).digest("base64")}`;
    stubRegistry(body, integrity);
    const m = await materialize(npmTarget());
    try {
      expect(m.provenance.integrity).toBe(integrity);
    } finally {
      await m.cleanup();
    }
  });

  it("REFUSES a tarball whose bytes do not match the published hash", async () => {
    stubRegistry(fakeTarball(), "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    await expect(materialize(npmTarget())).rejects.toThrow(/Integrity check FAILED/);
  });

  it("names recent versions when the requested one does not exist", async () => {
    stubRegistry(fakeTarball());
    await expect(materialize(npmTarget("9.9.9"))).rejects.toThrow(/Recent versions/);
  });

  // Resolving a range would mean implementing semver ordering here, and
  // grading a different version than the user believes is worse than
  // saying so.
  it("refuses a range rather than guessing which version was meant", async () => {
    stubRegistry(fakeTarball());
    await expect(materialize(npmTarget("^2.0.0"))).rejects.toThrow(/No published version/);
  });

  it("reports a package that does not exist", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("", { status: 404 }));
    await expect(materialize(npmTarget())).rejects.toThrow(/No such npm package/);
  });

  it("reports progress while resolving and downloading", async () => {
    stubRegistry(fakeTarball());
    const seen: string[] = [];
    const m = await materialize(npmTarget(), (msg) => seen.push(msg));
    await m.cleanup();
    expect(seen.join(" ")).toMatch(/Resolving.*Downloading/s);
  });
});
