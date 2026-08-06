/**
 * Target parsing.
 *
 * The load-bearing case is the `owner/repo` ambiguity: `src/utils` is a
 * valid GitHub shorthand AND a plausible local directory. Getting that
 * wrong means either failing on a path that exists, or silently cloning
 * a stranger's repository when the user meant a folder on their disk.
 * The second is much worse, so local always wins, and that is asserted
 * here rather than left to a comment.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { materialize, parseTarget, TargetError } from "../src/target";

describe("parseTarget — local paths", () => {
  it.each([".", "..", "./pkg", "../pkg", "/abs/path"])("treats %s as local", (spec) => {
    expect(parseTarget(spec).kind).toBe("local");
  });

  it("resolves a relative path to an absolute one", () => {
    expect(parseTarget("./pkg").location).toBe(resolve("./pkg"));
  });

  it("prefers an existing local directory over the GitHub shorthand", () => {
    const t = parseTarget("src/utils", true);
    expect(t.kind).toBe("local");
    expect(t.location).toBe(resolve("src/utils"));
  });

  it("falls back to GitHub when no such directory exists", () => {
    const t = parseTarget("src/utils", false);
    expect(t.kind).toBe("git");
    expect(t.location).toBe("https://github.com/src/utils.git");
  });

  it("rejects an empty spec instead of quietly evaluating the cwd", () => {
    expect(() => parseTarget("   ")).toThrow(TargetError);
  });
});

describe("parseTarget — GitHub", () => {
  it("expands owner/repo", () => {
    expect(parseTarget("anthropics/skills")).toMatchObject({
      kind: "git",
      location: "https://github.com/anthropics/skills.git",
      display: "anthropics/skills",
    });
  });

  it("carries a ref through @", () => {
    expect(parseTarget("anthropics/skills@v1.2.0")).toMatchObject({
      ref: "v1.2.0",
      location: "https://github.com/anthropics/skills.git",
    });
  });

  it("accepts the gh: prefix", () => {
    expect(parseTarget("gh:owner/repo").location).toBe("https://github.com/owner/repo.git");
  });

  it("turns a browser URL into a clone URL", () => {
    expect(parseTarget("https://github.com/owner/repo")).toMatchObject({
      kind: "git",
      location: "https://github.com/owner/repo.git",
    });
  });

  // This is the URL people actually have in their clipboard.
  it("extracts the ref and subdirectory from a /tree/ URL", () => {
    expect(
      parseTarget("https://github.com/anthropics/skills/tree/main/document-skills/pdf"),
    ).toMatchObject({
      kind: "git",
      location: "https://github.com/anthropics/skills.git",
      ref: "main",
      subdir: "document-skills/pdf",
    });
  });

  it("handles a trailing .git and trailing slashes", () => {
    expect(parseTarget("https://github.com/owner/repo.git/").location).toBe(
      "https://github.com/owner/repo.git",
    );
  });

  it("keeps an SSH remote verbatim", () => {
    expect(parseTarget("git@github.com:owner/repo.git")).toMatchObject({
      kind: "git",
      location: "git@github.com:owner/repo.git",
    });
  });

  it("strips a git+ prefix", () => {
    expect(parseTarget("git+https://gitlab.com/o/r").kind).toBe("git");
  });

  it("supports forges other than GitHub", () => {
    expect(parseTarget("https://codeberg.org/o/r/tree/v2/sub")).toMatchObject({
      location: "https://codeberg.org/o/r.git",
      ref: "v2",
      subdir: "sub",
    });
  });

  it("rejects a malformed URL rather than cloning something odd", () => {
    expect(() => parseTarget("https://")).toThrow(TargetError);
  });

  it("reads a ref from a URL fragment", () => {
    expect(parseTarget("https://github.com/owner/repo#v1.2.0").ref).toBe("v1.2.0");
  });

  it("prefers a /tree/ ref over a fragment when both appear", () => {
    expect(parseTarget("https://github.com/o/r/tree/main/sub#other").ref).toBe("main");
  });
});

/**
 * `//` is a split point, not a path separator. Every tool that used a
 * single slash has paid for it: degit had to brute-force split points
 * once nested GitLab namespaces existed, and Terraform rejected the
 * single slash because a git server can legitimately host a repo at
 * `/network.git/modules/vpc`.
 */
describe("parseTarget — subdirectories and refs in shorthand", () => {
  it("splits a subdirectory on //", () => {
    expect(parseTarget("anthropics/skills//skills/pdf")).toMatchObject({
      location: "https://github.com/anthropics/skills.git",
      subdir: "skills/pdf",
    });
  });

  // `#` when the left side is a REPO (npm, npx, degit, Yarn); `@` when
  // it is a package NAME. Both accepted, because people type both.
  it("accepts # as the ref separator", () => {
    expect(parseTarget("owner/repo#v2.0.0").ref).toBe("v2.0.0");
  });

  it("accepts @ as the ref separator", () => {
    expect(parseTarget("owner/repo@v2.0.0").ref).toBe("v2.0.0");
  });

  it("combines a subdirectory and a ref", () => {
    expect(parseTarget("owner/repo//a/b#main")).toMatchObject({ subdir: "a/b", ref: "main" });
  });

  // Found by writing the demo: `#ref//subdir` fell through the regex to
  // "no directory at ./owner/repo#main/a/b", which is a baffling error
  // for a perfectly reasonable thing to type. Both orders parse now —
  // `git check-ref-format` forbids consecutive slashes in a ref, so a
  // `//` after the `#` can only be the subdirectory marker.
  it("accepts the ref BEFORE the subdirectory too", () => {
    expect(parseTarget("owner/repo#main//a/b")).toMatchObject({ subdir: "a/b", ref: "main" });
  });

  it("agrees on both orderings", () => {
    const a = parseTarget("anthropics/skills//skills/xlsx#v2");
    const b = parseTarget("anthropics/skills#v2//skills/xlsx");
    expect(a.location).toBe(b.location);
    expect(a.subdir).toBe(b.subdir);
    expect(a.ref).toBe(b.ref);
  });

  it("keeps a slash-bearing branch name intact", () => {
    expect(parseTarget("owner/repo#feature/new-thing").ref).toBe("feature/new-thing");
  });

  it("combines a host, a subdirectory and a ref", () => {
    expect(parseTarget("ghe.example.com/o/r//pkg/a#v1")).toMatchObject({
      location: "https://ghe.example.com/o/r.git",
      subdir: "pkg/a",
      ref: "v1",
    });
  });

  // Docker's rule: a leading segment is a host only if it has a dot or
  // is exactly `localhost`. That beats gh's arity counting, which reads
  // `a/b/c` as host/owner/repo and so cannot also support a subdir.
  it("treats a dotted leading segment as a host", () => {
    expect(parseTarget("ghe.example.com/owner/repo").location).toBe(
      "https://ghe.example.com/owner/repo.git",
    );
  });

  it("treats localhost as a host", () => {
    expect(parseTarget("localhost/owner/repo").location).toBe("https://localhost/owner/repo.git");
  });

  // `owner/repo/skills/pdf` means four different things across gh, npm,
  // degit and Terraform. Rejecting it with the corrected form is Deno's
  // approach and keeps the ergonomics without the ambiguity.
  it("refuses an ambiguous single-slash path and shows both corrections", () => {
    let message = "";
    try {
      parseTarget("anthropics/skills/skills/pdf");
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toMatch(/Ambiguous/);
    expect(message).toContain("anthropics/skills//skills/pdf");
    expect(message).toContain("./anthropics/skills/skills/pdf");
  });

  it("does not complain when that path actually exists locally", () => {
    expect(parseTarget("a/b/c/d", true).kind).toBe("local");
  });
});

describe("parseTarget — npm", () => {
  it("parses an unscoped package", () => {
    expect(parseTarget("npm:left-pad")).toMatchObject({ kind: "npm", location: "left-pad" });
  });

  it("parses an unscoped package with a version", () => {
    expect(parseTarget("npm:left-pad@1.3.0")).toMatchObject({
      location: "left-pad",
      ref: "1.3.0",
    });
  });

  // The leading @ of a scope is not a version separator, and treating it
  // as one turns `@scope/pkg` into a request for package `` at version
  // `scope/pkg`.
  it("does not mistake a scope for a version", () => {
    const t = parseTarget("npm:@modelcontextprotocol/sdk");
    expect(t.location).toBe("@modelcontextprotocol/sdk");
    expect(t.ref).toBeUndefined();
  });

  it("parses a scoped package with a version", () => {
    expect(parseTarget("npm:@scope/pkg@2.1.0")).toMatchObject({
      location: "@scope/pkg",
      ref: "2.1.0",
    });
  });

  it("rejects an empty package name", () => {
    expect(() => parseTarget("npm:")).toThrow(TargetError);
  });
});

describe("materialize — local", () => {
  it("returns the directory and a no-op cleanup", async () => {
    const dir = mkdtempSync(join(tmpdir(), "assay-t-"));
    writeFileSync(join(dir, "SKILL.md"), "x");
    const m = await materialize(parseTarget(dir));
    expect(m.dir).toBe(dir);
    expect(m.provenance).toEqual({ kind: "local", spec: dir });
    await m.cleanup();
    // Cleanup must NOT delete a directory we did not create.
    expect(() => rmSync(dir, { recursive: true })).not.toThrow();
  });

  it("names both interpretations when an owner/repo-shaped path is missing", async () => {
    await expect(materialize(parseTarget("./some/owner/repo"))).rejects.toThrow(/No directory/);
  });

  it("points at the full URL when a shorthand matched nothing locally", async () => {
    // Reachable only by forcing the local branch, which is what happens
    // when a user types `owner/repo` meaning a relative path.
    const t = {
      kind: "local" as const,
      spec: "owner/repo",
      location: "/nope/owner/repo",
      display: "x",
    };
    await expect(materialize(t)).rejects.toThrow(/github\.com\/owner\/repo/);
  });
});
