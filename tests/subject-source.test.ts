/**
 * `subjectSource` records WHAT was graded in a form that pins it — a git
 * commit or a directory — rather than the ephemeral clone tmpdir. Guards
 * the reproducibility fix: the resolved commit used to be computed and
 * then dropped from the report.
 */
import { describe, expect, it } from "vitest";
import { subjectSource } from "../src/cli";
import type { Materialized } from "../src/target";

const mat = (provenance: Materialized["provenance"]): Materialized => ({
  dir: "/tmp/clone-xyz",
  provenance,
  cleanup: async () => {},
});

describe("subjectSource", () => {
  it("records the resolved commit for a git target, not the tmpdir", () => {
    const s = subjectSource(
      mat({
        kind: "git",
        spec: "owner/repo",
        url: "https://github.com/owner/repo",
        resolved: "abc123",
      }),
      "/tmp/clone-xyz",
    );
    expect(s).toEqual({ type: "git", url: "https://github.com/owner/repo", commit: "abc123" });
  });

  it("falls back to directory for a local target", () => {
    const s = subjectSource(mat({ kind: "local", spec: "./my-skill" }), "/home/me/my-skill");
    expect(s).toEqual({ type: "directory", path: "/home/me/my-skill" });
  });

  it("falls back to directory for a git target with no resolved commit", () => {
    // Defensive: without a commit there is nothing reproducible to pin,
    // so it must NOT emit a git source missing its anchor.
    const s = subjectSource(
      mat({ kind: "git", spec: "owner/repo", url: "https://github.com/owner/repo" }),
      "/tmp/clone-xyz",
    );
    expect(s).toEqual({ type: "directory", path: "/tmp/clone-xyz" });
  });

  it("keeps npm as directory rather than mislabeling a sha512 as sha256", () => {
    const s = subjectSource(
      mat({ kind: "npm", spec: "pkg@1.0.0", url: "https://reg/pkg.tgz", integrity: "sha512-AAAA" }),
      "/tmp/pkg",
    );
    expect(s.type).toBe("directory");
  });
});
