/**
 * The runner version stamped into every report MUST match the published
 * package version. 0.2.1 shipped with `ASSAY_VERSION` left at "0.2.0"
 * because `npm version` only bumps package.json, so every report it
 * produced was stamped with the wrong provenance. The release workflow
 * guards this in CI, but a manual `npm publish` bypassed it — this test
 * runs in the ordinary `npm test` gate so the mismatch can't slip through
 * again.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ASSAY_VERSION } from "../src/version";

describe("ASSAY_VERSION", () => {
  it("matches package.json version", () => {
    const pkgPath = fileURLToPath(new URL("../package.json", import.meta.url));
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string };
    expect(ASSAY_VERSION).toBe(pkg.version);
  });
});
