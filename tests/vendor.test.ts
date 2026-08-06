/**
 * Provisioning: the tool installs what it needs, and only what it needs.
 *
 * Two properties are being defended here, and they pull against each
 * other. A user who asks for a behavioral run must never be told to go
 * and run npm — that is an unfinished installation wearing an
 * instruction. But a security tool that will fetch and execute any
 * package a caller names has built a remote-code-execution primitive
 * into itself, which is a much worse bargain than the convenience is
 * worth.
 *
 * The allowlist is what makes both true at once.
 */
import { describe, expect, it } from "vitest";
import {
  assayLibRoot,
  ensurePackage,
  hasPackage,
  isProvisionable,
  provisionHint,
} from "../src/vendor";

describe("the provisionable allowlist", () => {
  it("covers the two capabilities that cannot be spoken over plain HTTP", () => {
    expect(isProvisionable("e2b")).toBe(true);
    expect(isProvisionable("sigstore")).toBe(true);
  });

  it("refuses anything else, however plausible", () => {
    for (const name of ["openai", "@anthropic-ai/sdk", "lodash", "left-pad", "../evil"]) {
      expect(isProvisionable(name)).toBe(false);
    }
  });

  it("will not install a package outside the allowlist even when asked directly", async () => {
    const r = await ensurePackage("definitely-not-allowed");
    expect(r.ok).toBe(false);
    expect(r.detail).toContain("not a package assay installs");
  });

  it("no longer needs a package for any model provider", () => {
    // Every LLM adapter speaks its vendor's HTTP API. If one of these
    // ever becomes provisionable again, the onboarding regression that
    // motivated all of this has come back.
    for (const sdk of ["openai", "@anthropic-ai/sdk"]) {
      expect(isProvisionable(sdk)).toBe(false);
    }
  });
});

describe("resolution", () => {
  it("resolves from the directory that owns assay's node_modules", () => {
    const root = assayLibRoot();
    expect(root).not.toMatch(/\/dist$/);
    expect(root.startsWith("/")).toBe(true);
  });

  it("reports a package that is genuinely absent as absent", () => {
    expect(hasPackage("a-package-that-does-not-exist-anywhere")).toBe(false);
  });

  it("short-circuits when the package is already resolvable", async () => {
    // vitest itself is present, so this must not shell out to npm. If
    // it did, the allowlist check would reject it first — proving the
    // early return happened.
    const r = await ensurePackage("vitest");
    expect(r.ok).toBe(true);
  });
});

describe("the fallback message", () => {
  it("names a command that works from where assay actually resolves", () => {
    // A bare `npm install e2b` lands in the user's current directory,
    // which assay never reads. That advice looked like it worked and
    // changed nothing.
    const hint = provisionHint("e2b", "offline");
    expect(hint).toContain(`--prefix ${assayLibRoot()}`);
    expect(hint).toContain("offline");
  });

  it("offers the escape hatch that needs no package at all", () => {
    expect(provisionHint("e2b")).toContain("podman");
  });
});
