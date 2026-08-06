/**
 * The provider registries and the infra-error brand.
 *
 * Public API, so it gets tested like public API. The two behaviours
 * worth pinning are that resolution FAILS LOUDLY for an unregistered
 * provider — a framework that silently falls back would make the run
 * environment a lie — and that `SandboxInfraError` survives being
 * loaded twice, which is what its brand exists for.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  SandboxInfraError,
  _resetProviders,
  getLlmProvider,
  getSandboxProvider,
  isSandboxInfraError,
  registerLlmProvider,
  registerSandboxProvider,
  type LlmProvider,
  type SandboxProvider,
} from "../src/ports";

const sandbox: SandboxProvider = { name: "demo-sandbox", create: async () => ({}) as never };
const llm: LlmProvider = { name: "demo-llm", complete: async () => ({}) as never };

describe("provider registries", () => {
  beforeEach(() => _resetProviders());

  it("resolves a registered sandbox provider", () => {
    registerSandboxProvider(sandbox);
    expect(getSandboxProvider("demo-sandbox")).toBe(sandbox);
  });

  it("resolves a registered LLM provider", () => {
    registerLlmProvider(llm);
    expect(getLlmProvider("demo-llm")).toBe(llm);
  });

  it("throws — and names what IS registered — for an unknown sandbox", () => {
    registerSandboxProvider(sandbox);
    expect(() => getSandboxProvider("nope")).toThrow(/not registered.*demo-sandbox/s);
  });

  it("throws for an unknown LLM provider", () => {
    expect(() => getLlmProvider("nope")).toThrow(/not registered.*\(none\)/s);
  });

  it("last registration wins for the same name", () => {
    const replacement: SandboxProvider = {
      name: "demo-sandbox",
      create: async () => ({}) as never,
    };
    registerSandboxProvider(sandbox);
    registerSandboxProvider(replacement);
    expect(getSandboxProvider("demo-sandbox")).toBe(replacement);
  });

  it("keeps the two registries independent", () => {
    registerSandboxProvider(sandbox);
    expect(() => getLlmProvider("demo-sandbox")).toThrow();
  });

  // No env-var default: the caller names what it wants, and the choice
  // is recorded in the report rather than inherited from ambient state.
  it("requires an explicit name — there is no ambient default", () => {
    expect(() => (getSandboxProvider as (n?: string) => unknown)()).toThrow();
  });
});

describe("SandboxInfraError", () => {
  it("is recognised by brand", () => {
    expect(isSandboxInfraError(new SandboxInfraError("dead"))).toBe(true);
  });

  it("rejects ordinary errors, so a real bug is not excused as infra", () => {
    expect(isSandboxInfraError(new Error("ordinary"))).toBe(false);
    expect(isSandboxInfraError(null)).toBe(false);
    expect(isSandboxInfraError("string")).toBe(false);
  });

  // tsx/ESM can load a module twice, and `instanceof` across module
  // instances silently returns false — which would turn an infra
  // failure back into an artifact verdict.
  it("survives a duplicated class identity that instanceof would miss", () => {
    class Impostor extends Error {
      readonly isSandboxInfraError = true as const;
    }
    const err = new Impostor("from another module instance");
    expect(err instanceof SandboxInfraError).toBe(false);
    expect(isSandboxInfraError(err)).toBe(true);
  });

  it("carries its cause", () => {
    const cause = new Error("root");
    expect(new SandboxInfraError("wrapper", cause).cause).toBe(cause);
  });
});
