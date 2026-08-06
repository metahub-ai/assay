/**
 * The setup wizard.
 *
 * The interactive path needs a TTY and is validated by driving the real
 * binary under a pty. What is unit-tested here is everything that has a
 * decidable right answer without a human at the keyboard:
 *
 * - **Credential verification.** The rules are not obvious and each one
 *   is a judgement call. A 401 means the key is wrong and must block. A
 *   500 means the *vendor* is down, and refusing to save someone's
 *   correct key because of a provider outage would be our bug.
 * - **Refusing to run without a terminal.** A wizard that blocks a CI
 *   job on stdin that will never arrive is worse than one that errors,
 *   and this is exactly how `sentry-cli login` hangs forever.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyCredential, runSetup, SHADOWING_VARS } from "../src/setup";
import { ask, askSecret, confirm, isInteractive, NotInteractiveError, select } from "../src/prompt";
import { createTheme } from "../src/term";
import fsSync from "node:fs";

afterEach(() => {
  vi.restoreAllMocks();
  // `Object.defineProperty` is not a mock, so `restoreAllMocks` will not
  // undo it — and a leaked `isTTY: true` would make the "refuses without
  // a terminal" tests below pass for the wrong reason.
  delete (process.stdout as { isTTY?: boolean }).isTTY;
});

function stubFetch(status: number, body: unknown = {}) {
  return vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(new Response(JSON.stringify(body), { status }));
}

describe("verifyCredential", () => {
  it("accepts a key the provider recognises", async () => {
    stubFetch(200);
    expect(await verifyCredential("anthropic", "k")).toMatchObject({ ok: true });
  });

  it.each([401, 403])("rejects a key the provider refuses (%i)", async (status) => {
    stubFetch(status);
    const r = await verifyCredential("openai", "bad");
    expect(r.ok).toBe(false);
    expect(r.detail).toMatch(/rejected/);
  });

  // A vendor outage is not evidence that the user's key is wrong.
  it("does not reject a key just because the provider is down", async () => {
    stubFetch(503);
    const r = await verifyCredential("openai", "k");
    expect(r.ok).toBe(true);
    expect(r.detail).toMatch(/could not confirm/);
  });

  it("does not reject a key when the network is unreachable", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("ENOTFOUND"));
    const r = await verifyCredential("openai", "k");
    expect(r.ok).toBe(true);
    expect(r.detail).toMatch(/could not confirm — ENOTFOUND/);
  });

  it("reports remaining OpenRouter credit, which is the other thing you want to know", async () => {
    stubFetch(200, { data: { limit_remaining: 12.5 } });
    expect((await verifyCredential("openrouter", "k")).detail).toMatch(/\$12\.50/);
  });

  it("copes with an OpenRouter key that has no spending limit", async () => {
    stubFetch(200, { data: { limit_remaining: null } });
    expect(await verifyCredential("openrouter", "k")).toMatchObject({
      ok: true,
      detail: "key is live",
    });
  });

  it("sends the credential in the header each provider actually expects", async () => {
    const spy = stubFetch(200);
    await verifyCredential("anthropic", "secret");
    expect(spy.mock.calls[0]![1]).toMatchObject({
      headers: { "x-api-key": "secret", "anthropic-version": "2023-06-01" },
    });
    spy.mockClear();
    await verifyCredential("e2b", "secret");
    expect(spy.mock.calls[0]![1]).toMatchObject({ headers: { "X-API-KEY": "secret" } });
  });

  it("builds the local endpoint from the supplied base URL", async () => {
    const spy = stubFetch(200);
    await verifyCredential("local", "", "http://localhost:11434/v1/");
    expect(spy.mock.calls[0]![0]).toBe("http://localhost:11434/v1/models");
  });

  it("says so, rather than failing, for a provider it cannot check", async () => {
    expect(await verifyCredential("something-else", "k")).toMatchObject({ ok: true });
  });

  // A hung setup wizard is indistinguishable from a broken one.
  it("gives up rather than hanging on an unresponsive provider", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_u, init) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const e = new Error("aborted");
          e.name = "AbortError";
          reject(e);
        });
      });
    });
    vi.useFakeTimers();
    const promise = verifyCredential("openai", "k");
    await vi.advanceTimersByTimeAsync(11_000);
    const r = await promise;
    vi.useRealTimers();
    expect(r.detail).toMatch(/timed out/);
  });
});

describe("runSetup without a terminal", () => {
  it("explains the CI alternative instead of blocking on stdin", async () => {
    let out = "";
    const result = await runSetup({
      theme: createTheme({ color: false }),
      out: (s) => (out += s),
    });
    // The test process has no TTY, which is precisely the case tested.
    expect(result).toBeNull();
    expect(out).toMatch(/interactive terminal/);
    // Both escape hatches named, the way supabase's message does.
    expect(out).toMatch(/ANTHROPIC_API_KEY/);
    expect(out).toMatch(/E2B_API_KEY/);
    expect(out).toMatch(/assay doctor/);
  });

  it("names every variable that would shadow the stored config", () => {
    // If one of these is missed, setup writes a file that silently
    // never wins and the user cannot work out why.
    expect(SHADOWING_VARS).toEqual(
      expect.arrayContaining([
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "LOCAL_LLM_BASE_URL",
        "E2B_API_KEY",
      ]),
    );
  });
});

/**
 * Byte handling for hidden input.
 *
 * Worth testing directly rather than only under a pty, because each
 * branch is a way to corrupt or leak a credential: an echoed character
 * puts the key on screen, an unhandled Ctrl-C traps the user in a
 * prompt that raw mode has stopped generating SIGINT for, and a pasted
 * control character silently changes the value that gets saved.
 *
 * `process.stdin` is replaced with a fake that records what was written
 * so the "never echo" property is checkable.
 */
describe("askSecret byte handling", () => {
  function withFakeStdin(bytes: number[][]): { promise: Promise<string>; echoed: () => string } {
    let onData: ((b: Buffer) => void) | undefined;
    let echoed = "";
    const fake = {
      isTTY: true,
      isRaw: false,
      setRawMode: vi.fn(),
      resume: vi.fn(),
      pause: vi.fn(),
      on: (_e: string, fn: (b: Buffer) => void) => (onData = fn),
      removeListener: vi.fn(),
    };
    vi.spyOn(process, "stdin", "get").mockReturnValue(fake as never);
    // `isTTY` is UNDEFINED (not false) on a non-TTY, so there is no
    // getter to spy on — the property has to be defined outright.
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    vi.spyOn(process.stdout, "write").mockImplementation((s) => {
      echoed += String(s);
      return true;
    });
    const promise = askSecret("key");
    // The listener is registered synchronously inside the Promise body.
    for (const chunk of bytes) onData!(Buffer.from(chunk));
    return { promise, echoed: () => echoed };
  }

  const ENTER = [13];

  it("returns what was typed", async () => {
    const { promise } = withFakeStdin([[...Buffer.from("sk-secret")], ENTER]);
    expect(await promise).toBe("sk-secret");
  });

  // The entire point of the function.
  it("never echoes the characters themselves", async () => {
    const { promise, echoed } = withFakeStdin([[...Buffer.from("sk-secret")], ENTER]);
    await promise;
    expect(echoed()).not.toContain("sk-secret");
    expect(echoed()).toContain("•");
  });

  it("accepts a bare newline as submit, not only carriage return", async () => {
    const { promise } = withFakeStdin([[...Buffer.from("abc")], [10]]);
    expect(await promise).toBe("abc");
  });

  it("handles backspace", async () => {
    const { promise } = withFakeStdin([[...Buffer.from("abcX")], [127], ENTER]);
    expect(await promise).toBe("abc");
  });

  it("ignores backspace on an empty value rather than underflowing", async () => {
    const { promise } = withFakeStdin([[127], [127], [...Buffer.from("a")], ENTER]);
    expect(await promise).toBe("a");
  });

  // In raw mode the terminal does not generate SIGINT, so without this
  // the user cannot leave the prompt at all.
  it("treats Ctrl-C as a cancellation", async () => {
    const { promise } = withFakeStdin([[...Buffer.from("abc")], [3]]);
    await expect(promise).rejects.toThrow(/cancelled/);
  });

  // A pasted key can carry control characters, and silently folding them
  // into the value produces a credential that fails for no visible reason.
  it("drops control characters instead of corrupting the value", async () => {
    const { promise } = withFakeStdin([[...Buffer.from("ab"), 27, 9, ...Buffer.from("cd")], ENTER]);
    expect(await promise).toBe("abcd");
  });

  it("accepts input arriving across several chunks", async () => {
    const { promise } = withFakeStdin([
      [...Buffer.from("sk-")],
      [...Buffer.from("live-")],
      [...Buffer.from("42")],
      ENTER,
    ]);
    expect(await promise).toBe("sk-live-42");
  });

  it("restores the terminal mode on the way out", async () => {
    let captured: { setRawMode: ReturnType<typeof vi.fn> } | undefined;
    const fake = {
      isTTY: true,
      isRaw: false,
      setRawMode: vi.fn(),
      resume: vi.fn(),
      pause: vi.fn(),
      on: (_e: string, fn: (b: Buffer) => void) => setTimeout(() => fn(Buffer.from([13])), 0),
      removeListener: vi.fn(),
    };
    captured = fake;
    vi.spyOn(process, "stdin", "get").mockReturnValue(fake as never);
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    await askSecret("key");
    // Raw mode on the way in, and back to the previous value on the way out.
    expect(captured.setRawMode).toHaveBeenNthCalledWith(1, true);
    expect(captured.setRawMode).toHaveBeenLastCalledWith(false);
  });
});

describe("prompts refuse to run without a terminal", () => {
  it("knows this process is not interactive", () => {
    expect(isInteractive()).toBe(false);
  });

  // Every one of these would otherwise wait forever on stdin.
  it.each([
    ["ask", () => ask("q")],
    ["askSecret", () => askSecret("q")],
    ["confirm", () => confirm("q")],
    ["select", () => select("q", [{ value: 1, label: "a" }])],
  ])("%s throws rather than hanging", async (_name, fn) => {
    await expect(fn()).rejects.toThrow(NotInteractiveError);
  });

  it("points at the environment-variable route in its error", async () => {
    await expect(ask("q")).rejects.toThrow(/assay doctor/);
  });
});

/**
 * Stored credentials must reach every command, not only `run`.
 *
 * `assay replay` re-judges recorded transcripts and therefore needs a
 * model — but it read only the environment, so it answered "Provider
 * openrouter is not configured. Set OPENROUTER_API_KEY." minutes after
 * the wizard had confirmed that exact key was live. That is the whole
 * "configure once" promise failing on the command that most needs it.
 */
describe("stored config reaches every command", () => {
  const HOME = "/tmp/assay-cli-cfg-test";

  afterEach(() => {
    delete process.env["ASSAY_HOME"];
    delete process.env["OPENROUTER_API_KEY"];
    fsSync.rmSync(HOME, { recursive: true, force: true });
  });

  function writeConfig() {
    fsSync.mkdirSync(HOME, { recursive: true });
    fsSync.writeFileSync(
      `${HOME}/config.json`,
      JSON.stringify({
        version: 1,
        llm: { provider: "openrouter", apiKey: "sk-or-stored", model: "m" },
      }),
    );
    process.env["ASSAY_HOME"] = HOME;
  }

  it("projects the stored key into the environment before dispatching", async () => {
    writeConfig();
    const { cli } = await import("../src/cli");
    // `list` needs nothing, so it exercises the dispatch path without
    // network or a sandbox.
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    await cli(["list"]);
    write.mockRestore();
    expect(process.env["OPENROUTER_API_KEY"]).toBe("sk-or-stored");
  });

  it("does not let the stored key override one already in the environment", async () => {
    writeConfig();
    process.env["OPENROUTER_API_KEY"] = "sk-or-from-ci";
    const { cli } = await import("../src/cli");
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    await cli(["list"]);
    write.mockRestore();
    expect(process.env["OPENROUTER_API_KEY"]).toBe("sk-or-from-ci");
  });
});
