/**
 * Runner guarantees.
 *
 * Three of these encode promises the framework makes publicly and
 * would be dishonest to break: a check gets only what it declared, our
 * crash is never recorded as their failure, and a check we could not
 * run is recorded rather than silently dropped.
 */
import { describe, expect, it, vi } from "vitest";
import { CheckRegistry, defineCheck } from "../src/check";
import type { CheckContext, CheckDefinition } from "../src/check";
import { deriveValidity, runAssay } from "../src/run";
import { MemorySource } from "../src/sources/memory";
import type { RunEnvironment, Subject } from "../src/types";

const subject: Subject = {
  kind: "skill",
  name: "demo",
  source: { type: "directory", path: "/tmp/demo" },
  digest: { sha256: "0".repeat(64) },
};

const environment: RunEnvironment = { runner: "assay/0.0.1" };

function harness(checks: CheckDefinition[], over: Partial<Parameters<typeof runAssay>[0]> = {}) {
  return runAssay({
    subject,
    source: new MemorySource({ "README.md": "hello world ".repeat(40) }),
    registry: CheckRegistry.from(checks),
    suite: { id: "test", version: "1.0.0" },
    environment,
    ...over,
  });
}

const passing = (id: string) =>
  defineCheck({
    id,
    version: "1.0.0",
    title: id,
    category: "structural",
    axis: "integrity",
    determinism: "deterministic",
    run: () => ({ status: "pass", summary: "ok" }),
  });

describe("capability enforcement", () => {
  it("withholds every capability a check did not declare", async () => {
    let seen: CheckContext | null = null;
    const check = defineCheck({
      id: "peek",
      version: "1.0.0",
      title: "peek",
      category: "structural",
      axis: "integrity",
      determinism: "deterministic",
      run: (ctx) => {
        seen = ctx;
        return { status: "pass", summary: "ok" };
      },
    });
    await harness([check], {
      capabilities: {
        net: { fetch: vi.fn() } as never,
        llm: { complete: vi.fn() } as never,
        sandbox: { provision: vi.fn() } as never,
      },
    });
    // Declared nothing, so it receives nothing — even though the
    // runner had all three implementations in hand.
    expect(seen!.net).toBeUndefined();
    expect(seen!.llm).toBeUndefined();
    expect(seen!.sandbox).toBeUndefined();
    expect(seen!.now).toBeUndefined();
  });

  it("grants exactly the declared capability and no more", async () => {
    let seen: CheckContext | null = null;
    const check = defineCheck({
      id: "needs-net",
      version: "1.0.0",
      title: "needs-net",
      category: "safety",
      axis: "safety",
      determinism: "sampled",
      needs: ["net"],
      run: (ctx) => {
        seen = ctx;
        return { status: "pass", summary: "ok" };
      },
    });
    await harness([check], {
      capabilities: {
        net: { fetch: vi.fn() } as never,
        llm: { complete: vi.fn() } as never,
      },
    });
    expect(seen!.net).toBeDefined();
    expect(seen!.llm).toBeUndefined();
  });

  it("records unmet-capability checks as skip rather than dropping them", async () => {
    const check = defineCheck({
      id: "needs-llm",
      version: "1.0.0",
      title: "needs-llm",
      category: "behavioral",
      axis: "behavior",
      determinism: "replayable",
      needs: ["llm"],
      run: () => ({ status: "pass", summary: "unreachable" }),
    });
    const report = await harness([check]);
    const r = report.results.find((x) => x.checkId === "needs-llm")!;
    expect(r.status).toBe("skip");
    expect(r.summary).toMatch(/requires llm/);
  });
});

/**
 * Ordering and the veto.
 *
 * Both exist for one reason: behavioral evaluation EXECUTES the
 * artifact, and it now does so by default once a sandbox and a model are
 * configured. The registry orders checks by id for a stable suite
 * digest, which put `behaves-as-documented` near the front of the
 * alphabet and therefore near the front of the run — so the framework
 * was executing code it had not finished inspecting, and a gate could
 * not consult a safety verdict that had not happened yet.
 */
describe("expensive checks run last, and can be vetoed", () => {
  const cheap = (id: string, over: Partial<CheckDefinition> = {}) =>
    defineCheck({
      id,
      version: "1.0.0",
      title: id,
      category: "safety",
      axis: "safety",
      determinism: "deterministic",
      run: () => ({ status: "pass", summary: "ok" }),
      ...over,
    } as CheckDefinition);

  const sandboxed = (id: string) =>
    defineCheck({
      id,
      version: "1.0.0",
      title: id,
      category: "behavioral",
      axis: "behavior",
      determinism: "replayable",
      needs: ["sandbox"],
      run: () => ({ status: "pass", summary: "ran it" }),
    });

  const caps = { sandbox: { provision: vi.fn() } as never };

  it("runs a sandbox check after every offline one, whatever the ids sort to", async () => {
    const order: string[] = [];
    const note = (id: string) => ({
      run: () => {
        order.push(id);
        return { status: "pass" as const, summary: "ok" };
      },
    });
    await harness(
      [
        // Sorts FIRST by id, which is exactly the trap.
        defineCheck({
          id: "aaa-executes",
          version: "1.0.0",
          title: "aaa",
          category: "behavioral",
          axis: "behavior",
          determinism: "replayable",
          needs: ["sandbox"],
          ...note("aaa-executes"),
        }),
        cheap("zzz-static", note("zzz-static")),
      ],
      { capabilities: caps },
    );
    expect(order).toEqual(["zzz-static", "aaa-executes"]);
  });

  it("a gate sees the results decided so far and can skip the check", async () => {
    const report = await harness(
      [
        cheap("blocking-safety", {
          blocking: true,
          run: () => ({ status: "fail", summary: "curl | bash" }),
        }),
        sandboxed("aaa-executes"),
      ],
      {
        capabilities: caps,
        gate: (check, soFar) =>
          (check.needs ?? []).includes("sandbox") &&
          soFar.some((r) => r.status === "fail" && r.blocking === true && r.axis === "safety")
            ? "Not run — a blocking safety check failed."
            : null,
      },
    );
    const behavioral = report.results.find((r) => r.checkId === "aaa-executes")!;
    // Skipped, and RECORDED as skipped — an omitted result is
    // indistinguishable from a passing one.
    expect(behavioral.status).toBe("skip");
    expect(behavioral.summary).toMatch(/blocking safety check failed/);
  });

  it("lets the check run when nothing blocking failed", async () => {
    const report = await harness([cheap("fine"), sandboxed("aaa-executes")], {
      capabilities: caps,
      gate: (check, soFar) =>
        (check.needs ?? []).includes("sandbox") &&
        soFar.some((r) => r.status === "fail" && r.blocking === true && r.axis === "safety")
          ? "vetoed"
          : null,
    });
    expect(report.results.find((r) => r.checkId === "aaa-executes")!.status).toBe("pass");
  });

  it("leaves the reported order alone — results still sort by id", async () => {
    const report = await harness([sandboxed("aaa-executes"), cheap("zzz-static")], {
      capabilities: caps,
    });
    expect(report.results.map((r) => r.checkId)).toEqual(["aaa-executes", "zzz-static"]);
  });
});

describe("failure isolation", () => {
  it("records a thrown check as error, never as fail", async () => {
    const boom = defineCheck({
      id: "boom",
      version: "1.0.0",
      title: "boom",
      category: "structural",
      axis: "integrity",
      determinism: "deterministic",
      run: () => {
        throw new Error("sandbox exploded");
      },
    });
    const report = await harness([boom]);
    const r = report.results.find((x) => x.checkId === "boom")!;
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/sandbox exploded/);
    // The artifact must not be scored down for our crash — and an axis
    // we failed to measure reports no value at all rather than a zero
    // that reads as a verdict.
    expect(report.score.axes.integrity.value).toBeNull();
    expect(report.score.axes.integrity.coverage).toBe(0);
  });

  it("times out a hung check instead of hanging the run", async () => {
    const hang = defineCheck({
      id: "hang",
      version: "1.0.0",
      title: "hang",
      category: "structural",
      axis: "integrity",
      determinism: "deterministic",
      run: () => new Promise(() => {}),
    });
    const report = await harness([hang], { checkTimeoutMs: 25 });
    const r = report.results.find((x) => x.checkId === "hang")!;
    expect(r.status).toBe("error");
    expect(r.summary).toMatch(/timed out/);
  });

  it("treats a malformed return value as error, not as a pass", async () => {
    const bad = defineCheck({
      id: "bad",
      version: "1.0.0",
      title: "bad",
      category: "structural",
      axis: "integrity",
      determinism: "deterministic",
      run: () => ({ status: "definitely-fine", summary: "trust me" }) as never,
    });
    const report = await harness([bad]);
    expect(report.results.find((x) => x.checkId === "bad")!.status).toBe("error");
  });

  it("one failing check does not prevent the others from running", async () => {
    const boom = defineCheck({
      id: "boom",
      version: "1.0.0",
      title: "boom",
      category: "structural",
      axis: "integrity",
      determinism: "deterministic",
      run: () => {
        throw new Error("nope");
      },
    });
    const report = await harness([boom, passing("fine")]);
    expect(report.results.find((x) => x.checkId === "fine")!.status).toBe("pass");
  });
});

describe("report provenance", () => {
  it("stamps every result with the version that produced it", async () => {
    const report = await harness([passing("alpha")]);
    const r = report.results[0]!;
    expect(r).toMatchObject({
      checkId: "alpha",
      checkVersion: "1.0.0",
      determinism: "deterministic",
      axis: "integrity",
    });
    expect(typeof r.durationMs).toBe("number");
  });

  it("emits a suite digest covering the checks that applied", async () => {
    const a = await harness([passing("x"), passing("y")]);
    const b = await harness([passing("x"), passing("y")]);
    const c = await harness([passing("x")]);
    expect(a.suite.checksDigest).toBe(b.suite.checksDigest);
    expect(a.suite.checksDigest).not.toBe(c.suite.checksDigest);
  });

  it("orders results deterministically regardless of registration order", async () => {
    const a = await harness([passing("zulu"), passing("alpha")]);
    expect(a.results.map((r) => r.checkId)).toEqual(["alpha", "zulu"]);
  });

  it("aborts cleanly, marking unrun checks as skip", async () => {
    const ac = new AbortController();
    ac.abort();
    const report = await harness([passing("a")], { signal: ac.signal });
    expect(report.results[0]!.status).toBe("skip");
  });
});

describe("validity / shelf life", () => {
  const sampled = (id: string) =>
    defineCheck({
      id,
      version: "1.0.0",
      title: id,
      category: "safety",
      axis: "safety",
      determinism: "sampled",
      needs: ["net"],
      run: () => ({ status: "pass", summary: "ok" }),
    });

  const net = { fetch: async () => ({ status: 200, headers: {}, text: async () => "" }) } as never;

  it("omits an expiry when every result is deterministic — bytes do not rot", async () => {
    const report = await harness([passing("pure")]);
    expect(report.validity).toBeUndefined();
  });

  it("expires a report containing a sampled result", async () => {
    const report = await harness([sampled("advisory")], { capabilities: { net } });
    expect(report.validity?.staleAfter).toBeTruthy();
    const ms = Date.parse(report.validity!.staleAfter!) - Date.parse(report.finishedAt);
    expect(Math.round(ms / 86_400_000)).toBe(30);
  });

  it("takes the SHORTEST shelf life — one perishable result bounds the whole report", async () => {
    const report = await harness([passing("pure"), sampled("advisory")], {
      capabilities: { net },
    });
    const days = Math.round(
      (Date.parse(report.validity!.staleAfter!) - Date.parse(report.finishedAt)) / 86_400_000,
    );
    expect(days).toBe(30);
  });

  it("ignores skipped results — a check that produced no claim has nothing to expire", async () => {
    // `sampled` needs net; without it the check is skipped, so the
    // report is left with only deterministic claims.
    const report = await harness([passing("pure"), sampled("advisory")]);
    expect(report.results.find((r) => r.checkId === "advisory")!.status).toBe("skip");
    expect(report.validity).toBeUndefined();
  });

  it("honours a shelf-life override", async () => {
    const report = await harness([sampled("advisory")], {
      capabilities: { net },
      shelfLife: { sampled: 7 },
    });
    const days = Math.round(
      (Date.parse(report.validity!.staleAfter!) - Date.parse(report.finishedAt)) / 86_400_000,
    );
    expect(days).toBe(7);
  });

  it("can be told a tier never expires", async () => {
    const report = await harness([sampled("advisory")], {
      capabilities: { net },
      shelfLife: { sampled: null },
    });
    expect(report.validity).toBeUndefined();
  });
});

describe("deriveValidity", () => {
  const at = "2026-01-01T00:00:00.000Z";
  const r = (determinism: "deterministic" | "replayable" | "sampled", status = "pass") =>
    ({
      checkId: "c",
      checkVersion: "1.0.0",
      title: "c",
      category: "x",
      determinism,
      weight: 1,
      axis: "safety",
      status,
      summary: "s",
    }) as never;

  it("gives replayable results a longer life than sampled ones", () => {
    const replay = deriveValidity([r("replayable")], at)!;
    const sample = deriveValidity([r("sampled")], at)!;
    expect(Date.parse(replay.staleAfter!)).toBeGreaterThan(Date.parse(sample.staleAfter!));
  });

  it("returns undefined for an unparseable timestamp rather than emitting garbage", () => {
    expect(deriveValidity([r("sampled")], "not-a-date")).toBeUndefined();
  });

  it("ignores errored results", () => {
    expect(deriveValidity([r("sampled", "error")], at)).toBeUndefined();
  });
});
