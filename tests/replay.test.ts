/**
 * Provider resolution and `assay replay`.
 *
 * The replay tests run against a real HTTP endpoint rather than a
 * stubbed provider, because the thing under test is the whole path a
 * user actually exercises: resolve a provider from the environment,
 * load the adapter lazily, speak the wire format, re-judge, compare.
 * Stubbing the provider would skip every part of that which can break.
 */
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { NoProviderError, podmanAvailable, resolveLlmProvider } from "../src/providers";
import { _resetProviders } from "../src/ports";
import { cli } from "../src/cli";
import { FileTranscriptSink } from "../src/transcripts";
import type { AssayReport } from "../src/types";
import type { JudgeVerdict, Transcript } from "../src/behavioral/types";

const PORT = 8977;
let server: Server;
let judgeAgrees = true;
let dir: string;

const PROVIDER_ENV = [
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "OPENROUTER_API_KEY",
  "LOCAL_LLM_BASE_URL",
] as const;
const saved: Record<string, string | undefined> = {};

function clearProviderEnv() {
  for (const k of PROVIDER_ENV) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
}
function restoreProviderEnv() {
  for (const k of PROVIDER_ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
}

const verdict = (pass: boolean) =>
  JSON.stringify({
    pass,
    scores: {
      correctness: pass ? 9 : 2,
      instruction_adherence: pass ? 8 : 3,
      safety: 10,
      latency: 9,
    },
    rationale: pass ? "Followed the documented workflow." : "Did not satisfy the instruction.",
    safetyFlags: [],
  });

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "assay-replay-"));
  server = createServer((req, res) => {
    let body = "";
    req
      .on("data", (d: Buffer) => (body += d))
      .on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            choices: [
              {
                message: { content: `\`\`\`json\n${verdict(judgeAgrees)}\n\`\`\`` },
                finish_reason: "stop",
              },
            ],
          }),
        );
      });
  });
  await new Promise<void>((r) => server.listen(PORT, r));
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  _resetProviders();
  restoreProviderEnv();
});

describe("resolveLlmProvider", () => {
  it("explains what to set when nothing is configured", async () => {
    clearProviderEnv();
    await expect(resolveLlmProvider()).rejects.toThrow(NoProviderError);
    await expect(resolveLlmProvider()).rejects.toThrow(/ANTHROPIC_API_KEY/);
  });

  it("auto-detects when exactly one provider is configured", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    const { provider, configured } = await resolveLlmProvider();
    expect(provider.name).toBe("local");
    expect(configured).toEqual(["local"]);
  });

  // Picking for the user would make a published grade depend on ambient
  // environment state, which is what RunEnvironment exists to prevent.
  it("REFUSES to choose when several are configured", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    process.env["ANTHROPIC_API_KEY"] = "sk-test";
    await expect(resolveLlmProvider()).rejects.toThrow(/Name one with --provider/);
  });

  it("an explicit provider wins over ambiguity", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    process.env["ANTHROPIC_API_KEY"] = "sk-test";
    expect((await resolveLlmProvider("local")).provider.name).toBe("local");
  });

  it("says which env var configures a provider that was asked for but is unset", async () => {
    clearProviderEnv();
    await expect(resolveLlmProvider("openai")).rejects.toThrow(/Set OPENAI_API_KEY/);
  });

  it("rejects an unknown provider name", async () => {
    clearProviderEnv();
    await expect(resolveLlmProvider("nope")).rejects.toThrow(/Unknown provider/);
  });
});

describe("assay replay", () => {
  let out: string;
  let err: string;
  const capture = () => {
    out = "";
    err = "";
    const so = process.stdout.write.bind(process.stdout);
    const se = process.stderr.write.bind(process.stderr);
    process.stdout.write = ((s: string) => ((out += s), true)) as typeof process.stdout.write;
    process.stderr.write = ((s: string) => ((err += s), true)) as typeof process.stderr.write;
    return () => {
      process.stdout.write = so;
      process.stderr.write = se;
    };
  };

  const transcript: Transcript = {
    messages: [
      { role: "user", content: "format this" },
      { role: "assistant", content: "done" },
    ],
    toolCalls: [],
    durationMs: 12,
  };
  const originalVerdict: JudgeVerdict = {
    pass: true,
    scores: { correctness: 9, instruction_adherence: 8, safety: 10, latency: 9 },
    rationale: "fine",
    safetyFlags: [],
  };

  let reportPath: string;
  let store: string;

  beforeAll(async () => {
    store = join(dir, "transcripts");
    const sink = new FileTranscriptSink(store);
    const digest = "b".repeat(64);
    await sink.put(digest, transcript, { kind: "skill", doc: "# Demo" }, originalVerdict);

    const report: AssayReport = {
      schemaVersion: "1",
      subject: {
        kind: "skill",
        name: "demo",
        source: { type: "directory", path: "." },
        digest: { sha256: "a".repeat(64) },
      },
      suite: { id: "t", version: "1.0.0", checksDigest: "d" },
      environment: { runner: "assay/test" },
      results: [
        {
          checkId: "behaves-as-documented",
          checkVersion: "1.0.0",
          title: "Behaves as documented",
          category: "behavioral",
          determinism: "replayable",
          weight: 5,
          axis: "behavior",
          status: "pass",
          summary: "ok",
          evidence: [{ type: "transcript", sha256: digest, turns: 2 }],
        },
      ],
      score: { formula: "assay-default@1.0.0", axes: {} as never },
      startedAt: "2026-08-01T00:00:00.000Z",
      finishedAt: "2026-08-01T00:01:00.000Z",
    };
    reportPath = join(dir, "report.json");
    writeFileSync(reportPath, JSON.stringify(report));
  });

  it("exits 2 without the required arguments", async () => {
    const restore = capture();
    expect(await cli(["replay"])).toBe(2);
    restore();
    expect(err).toMatch(/--transcripts/);
  });

  it("exits 2 for an unreadable report", async () => {
    const restore = capture();
    expect(await cli(["replay", join(dir, "nope.json"), "--transcripts", store])).toBe(2);
    restore();
  });

  it("says plainly when a report records no transcripts", async () => {
    const bare = join(dir, "bare.json");
    writeFileSync(
      bare,
      JSON.stringify({ schemaVersion: "1", results: [{ checkId: "x", evidence: [] }] }),
    );
    const restore = capture();
    const code = await cli(["replay", bare, "--transcripts", store]);
    restore();
    expect(code).toBe(2);
    expect(err).toMatch(/no transcripts/);
  });

  it("reproduces a verdict and exits 0", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    judgeAgrees = true;
    const restore = capture();
    const code = await cli(["replay", reportPath, "--transcripts", store, "--provider", "local"]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/All verdicts reproduced/);
  });

  // The case the whole tier exists for: a judge that has changed its
  // mind on identical input is exactly how a silently-swapped model
  // shows up, and nothing else in this ecosystem detects it.
  it("DETECTS disagreement, reports drift, and exits 1", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    judgeAgrees = false;
    const restore = capture();
    const code = await cli(["replay", reportPath, "--transcripts", store, "--provider", "local"]);
    restore();
    expect(code).toBe(1);
    expect(out).toMatch(/did NOT reproduce/);
    expect(out).toMatch(/drift/);
  });

  it("emits machine-readable outcomes with --json", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    judgeAgrees = true;
    const restore = capture();
    await cli(["replay", reportPath, "--transcripts", store, "--provider", "local", "--json"]);
    restore();
    const parsed = JSON.parse(out) as {
      provider: string;
      outcomes: { agrees: boolean; drift: number }[];
    };
    expect(parsed.provider).toBe("local");
    expect(parsed.outcomes[0]!.agrees).toBe(true);
  });

  it("reports a transcript the store does not have, rather than passing silently", async () => {
    clearProviderEnv();
    process.env["LOCAL_LLM_BASE_URL"] = `http://localhost:${PORT}/v1`;
    const restore = capture();
    const code = await cli([
      "replay",
      reportPath,
      "--transcripts",
      join(dir, "empty-store"),
      "--provider",
      "local",
    ]);
    restore();
    // Missing bytes are OUR storage failing, but the report is still
    // not checkable — so it is not a success either.
    expect(code).toBe(2);
  });

  it("surfaces a provider error instead of a stack trace", async () => {
    clearProviderEnv();
    const restore = capture();
    const code = await cli(["replay", reportPath, "--transcripts", store]);
    restore();
    expect(code).toBe(2);
    expect(err).toMatch(/No model provider is configured/);
  });
});

describe("podmanAvailable", () => {
  // The bug this guards: `podman info` against an installed binary with
  // an unreachable socket HANGS rather than failing, which made
  // `assay doctor` hang forever for exactly the users whose setup is
  // broken and who most need an answer.
  it("gives up rather than hanging when the runtime does not answer", async () => {
    const started = Date.now();
    const available = await podmanAvailable(150);
    expect(typeof available).toBe("boolean");
    // Whatever the answer, it must come back promptly.
    expect(Date.now() - started).toBeLessThan(3000);
  });
});
