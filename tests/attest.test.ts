/**
 * Signing, verification, and replay.
 *
 * These are the tests that decide whether a published Assay report
 * means anything. A verifier has to be able to answer three questions
 * without trusting the publisher: is this about the artifact I have,
 * does the score follow from the findings, and did the claimed signer
 * sign it.
 *
 * The score-consistency check is the one worth dwelling on. It holds
 * even against an attacker who HAS the signing key: re-signing an
 * altered report produces a valid signature over an inconsistent
 * document, and the recomputation catches it anyway.
 */
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPair, keyidFor, signReport, verifyReport, PAYLOAD_TYPE } from "../src/attest";
import { FileTranscriptSink, loadTranscript, replayTranscript } from "../src/transcripts";
import { MemorySource } from "../src/sources/memory";
import { digestTree } from "../src/digest";
import { scoreReport } from "../src/score";
import { cli } from "../src/cli";
import { describeSigner, hasAmbientIdentity, rekorLogIndex } from "../src/keyless";
import { fakeLlmProvider } from "./fakes";
import type { AssayReport, CheckReport } from "../src/types";
import type { JudgeVerdict, Transcript } from "../src/behavioral/types";

const keys = generateKeyPair();
let storeDir: string;

beforeAll(() => {
  storeDir = mkdtempSync(join(tmpdir(), "assay-transcripts-"));
});
afterAll(() => rmSync(storeDir, { recursive: true, force: true }));

const results: CheckReport[] = [
  {
    checkId: "a",
    checkVersion: "1.0.0",
    title: "A",
    category: "safety",
    determinism: "deterministic",
    weight: 2,
    axis: "safety",
    status: "pass",
    summary: "fine",
  },
  {
    checkId: "b",
    checkVersion: "1.0.0",
    title: "B",
    category: "safety",
    determinism: "deterministic",
    weight: 2,
    axis: "safety",
    status: "fail",
    summary: "broken",
  },
];

function makeReport(over: Partial<AssayReport> = {}): AssayReport {
  return {
    schemaVersion: "1",
    subject: {
      kind: "skill",
      name: "demo",
      source: { type: "directory", path: "." },
      digest: { sha256: "0".repeat(64) },
    },
    suite: { id: "test", version: "1.0.0", checksDigest: "abc" },
    environment: { runner: "assay/test" },
    results,
    score: scoreReport(results),
    startedAt: "2026-08-01T00:00:00.000Z",
    finishedAt: "2026-08-01T00:01:00.000Z",
    ...over,
  };
}

describe("keys", () => {
  it("generates a usable ed25519 pair", () => {
    expect(keys.privateKey).toMatch(/BEGIN PRIVATE KEY/);
    expect(keys.publicKey).toMatch(/BEGIN PUBLIC KEY/);
    expect(keys.keyid).toMatch(/^[0-9a-f]{16}$/);
  });

  it("derives a stable keyid from the public key alone", () => {
    expect(keyidFor(keys.publicKey)).toBe(keys.keyid);
  });

  it("gives different keys different ids", () => {
    expect(generateKeyPair().keyid).not.toBe(keys.keyid);
  });
});

describe("signing", () => {
  it("attaches an attestation naming the payload type and key", () => {
    const signed = signReport(makeReport(), keys);
    expect(signed.attestation).toMatchObject({
      payloadType: PAYLOAD_TYPE,
      predicateType: "https://github.com/metahub-ai/assay/spec/evidence/v1",
      keyid: keys.keyid,
    });
  });

  // Swapping a policy can flip a verdict on identical evidence, so a
  // record that omits it is not independently checkable.
  it("records the policies that produced the verdict", () => {
    const signed = signReport(makeReport(), keys);
    expect(signed.attestation?.verifier?.policies).toEqual(
      expect.arrayContaining(["assay-default@1.0.0", "test@1.0.0"]),
    );
  });

  it("does not mutate the input report", () => {
    const report = makeReport();
    signReport(report, keys);
    expect(report.attestation).toBeUndefined();
  });
});

describe("verification", () => {
  it("accepts a well-formed signed report", async () => {
    const r = await verifyReport(signReport(makeReport(), keys), { publicKey: keys.publicKey });
    expect(r.valid).toBe(true);
    expect(r.findings.find((f) => f.check === "signature")?.level).toBe("ok");
  });

  it("detects an inflated headline score", async () => {
    const signed = signReport(makeReport(), keys);
    const tampered = { ...signed, score: { ...signed.score, overall: 99.9 } };
    const r = await verifyReport(tampered, { publicKey: keys.publicKey });
    expect(r.valid).toBe(false);
    expect(r.findings.find((f) => f.check === "score")?.level).toBe("fail");
  });

  // The property that matters most: this holds even if the attacker
  // re-signs, because the score simply does not follow from the results.
  it("detects a flipped verdict EVEN WHEN correctly re-signed", async () => {
    const doctored = makeReport({
      results: results.map((x) => (x.status === "fail" ? { ...x, status: "pass" as const } : x)),
    });
    // Keep the original (now wrong) score, then sign properly.
    const withStaleScore = { ...doctored, score: scoreReport(results) };
    const resigned = signReport(withStaleScore, keys);
    const r = await verifyReport(resigned, { publicKey: keys.publicKey });
    expect(r.findings.find((f) => f.check === "signature")?.level).toBe("ok");
    expect(r.findings.find((f) => f.check === "score")?.level).toBe("fail");
    expect(r.valid).toBe(false);
  });

  it("detects a report about a different artifact", async () => {
    const source = new MemorySource({ "README.md": "hello" });
    const signed = signReport(
      makeReport({
        subject: {
          kind: "skill",
          name: "demo",
          source: { type: "directory", path: "." },
          digest: { sha256: "f".repeat(64) },
        },
      }),
      keys,
    );
    const r = await verifyReport(signed, { publicKey: keys.publicKey, source });
    expect(r.valid).toBe(false);
    expect(r.findings.find((f) => f.check === "subject")?.message).toMatch(/different artifact/);
  });

  it("confirms a matching subject digest", async () => {
    const source = new MemorySource({ "README.md": "hello" });
    const signed = signReport(
      makeReport({
        subject: {
          kind: "skill",
          name: "demo",
          source: { type: "directory", path: "." },
          digest: { sha256: await digestTree(source) },
        },
      }),
      keys,
    );
    const r = await verifyReport(signed, { publicKey: keys.publicKey, source });
    expect(r.findings.find((f) => f.check === "subject")?.level).toBe("ok");
  });

  it("rejects a signature from an unexpected key", async () => {
    const other = generateKeyPair();
    const r = await verifyReport(signReport(makeReport(), keys), { publicKey: other.publicKey });
    expect(r.valid).toBe(false);
    expect(r.findings.find((f) => f.check === "signature")?.message).toMatch(
      /not the key supplied/,
    );
  });

  it("warns on an unsigned report, and fails when signatures are required", async () => {
    const unsigned = makeReport();
    expect((await verifyReport(unsigned)).valid).toBe(true);
    expect(
      (await verifyReport(unsigned)).findings.find((f) => f.check === "signature")?.level,
    ).toBe("warn");
    const strict = await verifyReport(unsigned, { requireSignature: true });
    expect(strict.valid).toBe(false);
  });

  it("fails a withdrawn report", async () => {
    const withdrawn = makeReport({
      validity: { withdrawn: { at: "2026-08-01T00:00:00Z", reason: "check was broken" } },
    });
    const r = await verifyReport(signReport(withdrawn, keys), { publicKey: keys.publicKey });
    expect(r.valid).toBe(false);
    expect(r.findings.find((f) => f.check === "validity")?.message).toMatch(/check was broken/);
  });

  // Stale is a reason to re-run, not evidence of forgery.
  it("only WARNS on an expired report", async () => {
    const expired = makeReport({ validity: { staleAfter: "2020-01-01T00:00:00.000Z" } });
    const r = await verifyReport(signReport(expired, keys), { publicKey: keys.publicKey });
    expect(r.findings.find((f) => f.check === "validity")?.level).toBe("warn");
    expect(r.valid).toBe(true);
  });

  it("rejects an unsupported schema version outright", async () => {
    const r = await verifyReport({ ...makeReport(), schemaVersion: "9" } as never);
    expect(r.valid).toBe(false);
    expect(r.findings).toHaveLength(1);
  });

  it("returns findings per concern, not one boolean", async () => {
    // "Invalid" tells a publisher nothing; which check failed does.
    const r = await verifyReport(signReport(makeReport(), keys), { publicKey: keys.publicKey });
    expect(new Set(r.findings.map((f) => f.check))).toEqual(new Set(["score", "signature"]));
  });
});

describe("transcript store and replay", () => {
  const transcript: Transcript = {
    messages: [
      { role: "user", content: "format this" },
      { role: "assistant", content: "done" },
    ],
    toolCalls: [{ id: "1", name: "bash", input: { cmd: "ls" } }],
    durationMs: 42,
  };
  const verdict: JudgeVerdict = {
    pass: true,
    scores: { correctness: 9, instruction_adherence: 8, safety: 10, latency: 9 },
    rationale: "looked fine",
    safetyFlags: [],
  };

  it("writes a self-sufficient record and reads it back", async () => {
    const sink = new FileTranscriptSink(storeDir);
    const uri = await sink.put(
      "a".repeat(64),
      transcript,
      { kind: "skill", doc: "# Skill\nDoes a thing." },
      verdict,
    );
    expect(uri).toMatch(/^file:\/\//);

    const stored = await loadTranscript(storeDir, "a".repeat(64));
    // The rubric inputs travel WITH the transcript — a stored
    // transcript that cannot be re-judged proves only that we hashed
    // something.
    expect(stored?.context.doc).toBe("# Skill\nDoes a thing.");
    expect(stored?.verdict).toEqual(verdict);
    expect(stored?.transcript.messages).toHaveLength(2);
  });

  it("returns a public URI when a base URL is configured", async () => {
    const sink = new FileTranscriptSink(storeDir, { baseUrl: "https://cdn.example/t/" });
    const uri = await sink.put("b".repeat(64), transcript, { kind: "skill", doc: "d" }, verdict);
    expect(uri).toBe(`https://cdn.example/t/${"b".repeat(64)}.json`);
  });

  it("returns null for a transcript that was never stored", async () => {
    expect(await loadTranscript(storeDir, "c".repeat(64))).toBeNull();
  });

  it("re-judges a stored transcript and agrees with a matching verdict", async () => {
    const sink = new FileTranscriptSink(storeDir);
    await sink.put("d".repeat(64), transcript, { kind: "skill", doc: "# Doc" }, verdict);
    const stored = (await loadTranscript(storeDir, "d".repeat(64)))!;
    const outcome = await replayTranscript(stored, { llm: fakeLlmProvider });
    expect(outcome.agrees).toBe(true);
    expect(outcome.replayed.pass).toBe(true);
  });

  it("reports DISAGREEMENT when the replay reaches a different conclusion", async () => {
    // The fake judge fails any transcript carrying this marker, which
    // stands in for a judge that has genuinely changed its mind.
    const drifted: Transcript = {
      ...transcript,
      messages: [{ role: "user", content: "force-fail-verdict" }],
    };
    const sink = new FileTranscriptSink(storeDir);
    await sink.put("e".repeat(64), drifted, { kind: "skill", doc: "# Doc" }, verdict);
    const stored = (await loadTranscript(storeDir, "e".repeat(64)))!;
    const outcome = await replayTranscript(stored, { llm: fakeLlmProvider });
    expect(outcome.agrees).toBe(false);
    // Drift is surfaced even when the conclusion is what changed —
    // sustained drift on unchanged input is how judge-model swaps show up.
    expect(outcome.drift).toBeGreaterThan(0);
  });

  it("does not claim disagreement when there is no original to compare", async () => {
    const outcome = await replayTranscript(
      { version: 1, digest: "f".repeat(64), transcript, context: { kind: "skill", doc: "d" } },
      { llm: fakeLlmProvider },
    );
    expect(outcome.original).toBeNull();
    expect(outcome.agrees).toBe(true);
  });
});

describe("the attestation CLI", () => {
  let dir: string;
  let out: string;
  // A sink, not an assertion target: it exists to keep the CLI's stderr
  // out of the test runner's output. Error-message assertions live in
  // cli-args.test.ts.
  let _err: string;

  const capture = () => {
    out = "";
    _err = "";
    const so = process.stdout.write.bind(process.stdout);
    const se = process.stderr.write.bind(process.stderr);
    process.stdout.write = ((s: string) => ((out += s), true)) as typeof process.stdout.write;
    process.stderr.write = ((s: string) => ((_err += s), true)) as typeof process.stderr.write;
    return () => {
      process.stdout.write = so;
      process.stderr.write = se;
    };
  };

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "assay-cli-attest-"));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("keygen writes a 0600 private key and a publishable public key", async () => {
    const prefix = join(dir, "k");
    const restore = capture();
    const code = await cli(["keygen", "--out", prefix]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/keyid\s+[0-9a-f]{16}/);
    // A signing key readable by every process on the box is not a
    // signing key.
    expect(statSync(`${prefix}.pem`).mode & 0o777).toBe(0o600);
    expect(readFileSync(`${prefix}.pub.pem`, "utf8")).toMatch(/BEGIN PUBLIC KEY/);
  });

  it("signs a report and then verifies it", async () => {
    const reportPath = join(dir, "r.json");
    writeFileSync(reportPath, JSON.stringify(makeReport()));
    let restore = capture();
    expect(
      await cli(["sign", reportPath, "--key", join(dir, "k.pem"), "--pub", join(dir, "k.pub.pem")]),
    ).toBe(0);
    restore();

    restore = capture();
    const code = await cli(["verify", reportPath, "--key", join(dir, "k.pub.pem")]);
    restore();
    expect(code).toBe(0);
    expect(out).toMatch(/Report verified/);
  });

  it("exits 1 — not 0 — when verification fails", async () => {
    const reportPath = join(dir, "tampered.json");
    const signed = signReport(makeReport(), keys);
    writeFileSync(
      reportPath,
      JSON.stringify({ ...signed, score: { ...signed.score, overall: 99 } }),
    );
    const restore = capture();
    const code = await cli([
      "verify",
      reportPath,
      "--key",
      keys.publicKey && join(dir, "k.pub.pem"),
    ]);
    restore();
    expect(code).toBe(1);
    expect(out).toMatch(/FAILED verification/);
  });

  it("emits machine-readable findings with --json", async () => {
    const reportPath = join(dir, "j.json");
    writeFileSync(reportPath, JSON.stringify(signReport(makeReport(), keys)));
    const restore = capture();
    await cli(["verify", reportPath, "--json"]);
    restore();
    const parsed = JSON.parse(out) as { valid: boolean; findings: { check: string }[] };
    expect(parsed.findings.some((f) => f.check === "score")).toBe(true);
  });

  it("exits 2 when the report file is unreadable", async () => {
    const restore = capture();
    const code = await cli(["verify", join(dir, "nope.json")]);
    restore();
    expect(code).toBe(2);
  });

  it("exits 2 when verify is given no report", async () => {
    const restore = capture();
    expect(await cli(["verify"])).toBe(2);
    restore();
  });

  it("exits 2 when sign is missing its keys", async () => {
    const restore = capture();
    expect(await cli(["sign", join(dir, "r.json")])).toBe(2);
    restore();
  });

  it("still treats a bare path as `run`", async () => {
    const artifact = mkdtempSync(join(tmpdir(), "assay-bare-"));
    writeFileSync(
      join(artifact, "SKILL.md"),
      "---\nname: b\ndescription: Use when the user wants a tidy table from raw text\nallowed-tools: []\n---\n# B\n" +
        "word ".repeat(80),
    );
    const restore = capture();
    const code = await cli([artifact]);
    restore();
    expect(code).toBe(0);
    rmSync(artifact, { recursive: true, force: true });
  });
});

describe("keyless signing (unit)", () => {
  // The end-to-end keyless flow needs a real OIDC identity, real
  // Fulcio, and real Rekor, so it is exercised by the `keyless.yml`
  // workflow rather than mocked here. Mocking Sigstore would only
  // prove our mock matches our mock. What IS testable locally is the
  // guidance a developer hits when their environment cannot do it.
  it("detects an ambient CI identity", () => {
    expect(hasAmbientIdentity({})).toBe(false);
    expect(hasAmbientIdentity({ ACTIONS_ID_TOKEN_REQUEST_URL: "https://x" })).toBe(true);
    expect(hasAmbientIdentity({ SIGSTORE_ID_TOKEN: "t" })).toBe(true);
    expect(hasAmbientIdentity({ CI_JOB_JWT_V2: "t" })).toBe(true);
    expect(hasAmbientIdentity({ CIRCLE_OIDC_TOKEN: "t" })).toBe(true);
  });

  it("reads a Rekor log index out of a bundle", () => {
    expect(
      rekorLogIndex({ verificationMaterial: { tlogEntries: [{ logIndex: "1697019812" }] } }),
    ).toBe(1697019812);
    expect(rekorLogIndex({})).toBeUndefined();
  });

  it("describes the signing credential", () => {
    expect(
      describeSigner({
        verificationMaterial: { x509CertificateChain: { certificates: [{ rawBytes: "MII" }] } },
      }),
    ).toMatch(/Fulcio/);
    expect(describeSigner({})).toMatch(/unrecognised/);
  });
});
