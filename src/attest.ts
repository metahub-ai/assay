/**
 * Signing and verification.
 *
 * The point of this module is to make a published report *falsifiable
 * by a stranger*. Three separate questions, and a verifier answers all
 * three without trusting us:
 *
 *   1. **Is this report about the artifact I have?** Recompute the tree
 *      digest and compare to `subject.digest`.
 *   2. **Is the score consistent with the findings?** Recompute it from
 *      `results` using the named formula. A report whose score does not
 *      follow from its own evidence is the single most damning thing a
 *      verifier could find, and it is cheap to check.
 *   3. **Did the claimed signer actually sign this?** Verify the
 *      signature over the DSSE pre-authentication encoding.
 *
 * Ed25519 via `node:crypto` — no dependency, small keys, and no curve
 * or hash agility to get wrong. A Sigstore keyless flow is the better
 * long-term answer for a public registry and slots in behind the same
 * `Attestation` shape; this is the version that works offline today.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
} from "node:crypto";
import { canonicalizeForSigning, pae } from "./digest.js";
import { scoreReport } from "./score.js";
import type { AssayReport, Attestation, SourceReader } from "./index.js";
import { digestTree } from "./digest.js";
import { ASSAY_HOME } from "./version.js";

/**
 * The in-toto predicate type for an Assay evidence statement.
 *
 * A predicate type names the format under an authority the publisher
 * controls; this one previously claimed a URI under `assay.dev`, a
 * domain owned by an unrelated party, who could therefore define — or
 * redefine — what an Assay attestation means.
 */
export const EVIDENCE_PREDICATE_TYPE = `${ASSAY_HOME}/spec/evidence/v1`;

/** Media type of the signed payload. Bound into the signature by PAE. */
export const PAYLOAD_TYPE = "application/vnd.assay.report.v1+json";

export interface KeyPair {
  /** PKCS#8 PEM. Keep secret. */
  privateKey: string;
  /** SPKI PEM. Publish this. */
  publicKey: string;
  /** Short stable identifier derived from the public key. */
  keyid: string;
}

/** Generate an ed25519 keypair for signing reports. */
export function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: pub,
    keyid: keyidFor(pub),
  };
}

/** Stable short id for a public key, so a report can say which key. */
export function keyidFor(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

/**
 * Sign a report, returning it with an `attestation` attached.
 *
 * `verifier.policies` names the scoring formula and suite. It is
 * required rather than optional because swapping a policy can flip a
 * verdict on identical evidence — a record that does not name its own
 * policy is not independently checkable, which is in-toto's reasoning
 * for requiring the field even when empty.
 */
export function signReport(
  report: AssayReport,
  opts: { privateKey: string; publicKey: string; verifierId?: string },
): AssayReport {
  const payload = canonicalizeForSigning(report);
  const signature = cryptoSign(
    null, // ed25519 prehashes internally
    pae(PAYLOAD_TYPE, payload),
    createPrivateKey(opts.privateKey),
  ).toString("base64");

  const attestation: Attestation = {
    payloadType: PAYLOAD_TYPE,
    predicateType: EVIDENCE_PREDICATE_TYPE,
    signature,
    keyid: keyidFor(opts.publicKey),
    verifier: {
      id: opts.verifierId ?? `${ASSAY_HOME}/runner@${report.environment.runner}`,
      policies: [report.score.formula, `${report.suite.id}@${report.suite.version}`],
    },
  };
  return { ...report, attestation };
}

export type VerificationLevel = "ok" | "warn" | "fail";

export interface VerificationFinding {
  level: VerificationLevel;
  check: string;
  message: string;
}

export interface VerificationResult {
  /** False when any finding is `fail`. */
  valid: boolean;
  findings: VerificationFinding[];
}

export interface VerifyOptions {
  /** SPKI PEM of the key expected to have signed. */
  publicKey?: string;
  /** When supplied, the subject digest is recomputed from it. */
  source?: SourceReader;
  /** Treat a missing signature as a failure rather than a warning. */
  requireSignature?: boolean;
}

/**
 * Verify a report.
 *
 * Deliberately returns a LIST of findings rather than a boolean. "This
 * report is invalid" tells a publisher nothing; "the score does not
 * follow from the results" and "the signature is from an unexpected
 * key" are different problems with different fixes, and a verifier that
 * collapses them is unusable in a dispute.
 */
export async function verifyReport(
  report: AssayReport,
  opts: VerifyOptions = {},
): Promise<VerificationResult> {
  const findings: VerificationFinding[] = [];

  // ── 1. Structure ─────────────────────────────────────────────────
  if (report.schemaVersion !== "1") {
    findings.push({
      level: "fail",
      check: "schema",
      message: `Unsupported schemaVersion "${String(report.schemaVersion)}".`,
    });
    return { valid: false, findings };
  }
  if (!Array.isArray(report.results)) {
    findings.push({ level: "fail", check: "schema", message: "Report has no results array." });
    return { valid: false, findings };
  }

  // ── 2. Score consistency ─────────────────────────────────────────
  // The cheapest and most damning check available: does the published
  // score actually follow from the published findings?
  const recomputed = scoreReport(report.results, { formula: report.score.formula });
  // `null` means "nothing judged this axis" and must compare equal to
  // `null`, not be coerced to 0 — otherwise every unmeasured axis in a
  // valid report reads as a score mismatch.
  const mismatched = Object.entries(recomputed.axes).filter(([axis, a]) => {
    const published = report.score.axes[axis as keyof typeof report.score.axes]?.value ?? null;
    if (a.value === null || published === null) return a.value !== published;
    return Math.abs(a.value - published) > 0.05;
  });
  if (mismatched.length > 0) {
    findings.push({
      level: "fail",
      check: "score",
      message:
        `Score does not follow from the results under formula "${report.score.formula}". ` +
        `Mismatched axes: ${mismatched.map(([a]) => a).join(", ")}.`,
    });
  } else if (recomputed.overall !== report.score.overall) {
    findings.push({
      level: "fail",
      check: "score",
      message: `Overall score ${String(report.score.overall)} does not match the recomputed ${String(recomputed.overall)}.`,
    });
  } else {
    findings.push({ level: "ok", check: "score", message: "Score recomputes from the results." });
  }

  // ── 3. Subject digest ────────────────────────────────────────────
  if (opts.source) {
    const actual = await digestTree(opts.source);
    if (actual === report.subject.digest.sha256) {
      findings.push({
        level: "ok",
        check: "subject",
        message: "Subject digest matches the artifact provided.",
      });
    } else {
      findings.push({
        level: "fail",
        check: "subject",
        message:
          `This report is about a different artifact. ` +
          `Expected ${report.subject.digest.sha256.slice(0, 16)}…, got ${actual.slice(0, 16)}….`,
      });
    }
  }

  // ── 4. Freshness ─────────────────────────────────────────────────
  const withdrawn = report.validity?.withdrawn;
  if (withdrawn) {
    findings.push({
      level: "fail",
      check: "validity",
      message: `Report was withdrawn on ${withdrawn.at}: ${withdrawn.reason}`,
    });
  }
  const staleAfter = report.validity?.staleAfter;
  if (staleAfter && Date.parse(staleAfter) < Date.now()) {
    // A stale score is worse than no score, but it is not a forgery —
    // so this is a warning a consumer can weigh, not a hard failure.
    findings.push({
      level: "warn",
      check: "validity",
      message: `Report expired on ${staleAfter}; re-run before relying on it.`,
    });
  }

  // ── 5. Signature ─────────────────────────────────────────────────
  const att = report.attestation;
  if (!att) {
    findings.push({
      level: opts.requireSignature ? "fail" : "warn",
      check: "signature",
      message: "Report is unsigned; its origin cannot be established.",
    });
  } else if (!opts.publicKey) {
    findings.push({
      level: "warn",
      check: "signature",
      message: `Signed with keyid ${att.keyid ?? "(unknown)"}, but no public key was supplied to verify against.`,
    });
  } else {
    const expectedKeyid = keyidFor(opts.publicKey);
    if (att.keyid && att.keyid !== expectedKeyid) {
      findings.push({
        level: "fail",
        check: "signature",
        message: `Signed by keyid ${att.keyid}, which is not the key supplied (${expectedKeyid}).`,
      });
    } else {
      const payload = canonicalizeForSigning(report);
      let ok = false;
      try {
        ok = cryptoVerify(
          null,
          pae(att.payloadType, payload),
          createPublicKey(opts.publicKey),
          Buffer.from(att.signature, "base64"),
        );
      } catch {
        ok = false;
      }
      findings.push(
        ok
          ? {
              level: "ok",
              check: "signature",
              message: `Signature valid (keyid ${expectedKeyid}).`,
            }
          : {
              level: "fail",
              check: "signature",
              message:
                "Signature does not verify — the report has been altered or is not from this key.",
            },
      );
    }
  }

  // ── 6. Policy disclosure ─────────────────────────────────────────
  if (att && (!att.verifier || att.verifier.policies.length === 0)) {
    findings.push({
      level: "warn",
      check: "policy",
      message:
        "Attestation names no policy. Swapping a scoring policy can flip a verdict on identical evidence, so a record that omits it is not fully checkable.",
    });
  }

  return { valid: !findings.some((f) => f.level === "fail"), findings };
}
