/**
 * Sigstore keyless signing.
 *
 * The local ed25519 path in `attest.ts` works offline and is fine for a
 * team signing its own reports. It has one structural problem: somebody
 * has to hold the private key, and a registry publishing verdicts about
 * other people's work is exactly the kind of party whose key custody
 * everyone should be suspicious of.
 *
 * Keyless removes the key. An ephemeral keypair is generated, an OIDC
 * identity proves who is running, Fulcio issues a ~10-minute
 * certificate binding the key to that identity, the signature is
 * recorded in Rekor's public transparency log, and the private key is
 * discarded. There is nothing left to steal, and the issuance is
 * publicly auditable rather than something we assert.
 *
 * The trade-off is honest and worth stating: this requires network
 * access and an OIDC identity. In CI that identity is ambient — GitHub
 * Actions supplies it with `id-token: write`. Locally it means an
 * interactive browser flow. That is why it is opt-in rather than the
 * default.
 *
 * `sigstore` is an optional peer dependency, so this module is loaded
 * lazily and never on the offline path.
 */
import { canonicalizeForSigning } from "./digest.js";
import { PAYLOAD_TYPE } from "./attest.js";
import type { AssayReport } from "./types.js";

/** A Sigstore bundle, kept opaque so we do not couple to its schema. */
export type SigstoreBundle = Record<string, unknown>;

export class KeylessUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeylessUnavailableError";
  }
}

/**
 * True when an OIDC identity is ambient, so signing needs no browser.
 *
 * Checked explicitly rather than discovered by failure: telling someone
 * up front that they need `id-token: write` is far better than a
 * Fulcio error three steps into a release job.
 */
export function hasAmbientIdentity(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(
    env["ACTIONS_ID_TOKEN_REQUEST_URL"] ||
    env["SIGSTORE_ID_TOKEN"] ||
    // GitLab and CircleCI expose their own OIDC tokens.
    env["CI_JOB_JWT_V2"] ||
    env["CIRCLE_OIDC_TOKEN"],
  );
}

/**
 * The report is already logged, byte for byte.
 *
 * Distinct from `KeylessUnavailableError` because the outcomes are
 * opposite: unavailable means no signature exists, duplicate means one
 * already does.
 */
export class KeylessDuplicateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeylessDuplicateError";
  }
}

async function loadSigstore(): Promise<typeof import("sigstore")> {
  try {
    return await import("sigstore");
  } catch (err) {
    if (/Cannot find (module|package)/i.test((err as Error).message)) {
      throw new KeylessUnavailableError(
        "Keyless signing needs the Sigstore client:\n  npm install sigstore",
      );
    }
    throw err;
  }
}

/**
 * Sign a report keylessly, returning a Sigstore bundle.
 *
 * The payload is the same canonical form the local signer uses, so a
 * report signed either way covers exactly the same bytes — including
 * the timestamps and validity, which an earlier version of the local
 * signer wrongly excluded.
 */
export async function signKeyless(
  report: AssayReport,
  opts: { identityToken?: string } = {},
): Promise<SigstoreBundle> {
  const sigstore = await loadSigstore();
  const payload = Buffer.from(canonicalizeForSigning(report), "utf8");
  try {
    return (await sigstore.attest(payload, PAYLOAD_TYPE, {
      ...(opts.identityToken ? { identityToken: opts.identityToken } : {}),
    })) as unknown as SigstoreBundle;
  } catch (err) {
    const message = (err as Error).message;

    // Rekor is content-addressed and deduplicates. Signing the same
    // report twice returns 409 "an equivalent entry already exists",
    // which is not a failure — it is Rekor confirming the entry is in
    // the transparency log, which is the whole thing we were asking
    // for. Reporting it as an error meant re-signing an unchanged
    // report failed, and it broke our own signing workflow on any
    // re-run.
    if (/409|equivalent entry already exists/i.test(message)) {
      throw new KeylessDuplicateError(
        "This exact report is already in the Sigstore transparency log.\n" +
          "  Rekor deduplicates by content, so there is nothing to add.\n" +
          "  Verify the existing entry with `assay verify <report.json> --keyless`.",
      );
    }
    // The overwhelmingly common failure is "no identity", and the
    // default error does not say what to do about it.
    if (/identity|token|oidc/i.test(message) && !hasAmbientIdentity()) {
      throw new KeylessUnavailableError(
        `No OIDC identity available: ${message}\n` +
          "  In GitHub Actions, add `permissions: { id-token: write }` to the job.\n" +
          "  Locally, use `assay sign --key ... --pub ...` instead, or supply SIGSTORE_ID_TOKEN.",
      );
    }
    throw err;
  }
}

export interface KeylessVerifyOptions {
  /** Expected OIDC issuer, e.g. https://token.actions.githubusercontent.com */
  certificateIssuer?: string;
  /** Expected identity URI, e.g. the workflow ref that signed. */
  certificateIdentityURI?: string;
  certificateIdentityEmail?: string;
}

export interface KeylessVerification {
  valid: boolean;
  message: string;
}

/**
 * Verify a keyless signature.
 *
 * Note what this does NOT establish. A valid bundle proves that the
 * named identity signed these bytes and that the signature is in a
 * public log. It says nothing about whether that identity should be
 * trusted — which is why `cosign` refuses to run without an expected
 * identity, and why the caller is expected to pass one. "Valid
 * signature by someone" is not a security property.
 */
export async function verifyKeyless(
  report: AssayReport,
  bundle: SigstoreBundle,
  opts: KeylessVerifyOptions = {},
): Promise<KeylessVerification> {
  const sigstore = await loadSigstore();
  const payload = Buffer.from(canonicalizeForSigning(report), "utf8");
  try {
    await sigstore.verify(bundle as never, payload, {
      ...(opts.certificateIssuer ? { certificateIssuer: opts.certificateIssuer } : {}),
      ...(opts.certificateIdentityURI
        ? { certificateIdentityURI: opts.certificateIdentityURI }
        : {}),
      ...(opts.certificateIdentityEmail
        ? { certificateIdentityEmail: opts.certificateIdentityEmail }
        : {}),
    });
    const who = describeSigner(bundle);
    return {
      valid: true,
      message: opts.certificateIssuer
        ? `Keyless signature valid — signed by ${who}.`
        : `Keyless signature is cryptographically valid (${who}), but NO expected identity was supplied. ` +
          "A valid signature by an unspecified party is not a security property — pass --identity to bind it.",
    };
  } catch (err) {
    return { valid: false, message: `Keyless signature did not verify: ${(err as Error).message}` };
  }
}

/** Best-effort description of who signed, for the human-readable line. */
export function describeSigner(bundle: SigstoreBundle): string {
  const material = (bundle as { verificationMaterial?: Record<string, unknown> })
    .verificationMaterial;
  const chain = material?.["x509CertificateChain"] as
    { certificates?: { rawBytes?: string }[] } | undefined;
  const cert = chain?.certificates?.[0]?.rawBytes ?? material?.["certificate"];
  return cert ? "a Fulcio-issued certificate" : "an unrecognised credential";
}

/** Rekor entry index, when the bundle carries one. */
export function rekorLogIndex(bundle: SigstoreBundle): number | undefined {
  const entries = (
    bundle as { verificationMaterial?: { tlogEntries?: { logIndex?: string | number }[] } }
  ).verificationMaterial?.tlogEntries;
  const raw = entries?.[0]?.logIndex;
  return raw === undefined ? undefined : Number(raw);
}
