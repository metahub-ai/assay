/**
 * Transcript storage and replay — the last mile of the `replayable`
 * determinism tier.
 *
 * The tier's claim is that a stranger can re-derive a behavioral
 * verdict without trusting us and without paying for a sandbox.
 * Recording a transcript digest makes tampering detectable; it does not
 * make the grade checkable, because a hash of something nobody can
 * fetch proves only that we hashed something. This module closes that
 * gap: transcripts are written somewhere addressable, and `replay`
 * re-judges a stored transcript with the pinned judge and reports
 * whether the verdict reproduces.
 *
 * The honest framing to keep in mind: replay verifies the GRADE, not
 * the run. It answers "given this transcript, was the judgement fair?"
 * — a question we can settle offline and cheaply. It does not answer
 * "is this transcript what the artifact really did?", which requires
 * re-running the sandbox. Those are different disputes and it is worth
 * being able to have the cheap one on its own.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { judgeTranscript, type JudgeConfig } from "./behavioral/judge.js";
import { verdictMean } from "./behavioral/score.js";
import type { JudgeVerdict, Transcript } from "./behavioral/types.js";
import type { ArtifactKind } from "./types.js";
import type { LlmProvider } from "./ports.js";
import type { TranscriptContext, TranscriptSink } from "./checks/behavioral.js";

/**
 * What gets written per transcript.
 *
 * The transcript alone is not replayable — re-judging needs the same
 * rubric inputs the original run used. Storing them alongside is what
 * makes the stored artifact self-sufficient; a verifier should not have
 * to reconstruct our prompt from a blog post.
 */
export interface StoredTranscript {
  version: 1;
  digest: string;
  transcript: Transcript;
  /** Rubric inputs, so the judge prompt can be rebuilt exactly. */
  context: {
    kind: ArtifactKind;
    doc: string;
    expectation?: string;
    adversarial?: boolean;
  };
  /** The verdict the original run recorded, for comparison. */
  verdict?: JudgeVerdict;
}

/**
 * Filesystem-backed transcript sink.
 *
 * Deliberately dumb: content-addressed files under a directory. That is
 * enough to serve from object storage, a static site, or a CDN, and it
 * means the store has no index to corrupt or migrate.
 */
export class FileTranscriptSink implements TranscriptSink {
  readonly #dir: string;
  readonly #baseUrl: string | null;

  constructor(dir: string, opts: { baseUrl?: string } = {}) {
    this.#dir = resolve(dir);
    this.#baseUrl = opts.baseUrl ?? null;
  }

  async put(
    digest: string,
    transcript: Transcript,
    context: TranscriptContext,
    verdict: JudgeVerdict,
  ): Promise<string | null> {
    const path = join(this.#dir, `${digest}.json`);
    const stored: StoredTranscript = {
      version: 1,
      digest,
      transcript,
      context: { ...context, kind: context.kind },
      verdict,
    };
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(stored, null, 2)}\n`, "utf8");
    return this.#baseUrl ? `${this.#baseUrl.replace(/\/+$/, "")}/${digest}.json` : `file://${path}`;
  }
}

/** Read a stored transcript back by digest. */
export async function loadTranscript(
  dir: string,
  digest: string,
): Promise<StoredTranscript | null> {
  try {
    const raw = await readFile(join(resolve(dir), `${digest}.json`), "utf8");
    const parsed = JSON.parse(raw) as StoredTranscript;
    return parsed?.version === 1 ? parsed : null;
  } catch {
    return null;
  }
}

export interface ReplayOutcome {
  digest: string;
  /** Verdict recorded by the original run, when the store has it. */
  original: JudgeVerdict | null;
  /** Verdict produced by re-judging the stored transcript. */
  replayed: JudgeVerdict;
  /** Same pass/fail conclusion. */
  agrees: boolean;
  /** Absolute difference in mean dimension score, 0–10. */
  drift: number;
}

/**
 * Re-judge a stored transcript and compare to the recorded verdict.
 *
 * Agreement is measured on the PASS/FAIL conclusion rather than on
 * exact score equality. Insisting on identical numbers would report
 * disagreement for a 9.1-vs-9.0 difference that changes nothing, and
 * would make the check useless in precisely the case it is for — an
 * actual dispute about whether an artifact passed.
 *
 * `drift` is reported alongside so a reader can see whether the judge
 * is stable even when the conclusion holds. Sustained drift with
 * unchanged inputs is the signature of a provider silently swapping the
 * model under a stable name, which nothing else in this ecosystem
 * detects.
 */
export async function replayTranscript(
  stored: StoredTranscript,
  opts: { llm: LlmProvider; config?: Partial<JudgeConfig> },
): Promise<ReplayOutcome> {
  const replayed = await judgeTranscript({
    llm: opts.llm,
    kind: stored.context.kind,
    doc: stored.context.doc,
    transcript: stored.transcript,
    ...(opts.config ? { config: opts.config } : {}),
    ...(stored.context.expectation ? { expectation: stored.context.expectation } : {}),
    ...(stored.context.adversarial ? { adversarial: true } : {}),
  });
  const original = stored.verdict ?? null;
  return {
    digest: stored.digest,
    original,
    replayed,
    agrees: original === null ? true : original.pass === replayed.pass,
    drift: original === null ? 0 : Math.abs(verdictMean(original) - verdictMean(replayed)),
  };
}
