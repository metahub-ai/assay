/**
 * One JSON POST, with a bounded timeout and bounded retries.
 *
 * Every cloud adapter used to reach its vendor through that vendor's
 * SDK, and each SDK was an optional peer dependency. The consequence
 * was an onboarding step that should never have existed: a user who
 * installed assay from the release tarball, ran `assay setup`, entered
 * a key and asked for a behavioral run was told to type
 *
 *     npm install --prefix ~/.assay/lib openai
 *
 * before the tool would work. A tool that asks you to hand-install a
 * dependency into its own private lib directory has not finished being
 * installed.
 *
 * Nothing was lost by dropping them. Each adapter makes exactly one
 * kind of request, and what the SDKs contributed over `fetch` was an
 * auth header, a timeout and a retry loop — which is this file. Doing
 * it here also keeps assay's headline claim true (no runtime
 * dependencies, self-contained tarball) and removes the ESM
 * `data:`-URL resolution failure that bare-specifier imports hit under
 * tsx.
 */

export interface PostJsonRequest {
  url: string;
  headers: Record<string, string>;
  body: unknown;
  timeoutMs: number;
  maxRetries: number;
  /** Named in errors, so the user knows which credential to check. */
  provider: string;
}

/** Status codes where trying again is reasonable. */
function retriable(status: number): boolean {
  return status === 408 || status === 409 || status === 429 || status >= 500;
}

function backoffMs(attempt: number, retryAfter: string | null): number {
  if (retryAfter) {
    const secs = Number(retryAfter);
    if (Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, 60_000);
  }
  return Math.min(500 * 2 ** attempt, 8_000);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * POST JSON and parse the JSON response.
 *
 * The timeout is per attempt rather than for the whole call: a request
 * that wedges must not be able to stall a run indefinitely, which is
 * what an SDK default of roughly ten minutes plus silent retries
 * allowed.
 */
export async function postJson<T>(req: PostJsonRequest): Promise<T> {
  let lastError = "";

  for (let attempt = 0; attempt <= req.maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), req.timeoutMs);
    try {
      const res = await fetch(req.url, {
        method: "POST",
        signal: controller.signal,
        headers: { "content-type": "application/json", ...req.headers },
        body: JSON.stringify(req.body),
      });

      if (res.ok) return (await res.json()) as T;

      // Read the body for the message: providers put the actionable
      // part ("insufficient credits", "unknown model") in there, and a
      // bare status code sends the user to a search engine.
      const detail = (await res.text().catch(() => "")).slice(0, 400);
      lastError = `HTTP ${res.status}${detail ? ` — ${detail}` : ""}`;

      // A rejected key or an unknown model will fail identically
      // forever; retrying only makes the user wait for the same answer.
      if (!retriable(res.status)) {
        throw new FinalError(`${req.provider} request failed: ${lastError}`);
      }
      if (attempt === req.maxRetries) break;
      await sleep(backoffMs(attempt, res.headers.get("retry-after")));
    } catch (err) {
      if (err instanceof FinalError) throw err;
      const e = err as Error;
      lastError = e.name === "AbortError" ? `timed out after ${req.timeoutMs}ms` : e.message;
      if (attempt === req.maxRetries) break;
      await sleep(backoffMs(attempt, null));
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(
    `${req.provider} request failed after ${req.maxRetries + 1} attempt` +
      `${req.maxRetries === 0 ? "" : "s"}: ${lastError}`,
  );
}

/** A failure that retrying cannot fix. */
class FinalError extends Error {}
