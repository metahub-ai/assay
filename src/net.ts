/**
 * The constrained HTTP client granted to checks holding the `net`
 * capability.
 *
 * Deliberately not a thin wrapper around `fetch`. A check is ordinary
 * code from a stranger, and handing it unrestricted network access
 * would make the capability model theatre: a "deterministic" check
 * elsewhere in the suite means nothing if a `sampled` one can quietly
 * POST the artifact's contents somewhere.
 *
 * So: an allowlist the caller controls, a hard timeout, a redirect
 * ceiling, and a response-size cap. And every request is recorded, so a
 * report can say which external lookup contributed to a verdict rather
 * than asking the reader to take it on faith.
 */
import type { NetClient } from "./ports.js";

/** Hosts a default run may reach. Narrow on purpose. */
export const DEFAULT_ALLOWED_HOSTS = ["api.osv.dev", "osv.dev"] as const;

export interface NetOptions {
  allowedHosts?: readonly string[];
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
}

export interface RequestRecord {
  url: string;
  method: string;
  status: number | null;
  error?: string;
}

export interface RecordingNetClient extends NetClient {
  /** Everything this client was asked to fetch, in order. */
  readonly requests: readonly RequestRecord[];
}

export class NetAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NetAccessError";
  }
}

const DEFAULTS = {
  timeoutMs: 15_000,
  maxBytes: 8 * 1024 * 1024,
  maxRedirects: 3,
};

export function createNetClient(opts: NetOptions = {}): RecordingNetClient {
  const allowed = new Set((opts.allowedHosts ?? DEFAULT_ALLOWED_HOSTS).map((h) => h.toLowerCase()));
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
  const maxBytes = opts.maxBytes ?? DEFAULTS.maxBytes;
  const maxRedirects = opts.maxRedirects ?? DEFAULTS.maxRedirects;
  const requests: RequestRecord[] = [];

  const assertAllowed = (raw: string): URL => {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new NetAccessError(`Not a valid URL: ${raw}`);
    }
    // Plaintext would let anything on the path read or rewrite what a
    // verdict is based on.
    if (url.protocol !== "https:") {
      throw new NetAccessError(`Only https is permitted, got ${url.protocol}//`);
    }
    if (!allowed.has(url.hostname.toLowerCase())) {
      throw new NetAccessError(
        `Host ${url.hostname} is not on the allowlist (${[...allowed].join(", ")}).`,
      );
    }
    return url;
  };

  return {
    requests,
    async fetch(rawUrl, init) {
      const method = init?.method ?? "GET";
      let url = assertAllowed(rawUrl);

      for (let hop = 0; ; hop++) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let res: Response;
        try {
          res = await globalThis.fetch(url, {
            method,
            ...(init?.headers ? { headers: init.headers } : {}),
            ...(init?.body !== undefined ? { body: init.body } : {}),
            // Redirects are followed manually so each hop is
            // re-checked against the allowlist — `redirect: "follow"`
            // would let an allowed host bounce us anywhere.
            redirect: "manual",
            signal: controller.signal,
          });
        } catch (err) {
          const message =
            (err as Error).name === "AbortError"
              ? `timed out after ${timeoutMs}ms`
              : (err as Error).message;
          requests.push({ url: url.toString(), method, status: null, error: message });
          throw new Error(`${method} ${url.hostname}: ${message}`);
        } finally {
          clearTimeout(timer);
        }

        if (res.status >= 300 && res.status < 400) {
          const location = res.headers.get("location");
          if (!location) {
            requests.push({ url: url.toString(), method, status: res.status });
            throw new Error(`${url.hostname} returned ${res.status} with no location header`);
          }
          if (hop >= maxRedirects) {
            throw new NetAccessError(`Too many redirects from ${url.hostname}`);
          }
          url = assertAllowed(new URL(location, url).toString());
          continue;
        }

        requests.push({ url: url.toString(), method, status: res.status });
        const headers: Record<string, string> = {};
        res.headers.forEach((v, k) => (headers[k] = v));

        return {
          status: res.status,
          headers,
          async text() {
            const body = await res.text();
            if (body.length > maxBytes) {
              throw new Error(
                `Response from ${url.hostname} exceeded ${maxBytes} bytes; refusing to buffer it.`,
              );
            }
            return body;
          },
        };
      }
    },
  };
}
