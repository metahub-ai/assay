/**
 * The OpenAI Chat Completions wire format, spoken directly.
 *
 * Shared by the `openai` and `openrouter` adapters, which differ only
 * in base URL, headers and model pinning. No vendor SDK — see
 * `./http.ts` for why, and note that the SDK never fit here anyway:
 * both adapters already hand-built the request body and cast it
 * through `unknown`, because `ChatCompletionCreateParams` does not
 * describe what OpenRouter accepts across 150 models.
 */
import { postJson } from "./http.js";

export interface ChatToolCall {
  id: string;
  function: { name: string; arguments: string };
}

export interface ChatChoice {
  message: { content: string | null; tool_calls?: ChatToolCall[] };
  finish_reason: string;
}

export interface ChatCompletion {
  choices: ChatChoice[];
  usage?: { prompt_tokens: number; completion_tokens: number };
}

export interface ChatRequest {
  baseUrl: string;
  apiKey: string;
  body: Record<string, unknown>;
  headers?: Record<string, string>;
  timeoutMs: number;
  maxRetries: number;
  provider: string;
}

export async function chatCompletion(req: ChatRequest): Promise<ChatCompletion> {
  const parsed = await postJson<ChatCompletion>({
    url: `${req.baseUrl.replace(/\/+$/, "")}/chat/completions`,
    headers: { authorization: `Bearer ${req.apiKey}`, ...req.headers },
    body: req.body,
    timeoutMs: req.timeoutMs,
    maxRetries: req.maxRetries,
    provider: req.provider,
  });
  if (!Array.isArray(parsed.choices)) {
    throw new Error(`${req.provider} returned a response with no choices.`);
  }
  return parsed;
}

/** Parse a tool call's JSON arguments, tolerating a malformed payload. */
export function safeParseArgs(args: string): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(args);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Map an OpenAI finish_reason onto our stop reasons. */
export function mapFinish(raw: string): "tool_use" | "max_tokens" | "end" {
  if (raw === "tool_calls") return "tool_use";
  if (raw === "length") return "max_tokens";
  return "end";
}
