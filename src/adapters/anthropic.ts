/**
 * Anthropic LLM adapter — real-shaped, env-gated, EXCLUDED from coverage.
 *
 * Speaks the Messages API directly over `fetch`; see `./http.ts` for
 * why there is no SDK. Registered only when `ANTHROPIC_API_KEY` is set.
 */
import { postJson } from "./http.js";
import {
  registerLlmProvider,
  type LlmProvider,
  type LlmResponse,
  type LlmToolCall,
} from "../ports.js";

interface AnthropicContentBlock {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
}

interface AnthropicMessage {
  content: AnthropicContentBlock[];
  stop_reason: string | null;
  usage?: { input_tokens: number; output_tokens: number };
}

const BASE_URL = process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com";
const MODEL = process.env.EVAL_ANTHROPIC_MODEL ?? "claude-sonnet-4-6";

/** Pinned: the Messages API is versioned by this header, not the path. */
const API_VERSION = "2023-06-01";

function mapStopReason(raw: string | null): LlmResponse["stopReason"] {
  if (raw === "tool_use") return "tool_use";
  if (raw === "max_tokens") return "max_tokens";
  return "end";
}

export const anthropicLlmProvider: LlmProvider = {
  name: "anthropic",
  modelFor: () => MODEL,
  async complete(input): Promise<LlmResponse> {
    const msg = await postJson<AnthropicMessage>({
      url: `${BASE_URL.replace(/\/+$/, "")}/v1/messages`,
      provider: "anthropic",
      headers: {
        "x-api-key": process.env.ANTHROPIC_API_KEY ?? "",
        "anthropic-version": API_VERSION,
      },
      timeoutMs: Number(process.env.EVAL_LLM_TIMEOUT_MS ?? 90_000),
      maxRetries: Number(process.env.EVAL_LLM_MAX_RETRIES ?? 3),
      body: {
        model: MODEL,
        max_tokens: input.maxTokens ?? 1024,
        ...(input.temperature !== undefined ? { temperature: input.temperature } : {}),
        ...(input.system ? { system: input.system } : {}),
        messages: input.messages.map((m) => ({
          role: m.role === "assistant" ? "assistant" : "user",
          content: m.content,
        })),
        ...(input.tools && input.tools.length > 0
          ? {
              tools: input.tools.map((t) => ({
                name: t.name,
                description: t.description,
                input_schema: t.inputSchema,
              })),
            }
          : {}),
      },
    });

    const blocks = Array.isArray(msg.content) ? msg.content : [];
    const text = blocks
      .filter((b) => b.type === "text" && typeof b.text === "string")
      .map((b) => b.text!)
      .join("");
    const toolCalls: LlmToolCall[] = blocks
      .filter((b) => b.type === "tool_use")
      .map((b) => ({ id: b.id ?? "", name: b.name ?? "", input: b.input ?? {} }));
    return {
      text,
      toolCalls,
      stopReason: mapStopReason(msg.stop_reason),
      ...(msg.usage
        ? { usage: { inputTokens: msg.usage.input_tokens, outputTokens: msg.usage.output_tokens } }
        : {}),
    };
  },
};

/** Register the Anthropic provider iff its API key is present. */
export function registerAnthropicIfConfigured(): boolean {
  if (!process.env.ANTHROPIC_API_KEY) return false;
  registerLlmProvider(anthropicLlmProvider);
  return true;
}
