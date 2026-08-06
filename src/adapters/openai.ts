/**
 * OpenAI LLM adapter — real-shaped, env-gated, EXCLUDED from coverage.
 *
 * Speaks the Chat Completions wire format directly through
 * `openai-compat`, with no vendor SDK. See that module for why: the SDK
 * was an optional peer dependency, which turned a behavioral run into a
 * manual `npm install` into assay's own lib directory.
 */
import { chatCompletion, mapFinish, safeParseArgs, type ChatCompletion } from "./openai-compat.js";
import {
  registerLlmProvider,
  type LlmProvider,
  type LlmResponse,
  type LlmToolCall,
} from "../ports.js";

const BASE_URL = process.env.OPENAI_BASE_URL ?? "https://api.openai.com/v1";
const MODEL = process.env.EVAL_OPENAI_MODEL ?? "gpt-4o";

export const openaiLlmProvider: LlmProvider = {
  name: "openai",
  modelFor: () => MODEL,
  async complete(input): Promise<LlmResponse> {
    const messages: Record<string, unknown>[] = [];
    if (input.system) messages.push({ role: "system", content: input.system });
    for (const m of input.messages) {
      messages.push({ role: m.role === "tool" ? "user" : m.role, content: m.content });
    }
    const completion: ChatCompletion = await chatCompletion({
      provider: "openai",
      baseUrl: BASE_URL,
      apiKey: process.env.OPENAI_API_KEY ?? "",
      timeoutMs: Number(process.env.EVAL_LLM_TIMEOUT_MS ?? 90_000),
      maxRetries: Number(process.env.EVAL_LLM_MAX_RETRIES ?? 3),
      body: {
        model: MODEL,
        max_tokens: input.maxTokens ?? 1024,
        ...(input.temperature !== undefined ? { temperature: input.temperature } : {}),
        messages,
        ...(input.tools && input.tools.length > 0
          ? {
              tools: input.tools.map((t) => ({
                type: "function",
                function: { name: t.name, description: t.description, parameters: t.inputSchema },
              })),
            }
          : {}),
      },
    });

    const choice = completion.choices[0];
    const toolCalls: LlmToolCall[] = (choice?.message.tool_calls ?? []).map((c) => ({
      id: c.id,
      name: c.function.name,
      input: safeParseArgs(c.function.arguments),
    }));
    return {
      text: choice?.message.content ?? "",
      toolCalls,
      stopReason: mapFinish(choice?.finish_reason ?? "stop"),
      ...(completion.usage
        ? {
            usage: {
              inputTokens: completion.usage.prompt_tokens,
              outputTokens: completion.usage.completion_tokens,
            },
          }
        : {}),
    };
  },
};

/** Register the OpenAI provider iff its API key is present. */
export function registerOpenAiIfConfigured(): boolean {
  if (!process.env.OPENAI_API_KEY) return false;
  registerLlmProvider(openaiLlmProvider);
  return true;
}
