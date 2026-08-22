/**
 * NVIDIA API Catalog LLM adapter — OpenAI-compatible, env-gated,
 * EXCLUDED from coverage (it talks to a live service).
 *
 * NVIDIA's build.nvidia.com hosts 100+ foundation models (Llama,
 * Nemotron, DeepSeek, Qwen, Mistral, GLM, Phi, Gemma, …) behind a
 * single OpenAI-compatible endpoint at
 * https://integrate.api.nvidia.com/v1, reached with a personal
 * `nvapi-` key from the free developer tier. That makes it a drop-in
 * provider here: same Chat Completions shape as OpenRouter, different
 * base URL and key.
 *
 * Spoken directly over `fetch` via `openai-compat`, with no vendor SDK
 * — same rationale as every other adapter in this directory.
 *
 * Pinning matters for reproducibility: the operator pins stable ids via
 * NVIDIA_JUDGE_MODEL / NVIDIA_DRIVER_MODEL so scores stay comparable
 * across runs. The defaults are sensible, widely-available catalog ids,
 * but the exact id for any model is shown on its card at
 * build.nvidia.com — set the env vars to match what you have access to.
 */
import { chatCompletion, mapFinish, safeParseArgs, type ChatCompletion } from "./openai-compat.js";
import {
  registerLlmProvider,
  type LlmProvider,
  type LlmResponse,
  type LlmToolCall,
} from "../ports.js";

/**
 * Resolved per call, not at module load, so an operator (or a test)
 * changing the endpoint takes effect on the next request instead of
 * needing a restart — the same reason the model pins are resolved live.
 */
function baseUrl(): string {
  return process.env.NVIDIA_BASE_URL ?? "https://integrate.api.nvidia.com/v1";
}

/**
 * The JUDGE model: grades transcripts against a rubric and must return
 * strict JSON, so the default is a strong instruction-follower from the
 * catalog. Pin a specific id, not a moving alias, so scores stay
 * comparable over time.
 */
function judgeModel(): string {
  return process.env.NVIDIA_JUDGE_MODEL ?? "meta/llama-3.3-70b-instruct";
}

/**
 * The DRIVER model: stands in for the end user's AI client while
 * exercising the artifact. A small-but-capable catalog model by
 * default — representative of a real client, not a frontier model that
 * would flatter rough instructions. Override with NVIDIA_DRIVER_MODEL.
 */
function driverModel(): string {
  return (
    process.env.NVIDIA_DRIVER_MODEL ?? process.env.NVIDIA_MODEL ?? "meta/llama-3.1-8b-instruct"
  );
}

export const nvidiaLlmProvider: LlmProvider = {
  name: "nvidia",
  modelFor: (role) => (role === "judge" ? judgeModel() : driverModel()),
  async complete(input): Promise<LlmResponse> {
    const messages: Record<string, unknown>[] = [];
    if (input.system) messages.push({ role: "system", content: input.system });
    for (const m of input.messages) {
      messages.push({ role: m.role === "tool" ? "user" : m.role, content: m.content });
    }
    const completion: ChatCompletion = await chatCompletion({
      provider: "nvidia",
      baseUrl: baseUrl(),
      apiKey: process.env.NVIDIA_API_KEY ?? "",
      timeoutMs: Number(process.env.EVAL_LLM_TIMEOUT_MS ?? 90_000),
      maxRetries: Number(process.env.EVAL_LLM_MAX_RETRIES ?? 3),
      body: {
        // Resolved per call, not at module load: an operator changing
        // the pin takes effect on the next job instead of needing a
        // restart, and it keeps the adapter testable.
        model: input.role === "judge" ? judgeModel() : driverModel(),
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

/** Register the NVIDIA provider iff its API key is present. */
export function registerNvidiaIfConfigured(): boolean {
  if (!process.env.NVIDIA_API_KEY) return false;
  registerLlmProvider(nvidiaLlmProvider);
  return true;
}
