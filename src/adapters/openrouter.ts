/**
 * OpenRouter LLM adapter — real-shaped, env-gated, EXCLUDED from coverage.
 *
 * OpenRouter exposes an OpenAI-compatible Chat Completions API
 * (https://openrouter.ai/api/v1) routed to ~150 models behind a single
 * key, which lets an operator switch judge models by editing one env
 * var instead of rewiring an SDK.
 *
 * Spoken directly over `fetch` via `openai-compat`, with no vendor SDK
 * — see that module for why. The SDK never fit here anyway: its
 * `ChatCompletionCreateParams` types do not match what OpenRouter
 * accepts across 150 models, so the body was hand-built and cast
 * through `unknown` regardless.
 *
 * Pinning matters: for an LLM-as-judge role we want the same model on
 * every eval so scores are reproducible across runs. We do NOT use
 * `openrouter/auto` (the smart-router) — the operator pins stable model
 * ids via OPENROUTER_JUDGE_MODEL / OPENROUTER_DRIVER_MODEL and every
 * request goes through those.
 *
 * The two roles are separate on purpose — see LlmRole in ../llm.ts.
 */
import { chatCompletion, mapFinish, safeParseArgs, type ChatCompletion } from "./openai-compat.js";
import {
  registerLlmProvider,
  type LlmProvider,
  type LlmResponse,
  type LlmToolCall,
} from "../ports.js";

const BASE_URL = process.env.OPENROUTER_BASE_URL ?? "https://openrouter.ai/api/v1";

/**
 * The JUDGE model: grades transcripts against a rubric and must return
 * strict JSON. Pinned to a strong instruction-follower — score
 * reliability is bounded by this model's rubric adherence, and a weak
 * judge produced both wildly variable scores (the same artifact scoring
 * 6.1 / 6.5 / 7.7 across identical runs) and outright rubric misreads
 * (marking a correct refusal as a failure). Pin a specific version, not
 * a moving alias, so scores stay comparable over time.
 */
function judgeModel(): string {
  return process.env.OPENROUTER_JUDGE_MODEL ?? "anthropic/claude-haiku-4.5";
}

/**
 * The DRIVER model: stands in for the end user's AI client while
 * exercising the artifact.
 *
 * The default is a current small-but-capable model (Claude Haiku 4.5),
 * not a frontier one: the eval asks "does this artifact work for a
 * normal user", and a frontier driver would flatter every artifact by
 * papering over rough instructions. It is deliberately NOT the weakest
 * option either — gpt-4o-mini, the previous default, was weak enough to
 * add its own failures (building the wrong topic, asking for
 * clarification instead of acting), which showed up as run-to-run score
 * swings that were the model's noise, not the artifact's. A capable
 * small model is the honest middle: representative of a real client,
 * consistent enough that the number means something. Override with
 * OPENROUTER_DRIVER_MODEL to pin a specific consumer tier.
 */
function driverModel(): string {
  return (
    process.env.OPENROUTER_DRIVER_MODEL ??
    process.env.OPENROUTER_MODEL ??
    "anthropic/claude-haiku-4.5"
  );
}

// OpenRouter asks for these two headers so traffic can be attributed to
// the calling app in their dashboards. This is assay identifying
// itself, so it names assay.
const APP_NAME = process.env.OPENROUTER_APP_NAME ?? "assay";
const APP_URL = process.env.OPENROUTER_APP_URL ?? "https://github.com/metahub-ai/assay";

export const openrouterLlmProvider: LlmProvider = {
  name: "openrouter",
  modelFor: (role) => (role === "judge" ? judgeModel() : driverModel()),
  async complete(input): Promise<LlmResponse> {
    const messages: Record<string, unknown>[] = [];
    if (input.system) messages.push({ role: "system", content: input.system });
    for (const m of input.messages) {
      messages.push({ role: m.role === "tool" ? "user" : m.role, content: m.content });
    }
    const completion: ChatCompletion = await chatCompletion({
      provider: "openrouter",
      baseUrl: BASE_URL,
      apiKey: process.env.OPENROUTER_API_KEY ?? "",
      timeoutMs: Number(process.env.EVAL_LLM_TIMEOUT_MS ?? 90_000),
      maxRetries: Number(process.env.EVAL_LLM_MAX_RETRIES ?? 3),
      headers: { "HTTP-Referer": APP_URL, "X-Title": APP_NAME },
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

/** Register the OpenRouter provider iff its API key is present. */
export function registerOpenRouterIfConfigured(): boolean {
  if (!process.env.OPENROUTER_API_KEY) return false;
  registerLlmProvider(openrouterLlmProvider);
  return true;
}
