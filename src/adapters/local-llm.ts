/**
 * Local LLM adapter — a REAL OpenAI-compatible chat client, the default
 * when `EVAL_LLM` is "local" (the registry default).
 *
 * Talks to any OpenAI-compatible `/chat/completions` endpoint over plain
 * `fetch` (no SDK): Ollama (default), LM Studio, llama.cpp's server, or
 * vLLM all expose this shape. No API key is required for a local model.
 *
 *   - base URL: `LOCAL_LLM_BASE_URL` (default http://localhost:11434/v1)
 *   - model:    `LOCAL_LLM_MODEL`    (default qwen2.5)
 *   - api key:  `LOCAL_LLM_API_KEY`  (optional; sent as a Bearer token)
 *
 * Tool-calling uses the OpenAI `tools` / `tool_calls` shapes, mapped to
 * the engine's `LlmTool` / `LlmToolCall`. Excluded from unit-test
 * coverage — it hits a live HTTP endpoint. The vendor-agnostic engine
 * never imports this file directly; it self-registers on import.
 */
import {
  registerLlmProvider,
  type LlmMessage,
  type LlmProvider,
  type LlmResponse,
} from "../ports.js";

const BASE_URL = process.env.LOCAL_LLM_BASE_URL ?? "http://localhost:11434/v1";
const MODEL = process.env.LOCAL_LLM_MODEL ?? "qwen2.5";

interface OpenAiToolCall {
  id?: string;
  function: { name: string; arguments: string };
}

interface OpenAiChoice {
  message: { content: string | null; tool_calls?: OpenAiToolCall[] };
  finish_reason: string;
}

interface OpenAiCompletion {
  choices: OpenAiChoice[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

function mapFinish(raw: string): LlmResponse["stopReason"] {
  if (raw === "tool_calls") return "tool_use";
  if (raw === "length") return "max_tokens";
  return "end";
}

function safeParse(args: string): Record<string, unknown> {
  try {
    const v = JSON.parse(args);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** Map our message roles to the OpenAI chat shape, threading tool ids. */
function toOpenAiMessages(
  system: string | undefined,
  messages: LlmMessage[],
): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  if (system) out.push({ role: "system", content: system });
  for (const m of messages) {
    if (m.role === "tool") {
      out.push({ role: "tool", content: m.content, tool_call_id: m.toolCallId ?? "" });
    } else {
      out.push({ role: m.role, content: m.content });
    }
  }
  return out;
}

export const localLlmProvider: LlmProvider = {
  name: "local",
  modelFor: () => MODEL,
  async complete(input): Promise<LlmResponse> {
    const body: Record<string, unknown> = {
      model: MODEL,
      max_tokens: input.maxTokens ?? 1024,
      messages: toOpenAiMessages(input.system, input.messages),
    };
    if (input.temperature !== undefined) body["temperature"] = input.temperature;
    if (input.tools && input.tools.length > 0) {
      body["tools"] = input.tools.map((t) => ({
        type: "function",
        function: { name: t.name, description: t.description, parameters: t.inputSchema },
      }));
    }
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (process.env.LOCAL_LLM_API_KEY) {
      headers["authorization"] = `Bearer ${process.env.LOCAL_LLM_API_KEY}`;
    }
    // Bounded: a local model can genuinely take minutes, but "forever"
    // used to hang the single-threaded worker on a dead endpoint.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), Number(process.env.EVAL_LLM_TIMEOUT_MS ?? 180_000));
    let res: Response;
    try {
      res = await fetch(`${BASE_URL.replace(/\/$/, "")}/chat/completions`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: ac.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`local LLM request failed (${res.status}): ${text.slice(0, 200)}`);
    }
    const completion = (await res.json()) as OpenAiCompletion;
    const choice = completion.choices[0];
    const text = choice?.message.content ?? "";
    const toolCalls = (choice?.message.tool_calls ?? []).map((c, i) => ({
      id: c.id ?? `call_${i + 1}`,
      name: c.function.name,
      input: safeParse(c.function.arguments),
    }));
    return {
      text,
      toolCalls,
      stopReason: mapFinish(choice?.finish_reason ?? "stop"),
      ...(completion.usage
        ? {
            usage: {
              inputTokens: completion.usage.prompt_tokens ?? 0,
              outputTokens: completion.usage.completion_tokens ?? 0,
            },
          }
        : {}),
    };
  },
};

/** Register the local LLM provider as "local". Always available. */
export function registerLocalLlm(): void {
  registerLlmProvider(localLlmProvider);
}

registerLocalLlm();
