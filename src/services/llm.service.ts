import type { SecurityContext } from '../types/express-extensions';
import { env } from '../config/env';
import { getCachedResponse, setCachedResponse } from './cache.service';

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
}

interface OpenAIResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: { role: string; content: string };
    finish_reason: string;
  }>;
  usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';
const DEFAULT_MODEL  = 'gpt-3.5-turbo';

export async function generateResponse(
  messages: ChatMessage[],
  securityContext: SecurityContext | undefined,
  clientId: string | undefined,
  model?: string,
  maxTokens?: number
): Promise<OpenAIResponse> {
  const apiKey = env.OPENAI_API_KEY;
  if (!apiKey) {
    throw new Error('Service Unavailable: LLM provider key is not configured');
  }

  const resolvedModel = model ?? DEFAULT_MODEL;

  // ── Cache lookup (per-tenant) ──────────────────────────────────────────────
  if (clientId) {
    const cached = await getCachedResponse<OpenAIResponse>(
      clientId, resolvedModel, messages, maxTokens
    );
    if (cached) {
      if (securityContext) {
        securityContext.llmProvider = 'openai';
        securityContext.llmModel    = resolvedModel;
        securityContext.cacheHit    = true;
      }
      return cached;
    }
  }

  if (securityContext) {
    securityContext.llmProvider = 'openai';
    securityContext.llmModel    = resolvedModel;
  }

  const requestBody: Record<string, unknown> = { model: resolvedModel, messages };
  if (maxTokens !== undefined) requestBody['max_tokens'] = maxTokens;

  // ── Outbound fetch with hard timeout via AbortController ───────────────────
  const controller   = new AbortController();
  const timeoutTimer = setTimeout(() => controller.abort(), env.LLM_REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(OPENAI_API_URL, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        Authorization:   `Bearer ${apiKey}`,
      },
      body:    JSON.stringify(requestBody),
      signal:  controller.signal,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      throw new Error(`Service Unavailable: OpenAI returned ${response.status} — ${text}`);
    }

    const completion = await response.json() as OpenAIResponse;

    // ── Write-through cache (fire-and-forget) ──────────────────────────────
    if (clientId) {
      void setCachedResponse(clientId, resolvedModel, messages, maxTokens, completion);
    }

    return completion;
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`Service Unavailable: LLM request timed out after ${env.LLM_REQUEST_TIMEOUT_MS}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timeoutTimer);
  }
}
