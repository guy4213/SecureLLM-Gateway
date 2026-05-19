import { getRedisClient } from '../database/redis';
import { hashContent } from '../utils/crypto.util';
import { logger } from '../utils/logger';
import { env } from '../config/env';

const PREFIX = 'llm:';

interface ChatMessage {
  role: string;
  content: string;
}

/**
 * Build a cache key that uniquely identifies the (model + prompt + max_tokens)
 * tuple for a specific tenant.
 *
 * Per-tenant prefix prevents one client from probing what other clients asked.
 * Messages are PII-redacted by the time they reach here, so the key never
 * contains plaintext PII.
 */
function buildKey(
  clientId: string,
  model: string,
  messages: ChatMessage[],
  maxTokens?: number
): string {
  const canonical = JSON.stringify({ model, messages, maxTokens: maxTokens ?? null });
  return `${PREFIX}${clientId}:${hashContent(canonical).slice(0, 32)}`;
}

/**
 * Returns a cached LLM response if present, otherwise null.
 * Fails open on Redis errors — caching is an optimisation, not a hard dependency.
 */
export async function getCachedResponse<T>(
  clientId: string,
  model: string,
  messages: ChatMessage[],
  maxTokens?: number
): Promise<T | null> {
  if (env.LLM_CACHE_TTL_SECONDS === 0) return null;

  try {
    const redis = getRedisClient();
    const cached = await redis.get(buildKey(clientId, model, messages, maxTokens));
    if (cached === null) return null;
    return JSON.parse(cached) as T;
  } catch (err) {
    logger.warn({ err: (err as Error).message }, 'LLM cache read failed — bypassing cache');
    return null;
  }
}

/**
 * Stores a successful LLM response with TTL. Fails silently — a cache-write
 * failure should never bubble up to the client.
 */
export async function setCachedResponse<T>(
  clientId: string,
  model: string,
  messages: ChatMessage[],
  maxTokens: number | undefined,
  response: T
): Promise<void> {
  if (env.LLM_CACHE_TTL_SECONDS === 0) return;

  try {
    const redis = getRedisClient();
    await redis.set(
      buildKey(clientId, model, messages, maxTokens),
      JSON.stringify(response),
      'EX',
      env.LLM_CACHE_TTL_SECONDS
    );
  } catch (err) {
    logger.warn({ err: (err as Error).message }, 'LLM cache write failed — continuing');
  }
}
