import Redis from 'ioredis';
import { env } from '../config/env';
import { logger } from '../utils/logger';

let client: Redis | null = null;
const MAX_RECONNECT_ATTEMPTS = 10;
export function getRedisClient(): Redis {
  if (client === null) {
    throw new Error(
      '[Redis] Client not initialised — call connectRedis() first.'
    );
  }
  return client;
}

export function isRedisConnected(): boolean {
  return client?.status === 'ready';
}

export async function connectRedis(): Promise<Redis> {
  const redis = new Redis(env.REDIS_URI, {
    // Exponential back-off: 200 ms → 400 → 800 … cap at 10 s
    retryStrategy(times: number): number | null {
      if (times > MAX_RECONNECT_ATTEMPTS) {
        logger.fatal('Redis max retry attempts reached — giving up');
        return null;
      }
      const delay = Math.min(200 * 2 ** (times - 1), 10_000);
      logger.warn({ attempt: times, maxAttempts: MAX_RECONNECT_ATTEMPTS, retryInMs: delay }, 'Redis retry scheduled');
      return delay;
    },
    enableReadyCheck: true,
    // Per-command retry — keep low so callers fail fast
    maxRetriesPerRequest: 2,
    // Don't connect automatically; we call .connect() explicitly
    lazyConnect: true,
    // Optimise for high-throughput sliding-window rate limiting
    enableAutoPipelining: true,
  });

  redis.on('ready', () => {
    logger.info('Redis connected and ready');
  });

  redis.on('error', (err: Error) => {
    logger.error({ err: err.message }, 'Redis error');
  });

  redis.on('reconnecting', () => {
    logger.warn('Redis reconnecting');
  });

  redis.on('end', () => {
    logger.warn('Redis connection closed');
  });

  await redis.connect();
  client = redis;
  return redis;
}

export async function disconnectRedis(): Promise<void> {
  if (client !== null) {
    await client.quit();
    client = null;
    logger.info('Redis disconnected gracefully');
  }
}
