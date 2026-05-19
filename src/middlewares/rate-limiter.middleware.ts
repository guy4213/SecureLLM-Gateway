import { RequestHandler } from 'express';
import { randomBytes } from 'crypto';
import { getRedisClient } from '../database/redis';
import { logger } from '../utils/logger';
import { env } from '../config/env';

// Atomic sliding-window algorithm implemented as a Lua script.
// KEYS[1] = rate-limit bucket key
// ARGV[1] = current timestamp (ms)
// ARGV[2] = window size (ms)
// ARGV[3] = max allowed requests
// ARGV[4] = unique member ID for this request
//
// Returns: [allowed(0|1), currentCount, ttlMs]
const SLIDING_WINDOW_LUA = `
local key     = KEYS[1]
local now     = tonumber(ARGV[1])
local window  = tonumber(ARGV[2])
local limit   = tonumber(ARGV[3])
local member  = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = tonumber(redis.call('ZCARD', key))

if count >= limit then
  local ttl = redis.call('PTTL', key)
  return {0, count, ttl}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)

local ttl = redis.call('PTTL', key)
return {1, count + 1, ttl}
`.trim();

export const rateLimiter: RequestHandler = async (req, res, next) => {
  // auth middleware must have run first
  if (!req.client) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const redis = getRedisClient();
  const now = Date.now();
  const windowMs = env.RATE_LIMIT_WINDOW_MS;
  // Per-key override takes precedence over the global default
  const maxRequests = req.client.rateLimitPerMinute ?? env.RATE_LIMIT_MAX_REQUESTS;
  const rateLimitKey = `rl:${req.client.id}`;
  const memberId = `${now}-${randomBytes(4).toString('hex')}`;

  try {
    const raw = await redis.eval(
      SLIDING_WINDOW_LUA,
      1,
      rateLimitKey,
      now.toString(),
      windowMs.toString(),
      maxRequests.toString(),
      memberId
    ) as [number, number, number];

    const [allowed, count, ttlMs] = raw;
    const remaining = Math.max(0, maxRequests - count);
    const resetAt = Math.ceil((now + Math.max(ttlMs, 0)) / 1000);

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', allowed ? remaining : 0);
    res.setHeader('X-RateLimit-Reset', resetAt);

    if (!allowed) {
      const retryAfter = Math.ceil(Math.max(ttlMs, 0) / 1000);
      res.setHeader('Retry-After', retryAfter);

      if (req.securityContext) {
        req.securityContext.threatFlags.push('RATE_LIMIT_EXCEEDED');
        req.securityContext.errorMessage = 'Rate limit exceeded';
      }
      res.status(429).json({
        error: 'Too Many Requests',
        retryAfter,
      });
      return;
    }

    next();
  } catch (err) {
    // Redis failure — fail open to avoid a Redis outage taking down the gateway.
    (req.log ?? logger).error({ err }, 'Redis eval failed — failing open');
    next();
  }
};
