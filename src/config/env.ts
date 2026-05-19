import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),

  PORT: z.coerce
    .number()
    .int()
    .min(1)
    .max(65535)
    .default(3000),

  MONGO_URI: z
    .string()
    .min(1, 'MONGO_URI is required')
    .refine(
      (v) => v.startsWith('mongodb://') || v.startsWith('mongodb+srv://'),
      { message: 'MONGO_URI must begin with mongodb:// or mongodb+srv://' }
    ),

  REDIS_URI: z
    .string()
    .min(1, 'REDIS_URI is required')
    .refine(
      (v) => v.startsWith('redis://') || v.startsWith('rediss://'),
      { message: 'REDIS_URI must begin with redis:// or rediss://' }
    ),

  // Optional: gateway starts degraded (not crashed) when this is absent
  OPENAI_API_KEY: z.string().min(1).optional(),

  // 32-byte AES key as 64 hex chars — required for PII map persistence at audit time
  // Generate: openssl rand -hex 32
  PII_ENC_KEY: z
    .string()
    .regex(/^[0-9a-f]{64}$/, 'PII_ENC_KEY must be 64 lowercase hex characters (32 bytes)')
    .optional(),

  RATE_LIMIT_WINDOW_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(60_000),

  RATE_LIMIT_MAX_REQUESTS: z.coerce
    .number()
    .int()
    .positive()
    .default(30),

  // Hard cap on a single OpenAI request — prevents the gateway from holding
  // a socket open indefinitely if the upstream provider hangs.
  LLM_REQUEST_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(1_000)
    .max(120_000)
    .default(30_000),

  // Server-side ceiling on max_tokens to prevent FinOps / cost-DoS abuse.
  MAX_TOKENS_CAP: z.coerce
    .number()
    .int()
    .min(1)
    .max(200_000)
    .default(2_048),

  // Per-tenant response cache TTL in seconds. 0 disables caching entirely.
  LLM_CACHE_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(0)
    .max(86_400)
    .default(300),
});

export type EnvConfig = z.infer<typeof envSchema>;

function parseEnv(): EnvConfig & { readonly llmProviderKeyMissing: boolean } {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    // Fatal: misconfigured infrastructure variables crash the process early
    throw new Error(`[Config] Environment validation failed:\n${issues}`);
  }

  const config = result.data;
  const llmProviderKeyMissing = config.OPENAI_API_KEY === undefined;

  return { ...config, llmProviderKeyMissing };
}

export const env = parseEnv();
