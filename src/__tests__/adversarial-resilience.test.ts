/**
 * Phase 5 — Adversarial & Resilience QA
 *
 * Scenarios:
 *   1. Concurrency & race conditions on the sliding-window rate limiter
 *   2. LLM service failure injection (503 / 500 paths)
 *   3. ReDoS & payload extremes (413 / large-body timing)
 *   4. Malformed inputs & edge cases (401 / 400 paths)
 *   5. Audit-logger async resilience (threat flags, latency capture)
 *
 * No real infrastructure is required — MongoDB, Redis, and the LLM service
 * are all mocked at the module level via vi.mock / vi.hoisted.
 *
 * SAFETY: src/middlewares/test-payloads.ts and
 *         src/__tests__/injection-detector.test.ts are intentionally excluded.
 */

// ─── Hoisted shared state (must precede vi.mock calls) ──────────────────────
const redisState = vi.hoisted(() => ({ counter: 0, limit: 30 }));
const authState  = vi.hoisted(() => ({
  active: true,
  record: { _id: '000000000000000000000001', role: 'client' as const },
}));
const mongoState = vi.hoisted(() => ({ connected: false }));
// Single stable reference to the Redis eval spy so vi.clearAllMocks() can track it
const mockEval   = vi.hoisted(() => vi.fn<(...args: unknown[]) => Promise<[number, number, number]>>());

// ─── Module mocks ─────────────────────────────────────────────────────────────
vi.mock('../database/mongo', () => ({
  isMongoConnected: () => mongoState.connected,
  connectMongo:     vi.fn(),
  disconnectMongo:  vi.fn(),
}));

vi.mock('../models/ApiKey.model', () => ({
  ApiKeyModel: {
    findOne:  vi.fn(),
    updateOne: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock('../models/AuditLog.model', () => ({
  AuditLogModel: {
    create: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock('../database/redis', () => ({
  getRedisClient:   () => ({ eval: mockEval }),
  connectRedis:     vi.fn(),
  disconnectRedis:  vi.fn(),
  isRedisConnected: vi.fn(() => true),
}));

vi.mock('../services/llm.service', () => ({
  generateResponse: vi.fn(),
}));

// ─── Imports (resolved against hoisted mocks above) ─────────────────────────
import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp }        from '../server';
import { generateResponse } from '../services/llm.service';
import { AuditLogModel }    from '../models/AuditLog.model';
import { ApiKeyModel }      from '../models/ApiKey.model';

// ─── Constants ───────────────────────────────────────────────────────────────
const API_KEY    = 'test-key-123';
const VALID_BODY = { messages: [{ role: 'user', content: 'What is the capital of France?' }] };

const MOCK_OK_RESPONSE = {
  id: 'chatcmpl-mock-001',
  object: 'chat.completion',
  created: 1_000_000,
  model: 'gpt-3.5-turbo',
  choices: [
    { index: 0, message: { role: 'assistant', content: 'Paris' }, finish_reason: 'stop' },
  ],
  usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
};

// ─── Test server (single instance shared across all suites) ─────────────────
let baseUrl: string;
let server:  http.Server;

beforeAll(async () => {
  server = http.createServer(createApp());
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(
  () => new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve()))
  )
);

// ─── Per-test reset ───────────────────────────────────────────────────────────
beforeEach(() => {
  // 1. Wipe call histories (not implementations — vi.clearAllMocks preserves those)
  vi.clearAllMocks();

  // 2. Reset shared toggles
  redisState.counter   = 0;
  redisState.limit     = 30;
  authState.active     = true;
  mongoState.connected = false;

  // 3. Re-apply implementations so each test starts from a known state
  vi.mocked(ApiKeyModel.findOne).mockImplementation(() => ({
    lean: () => Promise.resolve(authState.active ? authState.record : null),
  }) as ReturnType<typeof ApiKeyModel.findOne>);

  vi.mocked(ApiKeyModel.updateOne).mockResolvedValue({} as never);
  vi.mocked(AuditLogModel.create).mockResolvedValue({} as never);
  vi.mocked(generateResponse).mockResolvedValue(MOCK_OK_RESPONSE as never);

  // Atomic sliding-window simulation: first `limit` calls allowed, rest blocked
  mockEval.mockImplementation(() => {
    redisState.counter++;
    const allowed = redisState.counter <= redisState.limit ? 1 : 0;
    const count   = Math.min(redisState.counter, redisState.limit);
    return Promise.resolve([allowed, count, 60_000]);
  });
});

// ─── HTTP helper ─────────────────────────────────────────────────────────────
interface Res { status: number; data: unknown; headers: Headers }

async function post(body: unknown, key: string | null = API_KEY): Promise<Res> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (key !== null) headers['x-api-key'] = key;

  const res = await fetch(`${baseUrl}/v1/chat`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  let data: unknown = null;
  try { data = await res.json(); } catch { /* body may not be JSON (e.g. 413) */ }
  return { status: res.status, data, headers: res.headers };
}

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 1 — Concurrency & Race Conditions
// ─────────────────────────────────────────────────────────────────────────────
describe('1 · Concurrency — sliding-window rate limiter', () => {

  it('allows exactly 30 of 50 concurrent requests; blocks remaining 20 with 429', async () => {
    const BURST = 50;

    const responses = await Promise.all(
      Array.from({ length: BURST }, () => post(VALID_BODY))
    );

    const statuses = responses.map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(30);
    expect(statuses.filter((s) => s === 429)).toHaveLength(20);
    // No stray status codes — every response is either allowed or blocked
    expect(statuses.every((s) => s === 200 || s === 429)).toBe(true);
  });

  it('blocked 429 response carries Retry-After and X-RateLimit-Remaining: 0', async () => {
    redisState.counter = 30; // bucket already exhausted

    const { status, data, headers } = await post(VALID_BODY);

    expect(status).toBe(429);
    expect(data).toMatchObject({ error: 'Too Many Requests' });
    expect(headers.get('x-ratelimit-remaining')).toBe('0');
    expect(Number(headers.get('retry-after'))).toBeGreaterThanOrEqual(0);
  });

  it('resets correctly: counter reset allows a new window of requests', async () => {
    redisState.counter = 30;
    const blocked = await post(VALID_BODY);
    expect(blocked.status).toBe(429);

    redisState.counter = 0; // simulate window expiry
    const allowed = await post(VALID_BODY);
    expect(allowed.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 2 — Failure Injection (LLM Service Outage)
// ─────────────────────────────────────────────────────────────────────────────
describe('2 · Failure injection — LLM service outage', () => {

  it('returns 503 on "Service Unavailable" and does not crash the process', async () => {
    vi.mocked(generateResponse).mockRejectedValueOnce(
      new Error('Service Unavailable: OpenAI returned 503 — overloaded')
    );

    const { status, data } = await post(VALID_BODY);

    expect(status).toBe(503);
    expect(data).toMatchObject({ error: expect.stringContaining('Service Unavailable') });
  });

  it('returns 500 for unknown errors without leaking the internal message', async () => {
    vi.mocked(generateResponse).mockRejectedValueOnce(
      new Error('ECONNRESET — internal network failure')
    );

    const { status, data } = await post(VALID_BODY);

    expect(status).toBe(500);
    expect((data as Record<string, string>).error).toBe('Internal Server Error');
    // Must NOT echo the raw exception message to the client
    expect(JSON.stringify(data)).not.toContain('ECONNRESET');
  });

  it('server recovers: one transient failure does not break subsequent requests', async () => {
    vi.mocked(generateResponse)
      .mockRejectedValueOnce(new Error('Service Unavailable: cold-start timeout'))
      .mockResolvedValueOnce(MOCK_OK_RESPONSE as never);

    // Two requests in flight simultaneously
    const [r1, r2] = await Promise.all([post(VALID_BODY), post(VALID_BODY)]);

    const statuses = [r1.status, r2.status].sort();
    expect(statuses).toEqual([200, 503]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 3 — ReDoS & Payload Extremes
// ─────────────────────────────────────────────────────────────────────────────
describe('3 · ReDoS & payload extremes', () => {

  it('rejects body > 1 MB with 413 Payload Too Large', async () => {
    // Total JSON ≈ 1.1 MB — well above the express.json({ limit: '1mb' }) ceiling
    const oversized = 'A'.repeat(1_100_000);

    const { status } = await post({ messages: [{ role: 'user', content: oversized }] });

    expect(status).toBe(413);
  });

  it('processes a ~900 KB repetitive body within 500 ms (ReDoS guard)', async () => {
    // Highly repetitive but non-malicious content stresses regex catastrophic backtracking
    const large = 'The quick brown fox jumps over the lazy dog. '.repeat(20_000); // ~900 KB

    const t0 = performance.now();
    const { status } = await post({ messages: [{ role: 'user', content: large }] });
    const elapsed = performance.now() - t0;

    expect([200, 400]).toContain(status);
    expect(elapsed).toBeLessThan(500);
  });

  it('handles 50-level nested JSON without a stack overflow', async () => {
    let nested: unknown = { role: 'user', content: 'deep nesting' };
    for (let i = 0; i < 50; i++) nested = { wrapper: nested };

    // InjectionDetector & PII redactor silently skip non-ChatMessage shapes
    const { status } = await post({ messages: [nested] });
    expect([200, 400]).toContain(status);
  });

  it('handles an empty messages array without crashing (returns 200 via mock LLM)', async () => {
    const { status } = await post({ messages: [] });
    expect(status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 4 — Malformed Inputs & Edge Cases
// ─────────────────────────────────────────────────────────────────────────────
describe('4 · Malformed inputs & edge cases', () => {

  it('returns 401 when x-api-key header is absent', async () => {
    const { status, data } = await post(VALID_BODY, null);

    expect(status).toBe(401);
    expect((data as Record<string, string>).error).toMatch(/x-api-key/i);
  });

  it('returns 401 for a whitespace-only x-api-key (trim guard)', async () => {
    const { status } = await post(VALID_BODY, '   ');
    expect(status).toBe(401);
  });

  it('safely rejects NoSQL injection in x-api-key header (returns 401, not bypass)', async () => {
    // The middleware hashes the raw header value with SHA-256 before any DB query.
    // {"$gt":""} can never match a real keyHash — it should be treated as unknown key.
    authState.active = false; // simulate: no record found for this hash

    const { status } = await post(VALID_BODY, '{"$gt":""}');
    expect(status).toBe(401);
  });

  it('returns 400 when messages is a string instead of an array', async () => {
    const { status, data } = await post({ messages: 'not-an-array' });

    expect(status).toBe(400);
    expect((data as Record<string, string>).error).toMatch(/messages/i);
  });

  it('returns 400 when messages is null', async () => {
    const { status, data } = await post({ messages: null });

    expect(status).toBe(400);
    expect((data as Record<string, string>).error).toMatch(/messages/i);
  });

  it('returns 400 when request body is an empty object (missing messages key)', async () => {
    const { status } = await post({});
    expect(status).toBe(400);
  });

  it('returns 400 when messages is a number', async () => {
    const { status } = await post({ messages: 42 });
    expect(status).toBe(400);
  });

  it('returns 400 when max_tokens exceeds the server cap (FinOps DoS guard)', async () => {
    const { status, data } = await post({ messages: VALID_BODY.messages, max_tokens: 999_999 });

    expect(status).toBe(400);
    expect((data as Record<string, string>).error).toMatch(/max_tokens/i);
  });

  it('accepts max_tokens at or below the cap without error', async () => {
    const { status } = await post({ messages: VALID_BODY.messages, max_tokens: 1024 });

    // Should pass validation and reach the LLM mock → 200
    expect(status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SUITE 5 — Audit Logger Async Resilience
// ─────────────────────────────────────────────────────────────────────────────
describe('5 · Audit logger — async resilience', () => {

  beforeEach(() => {
    mongoState.connected = true; // enable audit writes for this entire suite
  });

  it('logs RATE_LIMIT_EXCEEDED flag and statusCode 429 for rate-limited requests', async () => {
    redisState.counter = 30; // bucket full

    await post(VALID_BODY);

    // res.on('finish') fires before the test's await resolves; give the
    // fire-and-forget write one tick to land.
    await vi.waitFor(() => {
      expect(vi.mocked(AuditLogModel.create)).toHaveBeenCalled();
    });

    const [payload] = vi.mocked(AuditLogModel.create).mock.calls[0] as [Record<string, unknown>];
    expect(payload['statusCode']).toBe(429);
    expect(payload['threatFlags']).toContain('RATE_LIMIT_EXCEEDED');
  });

  it('logs AUTH_FAILURE flag and statusCode 401 when API key is missing', async () => {
    await post(VALID_BODY, null); // no x-api-key header

    await vi.waitFor(() => {
      expect(vi.mocked(AuditLogModel.create)).toHaveBeenCalled();
    });

    const [payload] = vi.mocked(AuditLogModel.create).mock.calls[0] as [Record<string, unknown>];
    expect(payload['statusCode']).toBe(401);
    expect(payload['threatFlags']).toContain('AUTH_FAILURE');
  });

  it('records non-negative latencyMs even for middleware-terminated requests', async () => {
    authState.active = false; // auth will reject → 401

    await post(VALID_BODY);

    await vi.waitFor(() => {
      expect(vi.mocked(AuditLogModel.create)).toHaveBeenCalled();
    });

    const [payload] = vi.mocked(AuditLogModel.create).mock.calls[0] as [Record<string, unknown>];
    expect(typeof payload['latencyMs']).toBe('number');
    expect(payload['latencyMs'] as number).toBeGreaterThanOrEqual(0);
  });

  it('logs MAX_TOKENS_EXCEEDED threat flag when max_tokens exceeds server cap', async () => {
    await post({ messages: VALID_BODY.messages, max_tokens: 999_999 });

    await vi.waitFor(() => {
      expect(vi.mocked(AuditLogModel.create)).toHaveBeenCalled();
    });

    const [payload] = vi.mocked(AuditLogModel.create).mock.calls[0] as [Record<string, unknown>];
    expect(payload['statusCode']).toBe(400);
    expect(payload['threatFlags']).toContain('MAX_TOKENS_EXCEEDED');
  });

  it('skips writing to MongoDB when isMongoConnected() returns false (graceful degradation)', async () => {
    mongoState.connected = false; // override suite beforeEach

    await post(VALID_BODY);
    // Allow any stray async tick
    await new Promise((r) => setTimeout(r, 30));

    expect(vi.mocked(AuditLogModel.create)).not.toHaveBeenCalled();
  });
});
