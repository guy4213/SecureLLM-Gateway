import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { injectionDetector } from '../middlewares/injection-detector.middleware';
import { PAYLOADS } from '../middlewares/test-payloads';
import type { SecurityContext } from '../types/express-extensions';

// ── Helpers ────────────────────────────────────────────────────────────────

function makeSecurityContext(): SecurityContext {
  return {
    correlationId: 'test-correlation-id',
    requestStart: Date.now(),
    sealedPiiMap: null,
    cacheHit: false,
    injectionDetected: false,
    injectionTypes: [],
    detectedPayloads: [],
    piiDetected: false,
    piiTokenCount: 0,
    outputBlocked: false,
    threatFlags: [],
    requestBodyHash: null,
    responseBodyHash: null,
    llmProvider: null,
    llmModel: null,
    errorMessage: null,
  };
}

function makeReq(messages: unknown[]): Request {
  return {
    body: { messages },
    securityContext: makeSecurityContext(),
  } as unknown as Request;
}

function makeRes() {
  const json = vi.fn();
  const status = vi.fn().mockReturnValue({ json });
  return { status, json };
}

function run(req: Request) {
  const res = makeRes();
  const next = vi.fn() as NextFunction;
  injectionDetector(req, res as unknown as Response, next);
  return { res, next };
}

// ── INJ-A: Direct Overrides ────────────────────────────────────────────────

describe('INJ-A: Direct Overrides', () => {
  it('INJ-A1 — blocks a "ignore all previous instructions" override', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_A1, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-A2 — blocks a ChatML delimiter + safety-filter disable payload', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_A2, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-A3 — blocks a false-authority [ADMIN] prefix override', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_A3, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});

// ── INJ-B: Context Extractions ─────────────────────────────────────────────

describe('INJ-B: Context Extractions', () => {
  it('INJ-B1 — blocks a "repeat initial instructions verbatim" probe', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_B1, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-B2 — blocks a full conversation history dump request', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_B2, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-B3 — blocks a prompt to exfiltrate environment variables and API keys', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_B3, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});

// ── INJ-C: Persona Hijacks ─────────────────────────────────────────────────

describe('INJ-C: Persona Hijacks', () => {
  it('INJ-C1 — blocks a DAN (Do Anything Now) jailbreak persona swap', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_C1, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-C2 — blocks an LLM-to-REPL persona swap with code execution payload', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_C2, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-C3 — blocks a response-format override designed to signal bypass', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_C3, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});

// ── INJ-E: Indirect Smuggling ──────────────────────────────────────────────

describe('INJ-E: Indirect Smuggling', () => {
  it('INJ-E1 — blocks an injection hidden inside a summarization task', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_E1, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-E2 — blocks an HTML comment SYSTEM_OVERRIDE smuggling attempt', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_E2, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('INJ-E3 — blocks a multi-step translate-then-execute instruction smuggle', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_E3, 'base64').toString('utf-8');
    const { res, next } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});

// ── securityContext population ─────────────────────────────────────────────

describe('securityContext side-effects on detection', () => {
  it('stamps injectionDetected, injectionTypes, detectedPayloads, and threatFlags (INJ-A1)', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_A1, 'base64').toString('utf-8');
    const req = makeReq([{ role: 'user', content: testPayload }]);
    run(req);

    const ctx = req.securityContext!;
    expect(ctx.injectionDetected).toBe(true);
    expect(ctx.injectionTypes).toContain('DIRECT_OVERRIDE');
    expect(ctx.detectedPayloads.length).toBeGreaterThan(0);
    expect(ctx.threatFlags).toContain('PROMPT_INJECTION_DETECTED');
  });

  it('stamps PERSONA_HIJACK in injectionTypes for INJ-C1', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_C1, 'base64').toString('utf-8');
    const req = makeReq([{ role: 'user', content: testPayload }]);
    run(req);

    expect(req.securityContext!.injectionTypes).toContain('PERSONA_HIJACK');
  });

  it('leaves securityContext clean when no injection is detected', () => {
    const req = makeReq([{ role: 'user', content: 'Hello, how are you?' }]);
    run(req);

    const ctx = req.securityContext!;
    expect(ctx.injectionDetected).toBe(false);
    expect(ctx.injectionTypes).toHaveLength(0);
    expect(ctx.threatFlags).not.toContain('PROMPT_INJECTION_DETECTED');
  });
});

// ── Response body shape ────────────────────────────────────────────────────

describe('400 response body shape', () => {
  it('includes an "error" string and a "categories" array on any blocked request', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_A1, 'base64').toString('utf-8');
    const { res } = run(makeReq([{ role: 'user', content: testPayload }]));

    expect(res.status).toHaveBeenCalledWith(400);
    const body = res.status.mock.results[0]!.value.json.mock.calls[0]?.[0];
    expect(typeof body.error).toBe('string');
    expect(Array.isArray(body.categories)).toBe(true);
    expect(body.categories.length).toBeGreaterThan(0);
  });

  it('"categories" field contains the matched InjectionType string(s)', () => {
    const testPayload = Buffer.from(PAYLOADS.INJ_A1, 'base64').toString('utf-8');
    const { res } = run(makeReq([{ role: 'user', content: testPayload }]));

    const body = res.status.mock.results[0]!.value.json.mock.calls[0]?.[0];
    expect(body.categories).toContain('DIRECT_OVERRIDE');
  });
});

// ── Clean requests — must pass through ────────────────────────────────────

describe('Clean requests', () => {
  it('calls next() with no arguments for a benign message', () => {
    const { res, next } = run(makeReq([{ role: 'user', content: 'What is the capital of France?' }]));

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('calls next() when the messages array is empty', () => {
    const { res, next } = run(makeReq([]));

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('skips non-object entries in messages without throwing', () => {
    const { res, next } = run(makeReq([null, undefined, 42, 'bare string']));

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('does not flag a message from the "assistant" role with benign content', () => {
    const { res, next } = run(makeReq([
      { role: 'assistant', content: 'I am here to help you with your questions.' },
    ]));

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });
});

// ── Edge cases ─────────────────────────────────────────────────────────────

describe('Edge cases — malformed request body', () => {
  it('returns 400 when body.messages is missing', () => {
    const req = { body: {}, securityContext: makeSecurityContext() } as unknown as Request;
    const { res, next } = run(req);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 400 when body is null', () => {
    const req = { body: null, securityContext: makeSecurityContext() } as unknown as Request;
    const { res, next } = run(req);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 400 when body.messages is a string, not an array', () => {
    const req = {
      body: { messages: 'not-an-array' },
      securityContext: makeSecurityContext(),
    } as unknown as Request;
    const { res, next } = run(req);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 400 when body.messages is an object, not an array', () => {
    const req = {
      body: { messages: { role: 'user', content: 'hello' } },
      securityContext: makeSecurityContext(),
    } as unknown as Request;
    const { res, next } = run(req);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});
