import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { piiRedactor } from '../middlewares/pii-redactor.middleware';
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

function makeReq(messages: Array<{ role: string; content: string }>): Request {
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
  piiRedactor(req, res as unknown as Response, next);
  return { res, next };
}

// ── PII-D1: Inline email only ──────────────────────────────────────────────

describe('PII-D1: Inline PII — single email address', () => {
  it('replaces an email address with <PII_EMAIL_1> token', () => {
    const req = makeReq([{ role: 'user', content: 'Please contact me at test@test.com for more info.' }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toContain('<PII_EMAIL_1>');
    expect(content).not.toContain('test@test.com');
  });

  it('populates req.piiMap with the email token → original mapping', () => {
    const req = makeReq([{ role: 'user', content: 'Reach me at test@test.com' }]);
    run(req);

    expect(req.piiMap).toBeDefined();
    expect(req.piiMap!.get('<PII_EMAIL_1>')).toBe('test@test.com');
  });

  it('sets securityContext.piiDetected to true', () => {
    const req = makeReq([{ role: 'user', content: 'My email: test@test.com' }]);
    run(req);

    expect(req.securityContext!.piiDetected).toBe(true);
  });

  it('increments securityContext.piiTokenCount by 1', () => {
    const req = makeReq([{ role: 'user', content: 'Email me: test@test.com' }]);
    run(req);

    expect(req.securityContext!.piiTokenCount).toBe(1);
  });

  it('appends PII_DETECTED to securityContext.threatFlags', () => {
    const req = makeReq([{ role: 'user', content: 'test@test.com' }]);
    run(req);

    expect(req.securityContext!.threatFlags).toContain('PII_DETECTED');
  });

  it('always calls next() regardless of PII presence', () => {
    const req = makeReq([{ role: 'user', content: 'test@test.com' }]);
    const { next } = run(req);

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
  });

  it('preserves surrounding text outside the email token', () => {
    const req = makeReq([{ role: 'user', content: 'Send the report to test@test.com today.' }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toBe('Send the report to <PII_EMAIL_1> today.');
  });
});

// ── PII-D2: Mixed — email + Israeli phone ─────────────────────────────────

describe('PII-D2: Mixed PII — email and phone in the same message', () => {
  const MIXED_CONTENT = 'Contact: test@test.com or call 050-000-0000 for support.';

  it('replaces both email and phone with distinct tokens', () => {
    const req = makeReq([{ role: 'user', content: MIXED_CONTENT }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toContain('<PII_EMAIL_1>');
    expect(content).toContain('<PII_PHONE_1>');
    expect(content).not.toContain('test@test.com');
    expect(content).not.toContain('050-000-0000');
  });

  it('populates req.piiMap with both token → original entries', () => {
    const req = makeReq([{ role: 'user', content: MIXED_CONTENT }]);
    run(req);

    expect(req.piiMap).toBeDefined();
    expect(req.piiMap!.get('<PII_EMAIL_1>')).toBe('test@test.com');
    expect(req.piiMap!.get('<PII_PHONE_1>')).toBe('050-000-0000');
  });

  it('sets piiTokenCount to 2', () => {
    const req = makeReq([{ role: 'user', content: MIXED_CONTENT }]);
    run(req);

    expect(req.securityContext!.piiTokenCount).toBe(2);
  });

  it('calls next() after redacting both PII types', () => {
    const req = makeReq([{ role: 'user', content: MIXED_CONTENT }]);
    const { next } = run(req);

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
  });

  it('accumulates tokens across multiple messages in the same request', () => {
    const req = makeReq([
      { role: 'user', content: 'Email: test@test.com' },
      { role: 'user', content: 'Phone: 050-000-0000' },
    ]);
    run(req);

    const msgs = (req.body as { messages: Array<{ content: string }> }).messages;
    expect(msgs[0]!.content).toContain('<PII_EMAIL_1>');
    expect(msgs[1]!.content).toContain('<PII_PHONE_1>');
    expect(req.piiMap!.size).toBe(2);
  });

  it('assigns incrementing counters when the same PII type appears in multiple messages', () => {
    const req = makeReq([
      { role: 'user', content: 'First: test@test.com' },
      { role: 'user', content: 'Second: other@test.com' },
    ]);
    run(req);

    const msgs = (req.body as { messages: Array<{ content: string }> }).messages;
    expect(msgs[0]!.content).toContain('<PII_EMAIL_1>');
    expect(msgs[1]!.content).toContain('<PII_EMAIL_2>');
    expect(req.piiMap!.get('<PII_EMAIL_1>')).toBe('test@test.com');
    expect(req.piiMap!.get('<PII_EMAIL_2>')).toBe('other@test.com');
  });
});

// ── PII-D3: JSON-embedded PII ─────────────────────────────────────────────

describe('PII-D3: JSON-embedded PII — structured data in message content', () => {
  const JSON_CONTENT = '{"name":"Test User","email":"test@test.com","phone":"050-000-0000"}';

  it('redacts email inside a JSON-formatted message', () => {
    const req = makeReq([{ role: 'user', content: JSON_CONTENT }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toContain('<PII_EMAIL_1>');
    expect(content).not.toContain('test@test.com');
  });

  it('redacts phone inside a JSON-formatted message', () => {
    const req = makeReq([{ role: 'user', content: JSON_CONTENT }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toContain('<PII_PHONE_1>');
    expect(content).not.toContain('050-000-0000');
  });

  it('preserves JSON keys and non-PII values surrounding the tokens', () => {
    const req = makeReq([{ role: 'user', content: JSON_CONTENT }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toContain('"name":"Test User"');
    expect(content).toContain('"email":"<PII_EMAIL_1>"');
    expect(content).toContain('"phone":"<PII_PHONE_1>"');
  });

  it('populates piiMap from JSON-embedded PII', () => {
    const req = makeReq([{ role: 'user', content: JSON_CONTENT }]);
    run(req);

    expect(req.piiMap!.get('<PII_EMAIL_1>')).toBe('test@test.com');
    expect(req.piiMap!.get('<PII_PHONE_1>')).toBe('050-000-0000');
  });

  it('records a SHA-256 requestBodyHash on securityContext before redaction', () => {
    const req = makeReq([{ role: 'user', content: JSON_CONTENT }]);
    run(req);

    // Hash is a 64-char lowercase hex string (SHA-256)
    expect(req.securityContext!.requestBodyHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ── Clean messages — no mutation ───────────────────────────────────────────

describe('Clean messages — no PII present', () => {
  it('does not mutate message content when no PII is found', () => {
    const original = 'Can you summarize this document for me?';
    const req = makeReq([{ role: 'user', content: original }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toBe(original);
  });

  it('does not set req.piiMap when no PII is found', () => {
    const req = makeReq([{ role: 'user', content: 'No sensitive data here.' }]);
    run(req);

    expect(req.piiMap).toBeUndefined();
  });

  it('leaves piiDetected false on securityContext', () => {
    const req = makeReq([{ role: 'user', content: 'Hello world.' }]);
    run(req);

    expect(req.securityContext!.piiDetected).toBe(false);
    expect(req.securityContext!.piiTokenCount).toBe(0);
    expect(req.securityContext!.threatFlags).not.toContain('PII_DETECTED');
  });

  it('always calls next() even when no PII is present', () => {
    const req = makeReq([{ role: 'user', content: 'What time is it?' }]);
    const { next } = run(req);

    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith();
  });
});

// ── Edge cases ─────────────────────────────────────────────────────────────

describe('Edge cases', () => {
  it('calls next() when body.messages is missing (safety-net branch)', () => {
    const req = { body: {}, securityContext: makeSecurityContext() } as unknown as Request;
    const { next } = run(req);

    expect(next).toHaveBeenCalledOnce();
  });

  it('skips non-object entries in messages without throwing', () => {
    const req = {
      body: { messages: [null, 42, 'bare string', { role: 'user', content: 'test@test.com' }] },
      securityContext: makeSecurityContext(),
    } as unknown as Request;

    expect(() => run(req)).not.toThrow();
    const msgs = (req.body as { messages: unknown[] }).messages;
    const last = msgs[3] as { content: string };
    expect(last.content).toContain('<PII_EMAIL_1>');
  });

  it('redacts messages from any role, not only "user"', () => {
    const req = makeReq([{ role: 'system', content: 'Admin email: test@test.com' }]);
    run(req);

    const content = (req.body as { messages: Array<{ content: string }> }).messages[0]!.content;
    expect(content).toContain('<PII_EMAIL_1>');
  });

  it('does not call res.status — piiRedactor never sends a blocking response', () => {
    const req = makeReq([{ role: 'user', content: 'test@test.com and 050-000-0000' }]);
    const { res } = run(req);

    expect(res.status).not.toHaveBeenCalled();
  });
});
