import { RequestHandler } from 'express';
import { redactPii, type PiiCounters } from '../utils/pii.util';
import { hashContent } from '../utils/crypto.util';
import { sealPiiMap } from '../utils/pii-crypto.util';

interface ChatMessage {
  role: string;
  content: string;
}

function isChatMessage(v: unknown): v is ChatMessage {
  return (
    typeof v === 'object' &&
    v !== null &&
    typeof (v as Record<string, unknown>)['content'] === 'string'
  );
}

export const piiRedactor: RequestHandler = (req, res, next) => {
  const body = req.body as Record<string, unknown>;

  if (!body || !Array.isArray(body['messages'])) {
    // Body has already been validated by injectionDetector; this is a safety net
    next();
    return;
  }

  const messages = body['messages'] as unknown[];
  const piiMap = new Map<string, string>();

  const counters: PiiCounters = { EMAIL: 0, PHONE: 0, IL_ID: 0 };
  let totalReplaced = 0;

  // Hash the original (pre-redaction) request for the audit trail
  const originalBodyStr = JSON.stringify(body);
  if (req.securityContext) {
    req.securityContext.requestBodyHash = hashContent(originalBodyStr);
  }

  // Redact PII from every message in-place
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (!isChatMessage(msg)) continue;

    const { redacted, mappings, totalReplaced: count } = redactPii(msg.content, counters);

    if (count > 0) {
      msg.content = redacted;
      for (const { token, original } of mappings) {
        piiMap.set(token, original);
      }
      totalReplaced += count;
    }
  }

  if (totalReplaced > 0) {
    req.piiMap = piiMap;

    if (req.securityContext) {
      req.securityContext.piiDetected = true;
      req.securityContext.piiTokenCount = totalReplaced;
      req.securityContext.threatFlags.push('PII_DETECTED');
      req.securityContext.sealedPiiMap = sealPiiMap(piiMap);
    }
  }

  next();
};
