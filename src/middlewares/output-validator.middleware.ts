import { RequestHandler, Response } from 'express';
import { hashContent } from '../utils/crypto.util';

// ── Secret-leakage patterns ───────────────────────────────────────────────────

const SECRET_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ['AWS_ACCESS_KEY', /AKIA[0-9A-Z]{16}/],
  ['AWS_SECRET_KEY', /(?:aws[_\-.]?secret[_\-.]?access[_\-.]?key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[a-zA-Z0-9/+=]{40}['"]?/i],
  ['OPENAI_KEY',     /sk-[a-zA-Z0-9]{20,}/],
  ['ANTHROPIC_KEY',  /sk-ant-[a-zA-Z0-9\-_]{20,}/],
  ['JWT',            /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/],
  ['GENERIC_SECRET', /(?:secret|password|passwd|api[-_]?key|bearer\s+token)\s*[=:]\s*['"]?[a-zA-Z0-9_\-./+=]{16,}['"]?/i],
];

// Phrases that should never appear in a legitimate LLM response because they
// indicate the model was successfully prompted to echo its system instructions.
const ECHO_INDICATORS: ReadonlyArray<RegExp> = [
  /my system prompt (is|says|states|reads)/i,
  /i (was|am) (instructed|told|programmed) to/i,
  /as (instructed|directed|commanded) by (my|the) system/i,
  /the (hidden|secret|confidential|base) (prompt|instruction)/i,
];

interface BlockReason {
  category: string;
  matched: string;
}

function extractText(body: unknown): string {
  if (typeof body === 'string') return body;
  return JSON.stringify(body);
}

function detectThreats(bodyText: string, detectedPayloads: string[]): BlockReason[] {
  const reasons: BlockReason[] = [];

  // 1. Check for known secret patterns
  for (const [category, pattern] of SECRET_PATTERNS) {
    const m = pattern.exec(bodyText);
    if (m !== null) {
      reasons.push({ category, matched: m[0].slice(0, 40) });
    }
  }

  // 2. Check for injection-echo indicators
  for (const pattern of ECHO_INDICATORS) {
    const m = pattern.exec(bodyText);
    if (m !== null) {
      reasons.push({ category: 'INJECTION_ECHO', matched: m[0].slice(0, 80) });
    }
  }

  // 3. Check if the response contains raw payloads that triggered the injection
  //    detector (only reachable here if detection fired on a WARN path, not block)
  for (const payload of detectedPayloads) {
    if (payload.length > 8 && bodyText.includes(payload)) {
      reasons.push({ category: 'INJECTION_PAYLOAD_ECHO', matched: payload.slice(0, 80) });
    }
  }

  return reasons;
}

// ── Middleware ────────────────────────────────────────────────────────────────

export const outputValidator: RequestHandler = (req, res, next) => {
  const detectedPayloads = req.securityContext?.detectedPayloads ?? [];

  // Intercept res.json before it sends anything
  const originalJson = res.json.bind(res) as Response['json'];

  res.json = function validatedJson(body?: unknown): Response {
    const bodyText = extractText(body);
    const threats = detectThreats(bodyText, detectedPayloads);

    if (threats.length > 0) {
      if (req.securityContext) {
        req.securityContext.outputBlocked = true;
        req.securityContext.responseBodyHash = hashContent(bodyText);
        for (const t of threats) {
          if (t.category === 'INJECTION_ECHO' || t.category === 'INJECTION_PAYLOAD_ECHO') {
            req.securityContext.threatFlags.push('OUTPUT_BLOCKED_INJECTION_ECHO');
          } else {
            req.securityContext.threatFlags.push('OUTPUT_BLOCKED_SECRET_LEAK');
          }
        }
        req.securityContext.errorMessage = `Output blocked: ${threats.map((t) => t.category).join(', ')}`;
      }

      // Override status before delegating to the original json sender
      res.statusCode = 403;
      return originalJson({
        error: 'Response blocked by output security policy',
        code: 'OUTPUT_VALIDATION_FAILED',
      });
    }

    if (req.securityContext) {
      req.securityContext.responseBodyHash = hashContent(bodyText);
    }

    return originalJson(body);
  } as Response['json'];

  next();
};
