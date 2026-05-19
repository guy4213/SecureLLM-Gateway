import { RequestHandler } from 'express';
import { env } from '../config/env';

// ── Injection category identifiers ────────────────────────────────────────────

export type InjectionType =
  | 'DIRECT_OVERRIDE'
  | 'CONTEXT_EXTRACTION'
  | 'PERSONA_HIJACK'
  | 'INDIRECT_SMUGGLING'
  | 'MULTILINGUAL_BYPASS';

// ── Detection patterns ────────────────────────────────────────────────────────

const INJECTION_PATTERNS: ReadonlyArray<{ type: InjectionType; regex: RegExp }> = [
  // A. Direct Overrides
  { type: 'DIRECT_OVERRIDE', regex: /ignore\s+(?:all\s+)?(?:previous|prior|above|initial|your)\s+(?:instructions?|directions?)/i },
  { type: 'DIRECT_OVERRIDE', regex: /disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|directions?)/i },
  { type: 'DIRECT_OVERRIDE', regex: /you\s+must\s+now\s+(?:ignore|disregard|forget|override)/i },
  { type: 'DIRECT_OVERRIDE', regex: /\[ADMIN\]:/i },

  // B. Context Extractions
  { type: 'CONTEXT_EXTRACTION', regex: /\binitial\s+instructions?\b/i },
  { type: 'CONTEXT_EXTRACTION', regex: /repeat\s+(?:it|them)\s+verbatim/i },
  { type: 'CONTEXT_EXTRACTION', regex: /(?:repeat|output|tell\s+me)\s+(?:them|your|the)?\s*(?:system\s*prompt|initial\s*instructions?|instructions?)/i },
  { type: 'CONTEXT_EXTRACTION', regex: /(?:print|output|show)\s+(?:everything|all)\s+(?:in|from)\s+this\s+conversation/i },
  { type: 'CONTEXT_EXTRACTION', regex: /from\s+the\s+very\s+first\s+message/i },
  { type: 'CONTEXT_EXTRACTION', regex: /output\s+(?:them|it)\s+(?:now\s+)?as\s+JSON/i },
  { type: 'CONTEXT_EXTRACTION', regex: /(?:environment\s+variables?|configuration\s+values?|API\s+keys?)/i },

  // C. Persona Hijacks
  { type: 'PERSONA_HIJACK', regex: /you\s+are\s+now\s+(?:DAN|unrestricted|a\s+Python\s+REPL)/i },
  { type: 'PERSONA_HIJACK', regex: /forget\s+you\s+are\s+an?\s+(?:LLM|AI)/i },
  { type: 'PERSONA_HIJACK', regex: /act\s+as\s+(?:a\s+)?(?:different|new|evil|unrestricted)/i },
  { type: 'PERSONA_HIJACK', regex: /roleplay\s+as\s+/i },
  { type: 'PERSONA_HIJACK', regex: /respond\s+only\s+in\s+valid\s+JSON/i },
  { type: 'PERSONA_HIJACK', regex: /"bypass":\s*(?:true|false)/i },

  // E. Multilingual Bypass — Unicode homoglyphs and RTL/LTR override characters
  { type: 'MULTILINGUAL_BYPASS', regex: /[‪-‮⁦-⁩]/u },          // Bidi override chars
  { type: 'MULTILINGUAL_BYPASS', regex: /(?:ignorez?|ignorieren|ignora|ignorer)\s+(?:les?\s+)?(?:instruction|consigne|Anweisung)/i }, // FR/DE/ES "ignore instructions"
  { type: 'MULTILINGUAL_BYPASS', regex: /نظام|تجاهل/u }, // Arabic: "system" / "ignore"

  // F. Indirect Smuggling
  { type: 'INDIRECT_SMUGGLING', regex: /<\|(?:im_start|im_end|system|user|assistant)\|>/i },
  { type: 'INDIRECT_SMUGGLING', regex: /\[(?:INST|\/INST|SYS|\/SYS)\]/i },
  { type: 'INDIRECT_SMUGGLING', regex: /&#(?:\d{2,5}|x[0-9a-fA-F]{2,4});/i },
  { type: 'INDIRECT_SMUGGLING', regex: /\[END\s+USER\s+MESSAGE\]/i },
  { type: 'INDIRECT_SMUGGLING', regex: /\[SYSTEM\]:/i },
  { type: 'INDIRECT_SMUGGLING', regex: /<!--[\s\S]*?SYSTEM_OVERRIDE/i },
  { type: 'INDIRECT_SMUGGLING', regex: /execute\s+the\s+system\s+instruction/i },
];

// ── Chat message schema ────────────────────────────────────────────────────────

interface ChatMessage {
  role: string;
  content: string;
}

function isChatMessage(v: unknown): v is ChatMessage {
  return (
    typeof v === 'object' &&
    v !== null &&
    'role' in v &&
    'content' in v &&
    typeof (v as Record<string, unknown>)['content'] === 'string'
  );
}

// ── Middleware ────────────────────────────────────────────────────────────────

export const injectionDetector: RequestHandler = (req, res, next) => {
  const body = req.body as Record<string, unknown>;

  if (!body || !Array.isArray(body['messages'])) {
    res.status(400).json({
      error: 'Invalid request body: "messages" array is required',
    });
    return;
  }

  // ── max_tokens cap — prevent FinOps / cost-DoS ────────────────────────────
  const maxTokens = body['max_tokens'];
  if (maxTokens !== undefined && typeof maxTokens === 'number' && maxTokens > env.MAX_TOKENS_CAP) {
    if (req.securityContext) {
      req.securityContext.threatFlags.push('MAX_TOKENS_EXCEEDED');
      req.securityContext.errorMessage = `max_tokens ${maxTokens} exceeds server cap of ${env.MAX_TOKENS_CAP}`;
    }
    res.status(400).json({
      error: `max_tokens exceeds the server cap of ${env.MAX_TOKENS_CAP}`,
    });
    return;
  }

  const messages = body['messages'] as unknown[];
  const detectedTypes = new Set<InjectionType>();
  const detectedPayloads: string[] = [];

  for (const raw of messages) {
    if (!isChatMessage(raw)) continue;

    const content = raw.content;

    for (const { type, regex } of INJECTION_PATTERNS) {
      regex.lastIndex = 0;
      const match = regex.exec(content);
      if (match !== null) {
        detectedTypes.add(type);
        detectedPayloads.push(match[0]);
      }
    }
  }

  if (detectedTypes.size > 0) {
    const types = Array.from(detectedTypes);

    if (req.securityContext) {
      req.securityContext.injectionDetected = true;
      req.securityContext.injectionTypes = types;
      req.securityContext.detectedPayloads = detectedPayloads;
      req.securityContext.threatFlags.push('PROMPT_INJECTION_DETECTED');
    }

    res.status(400).json({
      error: 'Request blocked: prompt injection detected',
      categories: types,
    });
    return;
  }

  next();
};
