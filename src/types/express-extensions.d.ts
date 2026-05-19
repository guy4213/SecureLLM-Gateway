import 'express';
import type { Logger } from 'pino';

declare global {
  namespace Express {
    interface Request {
      client?: ClientInfo;
      /** UUID assigned by correlation-id middleware; echoed as X-Request-ID */
      correlationId?: string;
      /** Child pino logger pre-bound with correlationId */
      log?: Logger;
      /** token → original PII value; populated by pii-redactor middleware */
      piiMap?: Map<string, string>;
      securityContext?: SecurityContext;
    }
  }
}

export interface ClientInfo {
  id: string;
  role: 'client' | 'admin';
  keyHash: string;
  /** Per-key rate limit override. Undefined = use global RATE_LIMIT_MAX_REQUESTS */
  rateLimitPerMinute?: number;
}

export interface SealedPiiMap {
  iv:   string;
  tag:  string;
  data: string;
}

export interface SecurityContext {
  correlationId: string;
  requestStart: number;
  injectionDetected: boolean;
  /** Which of the 5 injection categories fired */
  injectionTypes: string[];
  /** Raw matched substrings — used by output-validator for echo detection */
  detectedPayloads: string[];
  piiDetected: boolean;
  piiTokenCount: number;
  outputBlocked: boolean;
  threatFlags: string[];
  requestBodyHash: string | null;
  responseBodyHash: string | null;
  sealedPiiMap: SealedPiiMap | null;
  llmProvider: string | null;
  llmModel: string | null;
  /** True when the LLM response was served from the per-tenant Redis cache */
  cacheHit: boolean;
  errorMessage: string | null;
}
