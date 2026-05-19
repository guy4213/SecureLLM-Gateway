import { Router } from 'express';
import { auditLogger }       from '../middlewares/audit-logger.middleware';
import { authenticate, requireRole } from '../middlewares/auth.middleware';
import { rateLimiter }        from '../middlewares/rate-limiter.middleware';
import { injectionDetector }  from '../middlewares/injection-detector.middleware';
import { piiRedactor }        from '../middlewares/pii-redactor.middleware';
import { outputValidator }    from '../middlewares/output-validator.middleware';
import { chatController }     from '../controllers/chat.controller';
import { getAuditLogs, revealPiiMap } from '../controllers/audit.controller';

export const v1Router = Router();

/**
 * POST /v1/chat
 * Security pipeline (strict execution order):
 *   auditLogger → authenticate → rateLimiter → injectionDetector
 *     → piiRedactor → outputValidator (intercepts res.json) → chatController
 *
 * outputValidator MUST be mounted before chatController so that its res.json
 * override is in place when chatController calls res.json().
 */
v1Router.post(
  '/chat',
  auditLogger,
  authenticate,
  rateLimiter,
  injectionDetector,
  piiRedactor,
  outputValidator,
  chatController
);

/**
 * GET /v1/audit
 * Admin-only access. auditLogger still records the request.
 */
v1Router.get(
  '/audit',
  auditLogger,
  authenticate,
  requireRole('admin'),
  getAuditLogs
);

/**
 * GET /v1/audit/:id/reveal
 * Admin-only. Decrypts the sealed PII map for a specific audit log entry.
 */
v1Router.get(
  '/audit/:id/reveal',
  auditLogger,
  authenticate,
  requireRole('admin'),
  revealPiiMap
);
