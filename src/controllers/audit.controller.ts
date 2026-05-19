import { RequestHandler } from 'express';
import { AuditLogModel } from '../models/AuditLog.model';
import { openPiiMap } from '../utils/pii-crypto.util';
import { logger } from '../utils/logger';

const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 50;

/**
 * GET /v1/audit
 * Query params:
 *   limit      — number of records to return (1–500, default 50)
 *   offset     — number of records to skip (default 0)
 *   since         — ISO 8601 timestamp; return only records after this time (optional)
 *   correlationId — return the single request with this UUID (optional)
 *   apiKeyId      — filter by a specific key ID (optional)
 *   onlyThreats   — "true" to return only flagged transactions (optional)
 */
export const getAuditLogs: RequestHandler = async (req, res) => {
  try {
    const rawLimit = parseInt(String(req.query['limit'] ?? DEFAULT_LIMIT), 10);
    const limit = Number.isNaN(rawLimit)
      ? DEFAULT_LIMIT
      : Math.min(Math.max(1, rawLimit), MAX_LIMIT);

    const rawOffset = parseInt(String(req.query['offset'] ?? 0), 10);
    const offset = Number.isNaN(rawOffset) ? 0 : Math.max(0, rawOffset);

    const filter: Record<string, unknown> = {};

    if (typeof req.query['correlationId'] === 'string') {
      filter['correlationId'] = req.query['correlationId'];
    }

    if (typeof req.query['since'] === 'string') {
      const since = new Date(req.query['since']);
      if (!Number.isNaN(since.getTime())) {
        filter['timestamp'] = { $gte: since };
      }
    }

    if (typeof req.query['apiKeyId'] === 'string') {
      filter['apiKeyId'] = req.query['apiKeyId'];
    }

    if (req.query['onlyThreats'] === 'true') {
      filter['$or'] = [
        { promptInjectionDetected: true },
        { outputBlocked: true },
        { piiDetected: true },
      ];
    }

    const [logs, total] = await Promise.all([
      AuditLogModel.find(filter)
        .sort({ timestamp: -1 })
        .skip(offset)
        .limit(limit)
        .lean(),
      AuditLogModel.countDocuments(filter),
    ]);

    res.status(200).json({ total, limit, offset, logs });
  } catch (err) {
    (req.log ?? logger).error({ err }, 'Audit query failed');
    res.status(503).json({ error: 'Failed to retrieve audit logs' });
  }
};

/**
 * GET /v1/audit/:id/reveal
 * Admin-only. Decrypts and returns the sealed PII token→original mapping
 * for a single audit log entry.
 */
export const revealPiiMap: RequestHandler = async (req, res) => {
  const { id } = req.params;

  try {
    const entry = await AuditLogModel.findById(id).lean();

    if (!entry) {
      res.status(404).json({ error: 'Audit log entry not found' });
      return;
    }

    if (!entry.sealedPiiMap) {
      res.status(200).json({
        correlationId: entry.correlationId,
        message: 'No PII was detected in this request',
        tokens: {},
      });
      return;
    }

    const tokens = openPiiMap(entry.sealedPiiMap as { iv: string; tag: string; data: string });

    res.status(200).json({
      correlationId: entry.correlationId,
      tokens,
    });
  } catch (err) {
    (req.log ?? logger).error({ err }, 'PII reveal failed');
    res.status(503).json({ error: 'Failed to decrypt PII map' });
  }
};
