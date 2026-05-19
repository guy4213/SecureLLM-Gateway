import { RequestHandler } from 'express';
import { hashApiKey } from '../utils/crypto.util';
import { ApiKeyModel } from '../models/ApiKey.model';
import { logger } from '../utils/logger';
import type { ApiKeyRole } from '../models/ApiKey.model';

const HEADER = 'x-api-key';

export const authenticate: RequestHandler = async (req, res, next) => {
  const rawKey = req.headers[HEADER];

  if (typeof rawKey !== 'string' || rawKey.trim() === '') {
    if (req.securityContext) {
      req.securityContext.threatFlags.push('AUTH_FAILURE');
      req.securityContext.errorMessage = 'Missing x-api-key header';
    }
    res.status(401).json({ error: 'Unauthorized: x-api-key header is required' });
    return;
  }

  const keyHash = hashApiKey(rawKey.trim());

  try {
    // Lean query — we only need id + role, avoid loading the full document into mongoose
    const record = await ApiKeyModel
      .findOne({ keyHash, isActive: true }, { _id: 1, role: 1, rateLimitPerMinute: 1 })
      .lean();

    if (record === null) {
      if (req.securityContext) {
        req.securityContext.threatFlags.push('AUTH_FAILURE');
        req.securityContext.errorMessage = 'Invalid or inactive API key';
      }
      res.status(401).json({ error: 'Unauthorized: invalid or inactive API key' });
      return;
    }

    req.client = {
      id: record._id.toString(),
      role: record.role as ApiKeyRole,
      keyHash,
      ...(record.rateLimitPerMinute != null
        ? { rateLimitPerMinute: record.rateLimitPerMinute }
        : {}),
    };

    // Fire-and-forget: update lastUsedAt and increment counter without blocking the request
    void ApiKeyModel.updateOne(
      { _id: record._id },
      { $set: { lastUsedAt: new Date() }, $inc: { requestCount: 1 } }
    ).catch((err: Error) => {
      (req.log ?? logger).error({ err: err.message }, 'Failed to update key usage');
    });

    next();
  } catch (err) {
    (req.log ?? logger).error({ err }, 'Auth database error');
    res.status(503).json({ error: 'Service temporarily unavailable' });
  }
};

/**
 * Role-guard factory. Use after `authenticate`.
 * Example: `router.get('/audit', authenticate, requireRole('admin'), auditController)`
 */
export const requireRole = (role: ApiKeyRole): RequestHandler => (req, res, next) => {
  if (req.client?.role !== role) {
    res.status(403).json({ error: 'Forbidden: insufficient privileges' });
    return;
  }
  next();
};
