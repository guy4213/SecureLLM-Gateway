import { RequestHandler } from 'express';
import { AuditLogModel, type ThreatFlag } from '../models/AuditLog.model';
import { isMongoConnected } from '../database/mongo';
import { logger } from '../utils/logger';
import type { SecurityContext } from '../types/express-extensions';
import { Types } from 'mongoose';

let _auditFailures = 0;

/** Total audit log writes that failed since process start. Exposed via /healthz. */
export function getAuditFailureCount(): number {
  return _auditFailures;
}

function toObjectIdOrNull(id: string | undefined): Types.ObjectId | null {
  if (!id) return null;
  try {
    return new Types.ObjectId(id);
  } catch {
    return null;
  }
}

async function persistAuditLog(
  ctx: SecurityContext,
  clientId: string | undefined,
  keyHash: string | undefined,
  endpoint: string,
  method: string,
  statusCode: number
): Promise<void> {
  if (!isMongoConnected()) return;

  const latencyMs = Date.now() - ctx.requestStart;

  await AuditLogModel.create({
    correlationId: ctx.correlationId,
    timestamp: new Date(ctx.requestStart),
    apiKeyId: toObjectIdOrNull(clientId),
    apiKeyHash: keyHash ?? null,
    endpoint,
    httpMethod: method.toUpperCase(),
    requestBodyHash: ctx.requestBodyHash,
    responseBodyHash: ctx.responseBodyHash,
    sealedPiiMap: ctx.sealedPiiMap ?? null,
    statusCode,
    latencyMs,
    promptInjectionDetected: ctx.injectionDetected,
    injectionTypes: ctx.injectionTypes,
    piiDetected: ctx.piiDetected,
    piiTokenCount: ctx.piiTokenCount,
    outputBlocked: ctx.outputBlocked,
    threatFlags: ctx.threatFlags as ThreatFlag[],
    llmProvider: ctx.llmProvider,
    llmModel: ctx.llmModel,
    cacheHit: ctx.cacheHit,
    errorMessage: ctx.errorMessage,
  });
}

/**
 * Must be the FIRST middleware on every route so that:
 *  1. `securityContext` is initialised before any downstream middleware writes to it.
 *  2. `res.on('finish')` captures the final status code even for auth/rate-limit rejections.
 */
export const auditLogger: RequestHandler = (req, res, next) => {
  req.securityContext = {
    correlationId: req.correlationId ?? '',
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

  res.on('finish', () => {
    const ctx = req.securityContext;
    if (!ctx) return;

    void persistAuditLog(
      ctx,
      req.client?.id,
      req.client?.keyHash,
      req.path,
      req.method,
      res.statusCode
    ).catch((err: Error) => {
      _auditFailures++;
      (req.log ?? logger).error({ err: err.message }, 'Failed to persist audit log');
    });
  });

  next();
};
