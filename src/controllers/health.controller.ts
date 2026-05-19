import { RequestHandler } from 'express';
import { isMongoConnected } from '../database/mongo';
import { isRedisConnected } from '../database/redis';
import { getAuditFailureCount } from '../middlewares/audit-logger.middleware';
import { env } from '../config/env';

type CheckStatus = 'ok' | 'down' | 'missing_key';

interface HealthCheck {
  status: CheckStatus;
  latencyMs?: number;
}

interface HealthResponse {
  status: 'ok' | 'degraded';
  timestamp: string;
  checks: {
    mongodb: HealthCheck;
    redis: HealthCheck;
    llmProvider: HealthCheck;
    auditLog: { status: 'ok' | 'degraded'; failedWrites: number };
  };
}

export const healthCheck: RequestHandler = (_req, res) => {
  const mongoOk = isMongoConnected();
  const redisOk = isRedisConnected();
  const llmOk = !env.llmProviderKeyMissing;
  const auditFailures = getAuditFailureCount();
  const auditOk = auditFailures === 0;

  const allHealthy = mongoOk && redisOk && llmOk && auditOk;

  const body: HealthResponse = {
    status: allHealthy ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    checks: {
      mongodb:     { status: mongoOk  ? 'ok' : 'down' },
      redis:       { status: redisOk  ? 'ok' : 'down' },
      llmProvider: { status: llmOk    ? 'ok' : 'missing_key' },
      auditLog:    { status: auditOk  ? 'ok' : 'degraded', failedWrites: auditFailures },
    },
  };

  // 200 even when degraded: liveness vs readiness distinction.
  // Kubernetes liveness probe needs 200 to know the process is alive.
  // A separate readiness probe can parse the body.
  res.status(allHealthy ? 200 : 503).json(body);
};
