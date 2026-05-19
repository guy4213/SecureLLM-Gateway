import { Router } from 'express';
import { healthCheck } from '../controllers/health.controller';

export const rootRouter = Router();

/** GET /healthz — unauthenticated liveness / readiness probe */
rootRouter.get('/healthz', healthCheck);
