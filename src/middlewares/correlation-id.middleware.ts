import { RequestHandler } from 'express';
import { randomUUID } from 'node:crypto';
import { logger } from '../utils/logger';

export const correlationId: RequestHandler = (req, res, next) => {
  req.correlationId = randomUUID();
  req.log = logger.child({ correlationId: req.correlationId });
  res.setHeader('X-Request-ID', req.correlationId);
  next();
};
