import express, { Request, Response, NextFunction } from 'express';
import { correlationId } from './middlewares/correlation-id.middleware';
import { logger } from './utils/logger';
import { rootRouter } from './routes/root.routes';
import { v1Router }   from './routes/v1.routes';

export function createApp(): express.Application {
  const app = express();

  // ── Correlation ID (must be first — sets X-Request-ID on every response) ───
  app.use(correlationId);

  // ── Body parsing ────────────────────────────────────────────────────────────
  // 1 MB ceiling; LLM prompts can be large but should not be unbounded
  app.use(express.json({ limit: '1mb' }));

  // ── Security headers (manual, no external dependency) ──────────────────────
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    // Remove Express fingerprint
    res.removeHeader('X-Powered-By');
    next();
  });

  // ── Routes ──────────────────────────────────────────────────────────────────
  app.use('/', rootRouter);
  app.use('/v1', v1Router);

  // ── 404 handler ─────────────────────────────────────────────────────────────
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not Found' });
  });

  // ── Global error handler ─────────────────────────────────────────────────────
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error & { status?: number; statusCode?: number; type?: string }, req: Request, res: Response, _next: NextFunction) => {
    // Propagate well-known HTTP client errors (4xx) from body-parser and similar middleware
    const httpStatus = err.status ?? err.statusCode;
    if (httpStatus !== undefined && httpStatus >= 400 && httpStatus < 500) {
      res.status(httpStatus).json({ error: err.message || 'Bad Request' });
      return;
    }
    (req.log ?? logger).error({ err: err.message }, 'Unhandled server error');
    res.status(500).json({ error: 'Internal Server Error' });
  });

  return app;
}
