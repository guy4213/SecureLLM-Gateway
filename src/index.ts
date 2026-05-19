import { createApp }     from './server';
import { connectMongo, disconnectMongo } from './database/mongo';
import { connectRedis, disconnectRedis } from './database/redis';
import { logger }        from './utils/logger';
import { env }           from './config/env';

async function bootstrap(): Promise<void> {
  await connectMongo();
  await connectRedis();

  const app = createApp();
  const server = app.listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV }, 'Gateway listening');
    if (env.llmProviderKeyMissing) {
      logger.warn('OPENAI_API_KEY is absent — /v1/chat will return 503');
    }
  });

  // ── Graceful shutdown ────────────────────────────────────────────────────────
  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'Shutdown signal received — draining connections');
    server.close(async () => {
      await disconnectMongo();
      await disconnectRedis();
      logger.info('Clean exit');
      process.exit(0);
    });

    setTimeout(() => {
      logger.error('Forced exit — connections did not drain in time');
      process.exit(1);
    }, 10_000).unref();
  };

  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT',  () => void shutdown('SIGINT'));
}

bootstrap().catch((err: Error) => {
  logger.fatal({ err: err.message }, 'Fatal startup error');
  process.exit(1);
});
