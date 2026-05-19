import mongoose from 'mongoose';
import { env } from '../config/env';
import { logger } from '../utils/logger';

const RECONNECT_INTERVAL_MS = 5_000;
const MAX_RECONNECT_ATTEMPTS = 10;

let reconnectAttempts = 0;

export function isMongoConnected(): boolean {
  return mongoose.connection.readyState === 1; // 1 = connected
}

async function attemptConnect(): Promise<void> {
  await mongoose.connect(env.MONGO_URI, {
    serverSelectionTimeoutMS: 5_000,
    heartbeatFrequencyMS: 10_000,
    maxPoolSize: 100,
    minPoolSize: 5,
  });
}

async function connectWithRetry(): Promise<void> {
  try {
    await attemptConnect();
    reconnectAttempts = 0;
    logger.info('MongoDB connected');
  } catch (err) {
    reconnectAttempts += 1;

    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
      logger.fatal({ attempts: MAX_RECONNECT_ATTEMPTS }, 'MongoDB max retry attempts reached — terminating');
      process.exit(1);
    }

    const delay = Math.min(reconnectAttempts * RECONNECT_INTERVAL_MS, 30_000);
    logger.warn({ attempt: reconnectAttempts, maxAttempts: MAX_RECONNECT_ATTEMPTS, retryInMs: delay }, 'MongoDB connection failed, retrying');
    await new Promise<void>((resolve) => setTimeout(resolve, delay));
    await connectWithRetry();
  }
}

export async function connectMongo(): Promise<void> {
  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected — attempting to reconnect');
    void connectWithRetry();
  });

  mongoose.connection.on('error', (err: Error) => {
    logger.error({ err: err.message }, 'MongoDB error');
  });

  await connectWithRetry();
}

export async function disconnectMongo(): Promise<void> {
  await mongoose.disconnect();
  logger.info('MongoDB disconnected gracefully');
}
