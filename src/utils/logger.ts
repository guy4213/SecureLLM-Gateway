import pino from 'pino';

export const logger = pino({
  level: process.env['NODE_ENV'] === 'test' ? 'silent' : 'info',
  base: { service: 'securellm-gateway' },
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level(label) {
      return { level: label };
    },
  },
});
