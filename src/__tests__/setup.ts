/**
 * Global Vitest setup — runs once before any test file.
 *
 * Phase 3 will extend this with:
 *  - in-memory MongoDB (mongodb-memory-server)
 *  - ioredis-mock for Redis
 *  - environment variable seeding
 */

// Ensure a clean test environment regardless of host machine config
process.env['NODE_ENV'] = 'test';
process.env['PORT'] = '3001';
process.env['MONGO_URI'] = 'mongodb://localhost:27017/securellm_test';
process.env['REDIS_URI'] = 'redis://localhost:6379';
// LLM key intentionally absent to exercise the missing-key warning path
delete process.env['OPENAI_API_KEY'];
