import { createHash, randomBytes, timingSafeEqual } from 'crypto';

const SHA256_ALGORITHM = 'sha256';
/** 32 bytes → 64 hex characters; matches SHA-256 output length */
const API_KEY_RANDOM_BYTES = 32;

/**
 * Produces a lowercase SHA-256 hex digest of a raw API key string.
 * This is the value stored in MongoDB — the plaintext key is never persisted.
 */
export function hashApiKey(rawKey: string): string {
  return createHash(SHA256_ALGORITHM).update(rawKey, 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two strings encoded as UTF-8 byte sequences.
 *
 * Uses `crypto.timingSafeEqual` to prevent timing side-channels that could
 * allow an attacker to determine partial hash matches via response latency.
 *
 * Both inputs are compared as raw UTF-8 buffers; if their byte lengths differ
 * a dummy same-length comparison is still executed to maintain a uniform
 * timing profile before returning false.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Execute a dummy comparison of equal-length buffers so that the
    // function's execution time does not reveal the length mismatch.
    timingSafeEqual(bufA, bufA);
    return false;
  }

  return timingSafeEqual(bufA, bufB);
}

/**
 * Produces a SHA-256 hex digest of arbitrary content (string or Buffer).
 * Used to create tamper-evident hashes of request/response bodies for audit logs.
 */
export function hashContent(content: string | Buffer): string {
  const hash = createHash(SHA256_ALGORITHM);
  if (typeof content === 'string') {
    hash.update(content, 'utf8');
  } else {
    hash.update(content);
  }
  return hash.digest('hex');
}

/**
 * Generates a cryptographically secure random API key.
 *
 * Returns both the raw key (display once to the caller, then discard) and its
 * SHA-256 hash (safe to persist in MongoDB).
 */
export function generateApiKey(): { rawKey: string; keyHash: string } {
  const rawKey = randomBytes(API_KEY_RANDOM_BYTES).toString('hex');
  const keyHash = hashApiKey(rawKey);
  return { rawKey, keyHash };
}
