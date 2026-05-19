import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { env } from '../config/env';
import { logger } from './logger';

const ALGO  = 'aes-256-gcm' as const;
const IV_LEN = 12; // 96-bit IV — recommended for GCM

export interface SealedPiiMap {
  iv:   string; // base64, 12 bytes
  tag:  string; // base64, 16-byte GCM auth tag
  data: string; // base64, ciphertext
}

/**
 * Encrypts a piiMap with AES-256-GCM using the PII_ENC_KEY env var.
 * Returns null (with a warning) if the key is not configured.
 */
export function sealPiiMap(piiMap: Map<string, string>): SealedPiiMap | null {
  const hexKey = env.PII_ENC_KEY;
  if (!hexKey) {
    logger.warn('PII_ENC_KEY not set — piiMap cannot be persisted to audit log');
    return null;
  }

  const key        = Buffer.from(hexKey, 'hex');
  const iv         = randomBytes(IV_LEN);
  const cipher     = createCipheriv(ALGO, key, iv);
  const plaintext  = JSON.stringify(Object.fromEntries(piiMap));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

  return {
    iv:   iv.toString('base64'),
    tag:  cipher.getAuthTag().toString('base64'),
    data: ciphertext.toString('base64'),
  };
}

/**
 * Decrypts a sealed piiMap. Throws on tampered ciphertext (GCM tag mismatch).
 */
export function openPiiMap(sealed: SealedPiiMap): Record<string, string> {
  const hexKey = env.PII_ENC_KEY;
  if (!hexKey) throw new Error('PII_ENC_KEY is not configured');

  const key      = Buffer.from(hexKey, 'hex');
  const decipher = createDecipheriv(ALGO, key, Buffer.from(sealed.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(sealed.data, 'base64')),
    decipher.final(),
  ]);

  return JSON.parse(plaintext.toString('utf8')) as Record<string, string>;
}
