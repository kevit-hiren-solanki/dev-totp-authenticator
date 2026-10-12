import { createHmac } from 'node:crypto';

export const TOTP_PERIOD_SECONDS = 30;
const DEFAULT_DIGITS = 6;
const HASHES_BY_ALGORITHM = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

/**
 * Generates an RFC 6238 TOTP code for a secret given as plain ASCII (as the platform stores it)
 * or as raw bytes (as vault secrets are after base32 decoding).
 * @param secret - the shared secret, an ASCII string or a Buffer
 * @param options - `timeMs` to compute for (defaults to now), `digits`, `algorithm`
 *   (SHA1, SHA256 or SHA512) and `periodSeconds`
 * @returns the zero-padded code
 */
export function generateTotp(
  secret,
  { timeMs = Date.now(), digits = DEFAULT_DIGITS, algorithm = 'SHA1', periodSeconds = TOTP_PERIOD_SECONDS } = {},
) {
  const hash = HASHES_BY_ALGORITHM[algorithm];
  if (!hash) {
    throw new Error(`Unsupported TOTP algorithm: ${algorithm}. Supported: ${Object.keys(HASHES_BY_ALGORITHM).join(', ')}.`);
  }
  const counter = Math.floor(timeMs / 1000 / periodSeconds);
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(BigInt(counter));

  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'ascii');
  const hmac = createHmac(hash, key).update(counterBytes).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = hmac.readUInt32BE(offset) & 0x7fffffff;

  return String(binary % 10 ** digits).padStart(digits, '0');
}

/**
 * Returns the epoch millisecond at which the code for `timeMs` stops being current.
 * @param timeMs - the moment to check (defaults to now)
 * @returns the start of the next TOTP period, in epoch milliseconds
 */
export function periodEndsAt(timeMs = Date.now()) {
  const periodMs = TOTP_PERIOD_SECONDS * 1000;
  return (Math.floor(timeMs / periodMs) + 1) * periodMs;
}
