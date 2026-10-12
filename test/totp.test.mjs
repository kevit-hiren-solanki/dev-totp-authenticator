import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateTotp, periodEndsAt } from '../host/totp.mjs';

const RFC_6238_SECRET = '12345678901234567890';

test('matches the RFC 6238 SHA-1 test vectors', () => {
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [seconds, expected] of vectors) {
    assert.equal(generateTotp(RFC_6238_SECRET, { timeMs: seconds * 1000, digits: 8 }), expected);
  }
});

test('defaults to 6 digits', () => {
  assert.equal(generateTotp(RFC_6238_SECRET, { timeMs: 59_000 }), '287082');
});

test('accepts the secret as a Buffer, for vault secrets decoded from base32', () => {
  const buffer = Buffer.from(RFC_6238_SECRET, 'ascii');
  assert.equal(generateTotp(buffer, { timeMs: 59_000 }), generateTotp(RFC_6238_SECRET, { timeMs: 59_000 }));
});

test('matches the RFC 6238 SHA-256 and SHA-512 test vectors', () => {
  const sha256Secret = Buffer.from('12345678901234567890123456789012', 'ascii');
  const sha512Secret = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii');
  assert.equal(generateTotp(sha256Secret, { timeMs: 59_000, digits: 8, algorithm: 'SHA256' }), '46119246');
  assert.equal(generateTotp(sha512Secret, { timeMs: 59_000, digits: 8, algorithm: 'SHA512' }), '90693936');
});

test('honours a custom period, as some otpauth URIs use 60 seconds', () => {
  // T=29s and T=30s straddle the default 30s boundary but share the first 60s window.
  assert.equal(
    generateTotp(RFC_6238_SECRET, { timeMs: 29_000, periodSeconds: 60 }),
    generateTotp(RFC_6238_SECRET, { timeMs: 30_000, periodSeconds: 60 }),
  );
  assert.notEqual(
    generateTotp(RFC_6238_SECRET, { timeMs: 29_000 }),
    generateTotp(RFC_6238_SECRET, { timeMs: 30_000 }),
  );
});

test('rejects an unsupported algorithm instead of generating a wrong code', () => {
  assert.throws(() => generateTotp(RFC_6238_SECRET, { timeMs: 59_000, algorithm: 'MD5' }), /algorithm/i);
});

test('periodEndsAt returns the start of the next 30-second window', () => {
  assert.equal(periodEndsAt(59_000), 60_000);
  assert.equal(periodEndsAt(60_000), 90_000);
});
