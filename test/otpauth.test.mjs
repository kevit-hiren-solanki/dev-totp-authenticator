import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseOtpauthUri } from '../host/otpauth.mjs';

test('parses a full otpauth URI as platforms generate them', () => {
  const parsed = parseOtpauthUri('otpauth://totp/Vezly:hiren%40kevit.io?secret=JBSWY3DPEHPK3PXP&issuer=Vezly&algorithm=SHA1&digits=6&period=30');
  assert.deepEqual(parsed, {
    label: 'hiren@kevit.io',
    issuer: 'Vezly',
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  });
});

test('applies the standard defaults when optional params are missing', () => {
  const parsed = parseOtpauthUri('otpauth://totp/hiren?secret=JBSWY3DPEHPK3PXP');
  assert.deepEqual(parsed, {
    label: 'hiren',
    issuer: '',
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  });
});

test('prefers the issuer param but falls back to the label prefix', () => {
  const fromPrefix = parseOtpauthUri('otpauth://totp/Staging:me%40kevit.io?secret=JBSWY3DPEHPK3PXP');
  assert.equal(fromPrefix.issuer, 'Staging');
  assert.equal(fromPrefix.label, 'me@kevit.io');
});

test('rejects hotp URIs, which are counter-based and cannot be shown live', () => {
  assert.throws(() => parseOtpauthUri('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=0'), /totp/i);
});

test('rejects a URI without a secret', () => {
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?issuer=Vezly'), /secret/i);
});

test('rejects a secret that is not valid base32', () => {
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret=NOT-BASE32!'), /base32/i);
});

test('rejects non-otpauth input such as a random URL or pasted text', () => {
  assert.throws(() => parseOtpauthUri('https://example.com/qr'), /otpauth/i);
  assert.throws(() => parseOtpauthUri('hello'), /otpauth/i);
});
