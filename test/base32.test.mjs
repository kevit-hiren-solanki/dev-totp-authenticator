import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeBase32 } from '../host/base32.mjs';

// RFC 4648 §10 test vectors (minus the empty string: an empty secret is an error here).
const RFC_VECTORS = [
  ['MY======', 'f'],
  ['MZXQ====', 'fo'],
  ['MZXW6===', 'foo'],
  ['MZXW6YQ=', 'foob'],
  ['MZXW6YTB', 'fooba'],
  ['MZXW6YTBOI======', 'foobar'],
];

test('decodes the RFC 4648 test vectors', () => {
  for (const [encoded, plain] of RFC_VECTORS) {
    assert.equal(decodeBase32(encoded).toString('ascii'), plain, `vector "${encoded}"`);
  }
});

test('accepts unpadded input, as otpauth secrets are commonly written', () => {
  assert.equal(decodeBase32('MZXW6YTBOI').toString('ascii'), 'foobar');
});

test('accepts lowercase and ignores spaces, as setup screens often group the key', () => {
  assert.equal(decodeBase32('mzxw 6ytb oi').toString('ascii'), 'foobar');
});

test('rejects characters outside the base32 alphabet', () => {
  for (const bad of ['MZXW1===', 'MZXW8===', 'MZXW9===', 'MZXW0===', 'MZXW6YT!']) {
    assert.throws(() => decodeBase32(bad), /base32/i, `input "${bad}"`);
  }
});

test('error messages never echo any part of the secret', () => {
  const secret = 'JBSWY3DPEHPK3PX1';
  assert.throws(
    () => decodeBase32(secret),
    (err) => !err.message.includes('1') && !err.message.includes(secret),
  );
});

test('rejects empty-after-cleanup input so a blank secret cannot slip through', () => {
  assert.throws(() => decodeBase32('   '), /base32/i);
});
