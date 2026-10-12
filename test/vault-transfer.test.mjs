import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VaultSession } from '../host/vault-session.mjs';
import { encryptExport } from '../host/vault.mjs';

const PASSWORD = 'correct horse battery staple';
const PASSPHRASE = 'export passphrase 2026';
const SECRET = 'JBSWY3DPEHPK3PXP';
const OTHER_SECRET = 'KRSXG5CTMVRXEZLU';
const URI = `otpauth://totp/Vezly:hiren%40kevit.io?secret=${SECRET}&issuer=Vezly`;
const NOW = 1758700000000;
const KDF = { N: 1024, r: 8, p: 1 };

/** A fresh vault on its own "PC" (temp dir), with cheap scrypt and recorded failure delays. */
async function makePc({ unlock = true } = {}) {
  const vaultPath = join(mkdtempSync(join(tmpdir(), 'vault-transfer-')), 'vault.enc');
  const delays = [];
  const session = new VaultSession({ vaultPath, kdf: KDF, now: () => NOW, sleep: async (ms) => delays.push(ms) });
  if (unlock) {
    await session.handle({ type: 'vault.create', password: PASSWORD });
  }
  return { session, delays };
}

async function exportFrom(session, overrides = {}) {
  return session.handle({ type: 'vault.export', masterPassword: PASSWORD, exportPassphrase: PASSPHRASE, ...overrides });
}

test('accounts exported on one PC import into another with identical codes', async () => {
  const { session: pcA } = await makePc();
  await pcA.handle({ type: 'vault.add', otpauthUri: URI, domain: 'app.vezly.ai' });
  await pcA.handle({ type: 'vault.add', label: 'prod admin', secret: OTHER_SECRET });
  const exported = await exportFrom(pcA);
  assert.equal(exported.count, 2);

  const { session: pcB } = await makePc();
  const result = await pcB.handle({ type: 'vault.import', content: exported.content, passphrase: PASSPHRASE });
  assert.deepEqual(result, { imported: 2, skipped: 0, invalid: 0 });

  const codesA = (await pcA.handle({ type: 'vault.list' })).accounts.map(({ label, issuer, domain, code }) => ({ label, issuer, domain, code }));
  const codesB = (await pcB.handle({ type: 'vault.list' })).accounts.map(({ label, issuer, domain, code }) => ({ label, issuer, domain, code }));
  assert.deepEqual(codesB, codesA);
});

test('export asks for the master password again even while unlocked', async () => {
  const { session, delays } = await makePc();
  await assert.rejects(exportFrom(session, { masterPassword: 'wrong password!' }), /wrong master password/i);
  assert.deepEqual(delays, [500]);
});

test('export requires a passphrase of at least 12 characters', async () => {
  const { session } = await makePc();
  await assert.rejects(exportFrom(session, { exportPassphrase: 'short pass' }), /12/);
});

test('export needs an unlocked vault', async () => {
  const { session } = await makePc();
  await session.handle({ type: 'vault.lock' });
  await assert.rejects(exportFrom(session), /locked/i);
});

test('the export file and the export reply contain no secret, label or password in plaintext', async () => {
  const { session } = await makePc();
  await session.handle({ type: 'vault.add', otpauthUri: URI, domain: 'app.vezly.ai' });
  const exported = await exportFrom(session);
  const everything = JSON.stringify(exported);
  for (const plain of [SECRET, 'hiren@kevit.io', 'app.vezly.ai', 'Vezly', PASSWORD, PASSPHRASE]) {
    assert.ok(!everything.includes(plain), `export leaks "${plain}"`);
  }
  assert.equal(JSON.parse(exported.content).kind, 'dev-authenticator-export');
  assert.match(exported.fileName, /^dev-authenticator-export-\d{4}-\d{2}-\d{2}\.enc$/);
});

test('each export is encrypted afresh, so two exports of the same vault differ', async () => {
  const { session } = await makePc();
  await session.handle({ type: 'vault.add', otpauthUri: URI });
  const first = JSON.parse((await exportFrom(session)).content);
  const second = JSON.parse((await exportFrom(session)).content);
  assert.notEqual(first.kdf.salt, second.kdf.salt);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.data, second.data);
});

test('a wrong passphrase imports nothing and is delayed', async () => {
  const { session: pcA } = await makePc();
  await pcA.handle({ type: 'vault.add', otpauthUri: URI });
  const { content } = await exportFrom(pcA);

  const { session: pcB, delays } = await makePc();
  await assert.rejects(pcB.handle({ type: 'vault.import', content, passphrase: 'not the passphrase' }), /wrong passphrase|corrupted/i);
  assert.deepEqual(delays, [500]);
  assert.equal((await pcB.handle({ type: 'vault.list' })).accounts.length, 0);
});

test('a tampered export file is rejected', async () => {
  const { session: pcA } = await makePc();
  await pcA.handle({ type: 'vault.add', otpauthUri: URI });
  const file = JSON.parse((await exportFrom(pcA)).content);
  const data = Buffer.from(file.data, 'base64');
  data[0] ^= 0xff;
  file.data = data.toString('base64');

  const { session: pcB } = await makePc();
  await assert.rejects(pcB.handle({ type: 'vault.import', content: JSON.stringify(file), passphrase: PASSPHRASE }), /wrong passphrase|corrupted/i);
});

test('import merges: duplicates are skipped and existing accounts are untouched', async () => {
  const { session: pcA } = await makePc();
  await pcA.handle({ type: 'vault.add', otpauthUri: URI });
  await pcA.handle({ type: 'vault.add', label: 'prod admin', secret: OTHER_SECRET });
  const { content } = await exportFrom(pcA);

  const { session: pcB } = await makePc();
  await pcB.handle({ type: 'vault.add', label: 'renamed on B', secret: SECRET });
  const result = await pcB.handle({ type: 'vault.import', content, passphrase: PASSPHRASE });
  assert.deepEqual(result, { imported: 1, skipped: 1, invalid: 0 });

  const labels = (await pcB.handle({ type: 'vault.list' })).accounts.map((account) => account.label);
  assert.deepEqual(labels, ['renamed on B', 'prod admin']);
});

test('importing the same file twice adds nothing the second time', async () => {
  const { session: pcA } = await makePc();
  await pcA.handle({ type: 'vault.add', otpauthUri: URI });
  const { content } = await exportFrom(pcA);

  const { session: pcB } = await makePc();
  await pcB.handle({ type: 'vault.import', content, passphrase: PASSPHRASE });
  const again = await pcB.handle({ type: 'vault.import', content, passphrase: PASSPHRASE });
  assert.deepEqual(again, { imported: 0, skipped: 1, invalid: 0 });
});

test('malformed accounts inside a correctly encrypted file are counted and skipped', async () => {
  const content = encryptExport(
    [
      { label: 'good', issuer: '', secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30, domain: '' },
      { label: 'bad secret', issuer: '', secret: 'NOT-BASE32!', algorithm: 'SHA1', digits: 6, period: 30 },
      { label: '', issuer: '', secret: OTHER_SECRET, algorithm: 'SHA1', digits: 6, period: 30 },
      { label: 'bad algorithm', issuer: '', secret: OTHER_SECRET, algorithm: 'MD5', digits: 6, period: 30 },
      { label: 'bad digits', issuer: '', secret: OTHER_SECRET, algorithm: 'SHA1', digits: 99, period: 30 },
      'not even an object',
    ],
    PASSPHRASE,
    KDF,
  );
  const { session } = await makePc();
  const result = await session.handle({ type: 'vault.import', content, passphrase: PASSPHRASE });
  assert.deepEqual(result, { imported: 1, skipped: 0, invalid: 5 });
});

test('import rejects files that are not exports, or too large', async () => {
  const { session } = await makePc();
  for (const content of ['not json', '{"kind":"something-else"}', JSON.stringify({ kind: 'dev-authenticator-export', v: 99 }), 'x'.repeat(2_000_000)]) {
    await assert.rejects(session.handle({ type: 'vault.import', content, passphrase: PASSPHRASE }), /export file|too large/i);
  }
});

test('import needs an unlocked vault', async () => {
  const { session: pcA } = await makePc();
  const { content } = await exportFrom(pcA);
  const { session: pcB } = await makePc();
  await pcB.handle({ type: 'vault.lock' });
  await assert.rejects(pcB.handle({ type: 'vault.import', content, passphrase: PASSPHRASE }), /locked/i);
});
