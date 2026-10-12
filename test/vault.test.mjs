import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { changeVaultPassword, createVault, saveVault, unlockVault, vaultExists } from '../host/vault.mjs';

const PASSWORD = 'correct horse battery staple';
const ACCOUNT = {
  id: 'a1',
  label: 'hiren@kevit.io',
  issuer: 'Vezly Staging',
  secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  addedAt: 1758700000000,
};

// Scrypt at the production cost is deliberately slow; tests pass a cheap cost to stay fast.
const TEST_KDF = { N: 1024, r: 8, p: 1 };

function tempVaultPath() {
  return join(mkdtempSync(join(tmpdir(), 'vault-test-')), 'deep', 'vault.enc');
}

test('a new vault unlocks with its password and starts empty', () => {
  const path = tempVaultPath();
  assert.equal(vaultExists(path), false);
  createVault(path, PASSWORD, TEST_KDF);
  assert.equal(vaultExists(path), true);
  assert.deepEqual(unlockVault(path, PASSWORD).accounts, []);
});

test('accounts round-trip through save and unlock', () => {
  const path = tempVaultPath();
  const { key } = createVault(path, PASSWORD, TEST_KDF);
  saveVault(path, key, [ACCOUNT]);
  assert.deepEqual(unlockVault(path, PASSWORD).accounts, [ACCOUNT]);
});

test('a wrong password is rejected without echoing the password', () => {
  const path = tempVaultPath();
  createVault(path, PASSWORD, TEST_KDF);
  assert.throws(
    () => unlockVault(path, 'wrong-password'),
    (err) => /wrong master password/i.test(err.message) && !err.message.includes('wrong-password'),
  );
});

test('a tampered vault file is rejected the same way as a wrong password', () => {
  const path = tempVaultPath();
  const { key } = createVault(path, PASSWORD, TEST_KDF);
  saveVault(path, key, [ACCOUNT]);

  const file = JSON.parse(readFileSync(path, 'utf8'));
  const data = Buffer.from(file.data, 'base64');
  data[0] ^= 0xff;
  file.data = data.toString('base64');
  writeFileSync(path, JSON.stringify(file));

  assert.throws(() => unlockVault(path, PASSWORD), /wrong master password|corrupted/i);
});

test('the vault file never contains a secret or account label in plaintext', () => {
  const path = tempVaultPath();
  const { key } = createVault(path, PASSWORD, TEST_KDF);
  saveVault(path, key, [ACCOUNT]);
  const raw = readFileSync(path, 'utf8');
  assert.ok(!raw.includes(ACCOUNT.secret));
  assert.ok(!raw.includes(ACCOUNT.label));
  assert.ok(!raw.includes(PASSWORD));
});

test('the vault file and its directory are private to the user', () => {
  const path = tempVaultPath();
  createVault(path, PASSWORD, TEST_KDF);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(statSync(join(path, '..')).mode & 0o777, 0o700);
});

test('changing the password re-encrypts: old password fails, new one works', () => {
  const path = tempVaultPath();
  const { key } = createVault(path, PASSWORD, TEST_KDF);
  saveVault(path, key, [ACCOUNT]);

  changeVaultPassword(path, PASSWORD, 'new password 123', TEST_KDF);

  assert.throws(() => unlockVault(path, PASSWORD), /wrong master password/i);
  assert.deepEqual(unlockVault(path, 'new password 123').accounts, [ACCOUNT]);
});

test('each save uses a fresh IV so identical contents never encrypt alike', () => {
  const path = tempVaultPath();
  const { key } = createVault(path, PASSWORD, TEST_KDF);
  saveVault(path, key, [ACCOUNT]);
  const first = JSON.parse(readFileSync(path, 'utf8'));
  saveVault(path, key, [ACCOUNT]);
  const second = JSON.parse(readFileSync(path, 'utf8'));
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.data, second.data);
});

test('creating over an existing vault is refused so a typo cannot wipe accounts', () => {
  const path = tempVaultPath();
  createVault(path, PASSWORD, TEST_KDF);
  assert.throws(() => createVault(path, 'another password', TEST_KDF), /exists/i);
});
