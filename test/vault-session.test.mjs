import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VaultSession } from '../host/vault-session.mjs';
import { decodeBase32 } from '../host/base32.mjs';
import { generateTotp } from '../host/totp.mjs';

const PASSWORD = 'correct horse battery staple';
const SECRET = 'JBSWY3DPEHPK3PXP';
const URI = `otpauth://totp/Vezly:hiren%40kevit.io?secret=${SECRET}&issuer=Vezly`;
const NOW = 1758700000000;

// Cheap scrypt cost and a fixed clock; no artificial delay after failed unlocks.
function makeSession() {
  const path = join(mkdtempSync(join(tmpdir(), 'vault-session-')), 'vault.enc');
  return new VaultSession({ vaultPath: path, kdf: { N: 1024, r: 8, p: 1 }, now: () => NOW, sleep: async () => {} });
}

test('status reports exists/unlocked through create and lock', async () => {
  const session = makeSession();
  assert.deepEqual(await session.handle({ type: 'vault.status' }), { exists: false, unlocked: false });
  await session.handle({ type: 'vault.create', password: PASSWORD });
  assert.deepEqual(await session.handle({ type: 'vault.status' }), { exists: true, unlocked: true });
  await session.handle({ type: 'vault.lock' });
  assert.deepEqual(await session.handle({ type: 'vault.status' }), { exists: true, unlocked: false });
});

test('create rejects a short master password', async () => {
  const session = makeSession();
  await assert.rejects(session.handle({ type: 'vault.create', password: 'short' }), /8/);
});

test('an account added by otpauth URI lists with its live code and no secret', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });

  const reply = await session.handle({ type: 'vault.list' });
  assert.equal(reply.accounts.length, 1);
  const [account] = reply.accounts;
  assert.equal(account.label, 'hiren@kevit.io');
  assert.equal(account.issuer, 'Vezly');
  assert.equal(account.code, generateTotp(decodeBase32(SECRET), { timeMs: NOW }));
  assert.ok(!JSON.stringify(reply).includes(SECRET), 'reply must never contain the secret');
});

test('an account added by pasted secret and label works the same way', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  const added = await session.handle({ type: 'vault.add', label: 'prod admin', secret: ` ${SECRET.toLowerCase()} ` });
  assert.ok(!JSON.stringify(added).includes(SECRET.toLowerCase()), 'add reply must never echo the secret');

  const reply = await session.handle({ type: 'vault.list' });
  assert.equal(reply.accounts[0].label, 'prod admin');
  assert.equal(reply.accounts[0].code, generateTotp(decodeBase32(SECRET), { timeMs: NOW }));
});

test('a typed label and issuer override the ones inside the scanned QR', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI, label: 'Vezly beta', issuer: 'Vezly Beta' });

  const [account] = (await session.handle({ type: 'vault.list' })).accounts;
  assert.equal(account.label, 'Vezly beta');
  assert.equal(account.issuer, 'Vezly Beta');
});

test('blank label and issuer fields keep the QR values', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI, label: '  ', issuer: '' });

  const [account] = (await session.handle({ type: 'vault.list' })).accounts;
  assert.equal(account.label, 'hiren@kevit.io');
  assert.equal(account.issuer, 'Vezly');
});

test('the site domain sent with an add is stored and listed, lowercased', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI, domain: 'Beta.Vezly.AI' });

  const [account] = (await session.handle({ type: 'vault.list' })).accounts;
  assert.equal(account.domain, 'beta.vezly.ai');
});

test('an add without a domain lists an empty domain, like accounts saved before this feature', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });

  const [account] = (await session.handle({ type: 'vault.list' })).accounts;
  assert.equal(account.domain, '');
});

test('a malformed domain is dropped instead of stored', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  for (const domain of ['javascript:alert(1)', 'a b.com', 'x'.repeat(300), '<script>', 42]) {
    await session.handle({ type: 'vault.add', otpauthUri: URI, domain });
  }
  const { accounts } = await session.handle({ type: 'vault.list' });
  assert.deepEqual(
    accounts.map((account) => account.domain),
    ['', '', '', '', ''],
  );
});

test('accounts survive lock and unlock', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });
  await session.handle({ type: 'vault.lock' });

  await assert.rejects(session.handle({ type: 'vault.list' }), /locked/i);
  await session.handle({ type: 'vault.unlock', password: PASSWORD });
  assert.equal((await session.handle({ type: 'vault.list' })).accounts.length, 1);
});

test('remove deletes exactly the requested account', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });
  await session.handle({ type: 'vault.add', label: 'other', secret: SECRET });

  const { accounts } = await session.handle({ type: 'vault.list' });
  await session.handle({ type: 'vault.remove', accountId: accounts[0].id });

  const after = await session.handle({ type: 'vault.list' });
  assert.equal(after.accounts.length, 1);
  assert.equal(after.accounts[0].label, 'other');
});

test('a failed unlock is delayed to slow down guessing', async () => {
  const path = join(mkdtempSync(join(tmpdir(), 'vault-session-')), 'vault.enc');
  const delays = [];
  const session = new VaultSession({
    vaultPath: path,
    kdf: { N: 1024, r: 8, p: 1 },
    now: () => NOW,
    sleep: async (ms) => delays.push(ms),
  });
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.lock' });

  await assert.rejects(session.handle({ type: 'vault.unlock', password: 'wrong password!' }), /wrong master password/i);
  assert.deepEqual(delays, [500]);
});

test('changePassword re-encrypts and keeps the vault unlocked', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });
  await session.handle({ type: 'vault.changePassword', oldPassword: PASSWORD, newPassword: 'a brand new password' });

  assert.equal((await session.handle({ type: 'vault.list' })).accounts.length, 1);
  await session.handle({ type: 'vault.lock' });
  await assert.rejects(session.handle({ type: 'vault.unlock', password: PASSWORD }), /wrong master password/i);
  await session.handle({ type: 'vault.unlock', password: 'a brand new password' });
});

test('unknown vault message types are rejected', async () => {
  const session = makeSession();
  await assert.rejects(session.handle({ type: 'vault.selfdestruct' }), /unknown/i);
});

/** Builds a second session on the same vault, as a fresh host process after the popup reopens. */
function reopen(session, overrides = {}) {
  return new VaultSession({
    vaultPath: session.vaultPath,
    kdf: { N: 1024, r: 8, p: 1 },
    now: () => NOW,
    sleep: async () => {},
    ...overrides,
  });
}

test('unlock returns a session token that resumes without the password in a new process', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });
  await session.handle({ type: 'vault.lock' });
  const { sessionToken } = await session.handle({ type: 'vault.unlock', password: PASSWORD });
  assert.ok(sessionToken, 'unlock must return a session token');

  const later = reopen(session);
  const resumed = await later.handle({ type: 'vault.resume', sessionToken });
  assert.equal(resumed.unlocked, true);
  assert.equal((await later.handle({ type: 'vault.list' })).accounts.length, 1);
});

test('create also returns a session token', async () => {
  const session = makeSession();
  const { sessionToken } = await session.handle({ type: 'vault.create', password: PASSWORD });
  assert.ok(sessionToken);
});

test('a wrong or garbage session token cannot unlock the vault', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });

  const later = reopen(session);
  const bogus = Buffer.alloc(32, 7).toString('base64');
  await assert.rejects(later.handle({ type: 'vault.resume', sessionToken: bogus }), /session/i);
  await assert.rejects(later.handle({ type: 'vault.resume', sessionToken: 'not-base64!!' }), /session/i);
  assert.equal((await later.handle({ type: 'vault.status' })).unlocked, false);
});

test('a session token expires after six hours', async () => {
  const session = makeSession();
  const { sessionToken } = await session.handle({ type: 'vault.create', password: PASSWORD });

  const later = reopen(session, { now: () => NOW + 6 * 60 * 60 * 1000 + 1 });
  await assert.rejects(later.handle({ type: 'vault.resume', sessionToken }), /session/i);
});

test('locking the vault invalidates the session token everywhere', async () => {
  const session = makeSession();
  const { sessionToken } = await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.lock' });

  const later = reopen(session);
  await assert.rejects(later.handle({ type: 'vault.resume', sessionToken }), /session/i);
});

test('changing the password invalidates the old session token and returns a fresh one', async () => {
  const session = makeSession();
  const { sessionToken: oldToken } = await session.handle({ type: 'vault.create', password: PASSWORD });
  const changed = await session.handle({ type: 'vault.changePassword', oldPassword: PASSWORD, newPassword: 'a brand new password' });
  assert.ok(changed.sessionToken);
  assert.notEqual(changed.sessionToken, oldToken);

  const later = reopen(session);
  await assert.rejects(later.handle({ type: 'vault.resume', sessionToken: oldToken }), /session/i);
  await later.handle({ type: 'vault.resume', sessionToken: changed.sessionToken });
});

test('an existing session file with loose permissions is tightened on the next unlock', async () => {
  const { chmodSync, statSync } = await import('node:fs');
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  chmodSync(`${session.vaultPath}.session`, 0o644);

  await session.handle({ type: 'vault.unlock', password: PASSWORD });
  assert.equal(statSync(`${session.vaultPath}.session`).mode & 0o777, 0o600);
});

test('the session file never contains the vault key or accounts in plaintext', async () => {
  const session = makeSession();
  await session.handle({ type: 'vault.create', password: PASSWORD });
  await session.handle({ type: 'vault.add', otpauthUri: URI });
  const { readFileSync, statSync } = await import('node:fs');
  const raw = readFileSync(`${session.vaultPath}.session`, 'utf8');
  assert.ok(!raw.includes(SECRET));
  assert.ok(!raw.includes(session.key.toString('base64')));
  assert.ok(!raw.includes(session.key.toString('hex')));
  assert.equal(statSync(`${session.vaultPath}.session`).mode & 0o777, 0o600);
});
