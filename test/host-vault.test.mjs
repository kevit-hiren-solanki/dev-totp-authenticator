import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOST_PATH = fileURLToPath(new URL('../host/host.mjs', import.meta.url));
const PASSWORD = 'correct horse battery staple';
const SECRET = 'JBSWY3DPEHPK3PXP';
const URI = `otpauth://totp/Vezly:hiren%40kevit.io?secret=${SECRET}&issuer=Vezly`;

/**
 * Runs the host as Chrome does and exchanges length-prefixed JSON messages with it.
 */
function startHost() {
  const vaultPath = join(mkdtempSync(join(tmpdir(), 'host-vault-')), 'vault.enc');
  const child = spawn(process.execPath, [HOST_PATH], {
    env: { ...process.env, DEV_AUTHENTICATOR_VAULT: vaultPath },
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  let buffer = Buffer.alloc(0);
  // Replies are matched by request id, exactly as popup.js does, so an id mix-up hangs here too.
  const waiting = new Map();
  child.stdout.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4) {
      const length = buffer.readUInt32LE(0);
      if (buffer.length < 4 + length) {
        return;
      }
      const raw = buffer.subarray(4, 4 + length).toString('utf8');
      buffer = buffer.subarray(4 + length);
      const message = JSON.parse(raw);
      waiting.get(message.id)?.({ raw, message });
      waiting.delete(message.id);
    }
  });

  let nextId = 1;
  return {
    send(payload) {
      const id = nextId++;
      const body = Buffer.from(JSON.stringify({ ...payload, id }), 'utf8');
      const header = Buffer.alloc(4);
      header.writeUInt32LE(body.length);
      child.stdin.write(Buffer.concat([header, body]));
      return new Promise((resolve, reject) => {
        waiting.set(id, resolve);
        setTimeout(() => reject(new Error(`No reply matching request id ${id}.`)), 5000).unref();
      });
    },
    sendRaw(text) {
      const body = Buffer.from(text, 'utf8');
      const header = Buffer.alloc(4);
      header.writeUInt32LE(body.length);
      child.stdin.write(Buffer.concat([header, body]));
    },
    stop() {
      child.stdin.end();
    },
  };
}

test('the host answers vault requests end-to-end and never sends a secret', async () => {
  const host = startHost();
  try {
    const status = await host.send({ type: 'vault.status' });
    assert.deepEqual(status.message, { id: 1, ok: true, exists: false, unlocked: false });

    const created = await host.send({ type: 'vault.create', password: PASSWORD });
    assert.equal(created.message.ok, true);

    const added = await host.send({ type: 'vault.add', otpauthUri: URI });
    assert.equal(added.message.ok, true);
    assert.ok(!added.raw.includes(SECRET));

    const list = await host.send({ type: 'vault.list' });
    assert.equal(list.message.ok, true);
    assert.equal(list.message.accounts.length, 1);
    assert.match(list.message.accounts[0].code, /^\d{6}$/);
    assert.ok(!list.raw.includes(SECRET), 'no secret may cross the native messaging channel');
  } finally {
    host.stop();
  }
});

test('every vault reply carries the request id and ok flag, never overwritten by the payload', async () => {
  const host = startHost();
  try {
    await host.send({ type: 'vault.create', password: PASSWORD });
    const added = await host.send({ type: 'vault.add', otpauthUri: URI });
    assert.equal(added.message.ok, true);
    assert.equal(typeof added.message.accountId, 'string');

    const { message: list } = await host.send({ type: 'vault.list' });
    const removed = await host.send({ type: 'vault.remove', accountId: list.accounts[0].id });
    assert.equal(removed.message.ok, true);
  } finally {
    host.stop();
  }
});

test('a malformed message gets an error reply instead of crashing the host', async () => {
  const host = startHost();
  try {
    await host.sendRaw('{not json');
    const status = await host.send({ type: 'vault.status' });
    assert.equal(status.message.ok, true, 'host must survive a malformed message');
  } finally {
    host.stop();
  }
});

test('the host still answers unknown types with an error, not a crash', async () => {
  const host = startHost();
  try {
    const reply = await host.send({ type: 'nonsense' });
    assert.equal(reply.message.ok, false);
    assert.match(reply.message.error, /unknown request type/i);
  } finally {
    host.stop();
  }
});
