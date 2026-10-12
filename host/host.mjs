/**
 * Chrome native messaging host for the Dev Authenticator extension.
 * Chrome starts it when the popup opens; it reads 2FA secrets from the Mongo `users` collection
 * named by the popup (this machine or a team dev server in allowed-hosts.json) and replies with
 * the current codes. Secrets never leave this process.
 * stdout is the message channel — never write anything else to it.
 */
import { homedir } from 'node:os';
import { join } from 'node:path';
import { MongoClient } from 'mongodb';
import { assertAllowedDbUrl, describeDbUrl, loadAllowedHosts } from './db-url.mjs';
import { generateTotp, periodEndsAt, TOTP_PERIOD_SECONDS } from './totp.mjs';
import { VaultSession } from './vault-session.mjs';

const MAX_ACCOUNTS = 200;
const HEADER_BYTES = 4;
const SERVER_SELECTION_TIMEOUT_MS = 3000;
const ALLOWED_HOSTS = loadAllowedHosts();

let active = { dbUrl: null, client: null, connecting: null };

// DEV_AUTHENTICATOR_VAULT lets tests point the vault at a temp file.
const vaultPath =
  process.env.DEV_AUTHENTICATOR_VAULT ??
  join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'dev-authenticator', 'vault.enc');
const vaultSession = new VaultSession({ vaultPath });

/**
 * Closes a Mongo client, logging instead of throwing since the host is shutting it down anyway.
 * @param client - the client to close, if any
 * @returns resolves once closed
 */
function closeQuietly(client) {
  return client?.close().catch((err) => process.stderr.write(`Failed to close Mongo connection: ${err.message}\n`));
}

/**
 * Returns a connected database for `dbUrl`, reusing the connection until the popup switches URL.
 * @param dbUrl - the Mongo URL chosen in the popup
 * @returns the database named in the URL
 */
async function getDb(dbUrl) {
  assertAllowedDbUrl(dbUrl, ALLOWED_HOSTS);
  if (active.dbUrl !== dbUrl) {
    closeQuietly(active.client);
    active = {
      dbUrl,
      client: new MongoClient(dbUrl, { serverSelectionTimeoutMS: SERVER_SELECTION_TIMEOUT_MS }),
      connecting: null,
    };
  }
  const current = active;
  current.connecting ??= current.client.connect().catch((err) => {
    current.connecting = null;
    throw err;
  });
  await current.connecting;
  return current.client.db();
}

/**
 * Builds a display name from the platform's `{ first, last }` name object.
 * @param name - the user's name object, possibly missing
 * @returns the full name, or an empty string
 */
function toDisplayName(name) {
  return [name?.first, name?.last].filter(Boolean).join(' ');
}

/**
 * Lists every account in the given database that has an authenticator secret, with its current code.
 * @param dbUrl - the Mongo URL chosen in the popup
 * @returns the accounts plus the moment their codes expire
 */
async function listAccounts(dbUrl) {
  const db = await getDb(dbUrl);
  const users = await db
    .collection('users')
    .find(
      { 'mfaSettings.secret': { $exists: true, $nin: [null, ''] } },
      { projection: { email: 1, name: 1, 'mfaSettings.secret': 1, 'mfaSettings.mfaMethod': 1, 'mfaSettings.isEnabled': 1 } },
    )
    .sort({ updatedAt: -1 })
    .limit(MAX_ACCOUNTS)
    .toArray();

  const now = Date.now();
  return {
    period: TOTP_PERIOD_SECONDS,
    expiresAt: periodEndsAt(now),
    accounts: users.map((user) => ({
      email: user.email,
      name: toDisplayName(user.name),
      method: user.mfaSettings.mfaMethod ?? null,
      enabled: Boolean(user.mfaSettings.isEnabled),
      code: generateTotp(user.mfaSettings.secret, { timeMs: now }),
    })),
  };
}

/**
 * Writes one length-prefixed JSON message to Chrome.
 * @param message - the reply to send
 * @returns nothing
 */
function send(message) {
  const body = Buffer.from(JSON.stringify(message), 'utf8');
  const header = Buffer.alloc(HEADER_BYTES);
  header.writeUInt32LE(body.length);
  process.stdout.write(Buffer.concat([header, body]));
}

/**
 * Answers a single request from the popup.
 * @param request - the parsed message, carrying an `id` and a `type`
 * @returns resolves once the reply is sent
 */
async function handle(request) {
  try {
    const payload =
      typeof request.type === 'string' && request.type.startsWith('vault.')
        ? await vaultSession.handle(request)
        : await handleDbRequest(request);
    // Envelope last: a payload field can never overwrite the id the popup matches replies on.
    send({ ...payload, id: request.id, ok: true });
  } catch (err) {
    send({ id: request.id, ok: false, error: err.message });
  }
}

/**
 * Answers the database tab. The Mongo URL (which may hold a password) is stored encrypted with
 * the vault key: the popup sends it once on save and never again, and replies only ever carry
 * its host and database name.
 * @param request - the parsed message
 * @returns the reply payload
 */
async function handleDbRequest(request) {
  switch (request.type) {
    case 'db.status':
      return dbStatus();
    case 'db.save': {
      vaultSession.requireUnlocked();
      const dbUrl = String(request.dbUrl ?? '').trim();
      // listAccounts validates the host against the allow-list and proves the URL works.
      const reply = await listAccounts(dbUrl);
      vaultSession.saveDbUrl(dbUrl);
      return { ...reply, ...describeDbUrl(dbUrl) };
    }
    case 'db.list': {
      const dbUrl = vaultSession.getDbUrl();
      if (!dbUrl) {
        throw new Error('No database saved yet. Enter your Mongo URL in the database settings.');
      }
      return listAccounts(dbUrl);
    }
    default:
      throw new Error(`Unknown request type: ${request.type}`);
  }
}

/**
 * Says whether the database tab can run: the vault must be unlocked and a URL saved.
 * @returns vault state plus `configured`, and the host/database label when configured
 */
async function dbStatus() {
  const status = await vaultSession.handle({ type: 'vault.status' });
  if (!status.unlocked) {
    return { ...status, configured: false };
  }
  const dbUrl = vaultSession.getDbUrl();
  return dbUrl ? { ...status, configured: true, ...describeDbUrl(dbUrl) } : { ...status, configured: false };
}

/**
 * Parses one message body, answering with an error instead of crashing on malformed JSON.
 * @param body - the raw message text
 * @returns nothing
 */
function dispatch(body) {
  let request;
  try {
    request = JSON.parse(body);
  } catch {
    send({ id: null, ok: false, error: 'Malformed message.' });
    return;
  }
  handle(request ?? {});
}

let pending = Buffer.alloc(0);

process.stdin.on('data', (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  while (pending.length >= HEADER_BYTES) {
    const length = pending.readUInt32LE(0);
    if (pending.length < HEADER_BYTES + length) {
      return;
    }
    const body = pending.subarray(HEADER_BYTES, HEADER_BYTES + length).toString('utf8');
    pending = pending.subarray(HEADER_BYTES + length);
    dispatch(body);
  }
});

process.stdin.on('end', () => {
  Promise.resolve(closeQuietly(active.client)).finally(() => process.exit(0));
});
