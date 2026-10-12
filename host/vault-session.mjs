/**
 * In-memory vault session for one run of the native host.
 *
 * Holds the derived key and decrypted accounts only while the popup is open; Chrome kills the
 * host when the popup closes, which wipes them. Every reply is built here, and none ever
 * carries a secret or password — the popup only sees labels and 6-digit codes.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { decodeBase32 } from './base32.mjs';
import { parseOtpauthUri } from './otpauth.mjs';
import { generateTotp, periodEndsAt } from './totp.mjs';
import { changeVaultPassword, createVault, loadVaultWithKey, saveVault, unlockVault, vaultExists } from './vault.mjs';

const MIN_PASSWORD_LENGTH = 8;
const FAILED_UNLOCK_DELAY_MS = 500;
const ID_BYTES = 8;
// Bitwarden-style unlock session: the vault key, encrypted with a random one-time token that
// only the popup holds (in browser memory). Either half alone is useless.
const SESSION_DURATION_MS = 6 * 60 * 60 * 1000;
const SESSION_TOKEN_BYTES = 32;
const SESSION_IV_BYTES = 12;
const SESSION_FILE_MODE = 0o600;

export class VaultSession {
  /**
   * @param options - `vaultPath` for the encrypted file, plus test seams: `kdf` cost,
   *   `now` clock and `sleep` for the failed-unlock delay
   */
  constructor({ vaultPath, kdf, now = Date.now, sleep = delay } = {}) {
    this.vaultPath = vaultPath;
    this.kdf = kdf;
    this.now = now;
    this.sleep = sleep;
    this.key = null;
    this.accounts = null;
  }

  /**
   * Routes one `vault.*` request to its handler.
   * @param request - the parsed popup message
   * @returns the reply payload (never containing secrets)
   */
  async handle(request) {
    switch (request.type) {
      case 'vault.status':
        return { exists: vaultExists(this.vaultPath), unlocked: this.key !== null };
      case 'vault.create':
        return this.create(request.password);
      case 'vault.unlock':
        return this.unlock(request.password);
      case 'vault.resume':
        return this.resume(request.sessionToken);
      case 'vault.lock':
        this.key = null;
        this.accounts = null;
        this.clearSession();
        return { locked: true };
      case 'vault.list':
        return this.list();
      case 'vault.add':
        return this.add(request);
      case 'vault.remove':
        return this.remove(request.accountId);
      case 'vault.changePassword':
        return this.changePassword(request.oldPassword, request.newPassword);
      default:
        throw new Error(`Unknown vault request type: ${request.type}`);
    }
  }

  /**
   * Creates the vault and leaves it unlocked.
   * @param password - the new master password
   * @returns the unlocked status
   */
  create(password) {
    assertPasswordStrength(password);
    ({ key: this.key, accounts: this.accounts } = createVault(this.vaultPath, password, ...(this.kdf ? [this.kdf] : [])));
    return { exists: true, unlocked: true, sessionToken: this.startSession() };
  }

  /**
   * Unlocks the vault, pausing after a failure to slow down password guessing.
   * @param password - the master password to try
   * @returns the unlocked status
   */
  async unlock(password) {
    try {
      ({ key: this.key, accounts: this.accounts } = unlockVault(this.vaultPath, String(password ?? '')));
    } catch (err) {
      await this.sleep(FAILED_UNLOCK_DELAY_MS);
      throw err;
    }
    return { exists: true, unlocked: true, sessionToken: this.startSession() };
  }

  /**
   * Unlocks the vault with a session token from a previous unlock, instead of the password.
   * @param sessionToken - the token the popup stored in browser session memory
   * @returns the unlocked status
   */
  resume(sessionToken) {
    const invalid = () => new Error('The unlock session has expired. Enter your master password.');
    let file;
    try {
      file = JSON.parse(readFileSync(this.sessionPath(), 'utf8'));
    } catch {
      throw invalid();
    }
    if (typeof file?.expiresAt !== 'number' || file.expiresAt < this.now()) {
      this.clearSession();
      throw invalid();
    }
    try {
      const token = Buffer.from(String(sessionToken ?? ''), 'base64');
      const decipher = createDecipheriv('aes-256-gcm', token, Buffer.from(file.iv, 'base64'));
      decipher.setAuthTag(Buffer.from(file.tag, 'base64'));
      const key = Buffer.concat([decipher.update(Buffer.from(file.data, 'base64')), decipher.final()]);
      ({ key: this.key, accounts: this.accounts } = loadVaultWithKey(this.vaultPath, key));
    } catch {
      throw invalid();
    }
    return { exists: true, unlocked: true };
  }

  /**
   * Starts a six-hour unlock session: stores the vault key encrypted with a fresh random token.
   * @returns the base64 token for the popup to keep in browser session memory
   */
  startSession() {
    const token = randomBytes(SESSION_TOKEN_BYTES);
    const iv = randomBytes(SESSION_IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', token, iv);
    const data = Buffer.concat([cipher.update(this.key), cipher.final()]);
    const file = {
      v: 1,
      expiresAt: this.now() + SESSION_DURATION_MS,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    };
    // A fresh temp file + rename: `mode` only applies on create, so overwriting in place could
    // keep a looser mode from an older file.
    const tempPath = `${this.sessionPath()}.${randomBytes(6).toString('hex')}.tmp`;
    writeFileSync(tempPath, JSON.stringify(file), { mode: SESSION_FILE_MODE });
    renameSync(tempPath, this.sessionPath());
    return token.toString('base64');
  }

  /**
   * Deletes the session file, ending any resume-without-password session.
   * @returns nothing
   */
  clearSession() {
    rmSync(this.sessionPath(), { force: true });
  }

  /**
   * The session file's path, next to the vault.
   * @returns the path
   */
  sessionPath() {
    return `${this.vaultPath}.session`;
  }

  /**
   * Lists the vault accounts with their current codes.
   * @returns labels, issuers and codes plus the moment they expire
   */
  list() {
    const accounts = this.requireUnlocked();
    const nowMs = this.now();
    return {
      period: 30,
      expiresAt: periodEndsAt(nowMs),
      accounts: accounts.map((account) => ({
        id: account.id,
        label: account.label,
        issuer: account.issuer,
        code: generateTotp(decodeBase32(account.secret), {
          timeMs: nowMs,
          digits: account.digits,
          algorithm: account.algorithm,
          periodSeconds: account.period,
        }),
      })),
    };
  }

  /**
   * Adds an account from an otpauth URI or a pasted secret, verifying it generates a code.
   * @param request - `otpauthUri`, or `secret` with `label` (and optional `issuer`)
   * @returns the new account's id, as `accountId` so it never collides with the reply envelope
   */
  add(request) {
    const accounts = this.requireUnlocked();
    const typedLabel = String(request.label ?? '').trim();
    const typedIssuer = String(request.issuer ?? '').trim();
    const parsed = request.otpauthUri
      ? parseOtpauthUri(request.otpauthUri)
      : {
          label: '',
          issuer: '',
          secret: String(request.secret ?? '').trim().replace(/\s+/g, '').toUpperCase(),
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
        };
    // What the user typed wins over what the QR says; blank fields keep the QR's values.
    parsed.label = typedLabel || parsed.label;
    parsed.issuer = typedIssuer || parsed.issuer;
    if (!parsed.label) {
      throw new Error('The account needs a label so you can tell the codes apart.');
    }
    // Proves the secret decodes and generates before anything is saved.
    generateTotp(decodeBase32(parsed.secret), {
      timeMs: this.now(),
      digits: parsed.digits,
      algorithm: parsed.algorithm,
      periodSeconds: parsed.period,
    });

    const account = { id: randomBytes(ID_BYTES).toString('hex'), ...parsed, addedAt: this.now() };
    accounts.push(account);
    saveVault(this.vaultPath, this.key, accounts);
    return { accountId: account.id };
  }

  /**
   * Removes one account by id. The request field is `accountId`: `id` is the message envelope's.
   * @param id - the account id from `vault.list`
   * @returns the number of accounts left
   */
  remove(id) {
    const accounts = this.requireUnlocked();
    const remaining = accounts.filter((account) => account.id !== id);
    if (remaining.length === accounts.length) {
      throw new Error('No account with that id.');
    }
    this.accounts = remaining;
    saveVault(this.vaultPath, this.key, remaining);
    return { removed: true, count: remaining.length };
  }

  /**
   * Changes the master password and keeps the session unlocked under the new key.
   * @param oldPassword - the current master password
   * @param newPassword - the replacement master password
   * @returns the unlocked status
   */
  changePassword(oldPassword, newPassword) {
    assertPasswordStrength(newPassword);
    ({ key: this.key, accounts: this.accounts } = changeVaultPassword(
      this.vaultPath,
      String(oldPassword ?? ''),
      newPassword,
      ...(this.kdf ? [this.kdf] : []),
    ));
    // The old session file wraps the old key; replace it so only the fresh token works.
    return { exists: true, unlocked: true, sessionToken: this.startSession() };
  }

  /**
   * Returns the decrypted accounts or fails if the vault is locked.
   * @returns the account list
   */
  requireUnlocked() {
    if (!this.key || !this.accounts) {
      throw new Error('The vault is locked. Unlock it with your master password first.');
    }
    return this.accounts;
  }
}

/**
 * Enforces the minimum master password length.
 * @param password - the password to check
 * @returns nothing; throws when too short
 */
function assertPasswordStrength(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`The master password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
}
