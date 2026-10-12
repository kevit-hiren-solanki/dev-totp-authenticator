/**
 * Encrypted vault file for staging/production TOTP secrets.
 *
 * The file holds one AES-256-GCM blob whose key is derived from the master password with
 * scrypt. The password is never stored; a wrong password and a tampered file both fail the
 * GCM auth tag and are indistinguishable on purpose. Only this host process ever decrypts it.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const VAULT_VERSION = 1;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;
const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

// Interactive-login scrypt cost (OWASP recommendation): ~100ms and 128MB, hostile to brute force.
const DEFAULT_KDF = { N: 2 ** 17, r: 8, p: 1 };
const EXPORT_KIND = 'dev-authenticator-export';
const EXPORT_VERSION = 1;
// An import file names its own scrypt cost; bound it so a crafted file can't stall the host.
const MIN_IMPORT_N = 2 ** 10;
const MAX_IMPORT_N = 2 ** 17;

/**
 * Derives the vault key from the master password.
 * @param password - the master password
 * @param salt - the random salt stored in the vault file
 * @param kdf - scrypt cost parameters
 * @returns the 32-byte AES key
 */
function deriveKey(password, salt, kdf) {
  return scryptSync(password, salt, KEY_BYTES, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * 1024 * 1024 });
}

/**
 * Encrypts the account list and writes the vault file atomically with private permissions.
 * @param path - the vault file path
 * @param key - the derived AES key
 * @param accounts - the plaintext account list
 * @param kdfHeader - the kdf block (with salt) to store beside the ciphertext
 * @returns nothing
 */
function writeVaultFile(path, key, accounts, kdfHeader) {
  const file = { v: VAULT_VERSION, kdf: kdfHeader, cipher: 'aes-256-gcm', ...seal(key, accounts) };

  mkdirSync(dirname(path), { recursive: true, mode: DIR_MODE });
  // Write-then-rename so a crash mid-write can never leave a truncated vault.
  const tempPath = join(dirname(path), `.vault-${randomBytes(6).toString('hex')}.tmp`);
  writeFileSync(tempPath, JSON.stringify(file), { mode: FILE_MODE });
  renameSync(tempPath, path);
}

/**
 * Says whether a vault file exists at the given path.
 * @param path - the vault file path
 * @returns true if the vault has been created
 */
export function vaultExists(path) {
  return existsSync(path);
}

/**
 * Creates a new, empty vault encrypted with the given master password.
 * @param path - the vault file path; must not exist yet
 * @param password - the master password
 * @param kdf - scrypt cost override, used by tests; defaults to the production cost
 * @returns the derived key, for saving accounts without re-deriving
 */
export function createVault(path, password, kdf = DEFAULT_KDF) {
  if (vaultExists(path)) {
    throw new Error('A vault already exists. Unlock it, or delete the vault file to start over.');
  }
  const salt = randomBytes(SALT_BYTES);
  const key = deriveKey(password, salt, kdf);
  writeVaultFile(path, key, [], { algo: 'scrypt', ...kdf, salt: salt.toString('base64') });
  return { key, accounts: [] };
}

/**
 * Decrypts the vault with the master password.
 * @param path - the vault file path
 * @param password - the master password
 * @returns the derived key and the account list
 */
export function unlockVault(path, password) {
  const file = readVaultFile(path);
  const key = deriveKey(password, Buffer.from(file.kdf.salt, 'base64'), file.kdf);
  return { key, accounts: decryptVault(file, key) };
}

/**
 * Decrypts the vault with an already-derived key, as session resume does.
 * @param path - the vault file path
 * @param key - the 32-byte vault key
 * @returns the account list
 */
export function loadVaultWithKey(path, key) {
  return { key, accounts: decryptVault(readVaultFile(path), key) };
}

/**
 * Decrypts one parsed vault file.
 * @param file - the parsed vault file
 * @param key - the 32-byte vault key
 * @returns the account list
 */
function decryptVault(file, key) {
  return open(key, file, 'Wrong master password, or the vault file is corrupted.');
}

/**
 * Encrypts a JSON value with AES-256-GCM under a fresh random IV.
 * @param key - the 32-byte key
 * @param value - any JSON-serializable value
 * @returns the base64 iv, auth tag and ciphertext
 */
function seal(key, value) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
}

/**
 * Decrypts and verifies a value sealed by `seal`.
 * @param key - the 32-byte key
 * @param sealed - an object with base64 `iv`, `tag` and `data`
 * @param failureMessage - the error to throw on any failure
 * @returns the decrypted JSON value
 */
function open(key, sealed, failureMessage) {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(sealed.data, 'base64')), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    // GCM cannot tell a wrong key from tampering, and saying which would help an attacker anyway.
    throw new Error(failureMessage);
  }
}

/**
 * Writes a small JSON value next to the vault, sealed with the vault key (e.g. the database URL).
 * Atomic write-then-rename with owner-only permissions, like the vault itself.
 * @param path - the side file's path
 * @param key - the vault key
 * @param value - the value to store
 * @returns nothing
 */
export function writeSealedFile(path, key, value) {
  mkdirSync(dirname(path), { recursive: true, mode: DIR_MODE });
  const tempPath = join(dirname(path), `.sealed-${randomBytes(6).toString('hex')}.tmp`);
  writeFileSync(tempPath, JSON.stringify({ v: 1, cipher: 'aes-256-gcm', ...seal(key, value) }), { mode: FILE_MODE });
  renameSync(tempPath, path);
}

/**
 * Reads a value written by writeSealedFile.
 * @param path - the side file's path
 * @param key - the vault key
 * @returns the stored value, or null when the file doesn't exist
 */
export function readSealedFile(path, key) {
  if (!existsSync(path)) {
    return null;
  }
  let file;
  try {
    file = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Could not read ${path}: ${err.message}`);
  }
  return open(key, file, 'A file next to the vault is corrupted or was encrypted with a different key.');
}

/**
 * Encrypts accounts into a portable export file, under a key derived from the export passphrase
 * with a fresh salt. Nothing but the format marker and crypto parameters is readable.
 * @param accounts - the accounts to export (secrets included)
 * @param passphrase - the export passphrase
 * @param kdf - scrypt cost override, used by tests; defaults to the production cost
 * @returns the export file's text
 */
export function encryptExport(accounts, passphrase, kdf = DEFAULT_KDF) {
  const salt = randomBytes(SALT_BYTES);
  const key = deriveKey(passphrase, salt, kdf);
  return JSON.stringify({
    kind: EXPORT_KIND,
    v: EXPORT_VERSION,
    kdf: { algo: 'scrypt', N: kdf.N, r: kdf.r, p: kdf.p, salt: salt.toString('base64') },
    cipher: 'aes-256-gcm',
    ...seal(key, accounts),
  });
}

/**
 * Decrypts an export file made by `encryptExport`.
 * @param content - the export file's text
 * @param passphrase - the export passphrase
 * @returns the exported accounts, not yet validated
 */
export function decryptExport(content, passphrase) {
  let file;
  try {
    file = JSON.parse(content);
  } catch {
    file = null;
  }
  if (file?.kind !== EXPORT_KIND || file.v !== EXPORT_VERSION || file.cipher !== 'aes-256-gcm' || !isSafeImportKdf(file.kdf)) {
    throw new Error('This is not a Dev Authenticator export file.');
  }
  const key = deriveKey(passphrase, Buffer.from(file.kdf.salt, 'base64'), file.kdf);
  const accounts = open(key, file, 'Wrong passphrase, or the export file is corrupted.');
  if (!Array.isArray(accounts)) {
    throw new Error('Wrong passphrase, or the export file is corrupted.');
  }
  return accounts;
}

/**
 * Checks an import file's scrypt parameters before they are used.
 * @param kdf - the kdf block from the file
 * @returns true when the cost is within the range this app produces
 */
function isSafeImportKdf(kdf) {
  const { N, r, p } = kdf ?? {};
  const powerOfTwo = Number.isInteger(N) && (N & (N - 1)) === 0;
  return (
    kdf?.algo === 'scrypt' &&
    typeof kdf.salt === 'string' &&
    powerOfTwo &&
    N >= MIN_IMPORT_N &&
    N <= MAX_IMPORT_N &&
    r === 8 &&
    p === 1
  );
}

/**
 * Re-encrypts the current accounts under an already-derived key.
 * @param path - the vault file path
 * @param key - the key returned by createVault/unlockVault
 * @param accounts - the new account list
 * @returns nothing
 */
export function saveVault(path, key, accounts) {
  const file = readVaultFile(path);
  writeVaultFile(path, key, accounts, file.kdf);
}

/**
 * Changes the master password, deriving a fresh salt and key.
 * @param path - the vault file path
 * @param oldPassword - the current master password
 * @param newPassword - the replacement master password
 * @param kdf - scrypt cost override, used by tests; defaults to the production cost
 * @returns the new key
 */
export function changeVaultPassword(path, oldPassword, newPassword, kdf = DEFAULT_KDF) {
  const { accounts } = unlockVault(path, oldPassword);
  const salt = randomBytes(SALT_BYTES);
  const key = deriveKey(newPassword, salt, kdf);
  writeVaultFile(path, key, accounts, { algo: 'scrypt', ...kdf, salt: salt.toString('base64') });
  return { key, accounts };
}

/**
 * Reads and structurally validates the vault file.
 * @param path - the vault file path
 * @returns the parsed vault file
 */
function readVaultFile(path) {
  let file;
  try {
    file = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Could not read the vault file: ${err.message}`);
  }
  if (file?.v !== VAULT_VERSION || file.cipher !== 'aes-256-gcm' || file.kdf?.algo !== 'scrypt') {
    throw new Error('Unrecognized vault file format.');
  }
  return file;
}
