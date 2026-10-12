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
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(accounts), 'utf8'), cipher.final()]);

  const file = {
    v: VAULT_VERSION,
    kdf: kdfHeader,
    cipher: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64'),
  };

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
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(file.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(file.tag, 'base64'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(file.data, 'base64')), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch {
    // GCM cannot tell a wrong key from tampering, and saying which would help an attacker anyway.
    throw new Error('Wrong master password, or the vault file is corrupted.');
  }
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
