const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BITS_PER_CHAR = 5;
const BITS_PER_BYTE = 8;

/**
 * Decodes an RFC 4648 base32 string, the format otpauth QR codes use for TOTP secrets.
 * Case and spaces are ignored and padding is optional, matching how setup screens show the key.
 * @param encoded - the base32 text
 * @returns the decoded bytes
 */
export function decodeBase32(encoded) {
  const cleaned = String(encoded ?? '').toUpperCase().replace(/[\s=]/g, '');
  if (cleaned.length === 0) {
    throw new Error('Empty base32 secret.');
  }

  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of cleaned) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) {
      // The offending character is part of a secret, so it is never echoed back.
      throw new Error('Invalid base32 secret: only letters A–Z and digits 2–7 are allowed.');
    }
    value = (value << BITS_PER_CHAR) | index;
    bits += BITS_PER_CHAR;
    if (bits >= BITS_PER_BYTE) {
      bits -= BITS_PER_BYTE;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}
