import { decodeBase32 } from './base32.mjs';

const DEFAULTS = { algorithm: 'SHA1', digits: 6, period: 30 };

/**
 * Parses an `otpauth://totp/...` URI, the format inside 2FA setup QR codes.
 * @param uri - the text decoded from the QR (or pasted by hand)
 * @returns label, issuer, base32 secret, algorithm, digits and period
 */
export function parseOtpauthUri(uri) {
  let url;
  try {
    url = new URL(uri);
  } catch {
    url = null;
  }
  if (url?.protocol !== 'otpauth:') {
    throw new Error('Not an otpauth:// URI. Scan the 2FA setup QR, or paste the URI starting with otpauth://.');
  }
  if (url.hostname !== 'totp') {
    throw new Error(`Only totp is supported, not "${url.hostname}".`);
  }

  const rawLabel = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const [prefix, rest] = rawLabel.includes(':') ? rawLabel.split(/:(.*)/s) : ['', rawLabel];

  const secret = url.searchParams.get('secret');
  if (!secret) {
    throw new Error('The otpauth URI has no secret.');
  }
  decodeBase32(secret); // Throws on invalid base32 so a bad secret is caught at add time, not at login.

  return {
    label: rest.trim(),
    issuer: url.searchParams.get('issuer') ?? prefix.trim(),
    secret,
    algorithm: url.searchParams.get('algorithm')?.toUpperCase() ?? DEFAULTS.algorithm,
    digits: Number(url.searchParams.get('digits') ?? DEFAULTS.digits),
    period: Number(url.searchParams.get('period') ?? DEFAULTS.period),
  };
}
