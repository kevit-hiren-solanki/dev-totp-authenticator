/**
 * "Is this account for the site I'm on?" — compares hostnames by base domain, so an account
 * saved on app.vezly.ai is recognised on auth.vezly.ai, while look-alikes such as
 * vezly.ai.evil.com never match.
 *
 * Without bundling the full Public Suffix List this covers common two-part suffixes
 * (co.uk, com.au, co.in, …); anything else uses the last two labels.
 */

const TWO_PART_SUFFIX = /^(co|com|org|net|ac|gov|edu|ne|or)\.[a-z]{2}$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Returns the registrable part of a hostname (example.co.uk for app.example.co.uk).
 * @param hostname - a lowercase hostname
 * @returns the base domain; localhost and IP addresses are returned whole
 */
export function baseDomain(hostname) {
  const host = String(hostname ?? '').toLowerCase();
  if (!host.includes('.') || IPV4.test(host) || host.includes(':')) {
    return host;
  }
  const labels = host.split('.');
  const lastTwo = labels.slice(-2).join('.');
  return TWO_PART_SUFFIX.test(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

/**
 * Says whether an account saved for `savedDomain` belongs to the site at `currentHost`.
 * @param savedDomain - the hostname stored with the account (may be empty for old accounts)
 * @param currentHost - the active tab's hostname
 * @returns true when both share a base domain
 */
export function siteMatches(savedDomain, currentHost) {
  if (!savedDomain || !currentHost) {
    return false;
  }
  return baseDomain(savedDomain) === baseDomain(currentHost);
}

/**
 * Extracts the hostname from a tab URL, for http(s) pages only.
 * @param url - the tab URL
 * @returns the lowercase hostname, or '' for chrome://, file:// and invalid URLs
 */
export function hostFromUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.hostname.toLowerCase() : '';
  } catch {
    return '';
  }
}
