import { readFileSync } from 'node:fs';

const ALWAYS_ALLOWED_HOSTS = ['localhost', '127.0.0.1'];

/**
 * Reads the team dev servers from allowed-hosts.json, on top of this machine.
 * @returns every hostname the host may connect to
 */
export function loadAllowedHosts() {
  const file = JSON.parse(readFileSync(new URL('./allowed-hosts.json', import.meta.url), 'utf8'));
  return [...ALWAYS_ALLOWED_HOSTS, ...(file.hosts ?? [])];
}

/**
 * Replaces the password in a Mongo URL so it is safe to show or log.
 * @param dbUrl - the Mongo connection string
 * @returns the URL with the password masked
 */
export function maskDbUrl(dbUrl) {
  return String(dbUrl ?? '').replace(/^(mongodb:\/\/[^:@/]+:)[^@/]*@/, '$1***@');
}

/**
 * Throws unless the Mongo URL names a database on an allowed host, so codes can never come
 * from a server nobody approved (such as production).
 * @param dbUrl - the Mongo connection string to check
 * @param allowedHosts - hostnames that may be used
 * @returns nothing; throws on a disallowed or malformed URL
 */
export function assertAllowedDbUrl(dbUrl, allowedHosts) {
  let url;
  try {
    url = new URL(dbUrl);
  } catch {
    url = null;
  }
  const database = url?.pathname.slice(1);
  if (url?.protocol !== 'mongodb:' || !database || database.includes('/')) {
    throw new Error(`Not a valid MongoDB URL: "${maskDbUrl(dbUrl)}". Use mongodb://<host>:<port>/<database>.`);
  }
  if (!allowedHosts.includes(url.hostname)) {
    throw new Error(
      `Host ${url.hostname} is not allowed. Allowed: ${allowedHosts.join(', ')}. ` +
        'To add a team dev server, list it in host/allowed-hosts.json.',
    );
  }
}

/**
 * Splits a Mongo URL into host and database for display, leaving the credentials out.
 * @param dbUrl - the Mongo connection string
 * @returns the host (with port) and database name
 */
export function describeDbUrl(dbUrl) {
  const match = /^mongodb:\/\/(?:[^@/]*@)?([^/?]+)\/([^/?]+)/.exec(String(dbUrl ?? ''));
  return { host: match?.[1] ?? 'unknown host', database: match?.[2] ?? 'unknown database' };
}
