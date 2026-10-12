/**
 * Keyboard quick-fill: decides whether the open site has exactly one vault account and, if so,
 * fills and submits its code. Anything ambiguous (locked vault, no linked account, several
 * accounts, no code field) is returned as an outcome so the caller can open the popup instead —
 * this never guesses which account to use.
 *
 * Browser and host access come in as `deps`, so the decision logic is testable without Chrome.
 */
import { hostFromUrl, siteMatches } from './site-match.js';

// A code with less life than this may expire before the page verifies it.
const MIN_FILL_LIFETIME_MS = 3000;
const NEXT_CODE_MARGIN_MS = 150;

/**
 * Runs one quick-fill attempt.
 * @param deps - `getActiveTab`, `vaultStatus`, `listVault`, `injectFill(tab, code, options)`,
 *   `now` and `sleep`
 * @returns `{ outcome }`: submitted, filled, no-field, no-site, no-vault, locked, no-match,
 *   many, or error (with `message`)
 */
export async function quickFill(deps) {
  try {
    return await attempt(deps);
  } catch (err) {
    return { outcome: 'error', message: err.message };
  }
}

/**
 * The quick-fill steps; any thrown error becomes the `error` outcome.
 * @param deps - see quickFill
 * @returns the outcome
 */
async function attempt({ getActiveTab, vaultStatus, listVault, injectFill, now, sleep }) {
  const tab = await getActiveTab();
  const host = hostFromUrl(tab?.url);
  if (!host) {
    return { outcome: 'no-site' };
  }

  const status = await vaultStatus();
  if (!status.exists) {
    return { outcome: 'no-vault' };
  }
  if (!status.unlocked) {
    return { outcome: 'locked' };
  }

  let reply = await listVault();
  const matches = reply.accounts.filter((account) => siteMatches(account.domain, host));
  if (matches.length === 0) {
    return { outcome: 'no-match' };
  }
  if (matches.length > 1) {
    return { outcome: 'many' };
  }

  let [account] = matches;
  const remainingMs = reply.expiresAt - now();
  if (remainingMs < MIN_FILL_LIFETIME_MS) {
    await sleep(Math.max(remainingMs, 0) + NEXT_CODE_MARGIN_MS);
    reply = await listVault();
    account = reply.accounts.find((candidate) => candidate.id === account.id) ?? account;
  }

  const result = await injectFill(tab, account.code, { submit: true });
  if (!result.filled) {
    return { outcome: 'no-field' };
  }
  return { outcome: result.submitted ? 'submitted' : 'filled' };
}
