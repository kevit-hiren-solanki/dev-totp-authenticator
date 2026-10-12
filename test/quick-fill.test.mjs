import assert from 'node:assert/strict';
import { test } from 'node:test';
import { quickFill } from '../extension/quick-fill.js';

const NOW = 1_760_000_000_000;
const VEZLY = { id: 'v1', label: 'hiren@kevit.io', issuer: 'Vezly', domain: 'app.vezly.ai', code: '111111' };
const CHATOMATE = { id: 'c1', label: 'hiren@kevit.io', issuer: 'Chatomate', domain: 'stag.chatomate.com', code: '222222' };
const OLD = { id: 'o1', label: 'old@kevit.io', issuer: 'Legacy', domain: '', code: '333333' };

/** Fake browser + host. Override any piece per test; `calls` records what quickFill did. */
function fakes(overrides = {}) {
  const calls = { injected: [], lists: 0, slept: [] };
  const deps = {
    getActiveTab: async () => ({ id: 7, url: 'https://auth.vezly.ai/login' }),
    vaultStatus: async () => ({ exists: true, unlocked: true }),
    listVault: async () => {
      calls.lists += 1;
      return { accounts: [CHATOMATE, VEZLY, OLD], expiresAt: NOW + 20_000 };
    },
    injectFill: async (tab, code, options) => {
      calls.injected.push({ tabId: tab.id, code, options });
      return { filled: true, submitted: true };
    },
    now: () => NOW,
    sleep: async (ms) => calls.slept.push(ms),
    ...overrides,
  };
  return { deps, calls };
}

test('fills and submits the one account linked to the open site', async () => {
  const { deps, calls } = fakes();
  const result = await quickFill(deps);
  assert.equal(result.outcome, 'submitted');
  assert.deepEqual(calls.injected, [{ tabId: 7, code: '111111', options: { submit: true } }]);
});

test('reports filled-but-not-submitted when the page has no Verify button', async () => {
  const { deps } = fakes({ injectFill: async () => ({ filled: true, submitted: false }) });
  assert.equal((await quickFill(deps)).outcome, 'filled');
});

test('reports no-field when the page has no code input', async () => {
  const { deps } = fakes({ injectFill: async () => ({ filled: false, submitted: false }) });
  assert.equal((await quickFill(deps)).outcome, 'no-field');
});

test('never fills when no account is linked to the site', async () => {
  const { deps, calls } = fakes({ getActiveTab: async () => ({ id: 7, url: 'https://github.com/login' }) });
  assert.equal((await quickFill(deps)).outcome, 'no-match');
  assert.equal(calls.injected.length, 0);
});

test('never fills a look-alike domain', async () => {
  const { deps, calls } = fakes({ getActiveTab: async () => ({ id: 7, url: 'https://app.vezly.ai.evil.com/login' }) });
  assert.equal((await quickFill(deps)).outcome, 'no-match');
  assert.equal(calls.injected.length, 0);
});

test('does not guess between several accounts linked to the same site', async () => {
  const second = { ...VEZLY, id: 'v2', label: 'admin@kevit.io', code: '444444' };
  const { deps, calls } = fakes({ listVault: async () => ({ accounts: [VEZLY, second], expiresAt: NOW + 20_000 }) });
  assert.equal((await quickFill(deps)).outcome, 'many');
  assert.equal(calls.injected.length, 0);
});

test('needs an unlocked vault', async () => {
  const { deps, calls } = fakes({ vaultStatus: async () => ({ exists: true, unlocked: false }) });
  assert.equal((await quickFill(deps)).outcome, 'locked');
  assert.equal(calls.lists, 0);
});

test('reports a missing vault', async () => {
  const { deps } = fakes({ vaultStatus: async () => ({ exists: false, unlocked: false }) });
  assert.equal((await quickFill(deps)).outcome, 'no-vault');
});

test('does nothing on pages that are not websites', async () => {
  for (const url of ['chrome://extensions', 'file:///tmp/a.html', undefined]) {
    const { deps, calls } = fakes({ getActiveTab: async () => ({ id: 7, url }) });
    assert.equal((await quickFill(deps)).outcome, 'no-site', String(url));
    assert.equal(calls.injected.length, 0);
  }
});

test('waits for the next code when the current one is about to expire', async () => {
  let call = 0;
  const { deps, calls } = fakes({
    listVault: async () => {
      call += 1;
      return call === 1
        ? { accounts: [VEZLY], expiresAt: NOW + 1_000 }
        : { accounts: [{ ...VEZLY, code: '999999' }], expiresAt: NOW + 31_000 };
    },
  });
  await quickFill(deps);
  assert.deepEqual(calls.slept, [1_150]);
  assert.equal(calls.injected[0].code, '999999');
});

test('turns any failure into an error outcome instead of throwing', async () => {
  const { deps } = fakes({ vaultStatus: async () => Promise.reject(new Error('Specified native messaging host not found.')) });
  const result = await quickFill(deps);
  assert.equal(result.outcome, 'error');
  assert.match(result.message, /native messaging host not found/);
});
