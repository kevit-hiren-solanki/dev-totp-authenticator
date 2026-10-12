/**
 * Service worker for the "Fill code for this site" keyboard shortcut (Alt+Shift+F by default).
 *
 * The shortcut grants activeTab for the current tab only, like opening the popup does. When the
 * site has exactly one linked vault account its code is filled and submitted; otherwise the popup
 * opens so you can choose (it already lists this site's accounts first).
 */
import { injectFill } from './fill-otp.js';
import { disconnectHost, sendToHost, vaultStatusWithResume } from './host-client.js';
import { quickFill } from './quick-fill.js';

const FILL_COMMAND = 'fill-current-site';
const BADGE_MS = 2500;
const SUCCESS_COLOR = '#1f883d';
const NOTICE_COLOR = '#9a6700';

// Outcomes the popup can resolve: unlock, pick among accounts, add one, or paste manually.
const OPEN_POPUP = new Set(['locked', 'no-vault', 'no-match', 'many', 'no-field']);
const BADGES = {
  submitted: { text: '✓', color: SUCCESS_COLOR, title: 'Code filled and submitted' },
  filled: { text: '✓', color: SUCCESS_COLOR, title: 'Code filled — press Verify' },
  'no-site': { text: '–', color: NOTICE_COLOR, title: 'This page is not a website' },
  error: { text: '!', color: NOTICE_COLOR, title: 'Quick fill failed' },
};

/**
 * Shows a short-lived badge on the toolbar icon as feedback for the shortcut.
 * @param badge - text, color and title to show
 * @returns resolves once set; clears itself after BADGE_MS
 */
async function flashBadge({ text, color, title }) {
  await chrome.action.setBadgeBackgroundColor({ color });
  await chrome.action.setBadgeText({ text });
  await chrome.action.setTitle({ title: `Dev Authenticator — ${title}` });
  setTimeout(() => {
    chrome.action.setBadgeText({ text: '' }).catch(() => {});
    chrome.action.setTitle({ title: 'Dev Authenticator' }).catch(() => {});
  }, BADGE_MS);
}

/**
 * Opens the popup, falling back to a badge on browsers that don't allow it from a shortcut.
 * @param reason - why the popup is needed, for the fallback badge title
 * @returns resolves once the popup is open or the badge is set
 */
async function openPopupOr(reason) {
  try {
    await chrome.action.openPopup();
  } catch {
    await flashBadge({ text: '…', color: NOTICE_COLOR, title: `${reason} — click the icon` });
  }
}

/**
 * Handles one press of the shortcut.
 * @returns resolves once feedback is shown
 */
async function onFillCommand() {
  try {
    const result = await quickFill({
      getActiveTab: async () => (await chrome.tabs.query({ active: true, currentWindow: true }))[0],
      vaultStatus: vaultStatusWithResume,
      listVault: () => sendToHost({ type: 'vault.list' }),
      injectFill,
      now: Date.now,
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    });
    if (OPEN_POPUP.has(result.outcome)) {
      await openPopupOr(result.outcome);
    } else {
      await flashBadge(BADGES[result.outcome] ?? BADGES.error);
    }
    if (result.outcome === 'error') {
      console.warn('Quick fill failed:', result.message);
    }
  } finally {
    disconnectHost();
  }
}

chrome.commands.onCommand.addListener((command) => {
  if (command === FILL_COMMAND) {
    onFillCommand().catch((err) => console.warn('Quick fill failed:', err));
  }
});
