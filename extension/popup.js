import { injectFill } from './fill-otp.js';
import { HOST_MISSING_PATTERN, sendToHost, setBusy, vaultStatusWithResume, writeSessionToken } from './host-client.js';
import { hostFromUrl, siteMatches } from './site-match.js';

const DEFAULT_DB_URL = 'mongodb://localhost:27017/vezly';
const TICK_MS = 250;
const ENDING_SECONDS = 5;
const COPIED_FLASH_MS = 900;
const TIMER_CIRCUMFERENCE = 94.25;
const LAST_COPIED_KEY = 'lastCopiedAt';
const DB_URL_KEY = 'dbUrl';
const TAB_KEY = 'activeTab';
const QR_SCAN_WIDTHS = [1200, 2000];
const QR_SCAN_TIMEOUT_MS = 15000;
// A code with less life than this may expire before the user presses Verify.
const MIN_FILL_LIFETIME_MS = 3000;

const listEl = document.getElementById('list');
const statusEl = document.getElementById('status');
const searchWrapEl = document.getElementById('search-wrap');
const searchEl = document.getElementById('search');
const timerEl = document.getElementById('timer');
const timerFillEl = document.getElementById('timer-fill');
const timerSecondsEl = document.getElementById('timer-seconds');
const rowTemplate = document.getElementById('row-template');
const vaultRowTemplate = document.getElementById('vault-row-template');
const settingsToggleEl = document.getElementById('settings-toggle');
const settingsEl = document.getElementById('settings');
const dbUrlInputEl = document.getElementById('db-url');
const settingsErrorEl = document.getElementById('settings-error');
const settingsCancelEl = document.getElementById('settings-cancel');
const settingsSaveEl = document.getElementById('settings-save');
const dbLabelEl = document.getElementById('db-label');
const tabEls = [...document.querySelectorAll('.tab')];
const vaultLockEl = document.getElementById('vault-lock');
const vaultLockTitleEl = document.getElementById('vault-lock-title');
const vaultPasswordEl = document.getElementById('vault-password');
const vaultPasswordConfirmEl = document.getElementById('vault-password-confirm');
const vaultLockHelpEl = document.getElementById('vault-lock-help');
const vaultLockErrorEl = document.getElementById('vault-lock-error');
const vaultLockSubmitEl = document.getElementById('vault-lock-submit');
const vaultActionsEl = document.getElementById('vault-actions');
const vaultAddToggleEl = document.getElementById('vault-add-toggle');
const vaultTransferEl = document.getElementById('vault-transfer');
const vaultEditEl = document.getElementById('vault-edit');
const vaultEditLabelEl = document.getElementById('vault-edit-label');
const vaultEditIssuerEl = document.getElementById('vault-edit-issuer');
const vaultEditSiteEl = document.getElementById('vault-edit-site');
const vaultEditLinkEl = document.getElementById('vault-edit-link');
const vaultEditUnlinkEl = document.getElementById('vault-edit-unlink');
const vaultEditErrorEl = document.getElementById('vault-edit-error');
const vaultEditCancelEl = document.getElementById('vault-edit-cancel');
const vaultEditSaveEl = document.getElementById('vault-edit-save');
const vaultEditRemoveEl = document.getElementById('vault-edit-remove');
const vaultEditActionsEl = document.getElementById('vault-edit-actions');
const vaultEditConfirmEl = document.getElementById('vault-edit-confirm');
const vaultEditRemoveCancelEl = document.getElementById('vault-edit-remove-cancel');
const vaultEditRemoveConfirmEl = document.getElementById('vault-edit-remove-confirm');
const vaultChangePasswordEl = document.getElementById('vault-change-password');
const vaultLockNowEl = document.getElementById('vault-lock-now');
const vaultAddEl = document.getElementById('vault-add');
const vaultScanEl = document.getElementById('vault-scan');
const vaultAddInputEl = document.getElementById('vault-add-input');
const vaultAddLabelEl = document.getElementById('vault-add-label');
const vaultAddIssuerEl = document.getElementById('vault-add-issuer');
const vaultAddErrorEl = document.getElementById('vault-add-error');
const vaultAddScannedEl = document.getElementById('vault-add-scanned');
const vaultAddCancelEl = document.getElementById('vault-add-cancel');
const vaultAddSaveEl = document.getElementById('vault-add-save');
const vaultPasswordFormEl = document.getElementById('vault-password-form');
const vaultOldPasswordEl = document.getElementById('vault-old-password');
const vaultNewPasswordEl = document.getElementById('vault-new-password');
const vaultNewPasswordConfirmEl = document.getElementById('vault-new-password-confirm');
const vaultPasswordErrorEl = document.getElementById('vault-password-error');
const vaultPasswordCancelEl = document.getElementById('vault-password-cancel');

const state = {
  tab: 'db',
  accounts: [],
  period: 30,
  expiresAt: 0,
  lastCopiedAt: {},
  db: { configured: false, host: '', database: '' },
  refreshing: null,
  refreshQueued: false,
  editing: null,
  currentHost: '',
  vault: { exists: false, unlocked: false },
};

/**
 * Formats a 6-digit code as two groups of three for easier reading.
 * @param code - the raw code
 * @returns the grouped code
 */
function formatCode(code) {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

/**
 * The two lines shown for an account: DB accounts have name/email, vault accounts label/issuer.
 * @param account - the account from either source
 * @returns primary and secondary display text
 */
function describeAccount(account) {
  if (state.tab === 'vault') {
    return { primary: account.label || account.issuer, secondary: account.issuer };
  }
  return { primary: account.name || account.email, secondary: account.email };
}

/**
 * Returns the accounts matching the search box, most recently copied first.
 * @returns the accounts to show
 */
function getVisibleAccounts() {
  const query = searchEl.value.trim().toLowerCase();
  const copyKey = (account) => account.email ?? account.id;
  const onThisSite = (account) => (isForCurrentSite(account) ? 1 : 0);
  return state.accounts
    .filter((account) => {
      const { primary, secondary } = describeAccount(account);
      return !query || `${primary} ${secondary} ${account.domain ?? ''}`.toLowerCase().includes(query);
    })
    .sort(
      (a, b) =>
        onThisSite(b) - onThisSite(a) || (state.lastCopiedAt[copyKey(b)] ?? 0) - (state.lastCopiedAt[copyKey(a)] ?? 0),
    );
}

/**
 * Says whether a vault account was added on the site open in the current tab.
 * @param account - the account from either source (database accounts have no domain)
 * @returns true when the account's saved domain matches the current tab
 */
function isForCurrentSite(account) {
  return siteMatches(account.domain, state.currentHost);
}

/**
 * Copies an account's current code and flashes the row.
 * @param account - the account whose code to copy
 * @param row - the row element to flash
 * @returns resolves once the code is on the clipboard
 */
async function copyCode(account, row) {
  try {
    await navigator.clipboard.writeText(account.code);
  } catch (err) {
    showError('Could not copy to the clipboard.', err.message);
    return;
  }
  row.classList.add('is-copied');
  setTimeout(() => row.classList.remove('is-copied'), COPIED_FLASH_MS);

  state.lastCopiedAt[account.email ?? account.id] = Date.now();
  // Ordering is a convenience; a failed write only loses the sort order.
  chrome.storage.local
    .set({ [LAST_COPIED_KEY]: state.lastCopiedAt })
    .catch((err) => console.warn('Could not save copy order', err));
}

/**
 * Builds one clickable account row for the database tab.
 * @param account - the account to show
 * @returns the row element
 */
function buildRow(account) {
  const wrap = rowTemplate.content.firstElementChild.cloneNode(true);
  const row = wrap.querySelector('.row');
  const { primary, secondary } = describeAccount(account);
  row.querySelector('.name').textContent = primary;
  row.querySelector('.email').textContent = secondary;
  row.querySelector('.code').textContent = formatCode(account.code);
  row.title = `Copy code for ${secondary || primary}`;
  row.classList.toggle('is-disabled', !account.enabled);
  row.addEventListener('click', () => copyCode(account, row));
  wireFillButton(wrap, account);
  return wrap;
}

/**
 * Connects a row's fill button, which types the current code into the page in this tab.
 * @param wrap - the row wrapper holding `.row` and `.row-fill`
 * @param account - the account whose code to fill
 * @returns nothing
 */
function wireFillButton(wrap, account) {
  const fillEl = wrap.querySelector('.row-fill');
  fillEl.addEventListener('click', (event) =>
    fillIntoPage(account, fillEl, wrap.querySelector('.row'), { submit: !event.shiftKey }),
  );
}

/**
 * Returns a code with enough life left to be submitted, waiting for the next one if the
 * current code is about to expire.
 * @param account - the account as rendered
 * @returns the code to fill
 */
async function freshCode(account) {
  const remainingMs = state.expiresAt - Date.now();
  if (remainingMs >= MIN_FILL_LIFETIME_MS) {
    return account.code;
  }
  await new Promise((resolve) => setTimeout(resolve, Math.max(remainingMs, 0) + 150));
  await refresh();
  const key = account.email ?? account.id;
  return state.accounts.find((candidate) => (candidate.email ?? candidate.id) === key)?.code ?? account.code;
}

/**
 * Injects the code into the active tab's 2FA field and closes the popup. Only the 6-digit
 * code reaches the page, and only on this explicit click. Falls back to copying when the page
 * has no recognisable code field or can't be scripted (e.g. chrome:// pages).
 * @param account - the account whose code to fill
 * @param fillEl - the clicked fill button, spinning meanwhile
 * @param row - the row, flashed "Copied" on fallback
 * @param options - `submit`: also press the page's Verify button (Shift+click turns it off)
 * @returns resolves once filled or the fallback message is shown
 */
async function fillIntoPage(account, fillEl, row, options) {
  if (fillEl.classList.contains('is-busy')) {
    return;
  }
  fillEl.classList.add('is-busy');
  fillEl.disabled = true;
  let reason = 'No 2FA code field found on this page.';
  try {
    const code = await freshCode(account);
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if ((await injectFill(tab, code, options)).filled) {
      window.close();
      return;
    }
    account = { ...account, code };
  } catch (err) {
    reason = `This page can't be filled (${err.message}).`;
  } finally {
    fillEl.classList.remove('is-busy');
    fillEl.disabled = false;
  }
  await copyCode(account, row);
  showMessage(`${reason} The code was copied instead — paste it with Ctrl+V.`);
}

/**
 * Builds one vault row: the clickable code, Fill, and Edit (rename, link to a site, remove).
 * @param account - the vault account to show
 * @returns the row wrapper element
 */
function buildVaultRow(account) {
  const wrap = vaultRowTemplate.content.firstElementChild.cloneNode(true);
  const row = wrap.querySelector('.row');
  const { primary, secondary } = describeAccount(account);
  row.querySelector('.name').textContent = primary;
  row.querySelector('.email').textContent = secondary;
  row.querySelector('.code').textContent = formatCode(account.code);
  row.title = account.domain ? `Copy code for ${primary} (${account.domain})` : `Copy code for ${primary}`;
  row.addEventListener('click', () => copyCode(account, row));
  wrap.querySelector('.site-badge').hidden = !isForCurrentSite(account);
  wireFillButton(wrap, account);

  wrap.querySelector('.row-edit').addEventListener('click', () => openVaultEdit(account));
  return wrap;
}

/**
 * Re-renders the account list for the current search.
 * @returns nothing
 */
function renderList() {
  const accounts = getVisibleAccounts();
  listEl.replaceChildren(...accounts.map(state.tab === 'vault' ? buildVaultRow : buildRow));

  if (state.accounts.length === 0) {
    showMessage(
      state.tab === 'vault'
        ? 'The vault is empty. Add your staging/production accounts with “+ Add account”.'
        : 'No accounts with an authenticator secret in this database. Enroll 2FA (scan the QR) on an account first.',
    );
  } else if (accounts.length === 0) {
    showMessage(`No account matches “${searchEl.value.trim()}”.`);
  } else {
    statusEl.hidden = true;
  }
}

/**
 * Shows a neutral message in the status box.
 * @param text - the message to show
 * @returns nothing
 */
function showMessage(text) {
  statusEl.className = 'status';
  statusEl.textContent = text;
  statusEl.hidden = false;
}

/**
 * Shows an error with the next step: the setup command if the host is missing, else a way to change the database.
 * @param title - the headline
 * @param detail - the underlying error message
 * @returns nothing
 */
function showError(title, detail) {
  statusEl.className = 'status is-error';
  statusEl.replaceChildren();

  const heading = document.createElement('strong');
  heading.textContent = title;
  const text = document.createElement('span');
  text.textContent = detail;
  statusEl.append(heading, text);

  if (HOST_MISSING_PATTERN.test(detail)) {
    const hint = document.createElement('code');
    hint.textContent = 'cd totp-athenticator && npm install && npm run setup';
    statusEl.append(hint);
  } else if (state.tab === 'db') {
    const change = document.createElement('button');
    change.type = 'button';
    change.className = 'button-secondary';
    change.textContent = 'Change database';
    change.addEventListener('click', () => openSettings());
    statusEl.append(change);
  }
  statusEl.hidden = false;
}

/**
 * Stores a successful reply and redraws the list.
 * @param reply - the host's reply
 * @returns nothing
 */
function applyReply(reply) {
  state.accounts = reply.accounts;
  state.period = reply.period;
  state.expiresAt = reply.expiresAt;
  renderList();
}

/**
 * Fetches fresh codes for the active tab: the saved database, or the unlocked vault.
 * @returns resolves once the list is re-rendered
 */
async function refresh() {
  // A refresh asked for mid-flight (e.g. right after an add) must still run, not be dropped.
  if (state.refreshing) {
    state.refreshQueued = true;
    return state.refreshing;
  }
  state.refreshing = runRefresh().finally(() => {
    state.refreshing = null;
    if (state.refreshQueued) {
      state.refreshQueued = false;
      refresh();
    }
  });
  return state.refreshing;
}

/**
 * Performs one refresh of the active tab.
 * @returns resolves once the list or error is shown
 */
async function runRefresh() {
  try {
    if (state.tab === 'vault') {
      await refreshVault();
    } else {
      await refreshDb();
    }
  } catch (err) {
    state.expiresAt = Number.POSITIVE_INFINITY;
    listEl.replaceChildren();
    showError('Could not load codes', err.message);
  }
}

/**
 * Shows or hides the code list, search and timer.
 * @param visible - whether the codes view should show
 * @returns nothing
 */
function setCodesViewVisible(visible) {
  searchWrapEl.hidden = !visible;
  listEl.hidden = !visible;
  timerEl.hidden = !visible;
  if (!visible) {
    statusEl.hidden = true;
  }
}

/**
 * Opens the database settings, pausing code refresh while it is open.
 * @returns nothing
 */
function openSettings() {
  state.expiresAt = 0;
  setCodesViewVisible(false);
  settingsEl.hidden = false;
  settingsToggleEl.setAttribute('aria-expanded', 'true');
  settingsCancelEl.hidden = !state.db.configured;
  settingsErrorEl.hidden = true;
  // The stored URL is never sent back to the popup, so it can't be prefilled (or leak from here).
  dbUrlInputEl.value = state.db.configured ? '' : DEFAULT_DB_URL;
  dbUrlInputEl.placeholder = state.db.configured
    ? `Now: ${state.db.database} on ${state.db.host}. Paste a new URL to replace it.`
    : DEFAULT_DB_URL;
  dbUrlInputEl.focus();
  dbUrlInputEl.select();
}

/**
 * Closes the settings and goes back to the codes.
 * @returns nothing
 */
function closeSettings() {
  settingsEl.hidden = true;
  settingsToggleEl.setAttribute('aria-expanded', 'false');
  setCodesViewVisible(true);
  searchEl.focus();
}

/**
 * Updates the footer badge with the saved database name.
 * @returns nothing
 */
function renderDbLabel() {
  dbLabelEl.hidden = state.tab !== 'db' || !state.db.configured;
  if (state.db.configured) {
    dbLabelEl.textContent = `db: ${state.db.database}`;
    dbLabelEl.title = `${state.db.database} on ${state.db.host} — click to change`;
  }
}

/**
 * Loads the database tab. The Mongo URL lives encrypted with the vault key, so the vault must be
 * unlocked first (the six-hour session usually covers that).
 * @returns resolves once codes, the unlock form or the settings are shown
 */
async function refreshDb() {
  const vault = await vaultStatusWithResume();
  // The shared unlock form reads this to choose "unlock" over "create".
  state.vault = vault;
  if (!vault.exists) {
    showDbNeedsVault();
    return;
  }
  if (!vault.unlocked) {
    showVaultLockForm(false);
    settingsToggleEl.hidden = true;
    return;
  }
  hideVaultPanels();
  settingsToggleEl.hidden = false;
  state.db = await sendToHost({ type: 'db.status' });
  if (!state.db.configured && !(await migrateLegacyDbUrl())) {
    renderDbLabel();
    openSettings();
    return;
  }
  renderDbLabel();
  if (!settingsEl.hidden) {
    return;
  }
  setCodesViewVisible(true);
  applyReply(await sendToHost({ type: 'db.list' }));
}

/**
 * Explains that the database tab now needs a vault, with a shortcut to create one.
 * @returns nothing
 */
function showDbNeedsVault() {
  state.expiresAt = 0;
  setCodesViewVisible(false);
  settingsToggleEl.hidden = true;
  statusEl.className = 'status';
  statusEl.replaceChildren();
  const text = document.createElement('span');
  text.textContent =
    'Your database URL can contain a password, so it is stored encrypted in your vault. Create the vault (one master password) to use this tab.';
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'button-primary';
  button.textContent = 'Create vault';
  button.addEventListener('click', () => setTab('vault'));
  statusEl.append(text, button);
  statusEl.hidden = false;
}

/**
 * Moves a URL saved by an older version (in plain browser storage) into the encrypted vault file,
 * then deletes the browser copy. If the move fails, the old copy is kept for the next try.
 * @returns true when a legacy URL was migrated
 */
async function migrateLegacyDbUrl() {
  let legacy;
  try {
    legacy = (await chrome.storage.local.get(DB_URL_KEY))[DB_URL_KEY];
  } catch {
    legacy = null;
  }
  if (!legacy) {
    return false;
  }
  try {
    const reply = await sendToHost({ type: 'db.save', dbUrl: legacy });
    await removeLegacyDbUrl();
    state.db = { configured: true, host: reply.host, database: reply.database };
    return true;
  } catch (err) {
    console.warn('Could not move the saved database URL into the vault yet', err);
    return false;
  }
}

/**
 * Deletes the plain-text URL older versions kept in browser storage.
 * @returns resolves once removed
 */
async function removeLegacyDbUrl() {
  try {
    await chrome.storage.local.remove(DB_URL_KEY);
  } catch (err) {
    console.warn('Could not remove the old database URL from browser storage', err);
  }
}

/**
 * Connects to the entered database and saves it only if the host could read codes from it.
 * @param event - the form submit event
 * @returns resolves once saved or the error is shown
 */
async function saveSettings(event) {
  event.preventDefault();
  const dbUrl = dbUrlInputEl.value.trim();
  settingsSaveEl.disabled = true;
  settingsErrorEl.hidden = true;
  try {
    const reply = await sendToHost({ type: 'db.save', dbUrl });
    dbUrlInputEl.value = '';
    await removeLegacyDbUrl();
    state.db = { configured: true, host: reply.host, database: reply.database };
    renderDbLabel();
    closeSettings();
    applyReply(reply);
  } catch (err) {
    settingsErrorEl.textContent = HOST_MISSING_PATTERN.test(err.message)
      ? `${err.message} Run: npm install && npm run setup`
      : err.message;
    settingsErrorEl.hidden = false;
  } finally {
    settingsSaveEl.disabled = false;
  }
}

/**
 * Hides every vault panel (lock, add, change-password, actions bar).
 * @returns nothing
 */
function hideVaultPanels() {
  vaultLockEl.hidden = true;
  vaultAddEl.hidden = true;
  vaultEditEl.hidden = true;
  vaultPasswordFormEl.hidden = true;
  vaultActionsEl.hidden = true;
}

/**
 * Shows the master password form, in create mode for a brand-new vault.
 * @param creating - whether the vault does not exist yet
 * @returns nothing
 */
function showVaultLockForm(creating) {
  state.expiresAt = 0;
  state.accounts = [];
  setCodesViewVisible(false);
  hideVaultPanels();
  vaultLockEl.hidden = false;
  vaultLockTitleEl.textContent = creating ? 'Create your vault' : 'Master password';
  vaultLockSubmitEl.textContent = creating ? 'Create vault' : 'Unlock';
  vaultPasswordConfirmEl.hidden = !creating;
  vaultLockHelpEl.hidden = !creating;
  vaultLockErrorEl.hidden = true;
  vaultPasswordEl.value = '';
  vaultPasswordConfirmEl.value = '';
  vaultPasswordEl.placeholder = creating ? 'Master password (min 8 characters)' : '';
  vaultPasswordEl.focus();
}

/**
 * Loads the vault tab: resumes the six-hour unlock session if one is running,
 * shows the password form otherwise, then the live codes.
 * @returns resolves once the right view is shown
 */
async function refreshVault() {
  state.vault = await vaultStatusWithResume();
  if (!state.vault.unlocked) {
    showVaultLockForm(!state.vault.exists);
    return;
  }
  hideVaultPanels();
  vaultActionsEl.hidden = false;
  setCodesViewVisible(true);
  applyReply(await sendToHost({ type: 'vault.list' }));
}

/**
 * Creates or unlocks the vault with the typed master password.
 * @param event - the form submit event
 * @returns resolves once unlocked or the error is shown
 */
async function submitVaultLock(event) {
  event.preventDefault();
  const creating = !state.vault.exists;
  if (creating && vaultPasswordEl.value !== vaultPasswordConfirmEl.value) {
    vaultLockErrorEl.textContent = 'The passwords do not match.';
    vaultLockErrorEl.hidden = false;
    return;
  }
  vaultLockErrorEl.hidden = true;
  const done = setBusy(vaultLockSubmitEl, creating ? 'Creating…' : 'Unlocking…');
  try {
    const reply = await sendToHost({ type: creating ? 'vault.create' : 'vault.unlock', password: vaultPasswordEl.value });
    await writeSessionToken(reply.sessionToken ?? null);
    vaultPasswordEl.value = '';
    vaultPasswordConfirmEl.value = '';
    await refresh();
  } catch (err) {
    vaultLockErrorEl.textContent = err.message;
    vaultLockErrorEl.hidden = false;
    vaultPasswordEl.focus();
    vaultPasswordEl.select();
  } finally {
    done();
  }
}

/**
 * Opens the edit panel for one account. Code refresh pauses meanwhile, so the list is not
 * rebuilt under the form. The secret is never part of this panel.
 * @param account - the vault account to edit
 * @returns nothing
 */
function openVaultEdit(account) {
  state.expiresAt = 0;
  state.editing = { id: account.id, domain: account.domain ?? '' };
  setCodesViewVisible(false);
  hideVaultPanels();
  vaultEditEl.hidden = false;
  vaultEditErrorEl.hidden = true;
  vaultEditConfirmEl.hidden = true;
  vaultEditActionsEl.hidden = false;
  vaultEditLabelEl.value = account.label ?? '';
  vaultEditIssuerEl.value = account.issuer ?? '';
  renderEditSite();
  vaultEditLabelEl.focus();
}

/**
 * Shows the pending site link and which of Link / Unlink apply.
 * @returns nothing
 */
function renderEditSite() {
  const { domain } = state.editing;
  const onThisSite = siteMatches(domain, state.currentHost);
  vaultEditSiteEl.textContent = domain ? `Linked to ${domain}${onThisSite ? ' (this site)' : ''}` : 'Not linked to a site';
  vaultEditSiteEl.classList.toggle('is-linked', Boolean(domain));
  vaultEditLinkEl.hidden = !state.currentHost || onThisSite;
  vaultEditLinkEl.textContent = domain ? `Link to ${state.currentHost} instead` : `Link to ${state.currentHost}`;
  vaultEditUnlinkEl.hidden = !domain;
}

/**
 * Saves the label, issuer and site link.
 * @param event - the form submit event
 * @returns resolves once saved or the error is shown
 */
async function submitVaultEdit(event) {
  event.preventDefault();
  vaultEditErrorEl.hidden = true;
  const done = setBusy(vaultEditSaveEl, 'Saving…');
  try {
    await sendToHost({
      type: 'vault.update',
      accountId: state.editing.id,
      label: vaultEditLabelEl.value,
      issuer: vaultEditIssuerEl.value,
      domain: state.editing.domain,
    });
    state.editing = null;
    await refresh();
  } catch (err) {
    vaultEditErrorEl.textContent = err.message;
    vaultEditErrorEl.hidden = false;
  } finally {
    done();
  }
}

/**
 * Removes the account being edited, after the inline confirmation.
 * @returns resolves once removed or the error is shown
 */
async function removeEditedAccount() {
  vaultEditErrorEl.hidden = true;
  vaultEditRemoveCancelEl.disabled = true;
  const done = setBusy(vaultEditRemoveConfirmEl, 'Removing…');
  try {
    await sendToHost({ type: 'vault.remove', accountId: state.editing.id });
    state.editing = null;
    await refresh();
  } catch (err) {
    vaultEditErrorEl.textContent = err.message;
    vaultEditErrorEl.hidden = false;
  } finally {
    done();
    vaultEditRemoveCancelEl.disabled = false;
  }
}

/**
 * Opens the add-account panel.
 * @returns nothing
 */
function openVaultAdd() {
  state.expiresAt = 0;
  setCodesViewVisible(false);
  hideVaultPanels();
  vaultAddEl.hidden = false;
  vaultAddErrorEl.hidden = true;
  vaultAddScannedEl.hidden = true;
  vaultAddInputEl.value = '';
  vaultAddLabelEl.value = '';
  vaultAddIssuerEl.value = '';
  vaultAddInputEl.focus();
}

/**
 * Sends the new account to the host, which validates it before anything is stored.
 * @param event - the form submit event
 * @returns resolves once added or the error is shown
 */
async function submitVaultAdd(event) {
  event.preventDefault();
  const input = vaultAddInputEl.value.trim();
  const payload = {
    type: 'vault.add',
    ...(input.startsWith('otpauth://') ? { otpauthUri: input } : { secret: input }),
    // Typed values override the QR's own; the host keeps the QR's when these are blank.
    label: vaultAddLabelEl.value.trim(),
    issuer: vaultAddIssuerEl.value.trim(),
    // The site this account belongs to, so it sorts first (and is badged) when you're back here.
    domain: state.currentHost,
  };
  vaultAddErrorEl.hidden = true;
  const done = setBusy(vaultAddSaveEl, 'Adding…');
  try {
    await sendToHost(payload);
    // The secret must not linger in the DOM once it is in the vault.
    vaultAddInputEl.value = '';
    vaultAddLabelEl.value = '';
    vaultAddIssuerEl.value = '';
    await refresh();
  } catch (err) {
    vaultAddErrorEl.textContent = err.message;
    vaultAddErrorEl.hidden = false;
  } finally {
    done();
  }
}

/**
 * Reads the display parts of an otpauth URI (never the secret), splitting "Issuer:account".
 * @param uri - the scanned otpauth:// URI
 * @returns the account label and issuer, empty strings when absent
 */
function readOtpauthLabel(uri) {
  try {
    const url = new URL(uri);
    const raw = decodeURIComponent(url.pathname.replace(/^\//, ''));
    const colon = raw.indexOf(':');
    const prefix = colon === -1 ? '' : raw.slice(0, colon).trim();
    const label = (colon === -1 ? raw : raw.slice(colon + 1)).trim();
    return { label, issuer: url.searchParams.get('issuer')?.trim() || prefix };
  } catch {
    return { label: '', issuer: '' };
  }
}

/**
 * Screenshots the current tab and decodes a 2FA setup QR from it, filling the add form.
 * @returns resolves once the URI is filled in or the error is shown
 */
async function scanQrOnScreen() {
  vaultAddErrorEl.hidden = true;
  const done = setBusy(vaultScanEl, 'Scanning…');
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab({ format: 'png' });
    const uri = await decodeQr(dataUrl);
    if (!uri.startsWith('otpauth://')) {
      throw new Error('The QR code on screen is not a 2FA setup code.');
    }
    vaultAddInputEl.value = uri;
    // Pre-fill from the QR so the fields show exactly what will be saved; edit them to rename.
    const { label, issuer } = readOtpauthLabel(uri);
    vaultAddLabelEl.value = label;
    vaultAddIssuerEl.value = issuer;
    vaultAddScannedEl.textContent = 'QR scanned. Rename below if you like, then click “Add to vault”.';
    vaultAddScannedEl.hidden = false;
    vaultAddLabelEl.focus();
    vaultAddLabelEl.select();
  } catch (err) {
    vaultAddErrorEl.textContent = err.message;
    vaultAddErrorEl.hidden = false;
  } finally {
    done();
  }
}

/**
 * Sends one downscaled frame to the QR worker and waits for its verdict.
 * @param worker - the QR decoding worker
 * @param image - the decoded screenshot
 * @param width - the width to scan at
 * @returns the QR text, or null when none was found
 */
function scanAtWidth(worker, image, width) {
  const scale = width / image.naturalWidth;
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(image.naturalWidth * scale);
  canvas.height = Math.round(image.naturalHeight * scale);
  const context = canvas.getContext('2d', { willReadFrequently: true });
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height);

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('QR scanning took too long. Try again with the QR fully visible.')), QR_SCAN_TIMEOUT_MS);
    worker.onmessage = (event) => {
      clearTimeout(timer);
      resolve(event.data);
    };
    worker.onerror = (event) => {
      clearTimeout(timer);
      reject(new Error(event.message || 'QR scanning failed.'));
    };
    worker.postMessage({ data: pixels.data.buffer, width: pixels.width, height: pixels.height }, [pixels.data.buffer]);
  });
}

/**
 * Finds and decodes a QR code in a screenshot, in a worker and only at capped sizes:
 * a full-resolution scan can take tens of seconds and would freeze the popup until Chrome kills it.
 * @param dataUrl - the PNG screenshot as a data URL
 * @returns the decoded QR text
 */
async function decodeQr(dataUrl) {
  const image = new Image();
  image.src = dataUrl;
  await image.decode();

  const widths = QR_SCAN_WIDTHS.map((width) => Math.min(width, image.naturalWidth));
  const worker = new Worker('qr-worker.js');
  try {
    for (const width of [...new Set(widths)]) {
      const found = await scanAtWidth(worker, image, width);
      if (found) {
        return found;
      }
    }
  } finally {
    worker.terminate();
  }
  throw new Error('No QR code found on this screen. Make sure the setup QR is fully visible, then try again.');
}

/**
 * Opens the change-master-password panel.
 * @returns nothing
 */
function openVaultPasswordForm() {
  state.expiresAt = 0;
  setCodesViewVisible(false);
  hideVaultPanels();
  vaultPasswordFormEl.hidden = false;
  vaultPasswordErrorEl.hidden = true;
  vaultOldPasswordEl.value = '';
  vaultNewPasswordEl.value = '';
  vaultNewPasswordConfirmEl.value = '';
  vaultOldPasswordEl.focus();
}

/**
 * Changes the master password after checking the confirmation matches.
 * @param event - the form submit event
 * @returns resolves once changed or the error is shown
 */
async function submitVaultPassword(event) {
  event.preventDefault();
  if (vaultNewPasswordEl.value !== vaultNewPasswordConfirmEl.value) {
    vaultPasswordErrorEl.textContent = 'The new passwords do not match.';
    vaultPasswordErrorEl.hidden = false;
    return;
  }
  vaultPasswordErrorEl.hidden = true;
  try {
    const reply = await sendToHost({
      type: 'vault.changePassword',
      oldPassword: vaultOldPasswordEl.value,
      newPassword: vaultNewPasswordEl.value,
    });
    await writeSessionToken(reply.sessionToken ?? null);
    await refresh();
  } catch (err) {
    vaultPasswordErrorEl.textContent = err.message;
    vaultPasswordErrorEl.hidden = false;
  }
}

/**
 * Switches between the database and vault tabs.
 * @param tab - 'db' or 'vault'
 * @returns resolves once the tab's content is loading
 */
async function setTab(tab) {
  state.tab = tab;
  state.accounts = [];
  state.editing = null;
  state.expiresAt = 0;
  listEl.replaceChildren();
  statusEl.hidden = true;
  searchEl.value = '';
  for (const tabEl of tabEls) {
    tabEl.classList.toggle('is-active', tabEl.dataset.tab === tab);
    tabEl.setAttribute('aria-selected', String(tabEl.dataset.tab === tab));
  }
  settingsEl.hidden = true;
  settingsToggleEl.hidden = tab !== 'db';
  settingsToggleEl.setAttribute('aria-expanded', 'false');
  hideVaultPanels();
  setCodesViewVisible(true);
  renderDbLabel();
  chrome.storage.local.set({ [TAB_KEY]: tab }).catch((err) => console.warn('Could not save the active tab', err));

  await refresh();
}

/**
 * Updates the countdown ring and pulls new codes when the period rolls over.
 * @returns nothing
 */
function tick() {
  if (!Number.isFinite(state.expiresAt) || state.expiresAt === 0) {
    return;
  }
  const remainingMs = state.expiresAt - Date.now();
  if (remainingMs <= 0) {
    refresh();
    return;
  }
  const seconds = Math.ceil(remainingMs / 1000);
  const ending = seconds <= ENDING_SECONDS;
  timerSecondsEl.textContent = String(seconds);
  timerFillEl.style.strokeDashoffset = String(TIMER_CIRCUMFERENCE * (1 - remainingMs / (state.period * 1000)));
  timerEl.classList.toggle('is-ending', ending);
  document.body.classList.toggle('is-ending', ending);
}

searchEl.addEventListener('input', renderList);
searchEl.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') {
    return;
  }
  const firstRow = listEl.querySelector('.row');
  firstRow?.click();
});
settingsEl.addEventListener('submit', saveSettings);
settingsCancelEl.addEventListener('click', () => {
  closeSettings();
  refresh();
});
settingsToggleEl.addEventListener('click', () => {
  if (settingsEl.hidden) {
    openSettings();
  } else if (state.db.configured) {
    closeSettings();
    refresh();
  }
});
dbLabelEl.addEventListener('click', () => openSettings());

for (const tabEl of tabEls) {
  tabEl.addEventListener('click', () => setTab(tabEl.dataset.tab));
}
vaultLockEl.addEventListener('submit', submitVaultLock);
vaultAddEl.addEventListener('submit', submitVaultAdd);
vaultEditEl.addEventListener('submit', submitVaultEdit);
vaultEditCancelEl.addEventListener('click', () => {
  state.editing = null;
  refresh();
});
vaultEditLinkEl.addEventListener('click', () => {
  state.editing.domain = state.currentHost;
  renderEditSite();
});
vaultEditUnlinkEl.addEventListener('click', () => {
  state.editing.domain = '';
  renderEditSite();
});
// The confirmation takes the place of the action row, so the panel doesn't grow.
vaultEditRemoveEl.addEventListener('click', () => {
  vaultEditErrorEl.hidden = true;
  vaultEditActionsEl.hidden = true;
  vaultEditConfirmEl.hidden = false;
  vaultEditRemoveCancelEl.focus();
});
vaultEditRemoveCancelEl.addEventListener('click', () => {
  vaultEditConfirmEl.hidden = true;
  vaultEditActionsEl.hidden = false;
  vaultEditRemoveEl.focus();
});
vaultEditRemoveConfirmEl.addEventListener('click', removeEditedAccount);
vaultAddToggleEl.addEventListener('click', openVaultAdd);
// Export/import lives in a tab: Chrome closes the popup when a file picker opens.
vaultTransferEl.addEventListener('click', () => {
  chrome.tabs
    .create({ url: chrome.runtime.getURL('transfer.html') })
    .then(() => window.close())
    .catch((err) => showError('Could not open the export page', err.message));
});
vaultAddCancelEl.addEventListener('click', () => refresh());
vaultScanEl.addEventListener('click', scanQrOnScreen);
vaultAddInputEl.addEventListener('input', () => {
  vaultAddScannedEl.hidden = true;
});
vaultChangePasswordEl.addEventListener('click', openVaultPasswordForm);
vaultPasswordCancelEl.addEventListener('click', () => refresh());
vaultPasswordFormEl.addEventListener('submit', submitVaultPassword);
vaultLockNowEl.addEventListener('click', async () => {
  try {
    await sendToHost({ type: 'vault.lock' });
  } catch (err) {
    console.warn('Could not lock the vault', err);
  }
  await writeSessionToken(null);
  await refresh();
});

/**
 * Reads the active tab's hostname; opening the popup grants activeTab, which exposes the URL.
 * @returns the hostname, or '' on chrome:// pages or when it can't be read
 */
async function readCurrentHost() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return hostFromUrl(tab?.url);
  } catch (err) {
    console.warn('Could not read the current tab', err);
    return '';
  }
}

Promise.all([chrome.storage.local.get([LAST_COPIED_KEY, TAB_KEY]), readCurrentHost()])
  .then(([stored, currentHost]) => {
    state.lastCopiedAt = stored[LAST_COPIED_KEY] ?? {};
    state.tab = stored[TAB_KEY] === 'vault' ? 'vault' : 'db';
    state.currentHost = currentHost;
  })
  .catch((err) => {
    console.warn('Could not read saved settings', err);
  })
  .finally(() => {
    setTab(state.tab);
    setInterval(tick, TICK_MS);
  });
