/**
 * "Use on another PC": exports the vault to an encrypted file, or imports one.
 *
 * Runs as a full extension tab, not in the popup, because Chrome closes the popup as soon as a
 * file picker opens. The host encrypts before anything reaches this page and decrypts only after
 * import, so this page only ever handles ciphertext and never sees a secret.
 */
import { HOST_MISSING_PATTERN, sendToHost, setBusy, vaultStatusWithResume, writeSessionToken } from './host-client.js';

const MIN_PASSPHRASE_LENGTH = 12;
const MAX_FILE_BYTES = 1_000_000;

const messageEl = document.getElementById('transfer-message');
const unlockEl = document.getElementById('transfer-unlock');
const unlockPasswordEl = document.getElementById('transfer-unlock-password');
const unlockErrorEl = document.getElementById('transfer-unlock-error');
const unlockSubmitEl = document.getElementById('transfer-unlock-submit');
const mainEl = document.getElementById('transfer-main');
const tabEls = [...document.querySelectorAll('.tab')];
const exportFormEl = document.getElementById('export-form');
const exportMasterEl = document.getElementById('export-master');
const exportPassphraseEl = document.getElementById('export-passphrase');
const exportConfirmEl = document.getElementById('export-passphrase-confirm');
const exportErrorEl = document.getElementById('export-error');
const exportSubmitEl = document.getElementById('export-submit');
const importFormEl = document.getElementById('import-form');
const importFileEl = document.getElementById('import-file');
const importDropEl = document.getElementById('import-drop');
const importFileNameEl = document.getElementById('import-file-name');
const importFileHintEl = document.getElementById('import-file-hint');
const importPassphraseEl = document.getElementById('import-passphrase');
const importErrorEl = document.getElementById('import-error');
const importSubmitEl = document.getElementById('import-submit');
const resultEl = document.getElementById('transfer-result');
const resultTitleEl = document.getElementById('transfer-result-title');
const resultDetailEl = document.getElementById('transfer-result-detail');
const resultWarningEl = document.getElementById('transfer-result-warning');
const resultAgainEl = document.getElementById('transfer-result-again');

let chosenFile = null;
let currentPanel = 'export';

/**
 * Shows a full-width message instead of the forms (no vault, host missing, …).
 * @param text - the message
 * @param isError - whether to style it as an error
 * @returns nothing
 */
function showMessage(text, isError = false) {
  messageEl.className = isError ? 'status is-error' : 'status';
  messageEl.textContent = text;
  messageEl.hidden = false;
}

/**
 * Shows an inline form error, with the setup command when the native host is missing.
 * @param el - the form's error element
 * @param err - the error to show
 * @returns nothing
 */
function showFormError(el, err) {
  el.textContent = HOST_MISSING_PATTERN.test(err.message) ? `${err.message} Run: npm install && npm run setup` : err.message;
  el.hidden = false;
}

/**
 * Switches between the Export and Import forms.
 * @param panel - 'export' or 'import'
 * @returns nothing
 */
function showPanel(panel) {
  currentPanel = panel;
  for (const tabEl of tabEls) {
    const active = tabEl.dataset.panel === panel;
    tabEl.classList.toggle('is-active', active);
    tabEl.setAttribute('aria-selected', String(active));
  }
  exportFormEl.hidden = panel !== 'export';
  importFormEl.hidden = panel !== 'import';
  resultEl.hidden = true;
  (panel === 'export' ? exportMasterEl : importFileEl).focus();
}

/**
 * Replaces the active form with a result card.
 * @param title - what happened
 * @param detail - the specifics
 * @param warning - the next safety step
 * @returns nothing
 */
function showResult(title, detail, warning) {
  exportFormEl.hidden = true;
  importFormEl.hidden = true;
  resultTitleEl.textContent = title;
  resultDetailEl.textContent = detail;
  resultWarningEl.textContent = warning;
  resultEl.hidden = false;
  resultAgainEl.focus();
}

/**
 * Hands the encrypted export to the browser as a download. The content is ciphertext only.
 * @param content - the export file's text
 * @param fileName - the suggested file name
 * @returns nothing
 */
function downloadFile(content, fileName) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * Exports the vault after checking the passphrase locally; the host re-checks everything.
 * @param event - the form submit event
 * @returns resolves once downloaded or the error is shown
 */
async function submitExport(event) {
  event.preventDefault();
  exportErrorEl.hidden = true;
  if (exportPassphraseEl.value.length < MIN_PASSPHRASE_LENGTH) {
    showFormError(exportErrorEl, new Error(`The export passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`));
    return;
  }
  if (exportPassphraseEl.value !== exportConfirmEl.value) {
    showFormError(exportErrorEl, new Error('The passphrases do not match.'));
    return;
  }
  if (exportPassphraseEl.value === exportMasterEl.value) {
    showFormError(exportErrorEl, new Error('Use a different passphrase from your master password.'));
    return;
  }
  const done = setBusy(exportSubmitEl, 'Encrypting…');
  try {
    const reply = await sendToHost({
      type: 'vault.export',
      masterPassword: exportMasterEl.value,
      exportPassphrase: exportPassphraseEl.value,
    });
    downloadFile(reply.content, reply.fileName);
    exportFormEl.reset();
    const accounts = reply.count === 1 ? '1 account' : `${reply.count} accounts`;
    showResult(
      'Export file downloaded',
      `${reply.fileName} (${accounts}) is in your Downloads folder. On the other PC, open Dev Authenticator → Vault → Export / Import → Import.`,
      'Delete the file from Downloads, chat and email once it is imported.',
    );
  } catch (err) {
    showFormError(exportErrorEl, err);
  } finally {
    done();
  }
}

/**
 * Clears the picked file, so a finished import can't be repeated by accident.
 * @returns nothing
 */
function resetFileChoice() {
  chosenFile = null;
  importFileEl.value = '';
  importDropEl.classList.remove('has-file');
  importFileNameEl.textContent = 'Choose the .enc export file';
  importFileHintEl.textContent = 'or drop it here';
}

/**
 * Remembers the chosen file and shows its name, rejecting anything too big to be an export.
 * @param file - the picked or dropped file
 * @returns nothing
 */
function chooseFile(file) {
  importErrorEl.hidden = true;
  if (!file) {
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    resetFileChoice();
    showFormError(importErrorEl, new Error('That file is too large to be a Dev Authenticator export file.'));
    return;
  }
  chosenFile = file;
  importDropEl.classList.add('has-file');
  importFileNameEl.textContent = file.name;
  importFileHintEl.textContent = `${Math.max(1, Math.round(file.size / 1024))} KB · click to choose another`;
  importPassphraseEl.focus();
}

/**
 * Sends the file's (encrypted) text to the host, which decrypts, validates and merges it.
 * @param event - the form submit event
 * @returns resolves once imported or the error is shown
 */
async function submitImport(event) {
  event.preventDefault();
  importErrorEl.hidden = true;
  if (!chosenFile) {
    showFormError(importErrorEl, new Error('Choose the export file first.'));
    return;
  }
  const done = setBusy(importSubmitEl, 'Decrypting…');
  try {
    const reply = await sendToHost({
      type: 'vault.import',
      content: await chosenFile.text(),
      passphrase: importPassphraseEl.value,
    });
    importPassphraseEl.value = '';
    resetFileChoice();
    showResult(...describeImport(reply));
  } catch (err) {
    showFormError(importErrorEl, err);
  } finally {
    done();
  }
}

/**
 * Turns the host's import counts into the result card text.
 * @param reply - `{ imported, skipped, invalid }` from the host
 * @returns the title, detail and warning lines
 */
function describeImport({ imported, skipped, invalid }) {
  const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;
  const was = (count) => (count === 1 ? 'was' : 'were');
  const notes = [];
  if (skipped) {
    notes.push(`${plural(skipped, 'account', 'accounts')} already in this vault ${was(skipped)} skipped`);
  }
  if (invalid) {
    notes.push(`${plural(invalid, 'entry', 'entries')} couldn't be read and ${was(invalid)} ignored`);
  }
  const title = imported ? `Imported ${plural(imported, 'account', 'accounts')}` : 'Nothing new to import';
  const detail = notes.length ? `${notes.join('; ')}.` : 'They are in your vault now. Open the popup to see their codes.';
  return [title, detail, 'Delete the export file now. This PC no longer needs it.'];
}

/**
 * Unlocks the vault on this page (it has its own host process).
 * @param event - the form submit event
 * @returns resolves once unlocked or the error is shown
 */
async function submitUnlock(event) {
  event.preventDefault();
  unlockErrorEl.hidden = true;
  const done = setBusy(unlockSubmitEl, 'Unlocking…');
  try {
    const reply = await sendToHost({ type: 'vault.unlock', password: unlockPasswordEl.value });
    await writeSessionToken(reply.sessionToken ?? null);
    unlockPasswordEl.value = '';
    unlockEl.hidden = true;
    mainEl.hidden = false;
    showPanel('export');
  } catch (err) {
    showFormError(unlockErrorEl, err);
    unlockPasswordEl.select();
  } finally {
    done();
  }
}

/**
 * Shows the right first screen: no vault yet, locked, or the export/import forms.
 * @returns resolves once a screen is shown
 */
async function init() {
  let status;
  try {
    status = await vaultStatusWithResume();
  } catch (err) {
    const hint = HOST_MISSING_PATTERN.test(err.message) ? ' Run: cd totp-athenticator && npm install && npm run setup' : '';
    showMessage(`${err.message}${hint}`, true);
    return;
  }
  if (!status.exists) {
    showMessage('Create your vault first: open the extension popup, choose Vault and set a master password. Then come back here to import.');
    return;
  }
  if (!status.unlocked) {
    unlockEl.hidden = false;
    unlockPasswordEl.focus();
    return;
  }
  mainEl.hidden = false;
  showPanel(new URLSearchParams(location.search).get('panel') === 'import' ? 'import' : 'export');
}

for (const tabEl of tabEls) {
  tabEl.addEventListener('click', () => showPanel(tabEl.dataset.panel));
}
exportFormEl.addEventListener('submit', submitExport);
importFormEl.addEventListener('submit', submitImport);
unlockEl.addEventListener('submit', submitUnlock);
importFileEl.addEventListener('change', () => chooseFile(importFileEl.files[0]));
importDropEl.addEventListener('dragover', (event) => {
  event.preventDefault();
  importDropEl.classList.add('is-dragging');
});
importDropEl.addEventListener('dragleave', () => importDropEl.classList.remove('is-dragging'));
importDropEl.addEventListener('drop', (event) => {
  event.preventDefault();
  importDropEl.classList.remove('is-dragging');
  chooseFile(event.dataTransfer.files[0]);
});
resultAgainEl.addEventListener('click', () => showPanel(currentPanel));

init();
