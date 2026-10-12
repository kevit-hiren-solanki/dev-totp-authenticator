/**
 * Talks to the native host (host/host.mjs) over Chrome native messaging, for every extension
 * page: the popup and the transfer page. Each page gets its own host process, so a page that
 * opens later resumes the vault through the six-hour session token instead of the password.
 */

const HOST_NAME = 'com.vezly.dev_totp';
const REQUEST_TIMEOUT_MS = 20000;
const SESSION_TOKEN_KEY = 'vaultSessionToken';

export const HOST_MISSING_PATTERN = /not found|forbidden|exited/i;

const pendingRequests = new Map();
let nextRequestId = 1;
let port = null;

/**
 * Opens the native host; Chrome starts it and keeps it alive while this page is open.
 * @returns nothing
 */
function connect() {
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener((message) => {
    const request = pendingRequests.get(message.id);
    if (!request) {
      return;
    }
    pendingRequests.delete(message.id);
    if (message.ok) {
      request.resolve(message);
    } else {
      request.reject(new Error(message.error));
    }
  });
  port.onDisconnect.addListener(() => {
    const reason = chrome.runtime.lastError?.message ?? 'The native host exited.';
    port = null;
    for (const request of pendingRequests.values()) {
      request.reject(new Error(reason));
    }
    pendingRequests.clear();
  });
}

/**
 * Sends one request to the native host and resolves with its reply.
 * @param payload - the message, minus the id this function assigns
 * @returns the host's reply
 */
export function sendToHost(payload) {
  if (!port) {
    connect();
  }
  return new Promise((resolve, reject) => {
    const id = nextRequestId++;
    // A reply that never arrives must fail loudly, not leave a button spinning forever.
    const timer = setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error('The native host did not answer in time. Close and reopen the popup.'));
    }, REQUEST_TIMEOUT_MS);
    pendingRequests.set(id, {
      resolve: (message) => {
        clearTimeout(timer);
        resolve(message);
      },
      reject: (err) => {
        clearTimeout(timer);
        reject(err);
      },
    });
    // Envelope id last so a payload field can never replace it.
    port.postMessage({ ...payload, id });
  });
}

/**
 * Reads the unlock session token from browser session memory (cleared when the browser closes).
 * @returns the token, or null
 */
async function readSessionToken() {
  try {
    return (await chrome.storage.session.get(SESSION_TOKEN_KEY))[SESSION_TOKEN_KEY] ?? null;
  } catch {
    return null;
  }
}

/**
 * Stores or clears the unlock session token.
 * @param token - the token from the host, or null to clear it
 * @returns resolves once stored
 */
export async function writeSessionToken(token) {
  try {
    if (token) {
      await chrome.storage.session.set({ [SESSION_TOKEN_KEY]: token });
    } else {
      await chrome.storage.session.remove(SESSION_TOKEN_KEY);
    }
  } catch (err) {
    console.warn('Could not store the unlock session', err);
  }
}

/**
 * Asks the host for the vault state, resuming the six-hour unlock session if one is running.
 * @returns `{ exists, unlocked }` after any resume
 */
export async function vaultStatusWithResume() {
  const status = await sendToHost({ type: 'vault.status' });
  if (status.unlocked || !status.exists) {
    return status;
  }
  const token = await readSessionToken();
  if (!token) {
    return status;
  }
  try {
    await sendToHost({ type: 'vault.resume', sessionToken: token });
    return { ...status, unlocked: true };
  } catch {
    await writeSessionToken(null);
    return status;
  }
}

/**
 * Disables a button and swaps its label while work runs, so busy never looks like stuck.
 * @param button - the button to mark busy
 * @param busyText - the label to show meanwhile
 * @returns a function that restores the button
 */
export function setBusy(button, busyText) {
  const idleText = button.textContent;
  button.disabled = true;
  button.classList.add('is-busy');
  button.textContent = busyText;
  return () => {
    button.disabled = false;
    button.classList.remove('is-busy');
    button.textContent = idleText;
  };
}
