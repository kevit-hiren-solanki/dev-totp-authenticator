import assert from 'node:assert/strict';
import { test } from 'node:test';
import { JSDOM } from 'jsdom';
import { fillOtpCode } from '../extension/fill-otp.js';

const CODE = '053798';

/**
 * Runs fillOtpCode inside a page the way chrome.scripting.executeScript does: the function is
 * serialized and evaluated in the page, so it must not depend on anything outside itself.
 */
async function fillInPage(html, code = CODE, setup = () => {}, options = { submit: false }) {
  const dom = new JSDOM(`<!doctype html><body>${html}</body>`, { runScripts: 'outside-only' });
  setup(dom.window);
  const result = await dom.window.eval(`(${fillOtpCode.toString()})(${JSON.stringify(code)}, ${JSON.stringify(options)})`);
  return { result, document: dom.window.document, window: dom.window };
}

const values = (document, selector = 'input') => [...document.querySelectorAll(selector)].map((input) => input.value);

test('fills six single-digit boxes like the Vezly login', async () => {
  const boxes = '<input maxlength="1" placeholder="-">'.repeat(6);
  const { result, document } = await fillInPage(`<form>${boxes}<button>Verify</button></form>`);
  assert.deepEqual(values(document), ['0', '5', '3', '7', '9', '8']);
  assert.equal(result.filled, true);
});

test('fills a single one-time-code input', async () => {
  const { result, document } = await fillInPage('<input type="text" autocomplete="one-time-code">');
  assert.deepEqual(values(document), [CODE]);
  assert.equal(result.filled, true);
});

test('fills a single input recognised by its name or label', async () => {
  for (const attrs of ['name="otp"', 'id="totp-code"', 'placeholder="Authentication code"', 'aria-label="2FA code"', 'name="mfa_token"']) {
    const { result, document } = await fillInPage(`<input type="text" ${attrs}>`);
    assert.deepEqual(values(document), [CODE], attrs);
    assert.equal(result.filled, true, attrs);
  }
});

test('never fills a login form that has no code field', async () => {
  const { result, document } = await fillInPage('<input type="email" name="email"><input type="password" name="password">');
  assert.deepEqual(values(document), ['', '']);
  assert.equal(result.filled, false);
});

test('skips hidden, disabled and read-only inputs', async () => {
  const html = `
    <input type="hidden" name="otp">
    <input name="otp" style="display:none">
    <div hidden><input name="otp"></div>
    <input name="otp" disabled>
    <input name="otp" readonly>
    <input name="otp" id="real">`;
  const { result, document } = await fillInPage(html);
  assert.equal(document.getElementById('real').value, CODE);
  assert.deepEqual(values(document).filter(Boolean), [CODE]);
  assert.equal(result.filled, true);
});

test('falls back to the focused text input when nothing is labelled as a code field', async () => {
  const { result, document } = await fillInPage('<input id="plain" type="text">', CODE, (window) => {
    window.document.getElementById('plain').focus();
  });
  assert.equal(document.getElementById('plain').value, CODE);
  assert.equal(result.filled, true);
});

test('never types the code into a focused login password field', async () => {
  const { result, document } = await fillInPage('<input type="password" name="password" id="pw">', CODE, (window) => {
    window.document.getElementById('pw').focus();
  });
  assert.equal(document.getElementById('pw').value, '');
  assert.equal(result.filled, false);
});

test('does not treat four single-character boxes as a six-digit code', async () => {
  const { result, document } = await fillInPage('<input maxlength="1">'.repeat(4));
  assert.deepEqual(values(document), ['', '', '', '']);
  assert.equal(result.filled, false);
});

test('fires input and change events so frameworks see the new value', async () => {
  const events = [];
  const { document } = await fillInPage('<input name="otp">', CODE, (window) => {
    const input = window.document.querySelector('input');
    for (const type of ['input', 'change']) {
      input.addEventListener(type, (event) => events.push(`${type}:${event.bubbles}`));
    }
  });
  assert.equal(document.querySelector('input').value, CODE);
  assert.deepEqual(events, ['input:true', 'change:true']);
});

test('sets the value through the native setter, as React-controlled inputs require', async () => {
  // React wraps each input's `value` setter to track the last value it rendered. A plain
  // `input.value = x` updates that tracker, so React sees "no change" and ignores the event.
  let reactSawChange = false;
  await fillInPage('<input name="otp">', CODE, (window) => {
    const input = window.document.querySelector('input');
    const native = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    let tracked = '';
    Object.defineProperty(input, 'value', {
      configurable: true,
      get() {
        return native.get.call(this);
      },
      set(next) {
        tracked = next;
        native.set.call(this, next);
      },
    });
    input.addEventListener('input', () => {
      reactSawChange = native.get.call(input) !== tracked;
    });
  });
  assert.equal(reactSawChange, true);
});

test('prefers the split boxes over an unrelated focused field', async () => {
  const html = `<input id="search" type="search">${'<input class="box" maxlength="1">'.repeat(6)}`;
  const { document } = await fillInPage(html, CODE, (window) => window.document.getElementById('search').focus());
  assert.equal(document.getElementById('search').value, '');
  assert.deepEqual(values(document, '.box'), ['0', '5', '3', '7', '9', '8']);
});

const BOXES = '<input maxlength="1">'.repeat(6);

/** Records which buttons get clicked, and blocks jsdom's unimplemented form navigation. */
function trackClicks(window) {
  window.clicked = [];
  window.document.addEventListener('click', (event) => window.clicked.push(event.target.textContent.trim()), true);
  window.document.addEventListener('submit', (event) => event.preventDefault(), true);
}

test('presses Verify after filling', async () => {
  const html = `<form>${BOXES}<button type="submit">Verify</button><button type="button">Try another way</button></form>`;
  const { result, window } = await fillInPage(html, CODE, trackClicks, { submit: true });
  assert.deepEqual(window.clicked, ['Verify']);
  assert.equal(result.submitted, true);
});

test('waits for a Verify button the page only enables once all digits are in', async () => {
  const html = `<div>${BOXES}<button id="verify" type="button" disabled>Verify</button></div>`;
  const { result, window } = await fillInPage(
    html,
    CODE,
    (win) => {
      trackClicks(win);
      // Like React: re-render (and enable) a little after the last input event.
      win.document.querySelectorAll('input')[5].addEventListener('input', () => {
        win.setTimeout(() => (win.document.getElementById('verify').disabled = false), 80);
      });
    },
    { submit: true },
  );
  assert.deepEqual(window.clicked, ['Verify']);
  assert.equal(result.submitted, true);
});

test('never presses "Try another way", "Use a different account" or "Resend"', async () => {
  const html = `<div>${BOXES}<button type="button">Try another way</button><a href="#" role="button">Use a different account</a><button type="button">Resend code</button></div>`;
  const { result, window } = await fillInPage(html, CODE, trackClicks, { submit: true });
  assert.deepEqual(window.clicked, []);
  assert.equal(result.filled, true);
  assert.equal(result.submitted, false);
});

test('gives up without clicking when Verify stays disabled', async () => {
  const html = `<div>${BOXES}<button type="button" disabled>Verify</button></div>`;
  const { result, window } = await fillInPage(html, CODE, trackClicks, { submit: true });
  assert.deepEqual(window.clicked, []);
  assert.equal(result.submitted, false);
});

test('does not click again when the page submitted itself on the last digit', async () => {
  const html = `<div id="step">${BOXES}<button type="button">Verify</button></div>`;
  const { result, window } = await fillInPage(
    html,
    CODE,
    (win) => {
      trackClicks(win);
      win.document.querySelectorAll('input')[5].addEventListener('input', () => win.document.getElementById('step').remove());
    },
    { submit: true },
  );
  assert.deepEqual(window.clicked, []);
  assert.equal(result.submitted, false);
});

test('only fills when submit is off', async () => {
  const html = `<form>${BOXES}<button type="submit">Verify</button></form>`;
  const { result, window } = await fillInPage(html, CODE, trackClicks, { submit: false });
  assert.deepEqual(window.clicked, []);
  assert.equal(result.submitted, false);
});
