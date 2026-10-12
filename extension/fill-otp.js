/**
 * Types a 2FA code into the current page's code field and, optionally, presses its Verify button.
 *
 * Injected with chrome.scripting.executeScript only when the user clicks "fill", into the active
 * tab only. Chrome serializes this function into the page, so it must be fully self-contained:
 * no imports, no outer variables. It receives just the 6-digit code — never a secret.
 * @param code - the current TOTP code
 * @param options - `submit`: press the page's Verify/Submit button after filling
 * @returns { filled, fields, submitted }
 */
export async function fillOtpCode(code, { submit = false } = {}) {
  const CODE_HINT = /otp|totp|one.?time|2fa|mfa|two.?factor|auth(entication)?.?code|verif|security.?code|passcode|token|\bcode\b/i;
  const SUBMIT_TEXT = /verify|submit|continue|confirm|sign.?in|log.?in|next|done|authenticate|proceed/i;
  const AVOID_TEXT = /another|different|resend|send.?again|back|cancel|change|help|forgot/i;
  const TEXT_TYPES = new Set(['', 'text', 'tel', 'number', 'password']);
  const SUBMIT_WAIT_MS = 1500;
  const SUBMIT_POLL_MS = 50;

  const isVisible = (element) => {
    for (let node = element; node; node = node.parentElement) {
      const style = window.getComputedStyle(node);
      if (node.hidden || style.display === 'none' || style.visibility === 'hidden') {
        return false;
      }
    }
    return true;
  };

  const isFillable = (input) =>
    TEXT_TYPES.has((input.getAttribute('type') ?? '').toLowerCase()) &&
    !input.disabled &&
    !input.readOnly &&
    isVisible(input);

  const describe = (input) => {
    const labels = [...(input.labels ?? [])].map((label) => label.textContent);
    return [input.name, input.id, input.placeholder, input.getAttribute('aria-label'), input.autocomplete, ...labels].join(' ');
  };

  // Frameworks like React track the last value they set through the element's own setter;
  // the prototype setter bypasses that, so the input event is seen as a real change.
  const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  const setValue = (input, value) => {
    input.focus();
    nativeSetter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };

  /** Picks the inputs to fill: digit boxes, a labelled code field, or the focused field. */
  const pickTargets = () => {
    const inputs = [...document.querySelectorAll('input')].filter(isFillable);

    const boxes = inputs.filter((input) => input.maxLength === 1);
    if (boxes.length >= code.length) {
      return boxes.slice(0, code.length);
    }
    const single =
      inputs.find((input) => input.autocomplete === 'one-time-code') ??
      inputs.find((input) => input.maxLength !== 1 && CODE_HINT.test(describe(input)));
    if (single) {
      return [single];
    }
    // Never an unlabelled password field: on a normal login page that is the account password.
    const focused = document.activeElement;
    const focusedOk =
      focused instanceof window.HTMLInputElement &&
      inputs.includes(focused) &&
      focused.maxLength !== 1 &&
      focused.type !== 'password';
    return focusedOk ? [focused] : [];
  };

  /** Finds the Verify-style button nearest to the code field, skipping "Try another way" and co. */
  const findSubmitButton = (field) => {
    const labelOf = (button) => `${button.textContent} ${button.value ?? ''} ${button.getAttribute('aria-label') ?? ''}`;
    const isCandidate = (button) => {
      const label = labelOf(button);
      const plainSubmit = button.type === 'submit' && !label.trim();
      return isVisible(button) && !AVOID_TEXT.test(label) && (SUBMIT_TEXT.test(label) || plainSubmit);
    };
    for (let node = field.parentElement; node; node = node.parentElement) {
      const found = [...node.querySelectorAll('button, input[type="submit"], [role="button"]')].find(isCandidate);
      if (found) {
        return found;
      }
    }
    return null;
  };

  /**
   * Presses Verify once the page enables it (React re-renders after the last digit). Skips it if
   * the page already submitted by itself: the fields were removed or locked.
   */
  const pressSubmit = async (fields) => {
    const deadline = Date.now() + SUBMIT_WAIT_MS;
    while (Date.now() <= deadline) {
      if (!fields[0].isConnected || fields.every((field) => field.disabled)) {
        return false;
      }
      const button = findSubmitButton(fields[0]);
      if (button && !button.disabled && button.getAttribute('aria-disabled') !== 'true') {
        button.click();
        return true;
      }
      await new Promise((resolve) => window.setTimeout(resolve, SUBMIT_POLL_MS));
    }
    return false;
  };

  const targets = pickTargets();
  if (targets.length === 0) {
    return { filled: false, fields: 0, submitted: false };
  }
  if (targets.length === 1) {
    setValue(targets[0], code);
  } else {
    targets.forEach((input, index) => setValue(input, code[index]));
  }
  const submitted = submit ? await pressSubmit(targets) : false;
  return { filled: true, fields: targets.length, submitted };
}
