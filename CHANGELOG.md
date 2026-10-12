# Changelog

## 1.0.0 — 2026-10-05

First team release.

### Database tab
- Live 2FA codes for every account enrolled with an authenticator app in your local or team dev MongoDB.
- Production URLs are refused: only `localhost`, `127.0.0.1` and the dev servers in `host/allowed-hosts.json` are accepted.

### Vault tab (staging / production)
- Encrypted vault for your own accounts on servers whose database you can't reach (AES-256-GCM, scrypt-derived key, master password never stored).
- Add accounts by scanning the 2FA setup QR on screen, or by pasting the setup key / `otpauth://` URI. Optionally rename the label and issuer.
- 6-hour unlock session, like Bitwarden. Ends on lock, password change or browser restart.
- Change master password, remove accounts (with confirmation).

### Autofill
- One click types the code into the current page's 2FA field (single field or one box per digit) and presses Verify. Shift+click fills without pressing Verify.
- Works with React-style sites. Falls back to copying the code when the page has no recognisable code field.

### Security
- Secrets never reach the browser; the popup and web pages only ever see 6-digit codes.
- Vault and session files are readable only by you (`0600`, folder `0700`).
- Code is injected into a page only when you click fill, and only into the current tab.
