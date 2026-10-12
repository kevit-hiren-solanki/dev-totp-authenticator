# Changelog

## 1.1.0 — 2026-10-12

- **Mongo URL encrypted:** the Database tab's URL (which may hold a password) is now stored sealed with the vault key next to the vault, never in browser storage; the popup sends it only when you save it and shows just host and database name. The old plain-text copy is migrated and deleted automatically. The Database tab now needs the vault unlocked.
- **Alt+Shift+F quick fill:** fills and submits the code for the open site's single linked vault account, without opening the popup; falls back to the popup whenever there's any doubt.
- **Use on another PC:** encrypted export/import of the vault (AES-256-GCM, scrypt), with the master password asked again before export, a 12-character minimum passphrase, merge-only import that skips duplicates, and strict validation of imported accounts.
- Redesigned popup in GitHub's colors (dark and light), with bundled IBM Plex Sans and JetBrains Mono fonts.
- Clearer row actions: a labelled **Fill** button instead of an arrow icon, and one consistent GitHub-style button look across Fill, delete, Cancel and Add account.
- Vault accounts remember the site they were added on: on that site they're listed first with a **This site** badge, which also flags a look-alike site when the badge is missing.

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
