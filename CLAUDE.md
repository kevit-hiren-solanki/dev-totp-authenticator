# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Dev Authenticator: a Chrome MV3 extension that shows live 2FA (TOTP) codes from a dev MongoDB (Database tab) or from an encrypted personal vault (Vault tab), fills them into login pages, and moves the vault between PCs via encrypted export files. Personal/team tool; loaded unpacked, never published to the Chrome Web Store.

## Verify every change (no CI — this is the only gate)

There is no GitHub CI on purpose: the maintainer runs everything locally. After **any** code change, before saying the work is done:

1. Run the full suite: `npm test`. It must end with `# fail 0`. Report any failing test by name, including ones you didn't cause.
2. Syntax-check the extension (no build step catches typos): `for f in extension/*.js; do node --check "$f"; done`
3. If the change touches the popup or transfer page markup, check every `getElementById('…')` in the JS still has a matching `id="…"` in the HTML.
4. For UI changes, look at the result (see "Checking UI changes" below) — tests cover no layout.

One end-to-end test needs a local MongoDB on `localhost:27017`; without it, it is reported as `# SKIP no local MongoDB` rather than failing. Say so when it was skipped.

## Commands

```bash
npm install                 # deps: mongodb (host), jsdom + jsqr (dev/tests)
npm run setup               # registers the native host for Chrome/Chromium/Brave/Edge (Linux, macOS)
npm run uninstall-host
npm test                    # node --test test/*.test.mjs

node --test test/vault-session.test.mjs                               # one file
node --test --test-name-pattern="wrong passphrase" test/*.test.mjs    # tests matching a name
```

After changing extension files, reload the extension in `chrome://extensions` (manifest changes require it). Re-run `npm run setup` after moving the folder or switching Node versions: it writes `host/run-host.sh` with absolute paths (gitignored, machine-specific).

## Architecture

**Two processes.** `extension/` runs in Chrome; `host/` is a Node native-messaging host (`host/host.mjs`) that Chrome starts per connecting page — the popup, the transfer tab and the background service worker each get their own host process, which exits when that page disconnects. `install.mjs` registers the host for the extension ID derived from the pinned `key` in `manifest.json`; changing that key breaks every install.

**Core invariant: secrets never reach the browser.** The host decrypts the vault, generates codes and replies with labels, issuers, domains and 6-digit codes only. The browser sends a secret exactly once (when adding an account) and otherwise handles only ciphertext (export/import files). Tests assert no secret appears in replies — never add a message that returns a secret, a password, or the stored Mongo URL.

**Message protocol** (`extension/host-client.js` ↔ `host/host.mjs`): length-prefixed JSON over stdio. Each request is `{ ...payload, id }` and each reply `{ ...payload, id, ok }` — the envelope fields go **last** so a payload can't overwrite them. Never use `id` as a payload field (use `accountId`); that exact collision once made requests hang forever. `vault.*` types go to `VaultSession.handle` (`host/vault-session.mjs`), `db.*` to `handleDbRequest` in `host.mjs`; anything else is an error. Every request times out after 20s client-side.

**Storage** — `~/.config/dev-authenticator/` (`XDG_CONFIG_HOME` respected; `DEV_AUTHENTICATOR_VAULT` overrides the path, used by tests). All files are written temp-then-rename with mode `0600`, directory `0700`:
- `vault.enc` — accounts, AES-256-GCM under a key from the master password via scrypt (N=2^17). Wrong password and tampering are deliberately indistinguishable.
- `vault.enc.session` — the vault key sealed with a random token; the token lives only in `chrome.storage.session` (memory). Gives the 6-hour unlock; lock, password change or browser restart end it.
- `vault.enc.db` — the Database tab's Mongo URL (may contain a password), sealed with the vault key. So the Database tab requires an unlocked vault.
- Anything sealed with the vault key must be re-sealed in `VaultSession.changePassword` (it reads with the old key first).
- Export files (`host/vault.mjs` `encryptExport`/`decryptExport`) use their own passphrase (≥12 chars, master password re-checked before export). Import bounds the file's scrypt cost, validates every account, merges only and skips duplicate secrets.

**Two secret formats.** Database-tab secrets are the platform's raw ASCII strings (`users.mfaSettings.secret`); vault secrets are base32 from `otpauth://` URIs. `host/totp.mjs` takes either (string = ASCII, Buffer = decoded base32). The Database tab only connects to `localhost`, `127.0.0.1` and hosts in `host/allowed-hosts.json` — never add a production host.

**Extension modules** (no bundler; ES modules loaded directly):
- `popup.js` — the popup UI for both tabs. `host-client.js` — shared native-messaging client, session resume (`vaultStatusWithResume`) and `setBusy`.
- `transfer.html`/`transfer.js` — export/import page, opened in a tab because Chrome closes the popup when a file picker opens.
- `background.js` — service worker for the Alt+Shift+F command; the decision logic is `quick-fill.js` (dependencies injected, unit-tested). It fills only when exactly one vault account is linked to the site, otherwise opens the popup; it disconnects afterwards so the host (and vault key) exits.
- `fill-otp.js` — `fillOtpCode` is serialized into the page by `chrome.scripting.executeScript`, so it **must stay self-contained** (no imports, no outer variables). Tests run it via `toString()` in jsdom. It sets values through the native `HTMLInputElement` setter so React sees them, and only clicks Verify-like buttons.
- `site-match.js` — base-domain matching for "This site" sorting, the badge and quick fill; look-alikes like `vezly.ai.evil.com` must never match.
- `qr-worker.js` + `vendor/jsqr.js` — QR decoding off the main thread at capped widths (full-resolution decoding froze and killed the popup).

**No network at runtime.** Fonts (`vendor/fonts/`) and jsQR are vendored; don't add CDN links or remote resources.

## Tests

`node:test` only. Patterns used across the suite:
- `VaultSession` takes test seams: a cheap `kdf` (`{ N: 1024, r: 8, p: 1 }`), a fixed `now`, and a recording `sleep` (for the 500ms failed-unlock delay).
- `test/host-vault.test.mjs` spawns the real host and speaks the real framing, matching replies **by id** as the popup does (matching by order hid the id-collision bug).
- Write the failing test first; most features here were built that way.

## Checking UI changes

There are no automated UI tests. What has worked: copy `extension/` to a scratch directory, inject a `chrome-stub.js` (fake `chrome.runtime.connectNative`, `storage`, `tabs`, `scripting`) before the page scripts, serve it with `python3 -m http.server`, and drive it with Playwright at 360px wide in dark and light mode. Delete `.playwright-mcp/` artifacts afterwards.

UI rules learned the hard way:
- The popup is 360px wide and Chrome caps its height at 600px — measure tall panels (`document.body` height) in every state.
- The list rebuilds every 30s when codes roll over; state that must survive (open panels, busy buttons) can't live only in row DOM.
- Styling is token-based in `popup.css` (GitHub Primer palette, light/dark via `prefers-color-scheme`); the theme follows the system, there's no toggle. Buttons share one 30px default style.
- Check computed styles, not just screenshots: a later generic rule (e.g. `.icon-button`) has overridden specific ones before.

## Releases

Version lives in `package.json`, `package-lock.json` and `extension/manifest.json`; add a dated section to `CHANGELOG.md`. Tag `vX.Y.Z`, then build the team zip from the tag so it contains only committed files: `git archive --format=zip --prefix=totp-athenticator/ -o ../dev-authenticator-vX.Y.Z.zip vX.Y.Z`. Verify it in a fresh directory (`npm ci && npm test`) before sharing. Remote: `origin` → `git@github.com:kevit-hiren-solanki/dev-totp-authenticator.git`, branch `main`.
