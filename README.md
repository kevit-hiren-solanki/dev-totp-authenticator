# Dev Authenticator

Version 1.0.0 — see [CHANGELOG.md](CHANGELOG.md).

Chrome extension that shows live 2FA (authenticator-app) codes so you can log in without a phone. It has two tabs:

- **Database** — every enrolled account in your Vezly MongoDB, on your machine or the team dev server.
- **Vault** — your own accounts on staging/production (where you have no database access), stored encrypted on this machine like a password manager.

Clicking the toolbar icon starts a small local Node program through Chrome native messaging. It reads secrets from Mongo (`mfaSettings.secret` in `users`) or from the encrypted vault file and sends back only the 6-digit codes. Secrets never reach the browser.

Only `localhost`, `127.0.0.1` and the team dev servers listed in [`host/allowed-hosts.json`](host/allowed-hosts.json) are accepted, so a production URL is refused even if it's pasted by mistake. Add a dev server there (not a production one) if the team gets a new one.

## Setup (once per machine)

Requires Linux or macOS, Node 18+, and Chrome, Chromium, Brave or Edge. (Windows isn't supported: the setup script only registers the native host on Linux and macOS.)

Unzip the release somewhere permanent (the browser runs the host from this folder, so don't leave it in Downloads if you clean that out), then:

```bash
cd totp-athenticator
npm install
npm run setup
```

1. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and pick the `extension/` folder.
2. Click the extension icon (or press **Alt+Shift+2**).
3. On first open, enter your Mongo URL, including the database name, and click **Save & connect**. For example:
   - Local: `mongodb://localhost:27017/vezly`
   - Team dev server: `mongodb://<user>:<password>@172.24.3.43:27017/<your-db>?authSource=admin`

The URL (including any password) is saved in this browser's extension storage on your machine. The popup never displays the password. Change it later from the database button in the header or the `db:` badge in the footer.

Only need staging/production accounts? Skip the Mongo URL and open the **Vault** tab.

Re-run `npm run setup` if you move this folder or switch Node versions (for example with nvm).

## Updating to a new release

1. Replace the `totp-athenticator` folder with the new one, in the same place.
2. Run `npm install && npm run setup` in it.
3. Click the reload icon on Dev Authenticator in `chrome://extensions`.

Your vault isn't affected: it lives in `~/.config/dev-authenticator/`, not in this folder.

## Use

- Click a code to copy it. **Enter** copies the first match.
- Click **Fill** next to a code to type it into the 2FA field of the page you're on (single field or one box per digit) and press its Verify button. **Shift+click** fills without pressing Verify. If the page has no recognisable code field, the code is copied instead. Filling only happens on that click, only in the current tab, and only the 6-digit code reaches the page.
- Search by name or email.
- **Alt+Shift+F** on a login page fills and submits the code for that site's vault account without opening the popup. It acts only when exactly one account is linked to the site (see "This site" below); otherwise — vault locked, no linked account, several accounts, no code field — it opens the popup instead. The toolbar icon flashes ✓ on success. Change the key at `chrome://extensions/shortcuts`.
- Only users who finished 2FA enrolment with the authenticator app (scanned the QR) appear. Email and WhatsApp codes are sent to you, so they can't be shown here.

## Vault (staging / production accounts)

The Vault tab holds authenticator accounts for servers whose database you can't reach. It is encrypted with a master password you choose on first use (AES-256-GCM, scrypt key derivation) and stored only in `~/.config/dev-authenticator/vault.enc`. The password is never stored; if you forget it, delete that file and re-add your accounts.

Adding an account (once per account):

1. On the platform, start authenticator 2FA setup (or reset it) so the QR code shows.
2. In the Vault tab, click **+ Add account**, then **Scan QR code on this screen** while the QR is visible in the current tab — or paste the setup key / `otpauth://` URI instead.
3. Scan the same QR with your phone app too if you want both to work, then finish enrolment using the code from either.

The extension remembers which site you added each account on. Next time you open the popup on that site (any subdomain of it), that account is listed first with a **This site** badge. No badge means you're not on that account's site, so check the address bar before filling. Accounts added before this feature have no site; remove and re-add them to get one.

Notes:

- Microsoft Authenticator (and most phone apps) cannot export secrets, so existing enrolments can't be imported — re-enroll once as above.
- Unlocking starts a 6-hour session (like Bitwarden), so you don't retype the password on every open. The session survives popup closes but not a browser restart. The lock button ends it immediately.
- Keeping a 2FA secret next to the browser that holds the password weakens 2FA for that account. Fine for test accounts; think twice for real production admins.
- Each person has their own vault and master password. Never share or copy `vault.enc` or `vault.enc.session` — add accounts on your own machine.
- Fill only on the site you expect: check the address bar first, because a fake login page would receive the code too.

## Use on another PC

Your vault lives only on the PC where you created it. To use the same accounts on another PC, move them with an encrypted export file:

1. **On this PC:** popup → **Vault** → **Export / Import** (opens a tab) → **Export**. Type your master password again, choose an export passphrase (at least 12 characters, different from your master password), and click **Download export file**.
2. **Copy the file** (`dev-authenticator-export-YYYY-MM-DD.enc`) to the other PC any way you like: USB, email, chat. The file is encrypted (AES-256-GCM, scrypt-derived key) and contains no readable names, emails or secrets.
3. **On the other PC:** install the extension (see Setup), create its vault in the popup, then **Vault** → **Export / Import** → **Import**. Pick the file and type the export passphrase.
4. **Delete the export file** everywhere you copied it.

Import only adds accounts. Accounts already in the vault are skipped, and nothing is overwritten or deleted. Each PC keeps its own master password, so the two can differ.

## Troubleshooting

| Message | Fix |
|---|---|
| `Specified native messaging host not found` | Run `npm install && npm run setup`, then reopen the popup. |
| `Host … is not allowed` | Use localhost, or add the dev server to `host/allowed-hosts.json`. |
| `Not a valid MongoDB URL` | Use `mongodb://<host>:<port>/<database>`, with the database name. |
| `Authentication failed` | Check the user, password and `authSource=admin`. |
| `connect ECONNREFUSED` / timeout | Mongo isn't reachable on that host and port (not running, or you're off the office network/VPN). |
| `Wrong master password, or the vault file is corrupted` | Retype the password. Forgotten? Delete `~/.config/dev-authenticator/vault.enc` and re-add accounts. |
| `Wrong passphrase, or the export file is corrupted` | Retype the export passphrase exactly. If it still fails, export a fresh file on the other PC. |
| `No QR code found on this screen` | Make the QR fully visible in the current tab (no overlay), then scan again — or paste the setup key. |
| Code rejected at login | It expired. Wait for the next one; the ring shows the seconds left. |

## Remove

```bash
npm run uninstall-host
```

Then remove the extension from `chrome://extensions`.

## Tests

```bash
npm test
```
