/**
 * Registers the native messaging host with every installed Chromium browser, so the
 * Dev Authenticator popup can start it. Re-run after moving this folder or changing Node.
 *
 * The database URL is set per person inside the extension popup, not here.
 *
 * Run via: npm run setup
 *          npm run uninstall-host
 */
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOST_NAME = 'com.vezly.dev_totp';

const root = dirname(fileURLToPath(import.meta.url));
const hostDir = join(root, 'host');
const launcherPath = join(hostDir, 'run-host.sh');

const BROWSER_DIRS = {
  linux: ['.config/google-chrome', '.config/chromium', '.config/BraveSoftware/Brave-Browser', '.config/microsoft-edge'],
  darwin: [
    'Library/Application Support/Google/Chrome',
    'Library/Application Support/Chromium',
    'Library/Application Support/BraveSoftware/Brave-Browser',
    'Library/Application Support/Microsoft Edge',
  ],
};

/**
 * Derives the extension ID Chrome assigns from the public key pinned in the manifest.
 * @returns the 32-character extension ID
 */
function getExtensionId() {
  const manifest = JSON.parse(readFileSync(join(root, 'extension', 'manifest.json'), 'utf8'));
  const hash = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex');
  return [...hash.slice(0, 32)].map((hex) => String.fromCharCode(97 + Number.parseInt(hex, 16))).join('');
}

/**
 * Finds the NativeMessagingHosts folder of each Chromium browser present on this machine.
 * @returns absolute folder paths, one per installed browser
 */
function getHostManifestDirs() {
  const dirs = BROWSER_DIRS[platform()];
  if (!dirs) {
    throw new Error(`Unsupported platform: ${platform()}`);
  }
  return dirs
    .map((dir) => join(homedir(), dir))
    .filter((dir) => existsSync(dir))
    .map((dir) => join(dir, 'NativeMessagingHosts'));
}

/**
 * Writes the launcher and a host manifest for each browser.
 * @returns nothing
 */
function install() {
  const manifestDirs = getHostManifestDirs();
  if (manifestDirs.length === 0) {
    throw new Error('No Chrome, Chromium, Brave or Edge profile folder found.');
  }

  // Chrome starts hosts with a minimal PATH, so pin the absolute Node binary used right now.
  writeFileSync(launcherPath, `#!/bin/sh\nexec '${process.execPath}' '${join(hostDir, 'host.mjs')}' "$@"\n`);
  chmodSync(launcherPath, 0o755);

  const extensionId = getExtensionId();
  const hostManifest = {
    name: HOST_NAME,
    description: 'Dev Authenticator native host',
    path: launcherPath,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${extensionId}/`],
  };

  for (const dir of manifestDirs) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${HOST_NAME}.json`), `${JSON.stringify(hostManifest, null, 2)}\n`);
    process.stdout.write(`Registered host in ${dir}\n`);
  }
  process.stdout.write(`\nExtension ID: ${extensionId}\n`);
  process.stdout.write(`Load "${join(root, 'extension')}" in chrome://extensions (Developer mode → Load unpacked).\n`);
}

/**
 * Removes the host manifest from every browser folder.
 * @returns nothing
 */
function uninstall() {
  for (const dir of getHostManifestDirs()) {
    const file = join(dir, `${HOST_NAME}.json`);
    if (existsSync(file)) {
      rmSync(file);
      process.stdout.write(`Removed ${file}\n`);
    }
  }
}

try {
  if (process.argv.includes('--uninstall')) {
    uninstall();
  } else {
    install();
  }
} catch (err) {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
}
