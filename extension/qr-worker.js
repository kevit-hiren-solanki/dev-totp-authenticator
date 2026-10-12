/**
 * Decodes a QR code off the popup's main thread, so a slow decode can never freeze the popup.
 * Receives { data, width, height } (RGBA pixels, transferred) and replies with the QR text or null.
 */
importScripts('vendor/jsqr.js');

self.onmessage = (event) => {
  const { data, width, height } = event.data;
  const found = jsQR(new Uint8ClampedArray(data), width, height);
  self.postMessage(found?.data ?? null);
};
