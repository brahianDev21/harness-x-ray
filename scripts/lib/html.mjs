// HTML helpers shared by the HTML pages of the tool (the intake form now, the report later): the escaping of text,
// the hash of an inline style for a Content-Security-Policy, and the shared stylesheet. They are pure, except loadTheme,
// which reads one file of the harness, and they run nothing.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// The characters that are special in HTML text or in a double-quoted attribute, and the replacement of each.
const ENTITIES = new Map([
  ["&", "&amp;"],
  ["<", "&lt;"],
  [">", "&gt;"],
  ['"', "&quot;"],
  ["'", "&#39;"],
]);
// One pass over the text: the special characters, and the C0 controls (U+0000 to U+001F) except tab (U+0009) and line
// feed (U+000A). A control has no entity, so it becomes U+FFFD.
const TO_ESCAPE = /[&<>"'\u0000-\u0008\u000b-\u001f]/g;
const REPLACEMENT = "�";

/**
 * Escapes text for element content and for a double-quoted attribute value. Everything else is left as it is.
 * @param {string} text
 * @returns {string}
 * @throws {TypeError} If text is not a string.
 */
export function escapeHtml(text) {
  if (typeof text !== "string") throw new TypeError("escapeHtml takes a string");
  return text.replace(TO_ESCAPE, (char) => ENTITIES.get(char) ?? REPLACEMENT);
}

/**
 * The CSP source expression of an inline element whose text is `text`: the SHA-256 of its exact UTF-8 bytes, in base64,
 * quoted as the policy needs it.
 * @param {string} text The text between the tags of the element, exactly as it is written in the page.
 * @returns {string} For example 'sha256-...' with the single quotes.
 * @throws {TypeError} If text is not a string.
 */
export function cspHash(text) {
  if (typeof text !== "string") throw new TypeError("cspHash takes a string");
  return `'sha256-${crypto.createHash("sha256").update(text, "utf8").digest("base64")}'`;
}

/**
 * Reads the shared stylesheet, templates/theme.css: the color tokens for light and dark mode, and the base styles.
 * @param {string} harnessRoot The absolute folder of this repository.
 * @returns {string} The text of the file, exactly as it is on disk.
 * @throws {TypeError} If harnessRoot is not an absolute path.
 */
export function loadTheme(harnessRoot) {
  if (typeof harnessRoot !== "string" || !path.isAbsolute(harnessRoot)) {
    throw new TypeError("harnessRoot must be an absolute folder");
  }
  return fs.readFileSync(path.join(harnessRoot, "templates", "theme.css"), "utf8");
}
