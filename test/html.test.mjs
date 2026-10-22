import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { cspHash, escapeHtml, loadTheme } from "../scripts/lib/html.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const THEME_FILE = path.join(HARNESS_ROOT, "templates", "theme.css");

// The hash the policy expects, computed here with node:crypto from the same bytes.
const expectedHash = (text) => `'sha256-${crypto.createHash("sha256").update(text, "utf8").digest("base64")}'`;

describe("escapeHtml", () => {
  test("markup in the text becomes inert text", () => {
    assert.equal(escapeHtml("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
    assert.equal(escapeHtml('"><img onerror=x>'), "&quot;&gt;&lt;img onerror=x&gt;");
    assert.equal(escapeHtml("</style>"), "&lt;/style&gt;");
    assert.equal(escapeHtml("<"), "&lt;");
    assert.equal(escapeHtml("</style>").includes("<"), false);
    assert.equal(escapeHtml('"><img onerror=x>').includes("<"), false);
  });

  test("a javascript: text has no markup to act on, so it is kept as text", () => {
    assert.equal(escapeHtml("javascript:alert(1)"), "javascript:alert(1)");
  });

  test("quotes and the ampersand are escaped, and an entity is not decoded twice", () => {
    assert.equal(escapeHtml(`'x' "y"`), "&#39;x&#39; &quot;y&quot;");
    assert.equal(escapeHtml("&amp;"), "&amp;amp;");
    assert.equal(escapeHtml("a & b"), "a &amp; b");
  });

  test("C0 controls other than tab and line feed become U+FFFD", () => {
    assert.equal(escapeHtml("\u0000a\u0001b\u001fc"), "�a�b�c");
    assert.equal(escapeHtml("\u0007\u000b\u000c\r"), "����");
  });

  test("tab, line feed and every other character are kept as they are", () => {
    assert.equal(escapeHtml("a\tb\nc"), "a\tb\nc");
    assert.equal(escapeHtml("\u0085\u007f ñ € 😀"), "\u0085\u007f ñ € 😀");
  });

  test("positive control: plain text is unchanged", () => {
    const plain = "Layer frontend, folder apps/web-extra, 3 files.";
    assert.equal(escapeHtml(plain), plain);
    assert.equal(escapeHtml(""), "");
  });

  test("a value that is not text is refused", () => {
    assert.throws(() => escapeHtml(3), TypeError);
    assert.throws(() => escapeHtml(null), TypeError);
  });
});

describe("cspHash", () => {
  test("is the SHA-256 of the exact UTF-8 bytes, in base64, quoted", () => {
    for (const text of ["body { margin: 0; }", "", "ñandú € 😀", "line\r\nend\n"]) {
      assert.equal(cspHash(text), expectedHash(text));
    }
  });

  test("has the value of the empty string, which is a known digest", () => {
    assert.equal(cspHash(""), "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='");
  });

  test("hashes UTF-8 bytes, not the text in another encoding", () => {
    const text = "ñ";
    const latin1 = `'sha256-${crypto.createHash("sha256").update(text, "latin1").digest("base64")}'`;
    assert.notEqual(cspHash(text), latin1);
  });

  test("a text that differs by one byte has another hash", () => {
    assert.notEqual(cspHash("p { margin: 0; }"), cspHash("p { margin: 0; } "));
  });

  test("a value that is not text is refused", () => {
    assert.throws(() => cspHash(undefined), TypeError);
  });
});

describe("loadTheme", () => {
  test("returns the text of templates/theme.css exactly", () => {
    assert.equal(loadTheme(HARNESS_ROOT), fs.readFileSync(THEME_FILE, "utf8"));
  });

  test("a relative folder is refused, and the absolute one is accepted", () => {
    assert.throws(() => loadTheme("templates"), TypeError);
    assert.equal(typeof loadTheme(HARNESS_ROOT), "string");
  });

  test("the light tokens are on :root and the dark tokens under the dark media query", () => {
    const css = loadTheme(HARNESS_ROOT);
    const tokens = [
      "--color-background",
      "--color-surface",
      "--color-text",
      "--color-muted",
      "--color-border",
      "--color-accent",
      "--color-accent-text",
      "--color-danger",
      "--color-focus",
      "--space-1",
      "--space-4",
      "--radius",
      "--font-sans",
    ];
    const darkStart = css.indexOf("@media (prefers-color-scheme: dark)");
    assert.ok(darkStart > 0, "a dark mode block");
    const light = css.slice(0, darkStart);
    const dark = css.slice(darkStart);
    assert.match(light, /:root \{/);
    assert.match(dark, /:root:not\(\[data-theme="light"\]\) \{/);
    for (const token of tokens) {
      assert.match(light, new RegExp(`${token}:`), `light value of ${token}`);
    }
    for (const token of tokens.filter((name) => name.startsWith("--color-"))) {
      assert.match(dark, new RegExp(`${token}:`), `dark value of ${token}`);
    }
  });

  test("the stylesheet loads nothing from outside: no URL, no import, no font file", () => {
    const css = loadTheme(HARNESS_ROOT);
    assert.equal(/url\s*\(/i.test(css), false, "url()");
    assert.equal(/@import/i.test(css), false, "@import");
    assert.equal(/@font-face/i.test(css), false, "@font-face");
    assert.equal(/https?:/i.test(css), false, "an http or https reference");
  });

  test("outside the token declarations, no color is written as a value", () => {
    const values = loadTheme(HARNESS_ROOT)
      .split("\n")
      .filter((line) => !line.trim().startsWith("--"))
      .join("\n");
    assert.equal(/#[0-9a-fA-F]{3,8}\b/.test(values), false, "a hex color");
    assert.equal(/\b(rgb|rgba|hsl|hsla)\(/i.test(values), false, "a functional color");
  });

  test("the base styles cover the elements of the forms and the muted text", () => {
    const css = loadTheme(HARNESS_ROOT);
    for (const selector of ["body", "h1", "p", "fieldset", "legend", "label", "button", ":focus-visible", ".muted"]) {
      assert.ok(css.includes(selector), `a rule for ${selector}`);
    }
    assert.ok(css.includes('input[type="radio"]'), "radio buttons");
    assert.ok(css.includes('input[type="checkbox"]'), "checkboxes");
  });
});
