// Recognizes secrets: the names of secret files, the values of known token formats (and the private key header), and generic
// assignments such as api_key = "...". The patterns are data in data/secret-patterns.json, read and checked once per process.
// Nothing here reads the target or runs anything.
//
// A matched value leaves the scanner only through mask(): a short prefix, an ellipsis and the last four characters. The
// redactor (redact.mjs) imports this module to mask token-shaped text in every string copied from the target, so this module
// imports nothing from the scanner, which keeps the import graph free of cycles.

import fs from "node:fs";
import { isPlainObject } from "./json-out.mjs";

const DATA_URL = new URL("../../data/secret-patterns.json", import.meta.url);
const TOP_LEVEL = new Set(["fileNames", "contentPatterns", "genericAssignment"]);
const FILE_NAME_FIELDS = new Set(["id", "pattern", "except"]);
const CONTENT_FIELDS = new Set(["id", "pattern", "prefix"]);
const GENERIC_FIELDS = new Set(["id", "keyPattern", "minValueLength", "placeholders"]);
const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
// The scheme that a header puts before a token ("Bearer <token>"). It is not part of the secret.
const SCHEME = "(?:Bearer|Basic)[ \\t]+";
const AUTH_SCHEME = new RegExp(`^${SCHEME}`, "i");
// A value in text ends at whitespace, a quote, a backtick, a comma or a semicolon.
const TEXT_VALUE = "([^\\s\"'\\x60,;]+)";
// A value with whitespace is text, not a token.
const WHITESPACE = /\s/;
const ELLIPSIS = "\u2026";
// The tail shown after the ellipsis, and how much of a value must be longer than the prefix before the tail is shown.
const TAIL_LENGTH = 4;
const MIN_HIDDEN = 8;

let loaded = null;

/**
 * The patterns of data/secret-patterns.json, compiled. The file is read and checked once per process. The objects are
 * shared: callers must not change them.
 * @returns {{ fileNames: Array<{ id: string, pattern: RegExp, except: RegExp | null }>,
 *   contentPatterns: Array<{ id: string, pattern: RegExp, prefix: string }>,
 *   generic: { id: string, keyPattern: RegExp, textPattern: RegExp, minValueLength: number, placeholders: RegExp[] } }}
 */
export function loadSecretPatterns() {
  loaded ??= compilePatterns(validateSecretData(JSON.parse(fs.readFileSync(DATA_URL, "utf8"))));
  return loaded;
}

/**
 * Checks the shape of the data and throws on the first problem, naming the entry. Every regular expression must compile, and
 * every id must be unique kebab-case text.
 * @param {unknown} data The parsed file.
 * @returns {object} The same data.
 */
export function validateSecretData(data) {
  const where = "secret-patterns";
  if (!isPlainObject(data)) throw new Error(`${where}: the data must be an object`);
  for (const key of Object.keys(data)) {
    if (!TOP_LEVEL.has(key)) throw new Error(`${where}: unknown field "${key}"`);
  }
  if (!Array.isArray(data.fileNames) || data.fileNames.length === 0) throw new Error(`${where}: fileNames must be a non-empty list`);
  if (!Array.isArray(data.contentPatterns) || data.contentPatterns.length === 0) {
    throw new Error(`${where}: contentPatterns must be a non-empty list`);
  }
  if (!isPlainObject(data.genericAssignment)) throw new Error(`${where}: genericAssignment must be an object`);

  const ids = new Set();
  const claim = (id, entry) => {
    if (typeof id !== "string" || !KEBAB_CASE.test(id)) throw new Error(`${entry}: id must be kebab-case`);
    if (ids.has(id)) throw new Error(`${entry}: duplicate id "${id}"`);
    ids.add(id);
  };
  data.fileNames.forEach((item, index) => {
    const entry = `${where}: fileNames[${index}]`;
    checkFields(item, FILE_NAME_FIELDS, entry);
    claim(item.id, entry);
    compile(item.pattern, "i", `${entry}.pattern`);
    if (item.except !== undefined) compile(item.except, "i", `${entry}.except`);
  });
  data.contentPatterns.forEach((item, index) => {
    const entry = `${where}: contentPatterns[${index}]`;
    checkFields(item, CONTENT_FIELDS, entry);
    claim(item.id, entry);
    compile(item.pattern, "g", `${entry}.pattern`);
    if (typeof item.prefix !== "string" || item.prefix === "") throw new Error(`${entry}: prefix must be a non-empty string`);
  });
  const generic = data.genericAssignment;
  checkFields(generic, GENERIC_FIELDS, `${where}: genericAssignment`);
  claim(generic.id, `${where}: genericAssignment`);
  compile(generic.keyPattern, "i", `${where}: genericAssignment.keyPattern`);
  if (!Number.isSafeInteger(generic.minValueLength) || generic.minValueLength < 1) {
    throw new Error(`${where}: genericAssignment.minValueLength must be a positive integer`);
  }
  if (!Array.isArray(generic.placeholders)) throw new Error(`${where}: genericAssignment.placeholders must be a list`);
  generic.placeholders.forEach((source, index) =>
    compile(source, "i", `${where}: genericAssignment.placeholders[${index}]`),
  );
  return data;
}

function checkFields(item, allowed, entry) {
  if (!isPlainObject(item)) throw new Error(`${entry} is not an object`);
  for (const key of Object.keys(item)) {
    if (!allowed.has(key)) throw new Error(`${entry} has the unknown field "${key}"`);
  }
}

function compile(source, flags, entry) {
  if (typeof source !== "string" || source === "") throw new Error(`${entry} must be a non-empty string`);
  try {
    return new RegExp(source, flags);
  } catch (error) {
    throw new Error(`${entry} is not a valid regular expression: ${error.message}`, { cause: error });
  }
}

function compilePatterns(data) {
  const generic = data.genericAssignment;
  // A key that names a secret, then a separator, then a value. The key may be part of a longer name (DB_PASSWORD).
  const textSource = [
    "(?<![A-Za-z0-9])([A-Za-z0-9_.-]*(?:",
    generic.keyPattern,
    ")[A-Za-z0-9_.-]*)[\"']?[ \\t]*[:=][ \\t]*[\"']?(?:",
    SCHEME,
    ")?",
    TEXT_VALUE,
  ].join("");
  return {
    fileNames: data.fileNames.map((item) => ({
      id: item.id,
      pattern: new RegExp(item.pattern, "i"),
      except: item.except === undefined ? null : new RegExp(item.except, "i"),
    })),
    contentPatterns: data.contentPatterns.map((item) => ({
      id: item.id,
      pattern: new RegExp(item.pattern, "g"),
      prefix: item.prefix,
    })),
    generic: {
      id: generic.id,
      keyPattern: new RegExp(generic.keyPattern, "i"),
      textPattern: new RegExp(textSource, "gi"),
      minValueLength: generic.minValueLength,
      placeholders: generic.placeholders.map((source) => new RegExp(source, "i")),
    },
  };
}

/**
 * The rule id of a secret file, judged by the base name of its path (at any depth), or null when the name is not
 * secret-shaped. Names are compared without regard to letter case, so that ".ENV" on a case-insensitive disk is covered.
 * @param {string} relPath A path relative to the target, with "/" or "\" separators.
 * @returns {string | null}
 */
export function secretFileKind(relPath) {
  const name = relPath.split(/[\\/]/).pop();
  for (const rule of loadSecretPatterns().fileNames) {
    if (rule.pattern.test(name) && (rule.except === null || !rule.except.test(name))) return rule.id;
  }
  return null;
}

/**
 * The matches of the specific patterns (token formats and the private key header) in a text, in order of position. A
 * pattern earlier in the data takes a span first, so a value is reported once, under the most specific pattern.
 * @param {string} text
 * @returns {Array<{ id: string, prefix: string, value: string, start: number, end: number }>}
 */
export function findSpecificSecrets(text) {
  const taken = [];
  const found = [];
  for (const rule of loadSecretPatterns().contentPatterns) {
    for (const match of text.matchAll(rule.pattern)) {
      const span = { start: match.index, end: match.index + match[0].length };
      if (taken.some((other) => overlaps(span, other))) continue;
      taken.push(span);
      found.push({ id: rule.id, prefix: rule.prefix, value: match[0], start: span.start, end: span.end });
    }
  }
  return found.sort((a, b) => a.start - b.start);
}

/**
 * The generic assignments in a text: a line that gives a secret-named key a value that looks like a secret. The result has
 * the same shape as findSpecificSecrets, with prefix null.
 * @param {string} text
 * @returns {Array<{ id: string, prefix: null, value: string, start: number, end: number }>}
 */
export function findGenericSecrets(text) {
  const { id, textPattern } = loadSecretPatterns().generic;
  const found = [];
  for (const match of text.matchAll(textPattern)) {
    const secret = genericSecretOf(match[1], match[2]);
    if (secret === null) continue;
    const start = match.index + match[0].length - match[2].length;
    found.push({ id, prefix: null, value: secret, start, end: start + match[2].length });
  }
  return found;
}

/**
 * The secret that a key-value pair names, or null. The key must name a secret, and the value (without an Authorization scheme)
 * must be long enough, a single word, not a reference to a variable ("${...}") and not a placeholder. It does not check
 * whether the value matches a specific pattern: callers decide that.
 * @param {string} key
 * @param {string} value
 * @returns {string | null}
 */
export function genericSecretOf(key, value) {
  const { keyPattern, minValueLength, placeholders } = loadSecretPatterns().generic;
  if (typeof key !== "string" || typeof value !== "string") return null;
  if (!keyPattern.test(key)) return null;
  const secret = value.trim().replace(AUTH_SCHEME, "");
  if (secret.length < minValueLength || WHITESPACE.test(secret) || secret.includes("${")) return null;
  return placeholders.some((placeholder) => placeholder.test(secret)) ? null : secret;
}

/**
 * Shows a secret without revealing it: its prefix, an ellipsis and its last four characters, for example "sk-ant-…3f9a". The
 * prefix is the literal prefix of the pattern that matched, or else the first two characters. A value too short to hide
 * anything shows no tail. A masked form never contains the value.
 * @param {string} value A non-empty secret.
 * @param {string | null} [prefix] The literal prefix of the matching pattern, or null.
 * @returns {string}
 */
export function mask(value, prefix = null) {
  if (typeof value !== "string" || value === "") throw new TypeError("mask needs a non-empty string");
  const head = prefix && value.startsWith(prefix) ? prefix : value.slice(0, 2);
  const shown =
    value.length < head.length + MIN_HIDDEN
      ? `${head}${ELLIPSIS}`
      : `${head}${ELLIPSIS}${value.slice(-TAIL_LENGTH)}`;
  return shown.includes(value) ? ELLIPSIS : shown;
}

/**
 * The text with every specific match replaced by its masked form. Used by the redactor for every string copied from the target.
 * @param {string} text
 * @returns {string}
 */
export function maskSpecificSecrets(text) {
  const found = findSpecificSecrets(text);
  if (found.length === 0) return text;
  let masked = "";
  let last = 0;
  for (const item of found) {
    masked += text.slice(last, item.start) + mask(item.value, item.prefix);
    last = item.end;
  }
  return masked + text.slice(last);
}

/**
 * Whether two spans of a text share a character.
 * @param {{ start: number, end: number }} a
 * @param {{ start: number, end: number }} b
 * @returns {boolean}
 */
export function overlaps(a, b) {
  return a.start < b.end && b.start < a.end;
}
