// The fixed visible text of the report. Every label of a language is in templates/labels.<language>.json, as a flat
// object of text values. A value may hold placeholders such as {count}; createLabeller fills them. The renderer reads
// labels only through the function that createLabeller returns, so a missing key or a missing placeholder value is an
// error, and a raw key or placeholder can never reach the report. The report builds its runs with createLabelParts,
// which has the same checks.

import fs from "node:fs";
import path from "node:path";

// A placeholder: a name of letters and digits inside braces.
const PLACEHOLDER = /\{([A-Za-z][A-Za-z0-9]*)\}/g;

/**
 * Reads the labels of one language from the harness folder.
 * @param {string} harnessRoot The folder that contains templates/.
 * @param {string} language "en" or "es".
 * @returns {Readonly<Record<string, string>>}
 * @throws {Error} If the file is missing, is not JSON, or does not hold non-empty text values.
 */
export function loadLabels(harnessRoot, language) {
  const file = path.join(harnessRoot, "templates", `labels.${language}.json`);
  return parseLabels(JSON.parse(fs.readFileSync(file, "utf8")), file);
}

/**
 * Checks the shape of a labels object: a plain object whose values are non-empty text.
 * @param {unknown} data The parsed JSON.
 * @param {string} source The file name, for the error message.
 * @returns {Readonly<Record<string, string>>}
 */
export function parseLabels(data, source = "labels") {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`${source}: must be a JSON object of text values`);
  }
  for (const [key, value] of Object.entries(data)) {
    if (typeof value !== "string" || value.trim() === "") throw new Error(`${source}: "${key}" must be non-empty text`);
  }
  return Object.freeze({ ...data });
}

/**
 * The placeholder names of a label text, sorted.
 * @param {string} text
 * @returns {string[]}
 */
export function placeholdersOf(text) {
  return [...new Set([...text.matchAll(PLACEHOLDER)].map((match) => match[1]))].sort();
}

/**
 * Creates parts(key, values): the text of a label split at its placeholders, as a list. A fixed text is a string, and a
 * placeholder is its value exactly as it was given, so the caller decides what the value becomes. A missing key or
 * value is an error.
 * @param {Readonly<Record<string, string>>} labels
 * @returns {(key: string, values?: Record<string, unknown>) => unknown[]}
 */
export function createLabelParts(labels) {
  return function parts(key, values = {}) {
    if (!Object.hasOwn(labels, key)) throw new Error(`the labels have no text for "${key}"`);
    const text = labels[key];
    const pieces = [];
    let last = 0;
    for (const match of text.matchAll(PLACEHOLDER)) {
      const name = match[1];
      if (!Object.hasOwn(values, name)) throw new Error(`the label "${key}" needs a value for {${name}}`);
      if (match.index > last) pieces.push(text.slice(last, match.index));
      pieces.push(values[name]);
      last = match.index + match[0].length;
    }
    if (last < text.length) pieces.push(text.slice(last));
    return pieces;
  };
}

/**
 * Creates t(key, values): the text of a label with its placeholders filled.
 * @param {Readonly<Record<string, string>>} labels
 * @returns {(key: string, values?: Record<string, string>) => string}
 */
export function createLabeller(labels) {
  const parts = createLabelParts(labels);
  return function t(key, values = {}) {
    return parts(key, values).map(String).join("");
  };
}
