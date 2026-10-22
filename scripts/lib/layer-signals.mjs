// The signals of the layer mapping: data/layer-signals.json, its validator and its loader. The validator holds the rules of the
// file. check-catalog.mjs reports the issues it returns, and layers.mjs loads the file through loadLayerSignals. The module
// imports nothing heavy (the JSON helper and the message quoting of layer-plan.mjs), so the catalog check does not load the
// scanner through it.
//
// The format of the file. validateLayerSignals documents each rule.
// - manifests: the file names that make a folder a unit, such as package.json or go.mod;
// - names: hint -> folder names, lower case. A folder name belongs to one hint only, and it is the name signal of a unit;
// - languages: extension -> language name, for the languages of a unit.

import fs from "node:fs";
import { isPlainObject } from "./json-out.mjs";
import { quoteText, visibleText } from "./layer-plan.mjs";

const SIGNALS_URL = new URL("../../data/layer-signals.json", import.meta.url);
const SIGNALS_FILE_NAME = "data/layer-signals.json";
const SIGNAL_FIELDS = ["manifests", "names", "languages"];
// A hint is a lower-case kebab-case id that starts with a letter: the rules of check-catalog and of the mapping together.
const HINT_ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
// A folder name is one lower-case segment of letters, digits, dots, underscores and hyphens.
const FOLDER_NAME = /^[a-z0-9][a-z0-9._-]*$/;
// An extension is a lower-case key with a leading dot, then letters, digits, "+" or "-" (".c++" is one).
const EXTENSION = /^\.[a-z0-9][a-z0-9+-]*$/;
// A control character, a line break included, in a name.
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;

let loadedSignals = null;

/**
 * Checks the parsed data/layer-signals.json. It reports every problem it finds and never throws on bad data. The rules:
 * - manifests: a non-empty list of distinct file names. A name is a non-empty string with no slash, backslash or control
 *   character, and it is neither "." nor "..".
 * - names: a non-empty object from a hint to a non-empty list of folder names. A hint is a lower-case kebab-case id that starts
 *   with a letter. A folder name is a lower-case string of letters, digits, dots, underscores and hyphens, neither "." nor "..",
 *   with no slash or backslash. A folder name is listed once across all hints.
 * - languages: a non-empty object from an extension to a non-empty string. An extension is a lower-case key with a leading
 *   dot, such as .ts or .c++.
 * @param {unknown} data The parsed file.
 * @returns {{ pointer: string, message: string }[]} pointer is a JSON pointer, and "" is the whole document. The list is in
 *   check order, and it is empty for a valid file.
 */
export function validateLayerSignals(data) {
  const issues = [];
  const report = (pointer, message) => issues.push({ pointer, message });
  if (!isPlainObject(data)) {
    report("", `must be an object with the fields ${SIGNAL_FIELDS.join(", ")}`);
    return issues;
  }
  for (const key of Object.keys(data)) {
    if (!SIGNAL_FIELDS.includes(key)) {
      report(visibleText(`/${escapePointer(key)}`), `unknown field; the fields are ${SIGNAL_FIELDS.join(", ")}`);
    }
  }
  for (const key of SIGNAL_FIELDS) {
    if (!Object.hasOwn(data, key)) report(`/${key}`, "missing required field");
  }
  checkManifests(data.manifests, report);
  checkNames(data.names, report);
  checkLanguages(data.languages, report);
  return issues;
}

function checkManifests(manifests, report) {
  if (manifests === undefined) return;
  if (!Array.isArray(manifests) || manifests.length === 0) {
    report("/manifests", "must be a non-empty list of file names");
    return;
  }
  manifests.forEach((name, index) => {
    const field = `/manifests/${index}`;
    if (!isNonEmptyString(name)) {
      report(field, "must be a non-empty string");
    } else if (/[/\\]/.test(name)) {
      report(field, `must be a file name with no slash or backslash, found ${quoteText(name)}`);
    } else if (name === "." || name === "..") {
      report(field, `must not be ${quoteText(name)}`);
    } else if (CONTROL_CHARACTER.test(name)) {
      report(field, `must not contain a control character, found ${quoteText(name)}`);
    } else if (manifests.indexOf(name) !== index) {
      report(field, `${quoteText(name)} is listed twice`);
    }
  });
}

function checkNames(names, report) {
  if (names === undefined) return;
  if (!isPlainObject(names) || Object.keys(names).length === 0) {
    report("/names", "must be a non-empty object from hints to lists of folder names");
    return;
  }
  const firstFieldOfFolder = new Map();
  for (const hint of Object.keys(names)) {
    const base = visibleText(`/names/${escapePointer(hint)}`);
    if (!HINT_ID.test(hint)) {
      report(base, `must be a lower-case kebab-case id that starts with a letter, such as frontend, found ${quoteText(hint)}`);
    }
    const folders = names[hint];
    if (!Array.isArray(folders) || folders.length === 0) {
      report(base, "must be a non-empty list of folder names");
      continue;
    }
    folders.forEach((folder, index) => {
      const field = `${base}/${index}`;
      const problem = folderNameProblem(folder);
      if (problem !== null) {
        report(field, problem);
      } else if (firstFieldOfFolder.has(folder)) {
        report(field, `${quoteText(folder)} is already listed at ${firstFieldOfFolder.get(folder)}`);
      } else {
        firstFieldOfFolder.set(folder, field);
      }
    });
  }
}

// Why a folder name is not valid, or null. A folder name is one path segment: not "." or "..", and no separator.
function folderNameProblem(folder) {
  if (!isNonEmptyString(folder)) return "must be a non-empty string";
  if (folder === "." || folder === "..") return `must not be ${quoteText(folder)}`;
  if (/[/\\]/.test(folder)) return `must be one folder name with no slash or backslash, found ${quoteText(folder)}`;
  if (folder !== folder.toLowerCase()) return `must be lower case, found ${quoteText(folder)}`;
  if (!FOLDER_NAME.test(folder)) {
    return `must use only letters, digits, dots, underscores and hyphens, found ${quoteText(folder)}`;
  }
  return null;
}

function checkLanguages(languages, report) {
  if (languages === undefined) return;
  if (!isPlainObject(languages) || Object.keys(languages).length === 0) {
    report("/languages", "must be a non-empty object from extensions to language names");
    return;
  }
  for (const extension of Object.keys(languages)) {
    const field = visibleText(`/languages/${escapePointer(extension)}`);
    if (!EXTENSION.test(extension)) {
      report(field, `must be a lower-case extension with a leading dot, such as .ts, found ${quoteText(extension)}`);
    }
    if (!isNonEmptyString(languages[extension])) report(field, "must be a non-empty string");
  }
}

// The JSON pointer part of one key: "~" and "/" are escaped as RFC 6901 says.
function escapePointer(key) {
  return String(key).replaceAll("~", "~0").replaceAll("/", "~1");
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * Validates and compiles the parsed data/layer-signals.json.
 * @param {unknown} data The parsed file.
 * @returns {{ manifests: Set<string>, hintOf: Map<string, string>, languageOf: Map<string, string> }}
 * @throws {Error} When validateLayerSignals reports an issue. The message names each issue on one line.
 */
export function layerSignalsOf(data) {
  const issues = validateLayerSignals(data);
  if (issues.length > 0) {
    const detail = issues.map((issue) => `${issue.pointer === "" ? "(root)" : issue.pointer}: ${issue.message}`);
    throw new Error(`${SIGNALS_FILE_NAME} is not valid: ${detail.join("; ")}`);
  }
  return compileSignals(data);
}

/**
 * The signal data of data/layer-signals.json, checked and compiled. The file is read and checked once per process.
 * @returns {{ manifests: Set<string>, hintOf: Map<string, string>, languageOf: Map<string, string> }}
 * @throws {Error} When the file is not valid (see layerSignalsOf).
 */
export function loadLayerSignals() {
  loadedSignals ??= layerSignalsOf(JSON.parse(fs.readFileSync(SIGNALS_URL, "utf8")));
  return loadedSignals;
}

function compileSignals(data) {
  const hintOf = new Map();
  for (const [hint, folders] of Object.entries(data.names)) {
    for (const folder of folders) hintOf.set(folder, hint);
  }
  return { manifests: new Set(data.manifests), hintOf, languageOf: new Map(Object.entries(data.languages)) };
}
