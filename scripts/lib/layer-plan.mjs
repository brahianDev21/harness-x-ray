// The layer plan: <runDir>/layer-plan.json, which the agent writes after it groups the folders that <runDir>/layers.json
// lists into layers (frontend, backend, database...). Each layer is justified by the signals of the mapping. This module
// checks the plan against the layers. It never writes, and it runs nothing.
//
// The format. The top level is an object with exactly two keys: schemaVersion, which is 1, and layers, a non-empty list.
// A layer is { name, folders, reason, signals?, options? } and no other key.
// - name: a non-empty string of at most 80 characters, unique across the layers when case is ignored.
// - folders: a non-empty list of distinct strings. Each must be a folder of layers.json (an exact match). A folder of one
//   layer must not be a folder of another layer, nor lie inside one, nor contain one.
// - reason: a non-empty string of at most 500 characters: the justification, from the signals.
// - signals: optional, a list of distinct signal types (root, workspace, manifest, name, harness).
// - options: optional, a list of distinct folders: the sub-folders the person may pick inside the layer. Each must be a
//   folder of layers.json and must lie inside one of the layer's folders. It must neither be a folder of another layer nor
//   lie inside one.
// A folder lies inside another when it is the same, or below it split at "/"; "." holds every folder.
//
// Messages. Folder names come from the target and may hold newlines, quotes, backslashes or invisible characters. Every
// string in a message is shown with quoteText, and every pointer with visibleText, so no line can be forged.

import fs from "node:fs";
import path from "node:path";
import { isPlainObject } from "./json-out.mjs";

/** The fields of a layer plan. */
export const PLAN_FIELDS = Object.freeze(["schemaVersion", "layers"]);
/** The fields of one layer. name, folders and reason are required. */
export const LAYER_FIELDS = Object.freeze(["name", "folders", "reason", "signals", "options"]);
export const REQUIRED_LAYER_FIELDS = Object.freeze(["name", "folders", "reason"]);
/** The signal types a layer can cite. */
export const SIGNAL_TYPES = Object.freeze(["root", "workspace", "manifest", "name", "harness"]);
/** The longest name, in characters (code points). */
export const MAX_NAME_LENGTH = 80;
/** The longest reason, in characters (code points). */
export const MAX_REASON_LENGTH = 500;

const SCHEMA_VERSION = 1;
/** The name of the layer map in a run folder, written by map.mjs. */
export const LAYERS_FILE = "layers.json";
/** The name of the layer plan in a run folder, written by the agent. */
export const PLAN_FILE = "layer-plan.json";
const LAYERS_SHAPE = "an object with schemaVersion 1 and a folders list of strings";
// Characters that are invisible or that change how a line is laid out: controls, format characters (the right-to-left
// override U+202E, the zero-width joiner...), and line and paragraph separators.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/**
 * Quotes a string for a message. JSON.stringify quotes it, and the invisible characters are then escaped (see visibleText),
 * so the result is one line in which a newline, a quote or a bidirectional override shows as text.
 * @param {string} text
 * @returns {string}
 */
export function quoteText(text) {
  return visibleText(JSON.stringify(text));
}

/**
 * Replaces every invisible or line-breaking character with a \u escape: \u000a for a newline, \u202E for U+202E, and
 * \u{...} for a character above U+FFFF. Other text is unchanged.
 * @param {string} text
 * @returns {string}
 */
export function visibleText(text) {
  return text.replace(INVISIBLE, (char) => {
    const code = char.codePointAt(0);
    const hex = code.toString(16);
    return code > 0xffff ? `\\u{${hex}}` : `\\u${hex.padStart(4, "0")}`;
  });
}

/**
 * Checks a parsed layer plan against the parsed layers.json. It reports every problem it finds and never throws on bad
 * plan data.
 * @param {unknown} plan The parsed <runDir>/layer-plan.json.
 * @param {unknown} layers The parsed <runDir>/layers.json. Only schemaVersion and folders are read.
 * @returns {{ ok: boolean, errors: { pointer: string, message: string }[] }} pointer is a JSON pointer such as
 *   "/layers/1/folders/0", and "" is the whole document. ok is true when errors is empty. The list is in check order.
 * @throws {TypeError} When layers is not a layers.json: an object with schemaVersion 1 and a folders list of strings.
 */
export function validateLayerPlan(plan, layers) {
  const listed = listedFolders(layers);
  const errors = [];
  const report = (pointer, message) => errors.push({ pointer, message });
  if (!isPlainObject(plan)) {
    report("", `must be an object with the fields ${PLAN_FIELDS.join(" and ")}`);
  } else {
    checkFieldNames(plan, "", PLAN_FIELDS, PLAN_FIELDS, report);
    if (Object.hasOwn(plan, "schemaVersion") && plan.schemaVersion !== SCHEMA_VERSION) {
      report("/schemaVersion", `must be ${SCHEMA_VERSION}, found ${describe(plan.schemaVersion)}`);
    }
    if (Object.hasOwn(plan, "layers")) {
      if (!Array.isArray(plan.layers) || plan.layers.length === 0) {
        report("/layers", "must be a non-empty list of layers");
      } else {
        checkLayers(plan.layers, listed, report);
      }
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Reads <runDir>/layers.json and <runDir>/layer-plan.json with plain fs and validates the plan against the layers. A file
 * that is missing or is not valid JSON is an error in the result, not a throw. Nothing in the files runs.
 * @param {string} runDir Absolute path of the run folder.
 * @returns {{ ok: boolean, errors: { pointer: string, message: string }[] }}
 * @throws {TypeError} When runDir is not an absolute path.
 */
export function readLayerPlan(runDir) {
  const { ok, errors } = loadLayerPlan(runDir);
  return { ok, errors };
}

/**
 * The same check as readLayerPlan, and the parsed files too, for a caller that needs the folders of the plan and the target
 * that layers.json names (the scan command line does). plan and layers are the parsed files, or null when a file could not
 * be read or parsed. Only when ok is true have they passed the checks; otherwise they are data that the caller must not use
 * as a plan.
 * @param {string} runDir Absolute path of the run folder.
 * @returns {{ ok: boolean, errors: { pointer: string, message: string }[], plan: unknown, layers: unknown }}
 * @throws {TypeError} When runDir is not an absolute path.
 */
export function loadLayerPlan(runDir) {
  if (typeof runDir !== "string" || !path.isAbsolute(runDir)) throw new TypeError("runDir must be an absolute folder");
  const errors = [];
  const layers = readJsonFile(runDir, LAYERS_FILE, errors) ?? null;
  const plan = readJsonFile(runDir, PLAN_FILE, errors) ?? null;
  if (errors.length > 0) return { ok: false, errors, plan, layers };
  if (!hasLayersShape(layers)) {
    const error = { pointer: "", message: `${LAYERS_FILE} is not a layers.json: ${LAYERS_SHAPE}` };
    return { ok: false, errors: [error], plan, layers };
  }
  return { ...validateLayerPlan(plan, layers), plan, layers };
}

// The folders of layers.json as a set. A value of another shape is a caller's mistake, so it throws.
function listedFolders(layers) {
  if (!hasLayersShape(layers)) throw new TypeError(`layers must be the parsed layers.json: ${LAYERS_SHAPE}`);
  return new Set(layers.folders);
}

function hasLayersShape(layers) {
  return (
    isPlainObject(layers) &&
    layers.schemaVersion === SCHEMA_VERSION &&
    Array.isArray(layers.folders) &&
    layers.folders.every(isString)
  );
}

// Layers ----------------------------------------------------------------------------------------

// `listers` maps each folder that any layer lists to the indexes of those layers, in order, so its first entry is the first
// layer that lists it. `claims` lists every folder of layers.json that a layer lists, with the index of the layer, in layer
// order. `firstLayerOfName` maps a lower-case name to the first layer that has it.
function checkLayers(layers, listed, report) {
  const listers = new Map();
  const claims = [];
  layers.forEach((layer, index) => {
    for (const folder of new Set(stringFolders(layer))) {
      listers.set(folder, [...(listers.get(folder) ?? []), index]);
      if (listed.has(folder)) claims.push({ folder, index });
    }
  });
  const firstLayerOfName = new Map();
  layers.forEach((layer, index) => checkLayer(layer, index, { listed, listers, claims, firstLayerOfName, report }));
}

function checkLayer(layer, index, context) {
  const base = `/layers/${index}`;
  if (!isPlainObject(layer)) {
    context.report(base, "must be an object");
    return;
  }
  checkFieldNames(layer, base, LAYER_FIELDS, REQUIRED_LAYER_FIELDS, context.report);
  checkName(layer.name, base, index, context);
  checkFolders(layer.folders, base, index, context);
  checkReason(layer.reason, base, context.report);
  checkSignals(layer.signals, base, context.report);
  const own = stringFolders(layer).filter((folder) => context.listed.has(folder));
  checkOptions(layer.options, base, { ...context, own, index });
}

function checkName(name, base, index, { firstLayerOfName, report }) {
  const field = `${base}/name`;
  if (name === undefined) return;
  if (!isNonEmptyString(name)) {
    report(field, "must be a non-empty string");
    return;
  }
  if (Array.from(name).length > MAX_NAME_LENGTH) report(field, `must be at most ${MAX_NAME_LENGTH} characters`);
  const key = name.toLowerCase();
  if (firstLayerOfName.has(key)) {
    report(
      field,
      `must be unique across layers, ignoring case; ${quoteText(name)} is also the name of /layers/${firstLayerOfName.get(key)}`,
    );
  } else {
    firstLayerOfName.set(key, index);
  }
}

function checkFolders(folders, base, index, { listed, listers, claims, report }) {
  const field = `${base}/folders`;
  if (folders === undefined) return;
  if (!Array.isArray(folders) || folders.length === 0) {
    report(field, "must be a non-empty list of folders");
    return;
  }
  folders.forEach((folder, position) => {
    const at = `${field}/${position}`;
    if (!isString(folder)) {
      report(at, `must be a string, found ${describe(folder)}`);
    } else if (!listed.has(folder)) {
      report(at, `${quoteText(folder)} is not a folder of layers.json`);
    } else if (folders.indexOf(folder) !== position) {
      report(at, `${quoteText(folder)} is listed twice in this layer`);
    } else {
      // The first layer that lists the folder is the owner; a later layer that lists it too is reported here.
      const first = listers.get(folder)[0];
      if (first !== index) {
        report(at, `${quoteText(folder)} is also a folder of /layers/${first}`);
      } else {
        const overlap = overlapOfEarlier(folder, index, claims);
        if (overlap !== null) report(at, overlap);
      }
    }
  });
}

function checkReason(reason, base, report) {
  const field = `${base}/reason`;
  if (reason === undefined) return;
  if (!isNonEmptyString(reason)) {
    report(field, "must be a non-empty string");
  } else if (Array.from(reason).length > MAX_REASON_LENGTH) {
    report(field, `must be at most ${MAX_REASON_LENGTH} characters`);
  }
}

function checkSignals(signals, base, report) {
  const field = `${base}/signals`;
  if (signals === undefined) return;
  if (!Array.isArray(signals)) {
    report(field, "must be a list of signal types");
    return;
  }
  signals.forEach((signal, position) => {
    const at = `${field}/${position}`;
    if (!SIGNAL_TYPES.includes(signal)) {
      report(at, `must be one of ${SIGNAL_TYPES.join(", ")}, found ${describe(signal)}`);
    } else if (signals.indexOf(signal) !== position) {
      report(at, `${quoteText(signal)} is listed twice`);
    }
  });
}

// `own` is the folders of this layer that layers.json lists. An option must lie inside one of them, and it must neither be a
// folder of another layer nor lie inside one.
function checkOptions(options, base, { own, index, listed, listers, claims, report }) {
  const field = `${base}/options`;
  if (options === undefined) return;
  if (!Array.isArray(options)) {
    report(field, "must be a list of folders");
    return;
  }
  options.forEach((option, position) => {
    const at = `${field}/${position}`;
    if (!isString(option)) {
      report(at, `must be a string, found ${describe(option)}`);
    } else if (!listed.has(option)) {
      report(at, `${quoteText(option)} is not a folder of layers.json`);
    } else if (options.indexOf(option) !== position) {
      report(at, `${quoteText(option)} is listed twice in options`);
    } else if (!own.some((folder) => isInside(option, folder))) {
      report(at, `${quoteText(option)} is not inside a folder of this layer`);
    } else {
      const other = (listers.get(option) ?? []).find((owner) => owner !== index);
      const container = claims.find((claim) => claim.index !== index && claim.folder !== option && isInside(option, claim.folder));
      if (other !== undefined) {
        report(at, `${quoteText(option)} is also a folder of /layers/${other}`);
      } else if (container !== undefined) {
        report(at, `${quoteText(option)} is inside ${quoteText(container.folder)}, a folder of /layers/${container.index}`);
      }
    }
  });
}

// Whether a folder lies inside a container: the same folder, or a folder below it split at "/". "." holds every folder.
function isInside(folder, container) {
  return container === "." || folder === container || folder.startsWith(`${container}/`);
}

// The message for a folder that lies inside, or contains, a folder of an earlier layer, or null. A pair of layers is reported
// once, at the later layer. An equal folder is not an overlap: the exact check reports it.
function overlapOfEarlier(folder, index, claims) {
  for (const claim of claims) {
    if (claim.index >= index || claim.folder === folder) continue;
    if (isInside(folder, claim.folder)) {
      return `${quoteText(folder)} is inside ${quoteText(claim.folder)}, a folder of /layers/${claim.index}`;
    }
    if (isInside(claim.folder, folder)) {
      return `${quoteText(folder)} contains ${quoteText(claim.folder)}, a folder of /layers/${claim.index}`;
    }
  }
  return null;
}

// The entries of a layer's folders that are strings, in order. A layer that is not an object has none.
function stringFolders(layer) {
  return isPlainObject(layer) && Array.isArray(layer.folders) ? layer.folders.filter(isString) : [];
}

// Files ----------------------------------------------------------------------------------------

// Reads one JSON file of the run folder. A problem is pushed to errors and undefined is returned.
function readJsonFile(runDir, name, errors) {
  let text;
  try {
    text = fs.readFileSync(path.join(runDir, name), "utf8");
  } catch (error) {
    errors.push({ pointer: "", message: `${name}: cannot be read: ${error.code ?? "unknown error"}` });
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    errors.push({ pointer: "", message: `${name}: not valid JSON: ${visibleText(error.message)}` });
    return undefined;
  }
}

// Shared helpers --------------------------------------------------------------------------------

// Reports the fields that are not allowed and the ones that are required and missing.
function checkFieldNames(object, base, allowed, required, report) {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) report(pointerPart(base, key), `unknown field; the fields are ${allowed.join(", ")}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(object, key)) report(pointerPart(base, key), "missing required field");
  }
}

// The pointer of one key below base. "~" and "/" are escaped as RFC 6901 says, and invisible characters are escaped too.
function pointerPart(base, key) {
  return visibleText(`${base}/${String(key).replaceAll("~", "~0").replaceAll("/", "~1")}`);
}

// Describes a value for a message: a string quoted, a number or a boolean as it is, and the kind of anything else.
function describe(value) {
  if (typeof value === "string") return quoteText(value);
  if (value === null || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return "a list";
  if (isPlainObject(value)) return "an object";
  return typeof value;
}

function isString(value) {
  return typeof value === "string";
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}
