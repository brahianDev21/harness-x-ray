// Scan core: runs the measures of one target and merges what they return into one object. It reads
// the target only through safe-fs and safe-git, and it writes nothing. The caller decides where the
// result goes.
//
// A measure is { id, collect(ctx) }. collect returns a plain object with the sections it owns. Plain
// objects merge recursively, so two measures can share a branch of the tree. The lists in SHARED_LISTS
// are shared: every measure may add items to them. Any other value that two measures set at the same
// path is a programming error, and the scan fails.
//
// The core always writes context.alwaysLoaded: the components of the always-loaded budget and the
// items whose size is unknown. It sorts them, and it sets the total and the method. A measure never
// sets the total.

import fs from "node:fs";
import path from "node:path";
import { DEFAULT_MAX_BYTES, createTargetFs } from "./safe-fs.mjs";
import { listFiles } from "./safe-git.mjs";
import { isPlainObject, toStableJson } from "./json-out.mjs";
import { ESTIMATE_METHOD } from "./tokens.mjs";

/** Layout version of measurements.json. Change it only when an existing field changes meaning. */
export const SCHEMA_VERSION = 1;

// Warning sources that the core uses for the file system and for git. No measure may use them.
const RESERVED_SOURCES = new Set(["fs", "git"]);
// The lists that measures may add to, as JSON pointers.
const SHARED_LISTS = new Set([
  "/inventory",
  "/warnings",
  "/context/alwaysLoaded/byComponent",
  "/context/alwaysLoaded/unknownStatic",
]);

/**
 * Scans one target.
 * @param {object} options
 * @param {string} options.root Absolute path of an existing folder. The caller has validated it.
 * @param {Array<{ id: string, collect: (ctx: object) => object | Promise<object> }>} [options.measures]
 *   Run in this order. Each one returns a plain object with its sections.
 * @param {Date} [options.now] Time of the scan, written to meta.scannedAt.
 * @returns {Promise<object>} The measurements object, ready for toStableJson.
 * @throws {Error} If a measure fails, two measures set the same value, or a measure returns something malformed.
 */
export async function scan({ root, measures = [], now = new Date() }) {
  validateMeasures(measures);
  const fsView = createTargetFs(root);
  const listing = await listFiles(root);
  const ctx = Object.freeze({
    root,
    fs: fsView,
    files: listing.files,
    fileListSource: listing.fileListSource,
    commit: listing.commit,
    readText: createMemoizedReader(fsView),
    memory: new Map(),
  });

  const result = {
    schemaVersion: SCHEMA_VERSION,
    meta: { tool: readToolName(), scannedAt: now.toISOString() },
    target: {
      name: path.basename(root) || "root",
      git: { isRepo: listing.fileListSource === "git", head: listing.commit },
      fileListSource: listing.fileListSource,
      fileCount: listing.files.length,
    },
    inventory: [],
    warnings: [],
    context: {
      alwaysLoaded: { estTokensTotal: 0, estMethod: ESTIMATE_METHOD, byComponent: [], unknownStatic: [] },
    },
  };

  const owners = new Map();
  for (const measure of measures) {
    const section = await runMeasure(measure, ctx);
    mergeSection(result, section, measure.id, "", owners);
  }

  result.inventory.sort(compareInventory);
  finalizeAlwaysLoaded(result.context.alwaysLoaded);
  result.warnings = finalizeWarnings([
    ...result.warnings,
    ...listing.warnings.map((item) => toWarning(item, "git")),
    ...fsView.warnings().map((item) => toWarning(item, "fs")),
  ]);
  return result;
}

function readToolName() {
  const manifest = JSON.parse(fs.readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  return `${manifest.name}@${manifest.version}`;
}

function validateMeasures(measures) {
  if (!Array.isArray(measures)) throw new TypeError("measures must be an array");
  const ids = new Set();
  for (const measure of measures) {
    if (typeof measure?.id !== "string" || measure.id === "") {
      throw new TypeError("Every measure needs a non-empty string id");
    }
    if (RESERVED_SOURCES.has(measure.id)) throw new TypeError(`Measure id "${measure.id}" is reserved`);
    if (typeof measure.collect !== "function") throw new TypeError(`Measure "${measure.id}" needs a collect function`);
    if (ids.has(measure.id)) throw new TypeError(`Duplicate measure id "${measure.id}"`);
    ids.add(measure.id);
  }
}

async function runMeasure(measure, ctx) {
  let section;
  try {
    section = await measure.collect(ctx);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Measure "${measure.id}" failed: ${reason}`, { cause: error });
  }
  if (!isPlainObject(section)) throw new TypeError(`Measure "${measure.id}" must return a plain object`);
  return section;
}

// Merges the section of one measure into target. owner is the measure id. owners records which
// measure created each path, so that a collision can name it.
function mergeSection(target, section, owner, pointer, owners) {
  for (const key of Object.keys(section)) {
    const value = section[key];
    if (value === undefined) continue;
    const childPointer = `${pointer}/${key}`;
    if (SHARED_LISTS.has(childPointer)) {
      appendShared(target[key], childPointer, value, owner);
    } else if (!Object.hasOwn(target, key)) {
      owners.set(childPointer, owner);
      if (isPlainObject(value)) {
        const child = {};
        defineOwn(target, key, child);
        mergeSection(child, value, owner, childPointer, owners);
      } else {
        defineOwn(target, key, value);
      }
    } else if (isPlainObject(target[key]) && isPlainObject(value)) {
      mergeSection(target[key], value, owner, childPointer, owners);
    } else {
      const holder = owners.get(childPointer);
      const who = holder === undefined ? "the core" : `measure "${holder}"`;
      throw new Error(`Measure "${owner}" collides with ${who} at ${childPointer}`);
    }
  }
}

function appendShared(list, pointer, value, owner) {
  if (!Array.isArray(value)) throw new TypeError(`Measure "${owner}" must set ${pointer} to an array`);
  for (const item of value) {
    if (!isPlainObject(item)) throw new TypeError(`Measure "${owner}" added an item to ${pointer} that is not an object`);
    if (pointer === "/warnings") list.push(toWarning(item, owner));
    else if (pointer === "/context/alwaysLoaded/byComponent") list.push(checkComponent(item, list, owner));
    else list.push(item);
  }
}

// A component of the always-loaded budget. Two contributions with the same component are an error,
// so that each component is counted once.
function checkComponent(item, list, owner) {
  const { component, estTokens, items } = item;
  if (typeof component !== "string" || component === "") {
    throw new TypeError(`Measure "${owner}" added a budget component without a name`);
  }
  if (!Number.isSafeInteger(estTokens) || estTokens < 0) {
    throw new TypeError(`Measure "${owner}" gave component "${component}" an estTokens that is not a non-negative integer`);
  }
  if (!Array.isArray(items)) throw new TypeError(`Measure "${owner}" gave component "${component}" items that are not a list`);
  if (list.some((existing) => existing.component === component)) {
    throw new Error(`Measure "${owner}" adds component "${component}", which another contribution already adds`);
  }
  return item;
}

// Sorts the budget lists and sets the total as the sum of the components.
function finalizeAlwaysLoaded(alwaysLoaded) {
  alwaysLoaded.byComponent.sort((a, b) => compareText(a.component, b.component));
  alwaysLoaded.unknownStatic.sort((a, b) => compareText(toStableJson(a), toStableJson(b)));
  alwaysLoaded.estTokensTotal = alwaysLoaded.byComponent.reduce((sum, item) => sum + item.estTokens, 0);
}

function defineOwn(object, key, value) {
  Object.defineProperty(object, key, { value, enumerable: true, writable: true, configurable: true });
}

// The shape of every warning in the output: its source ("fs", "git" or a measure id), its path and
// its reason. detail is present only when the item has one.
function toWarning(item, source) {
  const { path: itemPath, reason, detail } = item;
  if (typeof itemPath !== "string" || typeof reason !== "string") {
    throw new TypeError(`A warning from "${source}" needs a string path and a string reason`);
  }
  if (detail !== undefined && typeof detail !== "string") {
    throw new TypeError(`A warning from "${source}" has a detail that is not a string`);
  }
  return detail === undefined ? { source, path: itemPath, reason } : { source, path: itemPath, reason, detail };
}

// Removes duplicates (same source, path, reason and detail) and sorts by path, reason, source and detail.
function finalizeWarnings(warnings) {
  const unique = new Map();
  for (const warning of warnings) {
    const key = JSON.stringify([warning.source, warning.path, warning.reason, warning.detail ?? null]);
    if (!unique.has(key)) unique.set(key, warning);
  }
  return [...unique.values()].sort(
    (a, b) =>
      compareText(a.path, b.path) ||
      compareText(a.reason, b.reason) ||
      compareText(a.source, b.source) ||
      compareText(a.detail ?? "", b.detail ?? ""),
  );
}

// Inventory items are sorted by path. Items with the same path are ordered by their serialized form,
// so the order never depends on which measure ran first.
function compareInventory(a, b) {
  return compareText(pathOf(a), pathOf(b)) || compareText(toStableJson(a), toStableJson(b));
}

function pathOf(item) {
  return typeof item.path === "string" ? item.path : "";
}

// readText for the measures. The same file and limit give the same result object, so a file that
// several measures read is read once. Paths that differ only by separators or "./" share an entry.
function createMemoizedReader(fsView) {
  const cache = new Map();
  return function readText(rel, options) {
    const maxBytes = options?.maxBytes ?? DEFAULT_MAX_BYTES;
    if (typeof rel !== "string") return fsView.readText(rel, { maxBytes });
    const key = JSON.stringify([memoKey(rel), maxBytes]);
    if (!cache.has(key)) cache.set(key, Object.freeze(fsView.readText(rel, { maxBytes })));
    return cache.get(key);
  };
}

function memoKey(rel) {
  const normalized = path.posix.normalize(rel.replaceAll("\\", "/"));
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
