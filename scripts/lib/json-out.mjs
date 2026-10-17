// Deterministic JSON output. Object keys are written in code-unit order at every depth, so the same
// data always gives the same bytes, whatever order the producer built it in. Arrays keep their
// order: the producer sorts them.
//
// The format is JSON.stringify(value, null, 2) with sorted keys and a final line feed. A value that
// JSON cannot represent (NaN, Infinity, functions, symbols, bigints, Dates, Maps, holes or undefined
// inside arrays) throws, so it cannot silently change the file. A property whose value is undefined
// is left out, as JSON.stringify does.

import fs from "node:fs";

/**
 * Serializes data as JSON with sorted keys, two-space indentation and a final line feed.
 * @param {unknown} value Null, booleans, finite numbers, strings, arrays, and objects whose
 *   prototype is Object.prototype or null.
 * @returns {string}
 * @throws {TypeError} If the value contains something JSON cannot represent.
 */
export function toStableJson(value) {
  return `${encode(value, 0, "")}\n`;
}

/**
 * Writes toStableJson(value) to a file as UTF-8. The folder must already exist.
 * @param {string} filePath
 * @param {unknown} value
 */
export function writeStableJson(filePath, value) {
  fs.writeFileSync(filePath, toStableJson(value), "utf8");
}

/** True for objects made by literals, JSON.parse or Object.create(null). */
export function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// pointer is the JSON pointer of the value. It is used only in error messages.
function encode(value, depth, pointer) {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (value === null) return "null";
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return encodeArray(value, depth, pointer);
  if (isPlainObject(value)) return encodeObject(value, depth, pointer);
  throw unsupported(pointer, value);
}

function encodeArray(items, depth, pointer) {
  if (items.length === 0) return "[]";
  const inner = indent(depth + 1);
  // Array.from reads holes as undefined, so a hole is reported instead of written as null.
  const lines = Array.from(items, (item, index) => `${inner}${encode(item, depth + 1, `${pointer}/${index}`)}`);
  return `[\n${lines.join(",\n")}\n${indent(depth)}]`;
}

function encodeObject(object, depth, pointer) {
  const keys = Object.keys(object)
    .filter((key) => object[key] !== undefined)
    .sort(compareText);
  if (keys.length === 0) return "{}";
  const inner = indent(depth + 1);
  const lines = keys.map(
    (key) => `${inner}${JSON.stringify(key)}: ${encode(object[key], depth + 1, `${pointer}/${key}`)}`,
  );
  return `{\n${lines.join(",\n")}\n${indent(depth)}}`;
}

function unsupported(pointer, value) {
  const where = pointer === "" ? "the top-level value" : pointer;
  const reason = typeof value === "number" ? "not a finite number" : "not plain data";
  return new TypeError(`Cannot write ${where} as JSON: ${reason}`);
}

function indent(depth) {
  return "  ".repeat(depth);
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
