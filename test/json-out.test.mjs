import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { toStableJson, writeStableJson } from "../scripts/lib/json-out.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

test("toStableJson sorts keys at every depth, in code-unit order", () => {
  const value = { zeta: { b: 1, a: [{ y: true, x: null }] }, alpha: "a", B: 2 };
  const expected = [
    "{",
    '  "B": 2,',
    '  "alpha": "a",',
    '  "zeta": {',
    '    "a": [',
    "      {",
    '        "x": null,',
    '        "y": true',
    "      }",
    "    ],",
    '    "b": 1',
    "  }",
    "}",
    "",
  ].join("\n");
  assert.equal(toStableJson(value), expected);
});

test("toStableJson sorts integer-like keys as text, not as numbers", () => {
  assert.equal(toStableJson({ 9: "b", 10: "a", x: 1 }), '{\n  "10": "a",\n  "9": "b",\n  "x": 1\n}\n');
});

test("toStableJson uses two spaces and one final line feed", () => {
  const text = toStableJson({ a: [1, "two", false, null, { b: [], c: {} }], d: 'quote " and \n newline' });
  assert.equal(text.endsWith("}\n"), true);
  assert.equal(text.endsWith("\n\n"), false);
  assert.equal(text.includes("\t"), false);
  assert.equal(text, JSON.stringify(JSON.parse(text), sortedReplacer, 2) + "\n");
  assert.match(text, /^\{\n  "a": \[\n    1,\n/);
});

test("toStableJson matches JSON.stringify for data whose keys are already sorted", () => {
  const sorted = { a: [1, "two", false, null, { b: [], c: {} }], d: "café \"quoted\"\n" };
  assert.equal(toStableJson(sorted), JSON.stringify(sorted, null, 2) + "\n");
});

test("toStableJson keeps the order of arrays", () => {
  assert.equal(toStableJson([3, 1, 2]), "[\n  3,\n  1,\n  2\n]\n");
  assert.equal(toStableJson({ list: [{ path: "b" }, { path: "a" }] }), '{\n  "list": [\n    {\n      "path": "b"\n    },\n    {\n      "path": "a"\n    }\n  ]\n}\n');
});

test("toStableJson writes empty objects and arrays on one line, and leaves out undefined properties", () => {
  assert.equal(toStableJson({}), "{}\n");
  assert.equal(toStableJson([]), "[]\n");
  assert.equal(toStableJson({ a: {}, b: [], c: undefined }), '{\n  "a": {},\n  "b": []\n}\n');
  assert.equal(toStableJson({ a: undefined, b: 1 }), '{\n  "b": 1\n}\n');
});

test("toStableJson refuses values that JSON cannot represent", () => {
  const sparse = [1];
  sparse[3] = 4;
  const refused = {
    "a NaN": Number.NaN,
    "an Infinity": Number.POSITIVE_INFINITY,
    "a function": () => 1,
    "a symbol": Symbol("x"),
    "a bigint": 10n,
    "a Date": new Date(0),
    "a Map": new Map(),
    "an array with undefined": [undefined],
    "a sparse array": sparse,
  };
  for (const [name, value] of Object.entries(refused)) {
    assert.throws(() => toStableJson({ nested: { value } }), TypeError, `should refuse ${name}`);
  }
  assert.throws(() => toStableJson(undefined), TypeError, "should refuse undefined at the top level");
});

test("writeStableJson writes the same text as toStableJson", (t) => {
  const fixture = makeFixture();
  t.after(fixture.cleanup);
  const file = path.join(fixture.root, "measurements.json");
  const value = { b: { d: 1, c: [2] }, a: "x" };

  writeStableJson(file, value);

  assert.equal(fs.readFileSync(file, "utf8"), toStableJson(value));
});

// Reorders keys the way toStableJson does, so the round trip through JSON.parse can be compared.
function sortedReplacer(_key, value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]]));
}
