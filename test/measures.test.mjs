import assert from "node:assert/strict";
import { test } from "node:test";
import { measuresFor } from "../scripts/lib/measures.mjs";

// The list of measures that scan.mjs and ci.mjs share. The goldens and snapshots check what the measures write; these tests check
// the list itself: its ids, their order, and what each flag adds or changes.
const STANDARD_IDS = [
  "claude-config",
  "memory",
  "agent-harness",
  "references",
  "verification",
  "destructive-commands",
  "secrets",
  "injection",
  "structure",
  "duplication",
];

function idsOf(options) {
  return measuresFor(options).map((measure) => measure.id);
}

test("measures: the standard list runs the measures in the order the scan has always used", () => {
  assert.deepEqual(idsOf({ userLayer: false, ancestors: false, depth: "standard" }), STANDARD_IDS);
});

test("measures: quick and deep make the same measures, with the same ids in the same order", () => {
  assert.deepEqual(idsOf({ userLayer: false, ancestors: false, depth: "quick" }), STANDARD_IDS);
  assert.deepEqual(idsOf({ userLayer: false, ancestors: false, depth: "deep" }), STANDARD_IDS);
});

test("measures: the user layer runs right after the project configuration, and only with its flag", () => {
  const ids = idsOf({ userLayer: true, ancestors: false, depth: "standard" });
  assert.deepEqual(ids.slice(0, 2), ["claude-config", "user-layer"]);
  assert.equal(ids.length, STANDARD_IDS.length + 1);
  assert.equal(idsOf({ userLayer: false, ancestors: false, depth: "standard" }).includes("user-layer"), false);
});

test("measures: a flag of the parent folders keeps the memory measure in its place", () => {
  assert.deepEqual(idsOf({ userLayer: false, ancestors: true, depth: "standard" }), STANDARD_IDS);
});
