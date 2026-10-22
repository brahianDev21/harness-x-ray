// Compares two scans of one harness: the measurements.json and findings.json of each run. It says which findings were
// resolved, which are new, which changed their impact and which stayed the same, and it warns when the two runs differ in
// something other than their findings: the target, the scope, the depth, the rule catalog or the schema. The module is pure.
// It reads no file and no target; the caller reads the two runs and writes the result (compare.mjs). The shape of the result
// is described in schemas/comparison.schema.json.
//
// Input. checkRunInputs checks that each file is an input of this tool, and throws a UsageError when it is not. It is not
// the validator (findings-validate.mjs), which also reads the target: here only the fields that the comparison uses are
// checked, and the form of each evidence path, as the validator checks it, without reading any file. A message names the
// run, the field and an index, and never a value of the file, because a value may come from a target.
//
// Units. A run has two kinds of unit, and both are paired in the same way.
// - Measured units are all the entries of measurements.measuredFindings, cited by findings.json or not. The key of a unit is
//   (rule, measurementRef, trigger), where trigger is the name of the first trigger whose measurementRef equals the finding's
//   measurementRef, or null when none does.
// - Judgment units are the findings of findings.json with kind judgment. The key is (rule, the sorted list of the distinct
//   files of its evidence). Line numbers are not part of the key, so a finding whose lines moved still pairs.
//
// Pairing. Pass 1 pairs a unit of A with a unit of B that has the same key. Pass 2 pairs the measured units that are still
// left over by (rule, measurementRef), so a trigger whose name changes with the level, such as always-loaded-total-medium and
// always-loaded-total-high, is still one finding. Inside a key, the units of A and of B are sorted by the number of their id
// (mf-2 before mf-10) or by their index, and paired in turn: the first of A with the first of B, and so on. A unit of A with
// no partner is resolved; a unit of B with no partner is new. A pair is same when the impacts are equal, and impact-changed
// when they are not. The key of a pair is the key of B.
//
// Order. Items are sorted by class (CLASSES), then axis (AXES), then rule, then kind (measured first), then key (measured:
// measurementRef, then trigger with null first; judgment: its files joined with a line feed), then the number of the id or
// index of B (of A when B is null). Texts are compared by code units, never with localeCompare, so the result does not depend
// on the locale or on the order of the keys of the input objects.
//
// Warnings. At most one per code, in WARNING_CODES order. target-changed names the two targets, never their paths. Each
// warning carries the two values that differ.

import { DEFAULT_DEPTH, DEPTHS } from "./scanner.mjs";
import {
  AXES,
  DEFAULT_LANGUAGE,
  EVIDENCE_LAYERS,
  IMPACTS,
  KINDS,
  LANGUAGES,
  LAYER_PREFIX,
  pathProblem,
} from "./findings-validate.mjs";
import { isPlainObject } from "./json-out.mjs";
import { missingField } from "./report.mjs";
import { UsageError } from "./target.mjs";

/** Layout version of the comparison object. Change it only when an existing field changes meaning. */
export const COMPARISON_SCHEMA_VERSION = 1;
/** The classes of an item, in the order the items are listed. */
export const CLASSES = Object.freeze(["resolved", "new", "impact-changed", "same"]);
/** The codes of the warnings, in the order they are listed. A code appears at most once. */
export const WARNING_CODES = Object.freeze([
  "target-changed",
  "scope-changed",
  "depth-changed",
  "catalog-changed",
  "catalog-unknown",
  "schema-changed",
]);

// A rule id as findings.schema.json writes it, and the id of a measured finding: mf- and a number without leading zeros.
const RULE_ID = /^(RUL|CTX|SEC|VER|STR|COD)-\d{2}$/;
const MEASURED_ID = /^mf-[1-9][0-9]*$/;
const CATALOG_SHA256 = /^[0-9a-f]{12}$/;
// A commit as the schema writes it: the full object name in lower-case hex, of 40 or 64 digits.
const COMMIT = /^([0-9a-f]{40}|[0-9a-f]{64})$/;
// An ISO 8601 time in UTC, in the form toISOString writes it, with or without milliseconds.
const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

/**
 * Checks that the parsed files of one run are inputs of this tool. It returns nothing: it throws when they are not.
 * @param {{ measurements: unknown, findings: unknown }} run The parsed measurements.json and findings.json of the run.
 * @param {string} label The name of the run in the messages: "A" or "B".
 * @throws {UsageError} With a message that starts with "run <label>: " and names the field to fix. It never quotes a value of the file.
 */
export function checkRunInputs({ measurements, findings }, label) {
  const fail = (message) => {
    throw new UsageError(`run ${label}: ${message}`);
  };
  const measuredIds = checkMeasurements(measurements, fail);
  checkFindings(findings, measuredIds, fail);
}

/**
 * Compares two runs.
 * @param {object} options
 * @param {{ name: string, measurements: unknown, findings: unknown }} options.a The first run. name is the folder name of the run.
 * @param {{ name: string, measurements: unknown, findings: unknown }} options.b The second run, the one whose language is used.
 * @returns {object} The comparison, as schemas/comparison.schema.json describes it. The caller writes it with writeStableJson.
 * @throws {UsageError} If a run is not an input of this tool (checkRunInputs).
 * @throws {TypeError} If a run has no name as text.
 */
export function compareRuns({ a, b }) {
  for (const [run, label] of [[a, "A"], [b, "B"]]) {
    if (!isPlainObject(run) || !isText(run.name)) throw new TypeError(`run ${label} needs a name as text`);
    checkRunInputs(run, label);
  }
  const records = pairUnits(unitsOf(a), unitsOf(b)).sort(compareRecords);
  const counts = { resolved: 0, new: 0, "impact-changed": 0, same: 0 };
  for (const record of records) counts[record.item.class] += 1;
  const runs = { a: runOf(a), b: runOf(b) };
  return {
    schemaVersion: COMPARISON_SCHEMA_VERSION,
    language: b.findings.language ?? DEFAULT_LANGUAGE,
    runs,
    warnings: warningsOf(a, b, runs),
    counts,
    items: records.map((record) => record.item),
  };
}

// Input checks ------------------------------------------------------------------------------------

// The checks of measurements.json. It returns the ids of its measured findings.
function checkMeasurements(measurements, fail) {
  if (!isPlainObject(measurements)) fail("measurements.json must hold a JSON object");
  const missing = missingField(measurements);
  if (missing !== null) fail(`measurements.json has no field ${missing}, so it is not a scan of this tool`);
  if (!Number.isSafeInteger(measurements.schemaVersion)) fail("measurements.json needs schemaVersion as a whole number");
  if (measurements.depth !== undefined && !DEPTHS.includes(measurements.depth)) {
    fail(`measurements.json depth must be ${DEPTHS.join(", ")}, or absent`);
  }
  const { meta, target, scope } = measurements;
  if (!isPlainObject(meta)) fail("measurements.json meta must be an object");
  if (!isUtcTime(meta.scannedAt)) {
    fail("measurements.json meta.scannedAt must be an ISO 8601 time in UTC, such as 2026-10-17T12:00:00.000Z");
  }
  if (!isText(meta.targetRoot)) fail("measurements.json meta.targetRoot must be text");
  if (!isPlainObject(target) || !isText(target.name)) fail("measurements.json target needs name as text");
  if (!isPlainObject(target.git)) fail("measurements.json target.git must be an object");
  if (!(target.git.head === null || (isText(target.git.head) && COMMIT.test(target.git.head)))) {
    fail("measurements.json target.git.head must be null, or 40 or 64 lowercase hex digits");
  }
  if (scope !== undefined) checkScope(scope, fail);
  if (meta.catalog !== undefined && !isCatalog(meta.catalog)) {
    fail("measurements.json meta.catalog needs count as a whole number from 0 and sha256 as 12 lowercase hex digits");
  }
  if (!Array.isArray(measurements.measuredFindings)) fail("measurements.json measuredFindings must be a list");
  const ids = new Set();
  measurements.measuredFindings.forEach((item, index) => checkMeasuredFinding(item, index, ids, fail));
  return ids;
}

// The scope of measurements.json: a plain object with the folders as a list. Each folder must be text, and the message names its index.
function checkScope(scope, fail) {
  if (!isPlainObject(scope) || !Array.isArray(scope.folders)) fail("measurements.json scope needs folders as a list, or no scope");
  scope.folders.forEach((folder, position) => {
    if (!isText(folder)) fail(`measurements.json scope.folders[${position}] must be text`);
  });
}

function checkMeasuredFinding(item, index, ids, fail) {
  const at = `measuredFindings[${index}]`;
  if (!isPlainObject(item)) fail(`${at} must be an object`);
  if (!isText(item.id) || !MEASURED_ID.test(item.id)) fail(`${at}.id must be mf- followed by a number without leading zeros`);
  if (ids.has(item.id)) fail(`${at}.id repeats the id of an earlier measured finding`);
  ids.add(item.id);
  if (!isText(item.rule) || !RULE_ID.test(item.rule)) fail(`${at}.rule must be a rule id, such as CTX-01`);
  if (!AXES.includes(item.axis)) fail(`${at}.axis must be one of ${AXES.join(", ")}`);
  if (!IMPACTS.includes(item.impact)) fail(`${at}.impact must be one of ${IMPACTS.join(", ")}`);
  if (!isText(item.measurementRef)) fail(`${at}.measurementRef must be text`);
  if (!Array.isArray(item.triggers) || item.triggers.length === 0) fail(`${at}.triggers must be a non-empty list`);
  item.triggers.forEach((trigger, position) => {
    if (!isPlainObject(trigger) || !isText(trigger.trigger) || !IMPACTS.includes(trigger.impact) || !isText(trigger.measurementRef)) {
      fail(`${at}.triggers[${position}] needs trigger and measurementRef as text, and impact as one of ${IMPACTS.join(", ")}`);
    }
  });
}

// The checks of findings.json. measuredIds are the ids of the measured findings of the same run.
function checkFindings(findings, measuredIds, fail) {
  if (!isPlainObject(findings)) fail("findings.json must hold a JSON object");
  if (findings.language !== undefined && !LANGUAGES.includes(findings.language)) {
    fail(`findings.json language must be ${LANGUAGES.join(" or ")}, or absent`);
  }
  if (!Array.isArray(findings.findings)) fail("findings.json needs a findings list");
  findings.findings.forEach((item, index) => checkFinding(item, index, measuredIds, fail));
}

function checkFinding(item, index, measuredIds, fail) {
  const at = `findings[${index}]`;
  if (!isPlainObject(item)) fail(`${at} must be an object`);
  if (!isText(item.rule) || !RULE_ID.test(item.rule)) fail(`${at}.rule must be a rule id, such as CTX-01`);
  if (!AXES.includes(item.axis)) fail(`${at}.axis must be one of ${AXES.join(", ")}`);
  if (!KINDS.includes(item.kind)) fail(`${at}.kind must be ${KINDS.join(" or ")}`);
  if (!IMPACTS.includes(item.impact)) fail(`${at}.impact must be one of ${IMPACTS.join(", ")}`);
  if (!isText(item.summary)) fail(`${at}.summary must be text`);
  if (!Array.isArray(item.evidence)) fail(`${at}.evidence must be a list`);
  item.evidence.forEach((entry, position) => checkEvidence(entry, `${at}.evidence[${position}]`, fail));
  if (item.kind === "measured" && !(isText(item.measuredFindingId) && measuredIds.has(item.measuredFindingId))) {
    fail(`${at}.measuredFindingId must name a measured finding of measurements.json`);
  }
}

function checkEvidence(entry, at, fail) {
  if (!isPlainObject(entry) || !isText(entry.file)) fail(`${at} must be an object with file as text`);
  for (const name of ["line", "endLine"]) {
    if (entry[name] !== undefined && !isLine(entry[name])) fail(`${at}.${name} must be a whole number from 1`);
  }
  checkEvidencePath(entry, at, fail);
}

// The form of the file of an evidence entry, checked as findings-validate.mjs checks it; nothing is read. Without a layer, the
// file is a path of the target. With a layer, it is a file outside the target, which starts with the prefix of its layer.
function checkEvidencePath(entry, at, fail) {
  if (entry.layer === undefined) {
    const problem = pathProblem(entry.file);
    if (problem !== null) fail(`${at}.file ${problem}`);
    return;
  }
  if (!EVIDENCE_LAYERS.includes(entry.layer)) fail(`${at}.layer must be one of ${EVIDENCE_LAYERS.join(", ")}`);
  const prefix = LAYER_PREFIX[entry.layer];
  if (!entry.file.startsWith(prefix)) fail(`${at}.file with layer ${entry.layer} must start with ${prefix}`);
}

// Units ------------------------------------------------------------------------------------------

// The units of one run: all its measured units, and its judgment units, each with its key and its side.
function unitsOf({ measurements, findings }) {
  const cited = citationsOf(findings);
  const measured = measurements.measuredFindings.map((item) => measuredUnit(item, cited));
  const judgment = [];
  findings.findings.forEach((item, index) => {
    if (item.kind === "judgment") judgment.push(judgmentUnit(item, index));
  });
  return { measured, judgment };
}

// The measured findings that findings.json cites, by id, with the summary of the first citing finding by index.
function citationsOf(findings) {
  const cited = new Map();
  for (const item of findings.findings) {
    if (item.kind === "measured" && !cited.has(item.measuredFindingId)) cited.set(item.measuredFindingId, item.summary);
  }
  return cited;
}

// A measured unit: its key, its order (the digits of its id) and its side as the contract describes it.
function measuredUnit(item, cited) {
  const trigger = item.triggers.find((entry) => entry.measurementRef === item.measurementRef)?.trigger ?? null;
  const isCited = cited.has(item.id);
  return {
    kind: "measured",
    rule: item.rule,
    axis: item.axis,
    order: item.id.slice("mf-".length),
    measurementRef: item.measurementRef,
    trigger,
    side: {
      id: item.id,
      impact: item.impact,
      triggers: item.triggers.map((entry) => ({
        trigger: entry.trigger,
        impact: entry.impact,
        measurementRef: entry.measurementRef,
      })),
      cited: isCited,
      summary: isCited ? cited.get(item.id) : null,
    },
  };
}

// A judgment unit: a finding of findings.json with kind judgment, keyed by the distinct files of its evidence.
function judgmentUnit(item, index) {
  const evidence = item.evidence.map((entry) => evidenceOf(entry));
  return {
    kind: "judgment",
    rule: item.rule,
    axis: item.axis,
    order: String(index),
    files: [...new Set(evidence.map((entry) => entry.file))].sort(compareText),
    side: { index, impact: item.impact, summary: item.summary, evidence },
  };
}

// An evidence entry as the comparison keeps it: its file, and its lines and layer when given. The quote is text of the target,
// so it is left out.
function evidenceOf(entry) {
  const kept = { file: entry.file };
  for (const name of ["line", "endLine", "layer"]) {
    if (entry[name] !== undefined) kept[name] = entry[name];
  }
  return kept;
}

// Pairing -----------------------------------------------------------------------------------------

// Pairs the units of A with those of B, in the passes of the header. It returns one record per item.
function pairUnits(unitsA, unitsB) {
  const measured = pairMeasured(unitsA.measured, unitsB.measured);
  const judgment = pairByKey(unitsA.judgment, unitsB.judgment, (unit) => JSON.stringify([unit.rule, unit.files]));
  const records = [];
  for (const [unitA, unitB] of [...measured.pairs, ...judgment.pairs]) records.push(recordOf(unitA, unitB));
  for (const unit of [...measured.leftA, ...judgment.leftA]) records.push(recordOf(unit, null));
  for (const unit of [...measured.leftB, ...judgment.leftB]) records.push(recordOf(null, unit));
  return records;
}

// Pass 1 pairs on (rule, measurementRef, trigger). Pass 2 pairs what is left on (rule, measurementRef).
function pairMeasured(listA, listB) {
  const first = pairByKey(listA, listB, (unit) => JSON.stringify([unit.rule, unit.measurementRef, unit.trigger]));
  const second = pairByKey(first.leftA, first.leftB, (unit) => JSON.stringify([unit.rule, unit.measurementRef]));
  return { pairs: [...first.pairs, ...second.pairs], leftA: second.leftA, leftB: second.leftB };
}

// Pairs the units of A and B that have the same key. Inside a key, both lists are sorted by order and paired in turn. A unit
// with no partner is left over: those of A in leftA, those of B in leftB.
function pairByKey(listA, listB, keyOf) {
  const groupsB = groupBy(listB, keyOf);
  const pairs = [];
  const leftA = [];
  const matchedB = new Set();
  for (const [key, groupA] of groupBy(listA, keyOf)) {
    const groupB = groupsB.get(key) ?? [];
    groupA.sort(compareOrder);
    groupB.sort(compareOrder);
    groupA.forEach((unit, position) => {
      if (position < groupB.length) {
        pairs.push([unit, groupB[position]]);
        matchedB.add(groupB[position]);
      } else {
        leftA.push(unit);
      }
    });
  }
  return { pairs, leftA, leftB: listB.filter((unit) => !matchedB.has(unit)) };
}

// The units by key, in the order they were given.
function groupBy(list, keyOf) {
  const groups = new Map();
  for (const unit of list) {
    const key = keyOf(unit);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(unit);
  }
  return groups;
}

// The item of a pair (both units), of a unit of A with no partner (resolved), or of a unit of B with no partner (new).
// order is the order of the key unit: B's when there is one, otherwise A's.
function recordOf(unitA, unitB) {
  const keyUnit = unitB ?? unitA;
  let itemClass = "same";
  if (unitA === null) itemClass = "new";
  else if (unitB === null) itemClass = "resolved";
  else if (unitA.side.impact !== unitB.side.impact) itemClass = "impact-changed";
  return {
    item: {
      class: itemClass,
      kind: keyUnit.kind,
      rule: keyUnit.rule,
      axis: keyUnit.axis,
      key: keyUnit.kind === "measured"
        ? { measurementRef: keyUnit.measurementRef, trigger: keyUnit.trigger }
        : { files: keyUnit.files },
      a: unitA === null ? null : unitA.side,
      b: unitB === null ? null : unitB.side,
    },
    order: keyUnit.order,
  };
}

// Order -------------------------------------------------------------------------------------------

// Class, axis, rule, kind, key, then the number of the id or index of the key unit.
function compareRecords(x, y) {
  const p = x.item;
  const q = y.item;
  return (
    CLASSES.indexOf(p.class) - CLASSES.indexOf(q.class) ||
    AXES.indexOf(p.axis) - AXES.indexOf(q.axis) ||
    compareText(p.rule, q.rule) ||
    KINDS.indexOf(p.kind) - KINDS.indexOf(q.kind) ||
    compareKeys(p, q) ||
    compareDigits(x.order, y.order)
  );
}

// Two items of one kind. Measured keys compare measurementRef, then trigger; judgment keys compare their joined files.
function compareKeys(p, q) {
  if (p.kind === "judgment") return compareText(p.key.files.join("\n"), q.key.files.join("\n"));
  return compareText(p.key.measurementRef, q.key.measurementRef) || compareTrigger(p.key.trigger, q.key.trigger);
}

function compareOrder(x, y) {
  return compareDigits(x.order, y.order);
}

// A trigger name, with null before every name.
function compareTrigger(x, y) {
  if (x === null || y === null) return x === y ? 0 : x === null ? -1 : 1;
  return compareText(x, y);
}

// Two digit strings without a leading zero, compared as numbers without converting them (mf-10 comes after mf-2).
function compareDigits(x, y) {
  return x.length - y.length || compareText(x, y);
}

// Summaries ---------------------------------------------------------------------------------------

// The summary of one run that the comparison shows: its identity, its settings and its counts.
function runOf({ name, measurements, findings }) {
  const { meta, target, scope } = measurements;
  return {
    name,
    target: target.name,
    head: target.git.head,
    scannedAt: meta.scannedAt,
    schemaVersion: measurements.schemaVersion,
    depth: measurements.depth ?? DEFAULT_DEPTH,
    scope: scope === undefined ? null : [...scope.folders].sort(compareText),
    catalog: meta.catalog === undefined ? null : { count: meta.catalog.count, sha256: meta.catalog.sha256 },
    findings: findings.findings.length,
    measuredFindings: measurements.measuredFindings.length,
  };
}

// The warnings of a pair of runs, in WARNING_CODES order, with the two values that differ.
function warningsOf(a, b, runs) {
  const found = new Map();
  if (a.measurements.meta.targetRoot !== b.measurements.meta.targetRoot) {
    found.set("target-changed", [runs.a.target, runs.b.target]);
  }
  if (!sameList(runs.a.scope, runs.b.scope)) found.set("scope-changed", [runs.a.scope, runs.b.scope]);
  if (runs.a.depth !== runs.b.depth) found.set("depth-changed", [runs.a.depth, runs.b.depth]);
  if (runs.a.catalog === null || runs.b.catalog === null) {
    found.set("catalog-unknown", [runs.a.catalog, runs.b.catalog]);
  } else if (runs.a.catalog.count !== runs.b.catalog.count || runs.a.catalog.sha256 !== runs.b.catalog.sha256) {
    found.set("catalog-changed", [runs.a.catalog, runs.b.catalog]);
  }
  if (runs.a.schemaVersion !== runs.b.schemaVersion) found.set("schema-changed", [runs.a.schemaVersion, runs.b.schemaVersion]);
  return WARNING_CODES.filter((code) => found.has(code)).map((code) => {
    const [first, second] = found.get(code);
    return { code, a: first, b: second };
  });
}

// Two scope lists are the same when both are null, or when both have the same folders in the same order. Both are sorted.
function sameList(x, y) {
  if (x === null || y === null) return x === y;
  return x.length === y.length && x.every((item, index) => item === y[index]);
}

// Helpers -----------------------------------------------------------------------------------------

function isText(value) {
  return typeof value === "string";
}

function isLine(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

/** True when the value is an ISO 8601 time in UTC, as meta.scannedAt is written; utcDate (report-markdown.mjs) reads it. */
export function isUtcTime(value) {
  return isText(value) && UTC_TIME.test(value) && !Number.isNaN(Date.parse(value));
}

function isCatalog(value) {
  return (
    isPlainObject(value) &&
    Number.isSafeInteger(value.count) &&
    value.count >= 0 &&
    isText(value.sha256) &&
    CATALOG_SHA256.test(value.sha256)
  );
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
