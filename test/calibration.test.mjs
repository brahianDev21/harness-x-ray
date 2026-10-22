import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  PERCENTILE_METHOD,
  buildCalibration,
  checkCalibration,
  checkTargetName,
  claimCalibrationDir,
  measureNames,
  percentileOf,
  renderCalibrationMarkdown,
  summaryOf,
  thresholdKeys,
} from "../scripts/lib/calibration.mjs";
import { isPlainObject, toStableJson } from "../scripts/lib/json-out.mjs";
import { THRESHOLDS } from "../scripts/lib/thresholds.mjs";
import { UsageError } from "../scripts/lib/target.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

// The pure part of the calibration: the percentiles, the aggregation, the names and the document. No target is scanned here. The
// scans are plain objects with the fields that the measures read (scanner.mjs and the measures write the same shape).
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "calibration.schema.json"), "utf8"));
const CATALOG = Object.freeze({ count: 19, sha256: "7bf4e797546c" });
const TOOL = "harness-x-ray@0.0.0";
const DATE = "2026-10-22";

// A scan with the fields that the calibration reads. Every field has a default that gives no value for any measure.
function scanOf(name, { tokens = 0, duplicationPct = 0, memory = [], largeFiles = [], warnings = [], skills = [] } = {}) {
  return {
    meta: { tool: TOOL, catalog: { ...CATALOG } },
    target: { name },
    context: { alwaysLoaded: { estTokensTotal: tokens } },
    inventory: memory,
    code: { duplication: { duplicatedLinesPct: duplicationPct } },
    structure: { largeFiles },
    warnings,
    claudeConfig: { skills },
  };
}

const memoryFile = (lines, loadMode = "always") => ({ path: "CLAUDE.md", kind: "memory", loadMode, lines, estTokens: 1 });
const skill = (descriptionChars, loadMode = "always") => ({ path: ".claude/skills/s/SKILL.md", descriptionChars, loadMode });

function calibrationOf(scans) {
  return buildCalibration(scans, { date: DATE, tool: TOOL, catalog: CATALOG });
}

function measureOf(calibration, name) {
  return calibration.measures.find((measure) => measure.name === name);
}

function thresholdOf(calibration, measure, key) {
  return measureOf(calibration, measure).thresholds.find((threshold) => threshold.key === key);
}

test("percentileOf: nearest rank for one, two, five and ten values", () => {
  assert.equal(percentileOf([7], 25), 7);
  assert.equal(percentileOf([7], 90), 7);

  const two = [1, 2];
  assert.deepEqual([25, 50, 75, 90].map((p) => percentileOf(two, p)), [1, 1, 2, 2]);

  const five = [10, 20, 30, 40, 50];
  assert.deepEqual([25, 50, 75, 90].map((p) => percentileOf(five, p)), [20, 30, 40, 50]);

  const ten = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  assert.deepEqual([25, 50, 75, 90].map((p) => percentileOf(ten, p)), [3, 5, 8, 9]);
});

test("percentileOf: the ends and the rank below one", () => {
  const values = [4, 8, 15];
  assert.equal(percentileOf(values, 0), 4);
  assert.equal(percentileOf(values, 100), 15);
  assert.throws(() => percentileOf([], 50), TypeError);
  assert.throws(() => percentileOf(values, 101), TypeError);
  assert.throws(() => percentileOf(values, 2.5), TypeError);
});

test("summaryOf: sorts the values, gives n and every statistic, and nulls when there is no value", () => {
  assert.deepEqual(summaryOf([30, 10, 20, 40, 50]), { n: 5, min: 10, p25: 20, median: 30, p75: 40, p90: 50, max: 50 });
  assert.deepEqual(summaryOf([]), { n: 0, min: null, p25: null, median: null, p75: null, p90: null, max: null });
});

test("measure names and threshold keys: every threshold is compared by exactly one measure, and the schema lists the same", () => {
  assert.deepEqual(thresholdKeys(), Object.keys(THRESHOLDS).sort());
  const schemaMeasures = SCHEMA.$defs.measure.properties.name.enum;
  assert.deepEqual([...schemaMeasures].sort(), measureNames());
  assert.deepEqual([...SCHEMA.$defs.threshold.properties.key.enum].sort(), Object.keys(THRESHOLDS).sort());
});

test("buildCalibration: values, n and the thresholds of each measure, with the rule's comparison (above, not equal)", () => {
  const scans = [
    scanOf("alpha", { tokens: 100, duplicationPct: 0, memory: [memoryFile(200)] }),
    scanOf("beta", { tokens: 3000, duplicationPct: 5, memory: [memoryFile(201)] }),
    scanOf("gamma", { tokens: 6001, duplicationPct: 16, memory: [memoryFile(10, "on-demand"), memoryFile(90)] }),
  ];
  const calibration = calibrationOf(scans);

  // Tokens: 3000 is not above 3000, and 6001 is above both thresholds.
  const tokens = measureOf(calibration, "alwaysLoadedTokens");
  assert.deepEqual([tokens.n, tokens.min, tokens.median, tokens.max], [3, 100, 3000, 6001]);
  assert.equal(thresholdOf(calibration, "alwaysLoadedTokens", "alwaysLoadedTokensMedium").exceeding, 1);
  assert.equal(thresholdOf(calibration, "alwaysLoadedTokens", "alwaysLoadedTokensHigh").exceeding, 1);

  // Duplication: 5 is not above 5; 16 is above both thresholds.
  const duplication = measureOf(calibration, "duplicationPct");
  assert.deepEqual([duplication.n, duplication.max], [3, 16]);
  assert.equal(thresholdOf(calibration, "duplicationPct", "duplicationPctMedium").exceeding, 1);
  assert.equal(thresholdOf(calibration, "duplicationPct", "duplicationPctHigh").exceeding, 1);

  // Memory: only the always-loaded file counts (gamma's on-demand file of 10 lines is left out), so gamma's largest is 90.
  const memory = measureOf(calibration, "memoryFileLines");
  assert.deepEqual([memory.n, memory.min, memory.median, memory.max], [3, 90, 200, 201]);
  assert.equal(thresholdOf(calibration, "memoryFileLines", "memoryFileMaxLines").exceeding, 1);
});

test("buildCalibration: a target with no value is not counted in n, and the statistics come from the rest", () => {
  const calibration = calibrationOf([scanOf("alpha", { memory: [] }), scanOf("beta", { memory: [memoryFile(40)] })]);
  const memory = measureOf(calibration, "memoryFileLines");
  assert.equal(memory.n, 1);
  assert.deepEqual([memory.min, memory.p25, memory.median, memory.p75, memory.p90, memory.max], [40, 40, 40, 40, 40, 40]);
  const skills = measureOf(calibration, "skillDescriptionMaxChars");
  assert.deepEqual([skills.n, skills.min, skills.max], [0, null, null]);
  assert.equal(thresholdOf(calibration, "skillDescriptionMaxChars", "skillDescriptionMaxChars").exceeding, 0);
});

test("buildCalibration: the large files count the list plus the files that its cap cut, and a target exceeds the threshold with one", () => {
  const big = { path: "data/a.bin", bytes: 300000 };
  const scans = [
    scanOf("none"),
    scanOf("one", { largeFiles: [big] }),
    scanOf("cut", { largeFiles: [big, big], warnings: [{ source: "structure", path: ".", reason: "large-files-cut", detail: "count=3" }] }),
  ];
  const calibration = calibrationOf(scans);
  const large = measureOf(calibration, "largeFileCount");
  assert.deepEqual([large.n, large.min, large.median, large.max], [3, 0, 1, 5]);
  assert.equal(thresholdOf(calibration, "largeFileCount", "largeFileBytes").exceeding, 2);
});

test("buildCalibration: skills count the always-loaded ones, and their longest description is the maximum", () => {
  const calibration = calibrationOf([
    scanOf("skills", { skills: [skill(1100), skill(200), skill(900, "not-loaded"), skill(null, null)] }),
    scanOf("plain", { skills: [skill(50)] }),
  ]);
  const count = measureOf(calibration, "skillCount");
  assert.deepEqual([count.n, count.min, count.max], [2, 1, 2]);
  const longest = measureOf(calibration, "skillDescriptionMaxChars");
  assert.deepEqual([longest.n, longest.min, longest.max], [2, 50, 1100]);
  assert.equal(thresholdOf(calibration, "skillDescriptionMaxChars", "skillDescriptionMaxChars").exceeding, 1);
});

test("buildCalibration: the order of the scans does not change the output, and the lists are sorted", () => {
  const scans = [
    scanOf("zeta", { tokens: 4000, memory: [memoryFile(120)] }),
    scanOf("alpha", { tokens: 10, duplicationPct: 2.5 }),
    scanOf("mid", { tokens: 3500, duplicationPct: 30, memory: [memoryFile(260)] }),
  ];
  const forward = toStableJson(calibrationOf(scans));
  const backward = toStableJson(calibrationOf([...scans].reverse()));
  assert.equal(forward, backward);

  const calibration = calibrationOf(scans);
  assert.deepEqual(calibration.sample, { count: 3, targets: ["alpha", "mid", "zeta"] });
  assert.deepEqual(calibration.measures.map((measure) => measure.name), measureNames());
  for (const measure of calibration.measures) {
    const keys = measure.thresholds.map((threshold) => threshold.key);
    assert.deepEqual(keys, [...keys].sort());
  }
});

test("buildCalibration: the same input gives the same bytes, and the date is the one given", () => {
  const scans = [scanOf("alpha", { tokens: 1, memory: [memoryFile(3)] }), scanOf("beta", { tokens: 2 })];
  const first = toStableJson(buildCalibration(scans, { date: DATE, tool: TOOL, catalog: CATALOG }));
  const second = toStableJson(buildCalibration(scans, { date: DATE, tool: TOOL, catalog: CATALOG }));
  assert.equal(first, second);
  assert.equal(calibrationOf(scans).meta.date, DATE);
  assert.deepEqual(calibrationOf(scans).meta.catalog, CATALOG);
  assert.equal(calibrationOf(scans).meta.tool, TOOL);
});

test("buildCalibration: the result matches the schema, and the statuses are the ones of THRESHOLDS_STATUS", () => {
  const calibration = calibrationOf([scanOf("alpha", { tokens: 5000, memory: [memoryFile(300)], skills: [skill(1200)] }), scanOf("beta")]);
  assert.deepEqual(schemaProblems(SCHEMA, calibration), []);
  for (const measure of calibration.measures) {
    for (const threshold of measure.thresholds) assert.equal(threshold.status, "provisional");
  }
});

test("buildCalibration: an empty list, a date that is not YYYY-MM-DD, or a control character in a name is refused", () => {
  assert.throws(() => buildCalibration([], { date: DATE, tool: TOOL, catalog: CATALOG }), TypeError);
  assert.throws(() => buildCalibration([scanOf("alpha")], { date: "22-10-2026", tool: TOOL, catalog: CATALOG }), TypeError);
  assert.throws(() => buildCalibration([scanOf("bad\nname")], { date: DATE, tool: TOOL, catalog: CATALOG }), UsageError);
});

test("checkTargetName: ordinary names pass; empty names, control, line-separator and format characters are usage errors", () => {
  for (const name of ["bloated", "my-app", "app v2", "café", "naïve", "a|b", "x\\y", "a_b*c", "日本語"]) {
    assert.doesNotThrow(() => checkTargetName(name), name);
  }
  // Positive control above; the refused names: control characters, a line separator, and format characters (Cf) such as the
  // right-to-left override U+202E, the zero-width space U+200B and the soft hyphen U+00AD, which change how a name reads.
  for (const name of ["", "tab\tname", "line\nbreak", "cr\rname", "del\x7f", "sep x", "c1\x85x", "rtl‮name", "zero​width", "soft­hyphen"]) {
    assert.throws(() => checkTargetName(name), UsageError, JSON.stringify(name));
  }
  assert.throws(() => checkTargetName(undefined), UsageError);
});

// A fake mkdir over a set of names: it creates a name that is free, and throws EEXIST, as the file system does, when it is taken.
function fakeMkdirOver(folders) {
  const calls = [];
  const mkdir = (name) => {
    calls.push(name);
    if (folders.has(name)) throw Object.assign(new Error(`EEXIST: ${name}`), { code: "EEXIST" });
    folders.add(name);
  };
  return { mkdir, calls };
}

test("claimCalibrationDir: the base name first, then -2, -3 and so on, each claimed by its own mkdir", () => {
  const folders = new Set();
  const first = fakeMkdirOver(folders);
  assert.equal(claimCalibrationDir(DATE, first.mkdir), "calibration-2026-10-22");
  assert.deepEqual(first.calls, ["calibration-2026-10-22"]);

  // The same day again, in the same folders: the first name is taken, so the claim goes on to -2 and does not write into the first one.
  const second = fakeMkdirOver(folders);
  assert.equal(claimCalibrationDir(DATE, second.mkdir), "calibration-2026-10-22-2");
  assert.deepEqual(second.calls, ["calibration-2026-10-22", "calibration-2026-10-22-2"]);
  assert.equal(claimCalibrationDir(DATE, fakeMkdirOver(folders).mkdir), "calibration-2026-10-22-3");
});

test("claimCalibrationDir: an error other than EEXIST ends the claim with that error; no free name is an error", () => {
  const denied = Object.assign(new Error("EACCES: denied"), { code: "EACCES" });
  assert.throws(
    () =>
      claimCalibrationDir(DATE, () => {
        throw denied;
      }),
    (error) => error === denied,
  );
  assert.throws(() => claimCalibrationDir(DATE, () => { throw Object.assign(new Error("taken"), { code: "EEXIST" }); }), /up to -1000/);
});

test("renderCalibrationMarkdown: a name with pipes, backslashes or markup keeps its table row whole", () => {
  const calibration = calibrationOf([scanOf("a|b"), scanOf("c\\d"), scanOf("e_f*g"), scanOf("plain-name")]);
  const markdown = renderCalibrationMarkdown(calibration);
  assert.ok(markdown.includes("| a\\|b |"), "a pipe is escaped");
  assert.ok(markdown.includes("| c\\\\d |"), "a backslash is escaped");
  assert.ok(markdown.includes("| e\\_f\\*g |"), "emphasis characters are escaped");
  // escapeMarkdown escapes every ASCII punctuation character, the hyphen too, so the escaped name is the same text in a table cell.
  assert.ok(markdown.includes("| plain\\-name |"), "an ordinary name is escaped the same way, with a backslash before the hyphen");
  // Every row of the sample table has one cell: after the escaped pipes are taken out, a row has its two outer pipes only.
  const lines = markdown.split("\n");
  const start = lines.indexOf("| Target |");
  const rows = lines.slice(start + 2, start + 2 + 4);
  assert.equal(rows.length, 4);
  for (const row of rows) assert.equal(row.replace(/\\\|/g, "").split("|").length, 3, row);
});

test("renderCalibrationMarkdown: says the method, the sample, the date, the tool and the note on the thresholds", () => {
  const markdown = renderCalibrationMarkdown(calibrationOf([scanOf("alpha", { tokens: 3500 }), scanOf("beta")]));
  assert.ok(markdown.startsWith("# Threshold calibration\n"));
  assert.ok(markdown.includes("- Date (UTC): 2026-10-22"));
  assert.ok(markdown.includes("- Tool: `harness-x-ray@0.0.0`"));
  assert.ok(markdown.includes("SHA-256 (first 12 hex digits) `7bf4e797546c`"));
  assert.ok(!markdown.includes("SHA-256 `"), "the hash is named as the first 12 hex digits, never as the whole SHA-256");
  assert.ok(markdown.includes("nearest rank"));
  assert.ok(markdown.includes("`scripts/lib/thresholds.mjs`") && markdown.includes("`calibrated`"));
  assert.ok(markdown.includes("`alwaysLoadedTokensMedium` = 3000 (provisional): exceeded by 1 of 2 targets with a value."));
});

test("buildCalibration: the object holds only numbers, the basenames, the fixed texts and the statuses", () => {
  const calibration = calibrationOf([scanOf("alpha", { tokens: 9000, memory: [memoryFile(999)] }), scanOf("beta", { skills: [skill(77)] })]);
  assert.ok(isPlainObject(calibration));
  const allowed = new Set([
    ...measureNames(),
    ...thresholdKeys(),
    "provisional",
    "calibrated",
    "alpha",
    "beta",
    DATE,
    TOOL,
    CATALOG.sha256,
    calibration.meta.percentileMethod,
  ]);
  const strings = [];
  const walk = (value) => {
    if (typeof value === "string") strings.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (isPlainObject(value)) Object.values(value).forEach(walk);
  };
  walk(calibration);
  assert.deepEqual(strings.filter((text) => !allowed.has(text)), []);
});
