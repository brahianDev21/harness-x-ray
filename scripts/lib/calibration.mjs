// Calibration of the thresholds: the distribution of each measure over a sample of targets, and how many targets are above each
// threshold. It is pure. buildCalibration takes the scans (the measurements objects of scanner.mjs) and returns the data of
// calibration.json; renderCalibrationMarkdown returns the document for a person. Nothing here reads a target or the clock: the
// date is a parameter, so the output is deterministic. A target gives only numbers and its folder name (target.name, its basename).
//
// Percentiles use the nearest rank. With the n values sorted ascending as v[1] to v[n], the p-th percentile is v[ceil(p * n / 100)].
// The product p * n is an integer, so the rank is exact. The median is the 50th percentile: with an even n it is the lower of the
// two middle values. With no value at all (n = 0) every statistic is null.
//
// A target that has no value for a measure (null) is not counted in that measure's n. For each threshold, "exceeding" counts the
// values of the measure that are above it, with the comparison of the rule that reads the threshold (measured-findings.mjs): a
// value equal to the threshold is not above it. largeFileBytes is the one threshold that is not a value of its measure: its measure
// counts the files above it, so a target exceeds it when it has at least one such file.
//
// The thresholds stay as they are. A value changes only on this evidence, and then its status in THRESHOLDS_STATUS becomes
// "calibrated" in the same change (see thresholds.mjs).

import { UsageError } from "./target.mjs";
import { THRESHOLDS, THRESHOLDS_STATUS } from "./thresholds.mjs";
import { codeSpan, escapeMarkdown, table } from "./report-markdown.mjs";

/** Layout version of calibration.json. Change it only when an existing field changes meaning. */
export const CALIBRATION_SCHEMA_VERSION = 1;
/** The method of the percentiles, written to meta.percentileMethod and to the document. */
export const PERCENTILE_METHOD =
  "nearest rank: with the n values sorted ascending as v[1] to v[n], the p-th percentile is v[ceil(p * n / 100)]; the median is the 50th percentile";
// A folder name with a control character, a line separator or a format character (for example U+202E, which reverses the text
// that follows it) is refused: it cannot be shown as it is in a document. \p{Cc} is the control characters, \p{Cf} the format ones.
const CONTROL_CHARACTERS = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const PERCENTILES = Object.freeze({ p25: 25, median: 50, p75: 75, p90: 90 });
// The highest suffix that the default run folder tries (calibration-<date>-2 up to -1000).
const MAX_SUFFIX = 1000;

// The measures, each with valueIn(scan), the value that one scan gives (a number, or null when the scan has none), and the
// thresholds that it is compared with. The comparison is "above": value > threshold, as in the rules.
const MEASURES = Object.freeze([
  {
    name: "alwaysLoadedTokens",
    description: "Estimated tokens of the always-loaded budget: the total of context.alwaysLoaded (CTX-01).",
    valueIn: alwaysLoadedTokensOf,
    thresholds: [
      { key: "alwaysLoadedTokensMedium", exceeds: (value) => value > THRESHOLDS.alwaysLoadedTokensMedium },
      { key: "alwaysLoadedTokensHigh", exceeds: (value) => value > THRESHOLDS.alwaysLoadedTokensHigh },
    ],
  },
  {
    name: "duplicationPct",
    description: "Percentage of redundant lines of the duplication measure (COD-01): code.duplication.duplicatedLinesPct.",
    valueIn: duplicationPctOf,
    thresholds: [
      { key: "duplicationPctMedium", exceeds: (value) => value > THRESHOLDS.duplicationPctMedium },
      { key: "duplicationPctHigh", exceeds: (value) => value > THRESHOLDS.duplicationPctHigh },
    ],
  },
  {
    name: "largeFileCount",
    description:
      "Number of versioned files above the current largeFileBytes (STR-02), lockfiles and generated files left out. The list of the structure measure holds at most 200 files, and the files cut from it are counted by its warning, so the count is exact. The threshold is exceeded by a target that has at least one such file. This measure counts files above the current value, so it cannot support a new byte value on its own: a new value needs the distribution of file sizes.",
    valueIn: largeFileCountOf,
    thresholds: [{ key: "largeFileBytes", exceeds: (value) => value > 0 }],
  },
  {
    name: "memoryFileLines",
    description:
      "Largest number of lines of an always-loaded memory file (CTX-01): the memory files of inventory with loadMode always. A target with no such file has no value.",
    valueIn: memoryFileLinesOf,
    thresholds: [{ key: "memoryFileMaxLines", exceeds: (value) => value > THRESHOLDS.memoryFileMaxLines }],
  },
  {
    name: "skillCount",
    description:
      "Number of skills in the listing: the skills of claudeConfig with loadMode always (CTX-04). A root skill whose frontmatter cannot be read is not counted, as in the rule.",
    valueIn: skillCountOf,
    thresholds: [{ key: "skillCountMax", exceeds: (value) => value > THRESHOLDS.skillCountMax }],
  },
  {
    name: "skillDescriptionMaxChars",
    description:
      "Longest listed description of a skill, in characters: descriptionChars of the skills with loadMode always (CTX-04). A target with no listed skill has no value. The count is above 1,024 characters, as the long-description trigger of CTX-04. It also counts a skill over the listing cut (overLimit, above 1,536 characters), which the rule reports as skill-description-truncated (medium) and not as long (low): such a skill is above 1,024 as well, so it is counted here.",
    valueIn: skillDescriptionMaxCharsOf,
    thresholds: [{ key: "skillDescriptionMaxChars", exceeds: (value) => value > THRESHOLDS.skillDescriptionMaxChars }],
  },
]);

/**
 * The names of the measures, sorted: the order of the measures in calibration.json.
 * @returns {string[]}
 */
export function measureNames() {
  return MEASURES.map((measure) => measure.name).sort(compareText);
}

/**
 * The keys of the thresholds that the measures compare, sorted.
 * @returns {string[]}
 */
export function thresholdKeys() {
  return MEASURES.flatMap((measure) => measure.thresholds.map((threshold) => threshold.key)).sort(compareText);
}

/**
 * The nearest-rank percentile of values sorted ascending: sorted[ceil(p * n / 100) - 1], and the first value for a rank below 1.
 * @param {number[]} sorted Non-empty, ascending.
 * @param {number} p An integer from 0 to 100.
 * @returns {number}
 */
export function percentileOf(sorted, p) {
  if (sorted.length === 0) throw new TypeError("a percentile needs at least one value");
  if (!Number.isInteger(p) || p < 0 || p > 100) throw new TypeError("a percentile is an integer from 0 to 100");
  const rank = Math.max(1, Math.ceil((p * sorted.length) / 100));
  return sorted[rank - 1];
}

/**
 * The statistics of the values of one measure: n, min, p25, median, p75, p90 and max. All but n are null when there is no value.
 * @param {number[]} values The values that are not null, in any order.
 * @returns {{ n: number, min: number | null, p25: number | null, median: number | null, p75: number | null, p90: number | null, max: number | null }}
 */
export function summaryOf(values) {
  const sorted = [...values].sort((a, b) => a - b);
  if (sorted.length === 0) return { n: 0, min: null, p25: null, median: null, p75: null, p90: null, max: null };
  return {
    n: sorted.length,
    min: sorted[0],
    p25: percentileOf(sorted, PERCENTILES.p25),
    median: percentileOf(sorted, PERCENTILES.median),
    p75: percentileOf(sorted, PERCENTILES.p75),
    p90: percentileOf(sorted, PERCENTILES.p90),
    max: sorted[sorted.length - 1],
  };
}

/**
 * Claims the default run folder of a calibration: calibration-<date>, then calibration-<date>-2, -3 and so on, with the first name
 * that mkdir creates. mkdir is passed in so that a test can run this without a folder. It creates the folder of the name it is
 * given, without a recursive flag, and throws an error with code EEXIST when that name is taken; any other error ends the claim.
 * The name is claimed by the same step that creates its folder, so two runs of the same day never share one folder.
 * @param {string} date YYYY-MM-DD (UTC).
 * @param {(name: string) => void} mkdir Creates the folder of a name, or throws (code EEXIST when the name is taken).
 * @returns {string} The name that was created.
 * @throws {Error} The error of mkdir when it is not EEXIST, or when no name up to -1000 is free.
 */
export function claimCalibrationDir(date, mkdir) {
  const base = `calibration-${date}`;
  for (let suffix = 1; suffix <= MAX_SUFFIX; suffix += 1) {
    const name = suffix === 1 ? base : `${base}-${suffix}`;
    try {
      mkdir(name);
      return name;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
  }
  throw new Error(`no free name for the calibration folder of ${date} up to -${MAX_SUFFIX}`);
}

/**
 * The constraints that the schema cannot state across fields, checked on a calibration before anything is written. The schema
 * (schemas/calibration.schema.json) checks the rest. Each problem is a fixed phrase, with the name of the measure or key where
 * one applies, and never a value of a target.
 * @param {object} calibration The data that buildCalibration returns.
 * @returns {string[]} The problems; an empty list means the calibration is consistent.
 */
export function checkCalibration(calibration) {
  const problems = [];
  const { meta, sample, measures } = calibration;
  if (!isRealDate(meta.date)) problems.push("meta.date is not a real date");
  if (sample.count !== sample.targets.length) problems.push("sample.count is not the number of sample.targets");
  if (!isSorted(sample.targets)) problems.push("sample.targets is not sorted");
  const names = measures.map((measure) => measure.name);
  if (new Set(names).size !== names.length) problems.push("a measure name is repeated");
  if (!isSorted(names)) problems.push("measures are not sorted by name");
  for (const measure of measures) {
    const definition = MEASURES.find((item) => item.name === measure.name);
    if (definition === undefined) {
      problems.push("a measure is not one of the measures of this tool");
      continue;
    }
    problems.push(...measureProblems(measure, definition, sample.count));
  }
  return problems;
}

// The problems of one measure: its n against the sample, its statistics against n, its order, and its thresholds.
function measureProblems(measure, definition, sampleCount) {
  const { name } = measure;
  const problems = [];
  if (measure.n > sampleCount) problems.push(`${name}: n is more than sample.count`);
  const stats = ["min", "p25", "median", "p75", "p90", "max"];
  if (measure.n === 0) {
    if (stats.some((stat) => measure[stat] !== null)) problems.push(`${name}: n is 0 but a statistic is not null`);
  } else {
    if (stats.some((stat) => typeof measure[stat] !== "number")) problems.push(`${name}: n is not 0 but a statistic is null`);
    const ordered = stats.map((stat) => measure[stat]);
    if (ordered.some((value, index) => index > 0 && typeof value === "number" && value < ordered[index - 1])) {
      problems.push(`${name}: the statistics are not in order from min to max`);
    }
  }
  const keys = measure.thresholds.map((threshold) => threshold.key);
  const expected = definition.thresholds.map((threshold) => threshold.key).sort(compareText);
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    problems.push(`${name}: its thresholds are not exactly the thresholds of this measure, sorted by key`);
  }
  for (const threshold of measure.thresholds) {
    if (threshold.exceeding > measure.n) problems.push(`${name}: ${threshold.key} exceeding is more than n`);
  }
  return problems;
}

// True when the text is a date that exists: YYYY-MM-DD, with a day the calendar has (not 2026-02-30).
function isRealDate(text) {
  if (typeof text !== "string" || !DATE.test(text)) return false;
  const date = new Date(`${text}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === text;
}

// True when a list is in code-unit order (non-decreasing).
function isSorted(list) {
  return list.every((item, index) => index === 0 || compareText(list[index - 1], item) <= 0);
}

/**
 * Checks the folder name of a target before it is written: a control character or a line separator is a usage error, since the
 * name would break the document. The name is not printed in the error.
 * @param {unknown} name The basename of the target.
 * @throws {UsageError} If the name is not text, is empty, or holds a control character.
 */
export function checkTargetName(name) {
  if (typeof name !== "string" || name === "") throw new UsageError("a target folder name must not be empty");
  if (CONTROL_CHARACTERS.test(name)) {
    throw new UsageError("a target folder name holds a control character, which calibration does not accept");
  }
}

/**
 * Builds the calibration of a sample: the sample, the statistics of each measure and the thresholds with their status and the
 * number of targets above each. The result is the data of calibration.json, before the schema check.
 * @param {object[]} scans One measurements object per target (scanner.mjs). Only target.name and the measures are read.
 * @param {{ date: string, tool: string, catalog: { count: number, sha256: string } }} options date is YYYY-MM-DD (UTC) and is the
 *   date of the run; tool and catalog are the meta.tool and meta.catalog of the scans.
 * @returns {object} The calibration, with sorted lists.
 * @throws {TypeError} If there is no scan, or the date is not YYYY-MM-DD.
 * @throws {UsageError} If a target name is not allowed (see checkTargetName).
 */
export function buildCalibration(scans, { date, tool, catalog }) {
  if (!Array.isArray(scans) || scans.length === 0) throw new TypeError("a calibration needs at least one scan");
  if (typeof date !== "string" || !DATE.test(date)) throw new TypeError("the date of a calibration is YYYY-MM-DD");
  const targets = scans.map((scan) => {
    const name = scan?.target?.name;
    checkTargetName(name);
    return name;
  });
  const measures = MEASURES.map((measure) => {
    const values = scans.map((scan) => measure.valueIn(scan)).filter((value) => value !== null);
    const thresholds = measure.thresholds
      .map(({ key, exceeds }) => ({
        key,
        value: THRESHOLDS[key],
        status: THRESHOLDS_STATUS[key],
        exceeding: values.filter((value) => exceeds(value)).length,
      }))
      .sort((a, b) => compareText(a.key, b.key));
    return { name: measure.name, ...summaryOf(values), thresholds };
  }).sort((a, b) => compareText(a.name, b.name));
  return {
    schemaVersion: CALIBRATION_SCHEMA_VERSION,
    meta: {
      date,
      tool,
      catalog: { count: catalog.count, sha256: catalog.sha256 },
      percentileMethod: PERCENTILE_METHOD,
    },
    sample: { count: scans.length, targets: [...targets].sort(compareText) },
    measures,
  };
}

/**
 * The document calibration.md, in English: the sample, the method, one table per measure with its thresholds, and the rule that
 * a threshold changes only with this evidence. Folder names are escaped, so a name cannot break a table.
 * @param {object} calibration The data that buildCalibration returns.
 * @returns {string}
 */
export function renderCalibrationMarkdown(calibration) {
  const { meta, sample, measures } = calibration;
  const blocks = [
    "# Threshold calibration",
    [
      "## Sample",
      "",
      `- Date (UTC): ${meta.date}`,
      `- Tool: ${codeSpan(meta.tool)}`,
      `- Rule catalog: ${meta.catalog.count} rule files, SHA-256 (first 12 hex digits) ${codeSpan(meta.catalog.sha256)}`,
      `- Targets: ${sample.count}`,
      "",
      "One row per target, in sorted order. Two targets with the same folder name are two rows.",
      "",
      table(
        ["Target"],
        sample.targets.map((name) => [escapeMarkdown(name)]),
      ),
    ].join("\n"),
    ["## Method", "", `${codeSpan(meta.percentileMethod)}.`, "", "A target with no value for a measure is not counted in its n."].join("\n"),
    ...measures.map(measureBlock),
    [
      "## Note",
      "",
      "A threshold changes only with this evidence. When a value changes, its status in `scripts/lib/thresholds.mjs` (THRESHOLDS_STATUS) becomes `calibrated` in the same change. Until then every value stays `provisional`.",
    ].join("\n"),
  ];
  return `${blocks.join("\n\n")}\n`;
}

// One measure: its description, its statistics as a table, and the thresholds it is compared with.
function measureBlock(measure) {
  const definition = MEASURES.find((item) => item.name === measure.name);
  const stats = ["n", "min", "p25", "median", "p75", "p90", "max"];
  const row = stats.map((stat) => (measure[stat] === null ? "-" : String(measure[stat])));
  const thresholds = measure.thresholds.map(
    (threshold) =>
      `- ${codeSpan(threshold.key)} = ${threshold.value} (${threshold.status}): exceeded by ${threshold.exceeding} of ${measure.n} targets with a value.`,
  );
  return [
    `## ${measure.name}`,
    "",
    definition.description,
    "",
    table(stats, [row]),
    "",
    ...thresholds,
  ].join("\n");
}

// The value of each measure of a scan. Each returns a number or null.

function alwaysLoadedTokensOf(scan) {
  const total = scan.context?.alwaysLoaded?.estTokensTotal;
  return Number.isInteger(total) ? total : null;
}

function duplicationPctOf(scan) {
  const pct = scan.code?.duplication?.duplicatedLinesPct;
  return typeof pct === "number" && Number.isFinite(pct) ? pct : null;
}

// The files above largeFileBytes: the list of the structure measure, plus the files that its cap cut, which its warning counts.
function largeFileCountOf(scan) {
  const large = scan.structure?.largeFiles;
  if (!Array.isArray(large)) return null;
  let count = large.length;
  for (const warning of scan.warnings ?? []) {
    if (warning?.reason !== "large-files-cut") continue;
    const cut = /^count=(\d+)$/.exec(warning.detail ?? "");
    if (cut === null) return null;
    count += Number(cut[1]);
  }
  return count;
}

// The largest line count of an always-loaded memory file, as CTX-01 selects them.
function memoryFileLinesOf(scan) {
  let max = null;
  for (const item of scan.inventory ?? []) {
    if (item.kind !== "memory" || item.loadMode !== "always" || !Number.isInteger(item.lines)) continue;
    max = max === null ? item.lines : Math.max(max, item.lines);
  }
  return max;
}

// The skills of the listing, as CTX-04 selects them: the skills whose loadMode is always.
function listedSkillsOf(scan) {
  const skills = scan.claudeConfig?.skills;
  return Array.isArray(skills) ? skills.filter((skill) => skill.loadMode === "always") : null;
}

function skillCountOf(scan) {
  return listedSkillsOf(scan)?.length ?? null;
}

function skillDescriptionMaxCharsOf(scan) {
  let max = null;
  for (const skill of listedSkillsOf(scan) ?? []) {
    if (!Number.isInteger(skill.descriptionChars)) continue;
    max = max === null ? skill.descriptionChars : Math.max(max, skill.descriptionChars);
  }
  return max;
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
