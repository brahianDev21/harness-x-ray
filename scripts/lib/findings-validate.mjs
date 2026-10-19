// Checks a parsed findings.json before the report is written. It checks each finding against the rule catalog,
// the measured findings of the same scan (measurements.json) and the target folder, and it looks for secrets in
// every string. Its result has two lists:
//
// - errors: the report must not be written. Each one says what is wrong and where.
// - warnings: the report can be written, but the reader should look. Numbers in the free text that measurements.json
//   does not contain are warnings, and so is a measured finding whose impact differs from its measured finding.
//
// The target is read only for evidence, and only through safe-fs. Nothing is written, and nothing from the target runs.
//
// Every issue is { finding, rule, field, message }. finding is the index in findings[] (null for the file as a whole),
// rule is the id of that finding when the catalog knows it (otherwise null), field is the path of the value to fix,
// such as "findings[2].evidence[0].line", and message says what is wrong. formatIssue prints all of that in one line.
//
// Number heuristic (warnings only). The free text (summary, recommendation, testInFunction2) is searched for number
// tokens. These are not checked: dates, rule ids such as SEC-02, measured finding and candidate ids such as mf-7 and
// cand-3, version numbers such as 2.1.277, file names with an optional :line or :line-line, and paths with a letter in
// them. A token is a number of the text when it matches one of its values: "2,300" and "2.300" are 2300 (thousands) and
// 2.3 (decimal); "0,37" is 0.37. A token with several separators that are not thousands is known when each part is.
// The known numbers are every finite JSON number of measurements.json.
//
// Secret heuristic (errors). Every string of findings.json is checked with the patterns of data/secret-patterns.json:
// the token formats and the generic key-value assignments. File names are not checked, because a finding about a
// secret file must name it. A match whose value has the shape of mask() is accepted (see isMasked).

import fs from "node:fs";
import path from "node:path";
import { parseFrontmatter } from "./frontmatter.mjs";
import { isPlainObject } from "./json-out.mjs";
import { createTargetFs } from "./safe-fs.mjs";
import { findGenericSecrets, findSpecificSecrets, isMasked } from "./secret-patterns.mjs";

/** Languages findings.json may name. A missing language means DEFAULT_LANGUAGE. */
export const LANGUAGES = Object.freeze(["en", "es"]);
export const DEFAULT_LANGUAGE = "en";
export const AXES = Object.freeze(["instructions", "context", "security", "verification", "structure", "code"]);
export const KINDS = Object.freeze(["measured", "judgment"]);
export const IMPACTS = Object.freeze(["high", "medium", "low"]);
/** The fields the validator accepts. The schema in schemas/findings.schema.json must document the same sets. */
export const TOP_LEVEL_FIELDS = Object.freeze(["findings", "language"]);
export const FINDING_FIELDS = Object.freeze([
  "rule",
  "axis",
  "kind",
  "measuredFindingId",
  "measuredSupport",
  "evidence",
  "impact",
  "summary",
  "recommendation",
  "testInFunction2",
]);
export const EVIDENCE_FIELDS = Object.freeze(["file", "line", "endLine", "quote"]);
export const REQUIRED_FINDING_FIELDS = Object.freeze([
  "rule",
  "axis",
  "kind",
  "evidence",
  "impact",
  "summary",
  "recommendation",
  "testInFunction2",
]);
// A rule file of the catalog: <ID>.md or <ID>-<slug>.md, as check-catalog.mjs reads them.
const RULE_FILE = /^[A-Z]{3}-\d{2}(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?\.md$/;
// A segment that Windows reads as the parent folder ("..", "... " and so on). The same rule as safe-fs.
const PARENT_SEGMENT = /^[. ]*\.\.[. ]*$/;
const READ_PROBLEMS = Object.freeze({
  "outside-root": "is outside the target folder",
  "not-found": "does not exist in the target",
  "not-a-file": "is not a regular file",
  "too-large": "is too large to check",
  binary: "is binary, so its lines cannot be checked",
  "read-error": "cannot be read",
});
const MAX_SHOWN = 60;
// Number tokens of free text. The lookbehind keeps ids such as "x2" out, and the lookahead takes the whole number.
const NUMBER_TOKEN = /(?<![\p{L}\p{N}_])\d+(?:[.,]\d+)*(?!\d)/gu;
const THOUSANDS = /^\d{1,3}(?:[.,]\d{3})+$/;
const DECIMAL = /^\d+[.,]\d+$/;
const INTEGER = /^\d+$/;
// Parts of the text that hold digits which are not numbers of the scan. They are replaced by a space before the
// number tokens are read. The order matters: the date and the version patterns come before the file names.
const REFERENCE_PATTERNS = Object.freeze([
  /\d{4}-\d{2}-\d{2}/g,
  /\b(?:RUL|CTX|SEC|VER|STR|COD)-\d{2}\b/g,
  /\b(?:mf|cand)-\d+\b/g,
  /\d+(?:\.\d+){2,}/g,
  /[\w-]+(?:\.[\w-]+)*\.[A-Za-z]\w*(?::\d+(?:-\d+)?)?/g,
]);
// A run with a separator. It is removed when it has a letter, so "5/10" stays a number and "src/2024" does not.
const PATH_LIKE = /[\w.\-\\/]*[\\/][\w.\-\\/]*/g;

/**
 * Checks a parsed findings.json. Reads the target only for evidence, and only through safe-fs.
 * @param {object} options
 * @param {unknown} options.findings The parsed findings.json (the whole object, with its language and findings list).
 * @param {object} options.measurements The parsed measurements.json of the same scan.
 * @param {Array<{ id: string, axis: string, kind: string }>} options.rules The catalog, as loadRules returns it.
 * @param {string} options.targetRoot Absolute path of the scanned folder: meta.targetRoot of measurements.json.
 * @returns {{ ok: boolean, language: "en" | "es" | null, errors: Issue[], warnings: Issue[] }}
 *   ok is true when there are no errors. language is the resolved language, or null when its value is not allowed.
 * @throws {TypeError} If an argument has the wrong shape. Problems in findings.json are errors, never throws.
 * @throws {Error} If targetRoot is not an existing folder (createTargetFs).
 */
export function validateFindings({ findings, measurements, rules, targetRoot }) {
  if (!isPlainObject(measurements)) throw new TypeError("measurements must be the parsed measurements.json object");
  if (!Array.isArray(rules)) throw new TypeError("rules must be a list of { id, axis, kind } objects");
  for (const rule of rules) {
    if (!isPlainObject(rule) || typeof rule.id !== "string" || typeof rule.axis !== "string" || typeof rule.kind !== "string") {
      throw new TypeError("each rule needs a string id, axis and kind");
    }
  }
  if (typeof targetRoot !== "string" || targetRoot === "") throw new TypeError("targetRoot must be the path of the scanned folder");

  const ctx = {
    errors: [],
    warnings: [],
    rules: new Map(rules.map((rule) => [rule.id, rule])),
    measured: measuredById(measurements),
    numbers: numbersIn(measurements, new Set()),
    target: createTargetFs(targetRoot),
    reads: new Map(),
  };
  const language = checkTopLevel(findings, ctx);
  return { ok: ctx.errors.length === 0, language, errors: ctx.errors, warnings: ctx.warnings };
}

/**
 * Prints one issue on one line, naming the finding and the field to fix.
 * @param {{ finding: number | null, rule: string | null, field: string, message: string }} issue
 * @returns {string} For example "findings[2] (SEC-02), field findings[2].evidence[0].line: line 99 is past the end of ...".
 */
export function formatIssue(issue) {
  const where = issue.finding === null
    ? "findings.json"
    : `findings[${issue.finding}]${issue.rule === null ? "" : ` (${issue.rule})`}`;
  return `${where}, field ${issue.field}: ${issue.message}`;
}

/**
 * Reads the rule catalog of a harness folder: the frontmatter of every rules/<ID>.md or rules/<ID>-<slug>.md file, parsed
 * by frontmatter.mjs as check-catalog.mjs parses it. Only the harness folder is read, never a target. It does not check the
 * catalog; run check-catalog.mjs for that.
 * @param {string} harnessRoot The folder that contains rules/.
 * @returns {Array<{ id: string, title: string, axis: string, kind: string, file: string }>} Sorted by id.
 * @throws {Error} If a rule file has a frontmatter that cannot be read, or no id, axis or kind as text.
 */
export function loadRules(harnessRoot) {
  const dir = path.join(harnessRoot, "rules");
  const names = fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && RULE_FILE.test(entry.name))
    .map((entry) => entry.name)
    .sort(compareText);
  const rules = [];
  for (const name of names) {
    const parsed = parseFrontmatter(fs.readFileSync(path.join(dir, name), "utf8"));
    const file = `rules/${name}`;
    if (parsed.error !== undefined || parsed.data === null) {
      throw new Error(`${file}: the frontmatter cannot be read; run the catalog check`);
    }
    const { id, title, axis, kind } = parsed.data;
    if (typeof id !== "string" || typeof axis !== "string" || typeof kind !== "string") {
      throw new Error(`${file}: the frontmatter needs id, axis and kind as text`);
    }
    rules.push({ id, title: typeof title === "string" ? title : "", axis, kind, file });
  }
  return rules.sort((a, b) => compareText(a.id, b.id));
}

// Top level ----------------------------------------------------------------------------------------

// Checks the file as a whole, then each finding. Returns the resolved language, or null when it is not allowed.
function checkTopLevel(findings, ctx) {
  if (!isPlainObject(findings)) {
    addIssue(ctx.errors, null, null, "findings", "the file must hold a JSON object with a findings list");
    return null;
  }
  for (const key of Object.keys(findings)) {
    if (!TOP_LEVEL_FIELDS.includes(key)) {
      addIssue(ctx.errors, null, null, key, `unknown field; the fields are ${TOP_LEVEL_FIELDS.join(", ")}`);
    }
  }

  let language = DEFAULT_LANGUAGE;
  if (findings.language !== undefined) {
    if (LANGUAGES.includes(findings.language)) {
      language = findings.language;
    } else {
      language = null;
      addIssue(ctx.errors, null, null, "language", `must be "en" or "es", found ${show(findings.language)}`);
    }
  }

  if (findings.findings === undefined) {
    addIssue(ctx.errors, null, null, "findings", "missing required field; it must be a list, which may be empty");
  } else if (!Array.isArray(findings.findings)) {
    addIssue(ctx.errors, null, null, "findings", "must be a list of finding objects");
  } else {
    findings.findings.forEach((item, index) => checkFinding(item, index, ctx));
  }
  return language;
}

// One finding -------------------------------------------------------------------------------------

function checkFinding(item, index, ctx) {
  const at = `findings[${index}]`;
  if (!isPlainObject(item)) {
    addIssue(ctx.errors, index, null, at, "must be an object");
    return;
  }
  // The rule is named in the issues only when the catalog knows it, so a stray string is never printed as a rule.
  const entry = typeof item.rule === "string" ? ctx.rules.get(item.rule) : undefined;
  const rule = entry === undefined ? null : entry.id;
  const fail = (name, message) => addIssue(ctx.errors, index, rule, `${at}.${name}`, message);
  const warn = (name, message) => addIssue(ctx.warnings, index, rule, `${at}.${name}`, message);

  for (const key of Object.keys(item)) {
    if (!FINDING_FIELDS.includes(key)) fail(key, `unknown field; the fields are ${FINDING_FIELDS.join(", ")}`);
  }
  for (const key of REQUIRED_FINDING_FIELDS) {
    if (item[key] === undefined) fail(key, "missing required field");
  }

  if (item.rule !== undefined && entry === undefined) {
    fail("rule", `${show(item.rule)} is not a rule of the catalog; use an id from rules/`);
  }
  if (item.axis !== undefined) {
    if (!AXES.includes(item.axis)) {
      fail("axis", `must be one of ${AXES.join(", ")}, found ${show(item.axis)}`);
    } else if (entry !== undefined && item.axis !== entry.axis) {
      fail("axis", `must be "${entry.axis}", the axis of ${entry.id}, found "${item.axis}"`);
    }
  }
  if (item.kind !== undefined) {
    if (!KINDS.includes(item.kind)) {
      fail("kind", `must be "measured" or "judgment", found ${show(item.kind)}`);
    } else if (entry !== undefined && item.kind !== entry.kind) {
      fail("kind", `must be "${entry.kind}", the kind of ${entry.id}, found "${item.kind}"`);
    }
  }

  checkMeasuredFields(item, { index, rule, fail, warn, ctx });
  if (item.impact !== undefined && !IMPACTS.includes(item.impact)) {
    fail("impact", `must be high, medium or low, found ${show(item.impact)}`);
  }
  if (Array.isArray(item.evidence)) {
    // An empty list is valid: some measured findings are absences (for example SEC-03 with no secret file), and
    // they have no file to cite.
    item.evidence.forEach((entryValue, position) =>
      checkEvidence(entryValue, `${at}.evidence[${position}]`, { index, rule, ctx }),
    );
  } else if (item.evidence !== undefined) {
    fail("evidence", "must be a list of { file, line, endLine, quote } objects");
  }

  for (const name of ["summary", "recommendation"]) {
    const value = item[name];
    if (value === undefined) continue;
    if (typeof value !== "string") fail(name, "must be text");
    else if (value.trim() === "") fail(name, "is blank; write one sentence");
    else checkNumbers(value, `${at}.${name}`, { index, rule, ctx });
  }
  const testText = item.testInFunction2;
  if (typeof testText === "string") {
    if (testText.trim() === "") fail("testInFunction2", "is blank; write the test, or use null");
    else checkNumbers(testText, `${at}.testInFunction2`, { index, rule, ctx });
  } else if (testText !== undefined && testText !== null) {
    fail("testInFunction2", "must be text or null");
  }

  checkSecrets(item, at, { index, rule, ctx });
}

// The fields that depend on the kind. A measured finding names one measured finding of its rule, and a judgment finding
// may name the measured findings that support it.
function checkMeasuredFields(item, { index, rule, fail, warn, ctx }) {
  const { kind } = item;
  if (kind === "measured" && item.measuredFindingId === undefined) {
    fail("measuredFindingId", `required for a measured finding; name a measuredFindings entry of measurements.json for ${rule ?? "this rule"}`);
  }
  if (kind === "measured" && item.measuredSupport !== undefined) {
    fail("measuredSupport", "is only for judgment findings; remove it");
  }
  if (kind === "judgment" && item.measuredFindingId !== undefined) {
    fail("measuredFindingId", "is only for measured findings; remove it");
  }

  if (kind === "measured" && item.measuredFindingId !== undefined) {
    const id = item.measuredFindingId;
    const measured = typeof id === "string" ? ctx.measured.get(id) : undefined;
    if (measured === undefined) {
      fail("measuredFindingId", `${show(id)} is not a measured finding of measurements.json`);
    } else if (rule !== null && measured.rule !== rule) {
      fail("measuredFindingId", `${id} is a finding of ${measured.rule}, not of ${rule}; name a measured finding of ${rule}`);
    } else if (IMPACTS.includes(item.impact) && item.impact !== measured.impact) {
      warn("impact", `is ${item.impact}, but ${id} has impact ${measured.impact}; a measured finding takes its impact from its numbers`);
    }
  }

  if (item.measuredSupport !== undefined) {
    if (!Array.isArray(item.measuredSupport)) {
      fail("measuredSupport", 'must be a list of measured finding ids, such as ["mf-1"]');
      return;
    }
    item.measuredSupport.forEach((id, position) => {
      if (typeof id !== "string" || !ctx.measured.has(id)) {
        fail(`measuredSupport[${position}]`, `${show(id)} is not a measured finding of measurements.json`);
      }
    });
  }
}

// Evidence -----------------------------------------------------------------------------------------

// Checks one evidence entry: its shape, then its file, line range and quote against the target.
function checkEvidence(entry, at, where) {
  const { index, rule, ctx } = where;
  const fail = (name, message) => addIssue(ctx.errors, index, rule, name === "" ? at : `${at}.${name}`, message);
  if (!isPlainObject(entry)) {
    fail("", "must be an object with file, and optionally line, endLine and quote");
    return;
  }
  for (const key of Object.keys(entry)) {
    if (!EVIDENCE_FIELDS.includes(key)) fail(key, `unknown field; the fields are ${EVIDENCE_FIELDS.join(", ")}`);
  }
  const { file, line, endLine, quote } = entry;
  if (file === undefined) fail("file", "missing required field");

  const hasLine = line !== undefined;
  let rangeOk = true;
  if (hasLine && !isPositiveInteger(line)) {
    fail("line", `must be a whole number from 1, found ${show(line)}`);
    rangeOk = false;
  }
  if (endLine !== undefined && !hasLine) {
    fail("endLine", "needs line, the first line of the range");
    rangeOk = false;
  } else if (endLine !== undefined && !isPositiveInteger(endLine)) {
    fail("endLine", `must be a whole number from 1, found ${show(endLine)}`);
    rangeOk = false;
  } else if (endLine !== undefined && isPositiveInteger(line) && endLine < line) {
    fail("endLine", `must not be before line (${line})`);
    rangeOk = false;
  }
  const quoteText = typeof quote === "string" && quote.trim() !== "" ? quote : null;
  if (quote !== undefined) {
    if (typeof quote !== "string") fail("quote", "must be text");
    else if (quoteText === null) fail("quote", "is blank; quote the text of the line");
    if (!hasLine) fail("quote", "needs line, the line where the quote is");
  }

  if (file === undefined) return;
  const problem = pathProblem(file);
  if (problem !== null) {
    fail("file", problem);
    return;
  }
  if (!hasLine) {
    const stat = ctx.target.stat(file);
    if (!stat.ok) fail("file", readProblem(file, stat.reason));
    else if (stat.type !== "file") fail("file", `${show(file)} is a folder; cite a file of it`);
    return;
  }
  if (!rangeOk) return;

  const read = readCached(ctx, file);
  if (!read.ok) {
    fail("file", readProblem(file, read.reason));
    return;
  }
  const lines = linesOf(read.text);
  const last = endLine ?? line;
  if (line > lines.length) {
    fail("line", `line ${line} is past the end of ${show(file)}, which has ${lines.length} lines`);
    return;
  }
  if (last > lines.length) {
    fail("endLine", `line ${last} is past the end of ${show(file)}, which has ${lines.length} lines`);
    return;
  }
  if (quoteText !== null) {
    const span = lines.slice(line - 1, last).join("\n");
    if (!collapse(span).includes(collapse(quoteText))) {
      const label = endLine === undefined ? `line ${line}` : `lines ${line}-${endLine}`;
      fail("quote", `does not appear on ${label} of ${show(file)}, with runs of spaces compared as one space`);
    }
  }
}

// Returns the problem with an evidence path, or null. Checked before any read, so a bad path is never opened.
function pathProblem(file) {
  if (typeof file !== "string") return "must be text: a path relative to the target, such as CLAUDE.md";
  if (file.trim() === "") return "is blank; give a path relative to the target";
  if (file.includes("\\")) return "must use forward slashes, not backslashes";
  if (file.includes("\0")) return "must not contain a NUL character";
  if (file.startsWith("/") || /^[A-Za-z]:/.test(file)) return "must be relative to the target, not an absolute path";
  if (file.split("/").some((part) => PARENT_SEGMENT.test(part))) {
    return "must not contain .. segments; stay inside the target";
  }
  return null;
}

function readProblem(file, reason) {
  return `${show(file)} ${READ_PROBLEMS[reason] ?? READ_PROBLEMS["read-error"]}`;
}

// Reads a file once per validation. The result is the one safe-fs returns: { ok, text } or { ok: false, reason }.
function readCached(ctx, file) {
  if (!ctx.reads.has(file)) ctx.reads.set(file, ctx.target.readText(file));
  return ctx.reads.get(file);
}

// The lines of a text, as an editor counts them: a final line break does not start a new line.
function linesOf(text) {
  if (text === "") return [];
  return text.replace(/\n$/, "").split("\n");
}

// Quotes and text are compared with runs of spaces, tabs and line breaks collapsed to one space, and trimmed.
function collapse(text) {
  return text.replace(/[ \t\r\n]+/g, " ").trim();
}

// Secrets ------------------------------------------------------------------------------------------

// Reports every string at or below value that holds a secret which is not masked. The value is never printed.
function checkSecrets(value, field, where) {
  const { index, rule, ctx } = where;
  if (typeof value === "string") {
    const kinds = unmaskedSecretKinds(value);
    if (kinds.length > 0) {
      addIssue(ctx.errors, index, rule, field,
        `holds a secret-shaped value that is not masked (${kinds.join(", ")}); replace it with its mask() form`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, position) => checkSecrets(item, `${field}[${position}]`, where));
  } else if (isPlainObject(value)) {
    for (const key of Object.keys(value)) checkSecrets(value[key], `${field}.${key}`, where);
  }
}

// The ids of the secret patterns that match text with a value that is not masked, sorted.
function unmaskedSecretKinds(text) {
  const kinds = [];
  for (const match of [...findSpecificSecrets(text), ...findGenericSecrets(text)]) {
    if (!isMasked(match.value)) kinds.push(match.id);
  }
  return [...new Set(kinds)].sort(compareText);
}

// Numbers -----------------------------------------------------------------------------------------

// Warns about each number token of the free text that measurements.json does not hold. One warning per distinct token.
function checkNumbers(text, field, where) {
  const { index, rule, ctx } = where;
  const seen = new Set();
  for (const match of stripReferences(text).matchAll(NUMBER_TOKEN)) {
    const token = match[0];
    if (seen.has(token)) continue;
    seen.add(token);
    if (!isKnownNumber(token, ctx.numbers)) {
      addIssue(ctx.warnings, index, rule, field,
        `number ${token} does not appear in measurements.json; check it against the measurement it comes from`);
    }
  }
}

// The text with its ids, paths, dates and versions replaced by spaces.
function stripReferences(text) {
  let stripped = text;
  for (const pattern of REFERENCE_PATTERNS) stripped = stripped.replace(pattern, " ");
  return stripped.replace(PATH_LIKE, (match) => (/[A-Za-z]/.test(match) ? " " : match));
}

// A token is known when one of its readings is a number of the scan: thousands, decimal or integer. A token with several
// separators that are not thousands is known when each part is.
function isKnownNumber(token, numbers) {
  if (THOUSANDS.test(token) || DECIMAL.test(token) || INTEGER.test(token)) {
    const readings = [];
    if (THOUSANDS.test(token)) readings.push(Number(token.replace(/[.,]/g, "")));
    if (DECIMAL.test(token)) readings.push(Number(token.replace(",", ".")));
    if (INTEGER.test(token)) readings.push(Number(token));
    return readings.some((value) => numbers.has(value));
  }
  return token.split(/[.,]/).every((part) => numbers.has(Number(part)));
}

// Every finite number of a JSON value, at any depth.
function numbersIn(value, out) {
  if (typeof value === "number" && Number.isFinite(value)) out.add(value);
  else if (Array.isArray(value)) for (const item of value) numbersIn(item, out);
  else if (isPlainObject(value)) for (const key of Object.keys(value)) numbersIn(value[key], out);
  return out;
}

// Measured findings of the scan, by id. A scan with no measured findings gives an empty map.
function measuredById(measurements) {
  const byId = new Map();
  if (!Array.isArray(measurements.measuredFindings)) return byId;
  for (const item of measurements.measuredFindings) {
    if (isPlainObject(item) && typeof item.id === "string") byId.set(item.id, item);
  }
  return byId;
}

// Helpers ------------------------------------------------------------------------------------------

// Adds an issue to a list. The list is either errors or warnings; both have the same shape.
function addIssue(list, finding, rule, field, message) {
  list.push({ finding, rule, field, message });
}

// A value as it may appear in a message: short, and never a secret. A value that looks like one is hidden.
function show(value) {
  const text = JSON.stringify(value) ?? String(value);
  if (findSpecificSecrets(text).length > 0 || findGenericSecrets(text).length > 0) {
    return "a value that looks like a secret";
  }
  return text.length > MAX_SHOWN ? `${text.slice(0, MAX_SHOWN - 3)}...` : text;
}

function isPositiveInteger(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
