// The views of a comparison of two scans: the object that scripts/lib/comparison.mjs writes as comparison.json.
// buildComparisonBlocks turns it into the blocks of the report model (report.mjs), renderComparisonMarkdown writes those blocks
// as Markdown, and renderComparisonHtml writes them as one HTML page. The fixed text of each view comes from the labels of the comparison's
// language, as compare.* keys. A value of the comparison (a target name, a path, a summary, a trigger) comes from the target or
// the agent: it is a text or a code run on one line, and no view reads it as markup. The HTML page has no script, no form, no
// link and no resource from outside; its style is the report's style, without the filter rules.

import { CLASSES, WARNING_CODES, isUtcTime } from "./comparison.mjs";
import { IMPACTS, KINDS, LANGUAGES } from "./findings-validate.mjs";
import { escapeHtml } from "./html.mjs";
import { isPlainObject } from "./json-out.mjs";
import { blocksHtml, fillPage, pagePolicy } from "./report-html.mjs";
import { createLabelParts, createLabeller } from "./report-labels.mjs";
import { formatNumber, inline, utcDate } from "./report-markdown.mjs";
import { blocksMarkdown } from "./report.mjs";
import { DEPTHS } from "./scanner.mjs";

// The label of each depth of a run, by its name in DEPTHS (the list of scanner.mjs).
const DEPTH_LABELS = Object.freeze(Object.fromEntries(DEPTHS.map((depth) => [depth, `compare.depth.${depth}`])));
// The headers of the table of the items of a class.
const ITEM_HEADERS = Object.freeze([
  "compare.table.rule",
  "compare.table.title",
  "compare.table.type",
  "compare.table.impact",
  "compare.table.key",
  "compare.table.summary",
]);
// The markers of templates/comparison.html. Each must appear exactly once.
const PAGE_MARKERS = Object.freeze(["lang", "csp", "title", "style", "body"]);
const PAGE_FILE = "templates/comparison.html";

/**
 * The blocks of the comparison: the title, the two runs side by side, the warnings, the counts by class, and one section per
 * class with its items. The blocks are those of the report model, so the Markdown and the HTML writers of the report write them.
 * @param {object} comparison The parsed comparison.json, as scripts/lib/comparison.mjs writes it.
 * @param {object} options
 * @param {Readonly<Record<string, string>>} options.labels The labels of the comparison's language, from labels.<language>.json.
 * @param {Map<string, string>} options.ruleTitles The title of each rule of the current catalog. A rule without a title shows a
 *   dash in its title cell.
 * @returns {import("./report.mjs").Block[]}
 * @throws {TypeError} If the comparison or an option has the wrong shape.
 * @throws {Error} If the labels have no text for a key, or a label has a placeholder without a value.
 */
export function buildComparisonBlocks(comparison, { labels, ruleTitles }) {
  checkComparison(comparison);
  if (!isPlainObject(labels)) throw new TypeError("labels must be the labels of the comparison's language");
  if (!(ruleTitles instanceof Map)) throw new TypeError("ruleTitles must be a Map from a rule id to its title");
  const ctx = createContext(comparison, labels, ruleTitles);
  return [
    { type: "heading", level: 1, runs: ctx.label("compare.title") },
    runsTable(ctx),
    { type: "heading", level: 2, runs: ctx.label("compare.warnings.title") },
    warningsBlock(ctx),
    { type: "heading", level: 2, runs: ctx.label("compare.counts.title") },
    countsTable(ctx),
    ...CLASSES.flatMap((name) => classBlocks(ctx, name)),
  ];
}

/**
 * The comparison as Markdown: its blocks, one blank line apart, and a line break at the end.
 * @param {object} comparison The parsed comparison.json.
 * @param {object} options See buildComparisonBlocks.
 * @returns {string}
 * @throws {TypeError} If the comparison or an option has the wrong shape.
 */
export function renderComparisonMarkdown(comparison, { labels, ruleTitles }) {
  return `${blocksMarkdown(buildComparisonBlocks(comparison, { labels, ruleTitles }))}\n`;
}

/**
 * The comparison as one HTML page, with no script and no resource from outside.
 * @param {object} comparison The parsed comparison.json.
 * @param {object} options
 * @param {Readonly<Record<string, string>>} options.labels The labels of the comparison's language.
 * @param {Map<string, string>} options.ruleTitles The title of each rule of the current catalog.
 * @param {string} options.template The text of templates/comparison.html.
 * @param {string} options.theme The text of templates/theme.css.
 * @param {string} options.css The text of templates/report.css.
 * @returns {{ html: string, csp: string }} csp is the Content-Security-Policy of the page, the one its meta element holds.
 * @throws {TypeError} If an argument has the wrong shape.
 * @throws {Error} If the stylesheet holds a closing style tag, or the template does not have each marker once.
 */
export function renderComparisonHtml(comparison, { labels, ruleTitles, template, theme, css }) {
  for (const [name, text] of Object.entries({ template, theme, css })) {
    if (typeof text !== "string") throw new TypeError(`${name} must be the text of its file`);
  }
  const blocks = buildComparisonBlocks(comparison, { labels, ruleTitles });
  const t = createLabeller(labels);
  // The style is the one text the policy names by its hash, so it is kept as it is, with its line breaks as LF, as the
  // report does.
  const style = [theme, css].join("\n").replace(/\r\n?/g, "\n");
  if (/<\/style/i.test(style)) throw new Error("the stylesheet must not hold a closing style tag");
  const csp = pagePolicy(style);
  const values = {
    lang: escapeHtml(comparison.language),
    csp: escapeHtml(csp),
    title: escapeHtml(t("compare.title")),
    style,
    body: blocksHtml(blocks),
  };
  return { html: fillPage(template, values, { file: PAGE_FILE, markers: PAGE_MARKERS }), csp };
}

// Context and runs -------------------------------------------------------------------------------------

// The helpers the blocks share. Each one returns runs. A fixed text is a label; a value of the comparison is a text or a code
// run on one line, and a number is formatted in the language of the comparison.
function createContext(comparison, labels, ruleTitles) {
  const parts = createLabelParts(labels);
  const label = (key, values = {}) =>
    parts(key, values).flatMap((piece) => (typeof piece === "string" ? [labelNode(piece)] : piece));
  // A value as one line: a line break becomes a space. An empty value is the dash of the labels, since a code span cannot
  // be empty.
  const line = (value, node) => {
    const text = inline(String(value));
    return text === "" ? label("compare.value.empty") : [node(text)];
  };
  return {
    comparison,
    ruleTitles,
    label,
    text: (value) => line(value, textNode),
    code: (value) => line(value, codeNode),
    num: (value) => [textNode(formatNumber(value, comparison.language))],
  };
}

const textNode = (text) => ({ type: "text", text });
const labelNode = (text) => ({ type: "label", text });
const codeNode = (text) => ({ type: "code", text });

// The runs of several parts, one after another, with the separator between them.
function joinRuns(parts, separator) {
  return parts.flatMap((part, index) => (index === 0 ? part : [...separator, ...part]));
}

// The runs of a depth: its label. A depth outside the three is an error, not a raw value (checkRun refuses it first).
function depthRuns(ctx, depth) {
  if (!Object.hasOwn(DEPTH_LABELS, depth)) throw new TypeError("a run has a depth that is not quick, standard or deep");
  return ctx.label(DEPTH_LABELS[depth]);
}

// The runs of a scope: the whole target, or the folders as code.
function scopeRuns(ctx, scope) {
  if (scope === null) return ctx.label("compare.scope.whole");
  if (scope.length === 0) return ctx.label("compare.value.none");
  return joinRuns(
    scope.map((folder) => ctx.code(folder)),
    ctx.label("compare.list.separator"),
  );
}

// The runs of a catalog: its rules and its digest, or that it is not registered.
function catalogRuns(ctx, catalog) {
  if (catalog === null) return ctx.label("compare.catalog.unregistered");
  return ctx.label("compare.catalog.value", { count: ctx.num(catalog.count), hash: ctx.code(catalog.sha256) });
}

// The runs of an impact: its label, checked against the known impacts.
function impactLabel(ctx, impact) {
  if (!IMPACTS.includes(impact)) throw new TypeError("an item has an impact that is not high, medium or low");
  return ctx.label(`compare.impact.${impact}`);
}

// Runs and table of the two runs ------------------------------------------------------------------------

// One row per field of a run, with the value of run A and of run B.
function runsTable(ctx) {
  const { a, b } = ctx.comparison.runs;
  const fields = [
    ["compare.field.name", (run) => ctx.code(run.name)],
    ["compare.field.target", (run) => ctx.code(run.target)],
    ["compare.field.commit", (run) => (run.head === null ? ctx.label("compare.value.noCommit") : ctx.code(run.head))],
    ["compare.field.scanDate", (run) => ctx.text(utcDate(run.scannedAt))],
    ["compare.field.depth", (run) => depthRuns(ctx, run.depth)],
    ["compare.field.scope", (run) => scopeRuns(ctx, run.scope)],
    ["compare.field.catalog", (run) => catalogRuns(ctx, run.catalog)],
    ["compare.field.schema", (run) => ctx.num(run.schemaVersion)],
    ["compare.field.findings", (run) => ctx.num(run.findings)],
    ["compare.field.measured", (run) => ctx.num(run.measuredFindings)],
  ];
  return {
    type: "table",
    headers: [ctx.label("compare.table.field"), ctx.label("compare.table.runA"), ctx.label("compare.table.runB")],
    rows: fields.map(([key, valueOf]) => [ctx.label(key), valueOf(a), valueOf(b)]),
  };
}

// Warnings ----------------------------------------------------------------------------------------------

// One item per warning, in the order of the comparison; the empty list is a sentence.
function warningsBlock(ctx) {
  const { warnings } = ctx.comparison;
  if (warnings.length === 0) return { type: "paragraph", runs: ctx.label("compare.warnings.none") };
  return { type: "list", items: warnings.map((warning) => warningRuns(ctx, warning)) };
}

// The text of a warning, with the values of its two runs in the form of its code.
function warningRuns(ctx, { code, a, b }) {
  return ctx.label(`compare.warning.${code}`, { a: warningValueRuns(ctx, code, a), b: warningValueRuns(ctx, code, b) });
}

// The value of a warning, as the code says what it is: a target, a scope, a depth, a catalog or a schema version.
function warningValueRuns(ctx, code, value) {
  switch (code) {
    case "target-changed":
      return ctx.code(value);
    case "scope-changed":
      return scopeRuns(ctx, value);
    case "depth-changed":
      return depthRuns(ctx, value);
    case "catalog-changed":
    case "catalog-unknown":
      return catalogRuns(ctx, value);
    case "schema-changed":
      return ctx.num(value);
    default:
      throw new TypeError("a warning has a code that is not known");
  }
}

// Counts by class -------------------------------------------------------------------------------------

function countsTable(ctx) {
  const rows = CLASSES.map((name) => [ctx.label(`compare.class.${name}`), ctx.num(ctx.comparison.counts[name])]);
  return { type: "table", headers: [ctx.label("compare.table.class"), ctx.label("compare.table.count")], rows };
}

// Sections by class ---------------------------------------------------------------------------------------

// The heading of a class and its table of items, in the order of the comparison; an empty class is a sentence.
function classBlocks(ctx, name) {
  const heading = { type: "heading", level: 2, runs: ctx.label(`compare.section.${name}`) };
  const items = ctx.comparison.items.filter((item) => item.class === name);
  if (items.length === 0) return [heading, { type: "paragraph", runs: ctx.label("compare.items.none") }];
  return [
    heading,
    {
      type: "table",
      headers: ITEM_HEADERS.map((key) => ctx.label(key)),
      rows: items.map((item) => itemRow(ctx, item)),
    },
  ];
}

// The row of an item: its rule and title, its type, its impact (both sides when there are two), its key and its summary.
function itemRow(ctx, item) {
  return [
    ctx.code(item.rule),
    titleRuns(ctx, item.rule),
    ctx.label(`compare.kind.${item.kind}`),
    impactRuns(ctx, item),
    keyRuns(ctx, item),
    summaryRuns(ctx, item),
  ];
}

// The title of a rule of the current catalog. A rule that the catalog does not have shows the dash, and its id is in the row.
function titleRuns(ctx, rule) {
  const title = ctx.ruleTitles.get(rule);
  return title === undefined ? ctx.label("compare.value.empty") : ctx.text(title);
}

// "A → B" when the item has both sides and their impacts differ; otherwise the one impact that the item has.
function impactRuns(ctx, item) {
  if (item.a !== null && item.b !== null && item.a.impact !== item.b.impact) {
    return ctx.label("compare.impact.change", { from: impactLabel(ctx, item.a.impact), to: impactLabel(ctx, item.b.impact) });
  }
  return impactLabel(ctx, (item.b ?? item.a).impact);
}

// The key of a measured item is the path of its measure and its trigger, if any. The key of a judgment item is its files.
function keyRuns(ctx, item) {
  if (item.kind === "measured") {
    const ref = ctx.code(item.key.measurementRef);
    if (item.key.trigger === null) return ref;
    return ctx.label("compare.key.trigger", { ref, trigger: ctx.code(item.key.trigger) });
  }
  if (item.key.files.length === 0) return ctx.label("compare.value.empty");
  return joinRuns(
    item.key.files.map((file) => ctx.code(file)),
    ctx.label("compare.list.separator"),
  );
}

// The summary of the side that stays: B, or A when the item has no B. A measured finding that findings.json does not cite has
// no summary of its own, so it says so.
function summaryRuns(ctx, item) {
  const side = item.b ?? item.a;
  if (item.kind === "measured" && side.cited === false) return ctx.label("compare.summary.uncited");
  return side.summary === null ? ctx.label("compare.value.empty") : ctx.text(side.summary);
}

// Checks ----------------------------------------------------------------------------------------------------

// The shape that the views read. A value outside it is an error, so no view writes a raw value by mistake.
function checkComparison(comparison) {
  if (!isPlainObject(comparison)) throw new TypeError("comparison must be the parsed comparison.json");
  if (!LANGUAGES.includes(comparison.language)) throw new TypeError(`comparison.language must be one of ${LANGUAGES.join(", ")}`);
  if (!isPlainObject(comparison.runs)) throw new TypeError("comparison.runs must hold the runs a and b");
  checkRun(comparison.runs.a, "runs.a");
  checkRun(comparison.runs.b, "runs.b");
  if (!Array.isArray(comparison.warnings)) throw new TypeError("comparison.warnings must be a list");
  comparison.warnings.forEach((warning, index) => checkWarning(warning, index));
  if (!isPlainObject(comparison.counts)) throw new TypeError("comparison.counts must be an object of counts");
  for (const name of CLASSES) {
    if (!Number.isInteger(comparison.counts[name]) || comparison.counts[name] < 0) {
      throw new TypeError(`comparison.counts.${name} must be a count`);
    }
  }
  if (!Array.isArray(comparison.items)) throw new TypeError("comparison.items must be a list");
  comparison.items.forEach((item, index) => checkItem(item, index));
}

// A run of the comparison: its texts, its scan time, its depth, its scope and catalog, and its whole numbers. The name of the
// run and of each field is in each message; a value is never quoted.
function checkRun(run, name) {
  if (!isPlainObject(run)) throw new TypeError(`${name} must be a run of comparison.json`);
  for (const key of ["name", "target"]) {
    if (typeof run[key] !== "string") throw new TypeError(`${name}.${key} must be text`);
  }
  if (run.head !== null && typeof run.head !== "string") throw new TypeError(`${name}.head must be text or null`);
  if (!isUtcTime(run.scannedAt)) throw new TypeError(`${name}.scannedAt must be an ISO 8601 time in UTC`);
  if (!DEPTHS.includes(run.depth)) throw new TypeError(`${name}.depth must be one of ${DEPTHS.join(", ")}`);
  checkScope(run.scope, `${name}.scope`);
  if (run.catalog !== null) mustBe(isCatalog(run.catalog), `${name}.catalog`, "an object with a count and a sha256, or null");
  for (const key of ["schemaVersion", "findings", "measuredFindings"]) {
    mustBe(Number.isInteger(run[key]), `${name}.${key}`, "a whole number");
  }
}

// A warning: its code, and the two values that its code says (WARNING_VALUES). The message names the warning and its side.
function checkWarning(warning, index) {
  if (!isPlainObject(warning)) throw new TypeError(`warnings[${index}] must be an object`);
  if (!WARNING_CODES.includes(warning.code)) {
    throw new TypeError(`warnings[${index}].code must be one of ${WARNING_CODES.join(", ")}`);
  }
  const check = WARNING_VALUES[warning.code];
  check(warning.a, `warnings[${index}].a`);
  check(warning.b, `warnings[${index}].b`);
}

// The check of each value of a warning, by its code: what the value must be. A check throws with the place of the value, never
// with the value itself.
const WARNING_VALUES = Object.freeze({
  "target-changed": (value, at) => mustBe(typeof value === "string", at, "text"),
  "scope-changed": (value, at) => checkScope(value, at),
  "depth-changed": (value, at) => mustBe(DEPTHS.includes(value), at, `one of ${DEPTHS.join(", ")}`),
  "catalog-changed": (value, at) => mustBe(isCatalog(value), at, "an object with a count and a sha256"),
  "catalog-unknown": (value, at) =>
    mustBe(value === null || isCatalog(value), at, "an object with a count and a sha256, or null"),
  "schema-changed": (value, at) => mustBe(Number.isInteger(value), at, "a whole number"),
});

// A scope: null for the whole target, or a list of folders, each one text. A folder that is not text is named by its index.
function checkScope(scope, at) {
  if (scope === null) return;
  mustBe(Array.isArray(scope), at, "a list of text, or null");
  scope.forEach((folder, position) => mustBe(typeof folder === "string", `${at}[${position}]`, "text"));
}

// A catalog: an object with the count of its rules as a whole number and its digest as text.
function isCatalog(value) {
  return isPlainObject(value) && Number.isInteger(value.count) && typeof value.sha256 === "string";
}

// Throws "<at> must be <expected>" unless ok holds. The message names the place of the value, never the value.
function mustBe(ok, at, expected) {
  if (!ok) throw new TypeError(`${at} must be ${expected}`);
}

// An item: its class, kind, rule and key, and its sides. A side is checked by the kind of its item.
function checkItem(item, index) {
  const at = `items[${index}]`;
  if (!isPlainObject(item)) throw new TypeError(`${at} must be an object`);
  if (!CLASSES.includes(item.class)) throw new TypeError(`${at}.class must be one of ${CLASSES.join(", ")}`);
  if (!KINDS.includes(item.kind)) throw new TypeError(`${at}.kind must be one of ${KINDS.join(", ")}`);
  if (typeof item.rule !== "string") throw new TypeError(`${at}.rule must be text`);
  if (!isPlainObject(item.key)) throw new TypeError(`${at}.key must be an object`);
  if (item.kind === "measured") {
    if (typeof item.key.measurementRef !== "string") throw new TypeError(`${at}.key.measurementRef must be text`);
    if (item.key.trigger !== null && typeof item.key.trigger !== "string") {
      throw new TypeError(`${at}.key.trigger must be text or null`);
    }
  } else if (!Array.isArray(item.key.files) || !item.key.files.every((file) => typeof file === "string")) {
    throw new TypeError(`${at}.key.files must be a list of text`);
  }
  if (item.a === null && item.b === null) throw new TypeError(`${at} has neither side a nor side b`);
  for (const [name, side] of [["a", item.a], ["b", item.b]]) {
    if (side !== null) checkSide(side, item.kind, `${at}.${name}`);
  }
}

// One side of an item: its impact, and its summary. A measure also says whether findings.json cites it.
function checkSide(side, kind, at) {
  if (!isPlainObject(side)) throw new TypeError(`${at} must be an object`);
  if (!IMPACTS.includes(side.impact)) throw new TypeError(`${at}.impact must be one of ${IMPACTS.join(", ")}`);
  if (kind === "measured") {
    if (typeof side.cited !== "boolean") throw new TypeError(`${at}.cited must be true or false`);
    if (side.summary !== null && typeof side.summary !== "string") throw new TypeError(`${at}.summary must be text or null`);
  } else if (typeof side.summary !== "string") {
    throw new TypeError(`${at}.summary must be text`);
  }
}
