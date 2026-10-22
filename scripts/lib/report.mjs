// Builds the report model, and the Markdown view that writes it as report.md. The scan (measurements.json) and the agent's
// findings (findings.json) are the input; the findings must already be validated (findings-validate.mjs). buildReportModel
// turns them into the model: the sections as lists of blocks, with every number already formatted, so a view only writes it.
// renderMarkdown is one view: it writes the model as Markdown and places the sections in templates/report.md by fillTemplate.
// Every string from the target, the measurements or the agent goes through the redactor before it reaches the model, and
// every number is read from measurements.json through its measurementRef: the agent's text never supplies a number. The
// model holds no markup; each view escapes the text for its own format.
//
// Findings are shown by axis, then by impact (high, medium, low), then by rule id, then by input order. A measured
// finding that no finding of findings.json cites (by measuredFindingId) is still shown, marked as not explained by the
// agent; buildReportModel lists those so the command line can warn about them. Evidence outside the target carries its layer
// and is marked in its row; the limits say what the scan read beyond the target, from meta.include. The skipped items
// outside the target (the user layer's warnings and the parent-folder files that were not read) are marked in the limits table.
// With a scope (measurements.scope), the header names the scope folders, and the limits say what was measured inside them,
// what was read outside them and what was not analyzed. With a layer plan (context.byLayer), the context section has one row
// per layer: what it loads on demand there, and its nested skills, which are not verified and are not in the total.

import { KINDS } from "./agent-harness.mjs";
import { AXES, DEFAULT_LANGUAGE } from "./findings-validate.mjs";
import { isPlainObject } from "./json-out.mjs";
import { THRESHOLDS_STATUS } from "./measured-findings.mjs";
import { createRedactor } from "./redact.mjs";
import { createLabelParts } from "./report-labels.mjs";
import { codeSpan, escapePipes, formatNumber, inline, link, table, utcDate } from "./report-markdown.mjs";

/** The section markers of templates/report.md. Each must appear exactly once. */
export const MARKERS = Object.freeze([
  "header",
  "summary",
  "findings",
  "context",
  "function2",
  "limits",
  "sources",
  "appendix",
]);

const MARKER = /\{\{\s*([^{}]*?)\s*\}\}/g;
const IMPACT_RANK = Object.freeze({ high: 3, medium: 2, low: 1 });
const SUMMARY_ROWS = 5;
const APPENDIX_ROWS = 50;
const COMPONENT_LABELS = Object.freeze({
  skills: "component.skills",
  commands: "component.commands",
  subagents: "component.subagents",
  memory: "component.memory",
});
const STATUS_LABELS = Object.freeze({ provisional: "status.provisional" });
// The agent whose every kind is evaluated: its permissions, hooks, settings, subagents and context budget are measured.
const CLAUDE_CODE = "claude-code";
// A trigger whose name does not say the state it stands for: its label is shown in brackets after the name.
const TRIGGER_NOTES = Object.freeze({ "hook-not-verified": "trigger.hookNotVerified" });
// The mark of an evidence entry that lies outside the target, by its layer.
const LAYER_LABELS = Object.freeze({ user: "layer.user", ancestor: "layer.ancestor" });
// The source column of a parent-folder file that the walk did not read: the memory measure, which lists it.
const ANCESTOR_SOURCE = "memory";
// The fields of measurements.json that the report reads. Their presence is checked before anything is rendered.
const REQUIRED_FIELDS = Object.freeze([
  "/meta/tool",
  "/meta/scannedAt",
  "/meta/targetRoot",
  "/target/name",
  "/target/git/head",
  "/target/fileCount",
  "/warnings",
  "/measuredFindings",
  "/undeterminable",
  "/candidates",
  "/context/alwaysLoaded/byComponent",
  "/context/alwaysLoaded/unknownStatic",
  "/context/alwaysLoaded/estTokensTotal",
  "/context/alwaysLoaded/estMethod",
  "/security/destructiveCoverage/mode",
  "/code/duplication/duplicatedLinesPct",
  "/code/duplication/filesScanned",
  "/structure/mapCoverage/dirs",
  "/structure/mapCoverage/mentioned",
]);

/**
 * The first field of measurements.json that the report needs and that is missing.
 * @param {unknown} measurements The parsed measurements.json.
 * @returns {string | null} A JSON pointer, or null when every field is there.
 */
export function missingField(measurements) {
  if (!isPlainObject(measurements)) return "a JSON object";
  return REQUIRED_FIELDS.find((pointer) => pointerValue(measurements, pointer) === undefined) ?? null;
}

/**
 * Places the section texts in the template. The replacement is one pass over the template, so text inside a section
 * is never read as a marker.
 * @param {string} template The text of templates/report.md.
 * @param {Record<string, string>} sections One text per marker in MARKERS.
 * @returns {string}
 * @throws {Error} If the template has an unknown marker, or a marker that is missing or repeated.
 */
export function fillTemplate(template, sections) {
  const found = [...template.matchAll(MARKER)].map((match) => match[1]);
  for (const name of found) {
    if (!MARKERS.includes(name)) throw new Error(`templates/report.md has an unknown marker {{${name}}}`);
  }
  for (const name of MARKERS) {
    const count = found.filter((item) => item === name).length;
    if (count !== 1) throw new Error(`templates/report.md must have the marker {{${name}}} once, found ${count}`);
  }
  return template.replace(MARKER, (whole, name) => sections[name]);
}

/**
 * Renders the report: the model, and its Markdown view.
 * @param {object} options
 * @param {object} options.measurements The parsed measurements.json of the scan.
 * @param {object} options.findings The parsed findings.json, validated.
 * @param {ReturnType<import("./report-catalog.mjs").readCatalog>} options.catalog The catalog for the report.
 * @param {Readonly<Record<string, string>>} options.labels The labels of the language of findings.json.
 * @param {string} options.template The text of templates/report.md.
 * @returns {{ markdown: string, unexplained: Array<{ id: string, rule: string }>, model: ReportModel }} unexplained lists
 *   the measured findings that findings.json does not cite.
 * @throws {TypeError} If an input has the wrong shape.
 * @throws {Error} If a measurementRef does not resolve, a rule or source is missing from the catalog, or a label is missing.
 */
export function renderReport({ measurements, findings, catalog, labels, template }) {
  const model = buildReportModel({ measurements, findings, catalog, labels });
  return { markdown: renderMarkdown(model, template), unexplained: model.unexplained, model };
}

// The report model -----------------------------------------------------------------------------------------

/**
 * The report model: the report as plain data, with no markup in any string. Each section is a list of blocks. A line of
 * text is a list of runs, and every view writes the runs in its own format.
 *
 * @typedef {{ type: "text", text: string }} TextRun Computed or target text, redacted and on one line. Never escaped.
 * @typedef {{ type: "label", text: string }} LabelRun Fixed text of labels.<language>.json. Never escaped.
 * @typedef {{ type: "code", text: string }} CodeRun Text shown as code, redacted. Never empty: an empty value is a LabelRun.
 * @typedef {{ type: "strong", runs: Run[] }} StrongRun Bold text.
 * @typedef {{ type: "link", label: string, url: string }} LinkRun A link. Both strings are redacted; the url is the address.
 * @typedef {TextRun | LabelRun | CodeRun | StrongRun | LinkRun} Run
 * @typedef {Run[]} Runs One line of text.
 * @typedef {{ type: "heading", level: number, runs: Runs }} HeadingBlock Level 1 to 4.
 * @typedef {{ type: "paragraph", runs: Runs }} ParagraphBlock
 * @typedef {{ type: "fields", items: Array<{ label: Runs, runs: Runs }> }} FieldsBlock One "label: value" line per item.
 * @typedef {{ type: "table", headers: Runs[], rows: Runs[][] }} TableBlock Every row has one cell per header.
 * @typedef {{ type: "list", items: Runs[] }} ListBlock
 * @typedef {{ type: "finding", ruleId: string, axis: string, impact: string, blocks: Block[] }} FindingBlock A finding and
 *   its blocks. The axis and the impact (high, medium or low) let a view filter the findings.
 * @typedef {HeadingBlock | ParagraphBlock | FieldsBlock | TableBlock | ListBlock | FindingBlock} Block
 * @typedef {{ language: string, sections: Record<string, Block[]>, unexplained: Array<{ id: string, rule: string }> }} ReportModel
 */

/**
 * Builds the report model from the inputs. This does the checks and all the work; a view only writes the model.
 * @param {object} options
 * @param {object} options.measurements The parsed measurements.json of the scan.
 * @param {object} options.findings The parsed findings.json, validated.
 * @param {ReturnType<import("./report-catalog.mjs").readCatalog>} options.catalog The catalog for the report.
 * @param {Readonly<Record<string, string>>} options.labels The labels of the language of findings.json.
 * @returns {ReportModel}
 * @throws {TypeError} If an input has the wrong shape.
 * @throws {Error} If a measurementRef does not resolve, a rule or source is missing from the catalog, or a label is missing.
 */
export function buildReportModel({ measurements, findings, catalog, labels }) {
  if (!isPlainObject(findings) || !Array.isArray(findings.findings)) {
    throw new TypeError("findings must be the parsed findings.json, with a findings list");
  }
  const missing = missingField(measurements);
  if (missing !== null) throw new TypeError(`measurements.json has no ${missing}`);

  const language = findings.language ?? DEFAULT_LANGUAGE;
  const ctx = createContext({ measurements, catalog, labels, language });
  const entries = collectEntries(ctx, findings.findings);
  return {
    language,
    sections: {
      header: headerSection(ctx),
      summary: summarySection(ctx, entries),
      findings: findingsSection(ctx, entries),
      context: contextSection(ctx),
      function2: function2Section(ctx, entries),
      limits: limitsSection(ctx),
      sources: sourcesSection(ctx, entries),
      appendix: appendixSection(ctx),
    },
    unexplained: entries
      .filter((entry) => entry.agent === null)
      .map((entry) => ({ id: entry.measured.id, rule: entry.measured.rule })),
  };
}

// Context and entries ------------------------------------------------------------------------------

// The helpers the sections share. Each one returns runs. A text from the target or the measurements is redacted, and a
// number is formatted here, once, so a view never formats or escapes a value.
function createContext({ measurements, catalog, labels, language }) {
  const parts = createLabelParts(labels);
  const redact = createRedactor({ root: measurements.meta.targetRoot });
  const plain = (value) => inline(redact(String(value)));
  const label = (key, values = {}) =>
    parts(key, values).flatMap((piece) => (typeof piece === "string" ? markedRuns(piece) : piece));
  return {
    label,
    // A fixed name shown as code, such as a mode. Its text comes from a label, so it is not redacted.
    codeLabel: (key) => [codeNode(parts(key).join(""))],
    language,
    measurements,
    included: includedOf(measurements),
    catalog,
    measured: new Map(measurements.measuredFindings.map((item) => [item.id, item])),
    num: (value) => [textNode(formatNumber(value, language))],
    text: (value) => [textNode(plain(value))],
    code: (value) => {
      const text = plain(value);
      return text === "" ? label("value.empty") : [codeNode(text)];
    },
    link: (text, url) => [{ type: "link", label: plain(text), url: plain(url) }],
  };
}

// The nodes of the model's text. Each one is a run, and a list of runs is a line.
const textNode = (text) => ({ type: "text", text });
const labelNode = (text) => ({ type: "label", text });
const codeNode = (text) => ({ type: "code", text });

// The runs of a fixed text of a label. A pair of backticks marks code, as in the labels that name a setting: those parts
// become code runs, so no view has to read Markdown.
function markedRuns(text) {
  const pieces = text.split("`");
  if (pieces.length % 2 === 0) throw new Error(`a label has a backtick that is not paired: ${text}`);
  return pieces.flatMap((piece, index) => {
    if (piece === "") return [];
    return [index % 2 === 1 ? codeNode(piece) : labelNode(piece)];
  });
}

// Joins runs and runs of runs into one line.
const runsOf = (...parts) => parts.flat();
// The separator text that the builder writes between parts. It is neither target text nor a label.
const glue = (text) => [textNode(text)];
// Bold text, such as the lead of a paragraph.
const bold = (runs) => [{ type: "strong", runs }];
// The runs of several parts, one after another, with the separator between them.
const between = (parts, separator) => parts.flatMap((part, index) => (index === 0 ? part : [...separator, ...part]));
// One "label: value" line of a fields block.
const field = (name, runs) => ({ label: name, runs });

// What the scan read beyond the target, from meta.include. The section is absent when no flag was given, so nothing was read.
function includedOf(measurements) {
  const include = measurements.meta.include ?? {};
  return { userLayer: include.userLayer === true, ancestors: include.ancestors === true };
}

// One entry per finding to show: each agent finding, then each measured finding that no agent finding cites.
// impact is the measured impact for a measured finding, and the agent's impact for a judgment finding.
function collectEntries(ctx, agentFindings) {
  for (const item of ctx.measurements.measuredFindings) {
    resolveRef(ctx, item.measurementRef);
    for (const trigger of item.triggers) resolveRef(ctx, trigger.measurementRef);
  }
  const entries = [];
  const cited = new Set();
  agentFindings.forEach((finding, index) => {
    const measured = finding.kind === "measured" ? measuredOf(ctx, finding.measuredFindingId) : null;
    if (measured !== null) cited.add(measured.id);
    entries.push({
      order: index,
      rule: ruleOf(ctx, finding.rule),
      impact: measured === null ? finding.impact : measured.impact,
      agent: finding,
      measured,
      support: (finding.measuredSupport ?? []).map((id) => measuredOf(ctx, id)),
    });
  });
  ctx.measurements.measuredFindings.forEach((item, index) => {
    if (cited.has(item.id)) return;
    entries.push({
      order: agentFindings.length + index,
      rule: ruleOf(ctx, item.rule),
      impact: item.impact,
      agent: null,
      measured: item,
      support: [],
    });
  });
  return entries;
}

// Within one axis: impact, then rule id, then input order.
function compareEntries(a, b) {
  return IMPACT_RANK[b.impact] - IMPACT_RANK[a.impact] || compareText(a.rule.id, b.rule.id) || a.order - b.order;
}

// Across axes, for the summary and the tests: impact, then axis order, then the rest.
function compareOverall(a, b) {
  return IMPACT_RANK[b.impact] - IMPACT_RANK[a.impact] || AXES.indexOf(a.rule.axis) - AXES.indexOf(b.rule.axis) || compareEntries(a, b);
}

function measuredOf(ctx, id) {
  const item = ctx.measured.get(id);
  if (item === undefined) throw new Error(`no measured finding ${String(id)} in measurements.json`);
  return item;
}

function ruleOf(ctx, id) {
  const rule = ctx.catalog.rules.get(id);
  if (rule === undefined) throw new Error(`rule ${String(id)} is not in the catalog`);
  return rule;
}

function sourceOf(ctx, id) {
  const source = ctx.catalog.sources.get(id);
  if (source === undefined) throw new Error(`source ${String(id)} is not in rules/sources.json`);
  return source;
}

// Values from measurements.json ------------------------------------------------------------------

// The value at a JSON pointer (RFC 6901), or undefined when it does not resolve.
function pointerValue(root, pointer) {
  if (typeof pointer !== "string" || (pointer !== "" && !pointer.startsWith("/"))) return undefined;
  let node = root;
  if (pointer === "") return node;
  for (const token of pointer.slice(1).split("/")) {
    const key = token.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(node)) {
      if (!/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= node.length) return undefined;
      node = node[Number(key)];
    } else if (isPlainObject(node) && Object.hasOwn(node, key)) {
      node = node[key];
    } else {
      return undefined;
    }
  }
  return node;
}

function resolveRef(ctx, ref) {
  const value = pointerValue(ctx.measurements, ref);
  if (value === undefined) throw new Error(`measurementRef ${String(ref)} does not resolve in measurements.json`);
  return value;
}

// A value as runs: numbers in the locale, strings as code, arrays and objects by their length or key count.
function valueRuns(ctx, value) {
  const { label } = ctx;
  if (value === null) return label("value.null");
  if (value === true) return label("value.true");
  if (value === false) return label("value.false");
  if (typeof value === "number") return ctx.num(value);
  if (typeof value === "string") return ctx.code(value);
  if (Array.isArray(value)) return label("value.list", { count: ctx.num(value.length) });
  if (isPlainObject(value)) return label("value.object", { count: ctx.num(Object.keys(value).length) });
  throw new TypeError("measurements.json holds a value that the report cannot show");
}

// The trigger groups of a measured finding: triggers with the same name, impact and threshold count as one line.
function triggerGroups(item) {
  const groups = new Map();
  for (const trigger of item.triggers) {
    const threshold = trigger.threshold ?? null;
    const key = JSON.stringify([trigger.trigger, trigger.impact, threshold === null ? null : threshold.key]);
    if (!groups.has(key)) groups.set(key, { trigger: trigger.trigger, impact: trigger.impact, threshold, refs: [] });
    groups.get(key).refs.push(trigger.measurementRef);
  }
  return [...groups.values()]
    .map((group) => ({ ...group, count: group.refs.length }))
    .sort(
      (a, b) =>
        IMPACT_RANK[b.impact] - IMPACT_RANK[a.impact] ||
        compareText(a.trigger, b.trigger) ||
        compareText(a.threshold?.key ?? "", b.threshold?.key ?? ""),
    );
}

function triggerRow(ctx, group) {
  const { label } = ctx;
  const single = group.count === 1 ? resolveRef(ctx, group.refs[0]) : undefined;
  const value = single === undefined || isObjectValue(single) ? label("value.empty") : valueRuns(ctx, single);
  const threshold =
    group.threshold === null
      ? label("value.empty")
      : label("threshold.cell", {
          key: ctx.code(group.threshold.key),
          value: valueRuns(ctx, group.threshold.value),
          status: statusRuns(ctx),
        });
  const name = Object.hasOwn(TRIGGER_NOTES, group.trigger)
    ? runsOf(ctx.code(group.trigger), glue(" ("), label(TRIGGER_NOTES[group.trigger]), glue(")"))
    : ctx.code(group.trigger);
  return [name, ctx.num(group.count), label(`impact.${group.impact}`), value, threshold];
}

function isObjectValue(value) {
  return value !== null && typeof value === "object";
}

function statusRuns(ctx) {
  const key = STATUS_LABELS[THRESHOLDS_STATUS];
  if (key === undefined) throw new Error(`no label for the threshold status "${String(THRESHOLDS_STATUS)}"`);
  return ctx.label(key);
}

// The permission mode that the SEC-02 outcomes use, or null for the default mode. The scan applies the project
// defaultMode only when it takes effect; otherwise its outcomes use default (destructive-commands.mjs).
function usedMode(measurements) {
  const mode = measurements.security.destructiveCoverage.mode;
  return mode !== null && mode.effect === "applies" ? mode.value : null;
}

// Header --------------------------------------------------------------------------------------------

function headerSection(ctx) {
  const { label, measurements: m, catalog } = ctx;
  const head = m.target.git.head;
  const fields = [
    field(label("header.target"), ctx.code(m.target.name)),
    ...scopeFields(ctx),
    field(label("header.commit"), head === null ? label("value.none") : ctx.code(head)),
    field(label("header.scanDate"), ctx.text(utcDate(m.meta.scannedAt))),
    field(label("header.axes"), between(AXES.map((axis) => label(`axis.${axis}`)), label("list.separator"))),
    field(label("header.tool"), ctx.code(m.meta.tool)),
    field(
      label("header.catalog"),
      label("header.catalogValue", { count: ctx.num(catalog.version.count), hash: ctx.code(catalog.version.sha256) }),
    ),
  ];
  return [
    { type: "heading", level: 1, runs: label("header.title") },
    { type: "fields", items: fields },
    ...agentBlocks(ctx),
  ];
}

// The scope of the run, as one header field, when the scan had one: its folders and the inherited folders, as code. Nothing
// is written without a scope, so a report of a scan without one is unchanged.
function scopeFields(ctx) {
  const { label, measurements: m } = ctx;
  if (m.scope === undefined) return [];
  const folders = between(m.scope.folders.map((folder) => ctx.code(folder)), label("list.separator"));
  const inherited = between(m.scope.inherited.map((folder) => ctx.code(folder)), label("list.separator"));
  return [field(label("header.scope"), label("header.scopeValue", { folders, inherited }))];
}

// The agents that the scan detected, one row each, in the order of agentHarness.agents. Every kind of Claude Code is evaluated:
// its permissions, hooks, settings, subagents and context budget are measured. Another agent gets only its instructions
// evaluated, because the instruction rules (RUL-01 to RUL-04) read the instruction files of any agent. Its settings and hooks
// are checked only for whether a known agent loads them (SEC-04, SEC-05), and its other kinds are shown as detected, content
// not evaluated.
function agentBlocks(ctx) {
  const { label, measurements: m } = ctx;
  const agents = listOf(m.agentHarness?.agents);
  if (agents.length === 0) return [{ type: "fields", items: [field(label("header.agents"), label("value.none"))] }];
  const items = listOf(m.agentHarness?.items);
  const rows = agents.map((agent) => {
    const kinds = kindsOf(items, agent.id);
    const evaluated = agent.id === CLAUDE_CODE ? kinds : kinds.filter((kind) => kind === "instructions");
    const notEvaluated = kinds.filter((kind) => !evaluated.includes(kind));
    return [label(`agent.${agent.id}`), kindList(ctx, evaluated), kindList(ctx, notEvaluated)];
  });
  const headers = [label("table.agent"), label("table.evaluated"), label("table.detectedOnly")];
  return [
    { type: "paragraph", runs: bold(runsOf(label("header.agents"), glue(":"))) },
    { type: "table", headers, rows },
  ];
}

// The distinct kinds of the items of one agent, in the order of KINDS.
function kindsOf(items, agentId) {
  const present = new Set(items.filter((item) => item.agent === agentId).map((item) => item.kind));
  return KINDS.filter((kind) => present.has(kind));
}

// The labels of some kinds, separated, or the empty value when there are none. For a table cell.
function kindList(ctx, kinds) {
  if (kinds.length === 0) return ctx.label("value.none");
  return between(kinds.map((kind) => ctx.label(`harnessKind.${kind}`)), ctx.label("list.separator"));
}

function listOf(value) {
  return Array.isArray(value) ? value : [];
}

// Summary by axis ----------------------------------------------------------------------------------

function summarySection(ctx, entries) {
  const { label } = ctx;
  const rows = AXES.map((axis) => {
    const counts = impactCounts(entries.filter((entry) => entry.rule.axis === axis));
    return [label(`axis.${axis}`), ctx.num(counts.high), ctx.num(counts.medium), ctx.num(counts.low)];
  });
  const total = impactCounts(entries);
  rows.push([label("summary.total"), ctx.num(total.high), ctx.num(total.medium), ctx.num(total.low)]);

  const headers = [label("summary.axis"), label("impact.high"), label("impact.medium"), label("impact.low")];
  const blocks = [
    { type: "heading", level: 2, runs: label("summary.title") },
    { type: "table", headers, rows },
  ];
  const top = [...entries].sort(compareOverall).slice(0, SUMMARY_ROWS);
  if (top.length === 0) {
    blocks.push({ type: "paragraph", runs: label("summary.none") });
  } else {
    blocks.push(
      { type: "paragraph", runs: bold(runsOf(label("summary.top"), glue(":"))) },
      {
        type: "list",
        items: top.map((entry) =>
          runsOf(
            ctx.code(entry.rule.id),
            glue(" "),
            ctx.text(entry.rule.title),
            glue(" ("),
            label(`impact.${entry.impact}`),
            glue(")"),
          ),
        ),
      },
    );
  }
  return blocks;
}

function impactCounts(list) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const entry of list) counts[entry.impact] += 1;
  return counts;
}

// Findings by axis --------------------------------------------------------------------------------

function findingsSection(ctx, entries) {
  const { label } = ctx;
  const blocks = [{ type: "heading", level: 2, runs: label("findings.title") }];
  for (const axis of AXES) {
    blocks.push({ type: "heading", level: 3, runs: label(`axis.${axis}`) });
    const list = entries.filter((entry) => entry.rule.axis === axis).sort(compareEntries);
    if (list.length === 0) blocks.push({ type: "paragraph", runs: label("findings.axisEmpty") });
    for (const entry of list) blocks.push(findingBlock(ctx, entry));
  }
  return blocks;
}

function findingBlock(ctx, entry) {
  const { label } = ctx;
  const { rule, agent } = entry;
  const blocks = [{ type: "heading", level: 4, runs: runsOf(ctx.text(rule.id), glue(" · "), ctx.text(rule.title)) }];
  if (agent === null) blocks.push({ type: "paragraph", runs: label("finding.unexplained") });

  const fields = [field(label("field.type"), typeRuns(ctx, entry)), field(label("field.impact"), impactRuns(ctx, entry))];
  const agents = agentsRuns(ctx, entry);
  if (agents !== null) fields.push(field(label("field.agents"), agents));
  fields.push(field(label("field.evidenceLevel"), label(`level.${rule.evidence}`)));
  if (agent !== null) {
    fields.push(field(label("field.summary"), ctx.text(agent.summary)));
    fields.push(field(label("field.recommendation"), ctx.text(agent.recommendation)));
    const test = agent.testInFunction2 == null ? label("finding.noTest") : ctx.text(agent.testInFunction2);
    fields.push(field(label("field.test"), test));
  }
  if (entry.support.length > 0) {
    const supported = entry.support.map((item) =>
      label("support.item", { id: ctx.code(item.id), rule: ctx.text(item.rule), impact: label(`impact.${item.impact}`) }),
    );
    fields.push(field(label("field.supported"), between(supported, label("list.separator"))));
  }
  blocks.push({ type: "fields", items: fields });
  blocks.push(evidenceBlock(ctx, entry));
  if (entry.measured !== null) blocks.push(...measuredBlocks(ctx, entry.measured));
  blocks.push(...ruleSourceBlocks(ctx, rule));
  return { type: "finding", ruleId: rule.id, axis: rule.axis, impact: entry.impact, blocks };
}

function typeRuns(ctx, entry) {
  if (entry.agent !== null && entry.agent.kind === "judgment") return ctx.label("kind.judgment");
  return runsOf(ctx.label("kind.measured"), glue(" ("), ctx.code(entry.measured.id), glue(")"));
}

// A judgment finding says that its impact is an opinion. A measured finding takes the impact of its numbers.
function impactRuns(ctx, entry) {
  const level = ctx.label(`impact.${entry.impact}`);
  if (entry.agent !== null && entry.agent.kind === "judgment") return ctx.label("impact.opinion", { impact: level });
  return level;
}

// The agents a finding applies to: its own list, else the list of its measured finding (the CTX-07 measure names the agents it
// measures). Null when neither names any agent. Each id shows as its label.
function agentsRuns(ctx, entry) {
  const own = entry.agent === null ? undefined : entry.agent.agents;
  const ids = Array.isArray(own) ? own : entry.measured?.agents;
  if (!Array.isArray(ids) || ids.length === 0) return null;
  return between(ids.map((id) => ctx.label(`agent.${id}`)), ctx.label("list.separator"));
}

function evidenceBlock(ctx, entry) {
  const { label } = ctx;
  const items = entry.agent === null ? entry.measured.evidence : entry.agent.evidence;
  if (items.length === 0) return { type: "paragraph", runs: label("finding.noEvidence") };
  const rows = items.map((item) => [
    evidenceLocation(ctx, item),
    item.quote === undefined ? label("value.empty") : ctx.code(item.quote),
  ]);
  return { type: "table", headers: [label("table.evidence"), label("table.quote")], rows };
}

function locationOf(item) {
  if (item.line === undefined) return item.file;
  return item.endLine === undefined ? `${item.file}:${item.line}` : `${item.file}:${item.line}-${item.endLine}`;
}

// The location of an evidence entry, with its mark when the file lies outside the target (its layer).
function evidenceLocation(ctx, item) {
  const location = ctx.code(locationOf(item));
  if (item.layer === undefined) return location;
  if (!Object.hasOwn(LAYER_LABELS, item.layer)) throw new Error(`an evidence entry has an unknown layer: ${String(item.layer)}`);
  return runsOf(location, glue(" ("), ctx.label(LAYER_LABELS[item.layer]), glue(")"));
}

// The measured numbers of a finding: the value at its measurementRef, and one row per group of triggers.
function measuredBlocks(ctx, item) {
  const { label } = ctx;
  const headline = label("measure.at", {
    ref: ctx.code(item.measurementRef),
    value: valueRuns(ctx, resolveRef(ctx, item.measurementRef)),
  });
  const rows = triggerGroups(item).map((group) => triggerRow(ctx, group));
  const headers = [label("table.trigger"), label("table.count"), label("table.impact"), label("table.value"), label("table.threshold")];
  return [{ type: "paragraph", runs: headline }, { type: "table", headers, rows }];
}

function ruleSourceBlocks(ctx, rule) {
  const { label } = ctx;
  if (rule.sources.length === 0) return [{ type: "paragraph", runs: label("finding.noSources") }];
  const items = rule.sources.map((id) => {
    const source = sourceOf(ctx, id);
    return runsOf(ctx.link(source.title, source.url), glue(", "), label(`level.${source.type}`));
  });
  return [
    { type: "paragraph", runs: bold(runsOf(label("field.sources"), glue(":"))) },
    { type: "list", items },
  ];
}

// Context budget -----------------------------------------------------------------------------------

function contextSection(ctx) {
  const { label, measurements: m } = ctx;
  const budget = m.context.alwaysLoaded;
  const blocks = [{ type: "heading", level: 2, runs: label("context.title") }];
  if (budget.byComponent.length === 0) {
    blocks.push({ type: "paragraph", runs: label("context.none") });
  } else {
    const rows = budget.byComponent.map((item) => [
      componentRuns(ctx, item.component),
      label("context.mode.always"),
      ctx.num(item.items.length),
      ctx.num(item.estTokens),
    ]);
    const headers = [label("table.component"), label("table.loadMode"), label("table.files"), label("table.tokens")];
    blocks.push({ type: "table", headers, rows });
  }
  blocks.push({ type: "paragraph", runs: label("context.total", { estimate: estimateRuns(ctx) }) });
  blocks.push({ type: "paragraph", runs: label(ctx.included.ancestors ? "context.layersAncestors" : "context.layers") });
  blocks.push({ type: "paragraph", runs: label("context.agents") });
  if (m.context.byLayer !== undefined) blocks.push(...layerBlocks(ctx, m.context.byLayer));
  if (budget.unknownStatic.length > 0) {
    blocks.push(
      { type: "paragraph", runs: label("context.unknownTitle") },
      { type: "list", items: budget.unknownStatic.map((item) => unknownRuns(ctx, item)) },
    );
  }
  return blocks;
}

// The context of each layer, when the scan had a layer plan (--layers). One row per layer: its folders as code, the always-loaded
// total (the same for every layer), the files on demand there, their sum, and the nested skills, which are not verified and are
// not in the sum. The layer names come from the plan, so they are escaped like every other text of the report.
function layerBlocks(ctx, byLayer) {
  const { label, measurements: m } = ctx;
  const always = m.context.alwaysLoaded.estTokensTotal;
  const rows = byLayer.map((layer) => [
    ctx.text(layer.name),
    between(layer.folders.map((folder) => ctx.code(folder)), label("list.separator")),
    ctx.num(always),
    ctx.num(layer.onDemand.estTokens),
    ctx.num(always + layer.onDemand.estTokens),
    ctx.num(layer.nestedSkills.estTokens),
  ]);
  const headers = [
    label("table.layer"),
    label("table.folders"),
    label("table.alwaysLoaded"),
    label("table.onDemand"),
    label("table.total"),
    label("table.nestedSkills"),
  ];
  return [
    { type: "paragraph", runs: bold(runsOf(label("context.byLayer"), glue(":"))) },
    { type: "table", headers, rows },
    { type: "paragraph", runs: label("context.byLayerNote") },
  ];
}

function componentRuns(ctx, name) {
  return Object.hasOwn(COMPONENT_LABELS, name) ? ctx.label(COMPONENT_LABELS[name]) : ctx.text(name);
}

function estimateRuns(ctx) {
  const budget = ctx.measurements.context.alwaysLoaded;
  return ctx.label("tokens.estimate", { tokens: ctx.num(budget.estTokensTotal), method: ctx.text(budget.estMethod) });
}

function unknownRuns(ctx, item) {
  const { label } = ctx;
  if (item.kind === "mcp-server") {
    return label("unknown.mcp-server", { name: ctx.code(item.name), source: ctx.code(item.source) });
  }
  if (item.kind === "hook-output") {
    const matcher = item.matcher === null || item.matcher === undefined ? label("value.noMatcher") : ctx.code(item.matcher);
    return label("unknown.hook-output", { event: ctx.code(item.event), matcher, source: ctx.code(item.source) });
  }
  throw new Error(`measurements.json holds an unknown kind of static item: ${String(item.kind)}`);
}

// What to test in function 2 -----------------------------------------------------------------------

function function2Section(ctx, entries) {
  const { label, measurements: m } = ctx;
  const unknown = m.context.alwaysLoaded.unknownStatic.map((item) => unknownRuns(ctx, item));
  const tests = entries
    .filter((entry) => entry.agent !== null && entry.agent.testInFunction2 != null)
    .sort(compareOverall)
    .map((entry) =>
      runsOf(ctx.text(entry.rule.id), glue(" "), ctx.text(entry.rule.title), glue(": "), ctx.text(entry.agent.testInFunction2)),
    );
  const hooks = m.candidates
    .filter((item) => item.kind === "hook-script")
    .map((item) => {
      const rules = between(item.rules.map((rule) => ctx.code(rule)), label("list.separator"));
      return label("function2.hook", { file: ctx.code(item.file), candidate: ctx.code(item.id), rules });
    });
  return [
    { type: "heading", level: 2, runs: label("function2.title") },
    { type: "heading", level: 3, runs: label("function2.unknownTitle") },
    listOrNone(ctx, unknown),
    { type: "heading", level: 3, runs: label("function2.findingsTitle") },
    listOrNone(ctx, tests),
    { type: "heading", level: 3, runs: label("function2.hooksTitle") },
    listOrNone(ctx, hooks),
    { type: "heading", level: 3, runs: label("function2.noisyTitle") },
    { type: "paragraph", runs: label("function2.noisy") },
  ];
}

function listOrNone(ctx, items) {
  if (items.length === 0) return { type: "paragraph", runs: ctx.label("function2.none") };
  return { type: "list", items };
}

// Limits ---------------------------------------------------------------------------------------------

function limitsSection(ctx) {
  const { label, measurements: m } = ctx;
  const blocks = [
    { type: "heading", level: 2, runs: label("limits.title") },
    { type: "paragraph", runs: readLimitRuns(ctx) },
  ];
  if (m.scope !== undefined) {
    blocks.push({ type: "paragraph", runs: label("limits.scope", { outside: ctx.num(m.scope.files.outside) }) });
  }
  blocks.push({ type: "paragraph", runs: label("limits.estimate", { method: ctx.text(m.context.alwaysLoaded.estMethod) }) });
  blocks.push({ type: "paragraph", runs: label("limits.thresholds", { status: statusRuns(ctx) }) });
  const mode = usedMode(m);
  const modeRuns = mode === null ? ctx.codeLabel("mode.default") : ctx.code(mode);
  blocks.push({ type: "paragraph", runs: label("limits.sec02", { mode: modeRuns }) });
  const matrix = matrixBlocks(ctx);
  if (matrix !== null) blocks.push(...matrix);
  const skipped = skippedItems(ctx);
  if (skipped.length === 0) {
    blocks.push({ type: "paragraph", runs: label("limits.noWarnings") });
  } else {
    const rows = skipped.map((item) => [
      ctx.code(item.source),
      pathRuns(ctx, item),
      ctx.code(item.reason),
      item.detail === undefined ? label("value.empty") : valueRuns(ctx, item.detail),
    ]);
    const headers = [label("table.source"), label("table.path"), label("table.reason"), label("table.detail")];
    blocks.push({ type: "paragraph", runs: label("limits.warnings") }, { type: "table", headers, rows });
  }
  if (m.undeterminable.length === 0) {
    blocks.push({ type: "paragraph", runs: label("limits.noUndeterminable") });
  } else {
    const rows = m.undeterminable.map((item) => [ctx.text(item.rule), ctx.code(item.measurementRef), ctx.text(item.reason)]);
    const headers = [label("table.rule"), label("table.reference"), label("table.reason")];
    blocks.push({ type: "paragraph", runs: label("limits.undeterminable") }, { type: "table", headers, rows });
  }
  return blocks;
}

// The items of the skipped table: the scan's own warnings, then the warnings of the user layer, then the parent-folder files
// that the walk listed and did not read (read false). The last two lie outside the target, so they carry their layer. Without
// a flag neither exists, and the table is the scan's own warnings as before.
function skippedItems(ctx) {
  const { measurements: m } = ctx;
  const user = (m.userLayer?.warnings ?? []).map((item) => ({ ...item, layer: "user" }));
  const ancestors = (m.context.ancestors ?? [])
    .filter((item) => item.read === false)
    .map((item) => ({ source: ANCESTOR_SOURCE, path: item.path, reason: item.reason, layer: "ancestor" }));
  return [...m.warnings, ...user, ...ancestors];
}

// The path of a skipped item, with its layer mark when it lies outside the target.
function pathRuns(ctx, item) {
  const path = ctx.code(item.path);
  if (item.layer === undefined) return path;
  return runsOf(path, glue(" ("), ctx.label(LAYER_LABELS[item.layer]), glue(")"));
}

// What the limits say the scan did not read. The user layer and the parent folders are named as read only when meta.include
// says the scan read them (the flags of the scan); otherwise they are not read.
function readLimitRuns(ctx) {
  const { label, included } = ctx;
  if (included.userLayer && included.ancestors) return label("limits.readBoth");
  if (included.userLayer) return label("limits.readUser");
  if (included.ancestors) return label("limits.readAncestors");
  return label("limits.notRead");
}

// The SEC-02 permission matrix, as context: one row per command, one column per session mode in the order the scan
// wrote them. Nothing is rendered when the scan has no matrixModes (a measurements.json of an older scan). A command
// without a value for a mode shows the empty value, never an invented outcome.
function matrixBlocks(ctx) {
  const { label, measurements: m } = ctx;
  const coverage = m.security.destructiveCoverage;
  if (!Array.isArray(coverage.matrixModes)) return null;
  const modes = coverage.matrixModes;
  const headers = [label("table.command"), ...modes.map((mode) => ctx.code(mode))];
  const rows = coverage.commands.map((command) => [
    ctx.code(command.id),
    ...modes.map((mode) => (command.modes?.[mode] === undefined ? label("value.empty") : ctx.code(command.modes[mode]))),
  ]);
  return [
    { type: "paragraph", runs: label("limits.matrix") },
    { type: "table", headers, rows },
    { type: "paragraph", runs: label("limits.matrixLegend") },
  ];
}

// Sources ----------------------------------------------------------------------------------------------

function sourcesSection(ctx, entries) {
  const { label } = ctx;
  const ids = new Set(entries.flatMap((entry) => entry.rule.sources));
  const sources = [...ids].sort(compareText).map((id) => sourceOf(ctx, id));
  const heading = { type: "heading", level: 2, runs: label("sources.title") };
  if (sources.length === 0) return [heading, { type: "paragraph", runs: label("sources.none") }];
  const rows = sources.map((source) => [
    ctx.code(source.id),
    ctx.text(source.title),
    label(`level.${source.type}`),
    ctx.link(source.url, source.url),
  ]);
  const headers = [label("table.id"), label("table.title"), label("table.level"), label("table.url")];
  return [heading, { type: "table", headers, rows }];
}

// Appendix ---------------------------------------------------------------------------------------------

function appendixSection(ctx) {
  const { label, measurements: m } = ctx;
  const blocks = [
    { type: "heading", level: 2, runs: label("appendix.title") },
    { type: "heading", level: 3, runs: label("appendix.measured") },
  ];
  if (m.measuredFindings.length === 0) {
    blocks.push({ type: "paragraph", runs: label("appendix.none") });
  } else {
    const shown = m.measuredFindings.slice(0, APPENDIX_ROWS).map((item) => [
      ctx.code(item.id),
      ctx.text(item.rule),
      ctx.code(item.measurementRef),
      valueRuns(ctx, resolveRef(ctx, item.measurementRef)),
    ]);
    const headers = [label("table.finding"), label("table.rule"), label("table.reference"), label("table.value")];
    blocks.push({ type: "table", headers, rows: shown });
    if (m.measuredFindings.length > APPENDIX_ROWS) {
      const count = ctx.num(m.measuredFindings.length - APPENDIX_ROWS);
      blocks.push({ type: "paragraph", runs: label("appendix.truncated", { count }) });
    }
  }

  const duplication = m.code.duplication;
  const map = m.structure.mapCoverage;
  const headline = [
    [label("appendix.files"), ctx.num(m.target.fileCount)],
    [label("appendix.warnings"), ctx.num(m.warnings.length)],
    [label("appendix.alwaysLoaded"), estimateRuns(ctx)],
    [label("appendix.duplication"), label("appendix.percent", { value: ctx.num(duplication.duplicatedLinesPct) })],
    [label("appendix.filesScanned"), ctx.num(duplication.filesScanned)],
    [
      label("appendix.mapCoverage"),
      label("appendix.mapValue", { mentioned: ctx.num(map.mentioned), dirs: ctx.num(map.dirs) }),
    ],
  ];
  blocks.push({ type: "heading", level: 3, runs: label("appendix.headline") });
  blocks.push({ type: "table", headers: [label("table.measure"), label("table.value")], rows: headline });
  return blocks;
}

// Markdown view -------------------------------------------------------------------------------------------

/**
 * Writes the report model as Markdown: each section is its blocks, one blank line apart, and fillTemplate places them.
 * @param {ReportModel} model The model of buildReportModel.
 * @param {string} template The text of templates/report.md.
 * @returns {string}
 * @throws {Error} If the template does not have each marker once.
 */
export function renderMarkdown(model, template) {
  const sections = Object.fromEntries(
    MARKERS.map((name) => [name, model.sections[name].map(blockMarkdown).join("\n\n")]),
  );
  return fillTemplate(template, sections);
}

function blockMarkdown(block) {
  switch (block.type) {
    case "heading":
      return `${"#".repeat(block.level)} ${runsMarkdown(block.runs)}`;
    case "paragraph":
      return runsMarkdown(block.runs);
    case "fields":
      return block.items.map((item) => `- **${runsMarkdown(item.label)}:** ${runsMarkdown(item.runs)}`).join("\n");
    case "table":
      return table(block.headers.map(cellMarkdown), block.rows.map((row) => row.map(cellMarkdown)));
    case "list":
      return block.items.map((item) => `- ${runsMarkdown(item)}`).join("\n");
    case "finding":
      return block.blocks.map(blockMarkdown).join("\n\n");
    default:
      throw new TypeError(`the report model holds an unknown block: ${String(block.type)}`);
  }
}

// A table cell: GFM reads a pipe as a cell boundary even inside a code span, so every pipe of the cell is escaped.
function cellMarkdown(runs) {
  return runsMarkdown(runs, true);
}

function runsMarkdown(runs, inTable = false) {
  return runs.map((run) => runMarkdown(run, inTable)).join("");
}

function runMarkdown(run, inTable) {
  const text = (value) => (inTable ? escapePipes(value) : value);
  switch (run.type) {
    case "text":
    case "label":
      return text(run.text);
    case "code":
      return codeSpan(text(run.text));
    case "strong":
      return `**${runsMarkdown(run.runs, inTable)}**`;
    case "link":
      return text(link(run.label, run.url));
    default:
      throw new TypeError(`the report model holds an unknown run: ${String(run.type)}`);
  }
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
