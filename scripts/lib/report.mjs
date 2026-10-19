// Renders report.md. The scan (measurements.json) and the agent's findings (findings.json) are the input; the findings
// must already be validated (findings-validate.mjs). The fixed text comes from the labels of the language, and the
// sections are placed in templates/report.md by fillTemplate. Every number is read from measurements.json through its
// measurementRef: the agent's text never supplies a number. Every string from the target, the measurements or the
// agent goes through the redactor before it is written, and every value in a table is escaped.
//
// Findings are shown by axis, then by impact (high, medium, low), then by rule id, then by input order. A measured
// finding that no finding of findings.json cites (by measuredFindingId) is still shown, marked as not explained by the
// agent; renderReport lists those so the command line can warn about them.

import { AXES, DEFAULT_LANGUAGE } from "./findings-validate.mjs";
import { isPlainObject } from "./json-out.mjs";
import { THRESHOLDS_STATUS } from "./measured-findings.mjs";
import { createRedactor } from "./redact.mjs";
import { createLabeller } from "./report-labels.mjs";
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
 * Renders the report.
 * @param {object} options
 * @param {object} options.measurements The parsed measurements.json of the scan.
 * @param {object} options.findings The parsed findings.json, validated.
 * @param {ReturnType<import("./report-catalog.mjs").readCatalog>} options.catalog The catalog for the report.
 * @param {Readonly<Record<string, string>>} options.labels The labels of the language of findings.json.
 * @param {string} options.template The text of templates/report.md.
 * @returns {{ markdown: string, unexplained: Array<{ id: string, rule: string }> }} unexplained lists the measured
 *   findings that findings.json does not cite.
 * @throws {TypeError} If an input has the wrong shape.
 * @throws {Error} If a measurementRef does not resolve, a rule or source is missing from the catalog, or a label is missing.
 */
export function renderReport({ measurements, findings, catalog, labels, template }) {
  if (!isPlainObject(findings) || !Array.isArray(findings.findings)) {
    throw new TypeError("findings must be the parsed findings.json, with a findings list");
  }
  const missing = missingField(measurements);
  if (missing !== null) throw new TypeError(`measurements.json has no ${missing}`);

  const language = findings.language ?? DEFAULT_LANGUAGE;
  const ctx = createContext({ measurements, catalog, labels, language });
  const entries = collectEntries(ctx, findings.findings);
  const sections = {
    header: renderHeader(ctx),
    summary: renderSummary(ctx, entries),
    findings: renderFindings(ctx, entries),
    context: renderContext(ctx),
    function2: renderFunction2(ctx, entries),
    limits: renderLimits(ctx),
    sources: renderSources(ctx, entries),
    appendix: renderAppendix(ctx),
  };
  return {
    markdown: fillTemplate(template, sections),
    unexplained: entries
      .filter((entry) => entry.agent === null)
      .map((entry) => ({ id: entry.measured.id, rule: entry.measured.rule })),
  };
}

// Context and entries ------------------------------------------------------------------------------

// The helpers the sections share. Each text helper redacts first, then escapes for its place in the Markdown.
function createContext({ measurements, catalog, labels, language }) {
  const t = createLabeller(labels);
  const redact = createRedactor({ root: measurements.meta.targetRoot });
  const plain = (value) => inline(redact(String(value)));
  return {
    t,
    language,
    measurements,
    catalog,
    measured: new Map(measurements.measuredFindings.map((item) => [item.id, item])),
    num: (value) => formatNumber(value, language),
    text: plain,
    code: (value) => {
      const text = plain(value);
      return text === "" ? t("value.empty") : codeSpan(text);
    },
    tableCode: (value) => {
      const text = plain(value);
      return text === "" ? t("value.empty") : codeSpan(escapePipes(text));
    },
    tableText: (value) => escapePipes(plain(value)),
    link: (label, url) => link(plain(label), plain(url)),
  };
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

// A value as text: numbers in the locale, strings as code, arrays and objects by their length or key count.
function valueText(ctx, value, inTable) {
  const { t } = ctx;
  if (value === null) return t("value.null");
  if (value === true) return t("value.true");
  if (value === false) return t("value.false");
  if (typeof value === "number") return ctx.num(value);
  if (typeof value === "string") return inTable ? ctx.tableCode(value) : ctx.code(value);
  if (Array.isArray(value)) return t("value.list", { count: ctx.num(value.length) });
  if (isPlainObject(value)) return t("value.object", { count: ctx.num(Object.keys(value).length) });
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
  const { t } = ctx;
  const single = group.count === 1 ? resolveRef(ctx, group.refs[0]) : undefined;
  const value = single === undefined || isObjectValue(single) ? t("value.empty") : valueText(ctx, single, true);
  const threshold =
    group.threshold === null
      ? t("value.empty")
      : t("threshold.cell", {
          key: ctx.tableCode(group.threshold.key),
          value: valueText(ctx, group.threshold.value, true),
          status: statusText(ctx),
        });
  return [ctx.tableCode(group.trigger), ctx.num(group.count), t(`impact.${group.impact}`), value, threshold];
}

function isObjectValue(value) {
  return value !== null && typeof value === "object";
}

function statusText(ctx) {
  const key = STATUS_LABELS[THRESHOLDS_STATUS];
  if (key === undefined) throw new Error(`no label for the threshold status "${String(THRESHOLDS_STATUS)}"`);
  return ctx.t(key);
}

// The permission mode that the SEC-02 outcomes use, or null for the default mode. The scan applies the project
// defaultMode only when it takes effect; otherwise its outcomes use default (destructive-commands.mjs).
function usedMode(measurements) {
  const mode = measurements.security.destructiveCoverage.mode;
  return mode !== null && mode.effect === "applies" ? mode.value : null;
}

// Header --------------------------------------------------------------------------------------------

function renderHeader(ctx) {
  const { t, measurements: m, catalog } = ctx;
  const head = m.target.git.head;
  const lines = [
    field(t("header.target"), ctx.code(m.target.name)),
    field(t("header.commit"), head === null ? t("value.none") : ctx.code(head)),
    field(t("header.scanDate"), utcDate(m.meta.scannedAt)),
    field(t("header.axes"), AXES.map((axis) => t(`axis.${axis}`)).join(t("list.separator"))),
    field(t("header.tool"), ctx.code(m.meta.tool)),
    field(
      t("header.catalog"),
      t("header.catalogValue", { count: ctx.num(catalog.version.count), hash: ctx.code(catalog.version.sha256) }),
    ),
  ];
  return [`# ${t("header.title")}`, lines.join("\n")].join("\n\n");
}

// Summary by axis ----------------------------------------------------------------------------------

function renderSummary(ctx, entries) {
  const { t } = ctx;
  const rows = AXES.map((axis) => {
    const counts = impactCounts(entries.filter((entry) => entry.rule.axis === axis));
    return [ctx.tableText(t(`axis.${axis}`)), ctx.num(counts.high), ctx.num(counts.medium), ctx.num(counts.low)];
  });
  const total = impactCounts(entries);
  rows.push([ctx.tableText(t("summary.total")), ctx.num(total.high), ctx.num(total.medium), ctx.num(total.low)]);

  const top = [...entries].sort(compareOverall).slice(0, SUMMARY_ROWS);
  const topText =
    top.length === 0
      ? t("summary.none")
      : [
          `**${t("summary.top")}:**`,
          top
            .map((entry) => `- ${ctx.code(entry.rule.id)} ${ctx.text(entry.rule.title)} (${t(`impact.${entry.impact}`)})`)
            .join("\n"),
        ].join("\n\n");
  const headers = [t("summary.axis"), t("impact.high"), t("impact.medium"), t("impact.low")];
  return [`## ${t("summary.title")}`, table(headers, rows), topText].join("\n\n");
}

function impactCounts(list) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const entry of list) counts[entry.impact] += 1;
  return counts;
}

// Findings by axis --------------------------------------------------------------------------------

function renderFindings(ctx, entries) {
  const { t } = ctx;
  const blocks = [`## ${t("findings.title")}`];
  for (const axis of AXES) {
    blocks.push(`### ${t(`axis.${axis}`)}`);
    const list = entries.filter((entry) => entry.rule.axis === axis).sort(compareEntries);
    if (list.length === 0) blocks.push(t("findings.axisEmpty"));
    for (const entry of list) blocks.push(renderFinding(ctx, entry));
  }
  return blocks.join("\n\n");
}

function renderFinding(ctx, entry) {
  const { t } = ctx;
  const { rule, agent } = entry;
  const blocks = [`#### ${rule.id} · ${ctx.text(rule.title)}`];
  if (agent === null) blocks.push(t("finding.unexplained"));

  const fields = [
    field(t("field.type"), typeText(ctx, entry)),
    field(t("field.impact"), impactText(ctx, entry)),
    field(t("field.evidenceLevel"), t(`level.${rule.evidence}`)),
  ];
  if (agent !== null) {
    fields.push(field(t("field.summary"), ctx.text(agent.summary)));
    fields.push(field(t("field.recommendation"), ctx.text(agent.recommendation)));
    const test = agent.testInFunction2 == null ? t("finding.noTest") : ctx.text(agent.testInFunction2);
    fields.push(field(t("field.test"), test));
  }
  if (entry.support.length > 0) {
    const supported = entry.support.map((item) =>
      t("support.item", { id: ctx.code(item.id), rule: ctx.text(item.rule), impact: t(`impact.${item.impact}`) }),
    );
    fields.push(field(t("field.supported"), supported.join(t("list.separator"))));
  }
  blocks.push(fields.join("\n"));
  blocks.push(evidenceBlock(ctx, entry));
  if (entry.measured !== null) blocks.push(...measuredBlocks(ctx, entry.measured));
  blocks.push(sourcesBlock(ctx, rule));
  return blocks.join("\n\n");
}

function field(label, text) {
  return `- **${label}:** ${text}`;
}

function typeText(ctx, entry) {
  if (entry.agent !== null && entry.agent.kind === "judgment") return ctx.t("kind.judgment");
  return `${ctx.t("kind.measured")} (${ctx.code(entry.measured.id)})`;
}

// A judgment finding says that its impact is an opinion. A measured finding takes the impact of its numbers.
function impactText(ctx, entry) {
  const level = ctx.t(`impact.${entry.impact}`);
  if (entry.agent !== null && entry.agent.kind === "judgment") return ctx.t("impact.opinion", { impact: level });
  return level;
}

function evidenceBlock(ctx, entry) {
  const { t } = ctx;
  const items = entry.agent === null ? entry.measured.evidence : entry.agent.evidence;
  if (items.length === 0) return t("finding.noEvidence");
  const rows = items.map((item) => [
    ctx.tableCode(locationOf(item)),
    item.quote === undefined ? t("value.empty") : ctx.tableCode(item.quote),
  ]);
  return table([t("table.evidence"), t("table.quote")], rows);
}

function locationOf(item) {
  if (item.line === undefined) return item.file;
  return item.endLine === undefined ? `${item.file}:${item.line}` : `${item.file}:${item.line}-${item.endLine}`;
}

// The measured numbers of a finding: the value at its measurementRef, and one row per group of triggers.
function measuredBlocks(ctx, item) {
  const { t } = ctx;
  const headline = t("measure.at", {
    ref: ctx.code(item.measurementRef),
    value: valueText(ctx, resolveRef(ctx, item.measurementRef), false),
  });
  const rows = triggerGroups(item).map((group) => triggerRow(ctx, group));
  const headers = [t("table.trigger"), t("table.count"), t("table.impact"), t("table.value"), t("table.threshold")];
  return [headline, table(headers, rows)];
}

function sourcesBlock(ctx, rule) {
  const { t } = ctx;
  if (rule.sources.length === 0) return t("finding.noSources");
  const items = rule.sources.map((id) => {
    const source = sourceOf(ctx, id);
    return `- ${ctx.link(source.title, source.url)}, ${t(`level.${source.type}`)}`;
  });
  return [`**${t("field.sources")}:**`, items.join("\n")].join("\n\n");
}

// Context budget -----------------------------------------------------------------------------------

function renderContext(ctx) {
  const { t, measurements: m } = ctx;
  const budget = m.context.alwaysLoaded;
  const blocks = [`## ${t("context.title")}`];
  if (budget.byComponent.length === 0) {
    blocks.push(t("context.none"));
  } else {
    const rows = budget.byComponent.map((item) => [
      ctx.tableText(componentName(ctx, item.component)),
      ctx.tableText(t("context.mode.always")),
      ctx.num(item.items.length),
      ctx.num(item.estTokens),
    ]);
    const headers = [t("table.component"), t("table.loadMode"), t("table.files"), t("table.tokens")];
    blocks.push(table(headers, rows));
  }
  blocks.push(t("context.total", { estimate: estimateText(ctx) }));
  blocks.push(t("context.layers"), t("context.agents"));
  if (budget.unknownStatic.length > 0) {
    blocks.push(t("context.unknownTitle"), budget.unknownStatic.map((item) => `- ${unknownText(ctx, item)}`).join("\n"));
  }
  return blocks.join("\n\n");
}

function componentName(ctx, name) {
  return Object.hasOwn(COMPONENT_LABELS, name) ? ctx.t(COMPONENT_LABELS[name]) : ctx.text(name);
}

function estimateText(ctx) {
  const budget = ctx.measurements.context.alwaysLoaded;
  return ctx.t("tokens.estimate", { tokens: ctx.num(budget.estTokensTotal), method: ctx.text(budget.estMethod) });
}

function unknownText(ctx, item) {
  const { t } = ctx;
  if (item.kind === "mcp-server") {
    return t("unknown.mcp-server", { name: ctx.code(item.name), source: ctx.code(item.source) });
  }
  if (item.kind === "hook-output") {
    const matcher = item.matcher === null || item.matcher === undefined ? t("value.noMatcher") : ctx.code(item.matcher);
    return t("unknown.hook-output", { event: ctx.code(item.event), matcher, source: ctx.code(item.source) });
  }
  throw new Error(`measurements.json holds an unknown kind of static item: ${String(item.kind)}`);
}

// What to test in function 2 -----------------------------------------------------------------------

function renderFunction2(ctx, entries) {
  const { t, measurements: m } = ctx;
  const unknown = m.context.alwaysLoaded.unknownStatic.map((item) => `- ${unknownText(ctx, item)}`);
  const tests = entries
    .filter((entry) => entry.agent !== null && entry.agent.testInFunction2 != null)
    .sort(compareOverall)
    .map((entry) => `- ${entry.rule.id} ${ctx.text(entry.rule.title)}: ${ctx.text(entry.agent.testInFunction2)}`);
  const hooks = m.candidates
    .filter((item) => item.kind === "hook-script")
    .map((item) => {
      const rules = item.rules.map((rule) => ctx.code(rule)).join(t("list.separator"));
      return `- ${t("function2.hook", { file: ctx.code(item.file), candidate: ctx.code(item.id), rules })}`;
    });
  return [
    `## ${t("function2.title")}`,
    `### ${t("function2.unknownTitle")}`,
    listOrNone(ctx, unknown),
    `### ${t("function2.findingsTitle")}`,
    listOrNone(ctx, tests),
    `### ${t("function2.hooksTitle")}`,
    listOrNone(ctx, hooks),
    `### ${t("function2.noisyTitle")}`,
    t("function2.noisy"),
  ].join("\n\n");
}

function listOrNone(ctx, items) {
  return items.length === 0 ? ctx.t("function2.none") : items.join("\n");
}

// Limits ---------------------------------------------------------------------------------------------

function renderLimits(ctx) {
  const { t, measurements: m } = ctx;
  const blocks = [`## ${t("limits.title")}`, t("limits.notRead")];
  blocks.push(t("limits.estimate", { method: ctx.text(m.context.alwaysLoaded.estMethod) }));
  blocks.push(t("limits.thresholds", { status: statusText(ctx) }));
  const mode = usedMode(m);
  blocks.push(t("limits.sec02", { mode: ctx.code(mode ?? t("mode.default")) }));
  if (m.warnings.length === 0) {
    blocks.push(t("limits.noWarnings"));
  } else {
    const rows = m.warnings.map((item) => [
      ctx.tableCode(item.source),
      ctx.tableCode(item.path),
      ctx.tableCode(item.reason),
      item.detail === undefined ? t("value.empty") : valueText(ctx, item.detail, true),
    ]);
    blocks.push(t("limits.warnings"), table([t("table.source"), t("table.path"), t("table.reason"), t("table.detail")], rows));
  }
  if (m.undeterminable.length === 0) {
    blocks.push(t("limits.noUndeterminable"));
  } else {
    const rows = m.undeterminable.map((item) => [
      ctx.tableText(item.rule),
      ctx.tableCode(item.measurementRef),
      ctx.tableText(item.reason),
    ]);
    blocks.push(t("limits.undeterminable"), table([t("table.rule"), t("table.reference"), t("table.reason")], rows));
  }
  return blocks.join("\n\n");
}

// Sources ----------------------------------------------------------------------------------------------

function renderSources(ctx, entries) {
  const { t } = ctx;
  const ids = new Set(entries.flatMap((entry) => entry.rule.sources));
  const sources = [...ids].sort(compareText).map((id) => sourceOf(ctx, id));
  if (sources.length === 0) return [`## ${t("sources.title")}`, t("sources.none")].join("\n\n");
  const rows = sources.map((source) => [
    ctx.tableCode(source.id),
    ctx.tableText(source.title),
    ctx.tableText(t(`level.${source.type}`)),
    escapePipes(ctx.link(source.url, source.url)),
  ]);
  const headers = [t("table.id"), t("table.title"), t("table.level"), t("table.url")];
  return [`## ${t("sources.title")}`, table(headers, rows)].join("\n\n");
}

// Appendix ---------------------------------------------------------------------------------------------

function renderAppendix(ctx) {
  const { t, measurements: m } = ctx;
  const blocks = [`## ${t("appendix.title")}`, `### ${t("appendix.measured")}`];
  if (m.measuredFindings.length === 0) {
    blocks.push(t("appendix.none"));
  } else {
    const shown = m.measuredFindings.slice(0, APPENDIX_ROWS).map((item) => [
      ctx.tableCode(item.id),
      ctx.tableText(item.rule),
      ctx.tableCode(item.measurementRef),
      valueText(ctx, resolveRef(ctx, item.measurementRef), true),
    ]);
    const headers = [t("table.finding"), t("table.rule"), t("table.reference"), t("table.value")];
    blocks.push(table(headers, shown));
    if (m.measuredFindings.length > APPENDIX_ROWS) {
      blocks.push(t("appendix.truncated", { count: ctx.num(m.measuredFindings.length - APPENDIX_ROWS) }));
    }
  }

  const duplication = m.code.duplication;
  const map = m.structure.mapCoverage;
  const headline = [
    [t("appendix.files"), ctx.num(m.target.fileCount)],
    [t("appendix.warnings"), ctx.num(m.warnings.length)],
    [t("appendix.alwaysLoaded"), estimateText(ctx)],
    [t("appendix.duplication"), t("appendix.percent", { value: ctx.num(duplication.duplicatedLinesPct) })],
    [t("appendix.filesScanned"), ctx.num(duplication.filesScanned)],
    [
      t("appendix.mapCoverage"),
      t("appendix.mapValue", { mentioned: ctx.num(map.mentioned), dirs: ctx.num(map.dirs) }),
    ],
  ];
  blocks.push(`### ${t("appendix.headline")}`);
  blocks.push(table([t("table.measure"), t("table.value")], headline));
  return blocks.join("\n\n");
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
