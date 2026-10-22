// The HTML view of the report model: one page, with its style inside the page and no script. buildReportModel makes the
// model, and renderMarkdown is the other view; this one writes the same blocks as HTML. The model holds no markup, so every
// text is escaped here, for element content and for attributes. A link is a link only when its address is https: any other
// address is shown as escaped text in a code element, so a javascript: or data: address never becomes an href.
// The filters are one checkbox per axis and per impact. CSS alone applies them: an unchecked box hides the findings it marks,
// through :has(), and a browser without :has() shows every finding. The page loads nothing from outside and runs no script.

import { AXES, IMPACTS, LANGUAGES } from "./findings-validate.mjs";
import { cspHash, escapeHtml } from "./html.mjs";
import { isPlainObject } from "./json-out.mjs";
import { MARKERS } from "./report.mjs";
import { createLabeller } from "./report-labels.mjs";

// A marker of a template: {{name}}, the same syntax as templates/report.md.
const MARKER = /\{\{\s*([^{}]*?)\s*\}\}/g;
// The markers of templates/report.html: the values of the page, then one per section of the model.
const PAGE_MARKERS = Object.freeze(["lang", "csp", "title", "style", "filters", ...MARKERS]);

/**
 * The href of an address that may be a link: the normalized address when it parses as an absolute URL with the https scheme,
 * otherwise null. A javascript:, data:, http:, relative or malformed address is not a link. This never throws.
 * @param {unknown} url
 * @returns {string | null}
 */
export function httpsHref(url) {
  if (typeof url !== "string") return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

/**
 * Renders the report model as one HTML page.
 * @param {import("./report.mjs").ReportModel} model The model of buildReportModel.
 * @param {object} options
 * @param {string} options.template The text of templates/report.html.
 * @param {string} options.theme The text of templates/theme.css.
 * @param {string} options.css The text of templates/report.css.
 * @param {Readonly<Record<string, string>>} options.labels The labels of the model's language, from labels.<language>.json.
 *   The page's own texts (the filter legend and the title) come from them.
 * @returns {{ html: string, csp: string }} csp is the Content-Security-Policy of the page, the one its meta element holds.
 * @throws {TypeError} If an argument has the wrong shape.
 * @throws {Error} If a finding has an axis or an impact outside the known lists, a table row has another number of cells than
 *   its headers, a heading has a level outside 1 to 4, the template does not have each marker once, or a stylesheet holds a
 *   closing style tag.
 */
export function renderHtml(model, { template, theme, css, labels }) {
  checkModel(model);
  for (const [name, text] of Object.entries({ template, theme, css })) {
    if (typeof text !== "string") throw new TypeError(`${name} must be the text of its file`);
  }
  if (!isPlainObject(labels)) throw new TypeError("labels must be the labels of the model's language");

  const t = createLabeller(labels);
  // The style is the one text the policy names by its hash. It is kept as it is: escaping it would break its selectors.
  // An HTML parser turns CRLF and a lone CR into LF, so they are made LF here, before the hash, or the hash would not match.
  const style = [theme, css, filterRules()].join("\n").replace(/\r\n?/g, "\n");
  if (/<\/style/i.test(style)) throw new Error("the stylesheet must not hold a closing style tag");
  const csp = pagePolicy(style);
  const sections = Object.fromEntries(MARKERS.map((name) => [name, sectionValueHtml(name, model.sections)]));
  const values = {
    lang: escapeHtml(model.language),
    csp: escapeHtml(csp),
    title: escapeHtml(t("header.title")),
    style,
    filters: filtersHtml(t),
    ...sections,
  };
  return { html: fillPage(template, values, { file: "templates/report.html", markers: PAGE_MARKERS }), csp };
}

/**
 * The Content-Security-Policy of a page whose only style element holds `style`: nothing loads unless it is named. The one
 * style is named by its hash; the page has no image, no other resource and no form. The report and the comparison share it.
 * @param {string} style The exact text between the tags of the style element, with its line feeds as LF.
 * @returns {string}
 * @throws {TypeError} If style is not a string.
 */
export function pagePolicy(style) {
  return `default-src 'none'; style-src ${cspHash(style)}; img-src 'none'; base-uri 'none'; form-action 'none'`;
}

/**
 * Writes a list of blocks as HTML, one block per line, with the escaping of the report page. The comparison view uses it too.
 * @param {import("./report.mjs").Block[]} blocks The blocks of the report model.
 * @returns {string}
 * @throws {TypeError} If a block or a run has an unknown type.
 * @throws {Error} If a finding, a heading or a table is outside the rules of the report page.
 */
export function blocksHtml(blocks) {
  return blocks.map(blockHtml).join("\n");
}

// Filters -----------------------------------------------------------------------------------------------

function filterId(kind, name) {
  return `filter-${kind}-${name}`;
}

// The checkboxes, checked by default. Each one is visually hidden but keeps its place in the focus order, and its label
// shows the state. The group titles name the groups for a screen reader.
function filtersHtml(t) {
  return [
    `<fieldset class="filters">`,
    `<legend>${escapeHtml(t("html.filter.legend"))}</legend>`,
    `<p class="muted">${escapeHtml(t("html.filter.help"))}</p>`,
    filterGroup("axis", AXES, (axis) => t(`axis.${axis}`), t("html.filter.axes")),
    filterGroup("impact", IMPACTS, (impact) => t(`impact.${impact}`), t("field.impact")),
    `</fieldset>`,
  ].join("\n");
}

function filterGroup(kind, names, textOf, title) {
  const titleId = `filter-title-${kind}`;
  const boxes = names.flatMap((name) => {
    const id = filterId(kind, name);
    return [
      `<input type="checkbox" class="visually-hidden" id="${id}" checked>`,
      `<label for="${id}">${escapeHtml(textOf(name))}</label>`,
    ];
  });
  return [
    `<div class="filter-group" role="group" aria-labelledby="${titleId}">`,
    `<p class="filter-title" id="${titleId}">${escapeHtml(title)}</p>`,
    ...boxes,
    `</div>`,
  ].join("\n");
}

// One rule per box: an unchecked box hides the findings that carry its axis, or its impact. A browser without :has() drops
// these rules, so every finding stays visible.
function filterRules() {
  const byAxis = AXES.map((axis) => hideRule(filterId("axis", axis), `.finding[data-axis="${axis}"]`));
  const byImpact = IMPACTS.map((impact) => hideRule(filterId("impact", impact), `.finding[data-impact="${impact}"]`));
  return [...byAxis, ...byImpact].join("\n");
}

function hideRule(id, target) {
  return `body:has(#${id}:not(:checked)) ${target} { display: none; }`;
}

// Sections and blocks ---------------------------------------------------------------------------------

function sectionHtml(blocks) {
  return `<section>\n${blocksHtml(blocks)}\n</section>`;
}

// The value of one section marker. The remediation section is optional: without blocks it is the empty text, and with them it
// starts on a line of its own, so the page keeps the same bytes as a report without one.
function sectionValueHtml(name, sections) {
  if (name !== "remediation") return sectionHtml(sections[name]);
  const blocks = sections.remediation ?? [];
  return blocks.length === 0 ? "" : `\n${sectionHtml(blocks)}`;
}

function blockHtml(block) {
  switch (block.type) {
    case "heading":
      return headingHtml(block);
    case "paragraph":
      return `<p>${runsHtml(block.runs)}</p>`;
    case "fields":
      return fieldsHtml(block);
    case "table":
      return tableHtml(block);
    case "list":
      return `<ul>${block.items.map((item) => `<li>${runsHtml(item)}</li>`).join("")}</ul>`;
    case "finding":
      return findingHtml(block);
    case "code-block":
      return `<pre><code>${escapeHtml(block.text)}</code></pre>`;
    default:
      throw new TypeError(`the report model holds an unknown block: ${String(block.type)}`);
  }
}

function headingHtml(block) {
  if (!Number.isInteger(block.level) || block.level < 1 || block.level > 4) {
    throw new Error(`a heading has the level ${String(block.level)}, and the levels are 1 to 4`);
  }
  const tag = `h${block.level}`;
  return `<${tag}>${runsHtml(block.runs)}</${tag}>`;
}

// One "label: value" item per div of the list, so each label stays with its value.
function fieldsHtml(block) {
  const items = block.items.map((item) => `<div><dt>${runsHtml(item.label)}</dt><dd>${runsHtml(item.runs)}</dd></div>`);
  return `<dl class="fields">${items.join("")}</dl>`;
}

// The table sits in a wrapper that scrolls sideways, and the wrapper takes the keyboard focus so that a keyboard reader can
// scroll it.
function tableHtml(block) {
  const width = block.headers.length;
  block.rows.forEach((row, index) => {
    if (row.length !== width) throw new Error(`table row ${index} has ${row.length} cells for ${width} headers`);
  });
  const head = block.headers.map((cell) => `<th scope="col">${runsHtml(cell)}</th>`).join("");
  const body = block.rows.map((row) => `<tr>${row.map((cell) => `<td>${runsHtml(cell)}</td>`).join("")}</tr>`).join("");
  return `<div class="table-wrap" tabindex="0"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

// A finding is an article whose axis, impact and rule are data attributes, which the filter rules select by. The axis and the
// impact are checked against the known lists, since a value outside them would be a selector nobody wrote.
function findingHtml(block) {
  if (!AXES.includes(block.axis)) throw new Error(`a finding has an unknown axis: ${String(block.axis)}`);
  if (!IMPACTS.includes(block.impact)) throw new Error(`a finding has an unknown impact: ${String(block.impact)}`);
  const attributes = `data-axis="${block.axis}" data-impact="${block.impact}" data-rule="${escapeHtml(block.ruleId)}"`;
  return `<article class="finding" ${attributes}>\n${block.blocks.map(blockHtml).join("\n")}\n</article>`;
}

// Runs -------------------------------------------------------------------------------------------------

function runsHtml(runs) {
  return runs.map(runHtml).join("");
}

function runHtml(run) {
  switch (run.type) {
    case "text":
    case "label":
    case "data":
      return escapeHtml(run.text);
    case "code":
      return `<code>${escapeHtml(run.text)}</code>`;
    case "strong":
      return `<strong>${runsHtml(run.runs)}</strong>`;
    case "link":
      return linkHtml(run);
    default:
      throw new TypeError(`the report model holds an unknown run: ${String(run.type)}`);
  }
}

// A link to an https address. Any other address is shown as its code alone, with no href and no label, as the Markdown view
// shows an address that is not http or https.
function linkHtml(run) {
  const href = httpsHref(run.url);
  if (href !== null) return `<a href="${escapeHtml(href)}" rel="noreferrer noopener">${escapeHtml(run.label)}</a>`;
  return `<code>${escapeHtml(run.url)}</code>`;
}

// Checks and template ----------------------------------------------------------------------------------

function checkModel(model) {
  if (!isPlainObject(model) || !isPlainObject(model.sections)) {
    throw new TypeError("model must be the report model of buildReportModel");
  }
  if (!LANGUAGES.includes(model.language)) throw new TypeError(`model.language must be one of ${LANGUAGES.join(", ")}`);
  for (const name of MARKERS) {
    // The remediation section is optional: a model without it is a report without a remediation.
    if (name === "remediation" && model.sections[name] === undefined) continue;
    if (!Array.isArray(model.sections[name])) throw new TypeError(`model.sections.${name} must be a list of blocks`);
  }
}

/**
 * Places the values in a page template in one pass, so a value is never read as a marker: a text of the report that looks
 * like a marker stays as it is. Each marker of `markers` must be in the template once, and no other marker may be there.
 * @param {string} template The text of the page template.
 * @param {Record<string, string>} values One escaped text per marker of `markers`.
 * @param {{ file: string, markers: readonly string[] }} page `file` names the template in the error messages.
 * @returns {string}
 * @throws {Error} If the template has an unknown marker, or a marker that is missing or repeated, or a value is missing.
 */
export function fillPage(template, values, { file, markers }) {
  const found = [...template.matchAll(MARKER)].map((match) => match[1]);
  for (const name of found) {
    if (!markers.includes(name)) throw new Error(`${file} has an unknown marker {{${name}}}`);
  }
  for (const name of markers) {
    const count = found.filter((item) => item === name).length;
    if (count !== 1) throw new Error(`${file} must have the marker {{${name}}} once, found ${count}`);
    if (!Object.hasOwn(values, name)) throw new Error(`no value for the marker {{${name}}} of ${file}`);
  }
  return template.replace(MARKER, (whole, name) => values[name]);
}
