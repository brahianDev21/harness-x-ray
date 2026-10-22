// Tests of the comparison views (scripts/lib/comparison-view.mjs): the Markdown and the HTML page of a comparison of two scans,
// built by hand from the contract of comparison.json. They check that every compare label is used, that no visible word comes
// from the code, that the output is deterministic, and that a text of the target or of the agent adds no markup, no table cell
// and no link. The report's own policy is the reference for the policy of the comparison page.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildComparisonBlocks, renderComparisonHtml, renderComparisonMarkdown } from "../scripts/lib/comparison-view.mjs";
import { cspHash, loadTheme } from "../scripts/lib/html.mjs";
import { blocksHtml, pagePolicy, renderHtml } from "../scripts/lib/report-html.mjs";
import { loadLabels, placeholdersOf } from "../scripts/lib/report-labels.mjs";
import { MARKERS, blocksMarkdown } from "../scripts/lib/report.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...parts) => fs.readFileSync(path.join(HARNESS_ROOT, ...parts), "utf8");
const TEMPLATE = read("templates", "comparison.html");
const REPORT_TEMPLATE = read("templates", "report.html");
const CSS = read("templates", "report.css");
const THEME = loadTheme(HARNESS_ROOT);
const labelsEn = loadLabels(HARNESS_ROOT, "en");
const labelsEs = loadLabels(HARNESS_ROOT, "es");
// The rules of the current catalog that the scenarios name. A rule that is not here shows a dash as its title.
const RULE_TITLES = new Map([
  ["CTX-01", "Always-loaded total"],
  ["COD-04", "Reuse of the permission reader"],
  ["SEC-02", "Destructive commands"],
]);
// The tags that the comparison page uses. A tag that the escaping does not stop would show up as another name here.
const ALLOWED_TAGS = new Set([
  "html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "p", "ul", "li", "table", "thead", "tbody", "tr", "th",
  "td", "div", "code",
]);
// The policy of a page with one inline style, as the report page has it.
const POLICY_FORM =
  /^default-src 'none'; style-src 'sha256-[A-Za-z0-9+/]+=*'; img-src 'none'; base-uri 'none'; form-action 'none'$/;
// Texts of the target and of the agent that try to add markup, a table cell, a link or a scheme.
const HOSTILE = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "</style>", "javascript:alert(1)", "a|b"];

// Scenarios -------------------------------------------------------------------------------------------------

function runOf(overrides) {
  return {
    name: "scan-2026-10-01",
    target: "web-app",
    head: "0123456789abcdef0123456789abcdef01234567",
    scannedAt: "2026-10-01T08:30:00.000Z",
    schemaVersion: 1,
    depth: "standard",
    scope: null,
    catalog: { count: 41, sha256: "ab12cd34" },
    findings: 4,
    measuredFindings: 3,
    ...overrides,
  };
}

function measuredSide(impact, summary, { cited = true, id = "mf-1" } = {}) {
  return {
    id,
    impact,
    triggers: [{ trigger: "always-loaded-total-high", impact, measurementRef: "/context/alwaysLoaded/estTokensTotal" }],
    cited,
    summary,
  };
}

function judgmentSide(impact, summary, index = 0) {
  return { index, impact, summary, evidence: [{ file: ".claude/settings.json", line: 4 }] };
}

// Every label of the views is reached: each class, each type, each warning code, both impacts and a pair of impacts, a key with a
// trigger and without one, a judgment key with files and without, an uncited measure, a rule without a title, both depths
// besides the deep one of run B, a scope, no scope, a catalog, no catalog, a commit, no commit. Not every value is consistent
// with one real scan; the scenario is a set of values the views must write.
function fullComparison(language) {
  return {
    schemaVersion: 1,
    language,
    runs: {
      a: runOf({ name: "scan-2026-10-01", depth: "quick", findings: 4, measuredFindings: 3 }),
      b: runOf({
        name: "scan-2026-10-20",
        target: "web-app-v2",
        head: "fedcba9876543210fedcba9876543210fedcba98",
        scannedAt: "2026-10-20T17:05:00.000Z",
        schemaVersion: 2,
        depth: "deep",
        scope: ["apps/web", "packages/ui"],
        catalog: null,
        findings: 12345,
        measuredFindings: 4,
      }),
    },
    warnings: [
      { code: "target-changed", a: "web-app", b: "web-app-v2" },
      { code: "scope-changed", a: null, b: ["apps/web", "packages/ui"] },
      { code: "depth-changed", a: "quick", b: "deep" },
      { code: "catalog-changed", a: { count: 41, sha256: "ab12cd34" }, b: { count: 43, sha256: "ef56ab78" } },
      { code: "catalog-unknown", a: { count: 41, sha256: "ab12cd34" }, b: null },
      { code: "schema-changed", a: 1, b: 2 },
    ],
    counts: { resolved: 2, new: 3, "impact-changed": 1, same: 1 },
    items: [
      {
        class: "resolved",
        kind: "measured",
        rule: "CTX-01",
        axis: "context",
        key: { measurementRef: "/context/alwaysLoaded/estTokensTotal", trigger: "always-loaded-total-high" },
        a: measuredSide("high", "The always-loaded total is high."),
        b: null,
      },
      {
        class: "resolved",
        kind: "measured",
        rule: "SEC-02",
        axis: "security",
        key: { measurementRef: "/security/destructiveCoverage/commands/0", trigger: null },
        a: measuredSide("low", null, { cited: false, id: "mf-9" }),
        b: null,
      },
      {
        class: "new",
        kind: "judgment",
        rule: "COD-04",
        axis: "code",
        key: { files: [".claude/settings.json", "apps/web/CLAUDE.md"] },
        a: null,
        b: judgmentSide("medium", "A reader for the permission settings may already exist."),
      },
      {
        class: "new",
        kind: "measured",
        rule: "STR-02",
        axis: "structure",
        key: { measurementRef: "/structure/mapCoverage/dirs", trigger: "large-file-unprotected" },
        a: null,
        b: measuredSide("low", "A large file is not protected.", { id: "mf-12" }),
      },
      {
        class: "new",
        kind: "judgment",
        rule: "COD-04",
        axis: "code",
        key: { files: [] },
        a: null,
        b: judgmentSide("low", "Another reader.", 1),
      },
      {
        class: "impact-changed",
        kind: "measured",
        rule: "SEC-02",
        axis: "security",
        key: { measurementRef: "/security/destructiveCoverage/commands/0", trigger: null },
        a: measuredSide("medium", "Old summary."),
        b: measuredSide("high", "New summary."),
      },
      {
        class: "same",
        kind: "judgment",
        rule: "COD-04",
        axis: "code",
        key: { files: [".claude/settings.json"] },
        a: judgmentSide("low", "Same."),
        b: judgmentSide("low", "Same.", 1),
      },
    ],
  };
}

// Nothing in either run, and no item: each class is a sentence, and the warnings are a sentence.
function emptyComparison(language) {
  return {
    schemaVersion: 1,
    language,
    runs: {
      a: runOf({ head: null, depth: "standard", scope: null, catalog: null }),
      b: runOf({ head: null, depth: "standard", scope: [], catalog: null, findings: 0, measuredFindings: 0 }),
    },
    warnings: [],
    counts: { resolved: 0, new: 0, "impact-changed": 0, same: 0 },
    items: [],
  };
}

// Every text of the target and of the agent is hostile: a folder, a commit, a target, a file, a path, a trigger, a summary and a
// digest. Each one holds markup, a pipe or a scheme. A normal summary sits next to them, as the positive control.
function hostileComparison(language) {
  const [script, img, styleEnd, scheme, pipe] = HOSTILE;
  return {
    schemaVersion: 1,
    language,
    runs: {
      a: runOf({ name: img, target: styleEnd, head: script, scope: [pipe, script] }),
      b: runOf({ name: `run ${pipe}`, target: scheme, head: null, scope: null, catalog: { count: 2, sha256: script } }),
    },
    warnings: [
      { code: "target-changed", a: styleEnd, b: `${pipe}${script}` },
      { code: "scope-changed", a: [pipe], b: null },
    ],
    counts: { resolved: 0, new: 3, "impact-changed": 0, same: 0 },
    items: [
      {
        class: "new",
        kind: "judgment",
        rule: "COD-04",
        axis: "code",
        key: { files: [`${pipe}.md`, `${img}.md`, scheme] },
        a: null,
        b: judgmentSide("medium", `${script} ${styleEnd} ${scheme} | ${img}\nline two`),
      },
      {
        class: "new",
        kind: "measured",
        rule: "CTX-01",
        axis: "context",
        key: { measurementRef: `/a|b/${script}`, trigger: `t|${img}` },
        a: null,
        b: measuredSide("low", `${pipe} ${img}`),
      },
      {
        class: "new",
        kind: "judgment",
        rule: "COD-04",
        axis: "code",
        key: { files: ["apps/web/CLAUDE.md"] },
        a: null,
        b: judgmentSide("low", "Normal summary text.", 1),
      },
    ],
  };
}

// The scenarios of one language: the full, the empty and the hostile comparison.
function scenariosOf(language) {
  return [fullComparison(language), emptyComparison(language), hostileComparison(language)];
}

// Views -----------------------------------------------------------------------------------------------------

// The Markdown and the HTML of a comparison, with the shared files of the harness.
function views(comparison, labels = labelsEn) {
  const markdown = renderComparisonMarkdown(comparison, { labels, ruleTitles: RULE_TITLES });
  const page = renderComparisonHtml(comparison, {
    labels,
    ruleTitles: RULE_TITLES,
    template: TEMPLATE,
    theme: THEME,
    css: CSS,
  });
  return { markdown, html: page.html, csp: page.csp };
}

// The text between the tags of the one style element.
function styleText(html) {
  const match = html.match(/<style>([\s\S]*?)<\/style>/);
  assert.ok(match, "a style element");
  return match[1];
}

// The policy of the meta element, with its entities read back.
function metaCsp(html) {
  const match = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/);
  assert.ok(match, "the Content-Security-Policy meta element");
  return match[1].replaceAll("&#39;", "'");
}

// The lines of each table of a Markdown text: the consecutive lines that start with a pipe.
function tablesOf(markdown) {
  const tables = [];
  let current = null;
  for (const line of markdown.split("\n")) {
    if (line.startsWith("|")) {
      current ??= [];
      current.push(line);
    } else if (current !== null) {
      tables.push(current);
      current = null;
    }
  }
  if (current !== null) tables.push(current);
  return tables;
}

// The cell boundaries of a Markdown row: its pipes that no backslash escapes.
const boundaries = (line) => (line.match(/(?<!\\)\|/g) ?? []).length;

// Labels and pseudo-locale ---------------------------------------------------------------------------------

// A labels object whose reads are recorded: a read is a use of the key.
function recording(labels, used) {
  return new Proxy(labels, {
    get(target, key, receiver) {
      if (typeof key === "string") used.add(key);
      return Reflect.get(target, key, receiver);
    },
  });
}

// Each label becomes its key in markers, with its placeholders kept so the views can fill them.
function pseudoLabels(labels) {
  return Object.fromEntries(
    Object.entries(labels).map(([key, text]) => [
      key,
      `⟦${key}⟧${placeholdersOf(text).map((name) => ` {${name}}`).join("")}`,
    ]),
  );
}

// Every string of the comparison and of the rule titles: the data, whose words are allowed in the output.
function dataTexts(comparison) {
  const texts = [...RULE_TITLES.values()];
  const collect = (value) => {
    if (typeof value === "string") texts.push(value);
    else if (Array.isArray(value)) value.forEach(collect);
    else if (value !== null && typeof value === "object") Object.values(value).forEach(collect);
  };
  collect(comparison);
  return texts;
}

// The words of the Markdown that are not marker text and not in the data. Numbers, punctuation and the escapes are not words.
function leakedWords(markdown, texts) {
  const allowed = new Set();
  for (const text of texts) for (const word of text.match(/\p{L}+/gu) ?? []) allowed.add(word);
  const visible = markdown.replace(/⟦[^⟧]*⟧/gu, " ");
  const words = visible.match(/\p{L}+/gu) ?? [];
  return [...new Set(words)].filter((word) => !allowed.has(word));
}

// Tests ----------------------------------------------------------------------------------------------------

describe("labels of the comparison", () => {
  test("every compare label of each language is read by the views over the scenarios", () => {
    for (const [language, labels] of [
      ["en", labelsEn],
      ["es", labelsEs],
    ]) {
      const used = new Set();
      const recorded = recording(labels, used);
      for (const comparison of scenariosOf(language)) {
        renderComparisonMarkdown(comparison, { labels: recorded, ruleTitles: RULE_TITLES });
        renderComparisonHtml(comparison, {
          labels: recorded,
          ruleTitles: RULE_TITLES,
          template: TEMPLATE,
          theme: THEME,
          css: CSS,
        });
      }
      const unused = Object.keys(labels).filter((key) => key.startsWith("compare.") && !used.has(key));
      assert.deepEqual(unused, [], `${language}: compare labels that no scenario renders`);
    }
  });

  test("with every label replaced by a marker, no visible word comes from the code", () => {
    for (const [language, labels] of [
      ["en", labelsEn],
      ["es", labelsEs],
    ]) {
      const pseudo = pseudoLabels(labels);
      for (const comparison of scenariosOf(language)) {
        const markdown = renderComparisonMarkdown(comparison, { labels: pseudo, ruleTitles: RULE_TITLES });
        const leaked = leakedWords(markdown, dataTexts(comparison));
        assert.deepEqual(leaked, [], `words of the ${language} comparison that are not data`);
      }
    }
    const markdown = renderComparisonMarkdown(fullComparison("en"), { labels: pseudoLabels(labelsEn), ruleTitles: RULE_TITLES });
    assert.ok((markdown.match(/⟦/gu) ?? []).length > 40, "positive control: the pseudo-locale view has many markers");
  });
});

describe("the Markdown view", () => {
  test("it starts with the title and the table of the two runs, and ends with one line break", () => {
    const { markdown } = views(fullComparison("en"));
    assert.ok(markdown.startsWith("# Harness X-Ray comparison\n\n| Field | Run A | Run B |\n| --- | --- | --- |\n"));
    assert.ok(markdown.endsWith("\n") && !markdown.endsWith("\n\n"));
  });

  test("the runs table shows the scope, the catalog and the commit of each run", () => {
    const { markdown } = views(fullComparison("en"));
    assert.ok(markdown.includes("| Scope | the whole target | `apps/web`, `packages/ui` |"));
    assert.ok(markdown.includes("| Catalog | 41 rules, SHA-256 `ab12cd34` | not registered |"));
    assert.ok(markdown.includes("| Depth | Quick | Deep |"));
    const head = ["0123456789abcdef0123456789abcdef01234567", "fedcba9876543210fedcba9876543210fedcba98"];
    assert.ok(markdown.includes(`| Commit | \`${head[0]}\` | \`${head[1]}\` |`));
    assert.ok(markdown.includes("| Scan date (UTC) | 2026-10-01 | 2026-10-20 |"));
  });

  test("the warnings are a list with one text per code, each with its values", () => {
    const { markdown } = views(fullComparison("en"));
    const warnings = markdown.split("## Warnings\n\n")[1].split("\n\n")[0].split("\n");
    assert.equal(warnings.length, 6);
    assert.ok(warnings.every((line) => line.startsWith("- ")));
    assert.ok(warnings[2].includes("Run A: Quick. Run B: Deep."));
    assert.ok(warnings[4].includes("Run B: not registered."));
  });

  test("an impact that changed reads from to; a pair with the same impact, and one side alone, read one impact", () => {
    const { markdown } = views(fullComparison("en"));
    assert.ok(markdown.includes("| measured | Medium → High |"));
    assert.ok(markdown.includes("| measured | High |"));
    assert.equal(markdown.includes("Low → Low"), false, "a pair with the same impact shows one impact");
    assert.ok(markdown.includes("| `COD-04` | Reuse of the permission reader | judgment | Low | `.claude/settings.json` | Same. |"));
  });

  test("the class of a pair with the same impact is Same impact, in the counts and in its section", () => {
    const { markdown } = views(fullComparison("en"));
    assert.ok(markdown.includes("| Same impact | 1 |"));
    assert.ok(markdown.includes("## Findings with the same impact\n\n| Rule |"));
  });

  test("the summary is the one of run B, or of run A when the item has no B; an uncited measure says so", () => {
    const { markdown } = views(fullComparison("en"));
    assert.ok(markdown.includes("The always-loaded total is high."), "run A summary of a resolved item");
    assert.ok(markdown.includes("| A reader for the permission settings may already exist. |"), "run B summary of a new item");
    assert.ok(markdown.includes("| New summary. |"));
    assert.ok(markdown.includes("| not cited in findings.json |"));
  });

  test("a rule that the titles do not have shows a dash as its title; its id stays in the row", () => {
    const { markdown } = views(fullComparison("en"));
    const row = markdown.split("\n").find((line) => line.includes("`STR-02`"));
    assert.ok(row.startsWith("| `STR-02` | — | measured |"), row);
    assert.ok(markdown.includes("| `CTX-01` | Always-loaded total | measured |"));
  });

  test("a key is the path of its measure and its trigger, or the files of a judgment; no files is a dash", () => {
    const { markdown } = views(fullComparison("en"));
    assert.ok(markdown.includes("`/context/alwaysLoaded/estTokensTotal`, trigger `always-loaded-total-high`"));
    assert.ok(markdown.includes("| `/security/destructiveCoverage/commands/0` |"));
    assert.ok(markdown.includes("`.claude/settings.json`, `apps/web/CLAUDE.md`"));
    assert.ok(markdown.includes("| judgment | Low | — | Another reader. |"), "no files: a dash, and the one side's impact");
  });

  test("the sections follow the order resolved, new, impact changed, same, and an empty class is a sentence", () => {
    const { markdown } = views(emptyComparison("en"));
    const order = [
      "## Resolved findings",
      "## New findings",
      "## Findings with a changed impact",
      "## Findings with the same impact",
    ];
    let previous = -1;
    for (const heading of order) {
      const at = markdown.indexOf(`${heading}\n\nNone.`);
      assert.ok(at > previous, `${heading} followed by None.`);
      previous = at;
    }
    assert.ok(markdown.includes("## Warnings\n\nNo warnings."));
    assert.ok(markdown.includes("| Scope | the whole target | none |"));
  });

  test("the empty comparison in Spanish has the Spanish sentences", () => {
    const { markdown } = views(emptyComparison("es"), labelsEs);
    assert.ok(markdown.includes(`## ${labelsEs["compare.warnings.title"]}\n\n${labelsEs["compare.warnings.none"]}`));
    assert.ok(markdown.includes(`## ${labelsEs["compare.section.resolved"]}\n\n${labelsEs["compare.items.none"]}`));
    const noCommit = labelsEs["compare.value.noCommit"];
    assert.ok(markdown.includes(`| ${labelsEs["compare.field.commit"]} | ${noCommit} | ${noCommit} |`));
  });

  test("numbers are formatted in the language of the comparison", () => {
    assert.ok(views(fullComparison("en")).markdown.includes("| 12,345 |"));
    assert.ok(views(fullComparison("es"), labelsEs).markdown.includes("| 12.345 |"));
  });

  test("positive control: the same comparison gives the same bytes, in Markdown and in HTML", () => {
    for (const comparison of scenariosOf("en")) {
      const first = views(comparison);
      const second = views(comparison);
      assert.equal(first.markdown, second.markdown);
      assert.equal(first.html, second.html);
    }
  });
});

describe("the HTML view", () => {
  test("the page is the template with its markers filled: the language, the title and one style, and no script", () => {
    const { html } = views(fullComparison("es"), labelsEs);
    assert.ok(html.startsWith("<!doctype html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">"));
    assert.ok(html.includes(`<title>${labelsEs["compare.title"]}</title>`));
    assert.ok(html.includes(`<h1>${labelsEs["compare.title"]}</h1>`));
    assert.equal(html.split("<style>").length - 1, 1);
    assert.equal(/<script/i.test(html), false);
  });

  test("the page and the Markdown hold the blocks of buildComparisonBlocks, whole and in their order", () => {
    for (const comparison of scenariosOf("en")) {
      const blocks = buildComparisonBlocks(comparison, { labels: labelsEn, ruleTitles: RULE_TITLES });
      const { markdown, html } = views(comparison);
      assert.equal(markdown, `${blocksMarkdown(blocks)}\n`, "the Markdown is the blocks, whole");
      assert.ok(html.includes(blocksHtml(blocks)), "the page holds the blocks as HTML, whole");
    }
    const { html } = views(fullComparison("en"));
    const headings = [...html.matchAll(/<h[12]>([^<]*)<\/h[12]>/g)].map((match) => match[1]);
    assert.deepEqual(headings.slice(0, 2), ["Harness X-Ray comparison", "Warnings"]);
    assert.deepEqual(headings.slice(-4), [
      "Resolved findings",
      "New findings",
      "Findings with a changed impact",
      "Findings with the same impact",
    ]);
  });

  test("positive control: the policy and the style are the expected ones, and the style has no filter rule", () => {
    const { html, csp } = views(fullComparison("en"));
    const style = styleText(html);
    assert.equal(style, [THEME, CSS].join("\n").replace(/\r\n?/g, "\n"));
    assert.equal(style.includes("body:has("), false, "no filter rule");
    assert.equal(csp, `default-src 'none'; style-src ${cspHash(style)}; img-src 'none'; base-uri 'none'; form-action 'none'`);
    assert.equal(metaCsp(html), csp);
  });

  test("the policy has the form of the report page's policy, and each page names its own style by its hash", () => {
    const { html, csp } = views(fullComparison("en"));
    assert.match(csp, POLICY_FORM);
    assert.equal(pagePolicy(styleText(html)), csp);
    const model = { language: "en", sections: Object.fromEntries(MARKERS.map((name) => [name, []])), unexplained: [] };
    const report = renderHtml(model, { template: REPORT_TEMPLATE, theme: THEME, css: CSS, labels: labelsEn });
    assert.match(report.csp, POLICY_FORM);
    assert.equal(pagePolicy(styleText(report.html)), report.csp);
  });

  test("the page has no link, no form, no image and no resource from outside", () => {
    for (const comparison of scenariosOf("en")) {
      const { html } = views(comparison);
      const names = [...html.matchAll(/<\/?([A-Za-z][A-Za-z0-9-]*)/g)].map((match) => match[1].toLowerCase());
      assert.deepEqual([...new Set(names)].filter((name) => !ALLOWED_TAGS.has(name)), [], "tags the page does not use");
      // The texts are escaped, so an attribute name in a text ("src=x" in a shown summary) is not an attribute: only the
      // tags count.
      for (const tag of html.match(/<[a-zA-Z][^>]*>/g) ?? []) {
        assert.equal(/\s(?:href|src|on[a-z]+)\s*=/i.test(tag), false, `a link, a resource or an event attribute in ${tag}`);
      }
    }
  });
});

describe("hostile texts", () => {
  test("markup in the comparison's texts is inert in the page", () => {
    const { html, csp } = views(hostileComparison("en"));
    assert.equal(/<script/i.test(html), false, "a script element");
    assert.equal(/<img/i.test(html), false, "an image element");
    assert.equal(html.split("</style>").length - 1, 1, "only the closing tag of the template's style");
    assert.equal(html.includes("href="), false, "a link");
    assert.equal(metaCsp(html), csp);
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "the script text, escaped");
    const names = [...html.matchAll(/<\/?([A-Za-z][A-Za-z0-9-]*)/g)].map((match) => match[1].toLowerCase());
    assert.deepEqual([...new Set(names)].filter((name) => !ALLOWED_TAGS.has(name)), []);
  });

  test("a pipe in a text does not break a table of the Markdown: each row keeps the cells of its header", () => {
    const { markdown } = views(hostileComparison("en"));
    const tables = tablesOf(markdown);
    assert.deepEqual(
      new Set(tables.map((table) => boundaries(table[0]))),
      new Set([3, 4, 7]),
      "the counts, the runs and the items tables",
    );
    for (const table of tables) {
      assert.equal(new Set(table.map(boundaries)).size, 1, `every row of a table has the same cells: ${table[0]}`);
    }
    const rows = markdown.split("\n").filter((line) => line.includes("line two"));
    assert.equal(rows.length, 1, "the summary with a line break is one row");
    assert.ok(rows[0].startsWith("|"), "the row is a table row");
  });

  test("positive control: a normal summary is shown as it is, in both views", () => {
    const { markdown, html } = views(hostileComparison("en"));
    assert.ok(markdown.includes("| Normal summary text. |"));
    assert.ok(html.includes("Normal summary text."));
  });
});

describe("refusals", () => {
  test("a comparison that breaks the contract is refused", () => {
    const options = { labels: labelsEn, ruleTitles: RULE_TITLES };
    assert.throws(() => buildComparisonBlocks(null, options), /must be the parsed comparison\.json/);

    const badWarning = fullComparison("en");
    badWarning.warnings.push({ code: "made-up", a: 1, b: 2 });
    assert.throws(() => buildComparisonBlocks(badWarning, options), /warnings\[6\]\.code must be one of/);

    const badDepth = fullComparison("en");
    badDepth.runs.b.depth = "fast";
    assert.throws(() => buildComparisonBlocks(badDepth, options), /runs\.b\.depth must be one of quick, standard, deep/);

    const badImpact = fullComparison("en");
    badImpact.items[0].a.impact = "huge";
    assert.throws(() => buildComparisonBlocks(badImpact, options), /items\[0\]\.a\.impact must be one of high, medium, low/);
  });

  test("a value outside its form is refused; the message names the field and the index, and never the value (positive control: the good form passes)", () => {
    const options = { labels: labelsEn, ruleTitles: RULE_TITLES };
    const VALUE = "HOSTILE-VALUE-7f3a";
    const broken = [
      ["warnings[0].a", (c) => { c.warnings = [{ code: "scope-changed", a: VALUE, b: null }]; }],
      ["warnings[0].a", (c) => { c.warnings = [{ code: "scope-changed", a: [VALUE, 4], b: null }]; }],
      ["warnings[0].b", (c) => { c.warnings = [{ code: "schema-changed", a: 1, b: 2.5 }]; }],
      ["warnings[0].a", (c) => { c.warnings = [{ code: "schema-changed", a: VALUE, b: 2 }]; }],
      ["warnings[0].a", (c) => { c.warnings = [{ code: "depth-changed", a: VALUE, b: "deep" }]; }],
      ["warnings[0].b", (c) => { c.warnings = [{ code: "catalog-changed", a: { count: 1, sha256: "ab12cd34" }, b: VALUE }]; }],
      ["warnings[0].code", (c) => { c.warnings = [{ code: VALUE, a: 1, b: 2 }]; }],
      ["runs.b.depth", (c) => { c.runs.b.depth = VALUE; }],
      ["runs.a.scannedAt", (c) => { c.runs.a.scannedAt = "yesterday"; }],
      ["runs.a.scope[0]", (c) => { c.runs.a.scope = [7]; }],
      ["runs.a.catalog", (c) => { c.runs.a.catalog = { count: VALUE, sha256: "ab12cd34" }; }],
      ["runs.a.schemaVersion", (c) => { c.runs.a.schemaVersion = 1.5; }],
      ["items[0].class", (c) => { c.items[0].class = VALUE; }],
      ["items[0].kind", (c) => { c.items[0].kind = VALUE; }],
      ["items[0].a.impact", (c) => { c.items[0].a.impact = VALUE; }],
      ["items[0].a.summary", (c) => { c.items[0].a.summary = 5; }],
      ["items[0].key.trigger", (c) => { c.items[0].key.trigger = 5; }],
    ];
    for (const [field, change] of broken) {
      const bad = fullComparison("en");
      change(bad);
      assert.throws(
        () => buildComparisonBlocks(bad, options),
        (error) => {
          assert.ok(error instanceof TypeError, `${field}: a TypeError`);
          assert.ok(error.message.includes(field), `${field} is named: ${error.message}`);
          assert.equal(error.message.includes(VALUE), false, `${field}: the message holds no value`);
          return true;
        },
      );
    }

    const good = fullComparison("en");
    good.warnings = [
      { code: "scope-changed", a: null, b: ["apps/web"] },
      { code: "schema-changed", a: 1, b: 2 },
      { code: "catalog-unknown", a: null, b: { count: 2, sha256: "ab12cd34" } },
    ];
    assert.doesNotThrow(() => buildComparisonBlocks(good, options));
    assert.doesNotThrow(() => buildComparisonBlocks(fullComparison("en"), options));
  });

  test("the titles must be a Map, and a label that is missing is an error", () => {
    assert.throws(
      () => buildComparisonBlocks(fullComparison("en"), { labels: labelsEn, ruleTitles: { "CTX-01": "x" } }),
      /ruleTitles must be a Map/,
    );
    const short = { ...labelsEn };
    delete short["compare.title"];
    assert.throws(
      () => buildComparisonBlocks(fullComparison("en"), { labels: short, ruleTitles: RULE_TITLES }),
      /no text for "compare\.title"/,
    );
  });

  test("a template with a repeated marker, and a stylesheet with a closing style tag, are refused", () => {
    const comparison = fullComparison("en");
    assert.throws(
      () =>
        renderComparisonHtml(comparison, {
          labels: labelsEn,
          ruleTitles: RULE_TITLES,
          template: TEMPLATE.replace("</main>", "{{body}}</main>"),
          theme: THEME,
          css: CSS,
        }),
      /templates\/comparison\.html must have the marker \{\{body\}\} once, found 2/,
    );
    assert.throws(
      () =>
        renderComparisonHtml(comparison, {
          labels: labelsEn,
          ruleTitles: RULE_TITLES,
          template: TEMPLATE,
          theme: THEME,
          css: "p { color: red; }</style>",
        }),
      /closing style tag/,
    );
  });
});
