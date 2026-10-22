import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { loadTheme, cspHash, escapeHtml } from "../scripts/lib/html.mjs";
import { AXES, IMPACTS, loadRules } from "../scripts/lib/findings-validate.mjs";
import { httpsHref, renderHtml } from "../scripts/lib/report-html.mjs";
import { MARKERS, buildReportModel } from "../scripts/lib/report.mjs";
import { readCatalog } from "../scripts/lib/report-catalog.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";
import { HARNESS_ROOT, makeRun, readGoldenFindings } from "./helpers/report-run.mjs";

const TEMPLATE = fs.readFileSync(path.join(HARNESS_ROOT, "templates", "report.html"), "utf8");
const CSS = fs.readFileSync(path.join(HARNESS_ROOT, "templates", "report.css"), "utf8");
const THEME = loadTheme(HARNESS_ROOT);
const labelsEn = loadLabels(HARNESS_ROOT, "en");
const labelsEs = loadLabels(HARNESS_ROOT, "es");
// The tags that the page uses. A tag that the escaping does not stop would show up as another name here.
const ALLOWED_TAGS = new Set([
  "html", "head", "meta", "title", "style", "body", "main", "section", "h1", "h2", "h3", "h4", "p", "dl", "div", "dt", "dd",
  "table", "thead", "tbody", "tr", "th", "td", "ul", "li", "article", "fieldset", "legend", "label", "input", "code", "strong", "a",
]);
// Addresses that are not https. Each one must be refused as a link, and each one is text on the page.
const NOT_HTTPS = ["javascript:alert(1)", "JavaScript:alert(1)", "data:text/html,<script>alert(1)</script>", "http://example.com/a", "/relative/path", "", "not a url", "https://"];

let run;
let catalog;

before(async () => {
  run = await makeRun();
  catalog = readCatalog(HARNESS_ROOT, loadRules(HARNESS_ROOT));
});

after(() => run?.cleanup());

// Helpers ---------------------------------------------------------------------------------------------------------

// Renders a page with the shared files of the harness, unless an option replaces one of them.
function render(model, options = {}) {
  return renderHtml(model, { template: TEMPLATE, theme: THEME, css: CSS, labels: labelsEn, ...options });
}

// A model with the given blocks in the given sections; every other section is empty.
function modelOf(sections = {}, language = "en") {
  return {
    language,
    sections: Object.fromEntries(MARKERS.map((name) => [name, sections[name] ?? []])),
    unexplained: [],
  };
}

// A model with one paragraph of runs in the summary section.
function paragraphOf(...runs) {
  return modelOf({ summary: [{ type: "paragraph", runs }] });
}

const text = (value) => ({ type: "text", text: value });

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

// The structure of a page is not text: only the known tags, one style element, and no script, image, link, event attribute
// or style attribute. Escaped text has no "<", so a hostile text adds no tag and no attribute.
function assertInert(html) {
  const names = [...html.matchAll(/<\/?([A-Za-z][A-Za-z0-9-]*)/g)].map((match) => match[1].toLowerCase());
  assert.deepEqual([...new Set(names)].filter((name) => !ALLOWED_TAGS.has(name)), [], "tags the page does not use");
  for (const tag of html.match(/<[a-zA-Z][^>]*>/g) ?? []) {
    assert.equal(/\son[a-z]+\s*=/i.test(tag), false, `an event attribute in ${tag}`);
    assert.equal(/\sstyle\s*=/i.test(tag), false, `a style attribute in ${tag}`);
    assert.equal(/\ssrc\s*=/i.test(tag), false, `a src attribute in ${tag}`);
  }
  assert.equal(/<script/i.test(html), false, "a script");
  assert.equal(/<img/i.test(html), false, "an image");
  assert.equal(/<link/i.test(html), false, "a link element");
  assert.equal(html.split("</style>").length - 1, 1, "one closing style tag");
  assert.equal(html.match(/<style\b/gi).length, 1, "one style element");
}

// The links of a model, found in any block or run.
function linksOf(value, found = []) {
  if (Array.isArray(value)) value.forEach((item) => linksOf(item, found));
  else if (value !== null && typeof value === "object") {
    if (value.type === "link") found.push(value);
    Object.values(value).forEach((item) => linksOf(item, found));
  }
  return found;
}

// A labels object whose reads are recorded: a read is a use of the key.
function recording(labels, used) {
  return new Proxy(labels, {
    get(target, key, receiver) {
      if (typeof key === "string") used.add(key);
      return Reflect.get(target, key, receiver);
    },
  });
}

// Escaping -------------------------------------------------------------------------------------------------

describe("escaping", () => {
  test("markup in a text becomes text: no tag, no script, no image, no attribute", () => {
    const hostile = `<script>alert(1)</script> <img src=x onerror=alert(1)> </style>`;
    const { html } = render(paragraphOf(text(hostile)));
    assert.ok(html.includes(`<p>${escapeHtml(hostile)}</p>`), "the hostile text, escaped");
    assert.ok(html.includes("<p>&lt;script&gt;alert(1)&lt;/script&gt; &lt;img src=x onerror=alert(1)&gt; &lt;/style&gt;</p>"));
    assertInert(html);
  });

  test("quotes and the ampersand are escaped in a text and in an attribute", () => {
    const { html } = render(
      modelOf({
        summary: [{ type: "paragraph", runs: [text(`say "hi" & 'bye'`)] }],
        findings: [{ type: "finding", ruleId: 'SEC-"01', axis: "security", impact: "high", blocks: [] }],
      }),
    );
    assert.ok(html.includes("<p>say &quot;hi&quot; &amp; &#39;bye&#39;</p>"), "the text");
    assert.ok(html.includes('data-rule="SEC-&quot;01"'), "the attribute");
    assertInert(html);
  });

  test("a marker-like text stays literal, and the style element is still the only one", () => {
    const { html } = render(paragraphOf(text("{{style}} and {{findings}} and {{ csp }}")));
    assert.ok(html.includes("<p>{{style}} and {{findings}} and {{ csp }}</p>"));
    assert.equal(html.match(/<style\b/gi).length, 1);
  });

  test("positive control: a normal text is unchanged", () => {
    const { html } = render(paragraphOf(text("Normal text, unchanged.")));
    assert.ok(html.includes("<p>Normal text, unchanged.</p>"));
  });
});

// Links ----------------------------------------------------------------------------------------------------

describe("links", () => {
  test("httpsHref accepts an https address, and returns it normalized", () => {
    assert.equal(httpsHref("https://example.com/a"), "https://example.com/a");
    assert.equal(httpsHref("https://example.com"), "https://example.com/");
    assert.equal(httpsHref("HTTPS://EXAMPLE.COM/x"), "https://example.com/x");
  });

  test("httpsHref refuses every other address, and never throws", () => {
    for (const url of [...NOT_HTTPS, undefined, null, 42, {}]) {
      assert.equal(httpsHref(url), null, `${String(url)}`);
    }
  });

  test("a link to an address that is not https has no a element and no href, and its address is shown escaped", () => {
    for (const url of [...NOT_HTTPS, 'javascript:alert("x")']) {
      const { html } = render(paragraphOf({ type: "link", label: "Docs", url }));
      assert.equal(html.includes("<a "), false, `no a element for ${url}`);
      assert.equal(/href\s*=/i.test(html), false, `no href for ${url}`);
      assert.ok(html.includes(`<p><code>${escapeHtml(url)}</code></p>`), `only the address of ${url}, as escaped code`);
      assertInert(html);
    }
    const { html } = render(paragraphOf({ type: "link", label: "x", url: 'javascript:alert("x")' }));
    assert.ok(html.includes("<code>javascript:alert(&quot;x&quot;)</code>"));
  });

  test("a link to an https address is an a element with its normalized address, escaped", () => {
    const url = 'https://example.com/a?b=1&c="2"<3>';
    const { html } = render(paragraphOf({ type: "link", label: "Example", url }));
    assert.ok(html.includes(`<a href="${escapeHtml(new URL(url).href)}" rel="noreferrer noopener">Example</a>`));
    assert.equal(html.includes("<img"), false);
    assertInert(html);
  });

  test("positive control: a plain https link is an a element with the rel attribute", () => {
    const { html } = render(paragraphOf({ type: "link", label: "Example", url: "https://example.com/a" }));
    assert.ok(html.includes('<a href="https://example.com/a" rel="noreferrer noopener">Example</a>'));
  });
});

// The page -----------------------------------------------------------------------------------------------

describe("the page", () => {
  test("the policy names the hash of the exact text of the style element, and the meta element holds it", () => {
    const { html, csp } = render(paragraphOf(text("x")));
    const style = styleText(html);
    const hash = `'sha256-${crypto.createHash("sha256").update(style, "utf8").digest("base64")}'`;
    assert.equal(cspHash(style), hash);
    assert.equal(csp, `default-src 'none'; style-src ${hash}; img-src 'none'; base-uri 'none'; form-action 'none'`);
    assert.equal(metaCsp(html), csp);
  });

  test("the policy meta element comes before the style element, and the style closes before the body", () => {
    const { html } = render(paragraphOf(text("x")));
    assert.ok(html.indexOf('http-equiv="Content-Security-Policy"') < html.indexOf("<style>"));
    assert.ok(html.indexOf("</style>") < html.indexOf("<body"));
  });

  test("CRLF and lone CR in the stylesheets become LF before the hash, so the policy names the hash of the text the browser sees", () => {
    const lf = render(paragraphOf(text("x")));
    const crlf = render(paragraphOf(text("x")), { theme: THEME.replace(/\n/g, "\r\n"), css: CSS.replace(/\n/g, "\r\n") });
    const loneCr = render(paragraphOf(text("x")), { theme: THEME.replace(/\n/g, "\r"), css: CSS.replace(/\n/g, "\r") });
    for (const { html, csp } of [crlf, loneCr]) {
      const style = styleText(html);
      assert.equal(style.includes("\r"), false, "a carriage return in the style");
      assert.equal(metaCsp(html), csp);
      assert.ok(csp.includes(`style-src ${cspHash(style)};`), "the hash of the exact text between the style tags");
    }
    // Positive control: the LF stylesheets give the page they always gave, and CRLF stylesheets give the same page.
    assert.equal(crlf.html, lf.html);
    assert.ok(styleText(lf.html).startsWith(THEME), "the theme, unchanged");
  });

  test("the style text is the shared stylesheet, then the report rules, then the filter rules", () => {
    const style = styleText(render(paragraphOf(text("x"))).html);
    assert.ok(style.includes("--color-background:"), "the color tokens");
    assert.ok(style.includes(".table-wrap {"), "the report rules");
    assert.ok(style.includes("body:has(#filter-axis-"), "the filter rules");
    assert.ok(style.indexOf("--color-background:") < style.indexOf(".table-wrap {"));
    assert.ok(style.indexOf(".table-wrap {") < style.indexOf("body:has(#filter-axis-"));
  });

  test("the page has no script, no event attribute, no style attribute, no external resource and no URL in its style", () => {
    const { html } = render(paragraphOf(text("x")));
    assertInert(html);
    assert.equal(/url\s*\(|@import/i.test(styleText(html)), false, "url() or an import in the style");
    assert.equal(/https?:/i.test(styleText(html)), false, "an address in the style");
  });

  test("the page declares the language, the charset, the referrer policy and the viewport", () => {
    const { html } = render(modelOf());
    assert.ok(html.startsWith("<!doctype html>\n<html lang=\"en\">"));
    assert.ok(html.includes('<meta charset="utf-8">'));
    assert.ok(html.includes('<meta name="referrer" content="no-referrer">'));
    assert.ok(html.includes('<meta name="viewport" content="width=device-width, initial-scale=1">'));
    assert.ok(html.includes(`<title>${labelsEn["header.title"]}</title>`));
  });

  test("a Spanish model gives a Spanish page, with the Spanish title", () => {
    const { html } = render(modelOf({}, "es"), { labels: labelsEs });
    assert.ok(html.includes('<html lang="es">'));
    assert.ok(html.includes(`<title>${labelsEs["header.title"]}</title>`));
  });
});

// Structure ------------------------------------------------------------------------------------------------

describe("structure", () => {
  test("each section is a section element, and each block has its element", () => {
    const model = modelOf({
      header: [
        { type: "heading", level: 1, runs: [text("Title")] },
        { type: "fields", items: [{ label: [text("Target")], runs: [{ type: "code", text: "app" }] }] },
      ],
      summary: [
        { type: "heading", level: 2, runs: [text("Summary")] },
        {
          type: "table",
          headers: [[text("Axis")], [text("High")]],
          rows: [[[text("Security")], [text("1")]]],
        },
        { type: "list", items: [[text("one")], [text("two")]] },
      ],
      findings: [
        { type: "heading", level: 3, runs: [text("Security")] },
        {
          type: "finding",
          ruleId: "SEC-01",
          axis: "security",
          impact: "high",
          blocks: [
            { type: "heading", level: 4, runs: [text("SEC-01 · Title")] },
            { type: "paragraph", runs: [{ type: "strong", runs: [text("Bold")] }] },
          ],
        },
      ],
    });
    const { html } = render(model);
    // The remediation section has no element when the model has none (a report without remediation.json).
    assert.equal(html.match(/<section>/g).length, MARKERS.length - 1);
    assert.ok(html.includes("<h1>Title</h1>"));
    assert.ok(html.includes('<dl class="fields"><div><dt>Target</dt><dd><code>app</code></dd></div></dl>'));
    assert.ok(html.includes("<h2>Summary</h2>"));
    assert.ok(
      html.includes(
        '<div class="table-wrap" tabindex="0"><table><thead><tr><th scope="col">Axis</th><th scope="col">High</th></tr></thead>' +
          "<tbody><tr><td>Security</td><td>1</td></tr></tbody></table></div>",
      ),
    );
    assert.ok(html.includes("<ul><li>one</li><li>two</li></ul>"));
    assert.ok(html.includes('<h3>Security</h3>'));
    assert.ok(html.includes('<article class="finding" data-axis="security" data-impact="high" data-rule="SEC-01">'));
    assert.ok(html.includes("<h4>SEC-01 · Title</h4>"));
    assert.ok(html.includes("<p><strong>Bold</strong></p>"));
    assertInert(html);
  });

  test("a finding with an axis or an impact outside the known lists is an error", () => {
    const finding = (axis, impact) => ({ type: "finding", ruleId: "SEC-01", axis, impact, blocks: [] });
    assert.throws(() => render(modelOf({ findings: [finding("nope", "high")] })), /unknown axis: nope/);
    assert.throws(() => render(modelOf({ findings: [finding("security", "critical")] })), /unknown impact: critical/);
    assert.throws(() => render(modelOf({ findings: [finding("security", "High")] })), /unknown impact: High/);
    // Positive control: the same finding with known values renders.
    const { html } = render(modelOf({ findings: [finding("security", "low")] }));
    assert.ok(html.includes('data-axis="security" data-impact="low"'));
  });

  test("a heading level outside 1 to 4, and a row with another number of cells, are errors", () => {
    assert.throws(() => render(modelOf({ summary: [{ type: "heading", level: 5, runs: [text("x")] }] })), /levels are 1 to 4/);
    const ragged = { type: "table", headers: [[text("a")], [text("b")]], rows: [[[text("only one")]]] };
    assert.throws(() => render(modelOf({ summary: [ragged] })), /1 cells for 2 headers/);
  });

  test("the model must be a report model, and its language a known one", () => {
    assert.throws(() => render({ ...modelOf(), language: "fr" }), /language must be one of/);
    assert.throws(() => render({ language: "en", sections: {} }), /must be a list of blocks/);
  });
});

// Template -----------------------------------------------------------------------------------------------

describe("template markers", () => {
  test("every marker of the template is in it once, and the shipped template renders", () => {
    for (const name of ["lang", "csp", "title", "style", "filters", ...MARKERS]) {
      assert.equal(TEMPLATE.split(`{{${name}}}`).length - 1, 1, `{{${name}}} once`);
    }
    assert.ok(render(modelOf()).html.length > 0);
  });

  test("a missing marker is an error", () => {
    const template = TEMPLATE.replace("{{title}}", "");
    assert.throws(() => render(modelOf(), { template }), /must have the marker \{\{title\}\} once, found 0/);
  });

  test("a repeated marker is an error", () => {
    const template = TEMPLATE.replace("</main>", "{{header}}</main>");
    assert.throws(() => render(modelOf(), { template }), /must have the marker \{\{header\}\} once, found 2/);
  });

  test("an unknown marker is an error", () => {
    const template = TEMPLATE.replace("</main>", "{{nope}}</main>");
    assert.throws(() => render(modelOf(), { template }), /unknown marker \{\{nope\}\}/);
  });

  test("a stylesheet with a closing style tag is an error", () => {
    assert.throws(() => render(modelOf(), { css: "p { color: red; }</style>" }), /closing style tag/);
    assert.throws(() => render(modelOf(), { theme: "/* </STYLE> */" }), /closing style tag/);
  });
});

// Filters ----------------------------------------------------------------------------------------------------

describe("filters", () => {
  test("every axis and every impact has a checked checkbox, followed by its label", () => {
    const { html } = render(modelOf());
    for (const axis of AXES) {
      const id = `filter-axis-${axis}`;
      assert.ok(html.includes(`<input type="checkbox" class="visually-hidden" id="${id}" checked>\n<label for="${id}">${labelsEn[`axis.${axis}`]}</label>`), id);
    }
    for (const impact of IMPACTS) {
      const id = `filter-impact-${impact}`;
      assert.ok(html.includes(`<input type="checkbox" class="visually-hidden" id="${id}" checked>\n<label for="${id}">${labelsEn[`impact.${impact}`]}</label>`), id);
    }
  });

  test("every axis and every impact has a CSS rule that hides its findings when its box is unchecked", () => {
    const { html } = render(modelOf());
    const style = styleText(html);
    for (const axis of AXES) {
      assert.ok(style.includes(`body:has(#filter-axis-${axis}:not(:checked)) .finding[data-axis="${axis}"] { display: none; }`), axis);
    }
    for (const impact of IMPACTS) {
      assert.ok(style.includes(`body:has(#filter-impact-${impact}:not(:checked)) .finding[data-impact="${impact}"] { display: none; }`), impact);
    }
  });

  test("the filters are not a form, the boxes are visually hidden and not removed from the focus order", () => {
    const { html } = render(modelOf());
    assert.equal(/<form/i.test(html), false, "a form element");
    for (const tag of html.match(/<input\b[^>]*>/g)) {
      assert.equal(/\shidden\b|type="hidden"/i.test(tag), false, `an input that is removed: ${tag}`);
    }
    const style = styleText(html);
    assert.ok(/\.visually-hidden \{[^}]*clip: rect/.test(style), "the visually hidden class clips the box");
    assert.equal(/\.visually-hidden \{[^}]*display: none/.test(style), false);
  });

  test("the filter legend, the axis group and the impact group are in the page", () => {
    const { html } = render(modelOf());
    assert.ok(html.includes(`<legend>${labelsEn["html.filter.legend"]}</legend>`));
    assert.ok(html.includes(`<p class="filter-title" id="filter-title-axis">${labelsEn["html.filter.axes"]}</p>`));
    assert.ok(html.includes(`<p class="filter-title" id="filter-title-impact">${labelsEn["field.impact"]}</p>`));
  });
});

// Labels -----------------------------------------------------------------------------------------------------

describe("labels of the page", () => {
  test("every html label is read by the view over the golden model", () => {
    const used = new Set();
    render(goldenModel(labelsEn), { labels: recording(labelsEn, used) });
    const htmlKeys = Object.keys(labelsEn).filter((key) => key.startsWith("html."));
    assert.ok(htmlKeys.length > 0);
    assert.deepEqual(htmlKeys.filter((key) => !used.has(key)), [], "html labels that the view does not read");
  });

  test("the html labels have no digit in either language", () => {
    for (const labels of [labelsEn, labelsEs]) {
      for (const [key, value] of Object.entries(labels)) {
        if (key.startsWith("html.")) assert.equal(/\d/.test(value), false, key);
      }
    }
  });
});

// The golden report -------------------------------------------------------------------------------------

// The model of the golden run, in the language of the given labels.
function goldenModel(labels) {
  const language = labels === labelsEs ? "es" : "en";
  const findings = readGoldenFindings(`findings.${language}.json`);
  return buildReportModel({ measurements: run.measurements, findings, catalog, labels });
}

describe("the golden report", () => {
  test("every finding of the model is an article with its axis, impact and rule, and the page stays inert", () => {
    const model = goldenModel(labelsEn);
    const { html } = render(model);
    const findings = model.sections.findings.filter((block) => block.type === "finding");
    assert.ok(findings.length > 0);
    assert.equal(html.match(/<article class="finding"/g).length, findings.length);
    for (const finding of findings) {
      assert.ok(html.includes(`data-axis="${finding.axis}" data-impact="${finding.impact}" data-rule="${finding.ruleId}"`), finding.ruleId);
    }
    assertInert(html);
  });

  test("every link of the golden report is an https link, and the other links are text", () => {
    const model = goldenModel(labelsEn);
    const links = linksOf(model.sections);
    assert.ok(links.length > 0, "positive control: the golden report has links");
    const { html } = render(model);
    const httpsLinks = links.filter((link) => httpsHref(link.url) !== null);
    assert.equal(html.match(/<a href="/g)?.length ?? 0, httpsLinks.length);
    assert.equal(/href="(?!https:\/\/)/.test(html), false, "an href that is not https");
  });

  test("the Spanish golden report is in Spanish, with the Spanish filter legend", () => {
    const { html } = render(goldenModel(labelsEs), { labels: labelsEs });
    assert.ok(html.includes('<html lang="es">'));
    assert.ok(html.includes(`<title>${labelsEs["header.title"]}</title>`));
    assert.ok(html.includes(`<legend>${labelsEs["html.filter.legend"]}</legend>`));
    assert.equal(html.includes(labelsEn["html.filter.legend"]), false);
  });
});
