import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { renderIntakeDone, renderIntakeError, renderIntakePage, renderQuestionsPage } from "../scripts/lib/intake-page.mjs";
import { MAX_ANSWER_LENGTH } from "../scripts/lib/questions.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ACTION = "/intake?token=abc123-XYZ_.~";
const QUESTIONS_ACTION = "/questions?token=abc123-XYZ_.~";
const AXES = ["instructions", "context", "security", "verification", "structure", "code"];
// The tags that the pages use. A tag that the escaping does not stop would show up as another name here.
const ALLOWED_TAGS = new Set([
  "html", "head", "meta", "title", "style", "body", "main", "h1", "p", "form", "fieldset", "legend",
  "label", "input", "span", "strong", "button", "a", "ul", "li", "code", "textarea",
]);

// A normal plan: three layers, one of them with a sub-folder that the person may narrow to.
const PLAN = {
  schemaVersion: 1,
  layers: [
    {
      name: "frontend",
      folders: ["apps/web"],
      reason: "package.json in apps/web, and the folder is named web",
      signals: ["manifest", "name"],
      options: ["apps/web/admin"],
    },
    { name: "backend", folders: ["apps/api"], reason: "Cargo.toml in apps/api", signals: ["manifest"] },
    { name: "database", folders: ["db"], reason: "the folder is named db", signals: ["name"] },
  ],
};

// The same shape with the hostile texts of the brief: a script, an image that runs code in an attribute, a closing style
// tag, a javascript: address, and a line break in the reason.
const HOSTILE_PLAN = {
  schemaVersion: 1,
  layers: [
    {
      name: "<script>alert(1)</script>",
      folders: ['"><img src=x onerror=alert(1)>'],
      reason: "</style>\njavascript:alert(1)",
      options: ["javascript:alert(1)"],
    },
    { name: "database", folders: ["db"], reason: "the folder is named db" },
  ],
};

// The questions as readQuestions returns them: one of each type, with the texts as the agent wrote them (redacted already).
const QUESTIONS = [
  {
    id: "contradiction",
    type: "single",
    text: "Which instruction file is right?",
    why: "CLAUDE.md and AGENTS.md give opposite test commands.",
    source: { file: "CLAUDE.md", line: 3 },
    options: [
      { id: "keep-claude", label: "Keep CLAUDE.md" },
      { id: "keep-agents", label: "Keep AGENTS.md" },
    ],
  },
  {
    id: "folders",
    type: "multi",
    text: "Which folders hold the frontend?",
    why: "The manifests do not say.",
    source: { file: "apps/web/package.json", line: 1 },
    options: [
      { id: "web", label: "apps/web" },
      { id: "admin", label: "apps/admin" },
    ],
  },
  {
    id: "generated",
    type: "text",
    text: "Is this file generated?",
    why: "It has no generator marker.",
    source: { file: "src/gen.ts", line: 1 },
  },
];

// The same shape with the hostile texts of the brief: a script in the text, an image in the reason, an attribute that would
// autofocus and run code in a label, and an SVG that runs code on load in a second label. The ids are valid, as the check requires.
const HOSTILE_QUESTIONS = [
  {
    id: "hostile",
    type: "single",
    text: "<script>alert(1)</script>",
    why: "<img src=x onerror=alert(1)>",
    source: { file: '"><svg onload=alert(1)>.md', line: 2 },
    options: [
      { id: "first-option", label: '" autofocus onfocus="alert(1)' },
      { id: "second-option", label: "'><svg onload=alert(1)>" },
    ],
  },
  { id: "note", type: "text", text: "Anything else?", why: "No marker.", source: { file: "README.md", line: 1 } },
];

let pseudoRoot;
let labelsEn;
let labelsEs;

before(() => {
  labelsEn = loadLabels(HARNESS_ROOT, "en");
  labelsEs = loadLabels(HARNESS_ROOT, "es");
  // A copy of the templates whose English labels are markers: each marker shows the key that the page rendered.
  pseudoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "xray-intake-"));
  fs.cpSync(path.join(HARNESS_ROOT, "templates"), path.join(pseudoRoot, "templates"), { recursive: true });
  const pseudo = Object.fromEntries(Object.keys(labelsEn).map((key) => [key, `⟦${key}⟧`]));
  fs.writeFileSync(path.join(pseudoRoot, "templates", "labels.en.json"), JSON.stringify(pseudo));
});

after(() => {
  if (pseudoRoot) fs.rmSync(pseudoRoot, { recursive: true, force: true });
});

// Helpers ---------------------------------------------------------------------------------------

function intake(overrides = {}) {
  return renderIntakePage({ harnessRoot: HARNESS_ROOT, plan: PLAN, action: ACTION, ...overrides });
}

// The text between the tags of the one style element.
function styleText(html) {
  const open = html.indexOf("<style>");
  const close = html.indexOf("</style>");
  assert.ok(open >= 0 && close > open, "one style element");
  assert.equal(html.split("<style>").length - 1, 1, "one opening style tag");
  return html.slice(open + "<style>".length, close);
}

// The name, the value, and the checked and required states of each input, in page order.
function controls(html) {
  return [...html.matchAll(/<input\b[^>]*>/g)].map(([tag]) => {
    const attributes = Object.fromEntries(
      [...tag.slice("<input".length).matchAll(/([a-zA-Z-]+)(?:="([^"]*)")?/g)].map(([, name, value]) => [name, value ?? true]),
    );
    return {
      type: attributes.type,
      name: attributes.name,
      value: attributes.value,
      checked: attributes.checked === true,
      required: attributes.required === true,
    };
  });
}

function checkedOf(html) {
  return controls(html)
    .filter((control) => control.checked)
    .map((control) => `${control.name}=${control.value}`)
    .sort();
}

// The structure of a page is not text: only the known tags, one style element, and no event attribute. Escaped text
// has no "<" at all, so a hostile text can add no tag and no attribute.
function assertInert(html) {
  const names = [...html.matchAll(/<\/?([A-Za-z][A-Za-z0-9-]*)/g)].map((match) => match[1].toLowerCase());
  assert.deepEqual([...new Set(names)].filter((name) => !ALLOWED_TAGS.has(name)), [], "tags the page does not use");
  assert.equal(/<[^>]*\son[a-z]+\s*=/i.test(html), false, "an event attribute on a tag");
  assert.equal(html.split("</style>").length - 1, 1, "one closing style tag");
  assert.equal(/<script/i.test(html), false, "a script");
  assert.equal(/<img/i.test(html), false, "an image");
  assert.equal(/\shref\s*=/i.test(html), false, "a link");
}

function metaCsp(html) {
  const match = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)">/);
  assert.ok(match, "the Content-Security-Policy meta element");
  return match[1];
}

// Tests -----------------------------------------------------------------------------------------

describe("the policy and the style", () => {
  test("the CSP meta element comes before the style element, and the charset and viewport come first", () => {
    const { html } = intake();
    const meta = html.indexOf('http-equiv="Content-Security-Policy"');
    assert.ok(meta > html.indexOf('<meta charset="utf-8">'), "charset before the policy");
    assert.ok(meta < html.indexOf("<style>"), "policy before the style");
    assert.ok(html.indexOf("<style>") < html.indexOf("</style>"));
    assert.equal(html.indexOf("<style"), html.indexOf("<style>"), "no style element before the policy");
  });

  test("the hash in the policy is the hash of the exact text of the style element", () => {
    const { html, csp } = intake();
    const style = styleText(html);
    const hash = `'sha256-${crypto.createHash("sha256").update(style, "utf8").digest("base64")}'`;
    assert.equal(csp, `default-src 'none'; style-src ${hash}; img-src 'none'; form-action 'self'; base-uri 'none'`);
    assert.equal(metaCsp(html), csp, "the meta element holds the policy that the caller gets");
  });

  test("the style text is the shared stylesheet followed by the intake rules", () => {
    const style = styleText(intake().html);
    assert.ok(style.includes("--color-background:"), "the color tokens");
    assert.ok(style.includes(".help {"), "the intake rules");
    assert.ok(style.indexOf("--color-background:") < style.indexOf(".help {"));
  });

  test("the page has no script, no external resource and no URL", () => {
    const { html } = intake();
    assert.equal(/<script/i.test(html), false);
    assert.equal(/https?:/i.test(html), false, "an http or https reference");
    assert.equal(/url\s*\(/i.test(html), false, "url()");
    assert.equal(/<link\b/i.test(html), false, "a link element");
    assertInert(html);
  });

  test("the done page has the same policy approach, with the hash of its own stylesheet", () => {
    const { html, csp } = renderIntakeDone({ harnessRoot: HARNESS_ROOT });
    const style = styleText(html);
    assert.equal(metaCsp(html), csp);
    assert.equal(csp, `default-src 'none'; style-src ${cspOf(style)}; img-src 'none'; form-action 'self'; base-uri 'none'`);
    assert.ok(html.indexOf('http-equiv="Content-Security-Policy"') < html.indexOf("<style>"));
    assert.equal(/<script|<form|https?:/i.test(html), false);
    assertInert(html);
  });
});

function cspOf(style) {
  return `'sha256-${crypto.createHash("sha256").update(style, "utf8").digest("base64")}'`;
}

describe("the form", () => {
  test("posts to the action given, and has no JavaScript", () => {
    const { html } = intake();
    assert.ok(html.includes(`<form method="post" action="${ACTION}">`));
    assert.equal(html.includes("<script"), false);
  });

  test("the defaults are the ones specified: standard depth, the whole repository, English, nothing extra", () => {
    const { html } = intake();
    assert.deepEqual(checkedOf(html), ["depth=standard", "language=en", "scope=all"]);
  });

  test("every question has its controls, with the values the server parses", () => {
    const found = controls(intake().html);
    const byName = (name) => found.filter((control) => control.name === name);
    assert.deepEqual(byName("depth").map((control) => [control.type, control.value]), [
      ["radio", "quick"],
      ["radio", "standard"],
      ["radio", "deep"],
    ]);
    assert.deepEqual(byName("scope").map((control) => [control.type, control.value]), [
      ["radio", "all"],
      ["radio", "layers"],
    ]);
    assert.deepEqual(byName("layer").map((control) => [control.type, control.value]), [
      ["checkbox", "0"],
      ["checkbox", "1"],
      ["checkbox", "2"],
    ]);
    assert.deepEqual(byName("axis").map((control) => [control.type, control.value]), AXES.map((axis) => ["checkbox", axis]));
    assert.deepEqual(byName("language").map((control) => [control.type, control.value]), [
      ["radio", "en"],
      ["radio", "es"],
    ]);
    assert.deepEqual(byName("userLayer").map((control) => [control.type, control.value, control.checked]), [
      ["checkbox", "yes", false],
    ]);
    assert.deepEqual(byName("ancestors").map((control) => [control.type, control.value, control.checked]), [
      ["checkbox", "yes", false],
    ]);
    assert.equal(found.length, 3 + 2 + 3 + AXES.length + 2 + 2);
  });

  test("a hint next to the layer checkboxes says they apply only when a selection of layers is chosen", () => {
    const en = intake().html;
    assert.ok(en.includes("These boxes apply only when"), "the English hint");
    const page = intake({ language: "es" }).html;
    assert.ok(page.includes("Estas casillas solo se aplican si eliges"), "the Spanish hint");
    // The hint is placed after the scope choices and before the first layer checkbox, using the marker copy of the templates.
    const marked = renderIntakePage({ harnessRoot: pseudoRoot, plan: PLAN, action: ACTION }).html;
    const hint = marked.indexOf("⟦intake.scope.layersHint⟧");
    assert.ok(marked.indexOf('name="scope" value="layers"') < hint && hint < marked.indexOf('name="layer"'), "the placement");
  });

  test("a plan with one layer still shows that layer", () => {
    const one = { schemaVersion: 1, layers: [PLAN.layers[2]] };
    const found = controls(intake({ plan: one }).html).filter((control) => control.name === "layer");
    assert.deepEqual(found.map((control) => control.value), ["0"]);
  });

  test("each layer shows its name, its folders and its reason", () => {
    const { html } = intake();
    assert.ok(html.includes("frontend") && html.includes("backend") && html.includes("database"));
    assert.ok(html.includes("Folders: apps/web") && html.includes("Folders: apps/api") && html.includes("Folders: db"));
    assert.ok(html.includes("package.json in apps/web, and the folder is named web"));
    assert.ok(html.includes("Sub-folders: apps/web/admin"), "the sub-folder of the layer with options");
  });
});

describe("hostile plan texts", () => {
  test("a plan with script, image, style-closing and javascript: texts shows them as inert text", () => {
    const { html } = intake({ plan: HOSTILE_PLAN });
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), "the name, as text");
    assert.ok(html.includes("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"), "the folder, as text");
    assert.ok(html.includes("Reason: &lt;/style&gt;\njavascript:alert(1)"), "the reason, as text, with its line break");
    assert.ok(html.includes("Sub-folders: javascript:alert(1)"), "the sub-folder, as text");
    assertInert(html);
  });

  test("positive control: the normal plan passes the same structural checks", () => {
    const { html } = intake();
    assert.ok(html.includes("frontend"));
    assertInert(html);
  });

  test("the hostile page keeps the same policy, so the escaped text cannot run anyway", () => {
    const { html, csp } = intake({ plan: HOSTILE_PLAN });
    assert.equal(metaCsp(html), csp);
    assert.ok(csp.startsWith("default-src 'none'; style-src 'sha256-"));
  });
});

describe("languages", () => {
  test("English renders the English labels, and Spanish the Spanish ones", () => {
    const en = intake({ language: "en" }).html;
    const es = intake({ language: "es" }).html;
    assert.ok(en.includes('<html lang="en">'));
    assert.ok(es.includes('<html lang="es">'));
    assert.ok(en.includes("Before the scan") && en.includes("Save answers") && en.includes("Standard"));
    assert.ok(es.includes("Antes del escaneo") && es.includes("Guardar respuestas") && es.includes("Estándar"));
    assert.ok(es.includes("Subcarpetas") && es.includes("Carpetas: apps/web"));
  });

  test("the Spanish page holds no English label", () => {
    const es = intake({ language: "es" }).html;
    for (const text of ["Save answers", "Before the scan", "Standard", "Reads outside", "Instructions", "Sub-folders"]) {
      assert.equal(es.includes(text), false, text);
    }
  });

  test("the report language is preselected to the language of the page", () => {
    const reportLanguage = (html) => checkedOf(html).filter((item) => item.startsWith("language="));
    assert.deepEqual(reportLanguage(intake({ language: "en" }).html), ["language=en"]);
    assert.deepEqual(reportLanguage(intake({ language: "es" }).html), ["language=es"]);
  });

  test("the done page renders in both languages", () => {
    assert.ok(renderIntakeDone({ harnessRoot: HARNESS_ROOT }).html.includes("Answers saved. You can close this tab."));
    const es = renderIntakeDone({ harnessRoot: HARNESS_ROOT, language: "es" }).html;
    assert.ok(es.includes("Respuestas guardadas. Puedes cerrar esta pestaña."));
    assert.ok(es.includes('<html lang="es">'));
    assert.equal(/<form/i.test(es), false, "no form on the done page");
  });
});

describe("the error page", () => {
  const ERRORS = [
    { pointer: "/depth", message: "must be one of quick, standard, deep" },
    { pointer: '"><script>alert(1)</script>', message: "x & y </style> <img src=x onerror=alert(1)>" },
  ];

  test("lists each error escaped, with a link back to the form action, in the page language", () => {
    const en = renderIntakeError({ harnessRoot: HARNESS_ROOT, action: ACTION, errors: ERRORS }).html;
    assert.ok(en.includes('<html lang="en">'));
    assert.ok(en.includes("The form was not accepted"));
    assert.ok(en.includes("<li>/depth: must be one of quick, standard, deep</li>"));
    assert.ok(
      en.includes("<li>&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;: x &amp; y &lt;/style&gt; &lt;img src=x onerror=alert(1)&gt;</li>"),
      "the hostile pointer and message, as text",
    );
    assert.equal(en.split("<li>").length - 1, 2, "one item per error");
    assert.ok(en.includes('<a href="' + ACTION + '">Back to the form</a>'));
    const es = renderIntakeError({ harnessRoot: HARNESS_ROOT, language: "es", action: ACTION, errors: ERRORS }).html;
    assert.ok(es.includes('<html lang="es">') && es.includes("El formulario no se aceptó") && es.includes("Volver al formulario"));
    assert.equal(es.includes("Back to the form"), false, "no English label in the Spanish page");
  });

  test("keeps the policy with the hash of its own stylesheet, and has no form, no script and no link but the one back", () => {
    const { html, csp } = renderIntakeError({ harnessRoot: HARNESS_ROOT, action: ACTION, errors: ERRORS });
    assert.equal(metaCsp(html), csp);
    assert.equal(csp, `default-src 'none'; style-src ${cspOf(styleText(html))}; img-src 'none'; form-action 'self'; base-uri 'none'`);
    assert.equal(/<form|<script|<img|https?:/i.test(html), false, "a form, a script, an image or an http reference");
    assert.deepEqual([...html.matchAll(/href="([^"]*)"/g)].map((match) => match[1]), [ACTION]);
    const names = [...html.matchAll(/<\/?([A-Za-z][A-Za-z0-9-]*)/g)].map((match) => match[1].toLowerCase());
    assert.deepEqual([...new Set(names)].filter((name) => !ALLOWED_TAGS.has(name)), [], "tags the page does not use");
  });

  test("an action with other characters or an error without a message is refused; an empty list of errors renders", () => {
    assert.throws(() => renderIntakeError({ harnessRoot: HARNESS_ROOT, action: "//evil.example/x", errors: ERRORS }), TypeError);
    assert.throws(() => renderIntakeError({ harnessRoot: HARNESS_ROOT, action: ACTION, errors: [{ pointer: "/x" }] }), TypeError);
    assert.ok(renderIntakeError({ harnessRoot: HARNESS_ROOT, action: ACTION, errors: ERRORS }).html.includes("<ul>"), "positive control");
    assert.ok(renderIntakeError({ harnessRoot: HARNESS_ROOT, action: ACTION, errors: [] }).html.includes("<ul>"));
  });
});

describe("the questions form", () => {
  test("the page keeps the policy with the hash of its own stylesheet, and has no script, no image and no http reference", () => {
    const { html, csp } = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION });
    assert.equal(metaCsp(html), csp);
    assert.equal(csp, `default-src 'none'; style-src ${cspOf(styleText(html))}; img-src 'none'; form-action 'self'; base-uri 'none'`);
    assert.ok(html.indexOf('http-equiv="Content-Security-Policy"') < html.indexOf("<style>"), "policy before the style");
    assert.ok(styleText(html).includes(".help {"), "the shared rules and the page rules are in the one style");
    assert.equal(/<script|<img|https?:/i.test(html), false, "a script, an image or an http reference");
    assert.ok(html.includes(`<form method="post" action="${QUESTIONS_ACTION}">`), "the form posts to the action given");
    assertInert(html);
  });

  test("each question is a fieldset: its text is the legend, its reason a paragraph, its source file:line in code", () => {
    const { html } = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION });
    assert.ok(html.includes("<legend>Which instruction file is right?</legend>"));
    assert.ok(html.includes("<p>CLAUDE.md and AGENTS.md give opposite test commands.</p>"));
    assert.ok(html.includes("<code>CLAUDE.md:3</code>"));
    assert.ok(html.includes("<code>apps/web/package.json:1</code>"));
    assert.equal(html.split("<fieldset>").length - 1, QUESTIONS.length, "one fieldset per question");
  });

  test("the controls send option ids: single is required radio buttons, multi is checkboxes, text is a box of the cap", () => {
    const found = controls(renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION }).html);
    assert.deepEqual(found.filter((control) => control.name === "q-contradiction").map((control) => [control.type, control.value, control.required]), [
      ["radio", "keep-claude", true],
      ["radio", "keep-agents", true],
    ]);
    assert.deepEqual(found.filter((control) => control.name === "q-folders").map((control) => [control.type, control.value, control.required]), [
      ["checkbox", "web", false],
      ["checkbox", "admin", false],
    ]);
    assert.deepEqual(found.filter((control) => control.name === "q-generated"), [], "a text question has no input");
    assert.equal(found.length, 4, "the four option controls, and no other input");
    const html = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION }).html;
    assert.ok(
      html.includes(`<textarea name="q-generated" maxlength="${MAX_ANSWER_LENGTH}" rows="4" aria-label="Is this file generated?"></textarea>`),
      "the text box, with the cap",
    );
  });

  test("positive control: a normal question keeps its text and labels unchanged, and its inputs carry the option ids", () => {
    const { html } = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION });
    assert.ok(html.includes("Keep CLAUDE.md</label>") && html.includes("Keep AGENTS.md</label>"), "the labels, as text");
    assert.ok(html.includes("apps/admin</label>"));
    assert.deepEqual(
      controls(html).map((control) => control.value).sort(),
      ["admin", "keep-agents", "keep-claude", "web"],
    );
    assertInert(html);
  });

  test("a hostile question shows its texts as inert text, and every input has an option id as its value", () => {
    const { html } = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: HOSTILE_QUESTIONS, action: QUESTIONS_ACTION });
    assertInert(html);
    assert.equal(/<svg/i.test(html), false, "an svg element");
    assert.equal(/<img/i.test(html), false, "an image");
    assert.equal(/<[^>]*\sautofocus/i.test(html), false, "an autofocus attribute on a tag");
    assert.ok(html.includes("<legend>&lt;script&gt;alert(1)&lt;/script&gt;</legend>"), "the question text, as text");
    assert.ok(html.includes("<p>&lt;img src=x onerror=alert(1)&gt;</p>"), "the reason, as text");
    assert.ok(html.includes("<code>&quot;&gt;&lt;svg onload=alert(1)&gt;.md:2</code>"), "the file, as text");
    assert.ok(html.includes("&quot; autofocus onfocus=&quot;alert(1)"), "the first label, as text");
    assert.ok(html.includes("&#39;&gt;&lt;svg onload=alert(1)&gt;"), "the second label, as text");
    const ids = new Set(["first-option", "second-option"]);
    const inputs = controls(html);
    assert.equal(inputs.length, 2);
    for (const control of inputs) assert.ok(ids.has(control.value), `an input value that is an option id: ${control.value}`);
    assert.ok(html.includes('<textarea name="q-note"'), "the text question keeps its own field");
  });

  test("the Spanish page has the Spanish labels and no English one; the English page has the English ones", () => {
    const en = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION }).html;
    const es = renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION, language: "es" }).html;
    assert.ok(en.includes('<html lang="en">') && en.includes("Questions about this repository") && en.includes("Choose one option."));
    assert.ok(en.includes("Source: <code>CLAUDE.md:3</code>"));
    assert.ok(es.includes('<html lang="es">') && es.includes("Preguntas sobre este repositorio") && es.includes("Elige una opción."));
    assert.ok(es.includes("Fuente: <code>CLAUDE.md:3</code>"));
    for (const text of ["Choose one option", "Questions about this repository", "Save answers", "Source:"]) {
      assert.equal(es.includes(text), false, text);
    }
  });

  test("the done and error pages serve the questions form too, with the same policy", () => {
    const done = renderIntakeDone({ harnessRoot: HARNESS_ROOT });
    assert.ok(done.html.includes("Answers saved. You can close this tab."), "the done text fits the answers");
    const error = renderIntakeError({
      harnessRoot: HARNESS_ROOT,
      action: QUESTIONS_ACTION,
      errors: [{ pointer: "/q-folders", message: "is not an option of this question" }],
    });
    assert.ok(error.html.includes('<a href="' + QUESTIONS_ACTION + '">Back to the form</a>'));
    assert.ok(error.html.includes("<li>/q-folders: is not an option of this question</li>"));
  });

  test("the questions are checked in shape: an empty list, or a question without its source, is refused", () => {
    assert.throws(() => renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: [], action: QUESTIONS_ACTION }), TypeError);
    const broken = [{ id: "x", type: "text", text: "t", why: "w" }];
    assert.throws(() => renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: broken, action: QUESTIONS_ACTION }), TypeError);
    assert.throws(() => renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: "//evil.example/q" }), TypeError);
    // Positive control: the same list, with its source, passes.
    assert.ok(renderQuestionsPage({ harnessRoot: HARNESS_ROOT, questions: QUESTIONS, action: QUESTIONS_ACTION }).html.includes("<form"));
  });
});

describe("every intake label is used by the page", () => {
  test("each intake.* key of the labels is rendered by the intake page, the done page, the error page or the questions page", () => {
    const keys = Object.keys(labelsEn).filter((key) => key.startsWith("intake."));
    assert.ok(keys.length > 20, "the intake labels exist");
    const used = new Set();
    for (const html of [
      renderIntakePage({ harnessRoot: pseudoRoot, plan: PLAN, action: ACTION }).html,
      renderIntakeDone({ harnessRoot: pseudoRoot }).html,
      renderIntakeError({ harnessRoot: pseudoRoot, action: ACTION, errors: [{ pointer: "/depth", message: "x" }] }).html,
      renderQuestionsPage({ harnessRoot: pseudoRoot, questions: QUESTIONS, action: QUESTIONS_ACTION }).html,
    ]) {
      for (const [, key] of html.matchAll(/⟦(intake\.[^⟧]+)⟧/gu)) used.add(key);
    }
    assert.deepEqual(keys.filter((key) => !used.has(key)), [], "intake labels that no page renders");
    assert.deepEqual([...used].filter((key) => !keys.includes(key)), [], "intake labels the pages do not have");
  });

  test("the Spanish labels have the same intake keys as the English ones", () => {
    assert.deepEqual(
      Object.keys(labelsEs).filter((key) => key.startsWith("intake.")).sort(),
      Object.keys(labelsEn).filter((key) => key.startsWith("intake.")).sort(),
    );
  });
});

describe("arguments", () => {
  test("an action that is not a plain path is refused with a TypeError", () => {
    const bad = [
      "intake",
      "//evil.example/intake",
      "https://evil.example/intake",
      "/intake token",
      '/intake"><script>alert(1)</script>',
      "/intake&x=1",
      "/intake'x",
      "/intake\nx",
      "",
    ];
    for (const action of bad) {
      assert.throws(() => intake({ action }), TypeError, JSON.stringify(action));
    }
    // Positive control: the same path with the characters that are allowed.
    assert.ok(intake({ action: "/intake?token=abc123-XYZ_.~/x=1" }).html.includes("abc123-XYZ_.~/x=1"));
  });

  test("a language other than en or es is refused, and the defaults are English", () => {
    assert.throws(() => intake({ language: "fr" }), TypeError);
    assert.ok(renderIntakePage({ harnessRoot: HARNESS_ROOT, plan: PLAN, action: ACTION }).html.includes('<html lang="en">'));
  });

  test("a plan without layers, or with a malformed layer, is refused", () => {
    assert.throws(() => intake({ plan: { schemaVersion: 1, layers: [] } }), TypeError);
    assert.throws(() => intake({ plan: { schemaVersion: 1 } }), TypeError);
    assert.throws(() => intake({ plan: { schemaVersion: 1, layers: [{ name: "x", reason: "y", folders: "db" }] } }), TypeError);
    // Positive control: the same plan with folders as a list is accepted.
    assert.ok(intake({ plan: { schemaVersion: 1, layers: [{ name: "x", reason: "y", folders: ["db"] }] } }));
  });

  test("a harness folder that is not absolute is refused", () => {
    assert.throws(() => renderIntakePage({ harnessRoot: "templates", plan: PLAN, action: ACTION }), TypeError);
    assert.throws(() => renderIntakeDone({ harnessRoot: "templates" }), TypeError);
  });
});
