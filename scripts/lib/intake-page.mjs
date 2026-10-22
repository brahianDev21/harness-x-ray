// The intake page: the form that the person answers before the report, the page that follows the answers, and the page that
// answers an invalid form. The questions page is the form of the agent's questions, which the person answers after a scan. The
// pages are built from templates/intake.html, intake-done.html, intake-error.html and questions.html, with the shared stylesheet
// of templates/theme.css. The done and error pages serve both forms.
// No page has a script. The form posts, so the policy allows no script, no image and no other resource, and the only
// style is the one the policy names by its hash. Every text from the plan or the questions is escaped where it is inserted.

import fs from "node:fs";
import path from "node:path";
import { cspHash, escapeHtml, loadTheme } from "./html.mjs";
import { isPlainObject } from "./json-out.mjs";
import { FIELD_PREFIX, MAX_ANSWER_LENGTH, QUESTION_TYPES } from "./questions.mjs";
import { createLabeller, loadLabels } from "./report-labels.mjs";

const LANGUAGES = Object.freeze(["en", "es"]);
/** The depths the page draws, in its order: the same list as intake-server.mjs and scanner.mjs DEPTHS. */
export const DEPTHS = Object.freeze(["quick", "standard", "deep"]);
// The axes in the order of the form. Each one has a label axis.<name>.
const AXES = Object.freeze(["instructions", "context", "security", "verification", "structure", "code"]);
// The form action: one leading slash (a second one would name another host), then letters, digits and . _ ~ / ? = -.
const ACTION = /^\/(?!\/)[A-Za-z0-9._~\/?=-]*$/;
// A marker of a template: {{name}}, with a name of letters and digits.
const MARKER = /\{\{([A-Za-z][A-Za-z0-9]*)\}\}/g;

// The rules of the intake page, after the shared stylesheet.
const INTAKE_CSS = `
.option {
  display: block;
  padding: var(--space-1) 0;
}

.help {
  display: block;
  margin: 0 0 0 1.75rem;
  color: var(--color-muted);
  font-size: 0.875rem;
}
`;

// The rules of the questions page, after the intake rules: a written answer fills the width of the form.
const QUESTIONS_CSS = `${INTAKE_CSS}
textarea {
  box-sizing: border-box;
  width: 100%;
  font: inherit;
}
`;

/**
 * Renders the intake page: the questions of the form, with the layers of the plan.
 * @param {object} options
 * @param {string} options.harnessRoot The absolute folder of this repository, which holds templates/.
 * @param {{ layers: Array<{ name: string, folders: string[], reason: string, options?: string[] }> }} options.plan The
 *   validated layer-plan.json.
 * @param {string} [options.language="en"] "en" or "es": the language of the page and of its labels.
 * @param {string} options.action The form action, a path such as "/intake?token=...".
 * @returns {{ html: string, csp: string }} csp is the Content-Security-Policy of the page, meant for the meta element
 *   and for the response header alike.
 * @throws {TypeError} If an argument has the wrong shape, including an action that holds other characters.
 */
export function renderIntakePage({ harnessRoot, plan, language = "en", action }) {
  checkRoot(harnessRoot);
  checkLanguage(language);
  checkAction(action);
  checkPlan(plan);
  const t = labeller(harnessRoot, language);
  const style = pageStyle(harnessRoot, INTAKE_CSS);
  const csp = policyOf(style);
  const values = {
    lang: language,
    title: escapeHtml(t("intake.title")),
    csp,
    style,
    heading: escapeHtml(t("intake.heading")),
    intro: escapeHtml(t("intake.intro")),
    action: escapeHtml(action),
    depth: depthFieldset(t),
    scope: scopeFieldset(t, plan),
    axis: axisFieldset(t),
    language: languageFieldset(t, language),
    access: accessFieldset(t),
    submit: escapeHtml(t("intake.submit")),
  };
  return { html: fillTemplate(readTemplate(harnessRoot, "intake.html"), values, "intake.html"), csp };
}

/**
 * Renders the page that follows the answers: a short text, with no form.
 * @param {object} options
 * @param {string} options.harnessRoot The absolute folder of this repository.
 * @param {string} [options.language="en"] "en" or "es".
 * @returns {{ html: string, csp: string }}
 * @throws {TypeError} If an argument has the wrong shape.
 */
export function renderIntakeDone({ harnessRoot, language = "en" }) {
  checkRoot(harnessRoot);
  checkLanguage(language);
  const t = labeller(harnessRoot, language);
  const style = pageStyle(harnessRoot);
  const csp = policyOf(style);
  const values = {
    lang: language,
    title: escapeHtml(t("intake.title")),
    csp,
    style,
    message: escapeHtml(t("intake.done")),
  };
  return { html: fillTemplate(readTemplate(harnessRoot, "intake-done.html"), values, "intake-done.html"), csp };
}

/**
 * Renders the page that answers an invalid form: the list of the errors and a link back to the form, in the page language.
 * The messages are the ones the validator gives, in English; the heading, the text and the link are in the page language.
 * @param {object} options
 * @param {string} options.harnessRoot The absolute folder of this repository.
 * @param {string} [options.language="en"] "en" or "es".
 * @param {string} options.action The form action, the same rules as renderIntakePage.
 * @param {{ pointer: string, message: string }[]} options.errors The errors of the form. Every text is escaped.
 * @returns {{ html: string, csp: string }}
 * @throws {TypeError} If an argument has the wrong shape.
 */
export function renderIntakeError({ harnessRoot, language = "en", action, errors }) {
  checkRoot(harnessRoot);
  checkLanguage(language);
  checkAction(action);
  checkErrors(errors);
  const t = labeller(harnessRoot, language);
  const style = pageStyle(harnessRoot, INTAKE_CSS);
  const csp = policyOf(style);
  const items = errors.map((item) => `<li>${escapeHtml(item.pointer === "" ? "form" : item.pointer)}: ${escapeHtml(item.message)}</li>`);
  const values = {
    lang: language,
    title: escapeHtml(t("intake.title")),
    csp,
    style,
    heading: escapeHtml(t("intake.error.heading")),
    intro: escapeHtml(t("intake.error.intro")),
    errors: items.join("\n"),
    action: escapeHtml(action),
    back: escapeHtml(t("intake.error.back")),
  };
  return { html: fillTemplate(readTemplate(harnessRoot, "intake-error.html"), values, "intake-error.html"), csp };
}

/**
 * Renders the questions form: one fieldset per question, with its text as the legend, its reason as a paragraph and its source
 * as file:line in code. A single question is a group of radio buttons (one is required), a multi question is a group of
 * checkboxes, and a text question is a text box of at most MAX_ANSWER_LENGTH characters. The controls send option ids, never
 * option labels, and the text box sends the written text.
 * @param {object} options
 * @param {string} options.harnessRoot The absolute folder of this repository.
 * @param {object[]} options.questions The questions, as readQuestions returns them: checked, and redacted for the page.
 * @param {string} [options.language="en"] "en" or "es": the language of the page and of its labels.
 * @param {string} options.action The form action, a path such as "/questions?token=...".
 * @returns {{ html: string, csp: string }} csp is the Content-Security-Policy of the page, as renderIntakePage gives it.
 * @throws {TypeError} If an argument has the wrong shape.
 */
export function renderQuestionsPage({ harnessRoot, questions, language = "en", action }) {
  checkRoot(harnessRoot);
  checkLanguage(language);
  checkAction(action);
  checkQuestions(questions);
  const t = labeller(harnessRoot, language);
  const style = pageStyle(harnessRoot, QUESTIONS_CSS);
  const csp = policyOf(style);
  const values = {
    lang: language,
    title: escapeHtml(t("intake.questions.title")),
    csp,
    style,
    heading: escapeHtml(t("intake.questions.heading")),
    intro: escapeHtml(t("intake.questions.intro")),
    action: escapeHtml(action),
    questions: questions.map((question) => questionFieldset(t, question)).join("\n"),
    submit: escapeHtml(t("intake.submit")),
  };
  return { html: fillTemplate(readTemplate(harnessRoot, "questions.html"), values, "questions.html"), csp };
}

// The policy: nothing loads unless it is named. The one style is the hash of the style element, and the form may post
// to this server only.
function policyOf(style) {
  return `default-src 'none'; style-src ${cspHash(style)}; img-src 'none'; form-action 'self'; base-uri 'none'`;
}

// The stylesheet of a page: the shared one, then the page's own rules. The text is inserted as it is, so its hash is the
// hash of the element's text; a closing style tag inside it would end the element early.
function pageStyle(harnessRoot, extra = "") {
  const style = `${loadTheme(harnessRoot)}${extra}`;
  if (/<\/style/i.test(style)) throw new Error("the stylesheet must not hold a closing style tag");
  return style;
}

// The questions ---------------------------------------------------------------------------------

function depthFieldset(t) {
  return fieldset(
    t("intake.depth.legend"),
    DEPTHS.map((depth) =>
      choice({
        type: "radio",
        name: "depth",
        value: depth,
        checked: depth === "standard",
        text: t(`intake.depth.${depth}`),
        help: [t(`intake.depth.${depth}.help`)],
      }),
    ),
  );
}

// One radio per scope, then one checkbox per layer of the plan, whatever the number of layers.
function scopeFieldset(t, plan) {
  return fieldset(t("intake.scope.legend"), [
    choice({ type: "radio", name: "scope", value: "all", checked: true, text: t("intake.scope.all") }),
    choice({ type: "radio", name: "scope", value: "layers", text: t("intake.scope.layers") }),
    note(t("intake.scope.help")),
    note(t("intake.scope.layersHint")),
    ...plan.layers.map((layer, index) =>
      choice({ type: "checkbox", name: "layer", value: index, text: layer.name, help: layerHelp(t, layer) }),
    ),
  ]);
}

function layerHelp(t, layer) {
  const lines = [
    `${t("intake.layer.folders")}: ${layer.folders.join(t("list.separator"))}`,
    `${t("intake.layer.reason")}: ${layer.reason}`,
  ];
  if (layer.options !== undefined && layer.options.length > 0) {
    lines.push(`${t("intake.layer.options")}: ${layer.options.join(t("list.separator"))}`);
  }
  return lines;
}

function axisFieldset(t) {
  return fieldset(t("intake.axis.legend"), [
    note(t("intake.axis.help")),
    ...AXES.map((axis) => choice({ type: "checkbox", name: "axis", value: axis, text: t(`axis.${axis}`) })),
  ]);
}

// The report language is preselected to the language of the page: the report follows the language the person reads.
function languageFieldset(t, pageLanguage) {
  return fieldset(
    t("intake.language.legend"),
    LANGUAGES.map((language) =>
      choice({
        type: "radio",
        name: "language",
        value: language,
        checked: language === pageLanguage,
        text: t(`intake.language.${language}`),
      }),
    ),
  );
}

// The two reads outside the target. Each is off unless the person checks it.
function accessFieldset(t) {
  return fieldset(t("intake.access.legend"), [
    note(t("intake.access.help")),
    choice({ type: "checkbox", name: "userLayer", value: "yes", text: t("intake.access.userLayer") }),
    choice({ type: "checkbox", name: "ancestors", value: "yes", text: t("intake.access.ancestors") }),
  ]);
}

// Markup helpers ---------------------------------------------------------------------------------

// One question of the questions form. Its controls are named "q-<id>", and each value is an option id, or the text box has no value.
function questionFieldset(t, question) {
  const field = `${FIELD_PREFIX}${question.id}`;
  const source = `${question.source.file}:${question.source.line}`;
  const parts = [
    `<p>${escapeHtml(question.why)}</p>`,
    `<p class="muted">${escapeHtml(t("intake.questions.source"))}: <code>${escapeHtml(source)}</code></p>`,
    note(t(`intake.questions.${question.type}`)),
  ];
  if (question.type === "text") {
    // The text box has no visible label of its own: the legend names the group, and aria-label names the box.
    parts.push(
      `<textarea name="${escapeHtml(field)}" maxlength="${MAX_ANSWER_LENGTH}" rows="4" aria-label="${escapeHtml(question.text)}"></textarea>`,
    );
  } else {
    const single = question.type === "single";
    for (const option of question.options) {
      parts.push(
        choice({ type: single ? "radio" : "checkbox", name: field, value: option.id, text: option.label, required: single }),
      );
    }
  }
  return fieldset(question.text, parts);
}

// One choice: an input inside its label, then the text and the help lines. Every text is escaped here, so a layer name or
// a reason from the plan is inert in the page.
function choice({ type, name, value, checked = false, required = false, text, help = [] }) {
  const attributes = [`type="${type}"`, `name="${escapeHtml(name)}"`, `value="${escapeHtml(String(value))}"`];
  if (checked) attributes.push("checked");
  if (required) attributes.push("required");
  const helpHtml = help.map((line) => `<span class="help">${escapeHtml(line)}</span>`).join("");
  return `<label class="option"><input ${attributes.join(" ")}> ${escapeHtml(text)}${helpHtml}</label>`;
}

function fieldset(legend, parts) {
  return ["<fieldset>", `<legend>${escapeHtml(legend)}</legend>`, ...parts, "</fieldset>"].join("\n");
}

function note(text) {
  return `<p class="muted">${escapeHtml(text)}</p>`;
}

// Templates and checks ---------------------------------------------------------------------------

function labeller(harnessRoot, language) {
  return createLabeller(loadLabels(harnessRoot, language));
}

function readTemplate(harnessRoot, name) {
  return fs.readFileSync(path.join(harnessRoot, "templates", name), "utf8");
}

// Places the values in the template. Each marker of the template needs one value, and each value must be a marker of the
// template, exactly once. The replacement is one pass, so a value is never read as a marker.
function fillTemplate(template, values, file) {
  const found = [...template.matchAll(MARKER)].map((match) => match[1]);
  for (const name of found) {
    if (!Object.hasOwn(values, name)) throw new Error(`${file} has an unknown marker {{${name}}}`);
  }
  for (const name of Object.keys(values)) {
    const count = found.filter((item) => item === name).length;
    if (count !== 1) throw new Error(`${file} must have the marker {{${name}}} once, found ${count}`);
  }
  return template.replace(MARKER, (whole, name) => values[name]);
}

function checkRoot(harnessRoot) {
  if (typeof harnessRoot !== "string" || !path.isAbsolute(harnessRoot)) {
    throw new TypeError("harnessRoot must be an absolute folder");
  }
}

function checkLanguage(language) {
  if (!LANGUAGES.includes(language)) throw new TypeError(`language must be one of ${LANGUAGES.join(", ")}`);
}

function checkErrors(errors) {
  const shaped = Array.isArray(errors) && errors.every((item) => isPlainObject(item) && typeof item.pointer === "string" && typeof item.message === "string");
  if (!shaped) throw new TypeError("errors must be a list of { pointer, message } strings");
}

function checkAction(action) {
  if (typeof action !== "string" || !ACTION.test(action)) {
    throw new TypeError("action must start with one slash and hold only letters, digits and . _ ~ / ? = -");
  }
}

// The shape only: the names and folders come from layer-plan.json, which the caller has validated.
function checkPlan(plan) {
  if (!isPlainObject(plan) || !Array.isArray(plan.layers) || plan.layers.length === 0) {
    throw new TypeError("plan must be a layer plan with a non-empty layers list");
  }
  plan.layers.forEach((layer, index) => {
    const where = `plan.layers[${index}]`;
    if (!isPlainObject(layer) || typeof layer.name !== "string" || typeof layer.reason !== "string") {
      throw new TypeError(`${where} must have a name and a reason`);
    }
    if (!isStringList(layer.folders)) throw new TypeError(`${where}.folders must be a list of strings`);
    if (layer.options !== undefined && !isStringList(layer.options)) {
      throw new TypeError(`${where}.options must be a list of strings`);
    }
  });
}

function isStringList(value) {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

// The shape only: readQuestions has checked the questions and redacted them. The texts are escaped where they are written.
function checkQuestions(questions) {
  const shaped = Array.isArray(questions) && questions.length > 0 && questions.every(isQuestionShape);
  if (!shaped) throw new TypeError("questions must be a non-empty list of questions, as readQuestions returns them");
}

function isQuestionShape(question) {
  if (!isPlainObject(question) || typeof question.id !== "string" || !QUESTION_TYPES.includes(question.type)) return false;
  if (typeof question.text !== "string" || typeof question.why !== "string") return false;
  const { source } = question;
  if (!isPlainObject(source) || typeof source.file !== "string" || !Number.isSafeInteger(source.line)) return false;
  if (question.type === "text") return true;
  return (
    Array.isArray(question.options) &&
    question.options.every((option) => isPlainObject(option) && typeof option.id === "string" && typeof option.label === "string")
  );
}
