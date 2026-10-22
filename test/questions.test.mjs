import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createRedactor } from "../scripts/lib/redact.mjs";
import {
  loadQuestions,
  MAX_ANSWER_LENGTH,
  MAX_FILE_BYTES,
  MAX_LABEL_LENGTH,
  MAX_OPTIONS,
  MAX_QUESTIONS,
  MAX_TEXT_LENGTH,
  MAX_WHY_LENGTH,
  readQuestions,
  redactQuestions,
  validateAnswers,
  validateQuestions,
} from "../scripts/lib/questions.mjs";
import { symlinkSupport } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

// The questions module, its two schemas, and readQuestions on run folders. The run folders are built in the system temp folder
// and removed afterwards. The home folder is passed to redactQuestions by the tests, so the result never depends on this machine.
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const QUESTIONS_SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "questions.schema.json"), "utf8"));
const ANSWERS_SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "answers.schema.json"), "utf8"));
const symlinks = symlinkSupport();
const symlinkSkip = symlinks.supported ? false : symlinks.reason;

// Builders. Each returns fresh objects. An override replaces a field, and an undefined override removes it.
function withFields(object, overrides) {
  const copy = { ...object, ...overrides };
  for (const key of Object.keys(copy)) {
    if (copy[key] === undefined) delete copy[key];
  }
  return copy;
}

function singleQuestion(overrides = {}) {
  return withFields(
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
    overrides,
  );
}

function multiQuestion(overrides = {}) {
  return withFields(
    {
      id: "folders",
      type: "multi",
      text: "Which folders hold the frontend?",
      why: "The layers are not clear from the manifests.",
      source: { file: "apps/web/package.json", line: 1 },
      options: [
        { id: "web", label: "apps/web" },
        { id: "admin", label: "apps/admin" },
      ],
    },
    overrides,
  );
}

function textQuestion(overrides = {}) {
  return withFields(
    {
      id: "generated",
      type: "text",
      text: "Is this file generated?",
      why: "It looks generated, but it has no marker.",
      source: { file: "src/gen/client.ts", line: 9 },
    },
    overrides,
  );
}

function optionsOf(count) {
  return Array.from({ length: count }, (_, index) => ({ id: `option-${index}`, label: `Option ${index}` }));
}

function documentOf(questions) {
  return { schemaVersion: 1, questions };
}

function validDocument() {
  return documentOf([singleQuestion(), multiQuestion(), textQuestion()]);
}

function oneQuestion(overrides) {
  return documentOf([singleQuestion(overrides)]);
}

test("validateQuestions accepts a question of each type, and a file of all three", () => {
  for (const question of [singleQuestion(), multiQuestion(), textQuestion()]) {
    const result = validateQuestions(documentOf([question]));
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.deepEqual(result.questions, [question]);
  }
  const all = validateQuestions(validDocument());
  assert.equal(all.ok, true, JSON.stringify(all.errors));
  assert.equal(all.questions.length, 3);
});

test("validateQuestions keeps HTML-like text as text: escaping is the page's job, not the validator's", () => {
  const html = "<img src=x onerror=alert(1)> & \"quotes\"";
  const result = validateQuestions(oneQuestion({ text: html }));
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.questions[0].text, html);
});

test("validateQuestions allows at most MAX_QUESTIONS questions, and at least one", () => {
  assert.equal(MAX_QUESTIONS, 5);
  const five = Array.from({ length: 5 }, (_, index) => textQuestion({ id: `question-${index}` }));
  assert.equal(validateQuestions(documentOf(five)).ok, true, "five questions pass");

  const six = validateQuestions(documentOf([...five, textQuestion({ id: "question-5" })]));
  assert.equal(six.ok, false);
  assert.ok(six.errors.some((error) => error.pointer === "/questions"), JSON.stringify(six.errors));

  const none = validateQuestions(documentOf([]));
  assert.equal(none.ok, false);
  assert.ok(none.errors.some((error) => error.pointer === "/questions"), JSON.stringify(none.errors));
});

test("validateQuestions refuses a document that is not an object", () => {
  const result = validateQuestions([]);
  assert.equal(result.ok, false);
  assert.equal(result.errors[0].pointer, "");
  assert.equal(validateQuestions(documentOf([textQuestion()])).ok, true, "positive control");
});

// The refusals of the rules, one case each. Each case refuses one value at its pointer, and the same case with an allowed value
// must pass, so a refusal is never the effect of a broken fixture.
const FILE_FORMS = [
  ["an absolute path", "/etc/hosts"],
  ["a Windows path with a drive letter", "C:/repo/x.mjs"],
  ["a Windows path with a drive letter and backslashes", "C:\\repo\\x.mjs"],
  ["a drive-relative path", "C:x.mjs"],
  ["a UNC path", "\\\\server\\share\\x.mjs"],
  ["a backslash-rooted path", "\\repo\\x.mjs"],
  ["a .. segment at the start", "../x.mjs"],
  ["a .. segment in the middle", "src/../../x.mjs"],
  ["a .. segment with backslashes", "src\\..\\x.mjs"],
  ["a path that is only ..", ".."],
  ["an empty path", ""],
  ["a NUL character", "src/\u0000x.mjs"],
  ["a path longer than 512 characters", `${"a/".repeat(256)}x.mjs`],
  // Whitespace hides a rooted path, a drive letter or a .. segment from the checks that read the first characters.
  ["a leading space before a drive letter", " C:\\x"],
  ["two leading spaces before an absolute path", "  /etc/passwd"],
  ["a leading space before a .. segment", " ../x"],
  ["a leading tab before a drive letter", "\tC:\\x"],
  ["a trailing space after a .. segment", "a/.. "],
  ["a segment that is .. once its spaces are trimmed", "src/ .. /x.mjs"],
  ["a trailing space", "docs/guide.md "],
];

// The forms of source.file that pass: the module and the schema must both accept each of them.
const ALLOWED_FILES = [
  "src/app.mjs",
  "a..b/c.mjs",
  "..cache/x.mjs",
  "docs/my notes.md",
  "docs/guide.md",
  "a/b c/d.md",
  "a".repeat(512),
  "x/.../y.mjs",
];

const CASES = [
  {
    name: "an id with a capital letter",
    refused: () => oneQuestion({ id: "Contradiction" }),
    accepted: () => oneQuestion({ id: "contradiction-2" }),
    pointer: "/questions/0/id",
  },
  {
    name: "an empty id",
    refused: () => oneQuestion({ id: "" }),
    accepted: () => oneQuestion({ id: "a" }),
    pointer: "/questions/0/id",
  },
  {
    name: "an id of 33 characters",
    refused: () => oneQuestion({ id: "a".repeat(33) }),
    accepted: () => oneQuestion({ id: "a".repeat(32) }),
    pointer: "/questions/0/id",
  },
  {
    name: "an id with an underscore",
    refused: () => oneQuestion({ id: "old_id" }),
    accepted: () => oneQuestion({ id: "old-id" }),
    pointer: "/questions/0/id",
  },
  {
    name: "an id that is not a string",
    refused: () => oneQuestion({ id: 7 }),
    accepted: () => oneQuestion({ id: "seven" }),
    pointer: "/questions/0/id",
  },
  {
    name: "a missing id",
    refused: () => oneQuestion({ id: undefined }),
    accepted: () => oneQuestion(),
    pointer: "/questions/0/id",
  },
  {
    name: "two questions with the same id",
    refused: () => documentOf([singleQuestion(), textQuestion({ id: "contradiction" })]),
    accepted: () => documentOf([singleQuestion(), textQuestion({ id: "generated" })]),
    pointer: "/questions/1/id",
  },
  {
    name: "an unknown type",
    refused: () => oneQuestion({ type: "choice" }),
    accepted: () => oneQuestion(),
    pointer: "/questions/0/type",
  },
  {
    name: "options on a text question",
    refused: () => documentOf([textQuestion({ options: optionsOf(2) })]),
    accepted: () => documentOf([textQuestion()]),
    pointer: "/questions/0/options",
  },
  {
    name: "no options on a single question",
    refused: () => oneQuestion({ options: undefined }),
    accepted: () => oneQuestion(),
    pointer: "/questions/0/options",
  },
  {
    name: "no options on a multi question",
    refused: () => documentOf([multiQuestion({ options: undefined })]),
    accepted: () => documentOf([multiQuestion()]),
    pointer: "/questions/0/options",
  },
  {
    name: "one option",
    refused: () => oneQuestion({ options: optionsOf(1) }),
    accepted: () => oneQuestion({ options: optionsOf(2) }),
    pointer: "/questions/0/options",
  },
  {
    name: "nine options",
    refused: () => oneQuestion({ options: optionsOf(MAX_OPTIONS + 1) }),
    accepted: () => oneQuestion({ options: optionsOf(MAX_OPTIONS) }),
    pointer: "/questions/0/options",
  },
  {
    name: "two options with the same id",
    refused: () =>
      oneQuestion({
        options: [
          { id: "same", label: "First" },
          { id: "same", label: "Second" },
        ],
      }),
    accepted: () =>
      oneQuestion({
        options: [
          { id: "first", label: "First" },
          { id: "second", label: "Second" },
        ],
      }),
    pointer: "/questions/0/options/1/id",
  },
  {
    name: "a text longer than MAX_TEXT_LENGTH",
    refused: () => oneQuestion({ text: "x".repeat(MAX_TEXT_LENGTH + 1) }),
    accepted: () => oneQuestion({ text: "x".repeat(MAX_TEXT_LENGTH) }),
    pointer: "/questions/0/text",
  },
  {
    name: "a blank text",
    refused: () => oneQuestion({ text: "   " }),
    accepted: () => oneQuestion({ text: "a" }),
    pointer: "/questions/0/text",
  },
  {
    name: "a reason longer than MAX_WHY_LENGTH",
    refused: () => oneQuestion({ why: "x".repeat(MAX_WHY_LENGTH + 1) }),
    accepted: () => oneQuestion({ why: "x".repeat(MAX_WHY_LENGTH) }),
    pointer: "/questions/0/why",
  },
  {
    name: "an option label longer than MAX_LABEL_LENGTH",
    refused: () =>
      oneQuestion({
        options: [
          { id: "long", label: "x".repeat(MAX_LABEL_LENGTH + 1) },
          { id: "short", label: "Short" },
        ],
      }),
    accepted: () =>
      oneQuestion({
        options: [
          { id: "long", label: "x".repeat(MAX_LABEL_LENGTH) },
          { id: "short", label: "Short" },
        ],
      }),
    pointer: "/questions/0/options/0/label",
  },
  {
    name: "a line of 0",
    refused: () => oneQuestion({ source: { file: "CLAUDE.md", line: 0 } }),
    accepted: () => oneQuestion({ source: { file: "CLAUDE.md", line: 1 } }),
    pointer: "/questions/0/source/line",
  },
  {
    name: "a line of 1.5",
    refused: () => oneQuestion({ source: { file: "CLAUDE.md", line: 1.5 } }),
    accepted: () => oneQuestion({ source: { file: "CLAUDE.md", line: 1 } }),
    pointer: "/questions/0/source/line",
  },
  {
    name: "a line that is a string",
    refused: () => oneQuestion({ source: { file: "CLAUDE.md", line: "3" } }),
    accepted: () => oneQuestion({ source: { file: "CLAUDE.md", line: 3 } }),
    pointer: "/questions/0/source/line",
  },
  {
    name: "a missing line",
    refused: () => oneQuestion({ source: { file: "CLAUDE.md" } }),
    accepted: () => oneQuestion({ source: { file: "CLAUDE.md", line: 3 } }),
    pointer: "/questions/0/source/line",
  },
  {
    name: "a file that is not a string",
    refused: () => oneQuestion({ source: { file: 3, line: 1 } }),
    accepted: () => oneQuestion({ source: { file: "src/app.mjs", line: 1 } }),
    pointer: "/questions/0/source/file",
  },
  {
    name: "an unknown top-level field",
    refused: () => ({ ...validDocument(), extra: true }),
    accepted: () => validDocument(),
    pointer: "/extra",
  },
  {
    name: "a missing schemaVersion",
    refused: () => ({ questions: [singleQuestion()] }),
    accepted: () => documentOf([singleQuestion()]),
    pointer: "/schemaVersion",
  },
  {
    name: "a schemaVersion other than 1",
    refused: () => ({ schemaVersion: 2, questions: [singleQuestion()] }),
    accepted: () => documentOf([singleQuestion()]),
    pointer: "/schemaVersion",
  },
  {
    name: "an unknown field of a question",
    refused: () => oneQuestion({ extra: 1 }),
    accepted: () => oneQuestion(),
    pointer: "/questions/0/extra",
  },
  {
    name: "an unknown field of a source",
    refused: () => oneQuestion({ source: { file: "CLAUDE.md", line: 3, extra: 1 } }),
    accepted: () => oneQuestion({ source: { file: "CLAUDE.md", line: 3 } }),
    pointer: "/questions/0/source/extra",
  },
  {
    name: "an unknown field of an option",
    refused: () =>
      oneQuestion({
        options: [
          { id: "a", label: "A", extra: 1 },
          { id: "b", label: "B" },
        ],
      }),
    accepted: () => oneQuestion(),
    pointer: "/questions/0/options/0/extra",
  },
];

for (const file of FILE_FORMS) {
  const [description, value] = file;
  CASES.push({
    name: `source.file with ${description}`,
    refused: () => oneQuestion({ source: { file: value, line: 1 } }),
    accepted: () => oneQuestion({ source: { file: "src/app.mjs", line: 1 } }),
    pointer: "/questions/0/source/file",
  });
}

for (const item of CASES) {
  test(`validateQuestions refuses ${item.name}, and accepts the allowed form`, () => {
    const refused = validateQuestions(item.refused());
    assert.equal(refused.ok, false, `${item.name} must be refused`);
    assert.ok(
      refused.errors.some((error) => error.pointer === item.pointer),
      `${item.name}: expected a problem at ${JSON.stringify(item.pointer)}, got ${JSON.stringify(refused.errors)}`,
    );
    const accepted = validateQuestions(item.accepted());
    assert.equal(accepted.ok, true, `${item.name}: the allowed form must pass: ${JSON.stringify(accepted.errors)}`);
  });
}

test("validateQuestions accepts the file forms that are allowed, at the length cap", () => {
  for (const file of ALLOWED_FILES) {
    const result = validateQuestions(oneQuestion({ source: { file, line: 1 } }));
    assert.equal(result.ok, true, `${JSON.stringify(file)} must pass: ${JSON.stringify(result.errors)}`);
  }
  assert.equal(validateQuestions(oneQuestion({ source: { file: "docs/guide.md", line: 1 } })).ok, true, "docs/guide.md");
  assert.equal(validateQuestions(oneQuestion({ source: { file: "a/b c/d.md", line: 1 } })).ok, true, "a/b c/d.md");
});

test("the questions schema refuses every refused source.file and passes the allowed ones, as the module does", () => {
  for (const [description, value] of FILE_FORMS) {
    const problems = schemaProblems(QUESTIONS_SCHEMA, oneQuestion({ source: { file: value, line: 1 } }));
    assert.ok(problems.length > 0, `the schema refuses ${description}`);
  }
  for (const file of ALLOWED_FILES) {
    assert.deepEqual(schemaProblems(QUESTIONS_SCHEMA, oneQuestion({ source: { file, line: 1 } })), [], `the schema passes ${file}`);
  }
});

test("validateQuestions reports every problem of a file, with its pointer", () => {
  const result = validateQuestions(
    documentOf([singleQuestion({ id: "Bad", source: { file: "../x", line: 0 }, options: optionsOf(1) })]),
  );
  const pointers = result.errors.map((error) => error.pointer);
  assert.deepEqual(pointers, ["/questions/0/id", "/questions/0/source/file", "/questions/0/source/line", "/questions/0/options"]);
});

test("redactQuestions replaces the target folder and the home folder in the text, the reason, the labels and the file", () => {
  const questions = validateQuestions(
    documentOf([
      singleQuestion({
        text: "Compare /w/repo/CLAUDE.md with /w/home/.claude/CLAUDE.md",
        why: "/w/repo/AGENTS.md disagrees",
        source: { file: "notes /w/repo/CLAUDE.md", line: 3 },
        options: [
          { id: "keep-claude", label: "Keep /w/repo/CLAUDE.md" },
          { id: "other", label: "Keep /w/home/x" },
        ],
      }),
    ]),
  ).questions;
  const before = structuredClone(questions);

  const [redacted] = redactQuestions(questions, { root: "/w/repo", home: "/w/home" });

  assert.equal(redacted.text, "Compare <target>/CLAUDE.md with ~/.claude/CLAUDE.md");
  assert.equal(redacted.why, "<target>/AGENTS.md disagrees");
  assert.equal(redacted.source.file, "notes <target>/CLAUDE.md");
  assert.deepEqual(redacted.options, [
    { id: "keep-claude", label: "Keep <target>/CLAUDE.md" },
    { id: "other", label: "Keep ~/x" },
  ]);
  assert.equal(redacted.id, "contradiction");
  assert.equal(redacted.type, "single");
  assert.equal(redacted.source.line, 3);
  assert.deepEqual(questions, before, "the input is not changed");
});

test("redactQuestions leaves a folder that only starts like the root, and a path outside both, unchanged", () => {
  const questions = validateQuestions(
    documentOf([textQuestion({ text: "See /w/repo-evil/x and /w/other/y", why: "/w/repo" })]),
  ).questions;
  const [redacted] = redactQuestions(questions, { root: "/w/repo", home: "/w/home" });
  assert.equal(redacted.text, "See /w/repo-evil/x and /w/other/y");
  assert.equal(redacted.why, "<target>", "the root itself is replaced");
});

test("redactQuestions with no root replaces only the home folder", () => {
  const questions = validateQuestions(oneQuestion({ text: "Read /w/repo/x and /w/home/y" })).questions;
  const [redacted] = redactQuestions(questions, { home: "/w/home" });
  assert.equal(redacted.text, "Read /w/repo/x and ~/y");
});

test("redactQuestions masks token-shaped text in the questions", () => {
  // Built at run time so that this file holds no secret-shaped text (push protection would block it).
  const token = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
  const questions = validateQuestions(oneQuestion({ why: `The token ${token} is in the file` })).questions;
  const [redacted] = redactQuestions(questions, { root: "/w/repo", home: "/w/home" });
  assert.equal(redacted.why, "The token ghp_\u2026Q7r8 is in the file");
});

test("the questions schema agrees with the module on the valid example and on refused examples", () => {
  const valid = validDocument();
  assert.deepEqual(schemaProblems(QUESTIONS_SCHEMA, valid), [], "a valid file passes the schema");
  assert.equal(validateQuestions(valid).ok, true);

  const refused = {
    "an option on a text question": documentOf([textQuestion({ options: optionsOf(2) })]),
    "a single question without options": oneQuestion({ options: undefined }),
    "an id with a capital letter": oneQuestion({ id: "Contradiction" }),
    "a parent path": oneQuestion({ source: { file: "../x", line: 1 } }),
    "a Windows path": oneQuestion({ source: { file: "C:/x", line: 1 } }),
    "an unknown field": { ...validDocument(), extra: true },
  };
  for (const [name, value] of Object.entries(refused)) {
    assert.ok(schemaProblems(QUESTIONS_SCHEMA, value).length > 0, `${name} fails the schema`);
    assert.equal(validateQuestions(value).ok, false, `${name} is refused by the module`);
  }
});

test("validateAnswers gives the answers of a valid form, in the order of the questions, and they pass the answers schema", () => {
  const questions = validatedQuestions();
  const result = validateAnswers(baseForm(), questions);
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.deepEqual(result.answers, [
    {
      id: "contradiction",
      type: "single",
      question: "Which instruction file is right?",
      why: "CLAUDE.md and AGENTS.md give opposite test commands.",
      source: { file: "CLAUDE.md", line: 3 },
      selected: [{ id: "keep-agents", label: "Keep AGENTS.md" }],
    },
    {
      id: "folders",
      type: "multi",
      question: "Which folders hold the frontend?",
      why: "The layers are not clear from the manifests.",
      source: { file: "apps/web/package.json", line: 1 },
      selected: [{ id: "admin", label: "apps/admin" }],
    },
    {
      id: "generated",
      type: "text",
      question: "Is this file generated?",
      why: "It looks generated, but it has no marker.",
      source: { file: "src/gen/client.ts", line: 9 },
      value: "It is generated by a script.",
    },
  ]);
  assert.deepEqual(schemaProblems(ANSWERS_SCHEMA, { schemaVersion: 1, answers: result.answers }), []);
});

test("validateAnswers gives an empty selection for a multi with no value, and an empty string for a text with no value", () => {
  const form = baseForm();
  form.delete("q-folders");
  form.delete("q-generated");
  const result = validateAnswers(form, validatedQuestions());
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.deepEqual(result.answers[1].selected, []);
  assert.equal(result.answers[2].value, "");
  assert.deepEqual(schemaProblems(ANSWERS_SCHEMA, { schemaVersion: 1, answers: result.answers }), []);
});

test("validateAnswers lists the selected options in the order of the question, not of the form", () => {
  const form = baseForm();
  form.set("q-folders", ["admin", "web"]);
  const result = validateAnswers(form, validatedQuestions());
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.deepEqual(
    result.answers[1].selected.map((option) => option.id),
    ["web", "admin"],
  );
});

test("validateAnswers accepts a written answer of exactly MAX_ANSWER_LENGTH characters", () => {
  const form = baseForm();
  form.set("q-generated", ["x".repeat(MAX_ANSWER_LENGTH)]);
  const result = validateAnswers(form, validatedQuestions());
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.answers[2].value.length, MAX_ANSWER_LENGTH);
});

test("validateAnswers counts a line break of a written answer as one character, as the browser's CRLF is counted, and stores LF", () => {
  const form = baseForm();
  // A browser sends a line break as CRLF. 1999 characters and one line break are 2000 characters, as the page's maxlength counts them.
  form.set("q-generated", [`${"x".repeat(1999)}\r\n`]);
  const accepted = validateAnswers(form, validatedQuestions());
  assert.equal(accepted.ok, true, JSON.stringify(accepted.errors));
  assert.equal(accepted.answers[2].value, `${"x".repeat(1999)}\n`, "the line break is stored as LF");
  form.set("q-generated", [`${"x".repeat(2000)}\r\n`]);
  assert.equal(validateAnswers(form, validatedQuestions()).ok, false, "2000 characters and a line break are 2001: refused");
  form.set("q-generated", ["a\rb\r\nc"]);
  assert.equal(validateAnswers(form, validatedQuestions()).answers[2].value, "a\nb\nc", "a lone CR is a line break too");
});

test("validateAnswers redacts a written answer: a token is masked, and the target and home folders are replaced", () => {
  // Built at run time so that this file holds no secret-shaped text (push protection would block it).
  const token = ["gh", "p_"].join("") + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".slice(0, 36);
  const form = baseForm();
  form.set("q-generated", [`Compare /w/repo/x and /w/home/y, token ${token}`]);
  const redact = createRedactor({ root: "/w/repo", home: "/w/home" });
  const result = validateAnswers(form, validatedQuestions(), { redact });
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.answers[2].value, "Compare <target>/x and ~/y, token ghp_…ghij");

  form.set("q-generated", ["Yes, it is generated by a script."]);
  const kept = validateAnswers(form, validatedQuestions(), { redact });
  assert.equal(kept.answers[2].value, "Yes, it is generated by a script.", "positive control: a normal sentence is kept as written");

  // Without a redactor, the default still masks a token: the home folder is replaced and the token is masked.
  form.set("q-generated", [`token ${token}`]);
  assert.equal(validateAnswers(form, validatedQuestions()).answers[2].value, "token ghp_…ghij");
});

// The form refusals, one by one. Each takes the valid form and changes one value. The valid form itself must pass.
const FORM_CASES = [
  {
    name: "a field whose question does not exist",
    change: (form) => form.set("q-missing", ["x"]),
    pointer: "/q-missing",
  },
  {
    name: "a field without the question prefix",
    change: (form) => form.set("depth", ["deep"]),
    pointer: "/depth",
  },
  {
    name: "a single question with no value",
    change: (form) => form.delete("q-contradiction"),
    pointer: "/q-contradiction",
  },
  {
    name: "a single question with an empty value",
    change: (form) => form.set("q-contradiction", [""]),
    pointer: "/q-contradiction",
  },
  {
    name: "a single question with two values",
    change: (form) => form.set("q-contradiction", ["keep-claude", "keep-agents"]),
    pointer: "/q-contradiction",
  },
  {
    name: "a single question with an option id that does not exist",
    change: (form) => form.set("q-contradiction", ["keep-nothing"]),
    pointer: "/q-contradiction",
  },
  {
    name: "a single question with an option of another question",
    change: (form) => form.set("q-contradiction", ["admin"]),
    pointer: "/q-contradiction",
  },
  {
    name: "a multi question with an option id that does not exist",
    change: (form) => form.set("q-folders", ["api"]),
    pointer: "/q-folders",
  },
  {
    name: "a multi question with a repeated option id",
    change: (form) => form.set("q-folders", ["admin", "admin"]),
    pointer: "/q-folders",
  },
  {
    name: "a text question with two values",
    change: (form) => form.set("q-generated", ["one", "two"]),
    pointer: "/q-generated",
  },
  {
    name: "a written answer longer than MAX_ANSWER_LENGTH",
    change: (form) => form.set("q-generated", ["x".repeat(MAX_ANSWER_LENGTH + 1)]),
    pointer: "/q-generated",
  },
];

for (const item of FORM_CASES) {
  test(`validateAnswers refuses ${item.name}, and accepts the valid form`, () => {
    const form = baseForm();
    item.change(form);
    const refused = validateAnswers(form, validatedQuestions());
    assert.equal(refused.ok, false, `${item.name} must be refused`);
    assert.ok(
      refused.errors.some((error) => error.pointer === item.pointer),
      `${item.name}: expected a problem at ${item.pointer}, got ${JSON.stringify(refused.errors)}`,
    );
    const accepted = validateAnswers(baseForm(), validatedQuestions());
    assert.equal(accepted.ok, true, JSON.stringify(accepted.errors));
  });
}

test("validateAnswers refuses a form that is not a Map, and questions that are not a list", () => {
  assert.throws(() => validateAnswers({ "q-contradiction": ["keep-claude"] }, validatedQuestions()), TypeError);
  assert.throws(() => validateAnswers(baseForm(), "questions"), TypeError);
});

test("the answers schema refuses an answer with a field that the shape does not have", () => {
  const result = validateAnswers(baseForm(), validatedQuestions());
  const answers = structuredClone(result.answers);
  answers[2].selected = [{ id: "x", label: "X" }];
  assert.ok(schemaProblems(ANSWERS_SCHEMA, { schemaVersion: 1, answers }).length > 0, "a text answer with selected fails");
  assert.deepEqual(schemaProblems(ANSWERS_SCHEMA, { schemaVersion: 1, answers: result.answers }), [], "the valid answers pass");
});

// Run folders for readQuestions. Each folder is made in one sandbox folder of the system temp folder, and removed afterwards.
const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-questions-"));
after(() => fs.rmSync(sandbox, { recursive: true, force: true }));
let runCount = 0;

function writeRun(dir, files) {
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), typeof content === "string" ? content : JSON.stringify(content));
  }
  return dir;
}

function newRun(files = {}) {
  runCount += 1;
  return writeRun(path.join(sandbox, `run-${runCount}`), files);
}

test("readQuestions returns the questions of a valid file, redacted with the target of measurements.json", () => {
  const target = path.join(sandbox, "target");
  const dir = newRun({
    "questions.json": documentOf([singleQuestion({ text: `Compare ${target}/CLAUDE.md with ${target}/AGENTS.md` })]),
    "measurements.json": { meta: { targetRoot: target } },
  });
  const questions = readQuestions(dir, { harnessRoot: HARNESS_ROOT });
  assert.equal(questions.length, 1);
  assert.equal(questions[0].text, "Compare <target>/CLAUDE.md with <target>/AGENTS.md");
  assert.equal(questions[0].id, "contradiction");
});

test("readQuestions redacts with the target of layers.json when measurements.json is missing", () => {
  const target = path.join(sandbox, "layers-target");
  const dir = newRun({
    "questions.json": documentOf([singleQuestion({ text: `Read ${target}/a.md` })]),
    "layers.json": { schemaVersion: 1, folders: ["."], meta: { targetRoot: target } },
  });
  const [question] = readQuestions(dir, { harnessRoot: HARNESS_ROOT });
  assert.equal(question.text, "Read <target>/a.md");
});

test("readQuestions prefers the target of measurements.json to the target of layers.json", () => {
  const target = path.join(sandbox, "measured-target");
  const other = path.join(sandbox, "layered-target");
  const dir = newRun({
    "questions.json": documentOf([singleQuestion({ text: `Compare ${target}/a and ${other}/b` })]),
    "measurements.json": { meta: { targetRoot: target } },
    "layers.json": { schemaVersion: 1, folders: ["."], meta: { targetRoot: other } },
  });
  const [question] = readQuestions(dir, { harnessRoot: HARNESS_ROOT });
  assert.equal(question.text, `Compare <target>/a and ${other}/b`);
});

test("readQuestions falls back to layers.json when measurements.json does not parse", () => {
  const target = path.join(sandbox, "fallback-target");
  const dir = newRun({
    "questions.json": documentOf([singleQuestion({ text: `Read ${target}/a.md` })]),
    "measurements.json": "{ not json",
    "layers.json": { schemaVersion: 1, folders: ["."], meta: { targetRoot: target } },
  });
  const [question] = readQuestions(dir, { harnessRoot: HARNESS_ROOT });
  assert.equal(question.text, "Read <target>/a.md");
});

test("loadQuestions returns the redactor of the run, with the target of measurements.json, next to the questions", () => {
  const target = path.join(sandbox, "loaded-target");
  const dir = newRun({
    "questions.json": documentOf([singleQuestion({ text: `Compare ${target}/a` })]),
    "measurements.json": { meta: { targetRoot: target } },
  });
  const loaded = loadQuestions(dir, { harnessRoot: HARNESS_ROOT });
  assert.equal(loaded.questions[0].text, "Compare <target>/a", "the questions are redacted");
  assert.equal(loaded.redact(`Read ${target}/b`), "Read <target>/b", "the written text uses the same target");
  assert.equal(loaded.redact(3), 3, "a value that is not a string is returned unchanged");
  assert.throws(() => loadQuestions("", { harnessRoot: HARNESS_ROOT }), TypeError);
});

test("readQuestions with no recorded target replaces only the home folder, so an absolute path stays", () => {
  const dir = newRun({ "questions.json": documentOf([singleQuestion({ text: "Read /xray-no-root-here/a.md" })]) });
  const [question] = readQuestions(dir, { harnessRoot: HARNESS_ROOT });
  assert.equal(question.text, "Read /xray-no-root-here/a.md");
});

test("readQuestions refuses a missing file, a file that is not JSON, and a file that does not pass the check", () => {
  assert.throws(() => readQuestions(newRun({}), { harnessRoot: HARNESS_ROOT }), {
    name: "UsageError",
    message: /questions\.json is missing/,
  });
  assert.throws(() => readQuestions(newRun({ "questions.json": "{" }), { harnessRoot: HARNESS_ROOT }), {
    name: "UsageError",
    message: /is not valid JSON/,
  });
  const six = Array.from({ length: MAX_QUESTIONS + 1 }, (_, index) => textQuestion({ id: `question-${index}` }));
  assert.throws(() => readQuestions(newRun({ "questions.json": documentOf(six) }), { harnessRoot: HARNESS_ROOT }), {
    name: "UsageError",
    message: /is not valid: \/questions: holds 6 questions/,
  });
  const five = Array.from({ length: MAX_QUESTIONS }, (_, index) => textQuestion({ id: `question-${index}` }));
  assert.equal(readQuestions(newRun({ "questions.json": documentOf(five) }), { harnessRoot: HARNESS_ROOT }).length, 5);
});

test("readQuestions refuses a file larger than MAX_FILE_BYTES before it reads it", () => {
  const dir = newRun({ "questions.json": "x".repeat(MAX_FILE_BYTES + 1) });
  assert.throws(() => readQuestions(dir, { harnessRoot: HARNESS_ROOT }), {
    name: "UsageError",
    message: /is larger than/,
  });
  const small = newRun({ "questions.json": documentOf([textQuestion()]) });
  assert.equal(readQuestions(small, { harnessRoot: HARNESS_ROOT }).length, 1, "a small file of the same kind passes");
});

test("readQuestions reads only the run folders inside runs/ of the harness, and refuses another folder of it", () => {
  const harness = path.join(sandbox, "harness");
  fs.mkdirSync(path.join(harness, "runs"), { recursive: true });
  const inside = writeRun(path.join(harness, "runs", "r1"), { "questions.json": documentOf([textQuestion()]) });
  const outside = writeRun(path.join(harness, "other", "r2"), { "questions.json": documentOf([textQuestion()]) });
  assert.equal(readQuestions(inside, { harnessRoot: harness }).length, 1, "a run inside runs/ passes");
  assert.throws(() => readQuestions(outside, { harnessRoot: harness }), {
    name: "UsageError",
    message: /must be inside runs\//,
  });
});

test("readQuestions refuses a questions.json that is a link to another file", { skip: symlinkSkip }, () => {
  const elsewhere = path.join(sandbox, "elsewhere.json");
  fs.writeFileSync(elsewhere, JSON.stringify(documentOf([textQuestion()])));
  const linked = newRun({});
  fs.symlinkSync(elsewhere, path.join(linked, "questions.json"));
  assert.throws(() => readQuestions(linked, { harnessRoot: HARNESS_ROOT }), {
    name: "UsageError",
    message: /not a regular file/,
  });
  const plain = newRun({ "questions.json": documentOf([textQuestion()]) });
  assert.equal(readQuestions(plain, { harnessRoot: HARNESS_ROOT }).length, 1, "a regular file passes");
});

test("readQuestions needs the run folder and the harness folder as strings", () => {
  assert.throws(() => readQuestions("", { harnessRoot: HARNESS_ROOT }), TypeError);
  assert.throws(() => readQuestions(newRun({}), {}), TypeError);
});

// The questions of the valid form, validated and used as readQuestions gives them.
function validatedQuestions() {
  const result = validateQuestions(validDocument());
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  return result.questions;
}

// The form of the valid document: one option for each choice, and a written answer.
function baseForm() {
  return new Map([
    ["q-contradiction", ["keep-agents"]],
    ["q-folders", ["admin"]],
    ["q-generated", ["It is generated by a script."]],
  ]);
}
