// The agent's questions for the person: <runDir>/questions.json, written after a scan when the measurements cannot settle a
// point (two instruction files that contradict each other, a file that looks generated but is not marked, an ambiguous scope).
// The intake server serves them, and the answers are written to <runDir>/answers.json.
//
// This module checks the questions, redacts their text for the page, and checks a submitted form against them. It never writes
// a file and runs nothing. It never reads the target either: a source file is checked for its form only. Answers are data. When
// an answer contradicts a measurement, the measurement prevails, and nothing here lets an answer change a measurement.
//
// The format. questions.json is { "schemaVersion": 1, "questions": [...] }, with at most MAX_QUESTIONS questions. A question is
// { id, type, text, why, source, options? } and no other key is allowed:
// - id: 1 to 32 characters of a-z, 0-9 and "-", unique among the questions. Its form field is "q-<id>".
// - type: "single" (one option), "multi" (any number of options) or "text" (a written answer).
// - text, why: non-blank strings of at most MAX_TEXT_LENGTH and MAX_WHY_LENGTH characters.
// - source: { file, line }. file is a path relative to the target (see fileProblem); line is an integer of at least 1.
// - options: a list of { id, label }, from MIN_OPTIONS to MAX_OPTIONS items. Required for single and multi, forbidden for text.
//   Option ids follow the id rule and are unique within their question. A label is a non-blank string of at most
//   MAX_LABEL_LENGTH characters.
//
// The form. A submitted form is a Map from field name to the list of values the browser sent. A choice sends option ids, never
// option text: a single question sends one id, a multi sends any number of ids, and a text sends the written answer.
//
// Lengths are counted in characters (code points), as the schemas count them. Redaction can make a redacted text longer than
// its cap, because a folder is replaced by a placeholder; the caps apply to the text as the agent wrote it. A written answer
// counts a line break as one character: CRLF (what a browser sends) and CR become LF before the count and before the answer is
// stored, so the count matches the page's maxlength. A written answer is redacted like the texts of the questions.

import fs from "node:fs";
import path from "node:path";
import { isPlainObject } from "./json-out.mjs";
import { LAYERS_FILE, visibleText } from "./layer-plan.mjs";
import { createRedactor } from "./redact.mjs";
import { checkRunDir, checkRunFile } from "./run-dir.mjs";
import { UsageError } from "./target.mjs";

/** The version of questions.json and answers.json. */
export const SCHEMA_VERSION = 1;
/** The name of the questions in a run folder, written by the agent. */
export const QUESTIONS_FILE = "questions.json";
/** The name of the answers in a run folder, written when the person answers the questions. */
export const ANSWERS_FILE = "answers.json";
/** The measurements of a run folder, written by scan.mjs. Its meta.targetRoot is read for redaction. */
export const MEASUREMENTS_FILE = "measurements.json";
/** The most questions a form asks. Five can be answered in one sitting; the agent asks only what the measurements cannot settle. */
export const MAX_QUESTIONS = 5;
/** The most characters of a question: a contradiction and its two sources, short enough to read on a phone without scrolling. */
export const MAX_TEXT_LENGTH = 500;
/** The most characters of the reason for a question. The same bound as a layer reason (MAX_REASON_LENGTH of layer-plan.mjs). */
export const MAX_WHY_LENGTH = 500;
/** The most characters of an option label: a short choice in a list. */
export const MAX_LABEL_LENGTH = 120;
/** The most characters of a written answer: a paragraph of context. A longer text is a document, not an answer. */
export const MAX_ANSWER_LENGTH = 2000;
/** The most characters of source.file. A path relative to the target is far shorter; the cap keeps a hostile one out of the page. */
export const MAX_FILE_LENGTH = 512;
/** The fewest options of a single or multi question. One option asks nothing. */
export const MIN_OPTIONS = 2;
/** The most options of a single or multi question. A longer list is not scanned by a person in a form. */
export const MAX_OPTIONS = 8;
/** The largest questions.json that is read, in bytes. Five questions take a few kilobytes; the cap bounds what is read. */
export const MAX_FILE_BYTES = 65_536;
/** The question types, in the order of the format description. */
export const QUESTION_TYPES = Object.freeze(["single", "multi", "text"]);
/** The prefix of the form field of a question: the field of question "depth" is "q-depth". */
export const FIELD_PREFIX = "q-";

const TOP_FIELDS = Object.freeze(["schemaVersion", "questions"]);
const QUESTION_FIELDS = Object.freeze(["id", "type", "text", "why", "source", "options"]);
const REQUIRED_QUESTION_FIELDS = Object.freeze(["id", "type", "text", "why", "source"]);
const SOURCE_FIELDS = Object.freeze(["file", "line"]);
const OPTION_FIELDS = Object.freeze(["id", "label"]);
const CHOICE_TYPES = Object.freeze(["single", "multi"]);
// The id rule. One character class with a bounded count: linear to check, with no nested quantifiers.
const ID_PATTERN = /^[a-z0-9-]{1,32}$/;
// A string with at least one character that is not a space: "non-blank".
const NON_BLANK = /\S/;
// A drive letter at the start, as in "C:x" or "C:/x".
const WINDOWS_DRIVE = /^[A-Za-z]:/;

/**
 * Checks the parsed questions.json. It reports every problem it finds, with a JSON pointer, and never throws on bad data.
 * It does not read the target: source.file is checked for its form only.
 * @param {unknown} data The parsed questions.json.
 * @returns {{ ok: true, questions: object[] } | { ok: false, errors: { pointer: string, message: string }[] }} pointer is a JSON
 *   pointer such as "/questions/0/id", and "" is the whole document. questions is the list of the file, as it was given.
 */
export function validateQuestions(data) {
  const errors = [];
  const report = (pointer, message) => errors.push({ pointer, message });
  if (!isPlainObject(data)) {
    report("", `must be an object with the fields ${TOP_FIELDS.join(" and ")}`);
    return { ok: false, errors };
  }
  checkFields(data, "", TOP_FIELDS, TOP_FIELDS, report);
  if (Object.hasOwn(data, "schemaVersion") && data.schemaVersion !== SCHEMA_VERSION) {
    report("/schemaVersion", `must be ${SCHEMA_VERSION}`);
  }
  if (Object.hasOwn(data, "questions")) checkQuestionList(data.questions, report);
  return errors.length === 0 ? { ok: true, questions: data.questions } : { ok: false, errors };
}

/**
 * Copies the questions with their text redacted: the text, the reason, the option labels and source.file go through
 * createRedactor, so a folder of the target becomes <target> and the home folder becomes ~. Ids, types, lines and the
 * options' ids are kept. The input is not changed. HTML escaping is not done here: the page does it when it shows a value.
 * @param {object[]} questions The questions, as validateQuestions returns them.
 * @param {{ root?: string, home?: string }} [options] root is the target folder; without it only the home folder is replaced.
 *   home defaults to the home folder of this machine; the tests pass their own.
 * @returns {object[]} The redacted copies, in the same order.
 */
export function redactQuestions(questions, { root, home } = {}) {
  if (!Array.isArray(questions)) throw new TypeError("redactQuestions needs the list of questions");
  const redact = createRedactor({ root, home });
  return questions.map((question) => {
    const copy = {
      id: question.id,
      type: question.type,
      text: redact(question.text),
      why: redact(question.why),
      source: { file: redact(question.source.file), line: question.source.line },
    };
    if (Object.hasOwn(question, "options")) {
      copy.options = question.options.map((option) => ({ id: option.id, label: redact(option.label) }));
    }
    return copy;
  });
}

/**
 * Checks the values that the person sent against the questions. The form holds one entry per question, named "q-<id>":
 * the list of option ids chosen (single and multi), or the written text in a list of one (text). Every problem is reported.
 * @param {Map<string, string[]>} form The submitted fields. A question with no entry has no value.
 * @param {object[]} questions The questions the form asks. Pass the list that loadQuestions returns: the question text and
 *   the labels copied into the answers are the ones given here, already redacted.
 * @param {{ redact?: (value: unknown) => unknown }} [options] redact is applied to every written answer. The default is
 *   createRedactor() (the home folder and token-shaped text); the server passes the redactor of the run, which knows its target.
 * @returns {{ ok: true, answers: object[] } | { ok: false, errors: { pointer: string, message: string }[] }} The answers come in
 *   the order of the questions. A single or multi answer is { id, type, question, why, source: { file, line }, selected:
 *   [{ id, label }] } with the options in the order of the question, and a text answer is { id, type, question, why, source,
 *   value }. A multi with no value is an empty selection, and a text with no value is "".
 * @throws {TypeError} When form is not a Map or questions is not a list.
 */
export function validateAnswers(form, questions, { redact = createRedactor() } = {}) {
  if (!(form instanceof Map)) throw new TypeError("form must be a Map from field name to the list of its values");
  if (!Array.isArray(questions)) throw new TypeError("questions must be the list that loadQuestions returns");
  const errors = [];
  const report = (pointer, message) => errors.push({ pointer, message });
  const fields = new Set(questions.map((question) => `${FIELD_PREFIX}${question.id}`));
  for (const name of form.keys()) {
    if (!fields.has(name)) report(childPointer("", name), "unknown field: no question has this id");
  }
  const answers = [];
  for (const question of questions) {
    const field = `${FIELD_PREFIX}${question.id}`;
    const before = errors.length;
    const answer = answerTo(question, form.get(field) ?? [], childPointer("", field), report, redact);
    if (errors.length === before) answers.push(answer);
  }
  return errors.length === 0 ? { ok: true, answers } : { ok: false, errors };
}

/**
 * Reads <runDir>/questions.json, checks it and returns its questions, redacted for the page (see loadQuestions).
 * @param {string} runDir The run folder, absolute or relative to the working directory.
 * @param {{ harnessRoot: string }} options harnessRoot is the absolute path of the harness-x-ray folder.
 * @returns {object[]} The redacted questions, in the order of the file (see redactQuestions).
 * @throws {UsageError} As loadQuestions does.
 * @throws {TypeError} When runDir or harnessRoot is not a string.
 */
export function readQuestions(runDir, options) {
  return loadQuestions(runDir, options).questions;
}

/**
 * Reads <runDir>/questions.json once, checks it, and returns its questions redacted for the page, with the redactor of the run.
 * The run folder must be allowed (checkRunDir), and so must the file (checkRunFile), so a link or a file outside the run folder
 * is refused. The redaction root is meta.targetRoot of measurements.json when that file is a plain file of the run folder that
 * parses and records an absolute path; otherwise it is the target root of layers.json, by the same rule; otherwise there is no
 * root and only the home folder is replaced. A file that cannot be used adds no root, and the next one is tried. The redactor
 * has the same root, so the written answers are redacted as the questions are.
 * @param {string} runDir The run folder, absolute or relative to the working directory.
 * @param {{ harnessRoot: string }} options harnessRoot is the absolute path of the harness-x-ray folder.
 * @returns {{ questions: object[], redact: (value: unknown) => unknown }} questions as readQuestions returns them; redact is the
 *   createRedactor function of the run, for validateAnswers.
 * @throws {UsageError} When the run folder or the file is not allowed, the file is missing, cannot be read, is larger than
 *   MAX_FILE_BYTES, is not JSON, or does not pass validateQuestions. The message lists the problems.
 * @throws {TypeError} When runDir or harnessRoot is not a string.
 */
export function loadQuestions(runDir, { harnessRoot } = {}) {
  if (typeof runDir !== "string" || runDir === "") throw new TypeError("loadQuestions needs the path of the run folder");
  if (typeof harnessRoot !== "string") throw new TypeError("loadQuestions needs harnessRoot, the path of the harness-x-ray folder");
  const dir = path.resolve(runDir);
  checkRunDir(dir, harnessRoot);
  const file = path.join(dir, QUESTIONS_FILE);
  checkRunFile(file, { harnessRoot });
  const checked = validateQuestions(readQuestionsFile(file));
  if (!checked.ok) throw new UsageError(`${file} is not valid: ${formatErrors(checked.errors)}`);
  const root = recordedTargetRoot(dir, harnessRoot);
  return { questions: redactQuestions(checked.questions, { root }), redact: createRedactor({ root }) };
}

// The list of questions. The limits are checked here, and the items are checked one by one, so every problem is reported.
function checkQuestionList(questions, report) {
  if (!Array.isArray(questions)) {
    report("/questions", "must be a list of questions");
    return;
  }
  if (questions.length === 0) report("/questions", "must hold at least one question");
  if (questions.length > MAX_QUESTIONS) {
    report("/questions", `holds ${questions.length} questions; the most is ${MAX_QUESTIONS}`);
  }
  const ids = new Set();
  questions.forEach((question, index) => checkQuestion(question, `/questions/${index}`, ids, report));
}

function checkQuestion(question, pointer, ids, report) {
  if (!isPlainObject(question)) {
    report(pointer, "must be an object");
    return;
  }
  checkFields(question, pointer, QUESTION_FIELDS, REQUIRED_QUESTION_FIELDS, report);
  if (Object.hasOwn(question, "id")) checkId(question.id, childPointer(pointer, "id"), ids, "an id", report);
  if (Object.hasOwn(question, "type") && !QUESTION_TYPES.includes(question.type)) {
    report(childPointer(pointer, "type"), `must be one of ${QUESTION_TYPES.join(", ")}`);
  }
  if (Object.hasOwn(question, "text")) checkText(question.text, childPointer(pointer, "text"), MAX_TEXT_LENGTH, report);
  if (Object.hasOwn(question, "why")) checkText(question.why, childPointer(pointer, "why"), MAX_WHY_LENGTH, report);
  if (Object.hasOwn(question, "source")) checkSource(question.source, childPointer(pointer, "source"), report);
  // The options depend on the type: a choice needs them, and a written answer has none.
  const optionsPointer = childPointer(pointer, "options");
  if (CHOICE_TYPES.includes(question.type) && !Object.hasOwn(question, "options")) {
    report(optionsPointer, `missing required field: a ${question.type} question needs options`);
  } else if (CHOICE_TYPES.includes(question.type)) {
    checkOptions(question.options, optionsPointer, report);
  } else if (question.type === "text" && Object.hasOwn(question, "options")) {
    report(optionsPointer, "is not allowed for a text question");
  }
}

function checkOptions(options, pointer, report) {
  if (!Array.isArray(options)) {
    report(pointer, "must be a list of options");
    return;
  }
  if (options.length < MIN_OPTIONS || options.length > MAX_OPTIONS) {
    report(pointer, `must hold from ${MIN_OPTIONS} to ${MAX_OPTIONS} options, found ${options.length}`);
  }
  const ids = new Set();
  options.forEach((option, index) => {
    const base = `${pointer}/${index}`;
    if (!isPlainObject(option)) {
      report(base, "must be an object with the fields id and label");
      return;
    }
    checkFields(option, base, OPTION_FIELDS, OPTION_FIELDS, report);
    if (Object.hasOwn(option, "id")) checkId(option.id, childPointer(base, "id"), ids, "an option id", report);
    if (Object.hasOwn(option, "label")) checkText(option.label, childPointer(base, "label"), MAX_LABEL_LENGTH, report);
  });
}

function checkSource(source, pointer, report) {
  if (!isPlainObject(source)) {
    report(pointer, "must be an object with the fields file and line");
    return;
  }
  checkFields(source, pointer, SOURCE_FIELDS, SOURCE_FIELDS, report);
  if (Object.hasOwn(source, "file")) {
    const problem = fileProblem(source.file);
    if (problem !== null) report(childPointer(pointer, "file"), problem);
  }
  if (Object.hasOwn(source, "line") && !(Number.isSafeInteger(source.line) && source.line >= 1)) {
    report(childPointer(pointer, "line"), "must be an integer of at least 1");
  }
}

// The form of a path from the agent. The path is relative to the target and is never read here. A UNC path starts with two
// separators, so the rule for a rooted path refuses it too.
function fileProblem(value) {
  if (typeof value !== "string") return "must be a string";
  if (value === "") return "must not be empty";
  if (value.includes("\0")) return "must not contain a NUL character";
  if (charLength(value) > MAX_FILE_LENGTH) return `is longer than ${MAX_FILE_LENGTH} characters`;
  // Whitespace at either end is refused first: a leading space would hide a rooted path or a drive letter from the checks below.
  if (value !== value.trim()) return "must not start or end with whitespace";
  if (value.startsWith("/") || value.startsWith("\\")) return "must be relative to the target, not rooted";
  if (WINDOWS_DRIVE.test(value)) return "must not start with a drive letter";
  // Both separators split the path, so a backslash path is checked as a Windows path would be. A segment that is .. once its
  // spaces are trimmed is a .. segment too.
  if (value.split(/[\\/]/).some((segment) => segment.trim() === "..")) return "must not contain a .. segment";
  return null;
}

// An id that follows the id rule and is not in seen yet. A valid id is added to seen.
function checkId(value, pointer, seen, what, report) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    report(pointer, 'must be 1 to 32 characters of a-z, 0-9 and "-"');
  } else if (seen.has(value)) {
    report(pointer, `repeats ${what}`);
  } else {
    seen.add(value);
  }
}

// A non-blank string of at most cap characters. A blank text is refused, because the page would show nothing.
function checkText(value, pointer, cap, report) {
  if (typeof value !== "string" || !NON_BLANK.test(value)) {
    report(pointer, "must be a non-blank string");
  } else if (charLength(value) > cap) {
    report(pointer, `is longer than ${cap} characters`);
  }
}

// Reports the fields that are not allowed and the ones that are required and missing.
function checkFields(object, pointer, allowed, required, report) {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) report(childPointer(pointer, key), `unknown field; the fields are ${allowed.join(", ")}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(object, key)) report(childPointer(pointer, key), "missing required field");
  }
}

// The answer to one question. It reports the problems of its value, and it returns the answer when there are none.
function answerTo(question, values, pointer, report, redact) {
  if (!Array.isArray(values) || !values.every((value) => typeof value === "string")) {
    report(pointer, "must be a list of strings");
    return answerRecord(question, { value: "" });
  }
  if (question.type === "text") return textAnswer(question, values, pointer, report, redact);
  return choiceAnswer(question, values, pointer, report);
}

// A written answer. A line break is one character, as the page's maxlength counts it: CRLF and CR become LF before the count and
// before the text is stored. The stored text is redacted, so a token or a folder typed into it is masked as the questions are.
function textAnswer(question, values, pointer, report, redact) {
  if (values.length > 1) report(pointer, `takes one value; found ${values.length}`);
  const value = (values[0] ?? "").replace(/\r\n?/g, "\n");
  if (charLength(value) > MAX_ANSWER_LENGTH) report(pointer, `is longer than ${MAX_ANSWER_LENGTH} characters`);
  return answerRecord(question, { value: redact(value) });
}

function choiceAnswer(question, values, pointer, report) {
  const chosen = new Set();
  if (question.type === "single" && values.length > 1) {
    report(pointer, `takes one value; found ${values.length}`);
  } else if (question.type === "single" && (values.length === 0 || values[0] === "")) {
    report(pointer, "needs an answer: choose one option");
  } else {
    const offered = new Set(question.options.map((option) => option.id));
    for (const value of values) {
      if (!offered.has(value)) report(pointer, "is not an option of this question");
      else if (chosen.has(value)) report(pointer, "repeats an option id");
      else chosen.add(value);
    }
  }
  // The options come in the order of the question, not in the order the form sent them.
  const selected = question.options
    .filter((option) => chosen.has(option.id))
    .map((option) => ({ id: option.id, label: option.label }));
  return answerRecord(question, { selected });
}

function answerRecord(question, answer) {
  return {
    id: question.id,
    type: question.type,
    question: question.text,
    why: question.why,
    source: { file: question.source.file, line: question.source.line },
    ...answer,
  };
}

// The target root that the run records: measurements.json first, then layers.json. A file that is not a plain file of the run
// folder, or that does not parse, or that records no absolute path, adds no root.
function recordedTargetRoot(dir, harnessRoot) {
  for (const name of [MEASUREMENTS_FILE, LAYERS_FILE]) {
    const root = targetRootOf(path.join(dir, name), harnessRoot);
    if (root !== undefined) return root;
  }
  return undefined;
}

function targetRootOf(file, harnessRoot) {
  try {
    checkRunFile(file, { harnessRoot });
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    const root = parsed?.meta?.targetRoot;
    return typeof root === "string" && path.isAbsolute(root) ? root : undefined;
  } catch {
    // Redaction is a safety net, not a check of the run: a file that cannot be used only leaves the next source to decide.
    return undefined;
  }
}

// Reads the file as text and parses it. The size is checked before the read, so a huge file is never read whole.
function readQuestionsFile(file) {
  let text;
  try {
    if (fs.statSync(file).size > MAX_FILE_BYTES) {
      throw new UsageError(`${file} is larger than ${MAX_FILE_BYTES} bytes`);
    }
    text = fs.readFileSync(file, "utf8");
  } catch (error) {
    if (error instanceof UsageError) throw error;
    if (error?.code === "ENOENT") throw new UsageError(`${file} is missing`);
    throw new UsageError(`${file} cannot be read: ${error?.code ?? "unknown error"}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${file} is not valid JSON: ${visibleText(error.message)}`);
  }
}

function formatErrors(errors) {
  return errors.map((item) => (item.pointer === "" ? item.message : `${visibleText(item.pointer)}: ${item.message}`)).join("; ");
}

// A JSON pointer for a key of an object. "~" and "/" are escaped as RFC 6901 says, so a key cannot forge a level.
function childPointer(pointer, key) {
  return `${pointer}/${String(key).replace(/~/g, "~0").replace(/\//g, "~1")}`;
}

// Length in characters (code points), not in UTF-16 units, so an emoji counts as one character, as the schemas count it.
function charLength(text) {
  return [...text].length;
}
