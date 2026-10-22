// The local server of the intake form and of the questions form, behind scripts/intake.mjs. It listens on 127.0.0.1 only, on a
// random port. The intake form (startIntake) is served at /intake?token=<token> for the layers of <runDir>/layer-plan.json. The
// questions form (startQuestions) is served at /questions?token=<token> for the questions of <runDir>/questions.json. The token
// is random and works once. A valid submission is checked again right before it is written, so only one submission can ever be
// written: the token is marked used before the write starts. The file is written to a temporary name in the run folder and then
// hard-linked to intake.json (or answers.json), which fails when that file exists, so the write is exclusive. The answer is the
// done page, the wait timer is cleared, and the server stops after the requests already in flight have had their answer. A
// timeout stops the server and writes nothing. A form that is not valid gets an HTML page with the list of its errors and a
// link back to the form, and the server keeps running, so the person can send it again. A run folder that already holds the
// output file is refused: the form is answered once, and the file must be removed to ask again.
//
// Both forms share one HTTP core (serve). It does the checks of the request, the body cap, the timeouts, the pages and the
// write. What differs is passed in by the two public functions: the route, the output file, the name of the result in done, the
// pages, and verify, which checks a body against the plan or the questions. The public functions read the run folder and check
// that the output file is free before the page renderers load, so a run that is already answered is refused at once.
//
// The request line and the headers are checked first. A request is refused with 403 unless the Host header is exactly
// 127.0.0.1:<port> (which defeats DNS rebinding), an Origin header, when present, is exactly http://127.0.0.1:<port>, and a POST
// carries that Origin. The body is read only up to maxBodyBytes. Past the cap, the answer (413, or the refusal that applies)
// goes out at once with Connection: close, at most DRAIN_BYTES more are read, and the socket is then cut off, so a client that
// sends a huge body cannot hold the server.
//
// The server's timeouts: a client that takes more than 10 s to send its headers, or 30 s for its whole request, is cut off, and
// a keep-alive connection that stays idle for 1 s is closed. A stop that follows a written file waits at most GRACE_MS for the
// requests in flight, and then cuts them.
//
// startIntake and startQuestions resolve to { url, port, token, done, close }. done resolves, once the server has stopped, to
// { code, intake? } or { code, answers? }: 0 when the output file was written (intake holds intake.json, answers holds the document
// of answers.json: { schemaVersion, answers }), 4 when the wait ran out, and 1 when close() stopped the server before a submission
// or the server failed (message says which). Nothing is opened in a browser, and nothing from the run folder is run.
//
// Routes and status codes: GET and HEAD of the route give 200 with the page; POST of the route gives 200 with the done page when
// the form is valid, and 400 with the HTML page of the errors otherwise; another method on the route gives 405 with Allow: GET,
// HEAD, POST; another path gives 404; a wrong, missing, repeated or used token, a wrong Host or Origin give 403; a body that is
// not a form gives 415; a body over the cap gives 413; a questions form whose names or values are not valid UTF-8 gives 400, with
// the error page; a file that cannot be written gives 500 and the server keeps running.

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { writeStableJson, isPlainObject } from "./json-out.mjs";
import { readLayerPlan } from "./layer-plan.mjs";
import {
  ANSWERS_FILE,
  MAX_ANSWER_LENGTH,
  MAX_QUESTIONS,
  SCHEMA_VERSION as ANSWERS_SCHEMA_VERSION,
  loadQuestions,
  validateAnswers,
} from "./questions.mjs";
import { checkRunDir, checkRunFile } from "./run-dir.mjs";
import { UsageError } from "./target.mjs";

/** The version of intake.json. */
export const INTAKE_SCHEMA_VERSION = 1;
/** The depths the form offers, in the order of the form. */
export const DEPTHS = Object.freeze(["quick", "standard", "deep"]);
/** The scopes the form offers: every layer, or the chosen layers. */
export const SCOPES = Object.freeze(["all", "layers"]);
/** The axes the form offers, in the fixed order that intake.json keeps. None chosen is valid. */
export const AXES = Object.freeze(["instructions", "context", "security", "verification", "structure", "code"]);
/** The languages of the form and of its pages. */
export const LANGUAGES = Object.freeze(["en", "es"]);
/** The fields of the form. */
export const FORM_FIELDS = Object.freeze(["depth", "scope", "layer", "axis", "language", "userLayer", "ancestors"]);

const REPEATED_FIELDS = Object.freeze(["layer", "axis"]);
const ROUTE = "/intake";
const QUESTIONS_ROUTE = "/questions";
const ALLOWED_METHODS = Object.freeze(["GET", "HEAD", "POST"]);
const FORM_TYPE = "application/x-www-form-urlencoded";
const HTML_TYPE = "text/html; charset=utf-8";
const TEXT_TYPE = "text/plain; charset=utf-8";
const INTAKE_FILE = "intake.json";
const LAYERS_FILE = "layers.json";
const PLAN_FILE = "layer-plan.json";
const TOKEN_BYTES = 32;
const TOKEN_REFUSED = "forbidden: the token is missing, wrong or already used";
const DEFAULT_TIMEOUT_MS = 600_000;
const DEFAULT_MAX_BODY_BYTES = 16_384;
// The default cap of the questions form, derived from the question caps. A written answer of MAX_ANSWER_LENGTH characters takes
// at most 4 bytes per character in UTF-8, and the browser sends each byte as %XX, which is 3 characters. Each question has a
// margin of QUESTION_MARGIN_BYTES for its field name, the separators and a choice: at most 8 values of 68 bytes each (the field
// name "q-" and an id of 32 characters, with the "=" and the "&"), which is 544 bytes. The sum for MAX_QUESTIONS questions is
// rounded up to a power of two: 2^17 bytes (128 KiB).
const UTF8_MAX_CHAR_BYTES = 4;
const PERCENT_ENCODED_BYTE_LENGTH = 3;
const QUESTION_MARGIN_BYTES = 1_024;
const QUESTION_BYTES = MAX_ANSWER_LENGTH * UTF8_MAX_CHAR_BYTES * PERCENT_ENCODED_BYTE_LENGTH + QUESTION_MARGIN_BYTES;
/** The default largest request body of the questions form, in bytes: 131072. The intake form keeps DEFAULT_MAX_BODY_BYTES. */
export const QUESTIONS_MAX_BODY_BYTES = 2 ** Math.ceil(Math.log2(MAX_QUESTIONS * QUESTION_BYTES));
// The decoder of a name or a value of the questions form. It keeps a byte order mark, as URLSearchParams does, and it fails on
// bytes that are not UTF-8, where URLSearchParams would put U+FFFD in their place.
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// The most a request is read past the cap, after its answer is sent. A client that sends more is cut off.
const DRAIN_BYTES = 65_536;
// The longest a stop that follows a written file waits for the requests in flight before it cuts them.
const GRACE_MS = 2_000;
// The timeouts of the HTTP server, in milliseconds (see the header comment).
const SERVER_TIMEOUTS = Object.freeze({ headersTimeout: 10_000, requestTimeout: 30_000 });
const KEEP_ALIVE_TIMEOUT_MS = 1_000;
// The longest delay that setTimeout keeps; a longer one would fire at once.
const MAX_TIMER_MS = 2_147_483_647;
// The index of a layer as the form writes it: 0, or a number without a leading zero.
const INDEX_PATTERN = /^(0|[1-9][0-9]*)$/;

/**
 * Starts the intake server for one run folder and resolves once it listens.
 * @param {object} options
 * @param {string} options.runDir The run folder. It must pass checkRunDir, hold a valid layer-plan.json, and hold no intake.json.
 * @param {string} options.harnessRoot Absolute path of the harness-x-ray folder.
 * @param {number} [options.timeoutMs] The wait for a valid submission, in milliseconds. The default is ten minutes.
 * @param {number} [options.maxBodyBytes] The largest request body, in bytes. The default is 16384.
 * @param {"en" | "es"} [options.language] The language of the pages. The default is en.
 * @param {Function} [options.renderPage] Renders the form: ({ harnessRoot, plan, language, action }) -> { html, csp }.
 * @param {Function} [options.renderDone] Renders the done page: ({ harnessRoot, language }) -> { html, csp }.
 * @param {Function} [options.renderError] Renders the page of an invalid form: ({ harnessRoot, language, action, errors }) ->
 *   { html, csp }. The renderers default to those of lib/intake-page.mjs, which is loaded only when one of them is not given.
 * @returns {Promise<{ url: string, port: number, token: string, done: Promise<{ code: number, intake?: object, message?: string }>, close: () => Promise<void> }>}
 *   url is the address of the form, with the token. done resolves when the server has stopped. close() stops the server
 *   and may be called any number of times; each call returns the same promise.
 * @throws {UsageError} If the run folder is not allowed, has no valid layer plan, already holds an intake.json, or the language is unknown.
 */
export async function startIntake({
  runDir,
  harnessRoot,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  language = "en",
  renderPage,
  renderDone,
  renderError,
} = {}) {
  checkStartArgs({ runDir, harnessRoot, timeoutMs, maxBodyBytes, language });
  const dir = path.resolve(runDir);
  checkRunDir(dir, harnessRoot);
  const plan = loadPlan(dir, harnessRoot);
  const outputFile = path.join(dir, INTAKE_FILE);
  checkOutputFree(outputFile, harnessRoot);
  const renderers = await loadRenderers({ renderPage, renderDone, renderError }, "renderIntakePage");
  return serve({
    dir,
    harnessRoot,
    route: ROUTE,
    outputFile,
    resultKey: "intake",
    timeoutMs,
    maxBodyBytes,
    pages: {
      renderPage: ({ action }) => renderers.renderPage({ harnessRoot, plan, language, action }),
      renderDone: () => renderers.renderDone({ harnessRoot, language }),
      renderError: ({ action, errors }) => renderers.renderError({ harnessRoot, language, action, errors }),
    },
    verify: (body) => verifyIntake(body, plan),
  });
}

/**
 * Starts the questions server for one run folder and resolves once it listens. The questions are read from
 * <runDir>/questions.json by loadQuestions, which refuses a missing or invalid file, and the answers are written to
 * <runDir>/answers.json. The page and the answers carry the questions as loadQuestions redacted them, and a written answer is
 * redacted with the same redactor.
 * @param {object} options
 * @param {string} options.runDir The run folder. It must pass checkRunDir, hold a valid questions.json, and hold no answers.json.
 * @param {string} options.harnessRoot Absolute path of the harness-x-ray folder.
 * @param {number} [options.timeoutMs] The wait for a valid submission, in milliseconds. The default is ten minutes.
 * @param {number} [options.maxBodyBytes] The largest request body, in bytes. The default is QUESTIONS_MAX_BODY_BYTES, derived from
 *   the question caps (128 KiB), so that five written answers of the largest size are accepted.
 * @param {"en" | "es"} [options.language] The language of the pages. The default is en.
 * @param {Function} [options.renderPage] Renders the form: ({ harnessRoot, questions, language, action }) -> { html, csp }.
 * @param {Function} [options.renderDone] Renders the done page: ({ harnessRoot, language }) -> { html, csp }.
 * @param {Function} [options.renderError] Renders the page of an invalid form: ({ harnessRoot, language, action, errors }) ->
 *   { html, csp }. The renderers default to those of lib/intake-page.mjs, which is loaded only when one of them is not given.
 * @returns {Promise<{ url: string, port: number, token: string, done: Promise<{ code: number, answers?: object, message?: string }>, close: () => Promise<void> }>}
 *   url is the address of the form, with the token. done resolves to { code: 0, answers } when answers.json was written, where
 *   answers is its document { schemaVersion, answers }. close() behaves as in startIntake.
 * @throws {UsageError} If the run folder is not allowed, has no valid questions.json (or more than five questions), already holds
 *   an answers.json, or the language is unknown.
 */
export async function startQuestions({
  runDir,
  harnessRoot,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBodyBytes = QUESTIONS_MAX_BODY_BYTES,
  language = "en",
  renderPage,
  renderDone,
  renderError,
} = {}) {
  checkStartArgs({ runDir, harnessRoot, timeoutMs, maxBodyBytes, language });
  const dir = path.resolve(runDir);
  checkRunDir(dir, harnessRoot);
  const { questions, redact } = loadQuestions(dir, { harnessRoot });
  const outputFile = path.join(dir, ANSWERS_FILE);
  checkOutputFree(outputFile, harnessRoot);
  const renderers = await loadRenderers({ renderPage, renderDone, renderError }, "renderQuestionsPage");
  return serve({
    dir,
    harnessRoot,
    route: QUESTIONS_ROUTE,
    outputFile,
    resultKey: "answers",
    timeoutMs,
    maxBodyBytes,
    pages: {
      renderPage: ({ action }) => renderers.renderPage({ harnessRoot, questions, language, action }),
      renderDone: () => renderers.renderDone({ harnessRoot, language }),
      renderError: ({ action, errors }) => renderers.renderError({ harnessRoot, language, action, errors }),
    },
    verify: (body) => verifyAnswers(body, questions, redact),
  });
}

/**
 * Parses the body of an answers form, which is application/x-www-form-urlencoded, into a Map from field name to the list of
 * its values, in the order they were sent. The names are not checked here: validateAnswers reports a field that no question has.
 * The split and the percent-decoding are done here, not by URLSearchParams: that one would put U+FFFD in place of a byte that is
 * not UTF-8, and a form with such a byte must be refused, not answered with a changed text.
 * @param {string | Buffer} body
 * @returns {Map<string, string[]> | null} null when a name or a value is not valid UTF-8.
 * @throws {TypeError} When body is neither a string nor a Buffer.
 */
export function parseAnswerForm(body) {
  if (typeof body !== "string" && !Buffer.isBuffer(body)) throw new TypeError("parseAnswerForm takes a string or a Buffer");
  // One character per byte (latin1), so that a sequence is split at the bytes of "&" and "=", and nothing else changes.
  const raw = Buffer.isBuffer(body) ? body.toString("latin1") : Buffer.from(body, "utf8").toString("latin1");
  const form = new Map();
  for (const pair of raw.split("&")) {
    if (pair === "") continue;
    const equals = pair.indexOf("=");
    const name = decodeComponent(equals < 0 ? pair : pair.slice(0, equals));
    const value = equals < 0 ? "" : decodeComponent(pair.slice(equals + 1));
    if (name === null || value === null) return null;
    const values = form.get(name);
    if (values === undefined) form.set(name, [value]);
    else values.push(value);
  }
  return form;
}

// One name or value of a form, given one byte per character. "+" is a space, "%XX" is the byte XX, and a "%" that is not followed
// by two hex digits stands for itself, as URLSearchParams reads it. The bytes must be UTF-8: null when they are not.
function decodeComponent(raw) {
  const decoded = raw.replace(/\+/g, " ").replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
  try {
    return UTF8_DECODER.decode(Buffer.from(decoded, "latin1"));
  } catch {
    return null;
  }
}

/**
 * Parses the body of the form, which is application/x-www-form-urlencoded. The body is split as URLSearchParams splits it.
 * Each field must be one of FORM_FIELDS. The single fields may appear once; layer and axis may repeat, and their values are
 * kept in order as lists.
 * @param {string | Buffer} body
 * @returns {{ ok: boolean, form: { depth?: string, scope?: string, language?: string, userLayer?: string, ancestors?: string,
 *   layer: string[], axis: string[] } | null, errors: { pointer: string, message: string }[] }} form is null when errors is
 *   not empty. A message never repeats the text of the body.
 */
export function parseForm(body) {
  const text = Buffer.isBuffer(body) ? body.toString("utf8") : body;
  if (typeof text !== "string") throw new TypeError("parseForm takes a string or a Buffer");
  const errors = [];
  const form = { layer: [], axis: [] };
  const counts = new Map();
  let unknownReported = false;
  for (const [name, value] of new URLSearchParams(text)) {
    if (!FORM_FIELDS.includes(name)) {
      if (!unknownReported) errors.push({ pointer: "", message: `unknown field; the fields are ${FORM_FIELDS.join(", ")}` });
      unknownReported = true;
      continue;
    }
    if (REPEATED_FIELDS.includes(name)) {
      form[name].push(value);
      continue;
    }
    const count = (counts.get(name) ?? 0) + 1;
    counts.set(name, count);
    if (count === 2) errors.push({ pointer: `/${name}`, message: "is given more than once" });
    if (count === 1) form[name] = value;
  }
  return errors.length === 0 ? { ok: true, form, errors } : { ok: false, form: null, errors };
}

/**
 * Checks the answers of the form against the layer plan and builds the intake. It reports every problem it finds.
 * @param {object} answers The form, as parseForm returns it (layer and axis are lists; a missing field is undefined).
 * @param {{ layers: { name: string }[] }} plan The layer plan, as layer-plan.json holds it (it has passed readLayerPlan).
 * @returns {{ ok: boolean, errors: { pointer: string, message: string }[], intake?: object }} intake is set when ok is true:
 *   { schemaVersion, depth, scope: { mode: "all" } | { mode: "layers", layers: names in plan order }, axes (in the order of
 *   AXES, empty when none was chosen), language, outsideAccess: { userLayer, ancestors } }.
 */
export function validateIntake(answers, plan) {
  const errors = [];
  const report = (pointer, message) => errors.push({ pointer, message });
  if (!isPlainObject(answers)) return { ok: false, errors: [{ pointer: "", message: "the answers must be an object" }] };
  for (const key of Object.keys(answers)) {
    if (!FORM_FIELDS.includes(key)) report(`/${key}`, "unknown field");
  }
  const count = Array.isArray(plan?.layers) ? plan.layers.length : 0;
  const depth = pickOne(answers.depth, "depth", DEPTHS, report);
  const scope = pickOne(answers.scope, "scope", SCOPES, report);
  const language = pickOne(answers.language, "language", LANGUAGES, report);
  const userLayer = yesFlag(answers.userLayer, "userLayer", report);
  const ancestors = yesFlag(answers.ancestors, "ancestors", report);
  const indexes = layerIndexes(answers.layer, scope, count, report);
  const axes = axisList(answers.axis, report);
  if (errors.length > 0) return { ok: false, errors };

  const scopeValue =
    scope === "all" ? { mode: "all" } : { mode: "layers", layers: indexes.map((index) => plan.layers[index].name) };
  return {
    ok: true,
    errors: [],
    intake: {
      schemaVersion: INTAKE_SCHEMA_VERSION,
      depth,
      scope: scopeValue,
      axes,
      language,
      outsideAccess: { userLayer, ancestors },
    },
  };
}

// The checks of the arguments that both forms share. They throw before the run folder is read or the server listens.
function checkStartArgs({ runDir, harnessRoot, timeoutMs, maxBodyBytes, language }) {
  if (typeof runDir !== "string" || typeof harnessRoot !== "string") throw new TypeError("runDir and harnessRoot must be paths");
  if (!isDelay(timeoutMs)) throw new TypeError("timeoutMs must be a whole number of milliseconds from 1 to 2147483647");
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) throw new TypeError("maxBodyBytes must be a positive integer");
  if (!LANGUAGES.includes(language)) throw new UsageError(`language must be one of ${LANGUAGES.join(", ")}`);
}

// The check of the intake form: the body is parsed and validated against the plan. The document is the intake.
function verifyIntake(body, plan) {
  const parsed = parseForm(body);
  const verdict = parsed.ok ? validateIntake(parsed.form, plan) : { ok: false, errors: parsed.errors };
  return verdict.ok ? { ok: true, document: verdict.intake } : verdict;
}

// The check of the questions form: the body is parsed and validated against the questions, and the written answers are redacted
// with the redactor of the run. The document is answers.json.
function verifyAnswers(body, questions, redact) {
  const form = parseAnswerForm(body);
  if (form === null) return { ok: false, errors: [{ pointer: "", message: "the form is not valid UTF-8" }] };
  const verdict = validateAnswers(form, questions, { redact });
  return verdict.ok ? { ok: true, document: { schemaVersion: ANSWERS_SCHEMA_VERSION, answers: verdict.answers } } : verdict;
}

// The output file must be free: a plain file or no file, and no file that already answered the form. The public functions call
// it before the renderers load; serve relies on the link of the write for the check that counts.
function checkOutputFree(file, harnessRoot) {
  checkRunFile(file, { harnessRoot });
  if (fs.existsSync(file)) throw new UsageError(`${file} already exists: already answered; remove it to ask again`);
}

// The HTTP core of both forms, behind the public functions. The caller passes the route, the output file and the name of its
// result in done (resultKey), the pages (renderPage({ action }), renderDone(), renderError({ action, errors }), each returning
// { html, csp }), and verify(body), which returns { ok: true, document } or { ok: false, errors }. The document is written as
// the output file, as it is.
async function serve({ dir, harnessRoot, route, outputFile, resultKey, timeoutMs, maxBodyBytes, pages, verify }) {
  const token = crypto.randomBytes(TOKEN_BYTES).toString("base64url");
  const action = `${route}?token=${token}`;
  const page = checkRendered(pages.renderPage({ action }), "renderPage");
  const donePage = checkRendered(pages.renderDone(), "renderDone");
  const pageCsp = withFrameAncestors(page.csp);
  const doneCsp = withFrameAncestors(donePage.csp);

  let port = 0;
  let tokenLive = true;
  let outcome = null;
  let shutdown = null;
  let forced = false;
  let timer = null;
  let settle;
  const finished = new Promise((resolve) => {
    settle = resolve;
  });
  const server = http.createServer(SERVER_TIMEOUTS);
  server.keepAliveTimeout = KEEP_ALIVE_TIMEOUT_MS;

  // Stops the server once. The first result is kept: a written file stays a success even if close() comes later. After a
  // written file (graceful), the server stops listening, lets the requests in flight get their answer (a refusal, since the
  // token is used), and cuts the rest after GRACE_MS. Any other stop cuts every connection at once.
  const stop = (next, { graceful = false } = {}) => {
    outcome ??= next;
    tokenLive = false;
    clearTimeout(timer);
    shutdown ??= new Promise((resolve) => {
      let grace = null;
      server.close(() => {
        clearTimeout(grace);
        settle(outcome);
        resolve();
      });
      if (graceful) {
        server.closeIdleConnections();
        grace = setTimeout(() => server.closeAllConnections(), GRACE_MS);
      } else {
        forced = true;
        server.closeAllConnections();
      }
    });
    return shutdown;
  };

  // Accepts only the one token of this run, and only while it is live. The query must hold exactly one parameter, token.
  const tokenAccepted = (query) => {
    if (!tokenLive) return false;
    const params = new URLSearchParams(query);
    const names = [...params.keys()];
    return names.length === 1 && names[0] === "token" && sameSecret(params.get("token"), token);
  };

  // The checks that need only the request line and the headers. Null means the request may go on: a GET or HEAD gets the
  // page, and a POST goes on to its body.
  const refusalOf = (req) => {
    const expectedOrigin = `http://127.0.0.1:${port}`;
    const { pathname, query } = splitTarget(req.url ?? "");
    if (req.headers.host !== `127.0.0.1:${port}`) return refusal(403, "forbidden: the Host header is not this server");
    if (req.headers.origin !== undefined && req.headers.origin !== expectedOrigin) {
      return refusal(403, "forbidden: the Origin is not this server");
    }
    if (pathname !== route) return refusal(404, "not found");
    if (!tokenAccepted(query)) return refusal(403, TOKEN_REFUSED);
    if (!ALLOWED_METHODS.includes(req.method)) return refusal(405, "method not allowed", { allow: "GET, HEAD, POST" });
    if (req.method !== "POST") return null;
    if (req.headers.origin !== expectedOrigin) return refusal(403, "forbidden: a form must be sent from this server");
    if (!isFormType(req.headers["content-type"])) return refusal(415, `the body must be ${FORM_TYPE}`);
    return null;
  };

  // A POST whose headers passed and whose body is within the cap. The token is checked here too, because another POST may
  // have been accepted while this one was being read.
  const submit = (res, body) => {
    if (!tokenLive) return sendRefusal(res, refusal(403, TOKEN_REFUSED));
    const verdict = verify(body);
    if (!verdict.ok) {
      const errorPage = checkRendered(pages.renderError({ action, errors: verdict.errors }), "renderError");
      return reply(res, 400, errorPage.html, { type: HTML_TYPE, csp: withFrameAncestors(errorPage.csp) });
    }
    // Checked again right before the write, and marked used before the write starts: no other submission can be written.
    if (!tokenLive) return sendRefusal(res, refusal(403, TOKEN_REFUSED));
    tokenLive = false;
    const tempFile = path.join(dir, `${path.basename(outputFile)}.${crypto.randomBytes(8).toString("hex")}.tmp`);
    try {
      checkRunDir(dir, harnessRoot);
      writeStableJson(tempFile, verdict.document);
      checkRunFile(outputFile, { harnessRoot });
      if (fs.existsSync(outputFile)) throw new UsageError(`${outputFile} already exists: already answered`);
      // A hard link, not a rename: linkSync fails with EEXIST when the file exists, in one system call, so a file that another
      // process creates after the check above is never replaced. The temporary name is then removed; removeQuietly never throws,
      // so a file that is linked is never reported as a failed write.
      fs.linkSync(tempFile, outputFile);
      removeQuietly(tempFile);
    } catch (error) {
      removeQuietly(tempFile);
      // Nothing was written, so the person may send the form again.
      tokenLive = true;
      const text = `the ${resultKey} could not be written, so the form was not accepted; send it again: ${firstLine(error)}`;
      return sendRefusal(res, refusal(500, text));
    }
    clearTimeout(timer);
    outcome = { code: 0, [resultKey]: verdict.document };
    // The answer goes out first; the server stops when its connection is closed, which is after the answer is flushed.
    res.once("close", () => stop(outcome, { graceful: true }));
    reply(res, 200, donePage.html, { type: HTML_TYPE, csp: doneCsp });
  };

  // The answer to a request whose body is complete: the refusal found from the headers, or the page, or the submission.
  const answer = (res, req, early, body) => {
    if (early !== null) return sendRefusal(res, early);
    if (req.method !== "POST") {
      return reply(res, 200, page.html, { type: HTML_TYPE, csp: pageCsp, head: req.method === "HEAD" });
    }
    return submit(res, body);
  };

  server.on("request", (req, res) => {
    const socket = req.socket;
    const early = refusalOf(req);
    const chunks = [];
    let size = 0;
    let overflowed = false;
    // A client that goes away gets no answer, and nothing else needs to happen.
    req.on("error", () => {});
    req.on("data", (chunk) => {
      if (forced) return;
      size += chunk.length;
      if (!overflowed && size <= maxBodyBytes) {
        chunks.push(chunk);
        return;
      }
      if (!overflowed) {
        // The cap is passed: the answer goes out now, with Connection: close, and the body is not kept.
        overflowed = true;
        chunks.length = 0;
        const verdict = early ?? refusal(413, `the body is larger than ${maxBodyBytes} bytes`);
        sendRefusal(res, verdict, { closeConnection: true });
      }
      if (size > maxBodyBytes + DRAIN_BYTES) socket.destroy();
    });
    req.on("end", () => {
      if (!overflowed && !forced) answer(res, req, early, Buffer.concat(chunks));
    });
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  port = server.address().port;
  server.on("error", (error) => stop({ code: 1, message: `the server failed: ${firstLine(error)}` }));
  timer = setTimeout(() => stop({ code: 4 }), timeoutMs);

  return {
    url: `http://127.0.0.1:${port}${route}?token=${token}`,
    port,
    token,
    done: finished,
    close: () => stop({ code: 1, message: "stopped before a submission" }),
  };
}

// Reads the run folder: layers.json and layer-plan.json must be plain files inside the allowed places, and the plan must pass
// readLayerPlan. The plan is then read as JSON, which is safe because it has just been validated against the layers.
function loadPlan(dir, harnessRoot) {
  for (const name of [LAYERS_FILE, PLAN_FILE]) checkRunFile(path.join(dir, name), { harnessRoot });
  const result = readLayerPlan(dir);
  if (!result.ok) {
    const lines = result.errors.map((item) => (item.pointer === "" ? item.message : `${item.pointer}: ${item.message}`));
    throw new UsageError(`the run folder has no valid layer plan: ${lines.join("; ")}`);
  }
  return JSON.parse(fs.readFileSync(path.join(dir, PLAN_FILE), "utf8"));
}

// The page renderers. They are imported only when a caller does not inject all of them, so the server and its tests can run
// without the page module. defaultPage names the form's page renderer in lib/intake-page.mjs; the done and error pages are the
// same for both forms.
async function loadRenderers({ renderPage, renderDone, renderError }, defaultPage) {
  if (typeof renderPage === "function" && typeof renderDone === "function" && typeof renderError === "function") {
    return { renderPage, renderDone, renderError };
  }
  const pages = await import("./intake-page.mjs");
  return {
    renderPage: renderPage ?? pages[defaultPage],
    renderDone: renderDone ?? pages.renderIntakeDone,
    renderError: renderError ?? pages.renderIntakeError,
  };
}

function checkRendered(result, name) {
  if (result === null || typeof result !== "object" || typeof result.html !== "string" || typeof result.csp !== "string") {
    throw new TypeError(`${name} must return { html, csp } with strings`);
  }
  return result;
}

// The policy of the page, with frame-ancestors added so that no other page can frame the form.
function withFrameAncestors(csp) {
  return `${csp.replace(/;\s*$/, "")}; frame-ancestors 'none'`;
}

// Splits a request target into its path and its query, without a URL parser: a target such as //host/path is a path.
function splitTarget(target) {
  const at = target.indexOf("?");
  return at < 0 ? { pathname: target, query: "" } : { pathname: target.slice(0, at), query: target.slice(at + 1) };
}

// Compares two secrets in constant time. Unequal lengths differ at once, which reveals only the length of the token.
function sameSecret(given, expected) {
  if (typeof given !== "string") return false;
  const a = Buffer.from(given, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isFormType(value) {
  return typeof value === "string" && value.split(";")[0].trim().toLowerCase() === FORM_TYPE;
}

function isDelay(value) {
  return Number.isSafeInteger(value) && value >= 1 && value <= MAX_TIMER_MS;
}

// A refusal: its status, the text of its plain-text answer, and the headers it needs (allow).
function refusal(status, text, options = {}) {
  return { status, text, options };
}

// Sends a refusal. closeConnection asks for Connection: close, so that the connection ends after the answer.
function sendRefusal(res, verdict, { closeConnection = false } = {}) {
  reply(res, verdict.status, `${verdict.text}\n`, { ...verdict.options, closeConnection });
}

// Sends a response with the headers of every answer. HTML answers also get the policy; a HEAD request gets no body.
function reply(res, status, body, { type = TEXT_TYPE, csp, allow, head = false, closeConnection = false } = {}) {
  const headers = {
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body),
    "Content-Type": type,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  };
  if (csp !== undefined) headers["Content-Security-Policy"] = csp;
  if (allow !== undefined) headers.Allow = allow;
  if (closeConnection) headers.Connection = "close";
  res.writeHead(status, headers);
  res.end(head ? undefined : body);
}

// Removes a file that may not exist, and never throws: it is used on the way out of a failed write.
function removeQuietly(file) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    // The temporary file stays; nothing else depends on it.
  }
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}

// A single-choice field: one of the allowed values. A message never repeats the value.
function pickOne(value, field, allowed, report) {
  if (typeof value === "string" && allowed.includes(value)) return value;
  const need = value === undefined ? "is required; it must be" : "must be";
  report(`/${field}`, `${need} one of ${allowed.join(", ")}`);
  return null;
}

// A yes-or-absent field. Absent means no; yes means yes; any other value is an error.
function yesFlag(value, field, report) {
  if (value === undefined) return false;
  if (value === "yes") return true;
  report(`/${field}`, 'must be "yes" when given');
  return false;
}

// The layer indexes of the form, checked against the layers of the plan. Returns the valid indexes in plan order.
function layerIndexes(list, scope, count, report) {
  const values = list === undefined ? [] : list;
  if (!Array.isArray(values)) {
    report("/layer", "must be a list");
    return [];
  }
  if (scope === "all" && values.length > 0) report("/layer", "must not be given with scope all");
  if (scope === "layers" && values.length === 0) report("/layer", "is required with scope layers: choose at least one layer");
  const seen = new Set();
  const indexes = [];
  values.forEach((value, position) => {
    const at = `/layer/${position}`;
    if (typeof value !== "string" || !INDEX_PATTERN.test(value)) {
      report(at, "must be the index of a layer");
      return;
    }
    const index = Number(value);
    if (index >= count) {
      report(at, `is not a layer of the plan, which has ${count}`);
      return;
    }
    if (seen.has(index)) {
      report(at, "is listed twice");
      return;
    }
    seen.add(index);
    indexes.push(index);
  });
  return indexes.sort((a, b) => a - b);
}

// The axes of the form: optional (none chosen means no priority), each one known and listed once. The result follows the
// fixed order of AXES, and is empty when none was chosen.
function axisList(list, report) {
  const values = list === undefined ? [] : list;
  if (!Array.isArray(values)) {
    report("/axis", "must be a list");
    return [];
  }
  const chosen = new Set();
  values.forEach((value, position) => {
    const at = `/axis/${position}`;
    if (!AXES.includes(value)) {
      report(at, `must be one of ${AXES.join(", ")}`);
    } else if (chosen.has(value)) {
      report(at, "is listed twice");
    } else {
      chosen.add(value);
    }
  });
  return AXES.filter((axis) => chosen.has(axis));
}
