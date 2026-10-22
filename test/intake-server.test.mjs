import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { UsageError } from "../scripts/lib/target.mjs";
import {
  AXES,
  DEPTHS,
  INTAKE_SCHEMA_VERSION,
  LANGUAGES,
  parseAnswerForm,
  parseForm,
  QUESTIONS_MAX_BODY_BYTES,
  startIntake,
  startQuestions,
  validateIntake,
} from "../scripts/lib/intake-server.mjs";
import { MAX_ANSWER_LENGTH } from "../scripts/lib/questions.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

// The intake server over real HTTP, on 127.0.0.1, with node:http, so that the Host and Origin headers are the test's choice.
// Every server is closed in t.after. The page renderers are stubs, injected through the options, except in the last test,
// which uses the real page module. The run folders are fixtures in the system temp folder. Every intake.json that a test reads
// is checked against schemas/intake.schema.json at the value level (readIntake).
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "intake.schema.json"), "utf8"));
const FORM_TYPE = "application/x-www-form-urlencoded";
const sorted = (values) => [...values].sort();

// Fixtures ----------------------------------------------------------------------------------------

// Three layers. The plan has no option, and each layer has one folder of layers.json.
const LAYERS = { schemaVersion: 1, folders: [".", "apps", "apps/api", "apps/web", "db"] };
const PLAN = {
  schemaVersion: 1,
  layers: [
    { name: "frontend", folders: ["apps/web"], reason: "package.json in apps/web" },
    { name: "backend", folders: ["apps/api"], reason: "Cargo.toml in apps/api" },
    { name: "database", folders: ["db"], reason: "the folder is named db" },
  ],
};

// A valid form that picks the first and the third layer, and writes the axes in the reverse of their fixed order.
const VALID = [
  ["depth", "standard"],
  ["scope", "layers"],
  ["layer", "0"],
  ["layer", "2"],
  ["axis", "security"],
  ["axis", "instructions"],
  ["language", "en"],
  ["userLayer", "yes"],
];
const VALID_INTAKE = {
  schemaVersion: INTAKE_SCHEMA_VERSION,
  depth: "standard",
  scope: { mode: "layers", layers: ["frontend", "database"] },
  axes: ["instructions", "security"],
  language: "en",
  outsideAccess: { userLayer: true, ancestors: false },
};

function formOf(pairs) {
  return new URLSearchParams(pairs).toString();
}

// The valid form with some pairs removed, or with extra pairs added.
function variant({ drop = [], add = [] } = {}) {
  return formOf([...VALID.filter(([name]) => !drop.includes(name)), ...add]);
}

// Reads an intake.json that a test has written, and checks it against schemas/intake.schema.json at the value level.
function readIntake(file) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(schemaProblems(SCHEMA, value), [], `${file} passes schemas/intake.schema.json`);
  return value;
}

// A run folder with the layers and the plan, in a fixture of the temp folder that is removed at the end of the test.
function makeRun(t, { plan = PLAN, layers = LAYERS } = {}) {
  const fixture = makeFixture({
    files: { "layers.json": JSON.stringify(layers), "layer-plan.json": JSON.stringify(plan) },
  });
  t.after(fixture.cleanup);
  return fixture.root;
}

const stubPage = ({ language, action }) => ({
  html: `<!doctype html><form action="${action}" data-language="${language}"></form>\n`,
  csp: "default-src 'none'; form-action 'self'",
});
const stubDone = ({ language }) => ({
  html: `<!doctype html><p data-language="${language}">done</p>\n`,
  csp: "default-src 'none'",
});
const stubError = ({ language, action, errors }) => ({
  html: `<!doctype html><p data-language="${language}">${errors.map((item) => `${item.pointer}: ${item.message}`).join("\n")}</p><a href="${action}">back</a>\n`,
  csp: "default-src 'none'",
});

// Starts a server on a new run folder. The options are passed to startIntake; the server is closed in t.after.
async function start(t, options = {}) {
  const runDir = makeRun(t, options.run);
  const started = await startIntake({
    runDir,
    harnessRoot: HARNESS_ROOT,
    renderPage: stubPage,
    renderDone: stubDone,
    renderError: stubError,
    timeoutMs: 60_000,
    ...options.start,
  });
  t.after(() => started.close());
  return { ...started, runDir, intakeFile: path.join(runDir, "intake.json") };
}

// Requests ----------------------------------------------------------------------------------------

// One request, on a new connection (agent: false), resolved with the status, the headers and the body as text.
function request(port, { method = "GET", path: target = "/intake", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body, "utf8");
    const allHeaders = payload === undefined ? { ...headers } : { "Content-Length": payload.length, ...headers };
    const req = http.request(
      { host: "127.0.0.1", port, method, path: target, agent: false, headers: allHeaders },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }),
        );
        res.on("error", reject);
      },
    );
    req.setTimeout(15_000, () => req.destroy(new Error("the request timed out")));
    req.on("error", reject);
    req.end(payload);
  });
}

const origin = (port) => `http://127.0.0.1:${port}`;

// A POST of a form to the token address, from this server's origin, unless the test gives other headers.
function postForm(started, body, headers = {}) {
  return request(started.port, {
    method: "POST",
    path: `/intake?token=${started.token}`,
    body,
    headers: { Origin: origin(started.port), "Content-Type": FORM_TYPE, ...headers },
  });
}

// The token address with a GET, from this server's origin.
function getPage(started, headers = {}) {
  return request(started.port, { path: `/intake?token=${started.token}`, headers: { Origin: origin(started.port), ...headers } });
}

// A POST whose body is sent in two parts: the first part now, the rest when finish() is called. The response resolves with the
// status and the text, so that a test can keep one submission in flight while another one completes. The route is /intake unless
// the test gives the questions route.
function openPost(started, body, route = "/intake") {
  const payload = Buffer.from(body, "utf8");
  const cut = Math.floor(payload.length / 2);
  let req;
  const response = new Promise((resolve, reject) => {
    req = http.request(
      {
        host: "127.0.0.1",
        port: started.port,
        method: "POST",
        path: `${route}?token=${started.token}`,
        agent: false,
        headers: { Origin: origin(started.port), "Content-Type": FORM_TYPE, "Content-Length": payload.length },
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.setTimeout(15_000, () => req.destroy(new Error("the request timed out")));
    req.on("error", reject);
  });
  req.write(payload.subarray(0, cut));
  return { response, finish: () => req.end(payload.subarray(cut)) };
}

// A POST whose body may be cut off by the server. Resolves with the status and the connection header when an answer comes, or
// with the error code when the connection ends first: a reset while the body is still being sent is an accepted outcome.
function sendOversized(port, target, body) {
  return new Promise((resolve) => {
    const payload = Buffer.from(body, "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path: target,
        agent: false,
        headers: { Origin: origin(port), "Content-Type": FORM_TYPE, "Content-Length": payload.length },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode, connection: res.headers.connection }));
        res.on("error", (error) => resolve({ closed: true, code: error.code }));
      },
    );
    req.setTimeout(15_000, () => req.destroy(new Error("the request timed out")));
    req.on("error", (error) => resolve({ closed: true, code: error.code }));
    req.end(payload);
  });
}

// The error of a connection to host:port, or null when it connects.
function connectionError(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(null);
    });
    socket.once("error", (error) => resolve(error));
    socket.setTimeout(5_000, () => {
      socket.destroy();
      resolve(new Error("the connection timed out"));
    });
  });
}

// The IPv4 addresses of this machine that are not loopback addresses.
function nonLoopbackAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter((item) => item.family === "IPv4" && !item.internal)
    .map((item) => item.address);
}

// Form parsing and validation (no server) -----------------------------------------------------------

test("parseForm keeps the repeated layer and axis fields as ordered lists, and decodes the form encoding", () => {
  const result = parseForm("depth=quick&scope=layers&layer=2&layer=0&axis=code&axis=security%20x&language=es&ancestors=yes");
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.form, {
    layer: ["2", "0"],
    axis: ["code", "security x"],
    depth: "quick",
    scope: "layers",
    language: "es",
    ancestors: "yes",
  });
  assert.equal(parseForm(Buffer.from("depth=a+b", "utf8")).form.depth, "a b");
});

test("parseForm refuses an unknown field and a single field given twice, and the same form without them passes", () => {
  const unknown = parseForm(`${variant()}&extra=1`);
  assert.equal(unknown.ok, false);
  assert.match(unknown.errors[0].message, /unknown field/);
  assert.equal(unknown.form, null);

  const twice = parseForm(`${variant()}&depth=deep`);
  assert.equal(twice.ok, false);
  assert.deepEqual(twice.errors, [{ pointer: "/depth", message: "is given more than once" }]);

  assert.equal(parseForm(variant()).ok, true, "positive control: the same form without the extra field passes");
});

test("validateIntake accepts a valid form and writes the layers in plan order and the axes in the fixed order", () => {
  const parsed = parseForm(variant());
  const result = validateIntake(parsed.form, PLAN);
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.intake, VALID_INTAKE);

  // Layers given in reverse order come out in plan order; the outside access fields may be absent (no).
  const reversed = validateIntake(
    { depth: "deep", scope: "layers", layer: ["2", "0"], axis: ["code"], language: "en" },
    PLAN,
  );
  assert.equal(reversed.ok, true);
  assert.deepEqual(reversed.intake.scope, { mode: "layers", layers: ["frontend", "database"] });
  assert.deepEqual(reversed.intake.outsideAccess, { userLayer: false, ancestors: false });

  const all = validateIntake({ depth: "quick", scope: "all", axis: AXES, language: "es", ancestors: "yes" }, PLAN);
  assert.equal(all.ok, true);
  assert.deepEqual(all.intake.scope, { mode: "all" });
  assert.deepEqual(all.intake.axes, [...AXES]);
  assert.equal(all.intake.outsideAccess.ancestors, true);
});

test("validateIntake refuses a bad depth, scope, language or outside-access value", () => {
  const base = { depth: "standard", scope: "all", axis: ["code"], language: "en" };
  const cases = [
    [{ ...base, depth: "QUICK" }, "/depth"],
    [{ ...base, depth: undefined }, "/depth"],
    [{ ...base, scope: "some" }, "/scope"],
    [{ ...base, language: "fr" }, "/language"],
    [{ ...base, userLayer: "no" }, "/userLayer"],
    [{ ...base, ancestors: true }, "/ancestors"],
  ];
  for (const [answers, pointer] of cases) {
    const result = validateIntake(answers, PLAN);
    assert.equal(result.ok, false, JSON.stringify(answers));
    assert.ok(result.errors.some((item) => item.pointer === pointer), `${pointer} in ${JSON.stringify(result.errors)}`);
    assert.equal(result.intake, undefined);
  }
  assert.equal(validateIntake(base, PLAN).ok, true, "positive control: the base answers pass");
});

test("validateIntake refuses scope layers with no layer, a layer with scope all, a bad or out-of-range index, and a repeated index", () => {
  const base = { depth: "deep", axis: ["code"], language: "en" };
  const cases = [
    [{ ...base, scope: "layers" }, "/layer"],
    [{ ...base, scope: "all", layer: ["0"] }, "/layer"],
    [{ ...base, scope: "layers", layer: ["3"] }, "/layer/0"],
    [{ ...base, scope: "layers", layer: ["-1"] }, "/layer/0"],
    [{ ...base, scope: "layers", layer: ["01"] }, "/layer/0"],
    [{ ...base, scope: "layers", layer: ["1.0"] }, "/layer/0"],
    [{ ...base, scope: "layers", layer: ["1", "1"] }, "/layer/1"],
  ];
  for (const [answers, pointer] of cases) {
    const result = validateIntake(answers, PLAN);
    assert.equal(result.ok, false, JSON.stringify(answers));
    assert.ok(result.errors.some((item) => item.pointer === pointer), `${pointer} in ${JSON.stringify(result.errors)}`);
  }
  const positive = validateIntake({ ...base, scope: "layers", layer: ["1"] }, PLAN);
  assert.equal(positive.ok, true, "positive control: one valid layer passes");
  assert.deepEqual(positive.intake.scope, { mode: "layers", layers: ["backend"] });
});

test("validateIntake accepts no axis as an empty list, and refuses an unknown axis and a repeated axis", () => {
  const base = { depth: "deep", scope: "all", language: "en" };
  const none = validateIntake({ ...base }, PLAN);
  assert.equal(none.ok, true, "no axis is valid: none chosen means no priority");
  assert.deepEqual(none.intake.axes, []);
  assert.deepEqual(validateIntake({ ...base, axis: [] }, PLAN).intake.axes, []);
  assert.ok(validateIntake({ ...base, axis: ["style"] }, PLAN).errors.some((item) => item.pointer === "/axis/0"));
  assert.ok(validateIntake({ ...base, axis: ["code", "code"] }, PLAN).errors.some((item) => item.pointer === "/axis/1"));
  assert.equal(validateIntake({ ...base, axis: ["code", "security"] }, PLAN).ok, true, "positive control");
});

test("the schema describes the intake that validateIntake writes: required keys, properties and enumerations", () => {
  const sample = validateIntake(parseForm(variant()).form, PLAN).intake;
  assert.equal(SCHEMA.additionalProperties, false);
  assert.deepEqual(sorted(SCHEMA.required), sorted(Object.keys(sample)));
  assert.deepEqual(sorted(Object.keys(SCHEMA.properties)), sorted(Object.keys(sample)));
  assert.equal(SCHEMA.properties.schemaVersion.const, INTAKE_SCHEMA_VERSION);
  assert.deepEqual(SCHEMA.properties.depth.enum, [...DEPTHS]);
  assert.deepEqual(SCHEMA.properties.language.enum, [...LANGUAGES]);
  assert.deepEqual(SCHEMA.properties.axes.items.enum, [...AXES]);
  assert.equal(SCHEMA.properties.axes.minItems, 0, "no axis is valid");
  assert.deepEqual(SCHEMA.properties.scope.oneOf, [{ $ref: "#/$defs/scopeAll" }, { $ref: "#/$defs/scopeLayers" }]);
  assert.equal(SCHEMA.$defs.scopeAll.properties.mode.const, "all");
  assert.equal(SCHEMA.$defs.scopeLayers.properties.mode.const, "layers");
  assert.deepEqual(sorted(SCHEMA.$defs.scopeLayers.required), sorted(Object.keys(sample.scope)));
  assert.deepEqual(sorted(SCHEMA.$defs.outsideAccess.required), sorted(Object.keys(sample.outsideAccess)));
  assert.deepEqual(sorted(Object.keys(SCHEMA.$defs.outsideAccess.properties)), sorted(Object.keys(sample.outsideAccess)));
});

test("the schema checker passes the intakes that validateIntake writes and fails the invalid objects (control)", () => {
  const sample = validateIntake(parseForm(variant()).form, PLAN).intake;
  const valid = [
    sample,
    { ...sample, scope: { mode: "all" }, axes: [] },
    { ...sample, depth: "deep", outsideAccess: { userLayer: false, ancestors: true } },
  ];
  for (const value of valid) assert.deepEqual(schemaProblems(SCHEMA, value), [], JSON.stringify(value));
  const withoutAccess = { ...sample };
  delete withoutAccess.outsideAccess;
  const invalid = {
    "an extra field": { ...sample, extra: 1 },
    "no outsideAccess": withoutAccess,
    "another schema version": { ...sample, schemaVersion: 2 },
    "an unknown depth": { ...sample, depth: "fast" },
    "an unknown axis": { ...sample, axes: ["style"] },
    "a repeated axis": { ...sample, axes: ["code", "code"] },
    "all and layers together": { ...sample, scope: { mode: "all", layers: ["frontend"] } },
    "layers with no layer": { ...sample, scope: { mode: "layers", layers: [] } },
    "a blank layer name": { ...sample, scope: { mode: "layers", layers: [" "] } },
    "a layer name of 81 characters": { ...sample, scope: { mode: "layers", layers: ["x".repeat(81)] } },
    "a non-boolean access flag": { ...sample, outsideAccess: { userLayer: "yes", ancestors: false } },
    "a language outside the list": { ...sample, language: "fr" },
  };
  for (const [name, value] of Object.entries(invalid)) {
    assert.notDeepEqual(schemaProblems(SCHEMA, value), [], name);
  }
});

// Startup -----------------------------------------------------------------------------------------

test("startIntake refuses a folder outside runs/ and the temp folder, a file, and a run folder without a valid plan", async (t) => {
  const runDir = makeRun(t);
  const noPlan = makeFixture({ files: { "layers.json": JSON.stringify(LAYERS) } });
  t.after(noPlan.cleanup);
  const badPlan = makeFixture({
    files: {
      "layers.json": JSON.stringify(LAYERS),
      "layer-plan.json": JSON.stringify({ schemaVersion: 1, layers: [{ name: "x", folders: ["nope"], reason: "r" }] }),
    },
  });
  t.after(badPlan.cleanup);
  const cases = [
    [path.join(HARNESS_ROOT, "scripts"), /must be inside/],
    [path.join(runDir, "layers.json"), /not a folder/],
    [noPlan.root, /layer-plan\.json: cannot be read: ENOENT/],
    [badPlan.root, /is not a folder of layers\.json/],
  ];
  for (const [dir, pattern] of cases) {
    await assert.rejects(
      startIntake({ runDir: dir, harnessRoot: HARNESS_ROOT, renderPage: stubPage, renderDone: stubDone, renderError: stubError }),
      (error) => error instanceof UsageError && pattern.test(error.message),
      dir,
    );
  }
  const started = await start(t);
  assert.match(started.url, /^http:\/\/127\.0\.0\.1:\d+\/intake\?token=[A-Za-z0-9_-]+$/, "positive control: a valid run starts");
});

test("a run folder that already holds an intake.json is refused, and the file is left as it is", async (t) => {
  const runDir = makeRun(t);
  const file = path.join(runDir, "intake.json");
  fs.writeFileSync(file, "previous\n");
  const options = { runDir, harnessRoot: HARNESS_ROOT, renderPage: stubPage, renderDone: stubDone, renderError: stubError, timeoutMs: 60_000 };
  await assert.rejects(
    startIntake(options),
    (error) => error instanceof UsageError && /already answered; remove it to ask again/.test(error.message),
  );
  assert.equal(fs.readFileSync(file, "utf8"), "previous\n", "the file is left as it is");
  fs.rmSync(file);
  const started = await startIntake(options);
  t.after(() => started.close());
  assert.equal((await postForm(started, variant())).status, 200, "positive control: once the file is removed, the run is answered");
  assert.equal((await started.done).code, 0);
});

test("the server listens on 127.0.0.1 only: the loopback address answers and other addresses refuse", async (t) => {
  const started = await start(t);
  assert.equal(await connectionError("127.0.0.1", started.port), null, "positive control: 127.0.0.1 connects");
  assert.equal((await getPage(started)).status, 200);
  const refused = ["::1", ...nonLoopbackAddresses()];
  for (const address of refused) {
    assert.notEqual(await connectionError(address, started.port), null, `${address} must refuse the connection`);
  }
});

// Requests ----------------------------------------------------------------------------------------

test("GET with the token gets the page, with the security headers and the policy of the page", async (t) => {
  const started = await start(t);
  const response = await getPage(started);
  assert.equal(response.status, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assert.equal(response.headers["content-security-policy"], "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(response.headers["x-content-type-options"], "nosniff");
  assert.equal(response.headers["referrer-policy"], "no-referrer");
  assert.ok(response.text.includes(`/intake?token=${started.token}`), "the form posts to the token address");
});

test("a request without the token, with a wrong or repeated token, or with another query parameter gets 403", async (t) => {
  const started = await start(t);
  const wrong = "A".repeat(43);
  const refused = [
    "/intake",
    "/intake?token=",
    `/intake?token=${wrong}`,
    `/intake?token=${started.token}&token=${started.token}`,
    `/intake?token=${started.token}&x=1`,
    `/intake?x=1&token=${started.token}`,
    `/intake?token=${started.token.slice(0, -1)}`,
  ];
  for (const target of refused) {
    const response = await request(started.port, { path: target, headers: { Origin: origin(started.port) } });
    assert.equal(response.status, 403, target);
    assert.equal(response.headers["content-type"], "text/plain; charset=utf-8");
    assert.equal(response.text.includes(started.token), false, "the answer does not repeat the token");
  }
  assert.equal((await getPage(started)).status, 200, "positive control: the right token gets the page");
});

test("a request with another Host gets 403, and the right Host passes", async (t) => {
  const started = await start(t);
  const target = `/intake?token=${started.token}`;
  for (const host of [`localhost:${started.port}`, "evil.example", `127.0.0.1`, `127.0.0.1:${started.port + 1}`]) {
    const response = await request(started.port, { path: target, headers: { Host: host } });
    assert.equal(response.status, 403, host);
  }
  const posted = await request(started.port, {
    method: "POST",
    path: target,
    body: variant(),
    headers: { Host: "evil.example", Origin: origin(started.port), "Content-Type": FORM_TYPE },
  });
  assert.equal(posted.status, 403, "a POST with a foreign Host is refused too");
  assert.equal((await getPage(started)).status, 200, "positive control: the right Host passes");
});

test("a request with a foreign Origin gets 403, and a POST without an Origin gets 403; the right Origin passes", async (t) => {
  const started = await start(t);
  for (const value of [`http://localhost:${started.port}`, "https://evil.example", "null"]) {
    assert.equal((await getPage(started, { Origin: value })).status, 403, value);
    assert.equal((await postForm(started, variant(), { Origin: value })).status, 403, `POST ${value}`);
  }
  const noOrigin = await request(started.port, {
    method: "POST",
    path: `/intake?token=${started.token}`,
    body: variant(),
    headers: { "Content-Type": FORM_TYPE },
  });
  assert.equal(noOrigin.status, 403, "a POST without Origin");
  const accepted = await postForm(started, variant());
  assert.equal(accepted.status, 200, "positive control: the right Origin passes");
});

test("another path gets 404, and another method gets 405 with the methods allowed", async (t) => {
  const started = await start(t);
  for (const target of ["/", `/intake/?token=${started.token}`, `/other?token=${started.token}`, `/INTAKE?token=${started.token}`]) {
    assert.equal((await request(started.port, { path: target })).status, 404, target);
  }
  for (const method of ["PUT", "DELETE", "OPTIONS"]) {
    const response = await request(started.port, {
      method,
      path: `/intake?token=${started.token}`,
      body: method === "PUT" ? variant() : undefined,
      headers: method === "PUT" ? { "Content-Type": FORM_TYPE } : {},
    });
    assert.equal(response.status, 405, method);
    assert.equal(response.headers.allow, "GET, HEAD, POST");
  }
  assert.equal((await getPage(started)).status, 200, "positive control: GET passes");
});

test("HEAD with the token gets the headers of the page and no body", async (t) => {
  const started = await start(t);
  const response = await request(started.port, { method: "HEAD", path: `/intake?token=${started.token}` });
  assert.equal(response.status, 200);
  assert.equal(response.text, "");
  assert.equal(response.headers["content-security-policy"], "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
});

test("a POST whose body is not a form gets 415, and the form type with parameters passes", async (t) => {
  const started = await start(t);
  for (const type of [undefined, "text/plain", "application/json", "multipart/form-data; boundary=x"]) {
    const headers = type === undefined ? {} : { "Content-Type": type };
    const response = await request(started.port, {
      method: "POST",
      path: `/intake?token=${started.token}`,
      body: variant(),
      headers: { Origin: origin(started.port), ...headers },
    });
    assert.equal(response.status, 415, String(type));
  }
  const accepted = await postForm(started, variant(), { "Content-Type": `${FORM_TYPE}; charset=UTF-8` });
  assert.equal(accepted.status, 200, "positive control: the form type with a charset passes");
});

test("a body over the cap gets 413 and nothing is written; a body of exactly the cap passes", async (t) => {
  const body = variant();
  const size = Buffer.byteLength(body);
  const over = await start(t, { start: { maxBodyBytes: size - 1 } });
  const refused = await postForm(over, body);
  assert.equal(refused.status, 413);
  assert.equal(refused.headers.connection, "close", "the connection is closed after the 413");
  assert.equal(fs.existsSync(over.intakeFile), false, "nothing is written for a body over the cap");

  const exact = await start(t, { start: { maxBodyBytes: size } });
  const accepted = await postForm(exact, body);
  assert.equal(accepted.status, 200, "positive control: a body of exactly the cap is accepted");
  assert.equal(fs.existsSync(exact.intakeFile), true);
});

test("a body far larger than the cap is cut off: 413 or a closed connection, quickly, nothing written, and the server still answers", async (t) => {
  const started = await start(t, { start: { maxBodyBytes: 1024 } });
  const huge = `${variant()}&pad=${"x".repeat(1024 * 1024)}`;
  const began = Date.now();
  const refused = await sendOversized(started.port, `/intake?token=${started.token}`, huge);
  assert.ok(refused.status === 413 || ["ECONNRESET", "EPIPE"].includes(refused.code), JSON.stringify(refused));
  if (refused.status === 413) assert.equal(refused.connection, "close", "the connection is closed after the 413");
  const wrongToken = await sendOversized(started.port, `/intake?token=${"C".repeat(43)}`, huge);
  assert.ok(
    wrongToken.status === 403 || ["ECONNRESET", "EPIPE"].includes(wrongToken.code),
    `the token is checked before the body is read on: ${JSON.stringify(wrongToken)}`,
  );
  assert.ok(Date.now() - began < 10_000, "the oversized bodies are answered or cut off quickly");
  assert.equal(fs.existsSync(started.intakeFile), false, "nothing is written");
  assert.equal((await getPage(started)).status, 200, "positive control: a normal request is still answered");
  assert.equal((await postForm(started, variant())).status, 200, "positive control: a normal form is still accepted");
  assert.equal((await started.done).code, 0);
});

test("a default form with no axis is accepted and writes an empty axes list", async (t) => {
  const started = await start(t);
  const response = await postForm(started, variant({ drop: ["axis"] }));
  assert.equal(response.status, 200);
  assert.equal((await started.done).code, 0);
  assert.deepEqual(readIntake(started.intakeFile).axes, []);
});

test("an invalid form gets the HTML page of its errors, with status 400, and nothing is written; the next valid form is accepted", async (t) => {
  const started = await start(t);
  const invalid = [
    [variant({ drop: ["layer"] }), "/layer"],
    [formOf([["depth", "quick"], ["scope", "all"], ["layer", "1"], ["axis", "code"], ["language", "en"]]), "/layer"],
    [variant({ add: [["layer", "3"]] }), "/layer/2"],
    [variant({ drop: ["depth"], add: [["depth", "fast"]] }), "/depth"],
    [variant({ add: [["extra", "1"]] }), "unknown field"],
    [variant({ add: [["depth", "deep"]] }), "/depth"],
    [formOf([["scope", "all"], ["axis", "code"], ["language", "en"]]), "/depth"],
  ];
  for (const [body, expected] of invalid) {
    const response = await postForm(started, body);
    assert.equal(response.status, 400, body);
    assert.equal(response.headers["content-type"], "text/html; charset=utf-8", body);
    assert.match(response.headers["content-security-policy"], /frame-ancestors 'none'/, body);
    assert.ok(response.text.includes(expected), `${expected} in the page for ${body}`);
    assert.ok(response.text.includes(`href="/intake?token=${started.token}"`), "a link back to the form");
    assert.equal(fs.existsSync(started.intakeFile), false, `nothing is written for ${body}`);
  }
  const accepted = await postForm(started, variant());
  assert.equal(accepted.status, 200, "the server still answers and accepts the corrected form");
  assert.equal(readIntake(started.intakeFile).depth, "standard");
});

test("a valid submission writes intake.json, answers the done page, stops the server and resolves done with 0", async (t) => {
  const started = await start(t);
  const response = await postForm(started, variant());
  assert.equal(response.status, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assert.ok(response.text.includes("done"), "the answer is the done page");
  const result = await started.done;
  assert.equal(result.code, 0);
  assert.deepEqual(result.intake, VALID_INTAKE);
  assert.deepEqual(readIntake(started.intakeFile), VALID_INTAKE);
  assert.equal(fs.readFileSync(started.intakeFile, "utf8").endsWith("\n"), true, "the file is written with writeStableJson");
  assert.deepEqual(fs.readdirSync(started.runDir).sort(), ["intake.json", "layer-plan.json", "layers.json"], "no temporary file is left");
  await assert.rejects(getPage(started), (error) => error.code === "ECONNREFUSED", "the server is closed, so the token is dead");
});

test("when intake.json cannot be written, the answer is 500, no temporary file is left, the server keeps running, and the next valid form is written", async (t) => {
  const started = await start(t);
  fs.mkdirSync(started.intakeFile);
  const failed = await postForm(started, variant());
  assert.equal(failed.status, 500);
  assert.deepEqual(fs.readdirSync(started.runDir).filter((name) => name.endsWith(".tmp")), [], "the temporary file is removed");
  fs.rmdirSync(started.intakeFile);
  const accepted = await postForm(started, variant());
  assert.equal(accepted.status, 200, "positive control: once the file can be written, the form is accepted");
  assert.equal((await started.done).code, 0);
  assert.deepEqual(readIntake(started.intakeFile), VALID_INTAKE);
});

test("two valid submissions in flight at once: one is written and answered 200, the other is refused with 403", async (t) => {
  const started = await start(t);
  // The first submission stays open: its body is only half sent when the second one is accepted and written.
  const late = openPost(started, formOf([["depth", "quick"], ["scope", "all"], ["axis", "code"], ["language", "en"]]));
  const first = await postForm(started, variant());
  assert.equal(first.status, 200, "the submission that completes first is written");
  late.finish();
  const second = await late.response;
  assert.equal(second.status, 403, "the submission still in flight is refused, not written");
  assert.equal((await started.done).code, 0, "done resolves once, with 0");
  assert.equal(readIntake(started.intakeFile).depth, "standard", "intake.json holds the one that was written");
});

test("the timeout stops the server with code 4 and writes nothing", async (t) => {
  const started = await start(t, { start: { timeoutMs: 50 } });
  const result = await started.done;
  assert.equal(result.code, 4);
  assert.equal(fs.existsSync(started.intakeFile), false);
  await assert.rejects(getPage(started), (error) => error.code === "ECONNREFUSED");
});

test("close() stops the server before a submission with code 1; calling it again resolves too", async (t) => {
  const started = await start(t);
  const first = started.close();
  const second = started.close();
  await Promise.all([first, second]);
  const result = await started.done;
  assert.equal(result.code, 1);
  assert.match(result.message, /before a submission/);
  assert.equal(fs.existsSync(started.intakeFile), false);
  await assert.rejects(getPage(started), (error) => error.code === "ECONNREFUSED");
});

test("the real page module renders the form, the page of an invalid form and the done page", async (t) => {
  const runDir = makeRun(t);
  const started = await startIntake({ runDir, harnessRoot: HARNESS_ROOT, language: "es", timeoutMs: 60_000 });
  t.after(() => started.close());
  const page = await getPage(started);
  assert.equal(page.status, 200);
  assert.match(page.headers["content-type"], /^text\/html/);
  assert.match(page.headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.ok(page.text.includes(`/intake?token=${started.token}`), "the form posts to the token address");
  assert.ok(page.text.includes('name="language" value="es" checked'), "the report language follows the page language");
  const invalid = await postForm(started, variant({ add: [["depth", "deep"]] }));
  assert.equal(invalid.status, 400);
  assert.ok(invalid.text.includes("El formulario no se aceptó"), "the error page is in the page language");
  const done = await postForm(started, variant());
  assert.equal(done.status, 200);
  assert.match(done.headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.equal((await started.done).code, 0);
  assert.deepEqual(readIntake(path.join(runDir, "intake.json")), VALID_INTAKE);
});

// The questions form (startQuestions) ---------------------------------------------------------------
// The same HTTP core as the intake form, so these tests check what differs: the route, the questions and their answers, the
// output file (answers.json, never intake.json), and the checks before the server listens. The pages are the stubs above, except
// in the last test.

const QUESTIONS_SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "questions.schema.json"), "utf8"));
const ANSWERS_SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "answers.schema.json"), "utf8"));

// A questions.json with one question of each type. Its texts hold no folder of this machine, so redaction changes nothing.
const QUESTIONS_DOC = {
  schemaVersion: 1,
  questions: [
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
  ],
};

// A valid answer. The folders are sent admin first: the answer keeps the order of the question, so web comes first.
const ANSWER_PAIRS = [
  ["q-contradiction", "keep-claude"],
  ["q-folders", "admin"],
  ["q-folders", "web"],
  ["q-generated", "Yes, it is generated."],
];
const VALID_ANSWERS = formOf(ANSWER_PAIRS);
const EXPECTED_ANSWERS = {
  schemaVersion: 1,
  answers: [
    {
      id: "contradiction",
      type: "single",
      question: "Which instruction file is right?",
      why: "CLAUDE.md and AGENTS.md give opposite test commands.",
      source: { file: "CLAUDE.md", line: 3 },
      selected: [{ id: "keep-claude", label: "Keep CLAUDE.md" }],
    },
    {
      id: "folders",
      type: "multi",
      question: "Which folders hold the frontend?",
      why: "The manifests do not say.",
      source: { file: "apps/web/package.json", line: 1 },
      selected: [
        { id: "web", label: "apps/web" },
        { id: "admin", label: "apps/admin" },
      ],
    },
    {
      id: "generated",
      type: "text",
      question: "Is this file generated?",
      why: "It has no generator marker.",
      source: { file: "src/gen.ts", line: 1 },
      value: "Yes, it is generated.",
    },
  ],
};

// A run folder with the given files (questions.json by default), in a fixture of the temp folder removed at the end of the test.
function makeQuestionsRun(t, files = { "questions.json": JSON.stringify(QUESTIONS_DOC) }) {
  const fixture = makeFixture({ files });
  t.after(fixture.cleanup);
  return fixture.root;
}

// Starts the questions server on a new run folder, with the stub pages. The server is closed in t.after.
async function startQuestionsRun(t, { files, maxBodyBytes, timeoutMs = 60_000 } = {}) {
  const runDir = makeQuestionsRun(t, files);
  const options = { runDir, harnessRoot: HARNESS_ROOT, renderPage: stubPage, renderDone: stubDone, renderError: stubError, timeoutMs };
  if (maxBodyBytes !== undefined) options.maxBodyBytes = maxBodyBytes;
  const started = await startQuestions(options);
  t.after(() => started.close());
  return { ...started, runDir, answersFile: path.join(runDir, "answers.json") };
}

// The questions page, with a GET of the token address, from this server's origin.
function getQuestions(started, headers = {}) {
  return request(started.port, { path: `/questions?token=${started.token}`, headers: { Origin: origin(started.port), ...headers } });
}

// A POST of the answers to the token address, from this server's origin, unless the test gives other headers.
function postAnswers(started, body, headers = {}) {
  return request(started.port, {
    method: "POST",
    path: `/questions?token=${started.token}`,
    body,
    headers: { Origin: origin(started.port), "Content-Type": FORM_TYPE, ...headers },
  });
}

// Reads an answers.json that a test has written, and checks it against schemas/answers.schema.json at the value level.
function readAnswers(file) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(schemaProblems(ANSWERS_SCHEMA, value), [], `${file} passes schemas/answers.schema.json`);
  return value;
}

test("parseAnswerForm keeps the repeated names in order, and leaves the names to validateAnswers", () => {
  const form = parseAnswerForm("q-folders=admin&q-folders=web&q-generated=a+b&unknown=1");
  assert.ok(form instanceof Map);
  assert.deepEqual([...form.entries()], [
    ["q-folders", ["admin", "web"]],
    ["q-generated", ["a b"]],
    ["unknown", ["1"]],
  ]);
  assert.deepEqual([...parseAnswerForm(Buffer.from("q-x=1", "utf8")).keys()], ["q-x"]);
  assert.throws(() => parseAnswerForm(42), TypeError);
});

test("parseAnswerForm reads the bytes strictly: a name or a value that is not UTF-8 gives null, and a valid form reads as URLSearchParams reads it", () => {
  assert.equal(parseAnswerForm("q-x=%E9"), null, "a percent-encoded byte that is not UTF-8");
  assert.equal(parseAnswerForm(Buffer.from([0x71, 0x2d, 0x78, 0x3d, 0xe9])), null, "a raw byte that is not UTF-8");
  assert.equal(parseAnswerForm("%E9=1"), null, "a name that is not UTF-8");
  assert.equal(parseAnswerForm("q-x=%C3%A9").get("q-x")[0], "é", "positive control: the UTF-8 bytes of e-acute are read");
  const valid = "q-a=one+two&q-b=%2B%26&&q-c=100%&q-d=%zz&q-e=%EF%BB%BFbom&q-f=%F0%9F%98%80&q-g";
  const strict = parseAnswerForm(valid);
  const expected = new Map();
  for (const [name, value] of new URLSearchParams(valid)) expected.set(name, [...(expected.get(name) ?? []), value]);
  assert.deepEqual([...strict.entries()], [...expected.entries()]);
  assert.equal(strict.get("q-b")[0], "+&", "an escaped plus and ampersand");
  assert.equal(strict.get("q-e")[0], "﻿bom", "a byte order mark is kept, as URLSearchParams keeps it");
});

test("the questions and answers documents of the tests pass their schemas, and a question with an extra field fails", () => {
  assert.deepEqual(schemaProblems(QUESTIONS_SCHEMA, QUESTIONS_DOC), [], "positive control: the fixture is valid");
  assert.deepEqual(schemaProblems(ANSWERS_SCHEMA, EXPECTED_ANSWERS), [], "positive control: the expected answers are valid");
  const broken = { schemaVersion: 1, questions: [{ ...QUESTIONS_DOC.questions[2], extra: true }] };
  assert.notDeepEqual(schemaProblems(QUESTIONS_SCHEMA, broken), [], "a question with an extra field fails");
});

test("startQuestions refuses a missing or invalid questions.json, more than five questions, and an answered run, and starts no server", async (t) => {
  const six = {
    schemaVersion: 1,
    questions: Array.from({ length: 6 }, (_, index) => ({
      id: `text-${index}`,
      type: "text",
      text: "A question",
      why: "A reason",
      source: { file: "README.md", line: 1 },
    })),
  };
  const cases = [
    [{}, /questions\.json is missing/],
    [{ "questions.json": "{" }, /questions\.json is not valid JSON/],
    [{ "questions.json": JSON.stringify(six) }, /holds 6 questions; the most is 5/],
    [{ "questions.json": JSON.stringify(QUESTIONS_DOC), "answers.json": "previous\n" }, /already answered; remove it to ask again/],
  ];
  for (const [files, pattern] of cases) {
    const runDir = makeQuestionsRun(t, files);
    await assert.rejects(
      startQuestions({ runDir, harnessRoot: HARNESS_ROOT, renderPage: stubPage, renderDone: stubDone, renderError: stubError }),
      (error) => error instanceof UsageError && pattern.test(error.message),
      pattern.source,
    );
    // Only the answered run has an answers.json, and it is left as it is.
    const answers = path.join(runDir, "answers.json");
    assert.equal(fs.existsSync(answers), "answers.json" in files, `answers.json is not written for ${pattern.source}`);
  }
  // Positive control: the valid run starts, and it needs no layer plan.
  const started = await startQuestionsRun(t);
  assert.match(started.url, /^http:\/\/127\.0\.0\.1:\d+\/questions\?token=[A-Za-z0-9_-]+$/);
  assert.equal(fs.existsSync(path.join(started.runDir, "layer-plan.json")), false, "no layer plan is needed");
});

test("the questions form is served at /questions only: another path gets 404, another method 405, and GET gets the page", async (t) => {
  const started = await startQuestionsRun(t);
  for (const target of ["/", "/intake", `/intake?token=${started.token}`, `/questions/?token=${started.token}`]) {
    assert.equal((await request(started.port, { path: target })).status, 404, target);
  }
  for (const method of ["PUT", "DELETE", "OPTIONS"]) {
    const response = await request(started.port, {
      method,
      path: `/questions?token=${started.token}`,
      body: method === "PUT" ? VALID_ANSWERS : undefined,
      headers: method === "PUT" ? { "Content-Type": FORM_TYPE } : {},
    });
    assert.equal(response.status, 405, method);
    assert.equal(response.headers.allow, "GET, HEAD, POST");
  }
  const page = await getQuestions(started);
  assert.equal(page.status, 200, "positive control: the page is served at the route");
  assert.equal(page.headers["content-security-policy"], "default-src 'none'; form-action 'self'; frame-ancestors 'none'");
});

test("an invalid token gets 403 on the page and on the form, nothing is written, and the right token still works", async (t) => {
  const started = await startQuestionsRun(t);
  const wrong = `/questions?token=${"B".repeat(43)}`;
  assert.equal((await request(started.port, { path: wrong, headers: { Origin: origin(started.port) } })).status, 403);
  const posted = await request(started.port, {
    method: "POST",
    path: wrong,
    body: VALID_ANSWERS,
    headers: { Origin: origin(started.port), "Content-Type": FORM_TYPE },
  });
  assert.equal(posted.status, 403);
  assert.equal(fs.existsSync(started.answersFile), false, "a refused request writes nothing");
  assert.equal((await getQuestions(started)).status, 200, "positive control: the right token gets the page");
});

test("a wrong Host or a wrong Origin gets 403, nothing is written, and the right Host and Origin pass", async (t) => {
  const started = await startQuestionsRun(t);
  const target = `/questions?token=${started.token}`;
  for (const host of [`localhost:${started.port}`, "evil.example"]) {
    assert.equal((await request(started.port, { path: target, headers: { Host: host } })).status, 403, host);
  }
  const foreignHost = await request(started.port, {
    method: "POST",
    path: target,
    body: VALID_ANSWERS,
    headers: { Host: "evil.example", Origin: origin(started.port), "Content-Type": FORM_TYPE },
  });
  assert.equal(foreignHost.status, 403, "a POST with a foreign Host is refused too");
  for (const value of [`http://localhost:${started.port}`, "https://evil.example", "null"]) {
    assert.equal((await postAnswers(started, VALID_ANSWERS, { Origin: value })).status, 403, value);
  }
  assert.equal(fs.existsSync(started.answersFile), false, "nothing is written");
  assert.equal((await postAnswers(started, VALID_ANSWERS)).status, 200, "positive control: the right Host and Origin are accepted");
});

test("a body over the cap gets 413 and nothing is written; a body of exactly the cap is accepted", async (t) => {
  const size = Buffer.byteLength(VALID_ANSWERS);
  const over = await startQuestionsRun(t, { maxBodyBytes: size - 1 });
  const refused = await postAnswers(over, VALID_ANSWERS);
  assert.equal(refused.status, 413);
  assert.equal(refused.headers.connection, "close", "the connection is closed after the 413");
  assert.equal(fs.existsSync(over.answersFile), false, "nothing is written for a body over the cap");

  const exact = await startQuestionsRun(t, { maxBodyBytes: size });
  assert.equal((await postAnswers(exact, VALID_ANSWERS)).status, 200, "positive control: a body of exactly the cap is accepted");
  assert.equal(fs.existsSync(exact.answersFile), true);
});

test("an invalid form gets the error page with 400 and nothing is written, and the server keeps waiting for a valid one", async (t) => {
  const started = await startQuestionsRun(t);
  const invalid = [
    [formOf([["q-contradiction", "keep-nothing"], ["q-folders", "web"]]), "/q-contradiction: is not an option of this question"],
    [formOf([["q-folders", "web"], ["q-generated", "x"]]), "/q-contradiction: needs an answer: choose one option"],
    [formOf([...ANSWER_PAIRS, ["q-extra", "1"]]), "/q-extra: unknown field: no question has this id"],
    [formOf([...ANSWER_PAIRS.filter(([name]) => name !== "q-generated"), ["q-generated", "x".repeat(MAX_ANSWER_LENGTH + 1)]]), `/q-generated: is longer than ${MAX_ANSWER_LENGTH} characters`],
  ];
  for (const [body, expected] of invalid) {
    const response = await postAnswers(started, body);
    assert.equal(response.status, 400, body.slice(0, 80));
    assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
    assert.ok(response.text.includes(expected), `${expected} in the page`);
    assert.ok(response.text.includes(`href="/questions?token=${started.token}"`), "a link back to the form");
    assert.equal(fs.existsSync(started.answersFile), false, "nothing is written");
    assert.equal(fs.existsSync(path.join(started.runDir, "intake.json")), false, "intake.json is never written");
  }
  const accepted = await postAnswers(started, VALID_ANSWERS);
  assert.equal(accepted.status, 200, "positive control: the server still answers and accepts the corrected form");
  assert.equal((await started.done).code, 0);
  assert.deepEqual(readAnswers(started.answersFile), EXPECTED_ANSWERS);
});

test("a valid form writes answers.json with the expected content, answers the done page, stops, and writes no intake.json", async (t) => {
  const started = await startQuestionsRun(t);
  const response = await postAnswers(started, VALID_ANSWERS);
  assert.equal(response.status, 200);
  assert.equal(response.headers["content-type"], "text/html; charset=utf-8");
  assert.ok(response.text.includes("done"), "the answer is the done page");
  const result = await started.done;
  assert.equal(result.code, 0);
  assert.deepEqual(result.answers, EXPECTED_ANSWERS);
  assert.deepEqual(readAnswers(started.answersFile), EXPECTED_ANSWERS);
  assert.equal(fs.readFileSync(started.answersFile, "utf8").endsWith("\n"), true, "the file is written with writeStableJson");
  assert.deepEqual(fs.readdirSync(started.runDir).sort(), ["answers.json", "questions.json"], "no temporary file and no intake.json");
  await assert.rejects(getQuestions(started), (error) => error.code === "ECONNREFUSED", "the server is closed, so the token is dead");
});

test("the timeout stops the questions server with code 4 and writes nothing; a longer wait for the same form is answered", async (t) => {
  const timed = await startQuestionsRun(t, { timeoutMs: 50 });
  const result = await timed.done;
  assert.equal(result.code, 4);
  assert.equal(fs.existsSync(timed.answersFile), false, "nothing is written");
  await assert.rejects(getQuestions(timed), (error) => error.code === "ECONNREFUSED");

  const waiting = await startQuestionsRun(t, { timeoutMs: 60_000 });
  assert.equal((await postAnswers(waiting, VALID_ANSWERS)).status, 200, "positive control: the same form is answered in time");
  assert.equal((await waiting.done).code, 0);
});

test("the real questions page renders the questions, and an invalid answer gets its error page in the page language", async (t) => {
  const runDir = makeQuestionsRun(t);
  const started = await startQuestions({ runDir, harnessRoot: HARNESS_ROOT, language: "es", timeoutMs: 60_000 });
  t.after(() => started.close());
  const page = await getQuestions(started);
  assert.equal(page.status, 200);
  assert.match(page.headers["content-type"], /^text\/html/);
  assert.match(page.headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.ok(page.text.includes(`/questions?token=${started.token}`), "the form posts to the token address");
  assert.ok(page.text.includes('name="q-contradiction" value="keep-claude" required'), "a single question is required radio buttons");
  assert.ok(page.text.includes("Elige una opción."), "the hint is in the page language");
  const invalid = await postAnswers(started, formOf([["q-folders", "web"]]));
  assert.equal(invalid.status, 400);
  assert.ok(invalid.text.includes("El formulario no se aceptó"), "the error page is in the page language");
  const done = await postAnswers(started, VALID_ANSWERS);
  assert.equal(done.status, 200);
  assert.match(done.headers["content-security-policy"], /frame-ancestors 'none'/);
  assert.equal((await started.done).code, 0);
  assert.deepEqual(readAnswers(path.join(runDir, "answers.json")), EXPECTED_ANSWERS);
});

// The questions form, the rest of it: the body cap, the UTF-8 check, the content type, the repeated fields, the exclusive write,
// the submissions in flight at once, and the redaction of the written answers ----------------------------------------------

// Five written questions, the most a form asks, and the largest answers they take: MAX_ANSWER_LENGTH characters of four bytes each,
// which the browser sends as twelve bytes a character. The default cap of the form must accept them.
const FIVE_TEXT_FILES = {
  "questions.json": JSON.stringify({
    schemaVersion: 1,
    questions: Array.from({ length: 5 }, (_, index) => ({
      id: `text-${index}`,
      type: "text",
      text: "A question",
      why: "A reason",
      source: { file: "README.md", line: index + 1 },
    })),
  }),
};
const FOUR_BYTE_CHARACTER = "\u{1F600}";
const LARGEST_ANSWERS = formOf(Array.from({ length: 5 }, (_, index) => [`q-text-${index}`, FOUR_BYTE_CHARACTER.repeat(MAX_ANSWER_LENGTH)]));

test("five written answers of the largest size are accepted by the default cap, and answers.json holds them", async (t) => {
  assert.equal(QUESTIONS_MAX_BODY_BYTES, 131_072, "2^17 bytes, the power of two above the question caps");
  assert.ok(Buffer.byteLength(LARGEST_ANSWERS) < QUESTIONS_MAX_BODY_BYTES, "the largest form fits the cap");
  const started = await startQuestionsRun(t, { files: FIVE_TEXT_FILES });
  const response = await postAnswers(started, LARGEST_ANSWERS);
  assert.equal(response.status, 200, `positive control: ${response.text.slice(0, 200)}`);
  assert.equal((await started.done).code, 0);
  const written = readAnswers(started.answersFile);
  assert.equal(written.answers.length, 5);
  for (const answer of written.answers) assert.equal([...answer.value].length, MAX_ANSWER_LENGTH);
});

test("one written answer of 2001 characters gets 400 that names its field, not 413, and the largest form is accepted after it", async (t) => {
  const started = await startQuestionsRun(t, { files: FIVE_TEXT_FILES });
  const pairs = Array.from({ length: 5 }, (_, index) => [`q-text-${index}`, FOUR_BYTE_CHARACTER.repeat(MAX_ANSWER_LENGTH)]);
  pairs[0][1] = FOUR_BYTE_CHARACTER.repeat(MAX_ANSWER_LENGTH + 1);
  const refused = await postAnswers(started, formOf(pairs));
  assert.equal(refused.status, 400, "the check refuses the answer, the cap does not");
  assert.ok(refused.text.includes("/q-text-0: is longer than 2000 characters"), refused.text);
  assert.equal(fs.existsSync(started.answersFile), false, "nothing is written");
  const accepted = await postAnswers(started, LARGEST_ANSWERS);
  assert.equal(accepted.status, 200, "positive control: the form with answers of the right length is accepted");
});

test("a body of exactly the default cap is accepted, and a body one byte larger gets 413 with nothing written", async (t) => {
  const started = await startQuestionsRun(t, { files: FIVE_TEXT_FILES });
  // Empty pairs are ignored by the form, and each "&" is one byte of the body.
  const size = Buffer.byteLength(LARGEST_ANSWERS);
  const over = await postAnswers(started, `${LARGEST_ANSWERS}${"&".repeat(QUESTIONS_MAX_BODY_BYTES + 1 - size)}`);
  assert.equal(over.status, 413);
  assert.equal(over.headers.connection, "close", "the connection is closed after the 413");
  assert.equal(fs.existsSync(started.answersFile), false, "nothing is written for a body over the cap");
  const exact = await postAnswers(started, `${LARGEST_ANSWERS}${"&".repeat(QUESTIONS_MAX_BODY_BYTES - size)}`);
  assert.equal(exact.status, 200, "positive control: a body of exactly the cap is accepted");
  assert.equal(fs.existsSync(started.answersFile), true);
});

test("a questions form whose value is not valid UTF-8 gets 400 with nothing written, and the server keeps waiting; the same character as UTF-8 is accepted", async (t) => {
  const started = await startQuestionsRun(t);
  const head = formOf(ANSWER_PAIRS.slice(0, 3));
  const broken = await postAnswers(started, `${head}&q-generated=%E9`);
  assert.equal(broken.status, 400);
  assert.ok(broken.text.includes("the form is not valid UTF-8"), broken.text);
  assert.equal(fs.existsSync(started.answersFile), false, "nothing is written");
  const accepted = await postAnswers(started, `${head}&q-generated=%C3%A9`);
  assert.equal(accepted.status, 200, "positive control: the same value as UTF-8, e-acute, is accepted");
  assert.equal(readAnswers(started.answersFile).answers[2].value, "é");
});

// Makes the output file appear once, between the check and the link, as another process would: the first link finds it there. A
// rename would have replaced it. The answer is then 500, the file that appeared is kept, no temporary file is left, the token is
// live again, and the next valid form is written once that file is gone.
async function checkExclusiveWrite(t, { started, outputFile, post, get }) {
  const realLink = fs.linkSync;
  let calls = 0;
  t.mock.method(fs, "linkSync", (source, destination) => {
    calls += 1;
    if (calls === 1) fs.writeFileSync(destination, "written by another process\n");
    return realLink(source, destination);
  });
  const failed = await post();
  assert.equal(failed.status, 500, failed.text);
  assert.equal(calls, 1, "the write is one link");
  assert.equal(fs.readFileSync(outputFile, "utf8"), "written by another process\n", "the file that appeared is kept");
  assert.deepEqual(fs.readdirSync(started.runDir).filter((name) => name.endsWith(".tmp")), [], "the temporary file is removed");
  assert.equal((await get()).status, 200, "the token is live again after the 500");
  fs.rmSync(outputFile);
  const accepted = await post();
  assert.equal(accepted.status, 200, "positive control: once the file is gone, the form is written");
  assert.equal((await started.done).code, 0);
}

test("the intake.json write is exclusive: a file that appears after the check is kept, the answer is 500, and the next valid form is written", async (t) => {
  const started = await start(t);
  await checkExclusiveWrite(t, {
    started,
    outputFile: started.intakeFile,
    post: () => postForm(started, variant()),
    get: () => getPage(started),
  });
  assert.deepEqual(readIntake(started.intakeFile), VALID_INTAKE);
});

test("the answers.json write is exclusive, as the intake's is: a file that appears after the check is kept, and the next valid answer is written", async (t) => {
  const started = await startQuestionsRun(t);
  await checkExclusiveWrite(t, {
    started,
    outputFile: started.answersFile,
    post: () => postAnswers(started, VALID_ANSWERS),
    get: () => getQuestions(started),
  });
  assert.deepEqual(readAnswers(started.answersFile), EXPECTED_ANSWERS);
  assert.equal(fs.existsSync(path.join(started.runDir, "intake.json")), false, "no intake.json is written");
});

test("a questions form whose Content-Type is not the form type gets 415, and nothing is written; the form type passes", async (t) => {
  const started = await startQuestionsRun(t);
  const missing = await request(started.port, {
    method: "POST",
    path: `/questions?token=${started.token}`,
    body: VALID_ANSWERS,
    headers: { Origin: origin(started.port) },
  });
  assert.equal(missing.status, 415, "no Content-Type");
  for (const type of ["text/plain", "application/json", "multipart/form-data; boundary=x"]) {
    const response = await postAnswers(started, VALID_ANSWERS, { "Content-Type": type });
    assert.equal(response.status, 415, type);
  }
  assert.equal(fs.existsSync(started.answersFile), false, "nothing is written");
  const accepted = await postAnswers(started, VALID_ANSWERS, { "Content-Type": `${FORM_TYPE}; charset=UTF-8` });
  assert.equal(accepted.status, 200, "positive control: the form type with a charset is accepted");
});

test("a single question sent twice gets 400 that names it, a text question sent twice does too, and nothing is written; a multi question sent twice is valid", async (t) => {
  const started = await startQuestionsRun(t);
  const singleTwice = formOf([
    ["q-contradiction", "keep-claude"],
    ["q-contradiction", "keep-agents"],
    ["q-folders", "admin"],
    ["q-generated", "Yes."],
  ]);
  const single = await postAnswers(started, singleTwice);
  assert.equal(single.status, 400);
  assert.ok(single.text.includes("/q-contradiction: takes one value; found 2"), single.text);
  const textTwice = await postAnswers(started, formOf([...ANSWER_PAIRS, ["q-generated", "Second."]]));
  assert.equal(textTwice.status, 400);
  assert.ok(textTwice.text.includes("/q-generated: takes one value; found 2"), textTwice.text);
  assert.equal(fs.existsSync(started.answersFile), false, "nothing is written");
  const accepted = await postAnswers(started, VALID_ANSWERS);
  assert.equal(accepted.status, 200, "positive control: the form where the multi question is sent twice is the valid form");
  assert.equal((await started.done).code, 0);
});

test("two valid answers in flight at once: one is written and answered 200, the other is refused with 403, and answers.json is written once", async (t) => {
  const started = await startQuestionsRun(t);
  // The first answer stays open: its body is only half sent when the second one is accepted and written.
  const late = openPost(started, VALID_ANSWERS, "/questions");
  const first = await postAnswers(started, VALID_ANSWERS);
  assert.equal(first.status, 200, "the answer that completes first is written");
  late.finish();
  const second = await late.response;
  assert.equal(second.status, 403, "the answer still in flight is refused, not written");
  assert.equal((await started.done).code, 0, "done resolves once, with 0");
  assert.deepEqual(fs.readdirSync(started.runDir).sort(), ["answers.json", "questions.json"], "one answers.json and no temporary file");
  assert.deepEqual(readAnswers(started.answersFile), EXPECTED_ANSWERS);
});

test("a written answer is redacted in answers.json: a folder of the run's target and a token are masked", async (t) => {
  // Built at run time so that this file holds no secret-shaped text (push protection would block it).
  const token = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
  const started = await startQuestionsRun(t, {
    files: {
      "questions.json": JSON.stringify(QUESTIONS_DOC),
      "measurements.json": JSON.stringify({ meta: { targetRoot: "/xray-target/app" } }),
    },
  });
  const pairs = ANSWER_PAIRS.map(([name, value]) => [
    name,
    name === "q-generated" ? `Yes, see /xray-target/app/src and ${token}` : value,
  ]);
  const response = await postAnswers(started, formOf(pairs));
  assert.equal(response.status, 200);
  assert.equal((await started.done).code, 0);
  const written = readAnswers(started.answersFile);
  assert.equal(written.answers[2].value, "Yes, see <target>/src and ghp_…Q7r8", "the folder and the token are masked");
  assert.equal(written.answers[2].question, "Is this file generated?", "the question is kept as it is");
});
