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
  parseForm,
  startIntake,
  validateIntake,
} from "../scripts/lib/intake-server.mjs";
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
// status and the text, so that a test can keep one submission in flight while another one completes.
function openPost(started, body) {
  const payload = Buffer.from(body, "utf8");
  const cut = Math.floor(payload.length / 2);
  let req;
  const response = new Promise((resolve, reject) => {
    req = http.request(
      {
        host: "127.0.0.1",
        port: started.port,
        method: "POST",
        path: `/intake?token=${started.token}`,
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
