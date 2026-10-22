import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { makeFixture } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

// The command line of scripts/intake.mjs, as a child process: the server runs for real on 127.0.0.1. Every child is killed in
// t.after if it is still running. The run folders are fixtures in the system temp folder. The intake.json that a run writes is
// checked against schemas/intake.schema.json at the value level, and the answers.json of a --questions run against
// schemas/answers.schema.json.
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const INTAKE = path.join(HARNESS_ROOT, "scripts", "intake.mjs");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "intake.schema.json"), "utf8"));
const ANSWERS_SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "answers.schema.json"), "utf8"));
const FORM_TYPE = "application/x-www-form-urlencoded";
const URL_PATTERN = /^http:\/\/127\.0\.0\.1:\d+\/intake\?token=[A-Za-z0-9_-]+$/;
const QUESTIONS_URL_PATTERN = /^http:\/\/127\.0\.0\.1:\d+\/questions\?token=[A-Za-z0-9_-]+$/;

const LAYERS = { schemaVersion: 1, folders: [".", "apps", "apps/api", "apps/web", "db"] };
const PLAN = {
  schemaVersion: 1,
  layers: [
    { name: "frontend", folders: ["apps/web"], reason: "package.json in apps/web" },
    { name: "backend", folders: ["apps/api"], reason: "Cargo.toml in apps/api" },
    { name: "database", folders: ["db"], reason: "the folder is named db" },
  ],
};
const VALID_BODY = new URLSearchParams([
  ["depth", "standard"],
  ["scope", "layers"],
  ["layer", "0"],
  ["layer", "2"],
  ["axis", "instructions"],
  ["axis", "security"],
  ["language", "en"],
  ["userLayer", "yes"],
]).toString();
const VALID_INTAKE = {
  schemaVersion: 1,
  depth: "standard",
  scope: { mode: "layers", layers: ["frontend", "database"] },
  axes: ["instructions", "security"],
  language: "en",
  outsideAccess: { userLayer: true, ancestors: false },
};

// A run folder with the layers and the plan.
function makeRun(t, files = { "layers.json": JSON.stringify(LAYERS), "layer-plan.json": JSON.stringify(PLAN) }) {
  const fixture = makeFixture({ files });
  t.after(fixture.cleanup);
  return fixture.root;
}

// Reads an intake.json that a run has written, and checks it against the schema at the value level.
function readIntake(file) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(schemaProblems(SCHEMA, value), [], `${file} passes schemas/intake.schema.json`);
  return value;
}

// Starts the command. The output is collected as it comes; closed resolves with the exit code once the streams are closed.
// The child is killed in t.after when it is still running, so a failing test leaves nothing behind.
function launch(t, args) {
  const child = spawn(process.execPath, [INTAKE, ...args], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const output = { stdout: "", stderr: "" };
  let exited = false;
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    output.stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output.stderr += chunk;
  });
  child.once("exit", () => {
    exited = true;
  });
  t.after(() => {
    if (!exited && child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  });
  const closed = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code));
  });
  // The URL line, once the command has printed it: "intake" or "questions". A command that exits first gives null.
  const urlLine = async (label = "intake") => {
    const pattern = new RegExp(`^${label}: (\\S+)$`, "m");
    await waitUntil(() => exited || pattern.test(output.stdout));
    const match = pattern.exec(output.stdout);
    return match === null ? null : match[1];
  };
  return { child, output, closed, urlLine };
}

async function waitUntil(predicate, ms = 30_000) {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the command");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

// A POST of a form to the printed URL, on a new connection, from the origin of the server.
function post(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(body, "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port: Number(url.port),
        method: "POST",
        path: `${url.pathname}${url.search}`,
        agent: false,
        headers: {
          Origin: `http://127.0.0.1:${url.port}`,
          "Content-Type": FORM_TYPE,
          "Content-Length": payload.length,
          ...headers,
        },
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
    req.end(payload);
  });
}

test("the command prints the URL, then exits 4 after the timeout, with nothing written", async (t) => {
  const runDir = makeRun(t);
  const run = launch(t, [runDir, "--timeout", "1", "--lang", "es"]);
  const url = await run.urlLine();
  assert.match(url, URL_PATTERN);
  assert.equal(run.output.stdout.split("\n")[0], `intake: ${url}`, "the first line is the URL");
  assert.equal(await run.closed, 4);
  assert.match(run.output.stderr, /timed out after 1s; nothing was written/);
  assert.equal(fs.existsSync(path.join(runDir, "intake.json")), false);
});

test("a wrong token gets 403 and the command keeps waiting; a valid form posted to the printed URL exits 0 and writes intake.json", async (t) => {
  const runDir = makeRun(t);
  const run = launch(t, [runDir, "--timeout", "30"]);
  const url = new URL(await run.urlLine());
  const wrong = new URL(url.href);
  wrong.search = `?token=${"B".repeat(43)}`;
  assert.equal((await post(wrong, VALID_BODY)).status, 403);
  assert.equal(fs.existsSync(path.join(runDir, "intake.json")), false, "a refused request writes nothing");

  const response = await post(url, VALID_BODY);
  assert.equal(response.status, 200);
  assert.equal(await run.closed, 0);
  assert.deepEqual(readIntake(path.join(runDir, "intake.json")), VALID_INTAKE);
  assert.deepEqual(fs.readdirSync(runDir).sort(), ["intake.json", "layer-plan.json", "layers.json"], "no temporary file is left");
  assert.match(run.output.stdout, /written: .*intake\.json/);
});

test("a run folder that already holds an intake.json exits 2, and the file is left as it is", async (t) => {
  const runDir = makeRun(t);
  fs.writeFileSync(path.join(runDir, "intake.json"), "previous\n");
  const run = launch(t, [runDir, "--timeout", "30"]);
  assert.equal(await run.closed, 2);
  assert.match(run.output.stderr, /already answered; remove it to ask again/);
  assert.doesNotMatch(run.output.stdout, /intake:/, "no server starts");
  assert.equal(fs.readFileSync(path.join(runDir, "intake.json"), "utf8"), "previous\n");
});

test("a run folder that is not allowed, or does not exist, exits 2 and starts no server", async (t) => {
  const outside = launch(t, [path.join(HARNESS_ROOT, "scripts")]);
  assert.equal(await outside.closed, 2);
  assert.match(outside.output.stderr, /must be inside/);
  assert.doesNotMatch(outside.output.stdout, /intake:/);

  const missing = makeFixture({ files: {} });
  t.after(missing.cleanup);
  const absent = launch(t, [path.join(missing.root, "not-here")]);
  assert.equal(await absent.closed, 2);
  assert.match(absent.output.stderr, /layer-plan\.json: cannot be read: ENOENT/);
  assert.doesNotMatch(absent.output.stdout, /intake:/);
});

test("a run folder without a layer plan exits 2 and names the missing file", async (t) => {
  const runDir = makeRun(t, { "layers.json": JSON.stringify(LAYERS) });
  const run = launch(t, [runDir]);
  assert.equal(await run.closed, 2);
  assert.match(run.output.stderr, /layer-plan\.json: cannot be read: ENOENT/);
  assert.doesNotMatch(run.output.stdout, /intake:/);
  assert.equal(fs.existsSync(path.join(runDir, "intake.json")), false);
});

test("invalid arguments exit 2 with the usage line, before any server starts", (t) => {
  const runDir = makeRun(t);
  const cases = [
    [],
    [runDir, runDir],
    [runDir, "--timeout", "0"],
    [runDir, "--timeout", "3601"],
    [runDir, "--timeout", "1.5"],
    [runDir, "--lang", "fr"],
    [runDir, "--bogus"],
  ];
  for (const args of cases) {
    const result = spawnSync(process.execPath, [INTAKE, ...args], { encoding: "utf8", timeout: 30_000, windowsHide: true });
    assert.equal(result.status, 2, JSON.stringify(args));
    assert.match(result.stderr, /usage: node scripts\/intake\.mjs/, JSON.stringify(args));
    assert.doesNotMatch(result.stdout, /intake:/, JSON.stringify(args));
  }
});

// The questions form (--questions) -------------------------------------------------------------------

// Two questions: a single one and a written one. The run folder holds no layer plan, which --questions does not need.
const QUESTIONS = {
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
      id: "generated",
      type: "text",
      text: "Is this file generated?",
      why: "It has no generator marker.",
      source: { file: "src/gen.ts", line: 1 },
    },
  ],
};
const QUESTIONS_BODY = new URLSearchParams([
  ["q-contradiction", "keep-agents"],
  ["q-generated", "No, it is written by hand."],
]).toString();

// A run folder with the given files, in a fixture of the temp folder that is removed at the end of the test.
function makeQuestionsRun(t, files) {
  const fixture = makeFixture({ files });
  t.after(fixture.cleanup);
  return fixture.root;
}

// Reads an answers.json that a run has written, and checks it against the schema at the value level.
function readAnswers(file) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(schemaProblems(ANSWERS_SCHEMA, value), [], `${file} passes schemas/answers.schema.json`);
  return value;
}

test("--questions prints the questions URL, a valid answer writes answers.json and exits 0, and no intake.json is written", async (t) => {
  const runDir = makeQuestionsRun(t, { "questions.json": JSON.stringify(QUESTIONS) });
  const run = launch(t, [runDir, "--questions", "--timeout", "30"]);
  const url = new URL(await run.urlLine("questions"));
  assert.match(url.href, QUESTIONS_URL_PATTERN);
  assert.equal(run.output.stdout.split("\n")[0], `questions: ${url.href}`, "the first line is the URL");
  assert.doesNotMatch(run.output.stdout, /^intake:/m, "the intake form is not started");

  const response = await post(url, QUESTIONS_BODY);
  assert.equal(response.status, 200);
  assert.equal(await run.closed, 0);
  assert.match(run.output.stdout, /written: .*answers\.json/);
  const answers = readAnswers(path.join(runDir, "answers.json"));
  assert.deepEqual(answers.answers.map((answer) => answer.id), ["contradiction", "generated"]);
  assert.deepEqual(answers.answers[0].selected, [{ id: "keep-agents", label: "Keep AGENTS.md" }]);
  assert.equal(answers.answers[1].value, "No, it is written by hand.");
  assert.deepEqual(fs.readdirSync(runDir).sort(), ["answers.json", "questions.json"], "no intake.json and no temporary file");
});

test("--questions with more than five questions exits 2 and starts no server; five questions start", async (t) => {
  const question = (index) => ({
    id: `text-${index}`,
    type: "text",
    text: "A question",
    why: "A reason",
    source: { file: "README.md", line: 1 },
  });
  const six = makeQuestionsRun(t, { "questions.json": JSON.stringify({ schemaVersion: 1, questions: [0, 1, 2, 3, 4, 5].map(question) }) });
  const refused = launch(t, [six, "--questions", "--timeout", "30"]);
  assert.equal(await refused.closed, 2);
  assert.match(refused.output.stderr, /holds 6 questions; the most is 5/);
  assert.doesNotMatch(refused.output.stdout, /questions:/, "no server starts");
  assert.equal(fs.existsSync(path.join(six, "answers.json")), false);

  // Positive control: the same run with five questions starts, and stops with code 4 after its one-second wait.
  const five = makeQuestionsRun(t, { "questions.json": JSON.stringify({ schemaVersion: 1, questions: [0, 1, 2, 3, 4].map(question) }) });
  const started = launch(t, [five, "--questions", "--timeout", "1"]);
  assert.match((await started.urlLine("questions")) ?? "", QUESTIONS_URL_PATTERN);
  assert.equal(await started.closed, 4);
  assert.equal(fs.existsSync(path.join(five, "answers.json")), false, "the timeout writes nothing");
});

test("--questions with no questions.json exits 2 and names the missing file, and starts no server", async (t) => {
  const runDir = makeQuestionsRun(t, {});
  const run = launch(t, [runDir, "--questions", "--timeout", "30"]);
  assert.equal(await run.closed, 2);
  assert.match(run.output.stderr, /questions\.json is missing/);
  assert.doesNotMatch(run.output.stdout, /questions:/);
});

test("--questions with an invalid questions.json exits 2 and starts no server; the same file with a valid id starts", async (t) => {
  const withId = (id) =>
    JSON.stringify({
      schemaVersion: 1,
      questions: [{ id, type: "text", text: "A question", why: "A reason", source: { file: "README.md", line: 1 } }],
    });
  const invalid = makeQuestionsRun(t, { "questions.json": withId("Bad Id") });
  const refused = launch(t, [invalid, "--questions", "--timeout", "30"]);
  assert.equal(await refused.closed, 2);
  assert.match(refused.output.stderr, /questions\.json is not valid: \/questions\/0\/id: /);
  assert.doesNotMatch(refused.output.stdout, /questions:/, "no server starts");

  // Positive control: the same file with a valid id starts.
  const valid = makeQuestionsRun(t, { "questions.json": withId("bad-id") });
  const started = launch(t, [valid, "--questions", "--timeout", "1"]);
  assert.match((await started.urlLine("questions")) ?? "", QUESTIONS_URL_PATTERN);
  assert.equal(await started.closed, 4);
});

test("--questions with an answers.json that already exists exits 2, and the file is left as it is", async (t) => {
  const runDir = makeQuestionsRun(t, { "questions.json": JSON.stringify(QUESTIONS), "answers.json": "previous\n" });
  const run = launch(t, [runDir, "--questions", "--timeout", "30"]);
  assert.equal(await run.closed, 2);
  assert.match(run.output.stderr, /already answered; remove it to ask again/);
  assert.doesNotMatch(run.output.stdout, /questions:/, "no server starts");
  assert.equal(fs.readFileSync(path.join(runDir, "answers.json"), "utf8"), "previous\n");
});

test("--questions with an existing intake.json still writes answers.json: the two forms have their own files", async (t) => {
  const runDir = makeQuestionsRun(t, { "questions.json": JSON.stringify(QUESTIONS), "intake.json": "previous\n" });
  const run = launch(t, [runDir, "--questions", "--timeout", "30"]);
  const url = new URL(await run.urlLine("questions"));
  assert.equal((await post(url, QUESTIONS_BODY)).status, 200);
  assert.equal(await run.closed, 0);
  assert.equal(fs.readFileSync(path.join(runDir, "intake.json"), "utf8"), "previous\n", "intake.json is left as it is");
  readAnswers(path.join(runDir, "answers.json"));
});
