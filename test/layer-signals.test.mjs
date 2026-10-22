import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { layerSignalsOf, loadLayerSignals, validateLayerSignals } from "../scripts/lib/layer-signals.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SIGNALS_FILE = path.join(HARNESS_ROOT, "data", "layer-signals.json");
const MODULE_FILE = path.join(HARNESS_ROOT, "scripts", "lib", "layer-signals.mjs");

// The rules of validateLayerSignals. check-catalog.mjs reports the same issues for data/layer-signals.json. Each case changes
// one field of a valid copy, and the issue at its pointer must have the message.
const MINIMAL_SIGNALS = {
  manifests: ["package.json", "Cargo.toml"],
  names: { frontend: ["web", "frontend"], "api-server": ["api", "server"] },
  languages: { ".ts": "TypeScript", ".c++": "C++", ".cs": "C#" },
};

// A copy of the minimal signals with one change made to it.
function signalsWith(change) {
  const data = structuredClone(MINIMAL_SIGNALS);
  change(data);
  return data;
}

// The issue at a pointer of validateLayerSignals. It fails if there is none, or if the message does not match.
function signalIssueAt(data, pointer, pattern) {
  const issues = validateLayerSignals(data);
  const found = issues.find((item) => item.pointer === pointer);
  assert.ok(found, `expected an issue at ${pointer}, got ${JSON.stringify(issues)}`);
  if (pattern !== undefined) assert.match(found.message, pattern);
  return found;
}

test("a valid layer-signals file has no issues, and the file in data/ is valid", () => {
  assert.deepEqual(validateLayerSignals(MINIMAL_SIGNALS), []);
  assert.deepEqual(validateLayerSignals(JSON.parse(fs.readFileSync(SIGNALS_FILE, "utf8"))), []);
  assert.ok(loadLayerSignals().manifests.has("package.json"));
});

test("the top level has exactly the fields manifests, names and languages", () => {
  signalIssueAt(signalsWith((data) => { data.owner = "team"; }), "/owner", /unknown field; the fields are manifests, names, languages/);
  signalIssueAt(signalsWith((data) => { delete data.languages; }), "/languages", /missing required field/);
  signalIssueAt(null, "", /must be an object with the fields manifests, names, languages/);
  signalIssueAt([], "", /must be an object/);
});

test("manifests are a non-empty list of distinct file names with no separator, dot names or control characters", () => {
  signalIssueAt(signalsWith((data) => { data.manifests = []; }), "/manifests", /non-empty list of file names/);
  signalIssueAt(signalsWith((data) => { data.manifests = "package.json"; }), "/manifests", /non-empty list of file names/);
  signalIssueAt(signalsWith((data) => { data.manifests = [""]; }), "/manifests/0", /must be a non-empty string/);
  signalIssueAt(signalsWith((data) => { data.manifests = ["apps/package.json"]; }), "/manifests/0", /no slash or backslash/);
  signalIssueAt(signalsWith((data) => { data.manifests = ["apps\\package.json"]; }), "/manifests/0", /no slash or backslash/);
  signalIssueAt(signalsWith((data) => { data.manifests = ["."]; }), "/manifests/0", /must not be "\."/);
  signalIssueAt(signalsWith((data) => { data.manifests = ["..", "x"]; }), "/manifests/0", /must not be "\.\."/);
  signalIssueAt(signalsWith((data) => { data.manifests = ["pack\nage.json"]; }), "/manifests/0", /control character/);
  signalIssueAt(signalsWith((data) => { data.manifests = ["package.json", "package.json"]; }), "/manifests/1", /listed twice/);
  assert.deepEqual(validateLayerSignals(signalsWith((data) => { data.manifests = ["package.json", "go.mod"]; })), [], "positive control");
});

test("names: hints are lower-case kebab-case ids that start with a letter, folder names are lower-case single names", () => {
  signalIssueAt(signalsWith((data) => { data.names = { Frontend: ["web"] }; }), "/names/Frontend", /lower-case kebab-case id/);
  signalIssueAt(signalsWith((data) => { data.names = { "front-": ["web"] }; }), "/names/front-", /lower-case kebab-case id/);
  signalIssueAt(signalsWith((data) => { data.names = { "1api": ["web"] }; }), "/names/1api", /starts with a letter/);
  signalIssueAt(signalsWith((data) => { data.names = { frontend: ["Web"] }; }), "/names/frontend/0", /must be lower case/);
  signalIssueAt(signalsWith((data) => { data.names = { frontend: ["apps/web"] }; }), "/names/frontend/0", /one folder name/);
  signalIssueAt(signalsWith((data) => { data.names = { frontend: ["."] }; }), "/names/frontend/0", /must not be "\."/);
  signalIssueAt(signalsWith((data) => { data.names = { frontend: ["web app"] }; }), "/names/frontend/0", /letters, digits, dots, underscores and hyphens/);
  signalIssueAt(signalsWith((data) => { data.names = { frontend: [] }; }), "/names/frontend", /non-empty list of folder names/);
  signalIssueAt(signalsWith((data) => { data.names = { frontend: "web" }; }), "/names/frontend", /non-empty list of folder names/);
  signalIssueAt(signalsWith((data) => { data.names = {}; }), "/names", /non-empty object from hints/);
  assert.deepEqual(validateLayerSignals(signalsWith((data) => { data.names = { infrastructure: ["k8s", "helm.d"] }; })), [], "positive control");
});

test("a folder name is listed once across all hints", () => {
  signalIssueAt(
    signalsWith((data) => { data.names = { frontend: ["web"], client: ["web"] }; }),
    "/names/client/0",
    /"web" is already listed at \/names\/frontend\/0/,
  );
  signalIssueAt(signalsWith((data) => { data.names = { frontend: ["web", "web"] }; }), "/names/frontend/1", /already listed/);
  assert.deepEqual(validateLayerSignals(signalsWith((data) => { data.names = { frontend: ["web"], client: ["app"] }; })), []);
});

test("languages: extensions are lower-case with a leading dot, names are non-empty strings", () => {
  signalIssueAt(signalsWith((data) => { data.languages = { ts: "TypeScript" }; }), "/languages/ts", /leading dot/);
  signalIssueAt(signalsWith((data) => { data.languages = { ".TS": "TypeScript" }; }), "/languages/.TS", /leading dot/);
  signalIssueAt(signalsWith((data) => { data.languages = { ".": "Nothing" }; }), "/languages/.", /leading dot/);
  signalIssueAt(signalsWith((data) => { data.languages = { "..ts": "TypeScript" }; }), "/languages/..ts", /leading dot/);
  signalIssueAt(signalsWith((data) => { data.languages = { ".c#": "C#" }; }), "/languages/.c#", /leading dot/);
  signalIssueAt(signalsWith((data) => { data.languages = { ".ts": "" }; }), "/languages/.ts", /must be a non-empty string/);
  signalIssueAt(signalsWith((data) => { data.languages = { ".ts": 1 }; }), "/languages/.ts", /must be a non-empty string/);
  signalIssueAt(signalsWith((data) => { data.languages = {}; }), "/languages", /non-empty object from extensions/);
});

test("a key with a line break is shown escaped in its pointer and message, and a normal key passes", () => {
  assert.deepEqual(validateLayerSignals(signalsWith((data) => { data.languages = { ".ts": "TypeScript" }; })), [], "positive control");
  const found = signalIssueAt(
    signalsWith((data) => { data.languages = { "\n.ts": "TypeScript" }; }),
    "/languages/\\u000a.ts",
    /leading dot, such as \.ts, found "\\n\.ts"/,
  );
  assert.doesNotMatch(found.pointer + found.message, /\n/u);
});

test("layerSignalsOf compiles valid data, and throws one line that names each issue of invalid data", () => {
  const signals = layerSignalsOf(MINIMAL_SIGNALS);
  assert.equal(signals.hintOf.get("web"), "frontend");
  assert.equal(signals.languageOf.get(".c++"), "C++");
  assert.throws(
    () => layerSignalsOf(signalsWith((data) => { data.manifests = []; delete data.languages; })),
    /data\/layer-signals\.json is not valid: \/languages: missing required field; \/manifests: must be a non-empty list of file names/,
  );
});

test("the signal module imports nothing heavy: only the JSON helper and the message quoting, besides node built-ins", () => {
  const source = fs.readFileSync(MODULE_FILE, "utf8");
  const imports = [...source.matchAll(/^import .* from "([^"]+)";$/gm)].map((match) => match[1]);
  assert.deepEqual(imports.filter((name) => !name.startsWith("node:")).sort(), ["./json-out.mjs", "./layer-plan.mjs"]);
});
