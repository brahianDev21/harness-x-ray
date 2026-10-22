import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  LAYER_FIELDS,
  MAX_NAME_LENGTH,
  MAX_REASON_LENGTH,
  PLAN_FIELDS,
  REQUIRED_LAYER_FIELDS,
  SIGNAL_TYPES,
  quoteText,
  readLayerPlan,
  validateLayerPlan,
  visibleText,
} from "../scripts/lib/layer-plan.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "layer-plan.schema.json");
const SCHEMA = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
const sorted = (values) => [...values].sort();

// Helpers ---------------------------------------------------------------------------------------

const DEFAULT_FOLDERS = [".", "apps", "apps/api", "apps/web", "apps/web-extra", "apps/web/admin", "db"];

// A layers.json as the mapping writes it. Only schemaVersion and folders are read by the validator.
function makeLayers(folders = DEFAULT_FOLDERS) {
  return {
    schemaVersion: 1,
    meta: { tool: "harness-x-ray", mappedAt: "2026-10-22T00:00:00.000Z", targetRoot: "/example/target" },
    structure: "units",
    units: [],
    workspaces: [],
    tree: { path: ".", files: 3, children: [], truncated: false },
    folders,
    suggestion: null,
    warnings: [],
  };
}

const LAYERS = makeLayers();

// A plan that passes: three layers, and one option that lies inside the frontend folder.
function validPlan() {
  return {
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
}

// The valid plan with the layers changed by the callback.
function planWith(change) {
  const plan = validPlan();
  change(plan.layers);
  return plan;
}

function describeErrors(errors) {
  return errors.map((item) => `${item.pointer}: ${item.message}`).join("\n") || "(none)";
}

// The one error at a pointer. It fails if there is none, or if the message does not match.
function errorAt(result, pointer, pattern) {
  const found = result.errors.find((item) => item.pointer === pointer);
  assert.ok(found, `expected an error at ${pointer}, got:\n${describeErrors(result.errors)}`);
  if (pattern !== undefined) assert.match(found.message, pattern);
  return found;
}

function assertPasses(plan, layers = LAYERS) {
  const result = validateLayerPlan(plan, layers);
  assert.deepEqual(result.errors, [], describeErrors(result.errors));
  assert.equal(result.ok, true);
}

// Positive control --------------------------------------------------------------------------------

test("a valid plan passes, with the signals and the options it uses", () => {
  assertPasses(validPlan());
  assertPasses(validPlan(), makeLayers());
});

test("the flat-repo suggestion shape passes: one layer for the whole repository, with options", () => {
  const layers = makeLayers([".", "src", "tests"]);
  const plan = {
    schemaVersion: 1,
    layers: [{ name: "whole repository", folders: ["."], reason: "no workspace and no manifest in a subfolder", options: ["src", "tests"] }],
  };
  assertPasses(plan, layers);
});

test("signals and options are optional", () => {
  assertPasses(planWith((layers) => {
    delete layers[0].signals;
    delete layers[0].options;
  }));
});

// Folders -----------------------------------------------------------------------------------------

test("an invented folder is rejected: it is not a folder of layers.json", () => {
  assertPasses(validPlan(), LAYERS);
  const result = validateLayerPlan(planWith((layers) => {
    layers[1].folders = ["apps/mobile"];
  }), LAYERS);
  assert.equal(result.ok, false);
  errorAt(result, "/layers/1/folders/0", /^"apps\/mobile" is not a folder of layers\.json$/);
});

test("a folder that two layers list is rejected at the later layer", () => {
  const result = validateLayerPlan(planWith((layers) => {
    layers[1].folders = ["apps/web"];
  }), LAYERS);
  errorAt(result, "/layers/1/folders/0", /is also a folder of \/layers\/0$/);
});

test("a folder inside a folder of another layer is rejected, in either order", () => {
  const layers = makeLayers(["packages", "packages/a"]);
  const outer = {
    schemaVersion: 1,
    layers: [
      { name: "packages", folders: ["packages"], reason: "the whole packages folder" },
      { name: "package a", folders: ["packages/a"], reason: "one package" },
    ],
  };
  assert.equal(
    errorAt(validateLayerPlan(outer, layers), "/layers/1/folders/0").message,
    '"packages/a" is inside "packages", a folder of /layers/0',
  );
  const inner = { schemaVersion: 1, layers: [outer.layers[1], outer.layers[0]] };
  assert.equal(
    errorAt(validateLayerPlan(inner, layers), "/layers/1/folders/0").message,
    '"packages" contains "packages/a", a folder of /layers/0',
  );
});

test("the root folder overlaps every folder of another layer, in either order", () => {
  for (const folder of ["apps", "apps/web", "db"]) {
    const whole = { name: "whole repository", folders: ["."], reason: "one layer for the whole repository" };
    const other = { name: "other", folders: [folder], reason: "a folder of the repository" };
    const first = validateLayerPlan({ schemaVersion: 1, layers: [whole, other] }, LAYERS);
    assert.equal(
      errorAt(first, "/layers/1/folders/0").message,
      `${JSON.stringify(folder)} is inside ".", a folder of /layers/0`,
    );
    const second = validateLayerPlan({ schemaVersion: 1, layers: [other, whole] }, LAYERS);
    assert.equal(
      errorAt(second, "/layers/1/folders/0").message,
      `"." contains ${JSON.stringify(folder)}, a folder of /layers/0`,
    );
  }
});

test("sibling folders in two layers pass, and folders that only share a name prefix pass too", () => {
  assertPasses(validPlan());
  const layers = makeLayers(["packages", "packages-old", "apps/web", "apps/api"]);
  assertPasses({
    schemaVersion: 1,
    layers: [
      { name: "web", folders: ["apps/web"], reason: "the web app" },
      { name: "api", folders: ["apps/api"], reason: "the api app" },
    ],
  }, layers);
  assertPasses({
    schemaVersion: 1,
    layers: [
      { name: "packages", folders: ["packages"], reason: "the packages folder" },
      { name: "old packages", folders: ["packages-old"], reason: "the old packages folder" },
    ],
  }, layers);
});

test("a folder listed twice in one layer is rejected at the second entry", () => {
  const result = validateLayerPlan(planWith((layers) => {
    layers[1].folders = ["apps/api", "apps/api"];
  }), LAYERS);
  errorAt(result, "/layers/1/folders/1", /listed twice in this layer/);
});

test("folders must be a non-empty list of strings", () => {
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].folders = []; }), LAYERS), "/layers/0/folders", /non-empty list/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].folders = "apps/web"; }), LAYERS), "/layers/0/folders", /non-empty list/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].folders = [1]; }), LAYERS), "/layers/0/folders/0", /must be a string, found 1/);
});

// Options -----------------------------------------------------------------------------------------

test("an option outside its layer is rejected", () => {
  const result = validateLayerPlan(planWith((layers) => {
    layers[0].options = ["apps/api"];
  }), LAYERS);
  errorAt(result, "/layers/0/options/0", /is not inside a folder of this layer/);
});

test("an option lies inside its folder only when it is the folder or is below it at a slash", () => {
  assertPasses(planWith((layers) => {
    layers[0].options = ["apps/web"];
  }));
  // apps/web-extra is a folder of layers.json, but it is not below apps/web: the boundary is a slash.
  const result = validateLayerPlan(planWith((layers) => {
    layers[0].options = ["apps/web-extra"];
  }), LAYERS);
  errorAt(result, "/layers/0/options/0", /is not inside a folder of this layer/);
});

test("the root folder holds every folder, but an option of the root is outside a layer folder", () => {
  const flat = { schemaVersion: 1, layers: [{ name: "whole repository", folders: ["."], reason: "one layer", options: ["apps/web"] }] };
  assertPasses(flat);
  const result = validateLayerPlan(planWith((layers) => {
    layers[0].options = ["."];
  }), LAYERS);
  errorAt(result, "/layers/0/options/0", /is not inside a folder of this layer/);
});

test("an option that lies inside a folder of another layer is rejected", () => {
  assertPasses(validPlan());
  const plan = planWith((layers) => {
    layers.push({ name: "apps", folders: ["apps"], reason: "the apps folder as a whole" });
  });
  const result = validateLayerPlan(plan, LAYERS);
  errorAt(result, "/layers/0/options/0", /^"apps\/web\/admin" is inside "apps", a folder of \/layers\/3$/);
});

test("an option that is also a folder of another layer is rejected, though it lies inside its own layer", () => {
  const withAdmin = planWith((layers) => {
    layers.push({ name: "admin", folders: ["apps/web/admin"], reason: "a folder named admin" });
  });
  const result = validateLayerPlan(withAdmin, LAYERS);
  errorAt(result, "/layers/0/options/0", /is also a folder of \/layers\/3$/);
});

test("options are unique and must be a list of folders", () => {
  const twice = validateLayerPlan(planWith((layers) => {
    layers[0].options = ["apps/web/admin", "apps/web/admin"];
  }), LAYERS);
  errorAt(twice, "/layers/0/options/1", /listed twice in options/);
  const notList = validateLayerPlan(planWith((layers) => {
    layers[0].options = "apps/web/admin";
  }), LAYERS);
  errorAt(notList, "/layers/0/options", /must be a list of folders/);
});

// Fields ------------------------------------------------------------------------------------------

test("unknown fields are errors at the top level and in a layer", () => {
  const extra = { ...validPlan(), note: "not in the format" };
  errorAt(validateLayerPlan(extra, LAYERS), "/note", /unknown field; the fields are schemaVersion, layers/);
  const typo = planWith((layers) => {
    layers[0].signal = ["manifest"];
  });
  errorAt(validateLayerPlan(typo, LAYERS), "/layers/0/signal", /unknown field; the fields are name, folders, reason, signals, options/);
});

test("required fields are reported when they are missing", () => {
  errorAt(validateLayerPlan(planWith((layers) => { delete layers[0].reason; }), LAYERS), "/layers/0/reason", /missing required field/);
  errorAt(validateLayerPlan({ schemaVersion: 1 }, LAYERS), "/layers", /missing required field/);
});

test("schemaVersion must be 1 and layers must be a non-empty list", () => {
  errorAt(validateLayerPlan({ ...validPlan(), schemaVersion: 2 }, LAYERS), "/schemaVersion", /must be 1, found 2/);
  errorAt(validateLayerPlan({ ...validPlan(), schemaVersion: "1" }, LAYERS), "/schemaVersion", /must be 1, found "1"/);
  errorAt(validateLayerPlan({ ...validPlan(), layers: [] }, LAYERS), "/layers", /must be a non-empty list of layers/);
  errorAt(validateLayerPlan({ ...validPlan(), layers: {} }, LAYERS), "/layers", /must be a non-empty list of layers/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0] = null; }), LAYERS), "/layers/0", /must be an object/);
});

test("the plan itself must be an object", () => {
  errorAt(validateLayerPlan(null, LAYERS), "", /must be an object with the fields schemaVersion and layers/);
  errorAt(validateLayerPlan([], LAYERS), "", /must be an object/);
});

test("names must be non-empty strings, at most 80 characters, and unique when case is ignored", () => {
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].name = ""; }), LAYERS), "/layers/0/name", /must be a non-empty string/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].name = "   "; }), LAYERS), "/layers/0/name", /must be a non-empty string/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].name = "a".repeat(81); }), LAYERS), "/layers/0/name", /at most 80 characters/);
  assertPasses(planWith((layers) => { layers[0].name = "a".repeat(MAX_NAME_LENGTH); }));
  // The limit counts characters, not UTF-16 units: 80 emoji are 80 characters.
  assertPasses(planWith((layers) => { layers[0].name = "\u{1F600}".repeat(MAX_NAME_LENGTH); }));
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].name = "\u{1F600}".repeat(81); }), LAYERS), "/layers/0/name", /at most 80 characters/);
  const duplicate = validateLayerPlan(planWith((layers) => { layers[1].name = "FRONTEND"; }), LAYERS);
  errorAt(duplicate, "/layers/1/name", /ignoring case; "FRONTEND" is also the name of \/layers\/0$/);
});

test("reasons must be non-empty strings, at most 500 characters", () => {
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].reason = ""; }), LAYERS), "/layers/0/reason", /must be a non-empty string/);
  assertPasses(planWith((layers) => { layers[0].reason = "x".repeat(MAX_REASON_LENGTH); }));
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].reason = "x".repeat(MAX_REASON_LENGTH + 1); }), LAYERS), "/layers/0/reason", /at most 500 characters/);
});

test("signals are known signal types, listed once", () => {
  assertPasses(planWith((layers) => { layers[0].signals = [...SIGNAL_TYPES]; }));
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].signals = ["gradle"]; }), LAYERS), "/layers/0/signals/0", /must be one of root, workspace, manifest, name, harness, found "gradle"/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].signals = ["manifest", "manifest"]; }), LAYERS), "/layers/0/signals/1", /listed twice/);
  errorAt(validateLayerPlan(planWith((layers) => { layers[0].signals = "manifest"; }), LAYERS), "/layers/0/signals", /must be a list of signal types/);
});

// Hostile folder names ----------------------------------------------------------------------------

const HOSTILE_FOLDERS = ["apps\nweb", 'say "hi"', "\u202Eevil", "back\\slash"];

test("hostile folder names are matched exactly when layers.json lists them", () => {
  const layers = makeLayers([...DEFAULT_FOLDERS, ...HOSTILE_FOLDERS]);
  const plan = {
    schemaVersion: 1,
    layers: [{ name: "odd", folders: [...HOSTILE_FOLDERS, "apps/api"], reason: "folders with a newline, quotes, a bidi override and a backslash" }],
  };
  assertPasses(plan, layers);
  // A near miss is not the folder: the newline is not a space, and the backslash is not a slash.
  const near = validateLayerPlan({
    schemaVersion: 1,
    layers: [{ name: "odd", folders: ["apps web", "back/slash"], reason: "near misses of hostile names" }],
  }, layers);
  errorAt(near, "/layers/0/folders/0", /^"apps web" is not a folder of layers\.json$/);
  errorAt(near, "/layers/0/folders/1", /^"back\/slash" is not a folder of layers\.json$/);
});

test("hostile folder names that layers.json does not list are rejected, and their messages stay on one line", () => {
  const invented = [
    ["apps\nweb", '"apps\\nweb" is not a folder of layers.json'],
    ['say "hi"', '"say \\"hi\\"" is not a folder of layers.json'],
    ["\u202Eevil", '"\\u202eevil" is not a folder of layers.json'],
    ["back\\slash", '"back\\\\slash" is not a folder of layers.json'],
  ];
  const plan = {
    schemaVersion: 1,
    layers: [{ name: "odd", folders: [...invented.map(([folder]) => folder), "apps/api"], reason: "invented folders" }],
  };
  const result = validateLayerPlan(plan, LAYERS);
  invented.forEach(([, message], index) => {
    const found = errorAt(result, `/layers/0/folders/${index}`);
    assert.equal(found.message, message);
    assert.doesNotMatch(found.message, /[\n\r\u2028\u2029\u202E]/u, "the message has no raw line break or bidi override");
  });
  // Positive control: the normal folder in the same plan has no error.
  assert.equal(result.errors.some((item) => item.pointer === "/layers/0/folders/4"), false, describeErrors(result.errors));
});

test("a hostile option is escaped in its message too", () => {
  const layers = makeLayers([...DEFAULT_FOLDERS, "apps\nweb", "apps\nweb/admin\u202E"]);
  const plan = planWith((all) => {
    all[0].folders = ["apps\nweb"];
    all[0].options = ["apps\nweb/admin\u202E", "apps\nweb/x"];
  });
  // The first option is a listed folder below apps\nweb: valid. The second is not listed: rejected.
  const result = validateLayerPlan(plan, layers);
  assert.equal(result.errors.length, 1, describeErrors(result.errors));
  errorAt(result, "/layers/0/options/1", /^"apps\\nweb\/x" is not a folder of layers\.json$/);
});

test("control characters in an unknown field name are escaped in its pointer", () => {
  assertPasses(validPlan());
  const plan = { ...validPlan(), "bad\nkey": 1 };
  const result = validateLayerPlan(plan, LAYERS);
  const found = errorAt(result, "/bad\\u000akey", /unknown field/);
  assert.doesNotMatch(found.pointer + found.message, /\n/u);
});

test("the text helpers escape invisible characters and keep plain text as it is", () => {
  assert.equal(visibleText("plain text"), "plain text");
  assert.equal(visibleText("a\nb\u202Ec"), "a\\u000ab\\u202ec");
  assert.equal(visibleText("\u{E0001}"), "\\u{e0001}");
  assert.equal(quoteText('x"y\\z'), '"x\\"y\\\\z"');
  assert.equal(quoteText("line\nbreak"), '"line\\nbreak"');
});

// Bad layers argument -----------------------------------------------------------------------------

test("a layers argument that is not a layers.json throws a TypeError", () => {
  const bad = [
    null,
    undefined,
    [],
    "layers",
    { schemaVersion: 2, folders: ["."] },
    { schemaVersion: 1 },
    { schemaVersion: 1, folders: "." },
    { schemaVersion: 1, folders: [1] },
  ];
  for (const layers of bad) {
    assert.throws(() => validateLayerPlan(validPlan(), layers), TypeError, `layers: ${String(layers)}`);
  }
  // Positive control: the valid layers do not throw.
  assert.doesNotThrow(() => validateLayerPlan(validPlan(), LAYERS));
});

// readLayerPlan -----------------------------------------------------------------------------------

test("readLayerPlan validates the plan of a run folder against its layers.json", (t) => {
  const run = makeFixture({ files: { "layers.json": JSON.stringify(LAYERS), "layer-plan.json": JSON.stringify(validPlan()) } });
  t.after(run.cleanup);
  assert.deepEqual(readLayerPlan(run.root), { ok: true, errors: [] });
});

test("readLayerPlan returns the errors of a plan that does not match its layers", (t) => {
  const plan = planWith((layers) => { layers[1].folders = ["apps/mobile"]; });
  const run = makeFixture({ files: { "layers.json": JSON.stringify(LAYERS), "layer-plan.json": JSON.stringify(plan) } });
  t.after(run.cleanup);
  const result = readLayerPlan(run.root);
  assert.equal(result.ok, false);
  errorAt(result, "/layers/1/folders/0", /is not a folder of layers\.json/);
});

test("readLayerPlan reports a missing plan as an error result, not a throw", (t) => {
  const run = makeFixture({ files: { "layers.json": JSON.stringify(LAYERS) } });
  t.after(run.cleanup);
  const result = readLayerPlan(run.root);
  assert.equal(result.ok, false);
  errorAt(result, "", /^layer-plan\.json: cannot be read: ENOENT$/);
});

test("readLayerPlan reports a file that is not JSON as an error result", (t) => {
  const run = makeFixture({ files: { "layers.json": JSON.stringify(LAYERS), "layer-plan.json": "{ \"layers\": [ }" } });
  t.after(run.cleanup);
  const result = readLayerPlan(run.root);
  assert.equal(result.ok, false);
  errorAt(result, "", /^layer-plan\.json: not valid JSON: /);
});

test("readLayerPlan reports a layers.json that is not a layers.json as an error result", (t) => {
  const run = makeFixture({ files: { "layers.json": JSON.stringify({ schemaVersion: 2 }), "layer-plan.json": JSON.stringify(validPlan()) } });
  t.after(run.cleanup);
  const result = readLayerPlan(run.root);
  assert.equal(result.ok, false);
  errorAt(result, "", /^layers\.json is not a layers\.json: an object with schemaVersion 1/);
});

test("readLayerPlan needs an absolute folder", () => {
  assert.throws(() => readLayerPlan("relative/run"), TypeError);
  assert.throws(() => readLayerPlan(42), TypeError);
});

// The schema -------------------------------------------------------------------------------------

test("layer-plan schema: the fields are the ones the validator accepts", () => {
  assert.deepEqual(sorted(Object.keys(SCHEMA.properties)), sorted(PLAN_FIELDS));
  assert.deepEqual(sorted(Object.keys(SCHEMA.$defs.layer.properties)), sorted(LAYER_FIELDS));
});

test("layer-plan schema: unknown fields are errors at both levels", () => {
  assert.equal(SCHEMA.additionalProperties, false, "the plan");
  assert.equal(SCHEMA.$defs.layer.additionalProperties, false, "a layer");
});

test("layer-plan schema: the required fields and the version are the validator's", () => {
  assert.deepEqual(sorted(SCHEMA.required), sorted(PLAN_FIELDS));
  assert.deepEqual(sorted(SCHEMA.$defs.layer.required), sorted(REQUIRED_LAYER_FIELDS));
  assert.equal(SCHEMA.properties.schemaVersion.const, 1);
  assert.equal(SCHEMA.properties.layers.minItems, 1, "at least one layer");
});

test("layer-plan schema: the limits, the signal types and the uniqueness are the validator's", () => {
  const layer = SCHEMA.$defs.layer.properties;
  assert.equal(layer.name.maxLength, MAX_NAME_LENGTH);
  assert.equal(layer.reason.maxLength, MAX_REASON_LENGTH);
  assert.deepEqual(layer.signals.items.enum, [...SIGNAL_TYPES]);
  assert.equal(layer.folders.minItems, 1);
  assert.equal(layer.folders.uniqueItems, true);
  assert.equal(layer.signals.uniqueItems, true);
  assert.equal(layer.options.uniqueItems, true);
  assert.equal(layer.options.items.type, "string");
});
