import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { defaultOutputDir, formatStamp, isInside } from "../scripts/lib/target.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const EMPTY_FIXTURE = path.join(TEST_DIR, "fixtures", "empty");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "measurements.schema.json");
const PACKAGE_FILE = path.join(HARNESS_ROOT, "package.json");
// Top-level keys of every scan with the registered measures. The core writes the first five, the
// claude-config measure always writes claudeConfig and security, and the references measure writes instructions.
// The derive step of the CLI writes the last three.
const TOP_LEVEL_KEYS = [
  "candidates",
  "claudeConfig",
  "code",
  "context",
  "instructions",
  "inventory",
  "measuredFindings",
  "meta",
  "schemaVersion",
  "security",
  "structure",
  "target",
  "undeterminable",
  "verification",
  "warnings",
];
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");

// Runs the command line through execFile (never a shell). Resolves with the exit code and both streams.
async function runScan(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [SCAN_SCRIPT, ...args], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error; // The process did not start.
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

// A copy of test/fixtures/empty in a temp folder. The scanner refuses to scan the fixture in place.
function copyOfEmptyFixture(t) {
  const fixture = makeFixture({ fromDir: EMPTY_FIXTURE });
  t.after(fixture.cleanup);
  return { target: fixture.root, base: fixture.base };
}

// Removes the meta block from the raw text. In the output, meta is a top-level key, so its block
// ends at the first line that is exactly "  },".
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

// The forms a path can take in JSON text: as given, with forward slashes, and escaped as JSON.
function pathForms(folder) {
  const forms = new Set();
  for (const value of [folder, folder.replaceAll("\\", "/")]) {
    forms.add(value);
    forms.add(JSON.stringify(value).slice(1, -1));
  }
  return [...forms].filter((form) => form.length >= 4);
}

function gitFixture(t) {
  const fixture = makeFixture({ git: true, files: { "CLAUDE.md": "# Project\n" } });
  t.after(fixture.cleanup);
  return fixture;
}

test("scan: a copy of the empty fixture exits 0 with valid JSON and a short summary", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const out = path.join(base, "out");

  const result = await runScan([target, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, "");
  const summary = result.stdout.trimEnd().split("\n");
  assert.ok(summary.length <= 10, `the summary has ${summary.length} lines`);
  assert.match(result.stdout, /^target: repo$/m);
  assert.deepEqual(fs.readdirSync(out), ["measurements.json"], "only measurements.json is written");

  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  assert.deepEqual(Object.keys(data).sort(), TOP_LEVEL_KEYS);
  assert.equal(data.schemaVersion, 1);
  const { version } = JSON.parse(fs.readFileSync(PACKAGE_FILE, "utf8"));
  assert.equal(data.meta.tool, `harness-x-ray@${version}`);
  assert.match(data.meta.scannedAt, ISO_TIME);
  assert.equal(data.target.name, "repo");
  assert.equal(data.target.fileCount, 1, "the .gitkeep file is the only file");
  assert.deepEqual(data.inventory, []);
  assert.deepEqual(data.context.alwaysLoaded, {
    estTokensTotal: 0,
    estMethod: "chars/4",
    byComponent: [
      { component: "commands", estTokens: 0, items: [] },
      { component: "memory", estTokens: 0, items: [] },
      { component: "skills", estTokens: 0, items: [] },
      { component: "subagents", estTokens: 0, items: [] },
    ],
    unknownStatic: [],
  });
});

test("scan: two runs on the same copy give the same JSON, except meta", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const first = path.join(base, "first");
  const second = path.join(base, "second");
  assert.equal((await runScan([target, "--out", first])).code, 0);
  assert.equal((await runScan([target, "--out", second])).code, 0);

  const rawFirst = fs.readFileSync(path.join(first, "measurements.json"), "utf8");
  const rawSecond = fs.readFileSync(path.join(second, "measurements.json"), "utf8");
  const dataFirst = JSON.parse(rawFirst);
  const dataSecond = JSON.parse(rawSecond);
  assert.ok(dataFirst.meta.scannedAt && dataSecond.meta.scannedAt);
  delete dataFirst.meta;
  delete dataSecond.meta;
  assert.deepEqual(dataFirst, dataSecond);
  assert.equal(withoutMetaText(rawFirst), withoutMetaText(rawSecond));
});

test("scan: meta.targetRoot is the resolved path of the scanned folder, and the schema documents it", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const out = path.join(base, "out");
  assert.equal((await runScan([target, "--out", out])).code, 0);

  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  assert.equal(data.meta.targetRoot, fs.realpathSync.native(target));
  assert.ok(path.isAbsolute(data.meta.targetRoot));

  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.ok(schema.properties.meta.required.includes("targetRoot"));
  assert.equal(schema.properties.meta.properties.targetRoot.type, "string");
});

const INVALID_TARGETS = {
  "a missing folder": (base) => path.join(base, "missing"),
  "a file instead of a folder": (base) => path.join(base, "repo", "notes.txt"),
  "the fixture in place": () => EMPTY_FIXTURE,
  "harness-x-ray itself": () => HARNESS_ROOT,
  "the folder that contains harness-x-ray": () => path.dirname(HARNESS_ROOT),
};

for (const [name, locate] of Object.entries(INVALID_TARGETS)) {
  test(`scan: ${name} exits 2 and writes nothing`, async (t) => {
    const fixture = makeFixture({ files: { "notes.txt": "plain file\n" } });
    t.after(fixture.cleanup);
    const out = path.join(fixture.base, "out");

    const result = await runScan([locate(fixture.base), "--out", out]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /^error: /m);
    assert.equal(fs.existsSync(out), false);
  });
}

test("scan: harness-x-ray written with other letter case exits 2", { skip: process.platform === "win32" ? false : "letter case is only ignored on Windows" }, async (t) => {
  const fixture = makeFixture();
  t.after(fixture.cleanup);

  const result = await runScan([HARNESS_ROOT.toUpperCase(), "--out", path.join(fixture.base, "out")]);

  assert.equal(result.code, 2, result.stderr);
});

test("scan: missing target, unknown option, extra target or empty value exit 2", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const out = path.join(base, "out");
  const invalidArgs = [
    [],
    ["--out", out],
    [target, "--axes", "rul", "--out", out],
    [target, target, "--out", out],
    [target, "--out"],
    [target, "--out", ""],
    ["", "--out", out],
  ];
  for (const args of invalidArgs) {
    const result = await runScan(args);
    assert.equal(result.code, 2, `arguments ${JSON.stringify(args)}: ${result.stderr}`);
  }
  assert.equal(fs.existsSync(out), false);
});

test("scan: an output folder inside the target, or the target itself, exits 2", async (t) => {
  const { target } = copyOfEmptyFixture(t);

  const inside = await runScan([target, "--out", path.join(target, "out")]);
  const same = await runScan([target, "--out", target]);

  assert.equal(inside.code, 2, inside.stderr);
  assert.equal(same.code, 2, same.stderr);
  assert.deepEqual(fs.readdirSync(target), [".gitkeep"], "the target is left untouched");
});

test("scan: outside meta, measurements.json holds no absolute path of this machine", async (t) => {
  const fixture = makeFixture({
    git: true,
    files: {
      "CLAUDE.md": "# Project\n",
      "src/index.mjs": "export const value = 1;\n",
      "guides/setup.md": "Setup\n",
    },
  });
  t.after(fixture.cleanup);
  const out = path.join(fixture.base, "out");

  const result = await runScan([fixture.root, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  // The check means something only if the scan really read the fixture.
  const data = JSON.parse(raw);
  assert.equal(data.target.fileListSource, "git");
  assert.equal(data.target.fileCount, 3);
  assert.match(data.target.git.head, /^[0-9a-f]{40}$/);

  const body = withoutMetaText(raw);
  const folders = [
    fixture.base,
    fixture.root,
    fs.realpathSync.native(fixture.base),
    fs.realpathSync.native(fixture.root),
    HARNESS_ROOT,
    fs.realpathSync.native(HARNESS_ROOT),
    os.homedir(),
    os.tmpdir(),
  ];
  for (const folder of folders) {
    for (const form of pathForms(folder)) {
      assert.equal(body.includes(form), false, `an absolute path leaked: ${form}`);
    }
  }
});

test("scan: measures merge their sections deeply and share the inventory and warnings lists", async (t) => {
  const fixture = gitFixture(t);
  const measures = [
    {
      id: "alpha",
      collect: () => ({
        security: { permissions: { allow: ["Bash(npm test)"] } },
        inventory: [{ path: "b.md", kind: "memory" }],
        warnings: [
          { path: "z.md", reason: "binary", detail: "x" },
          { path: "z.md", reason: "binary", detail: "x" },
        ],
      }),
    },
    {
      id: "beta",
      collect: () => ({
        security: { hooks: [] },
        inventory: [{ path: "a.md", kind: "memory" }],
        warnings: [
          { path: "a.md", reason: "too-large" },
          { path: "z.md", reason: "binary", detail: "x" },
        ],
      }),
    },
    {
      id: "gamma",
      collect: (ctx) => {
        ctx.readText("../outside.txt");
        return {};
      },
    },
  ];

  const result = await scan({ root: fixture.root, measures, now: FIXED_NOW });
  const reversed = await scan({ root: fixture.root, measures: [...measures].reverse(), now: FIXED_NOW });

  assert.equal(result.meta.scannedAt, "2026-10-17T12:00:00.000Z");
  assert.deepEqual(result.security, { permissions: { allow: ["Bash(npm test)"] }, hooks: [] });
  assert.deepEqual(result.inventory, [
    { path: "a.md", kind: "memory" },
    { path: "b.md", kind: "memory" },
  ]);
  assert.deepEqual(result.warnings, [
    { source: "fs", path: "../outside.txt", reason: "outside-root" },
    { source: "beta", path: "a.md", reason: "too-large" },
    { source: "alpha", path: "z.md", reason: "binary", detail: "x" },
    { source: "beta", path: "z.md", reason: "binary", detail: "x" },
  ]);
  assert.equal(toStableJson(reversed), toStableJson(result), "the order of the measures does not change the output");
});

test("scan: the budget lists are shared, sorted, and the total is the sum of the components", async (t) => {
  const fixture = gitFixture(t);
  const measures = [
    {
      id: "one",
      collect: () => ({
        context: {
          alwaysLoaded: {
            byComponent: [{ component: "skills", estTokens: 7, items: [{ path: "b.md", estTokens: 7 }] }],
            unknownStatic: [{ kind: "mcp-server", source: ".mcp.json", name: "z" }],
          },
        },
      }),
    },
    {
      id: "two",
      collect: () => ({
        context: {
          alwaysLoaded: {
            byComponent: [{ component: "commands", estTokens: 3, items: [] }],
            unknownStatic: [{ kind: "mcp-server", source: ".mcp.json", name: "a" }],
          },
        },
      }),
    },
  ];

  const result = await scan({ root: fixture.root, measures, now: FIXED_NOW });

  assert.equal(result.context.alwaysLoaded.estTokensTotal, 10);
  assert.deepEqual(
    result.context.alwaysLoaded.byComponent.map((item) => item.component),
    ["commands", "skills"],
  );
  assert.deepEqual(
    result.context.alwaysLoaded.unknownStatic.map((item) => item.name),
    ["a", "z"],
  );
});

test("scan: two budget contributions for one component, or a measure that sets the total, fail", async (t) => {
  const fixture = gitFixture(t);
  const component = (name) => ({ component: name, estTokens: 1, items: [] });
  const twice = [
    { id: "one", collect: () => ({ context: { alwaysLoaded: { byComponent: [component("skills")] } } }) },
    { id: "two", collect: () => ({ context: { alwaysLoaded: { byComponent: [component("skills")] } } }) },
  ];
  const sameMeasure = [
    {
      id: "solo",
      collect: () => ({ context: { alwaysLoaded: { byComponent: [component("skills"), component("skills")] } } }),
    },
  ];
  const setsTotal = [{ id: "total", collect: () => ({ context: { alwaysLoaded: { estTokensTotal: 99 } } }) }];

  await assert.rejects(scan({ root: fixture.root, measures: twice, now: FIXED_NOW }), /adds component "skills"/);
  await assert.rejects(scan({ root: fixture.root, measures: sameMeasure, now: FIXED_NOW }), /adds component "skills"/);
  await assert.rejects(scan({ root: fixture.root, measures: setsTotal, now: FIXED_NOW }), /collides with the core at \/context\/alwaysLoaded\/estTokensTotal/);
});

test("scan: two measures that set the same value at one path make the scan fail", async (t) => {
  const fixture = gitFixture(t);
  const measures = [
    { id: "first", collect: () => ({ security: { mode: "default" } }) },
    { id: "second", collect: () => ({ security: { mode: "strict" } }) },
  ];
  await assert.rejects(
    scan({ root: fixture.root, measures, now: FIXED_NOW }),
    /Measure "second" collides with measure "first" at \/security\/mode/,
  );
});

test("scan: a measure cannot overwrite a value that the core writes", async (t) => {
  const fixture = gitFixture(t);
  const overwriteVersion = [{ id: "rogue", collect: () => ({ schemaVersion: 2 }) }];
  const overwriteTarget = [{ id: "rogue", collect: () => ({ target: "x" }) }];

  await assert.rejects(scan({ root: fixture.root, measures: overwriteVersion }), /collides with the core at \/schemaVersion/);
  await assert.rejects(scan({ root: fixture.root, measures: overwriteTarget }), /collides with the core at \/target/);
});

test("scan: malformed measures are refused, and a failing measure is named", async (t) => {
  const fixture = gitFixture(t);
  const cases = {
    "a duplicate id": [
      { id: "same", collect: () => ({}) },
      { id: "same", collect: () => ({}) },
    ],
    "a reserved id": [{ id: "fs", collect: () => ({}) }],
    "no collect function": [{ id: "bare" }],
    "a section that is not an object": [{ id: "list", collect: () => [] }],
    "a warning without a reason": [{ id: "warn", collect: () => ({ warnings: [{ path: "a.md" }] }) }],
    "inventory that is not a list": [{ id: "inv", collect: () => ({ inventory: {} }) }],
  };
  for (const [name, measures] of Object.entries(cases)) {
    await assert.rejects(scan({ root: fixture.root, measures, now: FIXED_NOW }), TypeError, name);
  }

  await assert.rejects(
    scan({ root: fixture.root, measures: [{ id: "boom", collect: () => { throw new Error("kaboom"); } }], now: FIXED_NOW }),
    /Measure "boom" failed: kaboom/,
  );
});

test("scan: readText gives one result per file and limit, shared by all measures", async (t) => {
  const fixture = gitFixture(t);
  const seen = {};
  const measures = [
    {
      id: "one",
      collect(ctx) {
        seen.first = ctx.readText("CLAUDE.md");
        seen.repeat = ctx.readText("./CLAUDE.md");
        return {};
      },
    },
    {
      id: "two",
      collect(ctx) {
        seen.second = ctx.readText("CLAUDE.md");
        seen.limited = ctx.readText("CLAUDE.md", { maxBytes: 4 });
        return {};
      },
    },
  ];

  await scan({ root: fixture.root, measures, now: FIXED_NOW });

  assert.equal(seen.first.ok, true);
  assert.equal(seen.first.text, "# Project\n");
  assert.strictEqual(seen.repeat, seen.first);
  assert.strictEqual(seen.second, seen.first);
  assert.notStrictEqual(seen.limited, seen.first);
  assert.deepEqual(seen.limited, { ok: false, path: "CLAUDE.md", reason: "too-large" });
});

test("scan: measures receive one file listing, the commit and the root", async (t) => {
  const fixture = gitFixture(t);
  const seen = {};
  const measures = [
    {
      id: "probe",
      collect(ctx) {
        seen.files = ctx.files.map((file) => file.path);
        seen.fileListSource = ctx.fileListSource;
        seen.commit = ctx.commit;
        seen.root = ctx.root;
        seen.memory = ctx.memory instanceof Map;
        return {};
      },
    },
  ];

  const result = await scan({ root: fixture.root, measures, now: FIXED_NOW });

  assert.deepEqual(seen.files, ["CLAUDE.md"]);
  assert.equal(seen.fileListSource, "git");
  assert.match(seen.commit, /^[0-9a-f]{40}$/);
  assert.equal(result.target.git.head, seen.commit);
  assert.equal(seen.root, fixture.root);
  assert.equal(seen.memory, true);
});

test("default output folder is runs/<name>-<local time> under harness-x-ray", () => {
  const now = new Date(2026, 9, 17, 8, 5, 3);
  assert.equal(formatStamp(now), "20261017-080503");
  assert.equal(
    defaultOutputDir({ harnessRoot: HARNESS_ROOT, targetName: "agent-atlas", now }),
    path.join(HARNESS_ROOT, "runs", "agent-atlas-20261017-080503"),
  );
});

test("containment compares path segments, not text", () => {
  const at = (...parts) => path.join(os.tmpdir(), "hxr-containment", ...parts);

  assert.equal(isInside(at("a", "b"), at("a", "b")), true);
  assert.equal(isInside(at("a", "b"), at("a", "b", "c")), true);
  assert.equal(isInside(at("a", "b"), at("a", "bc")), false);
  assert.equal(isInside(at("a", "b"), at("a", "b..c")), false);
  assert.equal(isInside(at("a", "b", "c"), at("a", "b")), false);
  assert.equal(isInside(at("a"), at("a", "..b")), true);
});

test("containment ignores letter case on Windows", { skip: process.platform === "win32" ? false : "Windows rule" }, () => {
  assert.equal(isInside("C:\\Repo", "c:\\repo\\x"), true);
  assert.equal(isInside("C:\\Repo", "D:\\Repo"), false);
});

test("the measurements schema documents every top-level key", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual([...schema.required].sort(), TOP_LEVEL_KEYS);
  assert.deepEqual(Object.keys(schema.properties).sort(), TOP_LEVEL_KEYS);
});

test("scan: derive gets a deep-frozen copy of the merged result and no context, and its keys are added", async (t) => {
  const fixture = gitFixture(t);
  const seen = {};
  const measures = [{ id: "alpha", collect: () => ({ security: { mode: "default" } }) }];
  function derive(merged, ...extra) {
    seen.extraArguments = extra.length;
    seen.frozen = Object.isFrozen(merged) && Object.isFrozen(merged.security);
    try {
      merged.security.mode = "changed";
      seen.mutated = true;
    } catch {
      seen.mutated = false;
    }
    return { measuredFindings: [{ id: "mf-1", rule: "TEST-01" }] };
  }

  const result = await scan({ root: fixture.root, measures, now: FIXED_NOW, derive });

  assert.deepEqual(seen, { extraArguments: 0, frozen: true, mutated: false });
  assert.equal(result.security.mode, "default", "the merged result is not changed by derive");
  assert.deepEqual(result.measuredFindings, [{ id: "mf-1", rule: "TEST-01" }]);
  assert.equal(Object.hasOwn(result, "candidates"), false, "only the keys that derive returns are added");
});

test("scan: a measure cannot set a derived key, derive cannot add an unknown key, and derive must return an object", async (t) => {
  const fixture = gitFixture(t);
  const sets = [{ id: "rogue", collect: () => ({ measuredFindings: [] }) }];
  await assert.rejects(
    scan({ root: fixture.root, measures: sets, now: FIXED_NOW }),
    /Measure "rogue" sets measuredFindings, which only the derive step writes/,
  );
  await assert.rejects(
    scan({ root: fixture.root, measures: [], now: FIXED_NOW, derive: () => ({ inventory: [] }) }),
    /derive returned "inventory", which is not a derived key/,
  );
  await assert.rejects(
    scan({ root: fixture.root, measures: [], now: FIXED_NOW, derive: () => [] }),
    /derive must return a plain object/,
  );
  await assert.rejects(scan({ root: fixture.root, measures: [], now: FIXED_NOW, derive: "x" }), /derive must be a function/);
});

test("scan: without derive, no derived key is written", async (t) => {
  const fixture = gitFixture(t);
  const result = await scan({ root: fixture.root, measures: [], now: FIXED_NOW });
  for (const key of ["candidates", "measuredFindings", "undeterminable"]) {
    assert.equal(Object.hasOwn(result, key), false, key);
  }
});
