import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { defaultOutputDir, formatStamp, isInside } from "../scripts/lib/target.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";
import { runRender } from "./helpers/report-run.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const RUNS_DIR = path.join(HARNESS_ROOT, "runs");
const SCRIPTS_DIR = path.join(HARNESS_ROOT, "scripts");
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;
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
// The working directory of the child is cwd when given, and the one of this process otherwise. The environment of the
// child is env when given (a test sets HOME and USERPROFILE to a fake home), and the one of this process otherwise.
async function runScan(args, { cwd, env } = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [SCAN_SCRIPT, ...args], {
      cwd,
      env,
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
  assert.match(inside.stderr, /^error: output folder is inside the target: /m);
  assert.match(same.stderr, /^error: output folder is inside the target: /m);
  assert.deepEqual(fs.readdirSync(target), [".gitkeep"], "the target is left untouched");
});

// A random name, so that a test never reuses a folder of an earlier run.
function randomName(prefix) {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

test("scan: an output folder in the repository but outside runs/ exits 2 and is not created", async (t) => {
  const { target } = copyOfEmptyFixture(t);
  const out = path.join(HARNESS_ROOT, "test", randomName("hxr-not-allowed"));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));

  const result = await runScan([target, "--out", out]);

  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /^error: folder must be inside runs\/ or the system temp folder: /m);
  assert.equal(fs.existsSync(out), false);
});

test("scan: an output folder inside runs/ exits 0 and is written", async (t) => {
  const { target } = copyOfEmptyFixture(t);
  const out = path.join(RUNS_DIR, randomName("hxr-test"));
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));

  const result = await runScan([target, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(fs.readdirSync(out), ["measurements.json"]);
});

test("scan: a relative output folder in runs/, run from the harness folder, exits 0 and is written", async (t) => {
  const { target } = copyOfEmptyFixture(t);
  const name = randomName("hxr-relative");
  const out = path.join(RUNS_DIR, name);
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));

  const result = await runScan([target, "--out", path.join("runs", name)], { cwd: HARNESS_ROOT });

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(fs.readdirSync(out), ["measurements.json"]);
});

test("scan: an output folder that is an existing regular file in runs/ exits 2, and the file is untouched", async (t) => {
  const { target } = copyOfEmptyFixture(t);
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  const file = path.join(RUNS_DIR, randomName("hxr-file"));
  fs.writeFileSync(file, "keep\n");
  t.after(() => fs.rmSync(file, { force: true }));

  const result = await runScan([target, "--out", file]);

  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /^error: not a folder: /m);
  assert.equal(fs.readFileSync(file, "utf8"), "keep\n");
});

test("scan: a link inside runs/ that points to a folder outside exits 2, and nothing is created behind it", { skip: symlinkSkip }, async (t) => {
  const { target } = copyOfEmptyFixture(t);
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  const link = path.join(RUNS_DIR, randomName("hxr-link"));
  fs.symlinkSync(SCRIPTS_DIR, link, "dir");
  t.after(() => fs.unlinkSync(link));
  const behind = randomName("hxr-behind");
  t.after(() => fs.rmSync(path.join(SCRIPTS_DIR, behind), { recursive: true, force: true }));

  const result = await runScan([target, "--out", path.join(link, behind)]);

  assert.equal(result.code, 2, result.stderr);
  assert.equal(fs.existsSync(path.join(SCRIPTS_DIR, behind)), false);
});

test("scan: a dangling link inside runs/ exits 2, and mkdir does not create the folder it points to", { skip: symlinkSkip }, async (t) => {
  const { target } = copyOfEmptyFixture(t);
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  const missing = randomName("hxr-missing");
  const link = path.join(RUNS_DIR, randomName("hxr-dangling"));
  fs.symlinkSync(path.join(SCRIPTS_DIR, missing), link, "dir");
  t.after(() => fs.unlinkSync(link));
  t.after(() => fs.rmSync(path.join(SCRIPTS_DIR, missing), { recursive: true, force: true }));

  const result = await runScan([target, "--out", path.join(link, "sub")]);

  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /broken symbolic link/);
  assert.equal(fs.existsSync(path.join(SCRIPTS_DIR, missing)), false);
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

// The top-level key that only an opt-in flag writes (--include-user-layer). The schema documents it, but does not require it.
const OPT_IN_KEYS = ["userLayer"];

test("the measurements schema documents every top-level key", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.deepEqual([...schema.required].sort(), TOP_LEVEL_KEYS);
  assert.deepEqual(Object.keys(schema.properties).sort(), [...TOP_LEVEL_KEYS, ...OPT_IN_KEYS].sort());
});

test("the schema marks the opt-in fields as optional, and documents the fields of the user layer and of the ancestors", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.equal(schema.required.includes("userLayer"), false);
  assert.deepEqual(schema.properties.meta.required, ["scannedAt", "targetRoot", "tool"]);
  assert.deepEqual(Object.keys(schema.properties.meta.properties.include.properties).sort(), ["ancestors", "userLayer"]);
  const ancestorItem = schema.properties.context.properties.ancestors.items;
  assert.deepEqual(ancestorItem.required, ["path", "bytes"]);
  assert.deepEqual(
    Object.keys(ancestorItem.properties).sort(),
    ["bytes", "estTokens", "lines", "loadMode", "loadReason", "path", "read", "reason"],
  );
  assert.deepEqual(
    schema.properties.userLayer.required,
    ["root", "found", "memory", "settings", "skills", "subagents", "warnings", "notes"],
  );
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

test("scan: meta.include is written only when include is given, and a malformed include is refused", async (t) => {
  const fixture = gitFixture(t);
  const without = await scan({ root: fixture.root, measures: [], now: FIXED_NOW });
  assert.equal(Object.hasOwn(without.meta, "include"), false);

  const withFlags = await scan({ root: fixture.root, measures: [], now: FIXED_NOW, include: { userLayer: true, ancestors: false } });
  assert.deepEqual(withFlags.meta.include, { userLayer: true, ancestors: false });
  await assert.rejects(
    scan({ root: fixture.root, measures: [], now: FIXED_NOW, include: { userLayer: "yes", ancestors: false } }),
    /include must be \{ userLayer: boolean, ancestors: boolean \}/,
  );
});

test("scan: ctx.outside starts empty, and a measure that fills it is seen by the measures after it", async (t) => {
  const fixture = gitFixture(t);
  const seen = [];
  const measures = [
    {
      id: "fills",
      collect(ctx) {
        seen.push(ctx.outside.size);
        ctx.outside.set("user", { permissions: { allow: [], ask: [], deny: [] } });
        return {};
      },
    },
    {
      id: "reads",
      collect(ctx) {
        seen.push(ctx.outside.has("user"));
        return {};
      },
    },
  ];

  await scan({ root: fixture.root, measures, now: FIXED_NOW });

  assert.deepEqual(seen, [0, true]);
});

// The user-layer flags of the CLI tests. WITNESS sits in a file of the fake home that no measure reads.
const WITNESS = "WITNESS-CLI-USER-LAYER-91c2";
const RM_RULE = "Bash(rm:*)";

// A target and a fake home in the temp folder. The home holds a user allow for rm, and a witness in a projects file. Without
// withClaude the home has no .claude folder. The home is <base>/outside/home.
function userHomeCase(t, { withClaude = true } = {}) {
  const outside = { "home/README.txt": "A fake home folder.\n" };
  if (withClaude) {
    outside["home/.claude/settings.json"] = JSON.stringify({ permissions: { allow: [RM_RULE] } });
    outside["home/.claude/projects/p/x.jsonl"] = `${WITNESS}\n`;
  }
  const fixture = makeFixture({ files: { "README.md": "# Target\n" }, outside });
  t.after(fixture.cleanup);
  return { target: fixture.root, base: fixture.base, home: path.join(fixture.outsideDir, "home") };
}

// The environment of the child: the fake home is its home folder on POSIX (HOME) and on Windows (USERPROFILE).
function envWithHome(home) {
  return { ...process.env, HOME: home, USERPROFILE: home };
}

// The outcome of the rm command in the measurements of a scan.
function rmOf(data) {
  return data.security.destructiveCoverage.commands.find((command) => command.id === "rm-recursive-force");
}

test("scan: without the flags, ~/.claude is not read: a user allow changes nothing, the witness is absent, and no user section is written", async (t) => {
  const withClaude = userHomeCase(t);
  const withoutClaude = userHomeCase(t, { withClaude: false });
  const out = path.join(withClaude.base, "out");
  const outBaseline = path.join(withoutClaude.base, "out");

  const result = await runScan([withClaude.target, "--out", out], { env: envWithHome(withClaude.home) });
  const baseline = await runScan([withoutClaude.target, "--out", outBaseline], { env: envWithHome(withoutClaude.home) });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(baseline.code, 0, baseline.stderr);
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  const data = JSON.parse(raw);
  const baselineData = JSON.parse(fs.readFileSync(path.join(outBaseline, "measurements.json"), "utf8"));
  assert.equal(Object.hasOwn(data, "userLayer"), false);
  assert.equal(Object.hasOwn(data.meta, "include"), false);
  assert.equal(raw.includes(WITNESS), false, "the witness of the fake home is never read");
  assert.equal(rmOf(data).outcome, rmOf(baselineData).outcome, "the user allow does not change the outcome");
  assert.equal(rmOf(data).outcome, "asks", "positive control: the removal asks, as with an empty home");
});

test("scan: --include-user-layer reads ~/.claude, and a user allow passes the rm command, attributed to the user layer", async (t) => {
  const { target, base, home } = userHomeCase(t);
  const out = path.join(base, "out");

  const result = await runScan([target, "--out", out, "--include-user-layer"], { env: envWithHome(home) });

  assert.equal(result.code, 0, result.stderr);
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  const data = JSON.parse(raw);
  assert.equal(data.userLayer.found, true);
  assert.deepEqual(data.meta.include, { userLayer: true, ancestors: false });
  assert.equal(rmOf(data).outcome, "passes");
  assert.deepEqual(rmOf(data).decidedBy, {
    kind: "rule",
    list: "allow",
    rule: RM_RULE,
    source: "~/.claude/settings.json",
    layer: "user",
  });
  assert.equal(raw.includes(WITNESS), false, "the projects folder is not read, even with the flag");
  assert.equal(raw.includes(home), false, "the home folder is not written");
});

test("scan: --include-ancestors reads the memory file of the parent folder, and meta.include records the flag", async (t) => {
  const { target, base, home } = userHomeCase(t, { withClaude: false });
  // The target is <base>/repo, so its parent folder is <base>.
  fs.writeFileSync(path.join(base, "CLAUDE.md"), "# Parent memory\n\nRead me.\n");
  const out = path.join(base, "out");
  const outPlain = path.join(base, "out-plain");

  const result = await runScan([target, "--out", out, "--include-ancestors"], { env: envWithHome(home) });
  const plain = await runScan([target, "--out", outPlain], { env: envWithHome(home) });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(plain.code, 0, plain.stderr);
  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  const plainData = JSON.parse(fs.readFileSync(path.join(outPlain, "measurements.json"), "utf8"));
  assert.deepEqual(data.meta.include, { userLayer: false, ancestors: true });
  // The walk goes up to the file system root, so only the item of the fixture's own parent folder is asserted.
  const parent = data.context.ancestors.find((item) => item.path === "../CLAUDE.md");
  assert.equal(parent.read, true);
  assert.equal(parent.lines, 3);
  const plainParent = plainData.context.ancestors.find((item) => item.path === "../CLAUDE.md");
  assert.equal(Object.hasOwn(plainParent, "read"), false, "positive control: without the flag the file is listed by size only");
  assert.equal(Object.hasOwn(plainData.meta, "include"), false);
});

test("scan: an unknown flag still exits 2, and the usage line names the two opt-in flags", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const out = path.join(base, "out");

  const result = await runScan([target, "--out", out, "--include-everything"]);

  assert.equal(result.code, 2);
  assert.equal(
    result.stderr.trimEnd().split("\n").at(-1),
    "usage: node scripts/scan.mjs <target> [--out <dir>] [--include-user-layer] [--include-ancestors]",
  );
  assert.equal(fs.existsSync(out), false);
});

// Reads a JSON file of a run folder.
function readRunJson(dir, name) {
  return JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
}

// The end to end path of the user layer: the scan with the flag, a findings.json made from the measured finding that cites
// the user's settings, and the report. The positive control is the same target and fake home without the flag.
test("scan e2e: a user allow of rm is attributed to the user layer in the report, which says the layer was read (positive control: without the flag)", async (t) => {
  const { target, base, home } = userHomeCase(t);
  const withFlag = path.join(base, "run-user");
  const withoutFlag = path.join(base, "run-plain");
  const labels = loadLabels(HARNESS_ROOT, "en");
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));

  const scanned = await runScan([target, "--out", withFlag, "--include-user-layer"], { env: envWithHome(home) });
  const plain = await runScan([target, "--out", withoutFlag], { env: envWithHome(home) });
  assert.equal(scanned.code, 0, scanned.stderr);
  assert.equal(plain.code, 0, plain.stderr);

  const data = readRunJson(withFlag, "measurements.json");
  assert.deepEqual(Object.keys(data.userLayer).sort(), [...schema.properties.userLayer.required].sort());
  const sec02 = data.measuredFindings.find(
    (item) => item.rule === "SEC-02" && item.evidence.some((entry) => entry.layer === "user"),
  );
  assert.ok(sec02, "a SEC-02 finding cites the user's settings with layer user");
  const userEvidence = sec02.evidence.filter((entry) => entry.layer === "user");
  assert.deepEqual(userEvidence, [{ file: "~/.claude/settings.json", layer: "user" }]);

  // The findings are made from the measured finding: its id, its impact and its user evidence, with the agent's text.
  const findings = {
    findings: [
      {
        rule: "SEC-02",
        axis: "security",
        kind: "measured",
        measuredFindingId: sec02.id,
        evidence: userEvidence,
        impact: sec02.impact,
        summary: "The user's settings allow rm without a prompt, and the project does not ask for it.",
        recommendation: "Remove the rm allow rule from ~/.claude/settings.json, or put Bash(rm:*) in the project's ask list.",
        testInFunction2: null,
      },
    ],
  };
  fs.writeFileSync(path.join(withFlag, "findings.json"), `${JSON.stringify(findings, null, 2)}\n`);

  const rendered = await runRender([withFlag]);
  assert.equal(rendered.code, 0, rendered.stderr);
  const report = fs.readFileSync(path.join(withFlag, "report.md"), "utf8");
  assert.ok(report.includes(`\`~/.claude/settings.json\` (${labels["layer.user"]})`), "the evidence is not marked as user layer");
  assert.ok(report.includes(labels["limits.readUser"]), "the limits do not say that the user layer was read");
  assert.equal(report.includes(labels["limits.notRead"]), false);
  assert.equal(report.includes(home), false, "the home folder is written to the report");

  // Positive control: the same target and fake home without the flag. No user evidence exists, and the limits keep the
  // statement that the user layer was not read.
  const plainData = readRunJson(withoutFlag, "measurements.json");
  assert.equal(Object.hasOwn(plainData, "userLayer"), false);
  assert.equal(
    plainData.measuredFindings.some((item) => item.evidence.some((entry) => entry.layer === "user")),
    false,
    "without the flag, no finding cites the user layer",
  );
  fs.writeFileSync(path.join(withoutFlag, "findings.json"), `${JSON.stringify({ findings: [] })}\n`);
  const plainRendered = await runRender([withoutFlag]);
  assert.equal(plainRendered.code, 0, plainRendered.stderr);
  const plainReport = fs.readFileSync(path.join(withoutFlag, "report.md"), "utf8");
  assert.ok(plainReport.includes(labels["limits.notRead"]), "the limits do not keep the not-read statement");
  assert.equal(plainReport.includes(labels["limits.readUser"]), false);
  assert.equal(plainReport.includes(labels["layer.user"]), false);
});
