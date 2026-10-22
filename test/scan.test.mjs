import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { loadRules } from "../scripts/lib/findings-validate.mjs";
import { DEPTHS as INTAKE_PAGE_DEPTHS } from "../scripts/lib/intake-page.mjs";
import { DEPTHS as INTAKE_DEPTHS } from "../scripts/lib/intake-server.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { DEFAULT_DEPTH as REPORT_DEFAULT_DEPTH } from "../scripts/lib/report.mjs";
import { catalogVersion } from "../scripts/lib/report-catalog.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";
import { DEFAULT_DEPTH, DEPTHS, scan } from "../scripts/lib/scanner.mjs";
import { defaultOutputDir, formatStamp, isInside } from "../scripts/lib/target.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";
import { runRender } from "./helpers/report-run.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

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
// claude-config measure always writes claudeConfig and security, the references measure writes instructions, and the
// agent-harness measure writes agentHarness. The derive step of the CLI writes the last three.
const TOP_LEVEL_KEYS = [
  "agentHarness",
  "candidates",
  "claudeConfig",
  "code",
  "context",
  "depth",
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
  assert.deepEqual(data.meta.catalog, catalogVersion(HARNESS_ROOT, loadRules(HARNESS_ROOT)), "meta.catalog is the catalog of this harness");
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
const OPT_IN_KEYS = ["scope", "userLayer"];

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

test("scan: a depth that is not one of the depth levels is a TypeError, and each level is written as given (positive control)", async (t) => {
  const fixture = gitFixture(t);
  for (const depth of ["fast", "Deep", null]) {
    await assert.rejects(
      scan({ root: fixture.root, measures: [], now: FIXED_NOW, depth }),
      (error) => error instanceof TypeError && error.message === "depth must be one of quick, standard, deep",
      `depth ${String(depth)} is refused`,
    );
  }
  for (const depth of DEPTHS) {
    const result = await scan({ root: fixture.root, measures: [], now: FIXED_NOW, depth });
    assert.equal(result.depth, depth, "positive control: each level is written as given");
  }
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

test("scan: an unknown flag still exits 2, and the usage line names the opt-in flags, --scope and --layers", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const out = path.join(base, "out");

  const result = await runScan([target, "--out", out, "--include-everything"]);

  assert.equal(result.code, 2);
  assert.equal(
    result.stderr.trimEnd().split("\n").at(-1),
    "usage: node scripts/scan.mjs <target> [--out <dir>] [--include-user-layer] [--include-ancestors] [--scope <folder>]... [--layers <runDir>] [--depth quick|standard|deep]",
  );
  assert.equal(fs.existsSync(out), false);
});

// Reads a JSON file of a run folder.
function readRunJson(dir, name) {
  return JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
}

// A copy of a versioned fixture in a temp folder. The scanner refuses a target inside this repository.
function copyOfFixture(t, name) {
  const fixture = makeFixture({ fromDir: path.join(TEST_DIR, "fixtures", name) });
  t.after(fixture.cleanup);
  return fixture;
}

// The measurements without the keys that may differ between two depths of one scan: depth itself and meta.
function withoutDepthAndMeta(data) {
  const { depth, meta, ...rest } = data;
  return rest;
}

// The environment of the depth tests: a fake home folder in the fixture's temp folder, so no test reads the real HOME.
function depthEnv(base) {
  const home = path.join(base, "home");
  fs.mkdirSync(home);
  return envWithHome(home);
}

test("depth: standard is the default, quick and deep are written as given, and the schema lists the three levels", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const env = depthEnv(base);
  const plain = path.join(base, "plain");
  const quick = path.join(base, "quick");
  const deep = path.join(base, "deep");

  assert.equal((await runScan([target, "--out", plain], { env })).code, 0);
  assert.equal((await runScan([target, "--out", quick, "--depth", "quick"], { env })).code, 0);
  assert.equal((await runScan([target, "--out", deep, "--depth", "deep"], { env })).code, 0);

  assert.equal(measurementsIn(plain).depth, "standard");
  assert.equal(measurementsIn(quick).depth, "quick");
  assert.equal(measurementsIn(deep).depth, "deep");
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.deepEqual(schema.properties.depth.enum, ["quick", "standard", "deep"]);
  assert.ok(schema.required.includes("depth"), "every scan writes depth, so the schema requires it");
});

test("depth: the schema enum, the default of the report, the depth labels and the intake lists all agree with DEPTHS", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.deepEqual(schema.properties.depth.enum, [...DEPTHS]);
  assert.equal(REPORT_DEFAULT_DEPTH, DEFAULT_DEPTH, "the report reads a scan without depth as the scanner's default");
  for (const file of ["labels.en.json", "labels.es.json"]) {
    const labels = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "templates", file), "utf8"));
    for (const level of DEPTHS) assert.equal(typeof labels[`depth.${level}`], "string", `${file} has depth.${level}`);
  }
  assert.deepEqual([...INTAKE_DEPTHS], [...DEPTHS], "intake-server.mjs offers the depths of the scanner");
  assert.deepEqual([...INTAKE_PAGE_DEPTHS], [...DEPTHS], "intake-page.mjs draws the depths of the scanner");
});

test("depth: a value that is missing or is not quick, standard or deep exits 2, names the three levels, and writes nothing", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const env = depthEnv(base);
  const cases = [
    [["--depth", "fast"], /the --depth value must be quick, standard or deep, not "fast"$/m],
    [["--depth", "Deep"], /not "Deep"$/m],
    [["--depth="], /the --depth value must be quick, standard or deep, not ""$/m],
    [["--depth"], /^error: the --depth value must be quick, standard or deep$/m],
  ];
  for (const [index, [flags, pattern]] of cases.entries()) {
    const out = path.join(base, `out-${index}`);

    const result = await runScan([target, "--out", out, ...flags], { env });

    assert.equal(result.code, 2, `${flags.join(" ")}: ${result.stderr}`);
    assert.match(result.stderr, pattern, flags.join(" "));
    assert.equal(result.stderr.trimEnd().split("\n").at(-1).startsWith("usage: node scripts/scan.mjs"), true);
    assert.equal(fs.existsSync(out), false, "nothing is written");
  }
  // Positive control: the same command with a valid value exits 0.
  const valid = await runScan([target, "--out", path.join(base, "valid"), "--depth", "standard"], { env });
  assert.equal(valid.code, 0, valid.stderr);
});

test("depth: a --depth given more than once exits 2 and writes nothing, and a single --depth deep exits 0 (positive control)", async (t) => {
  const { target, base } = copyOfEmptyFixture(t);
  const env = depthEnv(base);
  const cases = [
    ["--depth", "quick", "--depth", "deep"],
    ["--depth", "deep", "--depth", "deep"],
    ["--depth", "fast", "--depth", "deep"],
  ];
  for (const [index, flags] of cases.entries()) {
    const out = path.join(base, `repeat-${index}`);

    const result = await runScan([target, "--out", out, ...flags], { env });

    assert.equal(result.code, 2, `${flags.join(" ")}: ${result.stderr}`);
    assert.match(result.stderr, /^error: the --depth option was given more than once$/m, flags.join(" "));
    assert.equal(fs.existsSync(out), false, "nothing is written");
  }
  // --depth followed by another option has no value: parseArgs refuses it, and the message names the levels.
  const noValue = path.join(base, "out-no-value");
  const missing = await runScan([target, "--depth", "--out", noValue], { env });
  assert.equal(missing.code, 2, missing.stderr);
  assert.match(missing.stderr, /^error: the --depth value must be quick, standard or deep$/m);
  assert.equal(fs.existsSync(noValue), false, "nothing is written");
  // Positive control: a single --depth deep exits 0 and is written as deep.
  const single = path.join(base, "out-single");
  const valid = await runScan([target, "--out", single, "--depth", "deep"], { env });
  assert.equal(valid.code, 0, valid.stderr);
  assert.equal(measurementsIn(single).depth, "deep");
});

test("depth: quick makes the same measures as standard, so the two measurements differ only in depth and meta", async (t) => {
  for (const name of ["permissive", "duplicated"]) {
    const fixture = copyOfFixture(t, name);
    const env = depthEnv(fixture.base);
    const quick = path.join(fixture.base, "quick");
    const standard = path.join(fixture.base, "standard");

    assert.equal((await runScan([fixture.root, "--out", quick, "--depth", "quick"], { env })).code, 0);
    assert.equal((await runScan([fixture.root, "--out", standard, "--depth", "standard"], { env })).code, 0);

    const quickData = measurementsIn(quick);
    const standardData = measurementsIn(standard);
    assert.notEqual(quickData.depth, standardData.depth, `${name}: positive control, the depth differs`);
    assert.deepEqual(withoutDepthAndMeta(quickData), withoutDepthAndMeta(standardData), name);
    assert.ok(standardData.code.duplication.groups.length > 0 || standardData.inventory.length > 0, `${name}: has content to compare`);
  }
});

test("depth: deep reads nothing from the fake home or the parent folders without the flags, and each flag reads its own (positive controls)", async (t) => {
  const withClaude = userHomeCase(t);
  // The target is <base>/repo, so the parent folder of the target is <base>, and it holds a memory file that --include-ancestors reads.
  fs.writeFileSync(path.join(withClaude.base, "CLAUDE.md"), "# Parent memory\n\nPARENT-WITNESS-DEEP-7d3a\n");
  const env = envWithHome(withClaude.home);
  const out = path.join(withClaude.base, "out");

  const result = await runScan([withClaude.target, "--out", out, "--depth", "deep"], { env });

  assert.equal(result.code, 0, result.stderr);
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  const data = JSON.parse(raw);
  assert.equal(data.depth, "deep");
  assert.equal(Object.hasOwn(data, "userLayer"), false);
  assert.equal(Object.hasOwn(data.meta, "include"), false);
  assert.equal(raw.includes(WITNESS), false, "the witness of the fake home is never read");
  // context.ancestors lists the parent folders by existence and size. Without --include-ancestors no item is read.
  assert.notEqual(data.context.ancestors.find((item) => item.path === "../CLAUDE.md"), undefined, "the parent CLAUDE.md is listed");
  assert.equal(data.context.ancestors.some((item) => Object.hasOwn(item, "read")), false, "no parent folder is read");
  assert.equal(rmOf(data).outcome, "asks", "without the user allow, the removal asks by default");

  // Positive control: --include-ancestors reads the parent CLAUDE.md, so its item has read true and its counts. The text is counted, never kept.
  const withAncestors = path.join(withClaude.base, "out-ancestors");
  const ancestors = await runScan([withClaude.target, "--out", withAncestors, "--depth", "deep", "--include-ancestors"], { env });
  assert.equal(ancestors.code, 0, ancestors.stderr);
  const ancestorsRaw = fs.readFileSync(path.join(withAncestors, "measurements.json"), "utf8");
  const readParent = JSON.parse(ancestorsRaw).context.ancestors.find((item) => item.path === "../CLAUDE.md");
  assert.notEqual(readParent, undefined, "the parent CLAUDE.md is listed");
  assert.equal(readParent.read, true, "positive control: the flag reads the parent CLAUDE.md");
  assert.equal(readParent.lines, 3);
  assert.equal(ancestorsRaw.includes("PARENT-WITNESS-DEEP-7d3a"), false, "the parent text is counted, never kept");

  const withFlag = path.join(withClaude.base, "out-flag");
  const flagged = await runScan([withClaude.target, "--out", withFlag, "--depth", "deep", "--include-user-layer"], { env });
  assert.equal(flagged.code, 0, flagged.stderr);
  const flaggedData = measurementsIn(withFlag);
  assert.equal(flaggedData.userLayer.found, true, "positive control: the flag makes the user layer read");
  assert.equal(rmOf(flaggedData).outcome, "passes");
});

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

// ---------------------------------------------------------------------------------------------------
// --scope on the command line

// A monorepo with a root harness (CLAUDE.md, AGENTS.md, .claude/settings.json) and a harness in apps/web and in apps/api.
const SCOPE_MONOREPO = {
  "package.json": JSON.stringify({ name: "mono", private: true, workspaces: ["packages/*", "apps/*"] }),
  "README.md": "# Mono\n",
  "CLAUDE.md": "# Mono\n\nRun the tests.\n",
  "AGENTS.md": "# Mono agents\n",
  ".claude/settings.json": `${JSON.stringify({ permissions: { allow: ["Read(README.md)"] } })}\n`,
  "packages/a/package.json": '{"name":"a"}\n',
  "packages/a/src/index.ts": "export const a = 1;\n",
  "packages/b/package.json": '{"name":"b"}\n',
  "packages/b/src/index.ts": "export const b = 2;\n",
  "apps/web/package.json": '{"name":"web"}\n',
  "apps/web/src/App.tsx": "export const App = () => null;\n",
  "apps/web/AGENTS.md": "# Web\n\nKeep components small.\n",
  "apps/web/.agents/skills/x/SKILL.md": "---\nname: x\ndescription: The x skill.\n---\nSteps.\n",
  "apps/api/AGENTS.md": "# API\n",
};

// The measurements that a scan wrote to its output folder.
function measurementsIn(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, "measurements.json"), "utf8"));
}

test("scan: --scope apps/web keeps the root harness and the harness of apps/web, and leaves out the nested harness of apps/api", async (t) => {
  const fixture = makeFixture({ files: SCOPE_MONOREPO });
  t.after(fixture.cleanup);
  const out = path.join(fixture.base, "out");

  const result = await runScan([fixture.root, "--out", out, "--scope", "apps/web"]);

  assert.equal(result.code, 0, result.stderr);
  const data = measurementsIn(out);
  assert.deepEqual(schemaProblems(JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8")), data), [], "the output matches the schema");
  assert.ok(data.inventory.some((item) => item.path === "CLAUDE.md"), "the root CLAUDE.md is in the inventory");
  assert.ok(data.inventory.some((item) => item.path === "AGENTS.md"), "the root AGENTS.md is in the inventory");
  assert.equal(data.inventory.some((item) => item.path === "apps/api/AGENTS.md"), false, "apps/api is outside the scope");
  const files = new Map(data.agentHarness.files.map((file) => [file.path, file]));
  for (const rel of [".claude/settings.json", "CLAUDE.md", "AGENTS.md", "apps/web/AGENTS.md"]) {
    assert.ok(files.has(rel), `${rel} is listed in agentHarness.files`);
  }
  assert.equal(files.get("apps/web/AGENTS.md").read, true);
  assert.equal(files.has("apps/api/AGENTS.md"), false);
  // The skill below apps/web is found by matching the registry below its harness folder: its pair has a base and an unknown status.
  const skillPairs = data.agentHarness.items.filter((item) => item.path === "apps/web/.agents/skills/x/SKILL.md");
  assert.deepEqual(skillPairs.map((item) => [item.agent, item.status, item.base]), [["agents-md", "unknown", "apps/web"]]);
  assert.deepEqual(data.scope, {
    folders: ["apps/web"],
    inherited: [".", "apps"],
    files: { inScope: 4, outside: data.target.fileCount - 4 },
  });

  // Positive control: without --scope there is no scope section, the nested AGENTS.md is listed and not read, and the skill has no pair.
  const plainOut = path.join(fixture.base, "out-plain");
  const plain = await runScan([fixture.root, "--out", plainOut]);
  assert.equal(plain.code, 0, plain.stderr);
  const plainData = measurementsIn(plainOut);
  assert.equal(Object.hasOwn(plainData, "scope"), false);
  const plainFiles = new Map(plainData.agentHarness.files.map((file) => [file.path, file]));
  assert.equal(plainFiles.get("apps/web/AGENTS.md").read, false);
  assert.ok(plainFiles.has("apps/api/AGENTS.md"), "without a scope apps/api/AGENTS.md is listed");
  assert.equal(plainData.agentHarness.items.some((item) => item.path === "apps/web/.agents/skills/x/SKILL.md"), false);
});

test("scan: --scope with a missing folder, a folder that leaves the target, an absolute path or a file exits 2 and writes nothing", async (t) => {
  const fixture = makeFixture({ files: SCOPE_MONOREPO });
  t.after(fixture.cleanup);
  const refused = ["missing", "../x", path.join(fixture.root, "apps", "web"), "README.md"];

  for (const [index, folder] of refused.entries()) {
    const out = path.join(fixture.base, `out-${index}`);
    const result = await runScan([fixture.root, "--out", out, "--scope", folder]);
    assert.equal(result.code, 2, `--scope ${folder}: ${result.stderr}`);
    assert.equal(fs.existsSync(out), false, `nothing is written for --scope ${folder}`);
  }
  // Positive control: a valid folder with the same flags exits 0 and writes the file.
  const valid = path.join(fixture.base, "out-valid");
  const result = await runScan([fixture.root, "--out", valid, "--scope", "apps/web"]);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(fs.existsSync(path.join(valid, "measurements.json")), true);
});

test("scan: --scope with --include-ancestors reads the same parent folders as --include-ancestors alone", async (t) => {
  const fixture = makeFixture({ files: SCOPE_MONOREPO, outside: { "home/README.txt": "A fake home folder.\n" } });
  t.after(fixture.cleanup);
  // The target is <base>/repo, so its parent folder is <base>.
  fs.writeFileSync(path.join(fixture.base, "CLAUDE.md"), "# Parent memory\n\nRead me.\n");
  const env = envWithHome(path.join(fixture.outsideDir, "home"));
  const scopedOut = path.join(fixture.base, "out-scoped");
  const plainOut = path.join(fixture.base, "out-plain");

  const scoped = await runScan([fixture.root, "--out", scopedOut, "--scope", "apps/web", "--include-ancestors"], { env });
  const plain = await runScan([fixture.root, "--out", plainOut, "--include-ancestors"], { env });

  assert.equal(scoped.code, 0, scoped.stderr);
  assert.equal(plain.code, 0, plain.stderr);
  const scopedData = measurementsIn(scopedOut);
  const plainData = measurementsIn(plainOut);
  assert.deepEqual(scopedData.context.ancestors, plainData.context.ancestors, "the parent folders are the target's, not the scope's");
  const parent = scopedData.context.ancestors.find((item) => item.path === "../CLAUDE.md");
  assert.equal(parent.read, true);
  assert.equal(parent.lines, 3);
  assert.deepEqual(scopedData.meta.include, { userLayer: false, ancestors: true });
});

// ---------------------------------------------------------------------------------------------------
// --layers on the command line

// A monorepo with a harness in apps/web only, and the layer plan of a map run for it.
const LAYERED_MONOREPO = {
  "package.json": JSON.stringify({ name: "mono", private: true, workspaces: ["apps/*"] }),
  "CLAUDE.md": "# Mono\n\nRun the tests.\n",
  "apps/web/package.json": '{"name":"web"}\n',
  "apps/web/src/App.tsx": "export const App = () => null;\n",
  "apps/web/CLAUDE.md": "# Web\n\nUse the web conventions.\n",
  "apps/api/package.json": '{"name":"api"}\n',
  "apps/api/src/server.ts": "export const server = 1;\n",
};
const LAYER_FOLDERS = [".", "apps", "apps/api", "apps/web"];
const LAYER_PLAN = {
  schemaVersion: 1,
  layers: [
    { name: "web", folders: ["apps/web"], reason: "package.json in apps/web" },
    { name: "api", folders: ["apps/api"], reason: "package.json in apps/api" },
  ],
};

// A run folder inside the fixture, with a layers.json and a layer-plan.json. A plan of null writes no layer-plan.json. The
// layers.json names the target by its real path, unless targetRoot says another folder.
function layerRunOf(fixture, { plan = LAYER_PLAN, folders = LAYER_FOLDERS, targetRoot = fs.realpathSync.native(fixture.root) } = {}) {
  const runDir = fs.mkdtempSync(path.join(fixture.base, "run-"));
  const layers = {
    schemaVersion: 1,
    meta: { tool: "harness-x-ray", mappedAt: FIXED_NOW.toISOString(), targetRoot },
    structure: "units",
    units: [],
    workspaces: [],
    tree: { path: ".", files: 0, children: [], truncated: false },
    folders,
    suggestion: null,
    warnings: [],
  };
  fs.writeFileSync(path.join(runDir, "layers.json"), `${JSON.stringify(layers, null, 2)}\n`);
  if (plan !== null) fs.writeFileSync(path.join(runDir, "layer-plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
  return runDir;
}

test("scan: --layers with a valid run folder adds context.byLayer in plan order, and the schema accepts it", async (t) => {
  const fixture = makeFixture({ files: LAYERED_MONOREPO });
  t.after(fixture.cleanup);
  const runDir = layerRunOf(fixture);
  const out = path.join(fixture.base, "out");

  const result = await runScan([fixture.root, "--out", out, "--layers", runDir]);

  assert.equal(result.code, 0, result.stderr);
  const data = measurementsIn(out);
  assert.deepEqual(schemaProblems(JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8")), data), [], "the output matches the schema");
  assert.deepEqual(data.context.byLayer.map((layer) => layer.name), ["web", "api"], "one entry per layer, in plan order");
  const [web, api] = data.context.byLayer;
  assert.deepEqual(web.onDemand.items.map((item) => item.path), ["apps/web/CLAUDE.md"]);
  assert.deepEqual(api.onDemand.items, []);
  // Positive control: the same scan without --layers has no byLayer, and its always-loaded budget is the same.
  const plainOut = path.join(fixture.base, "out-plain");
  const plain = await runScan([fixture.root, "--out", plainOut]);
  assert.equal(plain.code, 0, plain.stderr);
  const plainData = measurementsIn(plainOut);
  assert.equal(Object.hasOwn(plainData.context, "byLayer"), false);
  assert.deepEqual(data.context.alwaysLoaded, plainData.context.alwaysLoaded, "the budget is the same with or without the plan");
});

test("scan: --layers exits 2 and writes nothing for a missing, an invalid or a foreign plan, a folder that is gone, or a run folder outside runs/", async (t) => {
  const fixture = makeFixture({ files: LAYERED_MONOREPO });
  t.after(fixture.cleanup);
  const cases = [
    {
      name: "a missing plan",
      runDir: () => layerRunOf(fixture, { plan: null }),
      message: /the run folder has no valid layer plan: layer-plan\.json: cannot be read: ENOENT/,
    },
    {
      name: "an invalid plan",
      runDir: () => layerRunOf(fixture, { plan: { schemaVersion: 1, layers: [{ name: "web", folders: ["apps/mobile"], reason: "x" }] } }),
      message: /the run folder has no valid layer plan: \/layers\/0\/folders\/0: "apps\/mobile" is not a folder of layers\.json/,
    },
    {
      name: "a layers.json written for another target",
      runDir: () => layerRunOf(fixture, { targetRoot: fixture.base }),
      message: /layers\.json was not written for this target/,
    },
    {
      name: "a layer folder that no longer exists",
      runDir: () =>
        layerRunOf(fixture, {
          plan: { schemaVersion: 1, layers: [{ name: "web", folders: ["apps/gone"], reason: "x" }] },
          folders: [...LAYER_FOLDERS, "apps/gone"],
        }),
      message: /the layer plan does not match the target: layer "web": folder "apps\/gone" does not exist in the target/,
    },
    {
      name: "a run folder outside runs/ and the temp folder",
      runDir: () => SCRIPTS_DIR,
      message: /must be inside runs\/ or the system temp folder/,
    },
  ];

  for (const [index, item] of cases.entries()) {
    const out = path.join(fixture.base, `out-${index}`);
    const result = await runScan([fixture.root, "--out", out, "--layers", item.runDir()]);
    assert.equal(result.code, 2, `${item.name}: ${result.stderr}`);
    assert.match(result.stderr, item.message, item.name);
    assert.equal(fs.existsSync(out), false, `${item.name}: nothing is written`);
  }
  // Positive control: the valid plan with the same flags exits 0 and writes the file.
  const valid = path.join(fixture.base, "out-valid");
  const result = await runScan([fixture.root, "--out", valid, "--layers", layerRunOf(fixture)]);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(fs.existsSync(path.join(valid, "measurements.json")), true);
});

test("scan: --layers with an empty value exits 2", async (t) => {
  const fixture = makeFixture({ files: LAYERED_MONOREPO });
  t.after(fixture.cleanup);
  const out = path.join(fixture.base, "out");

  const result = await runScan([fixture.root, "--out", out, "--layers", ""]);

  assert.equal(result.code, 2);
  assert.match(result.stderr, /the --layers folder must not be empty/);
  assert.equal(fs.existsSync(out), false);
});

test("the schema documents context.byLayer as optional, with the fields of each layer", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.equal(schema.properties.context.required.includes("byLayer"), false);
  assert.deepEqual(schema.properties.context.properties.byLayer.items.required, [
    "name",
    "folders",
    "agent",
    "onDemand",
    "nestedSkills",
    "notCounted",
  ]);
});
