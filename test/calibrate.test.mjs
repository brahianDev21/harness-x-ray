import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { schemaProblems } from "./helpers/schema-check.mjs";

// The calibration command, scripts/calibrate.mjs. Each run is a child process, so the exit codes are the real ones. Every target is
// a copy of a fixture in a folder of the system temp folder, and every output folder is in that temp folder too, so nothing is
// written under runs/ of this repository. The child processes get a fake home folder. The copies of the fixtures are the targets
// that the tests scan: the fixtures themselves lie inside this repository, which a target may not do.
const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const CALIBRATE_SCRIPT = path.join(HARNESS_ROOT, "scripts", "calibrate.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "calibration.schema.json"), "utf8"));
const USAGE_LINE = "usage: node scripts/calibrate.mjs";
// The parts of this repository that scripts/calibrate.mjs reads. The default-folder tests copy them into a sandbox folder, which has
// no runs/ folder at first, and run the copy's own scripts/calibrate.mjs there.
const HARNESS_PARTS = ["package.json", "scripts", "rules", "data", "schemas", "templates"];
const UTC_DATE = () => new Date().toISOString().slice(0, 10);
// Permissions do not stop a write for root, and chmod does not restrict writes on Windows (the same skip as ci.test.mjs).
const rootSkip = typeof process.getuid === "function" && process.getuid() === 0 ? "running as root: permissions do not stop a write" : false;
const permissionSkip = rootSkip || (process.platform === "win32" ? "chmod does not restrict writes on Windows" : false);

// Runs the command through execFile (never a shell). Resolves with the exit code and both streams. The script is this repository's
// unless a test gives the copy of it that it runs.
async function runCalibrate(args, env, script = CALIBRATE_SCRIPT) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [script, ...args], {
      encoding: "utf8",
      env,
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error; // The process did not start.
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

// A folder of the temp folder for one test, removed when the test ends, with a fake home folder in it.
function sandboxOf(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-calibrate-"));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const home = path.join(base, "home");
  fs.mkdirSync(home);
  return { base, env: { ...process.env, HOME: home, USERPROFILE: home } };
}

// A copy of a fixture under a folder, named as the test chooses: the name is the target's basename in the calibration.
function copyInto(base, fixture, name, files = {}) {
  const dir = path.join(base, name);
  fs.cpSync(path.join(FIXTURES, fixture), dir, { recursive: true });
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

// Every file under a folder, relative and sorted, with its size: a snapshot to show that a target was not written.
function snapshotOf(dir) {
  const entries = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      entries.push(`${path.relative(dir, full)}:${fs.statSync(full).size}`);
      if (entry.isDirectory()) walk(full);
    }
  };
  walk(dir);
  return entries.sort();
}

function measureOf(calibration, name) {
  return calibration.measures.find((measure) => measure.name === name);
}

function thresholdOf(calibration, name, key) {
  return measureOf(calibration, name).thresholds.find((threshold) => threshold.key === key);
}

// A copy of the parts of this repository that scripts/calibrate.mjs reads, in a folder of the sandbox. Its own runs/ folder does not exist.
function harnessCopyIn(base) {
  const harness = path.join(base, "harness");
  fs.mkdirSync(harness);
  for (const name of HARNESS_PARTS) fs.cpSync(path.join(HARNESS_ROOT, name), path.join(harness, name), { recursive: true });
  return harness;
}

test("acceptance: three fixtures give exit 0, a calibration that matches its schema, and the expected distribution", async (t) => {
  const { base, env } = sandboxOf(t);
  const targets = [
    copyInto(base, "bloated", "bloated"),
    copyInto(base, "duplicated", "duplicated"),
    copyInto(base, "minimal-good", "minimal-good"),
  ];
  const before = targets.map(snapshotOf);
  const out = path.join(base, "out");
  const result = await runCalibrate([...targets, "--out", out], env);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /^targets: 3$/m);

  const calibration = JSON.parse(fs.readFileSync(path.join(out, "calibration.json"), "utf8"));
  assert.deepEqual(schemaProblems(SCHEMA, calibration), []);
  assert.deepEqual(calibration.sample, { count: 3, targets: ["bloated", "duplicated", "minimal-good"] });
  assert.equal(calibration.meta.tool, "harness-x-ray@0.0.0");
  assert.equal(calibration.meta.date, UTC_DATE());

  // Tokens: 3277 (bloated, 13107 bytes at 4 per token, rounded up), 0 (duplicated, no memory), 214 (minimal-good, 856 bytes).
  const tokens = measureOf(calibration, "alwaysLoadedTokens");
  assert.deepEqual([tokens.n, tokens.min, tokens.p25, tokens.median, tokens.p75, tokens.p90, tokens.max], [3, 0, 0, 214, 3277, 3277, 3277]);
  assert.equal(thresholdOf(calibration, "alwaysLoadedTokens", "alwaysLoadedTokensMedium").exceeding, 1);
  assert.equal(thresholdOf(calibration, "alwaysLoadedTokens", "alwaysLoadedTokensHigh").exceeding, 0);

  // Memory: 250 lines (bloated) and 23 (minimal-good). duplicated has no memory file, so it has no value and is not counted.
  const memory = measureOf(calibration, "memoryFileLines");
  assert.deepEqual([memory.n, memory.min, memory.median, memory.p75, memory.max], [2, 23, 23, 250, 250]);
  assert.equal(thresholdOf(calibration, "memoryFileLines", "memoryFileMaxLines").exceeding, 1);

  // Duplication: 0, 0 and 32.5 per cent (duplicated).
  const duplication = measureOf(calibration, "duplicationPct");
  assert.deepEqual([duplication.n, duplication.min, duplication.median, duplication.max], [3, 0, 0, 32.5]);
  assert.equal(thresholdOf(calibration, "duplicationPct", "duplicationPctMedium").exceeding, 1);
  assert.equal(thresholdOf(calibration, "duplicationPct", "duplicationPctHigh").exceeding, 1);

  // Large files, skills: none in these fixtures, so every target has a value of 0 files and 0 skills, and no skill description.
  assert.deepEqual([measureOf(calibration, "largeFileCount").n, measureOf(calibration, "largeFileCount").max], [3, 0]);
  assert.equal(thresholdOf(calibration, "largeFileCount", "largeFileBytes").exceeding, 0);
  assert.deepEqual([measureOf(calibration, "skillCount").n, measureOf(calibration, "skillCount").max], [3, 0]);
  const longest = measureOf(calibration, "skillDescriptionMaxChars");
  assert.deepEqual([longest.n, longest.min, longest.max], [0, null, null]);

  const markdown = fs.readFileSync(path.join(out, "calibration.md"), "utf8");
  assert.ok(markdown.startsWith("# Threshold calibration\n"));
  // escapeMarkdown escapes the hyphen too, so the name in its table cell is minimal\-good.
  assert.ok(markdown.includes("| minimal\\-good |"));
  assert.ok(!markdown.includes(base), "the document holds no path of the sandbox");

  // The targets are read only: their files and sizes are the same after the run.
  assert.deepEqual(targets.map(snapshotOf), before);
});

test("determinism: the same day gives the same bytes, and the order of the targets does not change them", async (t) => {
  const { base, env } = sandboxOf(t);
  const targets = [copyInto(base, "bloated", "bloated"), copyInto(base, "duplicated", "duplicated"), copyInto(base, "minimal-good", "minimal-good")];
  const first = path.join(base, "first");
  const second = path.join(base, "second");
  const reversed = path.join(base, "reversed");
  assert.equal((await runCalibrate([...targets, "--out", first], env)).code, 0);
  assert.equal((await runCalibrate([...targets, "--out", second], env)).code, 0);
  assert.equal((await runCalibrate([...[...targets].reverse(), "--out", reversed], env)).code, 0);
  for (const name of ["calibration.json", "calibration.md"]) {
    const bytes = fs.readFileSync(path.join(first, name));
    assert.ok(bytes.equals(fs.readFileSync(path.join(second, name))), `${name} is the same in two runs`);
    assert.ok(bytes.equals(fs.readFileSync(path.join(reversed, name))), `${name} is the same with the targets reversed`);
  }
});

test("privacy: a target's file names, folder names and text do not reach the files; a normal target next to it passes", async (t) => {
  const { base, env } = sandboxOf(t);
  const sentinel = "SENTINEL-7f3a-TEXT";
  const hostile = copyInto(base, "bloated", "zq-target-one", {
    "CLAUDE.md": Array.from({ length: 260 }, () => `line ${sentinel}`).join("\n") + "\n",
    "zq-hidden-notes.md": `notes SENTINEL-NOTES-9b2e\n`,
    ".claude/skills/zq-skill-x/SKILL.md": `---\nname: zq-skill-x\ndescription: SENTINEL-SKILL-5d8c ${"x".repeat(1200)}\n---\n\n# zq-skill-x\n`,
    "secretdir-q9/deeper/notes.txt": "SENTINEL-DEEP-2e6a\n",
  });
  const normal = copyInto(base, "minimal-good", "minimal-good");
  const out = path.join(base, "out");
  const result = await runCalibrate([hostile, normal, "--out", out], env);
  assert.equal(result.code, 0, result.stderr);

  const json = fs.readFileSync(path.join(out, "calibration.json"), "utf8");
  const markdown = fs.readFileSync(path.join(out, "calibration.md"), "utf8");
  for (const text of [json, markdown]) {
    for (const forbidden of [sentinel, "SENTINEL", "zq-hidden", "zq-skill", "secretdir", "deeper", hostile, base]) {
      assert.ok(!text.includes(forbidden), `the output holds ${forbidden}`);
    }
  }
  // escapeMarkdown escapes the hyphens of the name, so the table cell reads zq\-target\-one.
  assert.ok(markdown.includes("| zq\\-target\\-one |"), "the basename of the target is written, escaped for its table cell");

  // Every string value of calibration.json is one of the fixed texts, a statistic's name, a threshold key, a status, a meta field or
  // a basename of the sample.
  const calibration = JSON.parse(json);
  const allowed = new Set([
    ...calibration.measures.map((measure) => measure.name),
    ...calibration.measures.flatMap((measure) => measure.thresholds.map((threshold) => threshold.key)),
    "provisional",
    "calibrated",
    calibration.meta.date,
    calibration.meta.tool,
    calibration.meta.catalog.sha256,
    calibration.meta.percentileMethod,
    "zq-target-one",
    "minimal-good",
  ]);
  const strings = [];
  const walk = (value) => {
    if (typeof value === "string") strings.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value !== null && typeof value === "object") Object.values(value).forEach(walk);
  };
  walk(calibration);
  assert.deepEqual(strings.filter((text) => !allowed.has(text)), []);
  assert.deepEqual(calibration.sample.targets, ["minimal-good", "zq-target-one"]);
});

test("two targets with the same basename are both listed, as two rows of the sample", async (t) => {
  const { base, env } = sandboxOf(t);
  fs.mkdirSync(path.join(base, "one"));
  fs.mkdirSync(path.join(base, "two"));
  const first = copyInto(path.join(base, "one"), "bloated", "app");
  const second = copyInto(path.join(base, "two"), "minimal-good", "app");
  const out = path.join(base, "out");
  const result = await runCalibrate([first, second, "--out", out], env);
  assert.equal(result.code, 0, result.stderr);
  const calibration = JSON.parse(fs.readFileSync(path.join(out, "calibration.json"), "utf8"));
  assert.deepEqual(calibration.sample, { count: 2, targets: ["app", "app"] });
  const rows = fs.readFileSync(path.join(out, "calibration.md"), "utf8").split("\n").filter((line) => line === "| app |");
  assert.equal(rows.length, 2);
});

test("exits: each refused case is 2, and the same command with a valid target and folder is 0", async (t) => {
  const { base, env } = sandboxOf(t);
  const target = copyInto(base, "minimal-good", "minimal-good");

  // The positive control: the command that the refusals below change, with nothing refused.
  const valid = path.join(base, "valid");
  const accepted = await runCalibrate([target, "--out", valid], env);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.ok(fs.existsSync(path.join(valid, "calibration.json")));

  const out = path.join(base, "out");
  const none = await runCalibrate(["--out", out], env);
  assert.equal(none.code, 2);
  assert.ok(none.stderr.includes("missing the target folders"));
  assert.ok(none.stderr.includes(USAGE_LINE));

  const inside = await runCalibrate([path.join(FIXTURES, "minimal-good"), "--out", out], env);
  assert.equal(inside.code, 2);
  assert.ok(inside.stderr.includes("harness-x-ray or lies inside it"));

  const repeated = await runCalibrate([target, path.join(base, "minimal-good", "..", "minimal-good"), "--out", out], env);
  assert.equal(repeated.code, 2);
  assert.ok(repeated.stderr.includes("given more than once"));

  // A folder outside runs/ and outside the temp folder is refused before anything is created.
  const notAllowed = path.join(path.parse(HARNESS_ROOT).root, "xray-calibrate-not-allowed");
  const refused = await runCalibrate([target, "--out", notAllowed], env);
  assert.equal(refused.code, 2);
  assert.equal(fs.existsSync(notAllowed), false);

  // A folder inside a target is refused as well.
  const inTarget = path.join(target, "out");
  const insideTarget = await runCalibrate([target, "--out", inTarget], env);
  assert.equal(insideTarget.code, 2);
  assert.ok(insideTarget.stderr.includes("inside the target"));
  assert.equal(fs.existsSync(inTarget), false);

  assert.equal((await runCalibrate([target, "--out", out, "--out", out], env)).code, 2);
  assert.equal((await runCalibrate([target, "--out", ""], env)).code, 2);
  assert.equal(fs.existsSync(out), false, "no run folder was created by a refused run");
});

test("a folder name with a tab is a usage error, and the name is not printed; the same folder with a plain name is accepted", async (t) => {
  const { base, env } = sandboxOf(t);
  const plain = copyInto(base, "minimal-good", "plain-name");
  const out = path.join(base, "out");
  const accepted = await runCalibrate([plain, "--out", out], env);
  assert.equal(accepted.code, 0, accepted.stderr);

  const named = copyInto(base, "minimal-good", "bad\tname");
  const refusedOut = path.join(base, "refused");
  const result = await runCalibrate([named, "--out", refusedOut], env);
  assert.equal(result.code, 2);
  assert.ok(result.stderr.includes("control character"));
  assert.ok(!result.stderr.includes("bad\tname"));
  assert.equal(fs.existsSync(refusedOut), false);
});

test("exit 1: a run folder that cannot take a file ends with exit 1 and nothing is written", { skip: permissionSkip }, async (t) => {
  const { base, env } = sandboxOf(t);
  const target = copyInto(base, "minimal-good", "minimal-good");
  // The positive control: the same run into a folder that can take the files.
  const writable = path.join(base, "writable");
  const accepted = await runCalibrate([target, "--out", writable], env);
  assert.equal(accepted.code, 0, accepted.stderr);

  const readOnly = path.join(base, "read-only");
  fs.mkdirSync(readOnly);
  fs.chmodSync(readOnly, 0o555);
  try {
    const result = await runCalibrate([target, "--out", readOnly], env);
    assert.equal(result.code, 1, result.stderr);
    assert.deepEqual(fs.readdirSync(readOnly), []);
  } finally {
    fs.chmodSync(readOnly, 0o755);
  }
});

test("the default run folder: two runs of one day never share a folder, and each one keeps its own", async (t) => {
  const { base, env } = sandboxOf(t);
  const harness = harnessCopyIn(base);
  const target = copyInto(base, "minimal-good", "minimal-good");
  const date = UTC_DATE();
  const script = path.join(harness, "scripts", "calibrate.mjs");
  const runs = path.join(harness, "runs");

  const first = await runCalibrate([target], env, script);
  assert.equal(first.code, 0, first.stderr);
  const firstBytes = fs.readFileSync(path.join(runs, `calibration-${date}`, "calibration.json"));

  const second = await runCalibrate([target], env, script);
  assert.equal(second.code, 0, second.stderr);
  assert.ok(fs.existsSync(path.join(runs, `calibration-${date}-2`, "calibration.json")), "the second run goes to -2");
  assert.ok(fs.readFileSync(path.join(runs, `calibration-${date}`, "calibration.json")).equals(firstBytes), "the first run is not written over");

  const third = await runCalibrate([target], env, script);
  assert.equal(third.code, 0, third.stderr);
  assert.ok(fs.existsSync(path.join(runs, `calibration-${date}-3`, "calibration.json")), "the third run goes to -3");
});

test("the default run folder: a day folder that already exists is not written into; the output goes to -2", async (t) => {
  const { base, env } = sandboxOf(t);
  const harness = harnessCopyIn(base);
  const date = UTC_DATE();
  const existing = path.join(harness, "runs", `calibration-${date}`);
  fs.mkdirSync(existing, { recursive: true });
  fs.writeFileSync(path.join(existing, "keep.txt"), "not a calibration\n");
  const target = copyInto(base, "minimal-good", "minimal-good");

  const result = await runCalibrate([target], env, path.join(harness, "scripts", "calibrate.mjs"));
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(fs.readdirSync(existing), ["keep.txt"], "the existing folder keeps its only file");
  assert.equal(fs.readFileSync(path.join(existing, "keep.txt"), "utf8"), "not a calibration\n");
  assert.ok(fs.existsSync(path.join(harness, "runs", `calibration-${date}-2`, "calibration.json")));
});

test("the default run folder: a runs entry that is a file is a usage error (exit 2), and the file stays", async (t) => {
  const { base, env } = sandboxOf(t);
  const harness = harnessCopyIn(base);
  fs.writeFileSync(path.join(harness, "runs"), "a file, not a folder\n");
  const target = copyInto(base, "minimal-good", "minimal-good");

  const result = await runCalibrate([target], env, path.join(harness, "scripts", "calibrate.mjs"));
  assert.equal(result.code, 2, result.stderr);
  assert.ok(result.stderr.includes("cannot be used"));
  assert.equal(fs.readFileSync(path.join(harness, "runs"), "utf8"), "a file, not a folder\n");
});
