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
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";
import { sarifProblems } from "./helpers/sarif-check.mjs";

// The CI mode, scripts/ci.mjs. Each run is a child process, so the exit codes are the real ones. Every target is a copy of a
// fixture in the system temp folder, and every output folder is in that copy too, so nothing is written under runs/. The child
// processes get a fake home folder, so no test reads the real HOME. A test that needs a runs/ folder uses a copy of the harness
// in the temp folder (harnessCopyOf), never the real runs/ of this repository.
const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const CI_SCRIPT = path.join(HARNESS_ROOT, "scripts", "ci.mjs");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const USAGE_LINE = "usage: node scripts/ci.mjs";
const JUDGMENT_COUNT = loadRules(HARNESS_ROOT).filter((rule) => rule.kind === "judgment").length;
const SARIF_SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "sarif.schema.json"), "utf8"));
// The parts of this repository that scripts/ci.mjs reads, copied by harnessCopyOf. The copy has no runs/ folder.
const HARNESS_PARTS = ["package.json", "scripts", "rules", "data", "schemas", "templates"];
const ISO_TIME = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const rootSkip = typeof process.getuid === "function" && process.getuid() === 0 ? "running as root: permissions do not stop a write" : false;
const permissionSkip = rootSkip || (process.platform === "win32" ? "chmod does not restrict writes on Windows" : false);
const links = symlinkSupport();
const linkSkip = links.supported ? false : links.reason;
// A description longer than skillDescriptionMaxChars (1024) and shorter than the listing's cut: CTX-04 gives one low finding for it.
const LONG_DESCRIPTION = "Describes the skill in one long line. ".repeat(30).trim();

// Runs a command line through execFile (never a shell). Resolves with the exit code and both streams.
async function runCommand(script, args, env) {
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

// A copy of a fixture (with extra files) in a temp folder, and the environment of its runs: a fake home folder in the same folder.
function copyOf(t, name, files = {}) {
  const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), git: true, files });
  t.after(fixture.cleanup);
  const home = path.join(fixture.base, "home");
  fs.mkdirSync(home);
  return { root: fixture.root, base: fixture.base, env: { ...process.env, HOME: home, USERPROFILE: home } };
}

function runCi(args, env) {
  return runCommand(CI_SCRIPT, args, env);
}

// A copy of the parts of this repository that scripts/ci.mjs reads, in a folder of the temp folder that the test removes. The entries
// of replaced (relative path -> text) are written over the copy. Its ci.mjs is <copy>/scripts/ci.mjs.
function harnessCopyOf(t, replaced = {}) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-harness-"));
  t.after(() => fs.rmSync(copy, { recursive: true, force: true }));
  for (const name of HARNESS_PARTS) fs.cpSync(path.join(HARNESS_ROOT, name), path.join(copy, name), { recursive: true });
  for (const [name, text] of Object.entries(replaced)) fs.writeFileSync(path.join(copy, name), text);
  return copy;
}

// A skill whose listed description is long, so CTX-04 gives it a low finding, under the given folder name.
function longSkill(name) {
  return `---\nname: ${name}\ndescription: ${LONG_DESCRIPTION}\n---\n\n# ${name}\n\nThe body of the skill.\n`;
}

function readMeasurements(out) {
  return JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
}

// The summary line of the findings by impact.
function countsLine(stdout) {
  return stdout.split("\n").find((line) => line.startsWith("measured findings: "));
}

// The measurements text without the meta block, which holds the scan time and the target path of the run.
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

test("ci: a target with no measured finding exits 0 at every threshold", async (t) => {
  const { root, base, env } = copyOf(t, "guarded");
  for (const failOn of [undefined, "high", "medium", "low"]) {
    const out = path.join(base, `out-${failOn ?? "none"}`);
    const args = [root, "--out", out, ...(failOn === undefined ? [] : ["--fail-on", failOn])];
    const result = await runCi(args, env);
    assert.equal(result.code, 0, `exit code with --fail-on ${failOn}: ${result.stderr}`);
    assert.match(result.stdout, /^measured findings: high 0, medium 0, low 0$/m);
  }
});

test("ci: a high finding exits 3 at the high threshold, after the SARIF log is written", async (t) => {
  const { root, base, env } = copyOf(t, "permissive");
  const out = path.join(base, "out");
  const sarif = path.join(base, "sarif", "results.sarif");

  const result = await runCi([root, "--out", out, "--fail-on", "high", "--sarif", sarif], env);

  assert.equal(result.code, 3, result.stderr);
  assert.equal(result.stderr, "");
  assert.ok(fs.existsSync(path.join(out, "measurements.json")), "measurements.json is written before the exit");
  const log = JSON.parse(fs.readFileSync(sarif, "utf8"));
  assert.deepEqual(sarifProblems(log), [], "the SARIF log passes the checker");
  assert.match(result.stdout, /^fail-on: high, findings at or above it: 2$/m);
});

test("ci: the threshold decides, medium findings exit 3 at medium and at low, and 0 at high", async (t) => {
  const { root, base, env } = copyOf(t, "default-only");
  const expected = { high: 0, medium: 3, low: 3 };
  for (const [failOn, code] of Object.entries(expected)) {
    const out = path.join(base, `out-${failOn}`);
    const result = await runCi([root, "--out", out, "--fail-on", failOn], env);
    assert.equal(result.code, code, `exit code with --fail-on ${failOn}: ${result.stderr}`);
    assert.equal(fs.existsSync(path.join(out, "measurements.json")), true, "the measurements are written at every threshold");
  }
  const atHigh = await runCi([root, "--out", path.join(base, "out-high")], env);
  assert.equal(atHigh.code, 0, "without --fail-on the run does not exit 3");
});

test("ci: a finding of low impact alone exits 3 only at the low threshold", async (t) => {
  const { root, base, env } = copyOf(t, "guarded", {
    ".claude/skills/long-description/SKILL.md": `---\nname: long-description\ndescription: ${LONG_DESCRIPTION}\n---\n\n# Long description\n\nThe body of the skill.\n`,
  });
  const expected = { high: 0, medium: 0, low: 3 };
  for (const [failOn, code] of Object.entries(expected)) {
    const result = await runCi([root, "--out", path.join(base, `out-${failOn}`), "--fail-on", failOn], env);
    assert.equal(result.code, code, `exit code with --fail-on ${failOn}: ${result.stderr}`);
  }
  const summary = await runCi([root, "--out", path.join(base, "out-summary")], env);
  assert.equal(countsLine(summary.stdout), "measured findings: high 0, medium 0, low 1", "the only finding is the low one");
});

test("ci: without --fail-on the run never exits 3, even with high findings, and it prints no threshold line", async (t) => {
  const { root, base, env } = copyOf(t, "permissive");
  const result = await runCi([root, "--out", path.join(base, "out")], env);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(countsLine(result.stdout), "measured findings: high 2, medium 1, low 0");
  assert.doesNotMatch(result.stdout, /^fail-on:/m);
});

test("ci: the summary says the judgment rules were not applied and counts the judgment rules of the catalog", async (t) => {
  const { root, base, env } = copyOf(t, "default-only");
  const out = path.join(base, "out");
  const sarif = path.join(base, "sarif.sarif");
  const result = await runCi([root, "--out", out, "--sarif", sarif], env);

  assert.equal(result.code, 0, result.stderr);
  assert.ok(JUDGMENT_COUNT > 0, "the catalog has judgment rules");
  assert.ok(
    result.stdout.includes(
      `judgment rules: not applied (CI runs the measured rules only; the catalog has ${JUDGMENT_COUNT} judgment rules)`,
    ),
    "the judgment line is printed",
  );
  assert.ok(result.stdout.includes(`measurements: ${path.join(out, "measurements.json")}`));
  assert.ok(result.stdout.includes(`sarif: ${sarif}`));
  assert.deepEqual(fs.readdirSync(out), ["measurements.json"], "only measurements.json is written in the run folder");
});

test("ci: measurements.json equals the one of scan.mjs for the same copy, apart from meta", async (t) => {
  const { root, base, env } = copyOf(t, "permissive");
  const scanOut = path.join(base, "scan");
  const ciOut = path.join(base, "ci");
  assert.equal((await runCommand(SCAN_SCRIPT, [root, "--out", scanOut], env)).code, 0);
  assert.equal((await runCi([root, "--out", ciOut], env)).code, 0);

  const scanRaw = fs.readFileSync(path.join(scanOut, "measurements.json"), "utf8");
  const ciRaw = fs.readFileSync(path.join(ciOut, "measurements.json"), "utf8");
  assert.equal(withoutMetaText(ciRaw), withoutMetaText(scanRaw));
  assert.equal(readMeasurements(ciOut).meta.tool, readMeasurements(scanOut).meta.tool);
  assert.equal(readMeasurements(ciOut).meta.catalog.sha256, readMeasurements(scanOut).meta.catalog.sha256);
});

test("ci: the run reads nothing outside the target, so a user allow in the fake home changes nothing", async (t) => {
  const { root, base, env } = copyOf(t, "guarded");
  const userClaude = path.join(base, "home", ".claude");
  fs.mkdirSync(userClaude);
  fs.writeFileSync(
    path.join(userClaude, "settings.json"),
    JSON.stringify({ permissions: { allow: ["Bash(rm -rf *)"] } }),
  );
  const out = path.join(base, "out");
  assert.equal((await runCi([root, "--out", out], env)).code, 0);
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  assert.doesNotMatch(raw, /"userLayer"/, "no user layer section without --include-user-layer");
  assert.doesNotMatch(raw, /~\/\.claude/, "the user's files are not named");
});

test("ci: the SARIF file's folder is created when it is missing, and the log passes the checker", async (t) => {
  const { root, base, env } = copyOf(t, "default-only");
  const sarif = path.join(base, "new", "nested", "results.sarif");
  assert.equal(fs.existsSync(path.dirname(sarif)), false);

  const result = await runCi([root, "--out", path.join(base, "out"), "--sarif", sarif], env);

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(sarifProblems(JSON.parse(fs.readFileSync(sarif, "utf8"))), []);
});

test("ci: a SARIF file directly in the system temp folder is written, and the file is removed by the test", async (t) => {
  const { root, base, env } = copyOf(t, "default-only");
  const sarif = path.join(os.tmpdir(), `hxr-ci-${randomUUID()}.sarif`);
  t.after(() => fs.rmSync(sarif, { force: true }));

  const result = await runCi([root, "--out", path.join(base, "out"), "--sarif", sarif], env);

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(sarifProblems(JSON.parse(fs.readFileSync(sarif, "utf8"))), []);
});

test("ci: a SARIF file directly in runs/ is written, and runs/ is created when it is missing (in a copy of the harness)", async (t) => {
  const copy = harnessCopyOf(t);
  const { root, base, env } = copyOf(t, "default-only");
  const runs = path.join(copy, "runs");
  assert.equal(fs.existsSync(runs), false, "the copy has no runs folder");
  const sarif = path.join(runs, "results.sarif");

  const result = await runCommand(
    path.join(copy, "scripts", "ci.mjs"),
    [root, "--out", path.join(base, "out"), "--sarif", sarif],
    env,
  );

  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(fs.readdirSync(runs), ["results.sarif"], "runs/ holds the log and nothing else");
  assert.deepEqual(sarifProblems(JSON.parse(fs.readFileSync(sarif, "utf8"))), []);
});

test("ci: a --sarif file in a symlinked folder is refused when it is the measurements.json of the run, and a link to the run folder is accepted", { skip: linkSkip }, async (t) => {
  const { root, base, env } = copyOf(t, "guarded");
  const out = path.join(base, "out");
  fs.mkdirSync(out);
  const alias = path.join(base, "alias");
  fs.symlinkSync(out, alias, "dir");

  const refused = await runCi([root, "--out", out, "--sarif", path.join(alias, "measurements.json")], env);

  assert.equal(refused.code, 2, refused.stderr);
  assert.match(refused.stderr, /must not be the measurements\.json of the run/);
  assert.equal(fs.existsSync(path.join(out, "measurements.json")), false, "nothing is written");

  // Positive control: the link itself is a valid run folder, and its measurements.json is written.
  const accepted = await runCi([root, "--out", alias, "--sarif", path.join(base, "alias-run.sarif")], env);
  assert.equal(accepted.code, 0, accepted.stderr);
  assert.equal(fs.existsSync(path.join(out, "measurements.json")), true);
});

test("ci: an error in buildSarif exits 1 and writes no file, not even the run folder", async (t) => {
  const copy = harnessCopyOf(t, {
    "scripts/lib/sarif.mjs": 'export function buildSarif() {\n  throw new TypeError("injected failure");\n}\n',
  });
  const { root, base, env } = copyOf(t, "default-only");
  const out = path.join(base, "out");
  const sarif = path.join(base, "sarif", "results.sarif");

  const result = await runCommand(path.join(copy, "scripts", "ci.mjs"), [root, "--out", out, "--sarif", sarif], env);

  assert.equal(result.code, 1, `exit code: ${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /^error: injected failure$/m);
  assert.equal(result.stderr.includes(USAGE_LINE), false, "an unexpected failure prints no usage line");
  assert.equal(fs.existsSync(out), false, "the run folder is not created");
  assert.equal(fs.existsSync(path.dirname(sarif)), false, "the SARIF folder is not created");
});

test("ci: a SARIF write that fails exits 1 and leaves the new measurements.json", { skip: permissionSkip }, async (t) => {
  const { root, base, env } = copyOf(t, "default-only");
  const folder = path.join(base, "read-only-sarif");
  fs.mkdirSync(folder);
  fs.chmodSync(folder, 0o555);
  try {
    const out = path.join(base, "out");
    const result = await runCi([root, "--out", out, "--sarif", path.join(folder, "results.sarif")], env);

    assert.equal(result.code, 1, `exit code: ${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /^error: /m);
    assert.equal(fs.existsSync(path.join(out, "measurements.json")), true, "the new measurements.json is left in place");
    assert.equal(fs.existsSync(path.join(folder, "results.sarif")), false, "no SARIF file is written");
  } finally {
    // Restored, so the copy can be removed.
    fs.chmodSync(folder, 0o755);
  }
});

test("ci: a skill folder with a space gives a percent-encoded SARIF uri, and the log passes the checker and the schema", async (t) => {
  const { root, base, env } = copyOf(t, "guarded", {
    ".claude/skills/long description/SKILL.md": longSkill("long description"),
    ".claude/skills/long-plain/SKILL.md": longSkill("long-plain"),
  });
  const sarif = path.join(base, "encoded.sarif");

  const result = await runCi([root, "--out", path.join(base, "out"), "--sarif", sarif], env);

  assert.equal(result.code, 0, result.stderr);
  const log = JSON.parse(fs.readFileSync(sarif, "utf8"));
  assert.deepEqual(sarifProblems(log), []);
  assert.deepEqual(schemaProblems(SARIF_SCHEMA, log), [], "the log passes schemas/sarif.schema.json");
  const uris = log.runs[0].results.flatMap((item) =>
    (item.locations ?? []).map((location) => location.physicalLocation.artifactLocation.uri),
  );
  assert.ok(uris.includes(".claude/skills/long%20description/SKILL.md"), `the space is encoded: ${uris.join(", ")}`);
  assert.ok(uris.includes(".claude/skills/long-plain/SKILL.md"), "positive control: a plain name is written as it is");
});

// Each usage error, with the arguments it gives. The paths are the test's own: the target and the output folders are copies in
// the temp folder, and the refused paths are the ones that a check must refuse before anything is written.
const USAGE_CASES = {
  "an unknown option": (p) => [p.target, "--bogus"],
  "a --fail-on value that is not high, medium or low": (p) => [p.target, "--fail-on", "critical"],
  "an empty --fail-on value": (p) => [p.target, "--fail-on", ""],
  "a --fail-on without a value": (p) => [p.target, "--fail-on"],
  "a --fail-on given twice": (p) => [p.target, "--fail-on", "high", "--fail-on", "low"],
  "a --sarif given twice": (p) => [p.target, "--sarif", p.sarif, "--sarif", p.sarifTwo],
  "an --out given twice": (p) => [p.target, "--out", p.out, "--out", p.outTwo],
  "an empty --sarif value": (p) => [p.target, "--sarif", ""],
  "an empty --out value": (p) => [p.target, "--out", ""],
  "no target": () => [],
  "two targets": (p) => [p.target, p.target],
  "a target that does not exist": (p) => [p.missing],
  "a --sarif outside runs/ and the temp folder": (p) => [p.target, "--sarif", p.repoFile],
  "a --sarif inside the target": (p) => [p.target, "--sarif", p.insideTarget],
  "a --sarif named like the measurements.json of the run": (p) => [p.target, "--out", p.out, "--sarif", path.join(p.out, "measurements.json")],
  "an --out outside runs/ and the temp folder": (p) => [p.target, "--out", p.repoDir],
};

for (const [name, build] of Object.entries(USAGE_CASES)) {
  test(`ci: ${name} exits 2, prints the usage line and writes nothing`, async (t) => {
    const { root, base, env } = copyOf(t, "guarded");
    // These paths are never created: a check that lets one through would create it, and the test would see it.
    const repoFile = path.join(HARNESS_ROOT, "ci-not-allowed.sarif");
    const repoDir = path.join(HARNESS_ROOT, "ci-not-allowed-out");
    t.after(() => {
      fs.rmSync(repoFile, { force: true });
      fs.rmSync(repoDir, { recursive: true, force: true });
    });
    const paths = {
      target: root,
      missing: path.join(base, "missing"),
      out: path.join(base, "out"),
      outTwo: path.join(base, "out-two"),
      sarif: path.join(base, "a.sarif"),
      sarifTwo: path.join(base, "b.sarif"),
      insideTarget: path.join(root, "results.sarif"),
      repoFile,
      repoDir,
    };

    const result = await runCi(build(paths), env);

    assert.equal(result.code, 2, `exit code (${name}): ${result.stderr}`);
    assert.match(result.stderr, /^error: /m);
    assert.ok(result.stderr.includes(USAGE_LINE), "the usage line is printed");
    assert.equal(result.stdout, "", "no summary is printed");
    for (const created of [paths.out, paths.outTwo, paths.sarif, paths.sarifTwo, paths.insideTarget, repoFile, repoDir]) {
      assert.equal(fs.existsSync(created), false, `nothing is written: ${created}`);
    }
  });
}

test("ci: an --fail-on value that is not one of the three names them in the error", async (t) => {
  const { root, env } = copyOf(t, "guarded");
  const result = await runCi([root, "--fail-on", "critical"], env);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /high, medium or low/);
});

test("ci: an unexpected failure exits 1, here a run folder that cannot be written", { skip: permissionSkip }, async (t) => {
  const { root, base, env } = copyOf(t, "guarded");
  const readOnly = path.join(base, "read-only");
  fs.mkdirSync(readOnly);
  fs.chmodSync(readOnly, 0o555);
  try {
    const result = await runCi([root, "--out", readOnly, "--fail-on", "high"], env);

    assert.equal(result.code, 1, `exit code: ${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /^error: /m);
    assert.equal(result.stderr.includes(USAGE_LINE), false, "an unexpected failure prints no usage line");
    assert.equal(fs.existsSync(path.join(readOnly, "measurements.json")), false);
  } finally {
    // Restored, so the copy can be removed.
    fs.chmodSync(readOnly, 0o755);
  }
});

test("ci: the summary is short and has no timestamp", async (t) => {
  const { root, base, env } = copyOf(t, "permissive");
  const result = await runCi([root, "--out", path.join(base, "out"), "--fail-on", "low"], env);
  assert.equal(result.code, 3, result.stderr);
  const lines = result.stdout.trimEnd().split("\n");
  assert.ok(lines.length <= 6, `the summary has ${lines.length} lines`);
  assert.doesNotMatch(result.stdout, ISO_TIME);
});
