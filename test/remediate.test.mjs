// Tests of scripts/remediate.mjs, run through the command line on temp run folders: the exit codes (0, 2 and 1), the refused
// links and hard links, the all-or-nothing writes, and the rule that no secret value reaches any output. Every run folder is
// made in the temp folder by makeRun or by scanFixture below, and removed afterwards. The seeded secret values are built at run
// time and written only into those temp copies.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { schemaProblems } from "./helpers/schema-check.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";
import { SECRET_FIXTURE_FILES } from "./helpers/secret-fixture-files.mjs";
import { HARNESS_ROOT, RENDER_SCRIPT, SCAN_SCRIPT, makeRun } from "./helpers/report-run.mjs";
import { AGENT_FRAGMENTS_MAX_BYTES } from "../scripts/lib/remediation.mjs";
import { loadSecretPatterns } from "../scripts/lib/secret-patterns.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REMEDIATE_SCRIPT = path.join(HARNESS_ROOT, "scripts", "remediate.mjs");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "remediation.schema.json"), "utf8"));
const AGENT_SCHEMA_NAME = "agent-fragments.schema.json";
const SECRETS_FIXTURE = path.join(TEST_DIR, "fixtures", "secrets");
const DEFAULT_ONLY = path.join(TEST_DIR, "fixtures", "default-only");
const JUDGMENT_RULE = "SEC-05";

// Token-shaped and secret-named values, built at run time (see test/secrets.test.mjs for the same technique).
const GITHUB = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
const ANTHROPIC = ["sk", "ant", "api03"].join("-") + "-Zx41Qw82Er63Ty74Ui85Op96As07Df18Gh29Jk30Lm41Nb52Vc63";
const GENERIC_PASSWORD = "hunter2hunter2hunter2";
const SEEDED = [GITHUB, ANTHROPIC, GENERIC_PASSWORD];

// Runs a script of this repository through execFile (never a shell). Resolves with the exit code and both streams.
async function runScript(script, args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [script, ...args], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

const remediate = (args) => runScript(REMEDIATE_SCRIPT, args);

// Scans a temp copy of a fixture (with files written on top of it) into a run folder inside the copy.
async function scanFixture(fixture) {
  const runDir = path.join(fixture.base, "run");
  await execFileAsync(process.execPath, [SCAN_SCRIPT, fixture.root, "--out", runDir], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
  });
  return runDir;
}

// The files that a remediation writes, as a list of their names.
function outputsIn(dir) {
  return fs.readdirSync(dir).filter((name) => name.startsWith("remediation")).sort();
}

const agentFile = (fragments) => `${JSON.stringify({ schemaVersion: 1, fragments }, null, 2)}\n`;
const judgmentFragment = (overrides = {}) => ({
  rule: JUDGMENT_RULE,
  title: "Keep the rule in the settings",
  text: "The memory file says it; the deny rule enforces it.",
  settings: { permissions: { deny: ["Read(./notes/todo.md)"], ask: [] } },
  ...overrides,
});

describe("scripts/remediate.mjs: the exit codes", () => {
  test("exit 0 writes remediation.json and remediation.md, and prints their paths and the counts", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    const result = await remediate([run.runDir]);
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(outputsIn(run.runDir), ["remediation.json", "remediation.md"]);
    assert.match(result.stdout, /^remediation: .*remediation\.json$/m);
    assert.match(result.stdout, /^markdown: .*remediation\.md$/m);
    assert.match(result.stdout, /^fragments: \d+ \(\d+ simulated, \d+ not simulated\)$/m);
    const json = JSON.parse(fs.readFileSync(path.join(run.runDir, "remediation.json"), "utf8"));
    assert.deepEqual(schemaProblems(SCHEMA, json), [], "the written file matches its schema");
    assert.equal(json.scan.scannedAt, run.measurements.meta.scannedAt);
    const markdown = fs.readFileSync(path.join(run.runDir, "remediation.md"), "utf8");
    assert.ok(markdown.startsWith("# Remediation\n"));
    assert.ok(markdown.includes("Nothing here is written to the target"));
    assert.ok(markdown.includes("`auto` (not verified)"), "the auto column is marked not verified");
    assert.ok(markdown.includes("reordered or respelled form"), "the sample-and-prefix coverage is stated with a SEC-02 fragment");
    assert.ok(markdown.includes("Left out, because each list holds at most 200 items: 0 fragments"), "the counts of what is left out");
  });

  test("exit 0 with zero fragments: no destructive command measured, a dotenv read denied, and no secret file", async (t) => {
    // The matrix's bypassPermissions mode passes every command that removes no file, so a scan always gives fragments for the
    // data. Zero fragments needs a scan with no measured commands: the measurements are edited for that, in the temp copy.
    const fixture = makeFixture({
      fromDir: DEFAULT_ONLY,
      files: { ".claude/settings.json": `${JSON.stringify({ permissions: { deny: ["Read(./.env)"] } }, null, 2)}\n` },
    });
    t.after(fixture.cleanup);
    const runDir = await scanFixture(fixture);
    const file = path.join(runDir, "measurements.json");
    const measurements = JSON.parse(fs.readFileSync(file, "utf8"));
    measurements.security.destructiveCoverage.commands = [];
    fs.writeFileSync(file, `${JSON.stringify(measurements, null, 2)}\n`);
    const result = await remediate([runDir]);
    assert.equal(result.code, 0, result.stderr);
    const json = JSON.parse(fs.readFileSync(path.join(runDir, "remediation.json"), "utf8"));
    assert.equal(json.fragments.length, 0);
    assert.equal(json.summary.fragments, 0);
    assert.ok(fs.readFileSync(path.join(runDir, "remediation.md"), "utf8").includes("No fragment"));
  });

  test("exit 0 with a valid agent-fragments.json: the judgment fragment is in the output and in the markdown", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    fs.writeFileSync(path.join(run.runDir, "agent-fragments.json"), agentFile([judgmentFragment()]));
    const result = await remediate([run.runDir]);
    assert.equal(result.code, 0, result.stderr);
    const json = JSON.parse(fs.readFileSync(path.join(run.runDir, "remediation.json"), "utf8"));
    const agent = json.fragments.find((item) => item.origin === "agent");
    assert.equal(agent.rule, JUDGMENT_RULE);
    assert.equal(agent.simulated, true);
    assert.ok(fs.readFileSync(path.join(run.runDir, "remediation.md"), "utf8").includes("Keep the rule in the settings"));
  });

  test("exit 2 for the arguments: none, two, or an empty folder name", async () => {
    for (const args of [[], ["a", "b"], [""]]) {
      const result = await remediate(args);
      assert.equal(result.code, 2, JSON.stringify(args));
      assert.match(result.stderr, /usage: node scripts\/remediate\.mjs <runDir>/);
    }
  });

  test("exit 2 for a run folder that is not allowed, or that does not exist", async (t) => {
    const outside = await remediate([path.join(HARNESS_ROOT, "test", "fixtures")]);
    assert.equal(outside.code, 2);
    assert.match(outside.stderr, /must be inside runs\/ or the system temp folder/);
    const fixture = makeFixture({ files: { "placeholder.txt": "x\n" } });
    t.after(fixture.cleanup);
    const missing = await remediate([path.join(fixture.base, "nope")]);
    assert.equal(missing.code, 2);
    assert.match(missing.stderr, /does not exist/);
  });

  test("exit 2 when measurements.json is missing, is not JSON, or is not a scan of this tool", async (t) => {
    const fixture = makeFixture({ files: { "empty/placeholder.txt": "x\n" } });
    t.after(fixture.cleanup);
    const empty = await remediate([path.join(fixture.root, "empty")]);
    assert.equal(empty.code, 2);
    assert.match(empty.stderr, /missing input file/);

    const broken = makeFixture({ files: { "run/measurements.json": "{ not json SECRET-LIKE" } });
    t.after(broken.cleanup);
    const notJson = await remediate([path.join(broken.root, "run")]);
    assert.equal(notJson.code, 2);
    assert.match(notJson.stderr, /is not valid JSON/);
    assert.ok(!notJson.stderr.includes("SECRET-LIKE"), "the parser message is not printed");

    const other = makeFixture({ files: { "run/measurements.json": '{"meta": {}}\n' } });
    t.after(other.cleanup);
    const notScan = await remediate([path.join(other.root, "run")]);
    assert.equal(notScan.code, 2);
    assert.match(notScan.stderr, /is not a scan of this tool: it has no meta\.scannedAt/);
  });

  test("exit 2 when agent-fragments.json is not JSON, fails its schema, or breaks one of its checks", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    const file = path.join(run.runDir, "agent-fragments.json");

    fs.writeFileSync(file, "{ not json");
    assert.equal((await remediate([run.runDir])).code, 2);

    fs.writeFileSync(file, agentFile([judgmentFragment({ note: "an extra key" })]));
    const schema = await remediate([run.runDir]);
    assert.equal(schema.code, 2);
    assert.match(schema.stderr, /agent-fragments\.json does not match its schema/);

    fs.writeFileSync(file, agentFile([judgmentFragment({ rule: "SEC-02" })]));
    const notJudgment = await remediate([run.runDir]);
    assert.equal(notJudgment.code, 2);
    assert.match(notJudgment.stderr, /fragment 0: the rule is not a judgment rule of the catalog/);

    fs.writeFileSync(file, agentFile([judgmentFragment({ text: `Never paste ${ANTHROPIC} here.` })]));
    const secret = await remediate([run.runDir]);
    assert.equal(secret.code, 2);
    assert.match(secret.stderr, /holds a secret-shaped value/);
    assert.ok(!secret.stderr.includes(ANTHROPIC), "the refused value is not printed");
    assert.ok(!fs.existsSync(path.join(run.runDir, "remediation.json")), "nothing is written when an input is refused");
  });

  test("exit 2 when an output is a folder, and when remediation.json is a link to a file outside the run folder", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    fs.mkdirSync(path.join(run.runDir, "remediation.md"));
    const folder = await remediate([run.runDir]);
    assert.equal(folder.code, 2);
    assert.match(folder.stderr, /not a regular file/);
    fs.rmdirSync(path.join(run.runDir, "remediation.md"));

    if (!symlinkSupport().supported) return;
    const target = path.join(run.fixture.base, "outside.json");
    fs.writeFileSync(target, "untouched\n");
    fs.symlinkSync(target, path.join(run.runDir, "remediation.json"));
    const link = await remediate([run.runDir]);
    assert.equal(link.code, 2);
    assert.match(link.stderr, /not a regular file/);
    assert.equal(fs.readFileSync(target, "utf8"), "untouched\n", "the file the link names is not written");
  });

  test("exit 2 when measurements.json has a second hard link, and exit 0 again once it has one name", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    const measurementsFile = path.join(run.runDir, "measurements.json");
    const copy = path.join(run.fixture.base, "copy.json");
    fs.linkSync(measurementsFile, copy);
    const hard = await remediate([run.runDir]);
    assert.equal(hard.code, 2);
    assert.match(hard.stderr, /more than one hard link/);
    fs.unlinkSync(copy);
    assert.equal((await remediate([run.runDir])).code, 0, "one name again: it is read");
  });

  test("exit 1 when the run folder cannot be written, and then nothing new is written and an older file stays", async (t) => {
    if (process.platform === "win32" || (typeof process.getuid === "function" && process.getuid() === 0)) {
      t.skip("a read-only folder does not stop writes for root or on Windows");
      return;
    }
    const run = await makeRun();
    t.after(() => {
      fs.chmodSync(run.runDir, 0o755);
      run.cleanup();
    });
    fs.writeFileSync(path.join(run.runDir, "remediation.md"), "older text\n");
    fs.chmodSync(run.runDir, 0o555);
    const result = await remediate([run.runDir]);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, /^error: EACCES/m);
    assert.deepEqual(outputsIn(run.runDir), ["remediation.md"], "no new file, no temporary name");
    assert.equal(fs.readFileSync(path.join(run.runDir, "remediation.md"), "utf8"), "older text\n");
  });
});

describe("scripts/remediate.mjs: secret values never reach an output", () => {
  test("a scan with seeded values: the remediation, its markdown and the report hold no raw value", async (t) => {
    const fixture = makeFixture({
      fromDir: SECRETS_FIXTURE,
      files: {
        ...SECRET_FIXTURE_FILES,
        // The generic value sits in CLAUDE.md, which the secrets measure reads (it reads no other markdown file).
        "CLAUDE.md": `# Notes\n\nNever commit ${ANTHROPIC} to the repository.\npassword = "${GENERIC_PASSWORD}"\n`,
        ".claude/settings.json": `${JSON.stringify({ permissions: { allow: ["Bash(npm test)"] }, env: { GH_TOKEN: GITHUB } }, null, 2)}\n`,
      },
    });
    t.after(fixture.cleanup);
    const runDir = await scanFixture(fixture);
    // The scan detected the generic value first, so the absence checks below are not vacuous.
    const scanned = JSON.parse(fs.readFileSync(path.join(runDir, "measurements.json"), "utf8"));
    const generic = loadSecretPatterns().generic.id;
    assert.ok(
      scanned.security.secrets.literals.some((item) => item.file === "CLAUDE.md" && item.kind === generic),
      "the scan lists the generic value of CLAUDE.md",
    );
    fs.writeFileSync(path.join(runDir, "agent-fragments.json"), agentFile([judgmentFragment()]));
    fs.writeFileSync(path.join(runDir, "findings.json"), '{"findings": [], "language": "en"}\n');

    const result = await remediate([runDir]);
    assert.equal(result.code, 0, result.stderr);
    const rendered = await runScript(RENDER_SCRIPT, [runDir]);
    assert.equal(rendered.code, 0, rendered.stderr);

    for (const name of ["remediation.json", "remediation.md", "report.md", "report.html"]) {
      const text = fs.readFileSync(path.join(runDir, name), "utf8");
      for (const value of SEEDED) assert.ok(!text.includes(value), `${name} holds a seeded secret value`);
    }
    assertNoSeededValue(result.stdout + result.stderr, "the output of remediate");
    assertNoSeededValue(rendered.stdout + rendered.stderr, "the output of render-report");
    const json = JSON.parse(fs.readFileSync(path.join(runDir, "remediation.json"), "utf8"));
    assert.ok(json.notSimulated.length >= 2, "the literal secrets are listed by file and line");
  });
});

function assertNoSeededValue(text, label) {
  for (const value of SEEDED) assert.ok(!text.includes(value), `${label} holds a seeded secret value`);
}

describe("scripts/remediate.mjs: the inputs that are refused, and the caps", () => {
  test("exit 2 when agent-fragments.json has a key that the schema does not list, and the key is printed nowhere (positive control: without it, exit 0)", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    // A secret-shaped key name, built at run time, so this file holds no token-shaped text.
    const key = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
    const file = path.join(run.runDir, "agent-fragments.json");
    fs.writeFileSync(file, agentFile([{ ...judgmentFragment(), [key]: "x" }]));
    const refused = await remediate([run.runDir]);
    assert.equal(refused.code, 2, refused.stderr);
    assert.match(refused.stderr, /agent-fragments\.json does not match its schema: \/fragments\/0 has 1 key\(s\) that are not in the schema/);
    assert.ok(!refused.stdout.includes(key) && !refused.stderr.includes(key), "the key is in neither stream");
    assert.ok(!fs.existsSync(path.join(run.runDir, "remediation.json")), "nothing is written");

    fs.writeFileSync(file, agentFile([judgmentFragment()]));
    assert.equal((await remediate([run.runDir])).code, 0, "positive control: the same fragment without the key is accepted");
  });

  test("exit 2 when a list entry that the remediation reads is not an object, or has a field of the wrong type, and nothing is written", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    const file = path.join(run.runDir, "measurements.json");
    const original = fs.readFileSync(file, "utf8");
    const cases = [
      ["an allow entry that is null", (m) => { m.security.permissions.allow = [null]; }, /security\.permissions\.allow\[0\] is not an object/],
      ["a destructive command without its command text", (m) => { delete m.security.destructiveCoverage.commands[0].command; }, /security\.destructiveCoverage\.commands\[0\]\.command is missing or has a wrong type/],
      ["a secret file without its read decision", (m) => { m.security.secrets.files = [{ path: "x.pem", kind: "pem" }]; }, /security\.secrets\.files\[0\]\.readDecision is missing or has a wrong type/],
      ["a literal secret whose line is a string", (m) => { m.security.secrets.literals = [{ file: "a.md", line: "3", location: "text", kind: "x", masked: "y" }]; }, /security\.secrets\.literals\[0\]\.line is missing or has a wrong type/],
    ];
    for (const [name, edit, pattern] of cases) {
      const measurements = JSON.parse(original);
      edit(measurements);
      fs.writeFileSync(file, `${JSON.stringify(measurements, null, 2)}\n`);
      const result = await remediate([run.runDir]);
      assert.equal(result.code, 2, name);
      assert.match(result.stderr, /measurements\.json is not a scan of this tool/, name);
      assert.match(result.stderr, pattern, name);
      assert.ok(!fs.existsSync(path.join(run.runDir, "remediation.json")), `${name}: nothing is written`);
    }
    fs.writeFileSync(file, original);
    assert.equal((await remediate([run.runDir])).code, 0, "positive control: the original scan is accepted");
  });

  test("exit 2 when agent-fragments.json is larger than its cap, before it is read; a file of exactly the cap is read", async (t) => {
    const run = await makeRun();
    t.after(run.cleanup);
    const file = path.join(run.runDir, "agent-fragments.json");
    const text = agentFile([judgmentFragment()]);
    fs.writeFileSync(file, text + " ".repeat(AGENT_FRAGMENTS_MAX_BYTES));
    const larger = await remediate([run.runDir]);
    assert.equal(larger.code, 2, larger.stderr);
    assert.match(larger.stderr, new RegExp(`larger than ${AGENT_FRAGMENTS_MAX_BYTES} bytes`));
    fs.writeFileSync(file, text + " ".repeat(AGENT_FRAGMENTS_MAX_BYTES - Buffer.byteLength(text)));
    assert.equal((await remediate([run.runDir])).code, 0, "a file of exactly the cap is read");
  });

  test("exit 0 with more than 200 secret files: the lists are capped, the counts of what is left out are written, and render-report accepts the file", async (t) => {
    const files = {};
    for (let index = 0; index < 201; index += 1) files[`config/key-${index}.pem`] = "placeholder, not a certificate\n";
    const fixture = makeFixture({ fromDir: DEFAULT_ONLY, files });
    t.after(fixture.cleanup);
    const runDir = await scanFixture(fixture);
    fs.writeFileSync(path.join(runDir, "findings.json"), '{"findings": [], "language": "en"}\n');
    const result = await remediate([runDir]);
    assert.equal(result.code, 0, result.stderr);
    const json = JSON.parse(fs.readFileSync(path.join(runDir, "remediation.json"), "utf8"));
    assert.deepEqual(schemaProblems(SCHEMA, json), [], "the written file matches its schema");
    assert.equal(json.fragments.length, 200);
    assert.ok(json.omitted.fragments > 0, "the fragments left out are counted");
    assert.equal(json.reads.length, 200);
    const markdown = fs.readFileSync(path.join(runDir, "remediation.md"), "utf8");
    assert.ok(markdown.includes(`Left out, because each list holds at most 200 items: ${json.omitted.fragments} fragments`), "the markdown says it");
    const rendered = await runScript(RENDER_SCRIPT, [runDir]);
    assert.equal(rendered.code, 0, rendered.stderr);
    assert.ok(fs.readFileSync(path.join(runDir, "report.md"), "utf8").includes("Left out, because each list holds at most 200 items"));
  });
});
