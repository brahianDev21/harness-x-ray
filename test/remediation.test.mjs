// Tests of lib/remediation.mjs: the checks of the agent's fragments, and the fragments and the simulation built from a scan.
// The scans run through the command line on temp copies of fixtures (makeRun, or makeFixture with scanFixture below). The
// seeded secret values are built at run time, so this file holds no secret-shaped text, and they are written only into the temp
// copies. Every output of the remediation is checked for them.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { loadDestructiveCommands } from "../scripts/lib/destructive-commands.mjs";
import { MATRIX_MODES, decide, matchBash, parseRule } from "../scripts/lib/permissions.mjs";
import { createRedactor } from "../scripts/lib/redact.mjs";
import {
  anyStringHoldsSecretShape,
  buildRemediation,
  checkAgentFragments,
  commandResult,
  holdsSecretShape,
} from "../scripts/lib/remediation.mjs";
import { loadSecretPatterns } from "../scripts/lib/secret-patterns.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";
import { SECRET_FIXTURE_FILES } from "./helpers/secret-fixture-files.mjs";
import { SCAN_SCRIPT, makeRun } from "./helpers/report-run.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SECRETS_FIXTURE = path.join(TEST_DIR, "fixtures", "secrets");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "remediation.schema.json"), "utf8"));
const JUDGMENT = new Set(["SEC-05"]);
const NOT_REDACTED = (value) => value;

// Token-shaped and secret-named values, built at run time (see test/secrets.test.mjs for the same technique).
const GITHUB = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");
const ANTHROPIC = ["sk", "ant", "api03"].join("-") + "-Zx41Qw82Er63Ty74Ui85Op96As07Df18Gh29Jk30Lm41Nb52Vc63";
const GENERIC_PASSWORD = "hunter2hunter2hunter2";
const SEEDED = [GITHUB, ANTHROPIC, GENERIC_PASSWORD];

// Scans a temp copy of the secrets fixture with the given files written on top, and returns the run folder and measurements.
async function scanFixture(fixture) {
  const runDir = path.join(fixture.base, "run");
  await execFileAsync(process.execPath, [SCAN_SCRIPT, fixture.root, "--out", runDir], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
  return { runDir, measurements: JSON.parse(fs.readFileSync(path.join(runDir, "measurements.json"), "utf8")) };
}

// The seeded values sit in the places the secrets measure reads: a memory file (a token, and a generic assignment), and the env of
// the settings. The measure does not read other markdown files, so a generic value written there would be invisible to it.
function seededFiles() {
  return {
    ...SECRET_FIXTURE_FILES,
    "CLAUDE.md": `# Notes\n\nNever commit ${ANTHROPIC} to the repository.\npassword = "${GENERIC_PASSWORD}"\n`,
    ".claude/settings.json": `${JSON.stringify({ permissions: { allow: ["Bash(npm test)"] }, env: { GH_TOKEN: GITHUB, LOG_LEVEL: "info" } }, null, 2)}\n`,
  };
}

function assertNoSeededValue(text, label) {
  for (const value of SEEDED) assert.ok(!text.includes(value), `${label} holds a seeded secret value`);
}

// Every rule of a fragment, and the settings it prints as JSON, parse as the settings shape says.
function assertSettingsShape(settings) {
  const printed = JSON.stringify(settings, null, 2);
  assert.deepEqual(JSON.parse(printed), settings, "the printed settings parse back to the same object");
  assert.deepEqual(Object.keys(settings), ["permissions"]);
  assert.deepEqual(Object.keys(settings.permissions).sort(), ["ask", "deny"]);
  for (const list of [settings.permissions.deny, settings.permissions.ask]) {
    assert.ok(Array.isArray(list));
    for (const rule of list) {
      assert.equal(typeof rule, "string");
      const parsed = parseRule(rule);
      assert.ok(parsed.ok && parsed.skipped !== true, `the rule ${JSON.stringify(rule)} parses`);
    }
  }
}

const idsOf = (fragment) => fragment.targets.filter((target) => target.kind === "command").map((target) => target.id);
const rowOf = (remediation, id) => remediation.commands.find((row) => row.id === id);

describe("checkAgentFragments", () => {
  const item = (overrides = {}) => ({
    rule: "SEC-05",
    title: "Keep the rule in the settings",
    text: "The sentence in the memory file is the only control; add a deny rule for it.",
    settings: { permissions: { deny: ["Read(./notes/todo.md)"], ask: [] } },
    ...overrides,
  });
  const check = (items, redact = NOT_REDACTED) => checkAgentFragments(items, { judgmentRules: JUDGMENT, redact });

  test("a normal fragment is accepted, and its text is redacted (positive control)", () => {
    const [checked] = check([item()]);
    assert.equal(checked.rule, "SEC-05");
    assert.equal(checked.title, "Keep the rule in the settings");
    assert.deepEqual(checked.settings, { permissions: { deny: ["Read(./notes/todo.md)"], ask: [] } });
    const home = (value) => value.replaceAll("/home/someone", "~");
    const [redacted] = check([item({ text: "Read /home/someone/notes first." })], home);
    assert.equal(redacted.text, "Read ~/notes first.");
  });

  test("a rule that is not a judgment rule of the catalog is refused, and the refusal names the index only", () => {
    assert.throws(() => check([item({ rule: "SEC-02" })]), /fragment 0: the rule is not a judgment rule of the catalog/);
    assert.doesNotThrow(() => check([item()]));
  });

  test("a secret-shaped value in a text or a rule is refused, and the value is not in the message", () => {
    const withToken = item({ text: `Do not paste ${ANTHROPIC} anywhere.` });
    assert.throws(
      () => check([withToken]),
      (error) => /holds a secret-shaped value/.test(error.message) && !error.message.includes(ANTHROPIC),
    );
    const tokenInRule = item({ settings: { permissions: { deny: [`Bash(curl -H ${GITHUB} *)`], ask: [] } } });
    assert.throws(() => check([tokenInRule]), /holds a secret-shaped value/);
    assert.doesNotThrow(() => check([item({ text: "Do not paste a token anywhere." })]));
  });

  test("a rule that does not parse is refused, and its text is not printed", () => {
    const broken = item({ settings: { permissions: { deny: ["Read(./notes/todo.md"], ask: [] } } });
    assert.throws(() => check([broken]), (error) => /does not parse/.test(error.message) && !error.message.includes("todo.md"));
  });

  test("a rule that names a folder of this machine is refused, because the redactor would change it", () => {
    const home = (value) => value.replaceAll("/home/someone", "~");
    const local = item({ settings: { permissions: { deny: ["Read(/home/someone/notes/todo.md)"], ask: [] } } });
    assert.throws(() => check([local], home), /names a folder of this machine/);
  });

  test("a fragment without settings is accepted, with settings null", () => {
    const [checked] = check([item({ settings: undefined })]);
    assert.equal(checked.settings, null);
  });
});

describe("buildRemediation on a scan of the permissive fixture", () => {
  let run;
  before(async () => {
    run = await makeRun();
  });
  after(() => run?.cleanup());

  test("every fragment's settings print as JSON that parses back, with rules that parse", () => {
    const remediation = buildRemediation({ measurements: run.measurements });
    const withSettings = remediation.fragments.filter((fragment) => fragment.settings !== null);
    assert.ok(withSettings.length > 0, "the permissive scan gives fragments");
    for (const fragment of withSettings) assertSettingsShape(fragment.settings);
    assert.deepEqual(schemaProblems(SCHEMA, remediation), [], "the remediation matches its schema");
  });

  test("SEC-01: the broad git allow narrows to ask rules for the destructive git commands, and they move", () => {
    const remediation = buildRemediation({ measurements: run.measurements });
    const sec01 = remediation.fragments.find((fragment) => fragment.rule === "SEC-01");
    assert.ok(sec01, "a SEC-01 fragment exists");
    assert.ok(sec01.settings.permissions.ask.includes("Bash(git push --force *)"));
    assert.ok(sec01.settings.permissions.ask.includes("Bash(git reset --hard *)"));
    for (const id of idsOf(sec01)) {
      const row = rowOf(remediation, id);
      assert.equal(row.result, "moved", `${id} moves`);
      assert.ok(["asks", "blocked"].includes(row.after.outcome), `${id} asks or is blocked after the patch`);
      assert.ok(Object.values(row.after.modes).every((outcome) => outcome !== "passes"), `${id} passes in no mode after the patch`);
    }
  });

  test("SEC-02: every command that passes today (outcome, a mode or a subagent) is targeted, and no other command is", () => {
    const remediation = buildRemediation({ measurements: run.measurements });
    const coverage = run.measurements.security.destructiveCoverage;
    const subagentPasses = new Set(
      (coverage.subagents ?? []).flatMap((agent) => agent.results.filter((item) => item.outcome === "passes").map((item) => item.id)),
    );
    const passing = coverage.commands
      .filter((command) => command.outcome === "passes" || Object.values(command.modes).includes("passes") || subagentPasses.has(command.id))
      .map((command) => command.id);
    const targeted = remediation.fragments.flatMap(idsOf);
    assert.deepEqual(new Set(targeted), new Set(passing));
    assert.equal(targeted.length, new Set(targeted).size, "each command is targeted once");
    const data = new Map(loadDestructiveCommands().map((command) => [command.id, command]));
    for (const fragment of remediation.fragments.filter((item) => item.rule === "SEC-02")) {
      const [id] = idsOf(fragment);
      assert.deepEqual(fragment.settings.permissions.ask, [data.get(id).coverRule], `${id} gets its data rule`);
      assert.deepEqual(fragment.settings.permissions.deny, []);
    }
  });

  test("every row has its after value for each mode, and a moved row has no mode that passes", () => {
    const remediation = buildRemediation({ measurements: run.measurements });
    for (const row of remediation.commands) {
      if (row.result === "not-simulated") continue;
      assert.deepEqual(Object.keys(row.after.modes), [...MATRIX_MODES]);
      if (row.result === "moved") assert.ok(Object.values(row.after.modes).every((outcome) => outcome !== "passes"));
    }
  });

  test("a command whose rule does not match is marked still-passes, never hidden", () => {
    const data = loadDestructiveCommands().map((command) =>
      command.id === "git-branch-force-delete" ? { ...command, coverRule: "Bash(no-such-command *)" } : command,
    );
    const remediation = buildRemediation({ measurements: run.measurements, destructiveCommands: data });
    const row = rowOf(remediation, "git-branch-force-delete");
    assert.equal(row.result, "still-passes", "the Bash(git *) allow still passes it");
    assert.equal(remediation.summary.commandsStillPassing >= 1, true);
  });

  test("a critical command in the data gets a deny rule, and that command is blocked after the patch", () => {
    const data = loadDestructiveCommands().map((command) =>
      command.id === "rm-recursive-force" ? { ...command, criticalPath: true } : command,
    );
    const remediation = buildRemediation({ measurements: run.measurements, destructiveCommands: data });
    const fragment = remediation.fragments.find((item) => item.rule === "SEC-02" && idsOf(item).includes("rm-recursive-force"));
    assert.ok(fragment, "rm is targeted by SEC-02 (it passes in acceptEdits)");
    assert.deepEqual(fragment.settings.permissions.deny, ["Bash(rm -rf *)"]);
    assert.deepEqual(fragment.settings.permissions.ask, []);
    const row = rowOf(remediation, "rm-recursive-force");
    assert.equal(row.after.outcome, "blocked");
    assert.equal(row.result, "moved");
  });

  test("a command whose simulated before differs from the measured value is not simulated, and its fragment is not applied", () => {
    const measurements = structuredClone(run.measurements);
    const command = measurements.security.destructiveCoverage.commands.find((item) => item.id === "git-push-force-long");
    command.modes.default = "blocked";
    const remediation = buildRemediation({ measurements });
    const row = rowOf(remediation, "git-push-force-long");
    assert.equal(row.result, "not-simulated");
    assert.equal(row.reason, "simulation-mismatch");
    assert.equal(row.after, null);
    const fragment = remediation.fragments.find((item) => item.rule === "SEC-01" && idsOf(item).includes("git-push-force-long"));
    assert.equal(fragment.simulated, false, "its fragment is not in the patch");
    assert.equal(fragment.reason, "simulation-mismatch");
    assert.ok(fragment.settings.permissions.ask.includes("Bash(git push --force *)"), "the rule is still shown for review");
  });

  test("the summary counts match the rows and the fragments", () => {
    const remediation = buildRemediation({ measurements: run.measurements });
    const { summary } = remediation;
    assert.equal(summary.fragments, remediation.fragments.length);
    assert.equal(summary.simulatedFragments + summary.notSimulatedFragments, summary.fragments);
    assert.equal(summary.commandsMoved, remediation.commands.filter((row) => row.result === "moved").length);
    assert.equal(summary.commandsStillPassing, remediation.commands.filter((row) => row.result === "still-passes").length);
    assert.equal(summary.notSimulatedItems, remediation.notSimulated.length);
  });
});

describe("buildRemediation: secret reads, literals and agent fragments", () => {
  let fixture;
  let scanned;
  before(async () => {
    fixture = makeFixture({ fromDir: SECRETS_FIXTURE, files: seededFiles() });
    scanned = await scanFixture(fixture);
  });
  after(() => fixture?.cleanup());

  test("a secret file that is readable gets a deny of Read(./<path>), and its read moves to deny", () => {
    const remediation = buildRemediation({ measurements: scanned.measurements });
    const fragment = remediation.fragments.find((item) => item.rule === "SEC-03" && item.targets[0]?.path === "config/server.pem");
    assert.ok(fragment, "a SEC-03 fragment for the pem file exists");
    assert.deepEqual(fragment.settings, { permissions: { deny: ["Read(./config/server.pem)"], ask: [] } });
    const row = remediation.reads.find((item) => item.path === "config/server.pem");
    assert.equal(row.measured, "default");
    assert.equal(row.after, "deny");
    assert.equal(row.result, "moved");
    assert.deepEqual(
      remediation.reads.map((item) => item.path),
      [...new Set(remediation.reads.map((item) => item.path))],
      "each path has one row",
    );
  });

  test("a literal secret is listed as not simulated, by file and line only, and no value appears in the remediation", () => {
    const remediation = buildRemediation({ measurements: scanned.measurements });
    const generic = loadSecretPatterns().generic.id;
    assert.ok(
      remediation.notSimulated.some((item) => item.file === "CLAUDE.md" && item.secretKind === generic),
      "the scan detected the generic value in CLAUDE.md, so the check below is not vacuous",
    );
    assert.ok(remediation.notSimulated.length >= 2, "the seeded literals are found");
    for (const item of remediation.notSimulated) {
      assert.equal(item.kind, "literal-secret");
      assert.equal(item.reason, "literal-secret");
      assert.deepEqual(Object.keys(item).sort(), ["file", "kind", "line", "location", "reason", "rule", "secretKind"]);
    }
    assert.ok(remediation.notSimulated.some((item) => item.file === "CLAUDE.md"));
    assertNoSeededValue(JSON.stringify(remediation), "the remediation");
    assert.deepEqual(schemaProblems(SCHEMA, remediation), []);
  });

  test("an agent's permission fragment with shell and Read rules is simulated; a text-only one is not", () => {
    const agentFragments = checkAgentFragments(
      [
        {
          rule: "SEC-05",
          title: "Block the push",
          text: "The memory file says it; a deny rule enforces it.",
          settings: { permissions: { deny: ["Bash(git push origin *)"], ask: ["Read(./notes/todo.md)"] } },
        },
        { rule: "SEC-05", title: "Write it down", text: "Add a line to the memory file." },
        {
          rule: "SEC-05",
          title: "Fetch rule",
          text: "A fetch rule is not simulated.",
          settings: { permissions: { deny: ["WebFetch(domain:example.com)"], ask: [] } },
        },
      ],
      { judgmentRules: JUDGMENT, redact: NOT_REDACTED },
    );
    const remediation = buildRemediation({ measurements: scanned.measurements, agentFragments });
    const [first, second, third] = remediation.fragments.filter((fragment) => fragment.origin === "agent");
    assert.equal(first.simulated, true);
    assert.equal(first.kind, "permissions");
    assert.equal(second.simulated, false);
    assert.equal(second.reason, "not-permission");
    assert.equal(second.kind, "other");
    assert.equal(third.simulated, false);
    assert.equal(third.reason, "not-modelled-rule");
    assert.deepEqual(first.targets, []);
    assert.equal(first.measuredFindingId, null);
    assert.ok(remediation.reads.some((row) => row.path === "config/server.pem" && row.result === "moved"));
    assert.deepEqual(schemaProblems(SCHEMA, remediation), []);
  });

  test("the agent's text is kept as data: it is in the output as written, for the views to escape", () => {
    const agentFragments = checkAgentFragments(
      [{ rule: "SEC-05", title: "A *title* with _marks_", text: "See [this](x) and <b>tags</b>.", settings: undefined }],
      { judgmentRules: JUDGMENT, redact: NOT_REDACTED },
    );
    const remediation = buildRemediation({ measurements: scanned.measurements, agentFragments });
    const fragment = remediation.fragments.find((item) => item.origin === "agent");
    assert.equal(fragment.title, "A *title* with _marks_");
    assert.equal(fragment.text, "See [this](x) and <b>tags</b>.");
  });
});

// The checks of an agent's fragments, with the judgment rule of the tests and no redaction (no folder of this machine is named).
const checkedWith = (items) => checkAgentFragments(items, { judgmentRules: JUDGMENT, redact: NOT_REDACTED });

describe("the coverage of a destructive command's rule, and the texts that state it", () => {
  const coverOf = (id) => loadDestructiveCommands().find((command) => command.id === id).coverRule;
  const covers = (id, command) => matchBash(parseRule(coverOf(id)).specifier, command);

  test("a rule covers its sample command and the same prefix followed by any arguments (positive control)", () => {
    assert.equal(covers("git-push-force-long", "git push --force"), true, "the sample command");
    assert.equal(covers("git-push-force-long", "git push --force origin main"), true, "the same prefix with arguments");
    assert.equal(covers("rm-recursive-force", "rm -rf build"), true, "the sample command of rm");
  });

  test("a reordered or respelled form is not covered by the rule of its command", () => {
    assert.equal(covers("git-push-force-long", "git push origin --force"), false, "a reordered form");
    assert.equal(covers("rm-recursive-force", "rm -fr build"), false, "a respelled form");
    assert.equal(covers("rm-recursive-force", "rm build -rf"), false, "a reordered form of rm");
  });

  test("the texts state the coverage as the sample and the same prefix with any arguments, and none claims coverage with any arguments", () => {
    const read = (...parts) => fs.readFileSync(path.join(HARNESS_ROOT, ...parts), "utf8");
    const texts = {
      "templates/labels.en.json": read("templates", "labels.en.json"),
      "templates/labels.es.json": read("templates", "labels.es.json"),
      "scripts/lib/remediation.mjs": read("scripts", "lib", "remediation.mjs"),
      "scripts/lib/destructive-commands.mjs": read("scripts", "lib", "destructive-commands.mjs"),
      "README.md": read("README.md"),
    };
    for (const [name, text] of Object.entries(texts)) {
      assert.doesNotMatch(text, /covers the command with any arguments/i, `${name} claims coverage with any arguments`);
      assert.doesNotMatch(text, /Cubre el comando con cualquier argumento/, `${name} claims coverage with any arguments`);
    }
    assert.match(texts["templates/labels.en.json"], /the same prefix followed by any arguments/);
    assert.match(texts["templates/labels.en.json"], /reordered or respelled form/);
    assert.match(texts["templates/labels.es.json"], /el mismo prefijo seguido de cualquier argumento/);
    assert.match(texts["templates/labels.es.json"], /otro orden/);
  });
});

describe("buildRemediation on the permissive scan: notes, marks, an empty fragment and the caps", () => {
  let run;
  before(async () => {
    run = await makeRun();
  });
  after(() => run?.cleanup());

  test("a measured fragment shows the coverNote of its data entry, and a fragment whose entries have none shows null", () => {
    const data = loadDestructiveCommands().map((command) =>
      command.id === "rm-recursive-force" ? { ...command, coverNote: "Covers every rm with these flags, in any folder." } : command,
    );
    const remediation = buildRemediation({ measurements: run.measurements, destructiveCommands: data });
    const noted = remediation.fragments.find((item) => idsOf(item).includes("rm-recursive-force"));
    assert.equal(noted.coverNote, "Covers every rm with these flags, in any folder.");
    // A fragment shows the notes of its own commands, once each, and null when none of them has one (a read has none either).
    for (const fragment of remediation.fragments.filter((item) => item.origin === "measured")) {
      const notes = [...new Set(idsOf(fragment).map((id) => data.find((command) => command.id === id).coverNote).filter(Boolean))];
      assert.equal(fragment.coverNote, notes.length === 0 ? null : notes.join(" "), fragment.id);
    }
    assert.ok(remediation.fragments.some((item) => item.coverNote === null), "positive control: a fragment with no note gives null");
  });

  test("each command row lists auto and bypassPermissions as not verified when the scan has a matrix, and nothing otherwise", () => {
    const remediation = buildRemediation({ measurements: run.measurements });
    assert.ok(remediation.commands.some((row) => row.measured.modes !== null), "positive control: a row has a matrix");
    for (const row of remediation.commands) {
      assert.deepEqual(row.notVerified, row.measured.modes === null ? [] : ["auto", "bypassPermissions"], row.id);
    }
  });

  test("an agent's fragment with no rule is not simulated, and its reason is no-rule", () => {
    const remediation = buildRemediation({
      measurements: run.measurements,
      agentFragments: checkedWith([{ rule: "SEC-05", title: "Nothing", text: "No rule at all.", settings: { permissions: { deny: [], ask: [] } } }]),
    });
    const fragment = remediation.fragments.find((item) => item.origin === "agent");
    assert.equal(fragment.simulated, false);
    assert.equal(fragment.reason, "no-rule");
    assert.equal(fragment.kind, "permissions");
    assert.equal(remediation.summary.simulatedFragments, remediation.fragments.filter((item) => item.simulated).length);
  });

  test("a list longer than the cap is cut to the cap, the rest is counted in omitted, and only the kept fragments are simulated", () => {
    const base = buildRemediation({ measurements: run.measurements });
    const measurements = structuredClone(run.measurements);
    const extra = Array.from({ length: 250 }, (_, index) => ({
      path: `config/key-${index}.pem`,
      kind: "pem",
      readDecision: { decision: "default", rule: null, source: null, reason: "default-mode", list: null },
    }));
    measurements.security.secrets.files.push(...extra);
    const remediation = buildRemediation({ measurements });
    const total = base.fragments.length + base.omitted.fragments + extra.length;
    assert.equal(remediation.omitted.cap, 200);
    assert.equal(remediation.fragments.length, 200);
    assert.equal(remediation.omitted.fragments, total - 200, "the fragments left out are counted");
    assert.equal(remediation.fragments[0].id, "fr-1", "the kept fragments are the first ones");
    assert.equal(remediation.summary.fragments, 200, "the summary counts the kept fragments");
    assert.equal(remediation.summary.simulatedFragments, remediation.fragments.filter((item) => item.simulated).length);
    assert.equal(remediation.reads.length, 200, "the reads are capped too");
    assert.ok(remediation.omitted.reads > 0, "and the reads left out are counted");
    assert.deepEqual(schemaProblems(SCHEMA, remediation), [], "the capped remediation matches its schema");
    assert.deepEqual(schemaProblems(SCHEMA, base), [], "positive control: the uncapped scan matches it too");
  });
});

describe("buildRemediation: the agent's rules that the simulation cannot decide", () => {
  let fixture;
  let scanned;
  before(async () => {
    fixture = makeFixture({ fromDir: SECRETS_FIXTURE, files: seededFiles() });
    scanned = await scanFixture(fixture);
  });
  after(() => fixture?.cleanup());

  const agent = (deny, ask = []) => ({ rule: "SEC-05", title: "Agent rule", text: "Agent text.", settings: { permissions: { deny, ask } } });
  const reasonOf = (rule) => {
    const remediation = buildRemediation({ measurements: scanned.measurements, agentFragments: checkedWith([agent([rule])]) });
    return remediation.fragments.find((item) => item.origin === "agent");
  };

  test("a Read rule with a home path makes every read undeterminable in the simulator, so its fragment is not applied", () => {
    assert.equal(decide({ deny: ["Read(~/.ssh/**)"] }, { tool: "Read", path: "config/server.pem" }).decision, "undeterminable", "positive control");
    const agentFragments = checkedWith([agent(["Read(~/.ssh/**)"]), agent(["Read(./notes/todo.md)"])]);
    const remediation = buildRemediation({ measurements: scanned.measurements, agentFragments });
    const [home, notes] = remediation.fragments.filter((item) => item.origin === "agent");
    assert.equal(home.simulated, false);
    assert.equal(home.reason, "undecidable-rule");
    assert.equal(notes.simulated, true, "positive control: a decidable Read rule is simulated");
    const row = remediation.reads.find((item) => item.path === "config/server.pem");
    assert.equal(row.after, "deny", "the measured deny stays, since the undecidable rule is not in the patch");
    assert.ok(remediation.reads.every((item) => item.after !== "undeterminable"), "no read becomes undeterminable");
  });

  test("each rule that permissions.mjs cannot decide for some path or command is undecidable, and each one it decides is simulated", () => {
    for (const rule of ["Read(~/x)", "Read(!notes/x.md)", "Read(../x)", "Read(a/../b)", "Read(a//b)", "Read(a[1].txt)", "Read(//etc/x)", "Read(/)", "Bash(run_in_background: true)"]) {
      assert.equal(reasonOf(rule).reason, "undecidable-rule", rule);
    }
    for (const rule of ["Read(./notes/todo.md)", "Read(notes/*.md)", "Read(/notes/todo.md)", "Read(//**)", "Read(//**/secrets/*)", "Bash(git push origin *)"]) {
      assert.equal(reasonOf(rule).simulated, true, `${rule} is decided, so it is simulated`);
    }
  });

  test("a fragment with no rule is not simulated, and its reason is no-rule", () => {
    const remediation = buildRemediation({ measurements: scanned.measurements, agentFragments: checkedWith([agent([])]) });
    const fragment = remediation.fragments.find((item) => item.origin === "agent");
    assert.equal(fragment.simulated, false);
    assert.equal(fragment.reason, "no-rule");
  });

  test("an agent's title or text longer than its cap after redaction is refused, and the cap itself is accepted (positive control)", () => {
    assert.doesNotThrow(() => checkedWith([{ rule: "SEC-05", title: "t".repeat(120), text: "x", settings: undefined }]));
    assert.throws(
      () => checkedWith([{ rule: "SEC-05", title: "t".repeat(121), text: "x", settings: undefined }]),
      /longer than its limit once the folders of this machine are redacted/,
    );
  });
});

describe("commandResult and the secret-shape helpers", () => {
  const modes = (outcome, auto) => ({ default: outcome, acceptEdits: outcome, auto, bypassPermissions: outcome });

  test("a command that passed and that auto mode would leave to the classifier is classifier, not moved (positive control: all asks is moved)", () => {
    assert.equal(commandResult(true, { outcome: "asks", modes: modes("asks", "classifier") }), "classifier");
    assert.equal(commandResult(true, { outcome: "asks", modes: modes("asks", "asks") }), "moved");
  });

  test("an undeterminable mode wins over the classifier, a passing mode makes it still-passes, and a command that did not pass is unchanged", () => {
    assert.equal(commandResult(true, { outcome: "asks", modes: { ...modes("asks", "classifier"), bypassPermissions: "undeterminable" } }), "undeterminable");
    assert.equal(commandResult(true, { outcome: "asks", modes: { ...modes("asks", "asks"), bypassPermissions: "passes" } }), "still-passes");
    assert.equal(commandResult(false, { outcome: "asks", modes: modes("asks", "classifier") }), "unchanged");
  });

  test("a token or a generic assignment is secret-shaped, and a plain sentence is not (positive control)", () => {
    assert.equal(holdsSecretShape(`Never paste ${ANTHROPIC} here.`), true);
    assert.equal(holdsSecretShape(`password = "${GENERIC_PASSWORD}"`), true);
    assert.equal(holdsSecretShape("Do not paste a token anywhere."), false);
  });

  test("anyStringHoldsSecretShape looks at every string of a value, and not at numbers, booleans or nulls", () => {
    assert.equal(anyStringHoldsSecretShape({ a: ["ok", { b: `x ${ANTHROPIC}` }] }), true);
    assert.equal(anyStringHoldsSecretShape({ a: ["ok", 3, null, true] }), false);
  });
});
