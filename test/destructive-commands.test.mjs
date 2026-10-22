import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { claudeConfigMeasure } from "../scripts/lib/claude-config.mjs";
import {
  destructiveCommandsMeasure,
  hookFilterState,
  loadDestructiveCommands,
  toolsCoveredBy,
  validateDestructiveData,
} from "../scripts/lib/destructive-commands.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { MATRIX_MODES } from "../scripts/lib/permissions.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const DATA_FILE = path.join(HARNESS_ROOT, "data", "destructive-commands.json");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "measurements.schema.json");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
const MEASURES = [claudeConfigMeasure, destructiveCommandsMeasure];

// The commands of the data file, in data order, and the groups that the expectations use.
const ALL_IDS = [
  "rm-recursive-force",
  "git-push-force-long",
  "git-push-force-short",
  "git-reset-hard",
  "git-clean-force",
  "git-checkout-discard",
  "git-restore-discard",
  "git-branch-force-delete",
  "curl-pipe-shell",
  "wget-pipe-bash",
  "chmod-recursive-777",
  "npm-publish",
  "docker-system-prune",
  "remove-item-recurse-force",
  "cmd-rd-recurse-quiet",
  "cmd-del-recurse-quiet",
];
const GIT_IDS = ALL_IDS.filter((id) => id.startsWith("git-"));
const BASH_IDS = ALL_IDS.slice(0, 13);
const POWERSHELL_IDS = ALL_IDS.slice(13);
// Commands that acceptEdits does not approve: they ask, whatever the mode is (docs: acceptEdits mode).
const ASK_IN_ACCEPT_EDITS = ["curl-pipe-shell", "wget-pipe-bash", "chmod-recursive-777", "npm-publish", "docker-system-prune", "cmd-rd-recurse-quiet", "cmd-del-recurse-quiet"];
// The minimum commands that the data must list: shell, the tool that runs it, and the start of the command text.
const MINIMUM = [
  ["bash", "Bash", "rm -rf "],
  ["bash", "Bash", "git push --force"],
  ["bash", "Bash", "git push -f"],
  ["bash", "Bash", "git reset --hard"],
  ["bash", "Bash", "git clean -fdx"],
  ["bash", "Bash", "git checkout -- ."],
  ["bash", "Bash", "git restore ."],
  ["bash", "Bash", "git branch -D "],
  ["bash", "Bash", "curl "],
  ["bash", "Bash", "wget "],
  ["bash", "Bash", "chmod -R 777 "],
  ["bash", "Bash", "npm publish"],
  ["bash", "Bash", "docker system prune -af"],
  ["powershell", "PowerShell", "Remove-Item -Recurse -Force "],
  ["cmd", "PowerShell", "cmd /c rd /s /q "],
  ["cmd", "PowerShell", "cmd /c del /s /q "],
];

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

// A copy of a fixture in a temp folder, with files written on top of the copy. The scanner refuses a target inside
// this repository, so every test scans a copy.
function copyOf(t, name, files = {}) {
  const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), files });
  t.after(fixture.cleanup);
  return fixture;
}

async function coverageOf(root) {
  const result = await scan({ root, measures: MEASURES, now: FIXED_NOW });
  return result.security.destructiveCoverage;
}

const byId = (items) => new Map(items.map((item) => [item.id, item]));
const byName = (subagents) => new Map(subagents.map((agent) => [agent.name, agent]));
const resultOf = (subagent, id) => subagent.results.find((item) => item.id === id);
const PROJECT_RULE = (list, rule) => ({ kind: "rule", list, rule, source: ".claude/settings.json" });

test("the data lists every minimum command, each with the shell and the tool that runs it", () => {
  const commands = loadDestructiveCommands();
  for (const [shell, tool, prefix] of MINIMUM) {
    assert.ok(
      commands.some((command) => command.shell === shell && command.tool === tool && command.command.startsWith(prefix)),
      `missing ${shell} command ${prefix}`,
    );
  }
  for (const id of ["curl-pipe-shell", "wget-pipe-bash"]) {
    assert.equal(commands.find((command) => command.id === id).parts.length, 2, `${id} is a pipe, with two parts`);
  }
  assert.deepEqual(commands.map((command) => command.id), ALL_IDS);
});

test("the data file is valid and is the file the measure reads", () => {
  const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  assert.deepEqual(validateDestructiveData(data), data.commands);
  assert.deepEqual(loadDestructiveCommands().map((command) => command.id), data.commands.map((command) => command.id));
  const ids = data.commands.map((command) => command.id);
  assert.equal(new Set(ids).size, ids.length, "ids are unique");
  for (const command of data.commands) {
    assert.match(command.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    assert.match(command.category, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    assert.equal(typeof command.insideProject, "boolean");
    assert.equal(command.criticalPath, false, `${command.id} targets the build folder, not a critical path`);
  }
});

test("the data validator refuses a file that breaks its rules", () => {
  const valid = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  const cases = [
    ["a duplicate id", (data) => { data.commands[1].id = data.commands[0].id; }, /duplicate id/],
    ["an id that is not kebab-case", (data) => { data.commands[0].id = "Rm_Build"; }, /kebab-case/],
    ["a missing field", (data) => { delete data.commands[0].category; }, /has no "category"/],
    ["an unknown field", (data) => { data.commands[0].note = "x"; }, /unknown field "note"/],
    ["a shell that does not match its tool", (data) => { data.commands[0].tool = "PowerShell"; }, /does not match/],
    ["a cmd command without cmd /c", (data) => { data.commands[14].command = "rd /s /q build"; }, /cmd \/c/],
    ["parts with one command", (data) => { data.commands[8].parts = ["curl example"]; }, /parts must be/],
    ["a criticalPath that is not a boolean", (data) => { data.commands[0].criticalPath = "no"; }, /criticalPath must be a boolean/],
    ["an empty list", (data) => { data.commands = []; }, /non-empty commands list/],
  ];
  for (const [name, breakIt, pattern] of cases) {
    const broken = structuredClone(valid);
    breakIt(broken);
    assert.throws(() => validateDestructiveData(broken), pattern, name);
  }
});

test("hook matchers: exact names, lists, regular expressions, the wildcard, empty and omitted matchers", () => {
  const both = ["Bash", "PowerShell"];
  assert.deepEqual(toolsCoveredBy("Bash"), ["Bash"], "an exact name");
  assert.deepEqual(toolsCoveredBy("PowerShell"), ["PowerShell"]);
  assert.deepEqual(toolsCoveredBy("bash"), [], "exact names are case-sensitive");
  assert.deepEqual(toolsCoveredBy("Read|Edit"), [], "exact names that are not shell tools cover nothing");
  assert.deepEqual(toolsCoveredBy("Bash|PowerShell"), both, "a list separated by |");
  assert.deepEqual(toolsCoveredBy("Bash, PowerShell"), both, "a list separated by ',', whitespace trimmed");
  assert.deepEqual(toolsCoveredBy("Shell"), [], "letters only make an exact name, so Shell is no tool");
  assert.deepEqual(toolsCoveredBy("Shell$"), ["PowerShell"], "a matcher with other characters is a regular expression");
  assert.deepEqual(toolsCoveredBy("^Bash$|Shell$"), both);
  assert.deepEqual(toolsCoveredBy("mcp__.*"), [], "a regular expression that matches no shell tool");
  assert.deepEqual(toolsCoveredBy("*"), both, "the wildcard");
  assert.deepEqual(toolsCoveredBy(""), both, "an empty matcher");
  assert.deepEqual(toolsCoveredBy(null), both, "an omitted matcher");
  assert.equal(toolsCoveredBy("Bash("), "undeterminable", "an invalid regular expression");
  assert.equal(toolsCoveredBy("(Bash"), "undeterminable", "an invalid regular expression");
});

test("hook filters: the if rule decides whether the hook runs for a call", () => {
  const gitPush = { tool: "Bash", command: "git push --force" };
  assert.equal(hookFilterState(null, gitPush), "runs", "no filter lets every call through");
  assert.equal(hookFilterState("Bash(git *)", gitPush), "runs");
  assert.equal(hookFilterState("Bash(git *)", { tool: "Bash", command: "rm -rf build" }), "none");
  assert.equal(hookFilterState("Bash(git *)", { tool: "PowerShell", command: "git push" }), "none", "another tool");
  assert.equal(
    hookFilterState("Bash(git *)", { tool: "Bash", command: "npm test && git push", parts: ["npm test", "git push"] }),
    "runs",
    "a match in any part of a compound command",
  );
  assert.equal(hookFilterState("PowerShell(Remove-Item *)", { tool: "PowerShell", command: "Remove-Item -Recurse -Force build" }), "runs");
  assert.equal(hookFilterState("Bash(", gitPush), "undeterminable", "a rule that cannot be read");
});

test("permissive: the allow rule and acceptEdits pass the commands that they cover, and the rest asks", async (t) => {
  const coverage = await coverageOf(copyOf(t, "permissive").root);
  const results = byId(coverage.commands);

  assert.equal(coverage.mode.value, "acceptEdits");
  assert.deepEqual(coverage.commands.map((command) => command.id), ALL_IDS);
  for (const id of GIT_IDS) {
    assert.equal(results.get(id).outcome, "passes", id);
    assert.deepEqual(results.get(id).decidedBy, PROJECT_RULE("allow", "Bash(git *)"), id);
  }
  for (const id of ["rm-recursive-force", "remove-item-recurse-force"]) {
    assert.equal(results.get(id).outcome, "passes", id);
    assert.deepEqual(results.get(id).decidedBy, { kind: "mode", mode: "acceptEdits" }, id);
    assert.equal(results.get(id).reason, "accept-edits-inside-project", id);
  }
  for (const id of ASK_IN_ACCEPT_EDITS) {
    assert.equal(results.get(id).outcome, "asks", id);
    assert.deepEqual(results.get(id).decidedBy, { kind: "mode", mode: "acceptEdits" }, id);
  }
  for (const command of coverage.commands) assert.equal(command.preToolUseHook, "none", command.id);
  assert.deepEqual(coverage.preToolUseHooks, []);
});

test("permissive: the subagents with a shell tool pass the same commands, and a bypassPermissions one is ignored", async (t) => {
  const coverage = await coverageOf(copyOf(t, "permissive").root);
  const [edit, fast] = coverage.subagents;

  assert.equal(coverage.subagents.length, 2);
  assert.equal(edit.name, "edit-helper");
  assert.deepEqual(edit.shellTools, ["Bash"], "tools lists Bash and not PowerShell");
  assert.equal(edit.effectiveMode, "acceptEdits");
  assert.equal(edit.ignoredMode, undefined);
  assert.deepEqual(edit.results.map((result) => result.id), BASH_IDS);
  assert.equal(resultOf(edit, "rm-recursive-force").outcome, "passes");
  for (const id of GIT_IDS) assert.equal(resultOf(edit, id).outcome, "passes", id);
  for (const id of ASK_IN_ACCEPT_EDITS.filter((item) => BASH_IDS.includes(item))) {
    assert.equal(resultOf(edit, id).outcome, "asks", id);
  }

  assert.equal(fast.name, "fast-runner");
  assert.deepEqual(fast.shellTools, ["Bash", "PowerShell"], "omitted tools means every tool");
  assert.equal(fast.permissionMode, "bypassPermissions");
  assert.equal(fast.effectiveMode, "acceptEdits", "the main acceptEdits applies");
  assert.equal(fast.ignoredMode, "bypassPermissions");
  assert.deepEqual(fast.results.map((result) => result.id), ALL_IDS);
  assert.equal(resultOf(fast, "remove-item-recurse-force").outcome, "passes");
});

test("default-only: every command asks by the default mode, with no hook and no subagent", async (t) => {
  const coverage = await coverageOf(copyOf(t, "default-only").root);

  assert.equal(coverage.mode, null);
  for (const command of coverage.commands) {
    assert.equal(command.outcome, "asks", command.id);
    assert.deepEqual(command.decidedBy, { kind: "mode", mode: "default" }, command.id);
    assert.equal(command.reason, "default-mode", command.id);
    assert.equal(command.preToolUseHook, "none", command.id);
  }
  assert.deepEqual(coverage.preToolUseHooks, []);
  assert.deepEqual(coverage.subagents, []);
});

test("guarded: a deny rule blocks every command, and the PreToolUse hook runs for all of them", async (t) => {
  const coverage = await coverageOf(copyOf(t, "guarded").root);

  for (const command of coverage.commands) {
    assert.equal(command.outcome, "blocked", command.id);
    assert.equal(command.decidedBy.kind, "rule", command.id);
    assert.equal(command.decidedBy.list, "deny", command.id);
    assert.equal(command.preToolUseHook, "runs", command.id);
  }
  assert.equal(coverage.preToolUseHooks.length, 1);
  const [hook] = coverage.preToolUseHooks;
  assert.equal(hook.matcher, "Bash|PowerShell");
  assert.equal(hook.if, null);
  assert.equal(hook.onFailure, "block");
  assert.equal(hook.failsOpen, false);
  assert.deepEqual(hook.tools, ["Bash", "PowerShell"]);
  assert.deepEqual(hook.script, { path: ".claude/hooks/guard-destructive.mjs", external: false, exists: true });
  assert.deepEqual(coverage.subagents, []);
});

test("fail-open-hook: every command asks, the hook fails open, and it covers only Bash", async (t) => {
  const coverage = await coverageOf(copyOf(t, "fail-open-hook").root);

  for (const command of coverage.commands) {
    assert.equal(command.outcome, "asks", command.id);
    const expected = BASH_IDS.includes(command.id) ? "runs" : "none";
    assert.equal(command.preToolUseHook, expected, command.id);
  }
  assert.equal(coverage.preToolUseHooks.length, 1);
  assert.equal(coverage.preToolUseHooks[0].failsOpen, true);
  assert.equal(coverage.preToolUseHooks[0].onFailure, null);
  assert.deepEqual(coverage.preToolUseHooks[0].tools, ["Bash"]);
});

test("a project bypassPermissions or auto is recorded as ignored, and no command passes because of the mode", async (t) => {
  for (const value of ["bypassPermissions", "auto"]) {
    const fixture = copyOf(t, "permissive", {
      ".claude/settings.json": JSON.stringify({ permissions: { allow: ["Bash(git *)"], defaultMode: value } }),
    });
    const result = await scan({ root: fixture.root, measures: MEASURES, now: FIXED_NOW });
    const coverage = result.security.destructiveCoverage;

    assert.equal(result.security.permissions.defaultMode.effect, "ignored-from-project", value);
    assert.deepEqual(coverage.mode, { value, source: ".claude/settings.json", effect: "ignored-from-project" }, value);
    for (const command of coverage.commands) {
      if (GIT_IDS.includes(command.id)) {
        assert.equal(command.outcome, "passes", command.id);
        assert.equal(command.decidedBy.kind, "rule", `${command.id} passes by its rule, not by the mode`);
        continue;
      }
      assert.equal(command.outcome, "asks", `${value}: ${command.id}`);
      assert.deepEqual(command.decidedBy, { kind: "mode", mode: "default", ignoredMode: value }, command.id);
      assert.equal(command.reason, "ignored-project-mode", command.id);
    }
    const [edit, fast] = coverage.subagents;
    // The main mode is default, because the project mode is ignored, so the subagent's own acceptEdits applies.
    assert.equal(edit.effectiveMode, "acceptEdits");
    assert.equal(edit.ignoredMode, undefined);
    assert.equal(resultOf(edit, "rm-recursive-force").outcome, "passes");
    assert.equal(fast.effectiveMode, "default");
    assert.equal(fast.ignoredMode, "bypassPermissions");
  }
});

test("a manual defaultMode is the alias of default, and it applies", async (t) => {
  const fixture = copyOf(t, "default-only", {
    ".claude/settings.json": JSON.stringify({ permissions: { defaultMode: "manual" } }),
  });
  const coverage = await coverageOf(fixture.root);

  assert.deepEqual(coverage.mode, { value: "manual", source: ".claude/settings.json", effect: "applies" });
  for (const command of coverage.commands) {
    assert.equal(command.outcome, "asks", command.id);
    assert.deepEqual(command.decidedBy, { kind: "mode", mode: "default" }, command.id);
  }
});

test("a hook filter limits the commands that the hook runs for", async (t) => {
  const fixture = copyOf(t, "default-only", {
    ".claude/settings.json": JSON.stringify({
      hooks: {
        PreToolUse: [
          { matcher: "Bash", hooks: [{ type: "command", command: "node .claude/hooks/check-git.mjs", if: "Bash(git *)" }] },
        ],
      },
    }),
    ".claude/hooks/check-git.mjs": "// Fixture script. Never run.\n",
  });
  const coverage = await coverageOf(fixture.root);

  const [hook] = coverage.preToolUseHooks;
  assert.equal(hook.if, "Bash(git *)");
  assert.equal(hook.failsOpen, true);
  assert.deepEqual(hook.tools, ["Bash"]);
  for (const command of coverage.commands) {
    const expected = GIT_IDS.includes(command.id) ? "runs" : "none";
    assert.equal(command.preToolUseHook, expected, command.id);
  }
});

test("a hook whose matcher cannot be read makes the hook undeterminable for every command", async (t) => {
  const fixture = copyOf(t, "default-only", {
    ".claude/settings.json": JSON.stringify({
      hooks: { PreToolUse: [{ matcher: "Bash(", hooks: [{ type: "command", command: "node .claude/hooks/check.mjs" }] }] },
    }),
    ".claude/hooks/check.mjs": "// Fixture script. Never run.\n",
  });
  const coverage = await coverageOf(fixture.root);

  assert.equal(coverage.preToolUseHooks[0].tools, "undeterminable");
  for (const command of coverage.commands) assert.equal(command.preToolUseHook, "undeterminable", command.id);
});

test("a PreToolUse hook whose matcher covers no shell tool is not listed", async (t) => {
  const fixture = copyOf(t, "default-only", {
    ".claude/settings.json": JSON.stringify({
      hooks: { PreToolUse: [{ matcher: "Read|Edit", hooks: [{ type: "command", command: "node .claude/hooks/check.mjs" }] }] },
    }),
    ".claude/hooks/check.mjs": "// Fixture script. Never run.\n",
  });
  const coverage = await coverageOf(fixture.root);

  assert.deepEqual(coverage.preToolUseHooks, []);
  for (const command of coverage.commands) assert.equal(command.preToolUseHook, "none", command.id);
});

test("subagents: disallowedTools removes a tool, a subagent without a name is skipped, and so is one without a shell tool", async (t) => {
  const fixture = copyOf(t, "permissive", {
    ".claude/agents/no-bash.md": "---\nname: no-bash\ndescription: Works without Bash.\ndisallowedTools: Bash(git push *), Bash\npermissionMode: default\n---\n",
    ".claude/agents/read-only.md": "---\nname: read-only\ndescription: Reads only.\ntools: Read, Glob\npermissionMode: acceptEdits\n---\n",
    ".claude/agents/anonymous.md": "---\ndescription: Has no name.\ntools: Bash\npermissionMode: acceptEdits\n---\n",
  });
  const coverage = await coverageOf(fixture.root);

  assert.deepEqual(coverage.subagents.map((agent) => agent.name), ["edit-helper", "fast-runner", "no-bash"]);
  const noBash = coverage.subagents.find((agent) => agent.name === "no-bash");
  assert.deepEqual(noBash.shellTools, ["PowerShell"], "disallowedTools removes Bash whole, even with a specifier");
  assert.equal(noBash.effectiveMode, "acceptEdits", "under an acceptEdits main conversation, the subagent keeps the main mode");
  assert.equal(noBash.ignoredMode, "default", "its own default is ignored");
  assert.deepEqual(noBash.results.map((result) => result.id), POWERSHELL_IDS);
});

test("subagents under the default mode: auto is undeterminable, and plan and bypassPermissions follow the docs", async (t) => {
  const fixture = copyOf(t, "default-only", {
    ".claude/agents/auto-runner.md": "---\nname: auto-runner\ndescription: Uses auto.\ntools: Read, Bash\npermissionMode: auto\n---\n",
    ".claude/agents/plan-runner.md": "---\nname: plan-runner\ndescription: Plans.\npermissionMode: plan\n---\n",
    ".claude/agents/bypass-runner.md": "---\nname: bypass-runner\ndescription: Bypasses.\npermissionMode: bypassPermissions\n---\n",
  });
  const coverage = await coverageOf(fixture.root);
  const subagents = byName(coverage.subagents);

  const auto = subagents.get("auto-runner");
  assert.deepEqual(auto.shellTools, ["Bash"]);
  assert.equal(auto.effectiveMode, "undeterminable", "whether auto is available is unknown");
  assert.equal(auto.ignoredMode, undefined);
  for (const result of auto.results) assert.equal(result.outcome, "undeterminable", result.id);

  const plan = subagents.get("plan-runner");
  assert.equal(plan.effectiveMode, "plan");
  assert.deepEqual(plan.shellTools, ["Bash", "PowerShell"]);
  assert.equal(resultOf(plan, "rm-recursive-force").outcome, "undeterminable", "plan mode depends on the session");

  const bypass = subagents.get("bypass-runner");
  assert.equal(bypass.effectiveMode, "default", "bypassPermissions keeps the main mode");
  assert.equal(bypass.ignoredMode, "bypassPermissions");
  assert.equal(resultOf(bypass, "rm-recursive-force").outcome, "asks");
});

test("two scans of the same fixture give the same destructiveCoverage, and the same output apart from meta", async (t) => {
  const fixture = copyOf(t, "guarded");
  const first = await scan({ root: fixture.root, measures: MEASURES, now: FIXED_NOW });
  const second = await scan({ root: fixture.root, measures: MEASURES, now: FIXED_NOW });

  assert.equal(toStableJson(first.security.destructiveCoverage), toStableJson(second.security.destructiveCoverage));
  const { meta: firstMeta, ...firstRest } = first;
  const { meta: secondMeta, ...secondRest } = second;
  assert.equal(toStableJson(firstRest), toStableJson(secondRest));
  assert.equal(firstMeta.tool, secondMeta.tool);
});

test("the command line writes the measure to measurements.json", async (t) => {
  const fixture = copyOf(t, "permissive");
  const out = path.join(fixture.base, "out");

  const result = await runScan([fixture.root, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  assert.deepEqual(data.security.destructiveCoverage.commands.map((command) => command.id), ALL_IDS);
  assert.deepEqual(data.security.destructiveCoverage.subagents.map((agent) => agent.name), ["edit-helper", "fast-runner"]);
});

test("the measurements schema documents destructiveCoverage and the hook and subagent fields it relies on", async (t) => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  const coverage = (await coverageOf(copyOf(t, "permissive").root));

  const documented = schema.properties.security.properties.destructiveCoverage;
  assert.ok(schema.properties.security.required.includes("destructiveCoverage"));
  assert.deepEqual([...documented.required].sort(), Object.keys(coverage).sort());
  // The first command of the data has no parts, so its keys are exactly the required ones.
  assert.deepEqual([...documented.properties.commands.items.required].sort(), Object.keys(coverage.commands[0]).sort());
  assert.ok(schema.properties.claudeConfig.properties.hooks.items.required.includes("if"));
  assert.ok(schema.properties.claudeConfig.properties.subagents.items.properties.disallowedTools);
});

// A fixture whose project has a settings file with the given content, and nothing else.
function settingsFixture(t, settings) {
  const fixture = makeFixture({ files: { ".claude/settings.json": JSON.stringify(settings) } });
  t.after(fixture.cleanup);
  return fixture;
}

// A fixture with no file at all.
function emptyFixture(t) {
  const fixture = makeFixture({});
  t.after(fixture.cleanup);
  return fixture;
}

// The same outcome for each matrix mode, keyed by mode.
const allModes = (outcome) => Object.fromEntries(MATRIX_MODES.map((mode) => [mode, outcome]));

test("a broad allow passes every command in every matrix mode, and matrixModes lists the modes (permission-modes docs)", async (t) => {
  const coverage = await coverageOf(settingsFixture(t, { permissions: { allow: ["Bash", "PowerShell"] } }).root);

  assert.deepEqual(coverage.matrixModes, MATRIX_MODES);
  assert.deepEqual(coverage.commands.map((command) => command.id), ALL_IDS);
  for (const command of coverage.commands) {
    assert.deepEqual(command.modes, allModes("passes"), command.id);
  }
});

test("a deny rule blocks every command in every matrix mode, bypassPermissions included", async (t) => {
  const coverage = await coverageOf(copyOf(t, "guarded").root);

  for (const command of coverage.commands) {
    assert.deepEqual(command.modes, allModes("blocked"), command.id);
  }
});

test("a deny rule beats a broad allow in every mode, and the commands it does not match keep their allow (positive control)", async (t) => {
  const settings = { permissions: { allow: ["Bash", "PowerShell"], deny: ["Bash(npm publish *)"] } };
  const coverage = await coverageOf(settingsFixture(t, settings).root);

  for (const command of coverage.commands) {
    const expected = command.id === "npm-publish" ? allModes("blocked") : allModes("passes");
    assert.deepEqual(command.modes, expected, command.id);
  }
});

test("with no settings, auto is a classifier for every command, and the other modes follow their own rules", async (t) => {
  const coverage = await coverageOf(emptyFixture(t).root);

  assert.equal(coverage.mode, null);
  // acceptEdits approves the file commands inside the project: rm and Remove-Item (both insideProject) pass.
  // NOT VERIFIED for Remove-Item: the cited acceptEdits note names only mkdir, touch, rm, rmdir, mv, cp and sed, so the
  // Remove-Item pass is pending verification.
  const acceptEditsPasses = ["rm-recursive-force", "remove-item-recurse-force"];
  for (const command of coverage.commands) {
    assert.equal(command.modes.auto, "classifier", command.id);
    assert.equal(command.modes.default, "asks", command.id);
    assert.equal(command.modes.acceptEdits, acceptEditsPasses.includes(command.id) ? "passes" : "asks", command.id);
    assert.equal(command.modes.bypassPermissions, "passes", command.id);
  }
});

test("the schema documents modes on each command and matrixModes on destructiveCoverage, and the output matches it", async (t) => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  const documented = schema.properties.security.properties.destructiveCoverage;
  const outcomes = ["blocked", "asks", "passes", "classifier", "undeterminable"];

  assert.ok(documented.required.includes("matrixModes"));
  assert.deepEqual(documented.properties.matrixModes.items.enum, MATRIX_MODES);
  const command = documented.properties.commands.items;
  assert.ok(command.required.includes("modes"));
  assert.deepEqual(command.properties.modes.required, MATRIX_MODES);
  assert.deepEqual(Object.keys(command.properties.modes.properties), MATRIX_MODES);
  for (const mode of MATRIX_MODES) {
    assert.deepEqual(command.properties.modes.properties[mode].enum, outcomes, mode);
  }
  // Positive control: the measure writes exactly the documented keys, with documented values.
  const coverage = await coverageOf(copyOf(t, "permissive").root);
  for (const item of coverage.commands) {
    assert.deepEqual(Object.keys(item.modes), MATRIX_MODES, item.id);
    for (const mode of MATRIX_MODES) assert.ok(outcomes.includes(item.modes[mode]), `${item.id} ${mode}`);
  }
});

// A measure that puts user permission lists in ctx.outside, as the user layer measure does.
function userLists(lists) {
  return {
    id: "user-lists",
    collect(ctx) {
      ctx.outside.set("user", { permissions: { allow: [], ask: [], deny: [], ...lists } });
      return {};
    },
  };
}

test("a user allow passes the rm command that asks without it, and the decision names the user layer", async (t) => {
  const fixture = emptyFixture(t);
  const userAllow = { allow: [{ rule: "Bash(rm:*)", source: "~/.claude/settings.json" }] };
  const withoutUser = await scan({ root: fixture.root, measures: MEASURES, now: FIXED_NOW });
  const withUser = await scan({ root: fixture.root, measures: [claudeConfigMeasure, userLists(userAllow), destructiveCommandsMeasure], now: FIXED_NOW });
  const rm = (result) => byId(result.security.destructiveCoverage.commands).get("rm-recursive-force");

  assert.equal(rm(withoutUser).outcome, "asks", "positive control: without user data the removal asks by default");
  assert.deepEqual(rm(withoutUser).decidedBy, { kind: "mode", mode: "default" });
  assert.equal(rm(withUser).outcome, "passes");
  assert.deepEqual(rm(withUser).decidedBy, {
    kind: "rule",
    list: "allow",
    rule: "Bash(rm:*)",
    source: "~/.claude/settings.json",
    layer: "user",
  });
  assert.deepEqual(withUser.security.permissions.allow, [], "security.permissions holds the project lists only");
});

test("a user deny blocks a command that the project allows, and a project decision keeps its shape", async (t) => {
  const fixture = settingsFixture(t, { permissions: { allow: ["Bash(git reset:*)"] } });
  const userDeny = { deny: [{ rule: "Bash(git reset:*)", source: "~/.claude/settings.json" }] };
  const withUser = await scan({ root: fixture.root, measures: [claudeConfigMeasure, userLists(userDeny), destructiveCommandsMeasure], now: FIXED_NOW });
  const withoutUser = await scan({ root: fixture.root, measures: [claudeConfigMeasure, destructiveCommandsMeasure], now: FIXED_NOW });
  const reset = (result) => byId(result.security.destructiveCoverage.commands).get("git-reset-hard");

  assert.equal(reset(withoutUser).outcome, "passes", "positive control: the project allow passes the reset");
  assert.deepEqual(reset(withoutUser).decidedBy, PROJECT_RULE("allow", "Bash(git reset:*)"));
  assert.equal(reset(withUser).outcome, "blocked");
  assert.deepEqual(reset(withUser).decidedBy, {
    kind: "rule",
    list: "deny",
    rule: "Bash(git reset:*)",
    source: "~/.claude/settings.json",
    layer: "user",
  });
});
