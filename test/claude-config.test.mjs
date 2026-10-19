import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { claudeConfigMeasure } from "../scripts/lib/claude-config.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FULL_CONFIG = path.join(TEST_DIR, "fixtures", "full-config");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");

// Fake values that the fixture uses. None of them may appear in the output.
const FAKE_VALUES = ["fake-api-key-value-999", "fake-password-value-111", "fake-header-value-000"];

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

// A copy of the full-config fixture in a temp folder, with files written on top of the copy.
function fullConfig(t, files = {}) {
  const fixture = makeFixture({ fromDir: FULL_CONFIG, files });
  t.after(fixture.cleanup);
  return fixture;
}

function scanOnly(root) {
  return scan({ root, measures: [claudeConfigMeasure], now: FIXED_NOW });
}

const configWarnings = (result) => result.warnings.filter((warning) => warning.source === "claude-config");

// The forms a folder can take in text: as given, with forward slashes, and in Git Bash style on Windows.
function folderForms(folder) {
  const forms = new Set([folder, folder.replaceAll("\\", "/")]);
  const drive = /^([A-Za-z]):(.*)$/.exec(folder);
  if (drive !== null) forms.add(`/${drive[1].toLowerCase()}${drive[2].replaceAll("\\", "/")}`);
  const escaped = new Set();
  for (const form of forms) escaped.add(JSON.stringify(form).slice(1, -1));
  return [...forms, ...escaped].filter((form) => form.length >= 4);
}

test("claude-config: the full configuration lists skills, commands and subagents with their sizes", async (t) => {
  const fixture = fullConfig(t);

  const result = await scanOnly(fixture.root);
  const { claudeConfig } = result;

  assert.deepEqual(claudeConfig.skills.map((item) => item.name), [
    "internal-helper",
    "long-description",
    "nested-value",
    "release-notes",
    "review-diff",
  ]);
  assert.deepEqual(claudeConfig.commands.map((item) => item.name), ["deploy-check", "frontend:component"]);
  assert.deepEqual(claudeConfig.subagents.map((item) => item.name), ["code-reviewer", "planner"]);

  const review = claudeConfig.skills.find((item) => item.name === "review-diff");
  const reviewText = [
    "Reviews the current diff for correctness problems.",
    "Use when the user asks for a review of local changes before a commit.",
  ].join("\n");
  assert.equal(review.descriptionChars, reviewText.length, "description and when_to_use are joined with a line feed");
  assert.equal(review.loadMode, "always");

  const component = claudeConfig.commands.find((item) => item.name === "frontend:component");
  assert.equal(component.descriptionChars, "Create a component that follows the folder conventions of the project.".length,
    "without frontmatter, the first non-empty line is the description");

  const planner = claudeConfig.subagents.find((item) => item.name === "planner");
  assert.deepEqual(planner.tools, ["Read", "Grep"]);
  assert.equal(planner.permissionMode, "plan");
  assert.equal(claudeConfig.subagents.find((item) => item.name === "code-reviewer").tools, "Read, Glob, Grep");

  assert.deepEqual(configWarnings(result), [], "the good fixture produces no warnings from this measure");
});

test("claude-config: a description over 1,536 characters is flagged and still counted", async (t) => {
  const fixture = fullConfig(t);

  const result = await scanOnly(fixture.root);
  const long = result.claudeConfig.skills.find((item) => item.name === "long-description");

  assert.equal(long.overLimit, true);
  assert.ok(long.descriptionChars > 1536, `descriptionChars is ${long.descriptionChars}`);
  assert.equal(long.loadMode, "always");
  assert.ok(result.context.alwaysLoaded.byComponent.find((item) => item.component === "skills").items.some((item) => item.path === long.path));
});

test("claude-config: the budget keeps skills, commands and subagents apart and totals them", async (t) => {
  const fixture = fullConfig(t);

  const { alwaysLoaded } = (await scanOnly(fixture.root)).context;

  assert.deepEqual(alwaysLoaded.byComponent.map((item) => item.component), ["commands", "skills", "subagents"]);
  for (const component of alwaysLoaded.byComponent) {
    assert.equal(component.estTokens, component.items.reduce((sum, item) => sum + item.estTokens, 0), component.component);
  }
  assert.equal(alwaysLoaded.estTokensTotal, alwaysLoaded.byComponent.reduce((sum, item) => sum + item.estTokens, 0));
  assert.equal(alwaysLoaded.estMethod, "chars/4");
  assert.deepEqual(alwaysLoaded.byComponent.find((item) => item.component === "skills").items.map((item) => item.path), [
    ".claude/skills/long-description/SKILL.md",
    ".claude/skills/nested-value/SKILL.md",
    ".claude/skills/release-notes/SKILL.md",
    ".claude/skills/review-diff/SKILL.md",
  ]);
});

test("claude-config: a skill with disable-model-invocation is not counted in the budget", async (t) => {
  const fixture = fullConfig(t);

  const result = await scanOnly(fixture.root);
  const hidden = result.claudeConfig.skills.find((item) => item.name === "internal-helper");

  assert.equal(hidden.disableModelInvocation, true);
  assert.equal(hidden.loadMode, "not-loaded");
  const counted = result.context.alwaysLoaded.byComponent.flatMap((item) => item.items.map((entry) => entry.path));
  assert.equal(counted.includes(hidden.path), false);
});

test("claude-config: a nested frontmatter value under a key that is not read does not stop the skill from counting", async (t) => {
  const fixture = fullConfig(t);

  const result = await scanOnly(fixture.root);
  const nested = result.claudeConfig.skills.find((item) => item.name === "nested-value");

  assert.equal(nested.frontmatterError, null);
  assert.equal(nested.loadMode, "always");
  assert.equal(typeof nested.estTokens, "number");
  assert.equal(configWarnings(result).length, 0);
});

test("claude-config: unreadable frontmatter is flagged, warned and left out of the budget", async (t) => {
  const fixture = fullConfig(t, {
    ".claude/skills/colon-value/SKILL.md": "---\nname: colon-value\ndescription: Reads: the file\n---\n\nBody.\n",
    ".claude/skills/unclosed/SKILL.md": "---\nname: unclosed\ndescription: Never closed.\n\nBody.\n",
  });

  const result = await scanOnly(fixture.root);
  const colon = result.claudeConfig.skills.find((item) => item.path === ".claude/skills/colon-value/SKILL.md");
  const unclosed = result.claudeConfig.skills.find((item) => item.path === ".claude/skills/unclosed/SKILL.md");

  assert.equal(colon.frontmatterError, "unsupported-value");
  assert.equal(colon.estTokens, null);
  assert.equal(colon.loadMode, null);
  assert.equal(unclosed.frontmatterError, "broken");
  assert.equal(unclosed.name, "unclosed", "the folder name still names a skill");
  const counted = result.context.alwaysLoaded.byComponent.flatMap((item) => item.items.map((entry) => entry.path));
  assert.equal(counted.includes(colon.path), false);
  assert.equal(counted.includes(unclosed.path), false);
  assert.deepEqual(
    configWarnings(result).filter((warning) => warning.reason === "frontmatter-unsupported").map((warning) => warning.path),
    [".claude/skills/colon-value/SKILL.md", ".claude/skills/unclosed/SKILL.md"],
  );
});

test("claude-config: a subagent without a name is skipped, as Claude Code does, and is not counted", async (t) => {
  const fixture = fullConfig(t, {
    ".claude/agents/anonymous.md": "---\ndescription: Has no name, so it is not loaded.\n---\n\nBody.\n",
  });

  const result = await scanOnly(fixture.root);
  const anonymous = result.claudeConfig.subagents.find((item) => item.path === ".claude/agents/anonymous.md");

  assert.equal(anonymous.name, null);
  assert.equal(anonymous.loadMode, "not-loaded");
  const inventory = result.inventory.find((item) => item.path === ".claude/agents/anonymous.md");
  assert.equal(inventory.loadMode, "not-loaded");
  assert.equal(result.context.alwaysLoaded.byComponent.find((item) => item.component === "subagents").items.length, 2);
});

test("claude-config: defaultMode bypassPermissions and auto are recorded as ignored from the project", async (t) => {
  const shared = await scanOnly(fullConfig(t).root);
  assert.deepEqual(shared.security.permissions.defaultMode, {
    value: "bypassPermissions",
    source: ".claude/settings.json",
    effect: "ignored-from-project",
  });

  const local = fullConfig(t, {
    ".claude/settings.local.json": JSON.stringify({ permissions: { defaultMode: "auto" } }),
  });
  const overridden = await scanOnly(local.root);
  assert.deepEqual(overridden.security.permissions.defaultMode, {
    value: "auto",
    source: ".claude/settings.local.json",
    effect: "ignored-from-project",
  }, "the local file has the higher precedence, and its auto is ignored too");
});

test("claude-config: a mode that the project may set applies, and the local file overrides the shared one", async (t) => {
  const fixture = fullConfig(t, {
    ".claude/settings.local.json": JSON.stringify({ permissions: { defaultMode: "acceptEdits", allow: ["Bash(make)"] } }),
  });

  const result = await scanOnly(fixture.root);
  const { permissions } = result.security;

  assert.deepEqual(permissions.defaultMode, {
    value: "acceptEdits",
    source: ".claude/settings.local.json",
    effect: "applies",
  });
  assert.deepEqual(permissions.allow, [
    { rule: "Bash(make)", source: ".claude/settings.local.json" },
    { rule: "Bash(npm test)", source: ".claude/settings.json" },
    { rule: "Read(./src/**)", source: ".claude/settings.json" },
  ], "allow lists from both files are merged and sorted");
  assert.deepEqual(result.claudeConfig.settings.map((item) => item.path), [
    ".claude/settings.json",
    ".claude/settings.local.json",
  ]);
  const inventory = result.inventory.find((item) => item.path === ".claude/settings.local.json");
  assert.equal(inventory.loadMode, "not-loaded");
});

test("claude-config: the permission lists and the notes are read from the shared file", async (t) => {
  const result = await scanOnly(fullConfig(t).root);
  const { permissions } = result.security;

  assert.deepEqual(permissions.ask, [{ rule: "Bash(git push *)", source: ".claude/settings.json" }]);
  assert.deepEqual(permissions.deny, [{ rule: "Read(./.env)", source: ".claude/settings.json" }]);
  assert.deepEqual(permissions.additionalDirectories, [{ path: "../shared-docs", source: ".claude/settings.json" }]);
  assert.deepEqual(permissions.disableBypassPermissionsMode, { value: "disable", source: ".claude/settings.json" });
  assert.deepEqual(permissions.notes, ["additional-directories-require-folder-trust", "allow-requires-folder-trust"]);

  const [settings] = result.claudeConfig.settings;
  assert.deepEqual(settings.envKeys, ["EXAMPLE_API_KEY", "LOG_LEVEL"]);
  assert.equal(settings.enableAllProjectMcpServers, false);
  assert.deepEqual(settings.sandbox, { present: true, enabled: true, keys: ["autoAllowBashIfSandboxed", "enabled"] });
});

test("claude-config: hooks show the event, the script, whether it exists, injection and fail-open", async (t) => {
  const result = await scanOnly(fullConfig(t).root);
  const { hooks } = result.claudeConfig;

  assert.deepEqual(hooks.map((hook) => [hook.event, hook.script.path]), [
    ["PreToolUse", ".claude/hooks/guard-bash.mjs"],
    ["PreToolUse", "scripts/missing-check.mjs"],
    ["SessionStart", ".claude/hooks/session-context.mjs"],
  ]);
  const [guard, missing, start] = hooks;
  assert.deepEqual(guard.script, { path: ".claude/hooks/guard-bash.mjs", external: false, exists: true });
  assert.equal(guard.onFailure, "block");
  assert.equal(guard.failsOpen, false);
  assert.equal(guard.injectsContext, false);
  assert.equal(guard.matcher, "Bash");
  assert.equal(missing.script.exists, false);
  assert.equal(missing.failsOpen, true, "a hook without onFailure lets the action go on");
  assert.equal(start.injectsContext, true);
  assert.equal(start.timeout, 10);
  assert.equal(start.matcher, null);
  assert.deepEqual(result.context.alwaysLoaded.unknownStatic.filter((item) => item.kind === "hook-output"), [
    { kind: "hook-output", source: ".claude/settings.json", event: "SessionStart", matcher: null },
  ]);
});

test("claude-config: MCP servers are listed by name and type, as unknown-static, with key names only", async (t) => {
  const result = await scanOnly(fullConfig(t).root);

  assert.deepEqual(result.claudeConfig.mcpServers, [
    { source: ".mcp.json", name: "docs-search", type: "http", loadMode: "unknown-static", envKeys: [], headerKeys: ["Authorization"] },
    { source: ".mcp.json", name: "local-db", type: "stdio", loadMode: "unknown-static", envKeys: ["DB_PASSWORD"], headerKeys: [] },
  ]);
  assert.deepEqual(result.context.alwaysLoaded.unknownStatic.filter((item) => item.kind === "mcp-server"), [
    { kind: "mcp-server", source: ".mcp.json", name: "docs-search" },
    { kind: "mcp-server", source: ".mcp.json", name: "local-db" },
  ]);
});

test("claude-config: env and header values never reach the output, while their key names do", async (t) => {
  const fixture = fullConfig(t);

  const result = await scanOnly(fixture.root);
  const text = toStableJson(result);

  for (const value of FAKE_VALUES) assert.equal(text.includes(value), false, `the value ${value} was copied`);
  assert.equal(text.includes("https://docs.example.invalid"), false, "the URL of a server is not copied");
  assert.equal(text.includes("tools/db-server.mjs"), false, "the arguments of a server are not copied");
  for (const name of ["EXAMPLE_API_KEY", "DB_PASSWORD", "Authorization"]) {
    assert.ok(text.includes(name), `the key name ${name} should be listed`);
  }
});

test("claude-config: invalid JSON in settings and .mcp.json is a warning, and the scan still exits 0", async (t) => {
  const fixture = fullConfig(t, { ".claude/settings.json": '{ "permissions": ', ".mcp.json": "{" });
  const out = path.join(fixture.base, "out");

  const result = await runScan([fixture.root, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  assert.deepEqual(configWarnings(data), [
    { source: "claude-config", path: ".claude/settings.json", reason: "invalid-json" },
    { source: "claude-config", path: ".mcp.json", reason: "invalid-json" },
  ]);
  assert.equal(data.claudeConfig.settings[0].parsed, false);
  assert.deepEqual(data.claudeConfig.mcpServers, []);
});

test("claude-config: unexpected shapes inside a settings file are warnings, and the valid values are kept", async (t) => {
  const fixture = fullConfig(t, {
    ".claude/settings.json": JSON.stringify({
      permissions: { allow: "Bash(x)", deny: [1, "Bash(y)"], defaultMode: 5 },
      enableAllProjectMcpServers: "yes",
      env: [],
      sandbox: "on",
      hooks: { PreToolUse: "x" },
    }),
  });

  const result = await scanOnly(fixture.root);

  assert.deepEqual(result.security.permissions.allow, []);
  assert.deepEqual(result.security.permissions.deny, [{ rule: "Bash(y)", source: ".claude/settings.json" }]);
  assert.equal(result.security.permissions.defaultMode, null);
  const [settings] = result.claudeConfig.settings;
  assert.equal(settings.enableAllProjectMcpServers, null);
  assert.deepEqual(settings.envKeys, []);
  assert.deepEqual(settings.sandbox, { present: true, enabled: null, keys: [] });
  assert.deepEqual(result.claudeConfig.hooks, []);
  const details = configWarnings(result).map((warning) => `${warning.reason}:${warning.detail}`).sort();
  assert.deepEqual(details, [
    "unexpected-shape:enableAllProjectMcpServers",
    "unexpected-shape:env",
    "unexpected-shape:hooks",
    "unexpected-shape:permissions.allow",
    "unexpected-shape:permissions.defaultMode",
    "unexpected-shape:permissions.deny",
    "unexpected-shape:sandbox",
  ]);
});

test("claude-config: hook commands that contain the target root or the home folder are redacted", async (t) => {
  const fixture = fullConfig(t);
  const homeScript = path.join(os.homedir(), "tools", "helper.mjs");
  const settings = {
    hooks: {
      SessionStart: [
        {
          hooks: [
            { type: "command", command: `node "${path.join(fixture.root, "scripts", "a.mjs")}"` },
            { type: "command", command: `node ${fixture.root.replaceAll("\\", "/")}/scripts/b.mjs --root` },
            { type: "command", command: `node ${homeScript}` },
          ],
        },
      ],
    },
  };
  fs.writeFileSync(path.join(fixture.root, ".claude", "settings.json"), JSON.stringify(settings));

  const result = await scanOnly(fixture.root);
  // meta.targetRoot is the one absolute path the output may hold, so the check looks at everything else.
  const { meta: _meta, ...outsideMeta } = result;
  const text = toStableJson(outsideMeta);

  for (const folder of [fixture.root, os.homedir()]) {
    for (const form of folderForms(folder)) {
      assert.equal(text.includes(form), false, `an absolute path leaked: ${form}`);
    }
  }
  assert.ok(text.includes("<target>"), "the target root is shown as <target>");
  assert.ok(text.includes("~"), "the home folder is shown as ~");
  assert.equal(result.claudeConfig.hooks.length, 3);
  const byScript = new Map(result.claudeConfig.hooks.map((hook) => [hook.script.path, hook]));
  // An absolute script is external: it is shown redacted and not checked.
  for (const redacted of [`<target>${path.sep}scripts${path.sep}a.mjs`, "<target>/scripts/b.mjs", `~${path.sep}tools${path.sep}helper.mjs`]) {
    const hook = byScript.get(redacted);
    assert.ok(hook, `a hook script is shown as ${redacted}`);
    assert.equal(hook.script.external, true);
    assert.equal(hook.script.exists, null);
  }
});

test("claude-config: a symbolic link to a folder of skills is not followed", { skip: symlinkSupport().supported ? false : symlinkSupport().reason }, async (t) => {
  const fixture = makeFixture({
    fromDir: FULL_CONFIG,
    outside: { "skill/SKILL.md": "---\nname: linked\ndescription: Outside the project.\n---\n" },
    symlinks: [{ path: ".claude/skills/linked", target: "../../../outside/skill", type: "dir" }],
  });
  t.after(fixture.cleanup);

  const result = await scanOnly(fixture.root);

  assert.equal(result.claudeConfig.skills.some((item) => item.name === "linked"), false);
});

test("claude-config: two CLI runs on the full configuration give the same JSON, except meta", async (t) => {
  const fixture = fullConfig(t);
  const first = path.join(fixture.base, "first");
  const second = path.join(fixture.base, "second");

  assert.equal((await runScan([fixture.root, "--out", first])).code, 0);
  assert.equal((await runScan([fixture.root, "--out", second])).code, 0);

  const dataFirst = JSON.parse(fs.readFileSync(path.join(first, "measurements.json"), "utf8"));
  const dataSecond = JSON.parse(fs.readFileSync(path.join(second, "measurements.json"), "utf8"));
  delete dataFirst.meta;
  delete dataSecond.meta;
  assert.equal(toStableJson(dataFirst), toStableJson(dataSecond));
});

test("hostile-exec: a scan runs nothing from the target, and still lists its hooks and MCP server", async (t) => {
  const hook = ".claude/hooks/write-witness.mjs";
  const run = "node .claude/hooks/write-witness.mjs";
  const fixture = makeFixture({
    files: {
      "package.json": `${JSON.stringify(
        { name: "hostile", version: "1.0.0", scripts: { preinstall: run, install: run, postinstall: run, prepare: run, test: run } },
        null,
        2,
      )}\n`,
      [hook]: "placeholder\n",
      ".claude/settings.json": `${JSON.stringify(
        {
          hooks: {
            SessionStart: [{ hooks: [{ type: "command", command: run }] }],
            PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: run, onFailure: "block" }] }],
            PostToolUse: [{ matcher: "Edit|Write", hooks: [{ type: "command", command: run }] }],
            Stop: [{ hooks: [{ type: "command", command: run }] }],
          },
        },
        null,
        2,
      )}\n`,
      ".mcp.json": `${JSON.stringify({ mcpServers: { hostile: { type: "stdio", command: "node", args: [hook] } } }, null, 2)}\n`,
    },
  });
  t.after(fixture.cleanup);
  const witness = path.join(fixture.outsideDir, "witness.txt");
  const script = path.join(fixture.root, hook);
  fs.writeFileSync(script, `import fs from "node:fs";\nfs.writeFileSync(${JSON.stringify(witness)}, "ran\\n");\n`);

  // Positive control: the script writes its witness when it runs. Without this, the check below
  // could pass for a reason that has nothing to do with the scanner.
  await execFileAsync(process.execPath, [script]);
  assert.equal(fs.existsSync(witness), true, "the positive control must write the witness");
  fs.rmSync(witness);

  const out = path.join(fixture.base, "out");
  const result = await runScan([fixture.root, "--out", out]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(fs.existsSync(witness), false, "the scan ran the hostile script");
  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  assert.deepEqual(data.claudeConfig.hooks.map((item) => item.event), ["PostToolUse", "PreToolUse", "SessionStart", "Stop"]);
  for (const item of data.claudeConfig.hooks) {
    assert.deepEqual(item.script, { path: hook, external: false, exists: true });
  }
  assert.deepEqual(data.claudeConfig.mcpServers.map((item) => item.name), ["hostile"]);
});
