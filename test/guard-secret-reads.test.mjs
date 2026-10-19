import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(TEST_DIR, "..");
const HOOK = path.join(ROOT, "scripts", "hooks", "guard-secret-reads.mjs");
const SETTINGS = path.join(ROOT, ".claude", "settings.json");
const BLOCKED = "guard-secret-reads: blocked";

// The input that Claude Code sends to a PreToolUse command hook: the common fields and the call itself. It is built
// with JSON.stringify, so Windows backslashes are escaped the way Claude Code escapes them.
function preToolUse(toolName, toolInput) {
  return JSON.stringify({
    session_id: "test-session",
    transcript_path: "C:\\project\\transcript.jsonl",
    cwd: "C:\\project",
    hook_event_name: "PreToolUse",
    tool_name: toolName,
    tool_input: toolInput,
    tool_use_id: "toolu_test",
  });
}

function runHook(stdin, script = HOOK) {
  const result = spawnSync(process.execPath, [script], {
    input: stdin,
    encoding: "utf8",
    timeout: 20_000,
    windowsHide: true,
  });
  assert.equal(result.error, undefined, "the hook must start");
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function assertBlocked(stdin, script = HOOK) {
  const result = runHook(stdin, script);
  assert.equal(result.status, 2, result.stderr);
  assert.ok(result.stderr.startsWith(BLOCKED), result.stderr);
  assert.equal(result.stdout, "");
  return result;
}

function assertAllowed(stdin, script = HOOK) {
  const result = runHook(stdin, script);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
}

test("Read: a secret file name is blocked", () => {
  assertBlocked(preToolUse("Read", { file_path: "C:\\project\\.env" }));
});

test("Read: a template of .env is allowed (.env.example)", () => {
  assertAllowed(preToolUse("Read", { file_path: "C:\\project\\.env.example" }));
});

test("Read: a normal source file is allowed (positive control)", () => {
  assertAllowed(preToolUse("Read", { file_path: "C:\\project\\src\\index.mjs" }));
});

test("Read: the name is judged without regard to letter case, and id_rsa, server.pem and .env.local are blocked", () => {
  assertBlocked(preToolUse("Read", { file_path: "C:\\project\\.ENV" }));
  assertBlocked(preToolUse("Read", { file_path: "C:\\Users\\dev\\.ssh\\id_rsa" }));
  assertBlocked(preToolUse("Read", { file_path: "config\\server.pem" }));
  assertBlocked(preToolUse("Read", { file_path: "C:\\project\\config\\.env.local" }));
});

test("Bash: a command that names a secret file is blocked", () => {
  assertBlocked(preToolUse("Bash", { command: "cat .env" }));
  assertBlocked(preToolUse("Bash", { command: "cat config/.env.local" }));
  assertBlocked(preToolUse("Bash", { command: "cat ~/.ssh/id_rsa" }));
  assertBlocked(preToolUse("Bash", { command: "grep TOKEN .env*" }));
});

test("Bash: commands that name no secret file are allowed", () => {
  assertAllowed(preToolUse("Bash", { command: "cat .env.example" }));
  assertAllowed(preToolUse("Bash", { command: "npm test" }));
  assertAllowed(preToolUse("Bash", { command: "node scripts/scan.mjs C:\\some\\target" }));
});

test("PowerShell: Get-Content of a secret file is blocked, and an ordinary command passes", () => {
  assertBlocked(preToolUse("PowerShell", { command: "Get-Content .env" }));
  assertAllowed(preToolUse("PowerShell", { command: "Get-ChildItem -Recurse" }));
});

test("Grep: a path or a glob that names a secret file is blocked", () => {
  assertBlocked(preToolUse("Grep", { pattern: "API", path: ".env.local" }));
  assertBlocked(preToolUse("Grep", { pattern: "BEGIN", glob: "*.pem" }));
  assertBlocked(preToolUse("Grep", { pattern: "TOKEN", glob: "**/.env" }));
  assertBlocked(preToolUse("Grep", { pattern: "TOKEN", glob: ".env*" }));
  assertBlocked(preToolUse("Grep", { pattern: "TOKEN", glob: ".env.*" }));
});

test("Grep: a pattern alone, or a glob of ordinary files, is allowed", () => {
  assertAllowed(preToolUse("Grep", { pattern: "TODO" }));
  assertAllowed(preToolUse("Grep", { pattern: "TODO", path: "src", glob: "*.mjs" }));
});

test("an unknown tool is allowed (Glob lists names only and is not covered)", () => {
  assertAllowed(preToolUse("Glob", { pattern: "**/.env" }));
});

test("fail closed: empty stdin, invalid JSON and a JSON value that is not an object are blocked", () => {
  assertBlocked("");
  assertBlocked("{not json");
  assertBlocked("null");
});

test("fail closed: a missing tool_name is blocked", () => {
  assertBlocked(JSON.stringify({ tool_input: { command: "npm test" } }));
});

test("fail closed: a tool_input that is not an object is blocked", () => {
  assertBlocked(JSON.stringify({ tool_name: "Bash", tool_input: "npm test" }));
});

test("fail closed: a field to check with the wrong type is blocked", () => {
  assertBlocked(preToolUse("Read", { file_path: 5 }));
  assertBlocked(preToolUse("Read", {}));
  assertBlocked(preToolUse("Bash", { command: ["cat", ".env"] }));
  assertBlocked(preToolUse("Grep", { pattern: "x", glob: 3 }));
});

test("a Read of a real .env in the temp folder is blocked, its value is printed nowhere, and a normal file there passes", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-guard-"));
  try {
    // Built at run time, so this file holds no token-shaped text. The value exists only in the temp file.
    const fake = ["sk", "ant", "api03", "FakeValueOnlyForTheGuardTest0123"].join("-");
    const envFile = path.join(dir, ".env");
    const plainFile = path.join(dir, "index.mjs");
    fs.writeFileSync(envFile, `ANTHROPIC_API_KEY=${fake}\n`);
    fs.writeFileSync(plainFile, "export const value = 1;\n");

    const result = assertBlocked(preToolUse("Read", { file_path: envFile }));
    assert.ok(!result.stdout.includes(fake));
    assert.ok(!result.stderr.includes(fake));
    assert.ok(!result.stderr.includes(dir), "the stderr line names the base name only");

    assertAllowed(preToolUse("Read", { file_path: plainFile }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("fail closed: pattern data that cannot load is blocked, and the same copy with the real data allows the call", () => {
  // A copy of the hook and the modules it loads, in the system temp folder, with a data file that is not JSON.
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-guard-copy-"));
  try {
    const copy = path.join(base, "copy");
    fs.mkdirSync(path.join(copy, "scripts", "hooks"), { recursive: true });
    fs.mkdirSync(path.join(copy, "scripts", "lib"), { recursive: true });
    fs.mkdirSync(path.join(copy, "data"));
    const copyHook = path.join(copy, "scripts", "hooks", "guard-secret-reads.mjs");
    fs.copyFileSync(HOOK, copyHook);
    for (const name of ["secret-patterns.mjs", "json-out.mjs"]) {
      fs.copyFileSync(path.join(ROOT, "scripts", "lib", name), path.join(copy, "scripts", "lib", name));
    }
    const dataFile = path.join(copy, "data", "secret-patterns.json");
    const read = preToolUse("Read", { file_path: "C:\\project\\src\\index.mjs" });

    fs.writeFileSync(dataFile, "{ this is not JSON");
    const broken = runHook(read, copyHook);
    assert.equal(broken.status, 2, broken.stderr);
    assert.ok(broken.stderr.startsWith("guard-secret-reads: blocked: pattern data cannot load"), broken.stderr);
    assert.equal(broken.stdout, "");

    fs.copyFileSync(path.join(ROOT, "data", "secret-patterns.json"), dataFile);
    assertAllowed(read, copyHook);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("the hook file imports neither the file system module nor the process module", () => {
  const source = fs.readFileSync(HOOK, "utf8");
  assert.doesNotMatch(source, /["'](?:node:)?(?:fs(?:\/promises)?|child_process)["']/);
});

test(".claude/settings.json: allow and ask rules, no deny, the fixture exclusion and the PreToolUse hook", () => {
  const settings = JSON.parse(fs.readFileSync(SETTINGS, "utf8"));

  assert.deepEqual(settings.permissions, {
    allow: ["Bash(node scripts/scan.mjs *)", "Bash(node scripts/render-report.mjs *)", "Bash(npm test)"],
    ask: ["WebFetch", "WebSearch"],
  });

  assert.ok(settings.claudeMdExcludes.includes("**/test/fixtures/**"));

  const groups = settings.hooks.PreToolUse;
  assert.equal(groups.length, 1);
  assert.equal(groups[0].matcher, "Read|Grep|Bash|PowerShell");
  assert.equal(groups[0].hooks.length, 1);
  const [hook] = groups[0].hooks;
  assert.equal(hook.type, "command");
  assert.equal(hook.command, "node");
  assert.deepEqual(hook.args, ["${CLAUDE_PROJECT_DIR}/scripts/hooks/guard-secret-reads.mjs"]);
  assert.equal(hook.onFailure, "block");
  assert.ok(fs.existsSync(path.join(ROOT, hook.args[0].replace("${CLAUDE_PROJECT_DIR}/", ""))));
});
