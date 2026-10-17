import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyScriptPath, findScriptWord, hookWords } from "../scripts/lib/hook-command.mjs";

// The script that a shell command of a hook would run, as written, or null.
const scriptOf = (command, args) => findScriptWord(hookWords(command, args));

test("hook command: an interpreter runs its first file argument", () => {
  assert.equal(scriptOf("node .claude/hooks/x.mjs --flag value"), ".claude/hooks/x.mjs");
  assert.equal(scriptOf("bash ./scripts/check.sh"), "./scripts/check.sh");
  assert.equal(scriptOf("python3 tools/lint.py"), "tools/lint.py");
  assert.equal(scriptOf("pwsh -NoProfile -File ./check.ps1"), "./check.ps1");
  assert.equal(scriptOf('"C:\\Program Files\\nodejs\\node.exe" hooks\\guard.mjs'), "hooks\\guard.mjs");
});

test("hook command: node options that take a value are skipped", () => {
  assert.equal(scriptOf("node --import tsx src/x.ts"), "src/x.ts");
  assert.equal(scriptOf("node -r ./preload.cjs app.mjs"), "app.mjs");
});

test("hook command: code or a module run in place of a file has no script", () => {
  assert.equal(scriptOf("node -e 'console.log(1)'"), null);
  assert.equal(scriptOf("python3 -m pkg.tool"), null);
  assert.equal(scriptOf("bash -lc 'echo hi'"), null);
  assert.equal(scriptOf("powershell -Command Get-Date"), null);
  assert.equal(scriptOf("npx prettier --check ."), null);
});

test("hook command: a command whose first word is a path runs that path", () => {
  assert.equal(scriptOf("./.claude/hooks/x.sh --quiet"), "./.claude/hooks/x.sh");
  assert.equal(scriptOf(".claude/hooks/x.sh"), ".claude/hooks/x.sh");
  assert.equal(scriptOf("$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh"), "$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh");
});

test("hook command: the shell operators end the first simple command", () => {
  assert.equal(scriptOf("node a.mjs && node b.mjs"), "a.mjs");
  assert.equal(scriptOf("node a.mjs|tee log.txt"), "a.mjs");
  assert.deepEqual(hookWords("echo one; echo two"), ["echo", "one"]);
});

test("hook command: exec form takes the args as they are", () => {
  assert.equal(scriptOf("node", [".claude/hooks/a.mjs", "--x"]), ".claude/hooks/a.mjs");
  assert.deepEqual(hookWords("node", ["a b.mjs"]), ["node", "a b.mjs"]);
});

test("hook command: quotes group words and are removed", () => {
  assert.deepEqual(hookWords(`node "my hooks/a.mjs" 'x y'`), ["node", "my hooks/a.mjs", "x y"]);
  assert.equal(scriptOf(`node "my hooks/a.mjs"`), "my hooks/a.mjs");
});

test("classify: a project variable and a relative path are inside the project", () => {
  assert.deepEqual(classifyScriptPath("$CLAUDE_PROJECT_DIR/.claude/hooks/x.sh"), { external: false, rel: ".claude/hooks/x.sh" });
  assert.deepEqual(classifyScriptPath("${CLAUDE_PROJECT_DIR}/.claude/hooks/x.sh"), { external: false, rel: ".claude/hooks/x.sh" });
  assert.deepEqual(classifyScriptPath("${CLAUDE_PROJECT_DIR:-.}/x.sh"), { external: false, rel: "x.sh" });
  assert.deepEqual(classifyScriptPath(".claude\\hooks\\x.sh"), { external: false, rel: ".claude/hooks/x.sh" });
  assert.deepEqual(classifyScriptPath("./a/../b.sh"), { external: false, rel: "b.sh" });
});

test("classify: absolute, home, other variables and outside paths are external and not checked", () => {
  for (const raw of ["/usr/bin/x", "C:\\tools\\x.ps1", "C:/tools/x.ps1", "\\\\server\\share\\x", "~/x.sh", "$HOME/x.sh", "%USERPROFILE%\\x.ps1", "../x.sh", "a/../../x.sh"]) {
    assert.deepEqual(classifyScriptPath(raw), { external: true }, raw);
  }
});
