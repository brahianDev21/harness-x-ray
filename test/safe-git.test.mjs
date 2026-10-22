import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { classifyGitFailure, listFiles } from "../scripts/lib/safe-git.mjs";
import { makeFixture, runGit, symlinkSupport } from "./helpers/make-fixture.mjs";

const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;

// The stand-in for git in the timeout test is a POSIX shell script.
const POSIX_SHELL_SKIP = process.platform === "win32" ? "the stand-in for git is a POSIX shell script" : false;

const FULL_COMMIT = /^[0-9a-f]{40}$/;

// Content of the file outside the root. No result or warning may contain it.
const SECRET = "SECRET-VALUE outside the root\n";

function sizeOf(content) {
  return Buffer.byteLength(content);
}

// Absolute folders of a fixture must not appear in a result.
function assertNoAbsolutePaths(fixture, value) {
  const dump = JSON.stringify(value);
  const folders = [fixture.base, fixture.root, fixture.outsideDir, fs.realpathSync.native(fixture.base)];
  for (const folder of folders) {
    assert.equal(dump.includes(JSON.stringify(folder).slice(1, -1)), false, "an absolute fixture path leaked");
  }
}

function pathsOf(result) {
  return result.files.map((file) => file.path);
}

// Writes a hostile core.fsmonitor command into .git/config. The command creates a witness file in
// the outside folder. Git runs fsmonitor commands through sh, so the paths use forward slashes.
// Returns the witness path, which must not exist once the scanner has run.
function armFsmonitor(fixture) {
  const witness = path.join(fixture.outsideDir, "witness.txt");
  const hook = path.join(fixture.outsideDir, "fsmonitor-hook.sh");
  fs.writeFileSync(hook, `#!/bin/sh\ntouch "${toForwardSlashes(witness)}"\n`);
  runGit(fixture.root, ["config", "--local", "core.fsmonitor", `sh "${toForwardSlashes(hook)}"`]);
  return { witness };
}

function toForwardSlashes(value) {
  return value.replaceAll("\\", "/");
}

// Plain git, as the scanner must never run it: no hardening flags. The only change is the
// removal of GIT_* variables, which every helper in this project does.
function plainGit(cwd, args) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) env[key] = value;
  }
  execFileSync("git", ["--no-pager", "-C", cwd, ...args], {
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
    windowsHide: true,
  });
}

test("positive control: plain git runs an armed core.fsmonitor command", () => {
  // Without this, the hostile test below could pass for the wrong reason.
  for (const args of [["status", "--porcelain"], ["ls-files", "-z"]]) {
    const fixture = makeFixture({ git: true, files: { "a.txt": "a\n" } });
    try {
      const { witness } = armFsmonitor(fixture);
      plainGit(fixture.root, args);
      assert.equal(fs.existsSync(witness), true, `plain git ${args[0]} did not run the command`);
    } finally {
      fixture.cleanup();
    }
  }
});

test("hostile-git: a core.fsmonitor command in .git/config never runs, and the list still comes from git", async (t) => {
  const fixture = makeFixture({
    git: true,
    files: { "CLAUDE.md": "Rules\n", "src/index.mjs": "export {};\n" },
  });
  t.after(fixture.cleanup);
  const { witness } = armFsmonitor(fixture);

  const result = await listFiles(fixture.root);

  assert.equal(fs.existsSync(witness), false, "the core.fsmonitor command ran");
  assert.equal(result.fileListSource, "git");
  assert.deepEqual(pathsOf(result), ["CLAUDE.md", "src/index.mjs"]);
  assert.deepEqual(result.warnings, []);
  assert.match(result.commit, FULL_COMMIT);
});

test("git repository: tracked files with sizes, sorted, untracked files left out", async (t) => {
  const files = {
    "README.md": "# Demo\n",
    "CLAUDE.md": "Rules\n",
    "src/app.mjs": "export {};\n",
    "src/lib/util.mjs": "x".repeat(10),
    "notes/café.md": "café\n",
  };
  const fixture = makeFixture({ git: true, files });
  t.after(fixture.cleanup);
  fs.writeFileSync(path.join(fixture.root, "untracked.txt"), "not added\n");

  const result = await listFiles(fixture.root);

  assert.equal(result.fileListSource, "git");
  assert.match(result.commit, FULL_COMMIT);
  assert.deepEqual(result.files, [
    { path: "CLAUDE.md", bytes: sizeOf(files["CLAUDE.md"]) },
    { path: "README.md", bytes: sizeOf(files["README.md"]) },
    { path: "notes/café.md", bytes: sizeOf(files["notes/café.md"]) },
    { path: "src/app.mjs", bytes: sizeOf(files["src/app.mjs"]) },
    { path: "src/lib/util.mjs", bytes: sizeOf(files["src/lib/util.mjs"]) },
  ]);
  assert.deepEqual(result.warnings, []);
  assertNoAbsolutePaths(fixture, result);
});

test("subfolder of a repository: paths are relative to the subfolder and nothing outside it is listed", async (t) => {
  const fixture = makeFixture({
    git: true,
    files: {
      "README.md": "root\n",
      "apps/web/index.md": "web\n",
      "apps/web/src/main.ts": "main\n",
      "apps/web-old.md": "similar name, not inside apps/web\n",
      "apps/api/server.ts": "api\n",
    },
  });
  t.after(fixture.cleanup);

  const result = await listFiles(path.join(fixture.root, "apps", "web"));

  assert.equal(result.fileListSource, "git");
  assert.match(result.commit, FULL_COMMIT);
  assert.deepEqual(result.files, [
    { path: "index.md", bytes: sizeOf("web\n") },
    { path: "src/main.ts", bytes: sizeOf("main\n") },
  ]);
  assert.deepEqual(result.warnings, []);
});

test("folder without git: walks the disk, skips node_modules and .git at any depth, and warns", async (t) => {
  const fixture = makeFixture({
    files: {
      "CLAUDE.md": "Rules\n",
      "src/index.mjs": "export {};\n",
      "node_modules/dep/index.js": "module.exports = {};\n",
      "packages/app/node_modules/x/y.js": "y\n",
      "packages/app/src/a.ts": "a\n",
      "packages/app/.git/config": "[core]\n",
    },
  });
  t.after(fixture.cleanup);

  const result = await listFiles(fixture.root);

  assert.equal(result.fileListSource, "walk");
  assert.equal(result.commit, null);
  assert.deepEqual(pathsOf(result), ["CLAUDE.md", "packages/app/src/a.ts", "src/index.mjs"]);
  assert.deepEqual(result.warnings, [{ path: ".", reason: "file-list-from-walk", detail: "not-a-repository" }]);
  assertNoAbsolutePaths(fixture, result);
});

test("git not installed: falls back to the walk with the git-not-found detail", async (t) => {
  const fixture = makeFixture({ git: true, files: { "tracked.txt": "t\n" } });
  t.after(fixture.cleanup);
  fs.writeFileSync(path.join(fixture.root, "on-disk.txt"), "n\n");

  const result = await listFiles(fixture.root, { gitExecutable: "hxr-git-that-does-not-exist" });

  assert.equal(result.fileListSource, "walk");
  assert.equal(result.commit, null);
  assert.deepEqual(pathsOf(result), ["on-disk.txt", "tracked.txt"]);
  assert.deepEqual(result.warnings, [{ path: ".", reason: "file-list-from-walk", detail: "git-not-found" }]);
});

// A stand-in for git that never answers: it sleeps far longer than the time limit of the test. It
// ignores its arguments. "exec" makes sleep replace the shell, so the timeout kills the sleeping
// process itself, and execFile settles only after that process has exited.
const NEVER_ANSWERS_GIT = "#!/bin/sh\nexec sleep 60\n";

// Writes the stand-in into a new folder of the system temp folder and returns its path. The folder
// is removed when the test ends.
function neverAnsweringGit(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-git-stand-in-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const executable = path.join(dir, "git");
  fs.writeFileSync(executable, NEVER_ANSWERS_GIT);
  fs.chmodSync(executable, 0o755);
  return executable;
}

// The limit is 300 ms and git never answers, so the timeout always fires. A limit of 1 ms was a
// race: git ls-files on a small repository usually finishes in about 2 ms, so it sometimes won.
test("git command over its time limit: falls back to the walk with the timeout detail", { skip: POSIX_SHELL_SKIP }, async (t) => {
  const fixture = makeFixture({ git: true, files: { "a.txt": "a\n" } });
  t.after(fixture.cleanup);

  const result = await listFiles(fixture.root, { gitExecutable: neverAnsweringGit(t), timeoutMs: 300 });

  assert.equal(result.fileListSource, "walk");
  assert.equal(result.commit, null);
  assert.deepEqual(pathsOf(result), ["a.txt"]);
  assert.deepEqual(result.warnings, [{ path: ".", reason: "file-list-from-walk", detail: "timeout" }]);
});

test("git command within its time limit: its list is used and the walk is not", async (t) => {
  const fixture = makeFixture({ git: true, files: { "a.txt": "a\n" } });
  t.after(fixture.cleanup);
  fs.writeFileSync(path.join(fixture.root, "on-disk.txt"), "n\n");

  const result = await listFiles(fixture.root, { timeoutMs: 60_000 });

  assert.equal(result.fileListSource, "git");
  assert.deepEqual(pathsOf(result), ["a.txt"]);
  assert.deepEqual(result.warnings, []);
});

test("classifyGitFailure maps errors to fixed detail codes", () => {
  const dubious = "fatal: detected dubious ownership in repository at 'C:/Users/someone/repo'\n" +
    "To add an exception for this directory, call:\n\n\tgit config --global --add safe.directory C:/Users/someone/repo\n";
  assert.equal(classifyGitFailure({ code: 128, stderr: Buffer.from(dubious) }), "dubious-ownership");
  assert.equal(
    classifyGitFailure({ code: 128, stderr: "fatal: unsafe repository ('C:/x' is owned by someone else)\n" }),
    "dubious-ownership",
  );
  assert.equal(
    classifyGitFailure({ code: 128, stderr: "fatal: not a git repository (or any of the parent directories): .git\n" }),
    "not-a-repository",
  );
  assert.equal(classifyGitFailure({ code: "ENOENT" }), "git-not-found");
  assert.equal(classifyGitFailure({ code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }), "output-too-large");
  assert.equal(classifyGitFailure({ code: null, killed: true, signal: "SIGTERM" }), "timeout");
  assert.equal(classifyGitFailure({ code: 128, stderr: "fatal: something unexpected\n" }), "git-error");
});

test("tracked symlink that points outside the root is left out with a warning", { skip: symlinkSkip }, async (t) => {
  const fixture = makeFixture({
    git: true,
    files: { "CLAUDE.md": "Rules\n", "docs/guide.md": "Guide\n" },
    outside: { "secret.txt": SECRET },
    symlinks: [{ path: "linked-secret.md", target: "../outside/secret.txt" }],
  });
  t.after(fixture.cleanup);

  const result = await listFiles(fixture.root);

  assert.equal(result.fileListSource, "git");
  assert.deepEqual(pathsOf(result), ["CLAUDE.md", "docs/guide.md"]);
  assert.deepEqual(result.warnings, [{ path: "linked-secret.md", reason: "outside-root" }]);
  assert.equal(JSON.stringify(result).includes("SECRET-VALUE"), false, "the outside secret leaked");
});

test("folder without git: links to outside are left out, folder links are not entered, inside links to files are kept", { skip: symlinkSkip }, async (t) => {
  const fixture = makeFixture({
    files: { "CLAUDE.md": "Rules\n", "docs/guide.md": "Guide\n" },
    outside: { "secret.txt": SECRET },
    symlinks: [
      { path: "linked-secret.md", target: "../outside/secret.txt" },
      { path: "docs-alias", target: "docs", type: "dir" },
      { path: "guide-alias.md", target: "docs/guide.md" },
    ],
  });
  t.after(fixture.cleanup);

  const result = await listFiles(fixture.root);

  assert.equal(result.fileListSource, "walk");
  assert.deepEqual(result.files, [
    { path: "CLAUDE.md", bytes: sizeOf("Rules\n") },
    { path: "docs/guide.md", bytes: sizeOf("Guide\n") },
    { path: "guide-alias.md", bytes: sizeOf("Guide\n") },
  ]);
  assert.deepEqual(result.warnings, [
    { path: ".", reason: "file-list-from-walk", detail: "not-a-repository" },
    { path: "docs-alias", reason: "symlinked-folder" },
    { path: "linked-secret.md", reason: "outside-root" },
  ]);
  assert.equal(JSON.stringify(result).includes("SECRET-VALUE"), false, "the outside secret leaked");
});

test("tracked file deleted from disk and a submodule-like folder are left out with warnings", async (t) => {
  const fixture = makeFixture({ git: true, files: { "kept.md": "kept\n", "gone.md": "gone\n" } });
  t.after(fixture.cleanup);
  fs.rmSync(path.join(fixture.root, "gone.md"));
  // A gitlink entry (what a submodule is in the index) whose folder exists on disk.
  runGit(fixture.root, ["update-index", "--add", "--cacheinfo", `160000,${"1".repeat(40)},vendor/lib`]);
  fs.mkdirSync(path.join(fixture.root, "vendor", "lib"), { recursive: true });

  const result = await listFiles(fixture.root);

  assert.equal(result.fileListSource, "git");
  assert.deepEqual(pathsOf(result), ["kept.md"]);
  assert.deepEqual(result.warnings, [
    { path: "gone.md", reason: "not-found" },
    { path: "vendor/lib", reason: "not-a-file" },
  ]);
});

test("repository without commits: files come from git, commit is null with a warning", async (t) => {
  const fixture = makeFixture({ files: { "staged.md": "staged\n" } });
  t.after(fixture.cleanup);
  runGit(fixture.root, ["init", "-q", "-b", "main"]);
  runGit(fixture.root, ["add", "--all"]);

  const result = await listFiles(fixture.root);

  assert.equal(result.fileListSource, "git");
  assert.equal(result.commit, null);
  assert.deepEqual(result.files, [{ path: "staged.md", bytes: sizeOf("staged\n") }]);
  assert.deepEqual(result.warnings, [{ path: ".", reason: "commit-unavailable", detail: "no-commit" }]);
});

test("two runs on the same folders give deep-equal results", { skip: symlinkSkip }, async (t) => {
  const repo = makeFixture({
    git: true,
    files: { "CLAUDE.md": "Rules\n", "src/a.mjs": "a\n", "src/b.mjs": "bb\n" },
    outside: { "secret.txt": SECRET },
    symlinks: [{ path: "escape.md", target: "../outside/secret.txt" }],
  });
  const plain = makeFixture({
    files: { "CLAUDE.md": "Rules\n", "node_modules/x.js": "x\n", "src/a.mjs": "a\n" },
  });
  t.after(repo.cleanup);
  t.after(plain.cleanup);

  for (const fixture of [repo, plain]) {
    const first = await listFiles(fixture.root);
    const second = await listFiles(fixture.root);
    assert.deepEqual(second, first);
  }
});

test("invalid options are refused with a TypeError", async (t) => {
  const fixture = makeFixture({ files: { "a.txt": "a\n" } });
  t.after(fixture.cleanup);

  await assert.rejects(listFiles(fixture.root, { timeoutMs: 0 }), TypeError);
  await assert.rejects(listFiles(fixture.root, { timeoutMs: 1.5 }), TypeError);
  await assert.rejects(listFiles(fixture.root, { gitExecutable: "" }), TypeError);
  await assert.rejects(listFiles(fixture.root, { shell: true }), TypeError);
  await assert.rejects(listFiles(path.join(fixture.root, "missing")), Error);
});
