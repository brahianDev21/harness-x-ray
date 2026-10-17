import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { makeFixture, runGit, symlinkSupport } from "./helpers/make-fixture.mjs";

const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;

test("git fixture: git ls-files lists exactly the described files, and cleanup removes the folder", (t) => {
  const fixture = makeFixture({
    git: true,
    files: {
      "CLAUDE.md": "# Project\n",
      "guide/setup.md": "Setup\n",
      "src/index.mjs": "export const value = 1;\n",
    },
  });
  t.after(fixture.cleanup);

  const listed = runGit(fixture.root, ["ls-files", "-z"]).split("\0").filter(Boolean).sort();
  assert.deepEqual(listed, ["CLAUDE.md", "guide/setup.md", "src/index.mjs"]);

  fixture.cleanup();
  assert.equal(fs.existsSync(fixture.base), false, "base folder should be gone after cleanup()");
  assert.doesNotThrow(() => fixture.cleanup(), "cleanup() must be safe to call twice");
});

test("non-git fixture: file bytes are written exactly, with the expected layout", (t) => {
  const crlf = "first line\r\nsecond line\r\n";
  const binary = Buffer.from([0x00, 0xff, 0x0d, 0x0a, 0x80]);
  const fixture = makeFixture({
    files: { "windows.txt": crlf, "nested/dir/blob.bin": binary },
  });
  t.after(fixture.cleanup);

  assert.ok(fixture.base.startsWith(os.tmpdir() + path.sep), "fixture must live in the system temp folder");
  assert.equal(fixture.root, path.join(fixture.base, "repo"));
  assert.equal(fixture.outsideDir, path.join(fixture.base, "outside"));
  assert.ok(fs.statSync(fixture.outsideDir).isDirectory(), "outside folder is created even when empty");
  assert.equal(fs.existsSync(path.join(fixture.root, ".git")), false, "no git repository without git: true");

  assert.deepEqual(fs.readFileSync(path.join(fixture.root, "windows.txt")), Buffer.from(crlf, "utf8"));
  assert.deepEqual(fs.readFileSync(path.join(fixture.root, "nested", "dir", "blob.bin")), binary);
});

test("symlink fixture: a file symlink points to a file outside the root", { skip: symlinkSkip }, (t) => {
  const fixture = makeFixture({
    files: { "nested/notes.txt": "inside the root\n" },
    outside: { "secret.txt": "outside the root\n" },
    // The target is relative to nested/, so ../../ leads to the base folder, then outside/.
    symlinks: [{ path: "nested/linked-secret.txt", target: "../../outside/secret.txt" }],
  });
  t.after(fixture.cleanup);

  const linkPath = path.join(fixture.root, "nested", "linked-secret.txt");
  assert.ok(fs.lstatSync(linkPath).isSymbolicLink(), "the entry must be a symbolic link");
  assert.equal(fs.readFileSync(linkPath, "utf8"), "outside the root\n");
  assert.equal(
    fs.realpathSync.native(linkPath),
    fs.realpathSync.native(path.join(fixture.outsideDir, "secret.txt")),
  );
});

test("cleanup removes a folder symlink without deleting what it points to", { skip: symlinkSkip }, (t) => {
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-external-"));
  t.after(() => fs.rmSync(external, { recursive: true, force: true }));
  fs.writeFileSync(path.join(external, "keep.txt"), "must survive cleanup\n");

  const fixture = makeFixture({
    symlinks: [{ path: "linked-dir", target: external, type: "dir" }],
  });
  t.after(fixture.cleanup);

  fixture.cleanup();
  assert.equal(fs.existsSync(fixture.base), false);
  assert.equal(fs.readFileSync(path.join(external, "keep.txt"), "utf8"), "must survive cleanup\n");
});

test("junction fixture: the junction resolves to its target, and cleanup keeps the target", {
  skip: process.platform === "win32" ? false : "junctions are a Windows feature",
}, (t) => {
  const external = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-external-"));
  t.after(() => fs.rmSync(external, { recursive: true, force: true }));
  fs.writeFileSync(path.join(external, "keep.txt"), "must survive cleanup\n");

  const fixture = makeFixture({
    files: { "notes.txt": "inside\n" },
    symlinks: [{ path: "linked-junction", target: external, type: "junction" }],
  });
  t.after(fixture.cleanup);

  const junction = path.join(fixture.root, "linked-junction");
  assert.ok(fs.lstatSync(junction).isSymbolicLink(), "lstat reports a junction as a link");
  assert.equal(fs.readFileSync(path.join(junction, "keep.txt"), "utf8"), "must survive cleanup\n");

  fixture.cleanup();
  assert.equal(fs.existsSync(fixture.base), false);
  assert.equal(fs.readFileSync(path.join(external, "keep.txt"), "utf8"), "must survive cleanup\n");
});

test("gitConfig is applied after the initial commit, and the commit exists", (t) => {
  // An inert placeholder: no git command in this test reads the index, and nothing executes it.
  const placeholder = "hxr-test-placeholder";
  const fixture = makeFixture({
    git: true,
    files: { "a.txt": "a\n" },
    gitConfig: { "core.fsmonitor": placeholder },
  });
  t.after(fixture.cleanup);

  assert.equal(runGit(fixture.root, ["config", "--local", "--get", "core.fsmonitor"]).trim(), placeholder);
  assert.match(runGit(fixture.root, ["rev-parse", "--verify", "HEAD"]).trim(), /^[0-9a-f]{40}$/);
  assert.equal(runGit(fixture.root, ["ls-tree", "--name-only", "HEAD"]).trim(), "a.txt");
});

test("invalid descriptions are rejected", () => {
  assert.throws(() => makeFixture({ files: { "../escape.txt": "x" } }), /must stay inside/);
  assert.throws(() => makeFixture({ git: true, files: { ".git/config": "[core]\n" } }), /gitConfig/);
  assert.throws(() => makeFixture({ gitConfig: { "core.fsmonitor": "x" } }), /requires git: true/);
  assert.throws(() => makeFixture({ filse: {} }), /Unknown fixture option/);
});
