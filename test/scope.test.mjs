import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { MAX_SCOPE_FOLDERS, ScopeError, createScope, harnessFolderOf, resolveScopeFolders } from "../scripts/lib/scope.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;

// A target with two folders under apps, one under packages and a file at the root.
const TARGET = {
  "apps/web/src/index.ts": "export {};\n",
  "apps/api/server.ts": "export {};\n",
  "packages/a/index.ts": "export {};\n",
  "README.md": "# Target\n",
};

// The root of a fixture of TARGET, removed when the test ends.
function targetRoot(t, description = {}) {
  const fixture = makeFixture({ files: TARGET, ...description });
  t.after(fixture.cleanup);
  return fixture.root;
}

test("resolveScopeFolders: a valid folder is checked and returned as a POSIX path", (t) => {
  const root = targetRoot(t);

  assert.deepEqual(resolveScopeFolders(root, ["apps/web"]), ["apps/web"]);
});

test("resolveScopeFolders: a trailing slash, a leading ./ and a repeated slash name the same folder", (t) => {
  const root = targetRoot(t);

  assert.deepEqual(resolveScopeFolders(root, ["apps/web/"]), ["apps/web"]);
  assert.deepEqual(resolveScopeFolders(root, ["./apps/web"]), ["apps/web"]);
  assert.deepEqual(resolveScopeFolders(root, ["apps//web"]), ["apps/web"]);
  assert.deepEqual(resolveScopeFolders(root, ["apps/web"]), ["apps/web"], "positive control: the plain form");
});

test("resolveScopeFolders: repeated and nested folders reduce to the smallest set, sorted", (t) => {
  const root = targetRoot(t);

  assert.deepEqual(resolveScopeFolders(root, ["apps/web", "apps/web/", "apps/web/src"]), ["apps/web"]);
  assert.deepEqual(resolveScopeFolders(root, ["packages/a", "apps/web", "apps/web/src"]), ["apps/web", "packages/a"]);
});

test("resolveScopeFolders: a folder that cannot be a scope is refused, and a valid folder beside it is accepted", (t) => {
  const root = targetRoot(t);
  const refused = [
    ["", /must not be empty/],
    [".", /subfolder of the target/],
    [path.join(root, "apps", "web"), /relative to the target/],
    ["../x", /leaves the target/],
    ["apps/../../x", /leaves the target/],
    ["missing", /does not exist/],
    ["README.md", /not a folder/],
  ];

  assert.deepEqual(resolveScopeFolders(root, ["apps/web"]), ["apps/web"], "positive control: a valid folder");
  for (const [input, message] of refused) {
    const isScopeError = (error) => error instanceof ScopeError && message.test(error.message);
    assert.throws(() => resolveScopeFolders(root, [input]), isScopeError, `input ${JSON.stringify(input)}`);
  }
});

test("resolveScopeFolders: a folder reached through a link inside the target is refused", { skip: symlinkSkip }, (t) => {
  const fixture = makeFixture({ files: TARGET, symlinks: [{ path: "link", target: "apps/api" }] });
  t.after(fixture.cleanup);

  assert.throws(() => resolveScopeFolders(fixture.root, ["link"]), /reached through a link/);
  assert.deepEqual(resolveScopeFolders(fixture.root, ["apps/api"]), ["apps/api"], "positive control: the folder by its own name");
});

test("resolveScopeFolders: more than MAX_SCOPE_FOLDERS folders are refused, and MAX_SCOPE_FOLDERS are accepted", (t) => {
  const root = targetRoot(t);
  const many = Array.from({ length: MAX_SCOPE_FOLDERS + 1 }, () => "apps/web");

  assert.deepEqual(resolveScopeFolders(root, many.slice(0, MAX_SCOPE_FOLDERS)), ["apps/web"], "positive control: the limit itself");
  assert.throws(() => resolveScopeFolders(root, many), /at most 64 scope folders/);
});

test("createScope: the inherited folders of apps/web are the root and apps, and the folders are kept", () => {
  const scope = createScope(["apps/web"]);

  assert.deepEqual(scope.folders, ["apps/web"]);
  assert.deepEqual(scope.inherited, [".", "apps"]);
  assert.equal(Object.isFrozen(scope), true);
  assert.throws(() => createScope([]), TypeError);
  assert.deepEqual(createScope(["apps"]).inherited, ["."], "positive control: a folder at the first level");
});

test("createScope: contains is true for a scope folder and what lies inside it, and false for its siblings and parents", () => {
  const scope = createScope(["apps/web"]);

  assert.equal(scope.contains("apps/web"), true);
  assert.equal(scope.contains("apps/web/src/index.ts"), true);
  assert.equal(scope.contains("apps/webhook/index.ts"), false, "a name that begins the same way is not inside");
  assert.equal(scope.contains("apps/api/server.ts"), false);
  assert.equal(scope.contains("apps/AGENTS.md"), false);
});

test("createScope: isInherited is true for the root and the folders between the root and the scope only", () => {
  const scope = createScope(["apps/web"]);

  assert.equal(scope.isInherited("."), true);
  assert.equal(scope.isInherited("apps"), true);
  assert.equal(scope.isInherited("apps/web"), false, "a scope folder is not inherited");
  assert.equal(scope.isInherited("packages"), false);
});

test("createScope: keepsHarness keeps the harness of the root, of the inherited folders and of the scope, and no other", () => {
  const scope = createScope(["apps/web"]);

  assert.equal(scope.keepsHarness("apps/.claude/skills/a/SKILL.md"), true);
  assert.equal(scope.keepsHarness("apps/web/src/AGENTS.md"), true);
  assert.equal(scope.keepsHarness("apps/api/AGENTS.md"), false);
  assert.equal(scope.keepsHarness(".cursor/rules/a.mdc"), true);
});

test("harnessFolderOf: a file belongs to the folders before its first harness folder, or before its name", () => {
  assert.equal(harnessFolderOf("CLAUDE.md"), ".");
  assert.equal(harnessFolderOf(".cursor/rules/a.mdc"), ".");
  assert.equal(harnessFolderOf("apps/.claude/skills/a/SKILL.md"), "apps");
  assert.equal(harnessFolderOf("apps/web/.agents/skills/x/SKILL.md"), "apps/web");
  assert.equal(harnessFolderOf("apps/web/src/AGENTS.md"), "apps/web/src");
  assert.equal(harnessFolderOf("packages/a/.github/x.md"), "packages/a", "positive control: a dot folder further down");
});

test("harnessFolderOf: a dot folder that is not a harness folder is an ordinary folder that owns its files", () => {
  assert.equal(harnessFolderOf("apps/.venv/lib/pkg/AGENTS.md"), "apps/.venv/lib/pkg");
  assert.equal(harnessFolderOf("apps/.clinerules/x.md"), "apps", "a registry folder that is not .claude");
  assert.equal(harnessFolderOf("apps/.claude/skills/a/SKILL.md"), "apps", "positive control: a registry folder");
  assert.equal(harnessFolderOf("apps/.cache/CLAUDE.md"), "apps/.cache");
});

test("createScope: keepsHarness drops a file in an ordinary dot folder of an inherited folder, and keeps registry folders", () => {
  const scope = createScope(["apps/web"]);

  assert.equal(scope.keepsHarness("apps/.cache/CLAUDE.md"), false, "apps/.cache belongs to itself, which is not inherited");
  assert.equal(scope.keepsHarness("apps/.venv/pkg/AGENTS.md"), false);
  assert.equal(scope.keepsHarness("apps/.agents/skills/x/SKILL.md"), true, "positive control: a registry folder of apps");
  assert.equal(scope.keepsHarness("apps/CLAUDE.md"), true, "positive control: a file of an inherited folder");
});
