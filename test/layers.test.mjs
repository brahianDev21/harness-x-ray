import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { MAX_MANIFEST_BYTES, MAX_WORKSPACE_PATTERNS, mapLayers, readWorkspaceFile } from "../scripts/lib/layers.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "layers.schema.json");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
const MIB = 1_000_000;
// Windows cannot hold a folder name with a newline or a backslash, so the hostile names are made only on the other systems.
const hostileSkip = process.platform === "win32" ? "Windows cannot hold a newline or a backslash in a folder name" : false;
const symlinkSkip = symlinkSupport().supported ? false : symlinkSupport().reason;

const MONOREPO = {
  "package.json": JSON.stringify({ name: "mono", private: true, workspaces: ["packages/*", "apps/*"] }),
  "README.md": "# Mono\n",
  "packages/a/package.json": '{"name":"a"}\n',
  "packages/a/src/index.ts": "export const a = 1;\n",
  "packages/b/package.json": '{"name":"b"}\n',
  "packages/b/src/index.ts": "export const b = 2;\n",
  "apps/web/package.json": '{"name":"web"}\n',
  "apps/web/src/App.tsx": "export const App = () => null;\n",
  "apps/web/AGENTS.md": "# Web\n\nKeep components small.\n",
};

// A fixture that is removed when the test ends.
function freshFixture(t, files) {
  const fixture = makeFixture({ files });
  t.after(fixture.cleanup);
  return fixture;
}

async function mapOf(t, files, limits) {
  const fixture = freshFixture(t, files);
  return mapLayers({ root: fixture.root, now: FIXED_NOW, limits });
}

function unitOf(layers, unitPath) {
  const unit = layers.units.find((item) => item.path === unitPath);
  assert.ok(unit, `the unit ${unitPath} is listed`);
  return unit;
}

function workspaceOf(layers, manifest) {
  const workspace = layers.workspaces.find((item) => item.manifest === manifest);
  assert.ok(workspace, `a workspace is declared by ${manifest}`);
  return workspace;
}

// Checks a value against the subset of JSON Schema that schemas/layers.schema.json uses: type, const, enum, pattern, minimum,
// properties with additionalProperties false, required, items, anyOf and $ref into $defs. It returns the problems it finds.
function problemsOf(schema, value, where, root) {
  if (schema.$ref !== undefined) return problemsOf(resolveRef(root, schema.$ref), value, where, root);
  if (schema.anyOf !== undefined) {
    const matches = schema.anyOf.some((branch) => problemsOf(branch, value, where, root).length === 0);
    return matches ? [] : [`${where} matches none of the allowed forms`];
  }
  const problems = [];
  if (schema.const !== undefined && value !== schema.const) problems.push(`${where} must be ${JSON.stringify(schema.const)}`);
  if (schema.enum !== undefined && !schema.enum.includes(value)) problems.push(`${where} is not in the enum`);
  if (schema.type !== undefined && !typeMatches(schema.type, value)) problems.push(`${where} must be ${schema.type}`);
  if (typeof value === "string" && schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
    problems.push(`${where} does not match ${schema.pattern}`);
  }
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) {
    problems.push(`${where} is below ${schema.minimum}`);
  }
  if (isObject(value)) {
    const properties = schema.properties ?? {};
    for (const key of Object.keys(value)) {
      if (schema.additionalProperties === false && !Object.hasOwn(properties, key)) {
        problems.push(`${where} emits ${key}, which the schema does not list`);
      } else if (Object.hasOwn(properties, key)) {
        problems.push(...problemsOf(properties[key], value[key], `${where}.${key}`, root));
      }
    }
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(value, key)) problems.push(`${where} lacks the required ${key}`);
    }
  }
  if (Array.isArray(value) && schema.items !== undefined) {
    value.forEach((item, index) => problems.push(...problemsOf(schema.items, item, `${where}[${index}]`, root)));
  }
  return problems;
}

function resolveRef(root, ref) {
  const parts = ref.replace(/^#\//, "").split("/");
  return parts.reduce((node, part) => node[part], root);
}

function typeMatches(type, value) {
  const types = Array.isArray(type) ? type : [type];
  return types.some((name) => {
    if (name === "object") return isObject(value);
    if (name === "array") return Array.isArray(value);
    if (name === "string") return typeof value === "string";
    if (name === "integer") return Number.isSafeInteger(value);
    if (name === "null") return value === null;
    return false;
  });
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

test("monorepo: npm workspaces give the members, and each unit gets its manifest, workspace and name signals", async (t) => {
  const layers = await mapOf(t, MONOREPO);

  assert.equal(layers.structure, "units");
  assert.deepEqual(
    layers.units.map((unit) => unit.path),
    [".", "apps", "apps/web", "packages", "packages/a", "packages/b"],
  );
  assert.deepEqual(workspaceOf(layers, "package.json"), {
    manager: "npm",
    manifest: "package.json",
    patterns: ["apps/*", "packages/*"],
    members: ["apps/web", "packages/a", "packages/b"],
  });
  assert.deepEqual(unitOf(layers, "packages/a").signals, [
    { type: "manifest", file: "package.json" },
    { type: "workspace", manager: "npm", manifest: "package.json" },
  ]);
  assert.deepEqual(unitOf(layers, "apps").signals, [{ type: "name", hint: "packages" }]);
  assert.deepEqual(unitOf(layers, "packages").signals, [{ type: "name", hint: "packages" }]);
  assert.deepEqual(unitOf(layers, "apps/web").signals, [
    { type: "harness", agents: ["agents-md", "claude-code"] },
    { type: "manifest", file: "package.json" },
    { type: "name", hint: "frontend" },
    { type: "workspace", manager: "npm", manifest: "package.json" },
  ]);
  assert.deepEqual(unitOf(layers, "apps/web").languages, [
    { language: "JSON", files: 1 },
    { language: "Markdown", files: 1 },
    { language: "TypeScript", files: 1 },
  ]);
  assert.equal(unitOf(layers, ".").files, 9);
  assert.deepEqual(unitOf(layers, ".").signals, [{ type: "root" }]);
  assert.deepEqual(
    layers.tree.children.map((child) => [child.path, child.files]),
    [
      ["apps", 3],
      ["packages", 4],
    ],
  );
  assert.ok(layers.folders.includes("packages/a/src"), "a tree folder is in folders");
  assert.equal(layers.suggestion, null);
});

test("a nested AGENTS.md, CLAUDE.md and skill give harness signals on their own folders", async (t) => {
  const layers = await mapOf(t, {
    "CLAUDE.md": "# Root\n",
    "services/api/CLAUDE.md": "# API\n",
    "services/api/src/main.py": "print(1)\n",
    "tools/x/.claude/skills/review/SKILL.md": "---\nname: review\ndescription: Reviews\n---\n\nSteps.\n",
    "tools/x/run.sh": "echo run\n",
  });

  assert.equal(layers.structure, "units");
  assert.deepEqual(unitOf(layers, ".").signals, [{ type: "root" }], "a root harness file gives no signal to the root");
  assert.deepEqual(unitOf(layers, "services/api").signals, [
    { type: "harness", agents: ["claude-code"] },
    { type: "name", hint: "backend" },
  ]);
  assert.deepEqual(unitOf(layers, "tools/x").signals, [{ type: "harness", agents: ["claude-code"] }]);
  assert.ok(layers.folders.includes("services/api") && layers.folders.includes("tools/x"));
});

test("Cargo, go.work, pnpm, lerna and uv workspaces declare their members", async (t) => {
  const cargo = await mapOf(t, {
    "Cargo.toml": '[workspace]\nresolver = "2"\nmembers = [\n  "crates/*",  # every crate\n]\n',
    "crates/core/Cargo.toml": '[package]\nname = "core"\n',
    "crates/core/src/lib.rs": "pub fn core() {}\n",
    "crates/cli/Cargo.toml": '[package]\nname = "cli"\n',
    "crates/cli/src/main.rs": "fn main() {}\n",
  });
  assert.deepEqual(workspaceOf(cargo, "Cargo.toml"), {
    manager: "cargo",
    manifest: "Cargo.toml",
    patterns: ["crates/*"],
    members: ["crates/cli", "crates/core"],
  });
  assert.deepEqual(unitOf(cargo, "crates").signals, [{ type: "name", hint: "packages" }]);

  const goWork = await mapOf(t, {
    "go.work": 'go 1.22\n\nuse ./svc // the service\n\nuse (\n\t./lib\n\t"./tools/gen"\n)\n',
    "svc/go.mod": "module example.com/svc\n",
    "svc/main.go": "package main\n",
    "lib/go.mod": "module example.com/lib\n",
    "lib/lib.go": "package lib\n",
    "tools/gen/go.mod": "module example.com/gen\n",
    "tools/gen/gen.go": "package gen\n",
  });
  assert.deepEqual(workspaceOf(goWork, "go.work"), {
    manager: "go",
    manifest: "go.work",
    patterns: ["./lib", "./svc", "./tools/gen"],
    members: ["lib", "svc", "tools/gen"],
  });
  assert.deepEqual(unitOf(goWork, "svc").signals, [
    { type: "manifest", file: "go.mod" },
    { type: "workspace", manager: "go", manifest: "go.work" },
  ]);

  const pnpm = await mapOf(t, {
    "pnpm-workspace.yaml": "packages:\n  - 'services/*'\n  - \"libs/shared\"  # shared code\n  - tools/*\n",
    "lerna.json": '{"packages": ["modules/*"]}\n',
    "services/api/package.json": "{}\n",
    "services/worker/package.json": "{}\n",
    "libs/shared/package.json": "{}\n",
    "tools/cli/package.json": "{}\n",
    "modules/x/package.json": "{}\n",
  });
  assert.deepEqual(
    pnpm.workspaces.map(({ manager, manifest }) => [manager, manifest]),
    [
      ["lerna", "lerna.json"],
      ["pnpm", "pnpm-workspace.yaml"],
    ],
  );
  assert.deepEqual(workspaceOf(pnpm, "pnpm-workspace.yaml").members, [
    "libs/shared",
    "services/api",
    "services/worker",
    "tools/cli",
  ]);
  assert.deepEqual(workspaceOf(pnpm, "lerna.json").members, ["modules/x"]);

  const uv = await mapOf(t, {
    "pyproject.toml": '[project]\nname = "root"\n\n[tool.uv.workspace]\nmembers = [\n    "packages/*",\n]\n',
    "packages/core/pyproject.toml": '[project]\nname = "core"\n',
    "packages/core/core.py": "x = 1\n",
  });
  assert.deepEqual(workspaceOf(uv, "pyproject.toml"), {
    manager: "uv",
    manifest: "pyproject.toml",
    patterns: ["packages/*"],
    members: ["packages/core"],
  });
});

test("Cargo and uv excludes remove the excluded folders from the members, and are not patterns", async (t) => {
  const layers = await mapOf(t, {
    "Cargo.toml": '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/old"]\n',
    "pyproject.toml": '[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = [\n  "packages/legacy",  # kept for the old build\n]\n',
    "crates/core/Cargo.toml": '[package]\nname = "core"\n',
    "crates/old/Cargo.toml": '[package]\nname = "old"\n',
    "packages/api/pyproject.toml": '[project]\nname = "api"\n',
    "packages/legacy/pyproject.toml": '[project]\nname = "legacy"\n',
  });

  assert.deepEqual(workspaceOf(layers, "Cargo.toml").members, ["crates/core"]);
  assert.deepEqual(workspaceOf(layers, "Cargo.toml").patterns, ["crates/*"]);
  assert.deepEqual(workspaceOf(layers, "pyproject.toml").members, ["packages/api"]);
  assert.deepEqual(workspaceOf(layers, "pyproject.toml").patterns, ["packages/*"]);
});

test("yarn is the manager of a package.json workspace when a yarn.lock is at the root", async (t) => {
  const layers = await mapOf(t, {
    "package.json": '{"workspaces":{"packages":["libs/*"]}}\n',
    "yarn.lock": "# lock\n",
    "libs/a/package.json": "{}\n",
  });
  assert.equal(workspaceOf(layers, "package.json").manager, "yarn");
  assert.deepEqual(workspaceOf(layers, "package.json").members, ["libs/a"]);
});

test("frontend and backend without workspaces: manifests, names and languages, and no workspace", async (t) => {
  const layers = await mapOf(t, {
    "frontend/package.json": '{"name":"frontend"}\n',
    "frontend/src/App.tsx": "export {};\n",
    "backend/go.mod": "module example.com/backend\n",
    "backend/main.go": "package main\n",
    "db/migrations/001.sql": "create table t (id int);\n",
  });

  assert.equal(layers.structure, "units");
  assert.deepEqual(layers.workspaces, []);
  assert.deepEqual(
    layers.units.map((unit) => unit.path),
    [".", "backend", "db", "db/migrations", "frontend"],
  );
  assert.deepEqual(unitOf(layers, "frontend").signals, [
    { type: "manifest", file: "package.json" },
    { type: "name", hint: "frontend" },
  ]);
  assert.deepEqual(unitOf(layers, "backend").signals, [
    { type: "manifest", file: "go.mod" },
    { type: "name", hint: "backend" },
  ]);
  assert.deepEqual(unitOf(layers, "db").signals, [{ type: "name", hint: "database" }]);
  assert.deepEqual(unitOf(layers, "db/migrations").signals, [{ type: "name", hint: "database" }]);
  assert.deepEqual(unitOf(layers, "backend").languages, [{ language: "Go", files: 1 }]);
  assert.deepEqual(unitOf(layers, "db/migrations").languages, [{ language: "SQL", files: 1 }]);
});

test("flat repository: one suggested layer, whole repository, with the top-level folders as options", async (t) => {
  const layers = await mapOf(t, {
    "package.json": '{"name":"flat","scripts":{"test":"node --test"}}\n',
    "README.md": "# Flat\n",
    "src/index.js": "export const x = 1;\n",
    "tests/index.test.js": "import './index.js';\n",
  });

  assert.equal(layers.structure, "flat");
  assert.deepEqual(
    layers.units.map((unit) => unit.path),
    [".", "tests"],
    "a name alone is a unit, and does not make the structure",
  );
  assert.deepEqual(unitOf(layers, "tests").signals, [{ type: "name", hint: "tests" }]);
  assert.deepEqual(layers.workspaces, []);
  assert.deepEqual(layers.suggestion, {
    layers: [{ name: "whole repository", folders: ["."], options: ["src", "tests"] }],
  });
  assert.deepEqual(layers.folders, [".", "src", "tests"]);
});

test("a flat suggestion whose top-level folders are cut by the entry cap warns with options-cut", async (t) => {
  const files = { "package.json": '{"name":"flat"}\n' };
  for (let number = 0; number < 35; number += 1) files[`dir${String(number).padStart(2, "0")}/file.txt`] = "x\n";
  const layers = await mapOf(t, files);

  assert.equal(layers.structure, "flat");
  assert.equal(layers.suggestion.layers[0].options.length, 30);
  assert.deepEqual(
    layers.warnings.filter((item) => item.reason === "options-cut"),
    [{ path: ".", reason: "options-cut", detail: "count=5" }],
  );
  const few = await mapOf(t, { "package.json": '{"name":"flat"}\n', "dir00/file.txt": "x\n" });
  assert.ok(!few.warnings.some((item) => item.reason === "options-cut"), "positive control: no cut, no warning");
});

test("the tree stops at the depth cap and shows at most the entry cap, and truncated counts what it leaves out", async (t) => {
  const files = { "a/b/c/d/e/f.txt": "x\n" };
  for (let number = 0; number < 35; number += 1) {
    files[`dir${String(number).padStart(2, "0")}/file.txt`] = "y\n";
  }
  const layers = await mapOf(t, files);

  assert.equal(layers.tree.children.length, 30);
  assert.equal(layers.tree.truncated, 6, "dir29 to dir34 are left out");
  const a = layers.tree.children.find((child) => child.path === "a");
  assert.ok(a, "a is shown");
  const c = a.children[0].children[0];
  assert.equal(c.path, "a/b/c");
  assert.deepEqual(c.children, [], "the depth cap stops the tree at a/b/c");
  assert.equal(c.truncated, 1, "d is counted, not shown");
  assert.ok(!layers.folders.includes("a/b/c/d"), "a folder below the depth cap is not in folders");
  const depth = (node, level) => Math.max(level, ...node.children.map((child) => depth(child, level + 1)));
  assert.equal(depth(layers.tree, 0), 3);
});

test("bytes are null above the file cap, and given under it", async (t) => {
  const files = { "packages/x/package.json": "{}\n", "packages/x/index.js": "let x;\n", "notes.txt": "hello\n" };
  const under = await mapOf(t, files, { maxStats: 3 });
  assert.equal(unitOf(under, ".").bytes, 16);
  assert.equal(unitOf(under, "packages/x").bytes, 10);
  assert.ok(!under.warnings.some((item) => item.reason === "bytes-cut"), "the cap is not passed at the limit");

  const over = await mapOf(t, files, { maxStats: 2 });
  for (const unit of over.units) assert.equal(unit.bytes, null, `${unit.path} has no bytes`);
  assert.deepEqual(
    over.warnings.filter((item) => item.reason === "bytes-cut"),
    [{ path: ".", reason: "bytes-cut", detail: "count=3" }],
  );
});

test("a root manifest that cannot be parsed gives a manifest-unparsed warning, and a valid one does not", async (t) => {
  const broken = await mapOf(t, {
    "package.json": '{"name": "broken", "workspaces": [',
    "packages/a/package.json": '{"name":"a"}\n',
  });
  assert.deepEqual(broken.workspaces, []);
  assert.deepEqual(
    broken.warnings.filter((item) => item.reason === "manifest-unparsed"),
    [{ path: "package.json", reason: "manifest-unparsed", detail: "invalid-json" }],
  );

  const valid = await mapOf(t, {
    "package.json": '{"name":"ok","workspaces":["packages/*"]}\n',
    "packages/a/package.json": '{"name":"a"}\n',
  });
  assert.deepEqual(workspaceOf(valid, "package.json").members, ["packages/a"]);
  assert.ok(!valid.warnings.some((item) => item.reason === "manifest-unparsed"));
});

test("a manifest over the 1 MiB cap is not read: a manifest-unparsed warning, no workspace, and the folders still map", async (t) => {
  const big = JSON.stringify({ workspaces: ["packages/*"], pad: "x".repeat(MAX_MANIFEST_BYTES) });
  const layers = await mapOf(t, { "package.json": big, "packages/a/package.json": "{}\n" });

  assert.deepEqual(layers.workspaces, []);
  assert.deepEqual(
    layers.warnings.filter((item) => item.reason === "manifest-unparsed"),
    [{ path: "package.json", reason: "manifest-unparsed", detail: "too-large" }],
  );
  assert.ok(layers.units.some((unit) => unit.path === "packages/a"), "the folders still map");
});

test("workspace patterns are read up to the cap, and the rest are counted in one warning", async (t) => {
  const patterns = Array.from({ length: MAX_WORKSPACE_PATTERNS + 5 }, (_, index) => `packages/p${index}`);
  const files = { "package.json": JSON.stringify({ workspaces: patterns }) };
  for (const name of ["p0", "p1", "p2", "p3"]) files[`packages/${name}/package.json`] = "{}\n";
  const layers = await mapOf(t, files);

  assert.equal(workspaceOf(layers, "package.json").patterns.length, MAX_WORKSPACE_PATTERNS);
  assert.deepEqual(workspaceOf(layers, "package.json").members, [
    "packages/p0",
    "packages/p1",
    "packages/p2",
    "packages/p3",
  ]);
  assert.deepEqual(
    layers.warnings.filter((item) => item.reason === "workspace-patterns-cut"),
    [{ path: "package.json", reason: "workspace-patterns-cut", detail: "count=5" }],
  );
});

test("negated and unsupported workspace patterns are skipped with a warning, and the other patterns still match", async (t) => {
  const layers = await mapOf(t, {
    "package.json": '{"workspaces":["packages/*","!packages/a","packages/{a,b}"]}\n',
    "packages/a/package.json": "{}\n",
    "packages/b/package.json": "{}\n",
  });

  assert.deepEqual(workspaceOf(layers, "package.json").patterns, ["!packages/a", "packages/*", "packages/{a,b}"]);
  assert.deepEqual(workspaceOf(layers, "package.json").members, ["packages/a", "packages/b"]);
  const skipped = layers.warnings.filter((item) => item.reason === "workspace-pattern-skipped");
  assert.deepEqual(skipped, [
    { path: "package.json", reason: "workspace-pattern-skipped", detail: "negated" },
    { path: "package.json", reason: "workspace-pattern-skipped", detail: "unsupported" },
  ]);
});

test("two names that redact to the same text keep the first in raw order, with one redacted-duplicate warning", async (t) => {
  const first = `ghp_${"a".repeat(20)}wxyz`;
  const second = `ghp_${"b".repeat(20)}wxyz`;
  const layers = await mapOf(t, {
    [`${first}/package.json`]: "{}\n",
    [`${second}/package.json`]: "{}\n",
    "plain/package.json": "{}\n",
  });

  const masked = "ghp_\u2026wxyz";
  assert.deepEqual(layers.units.map((unit) => unit.path), [".", masked, "plain"]);
  assert.deepEqual(layers.tree.children.map((child) => child.path), [masked, "plain"]);
  assert.deepEqual(
    layers.warnings.filter((item) => item.reason === "redacted-duplicate"),
    [{ path: masked, reason: "redacted-duplicate" }],
  );
  assert.ok(!toStableJson(layers).includes("aaaaaaaa"), "the token body is not written");
});

test("hostile folder names: the JSON round-trips, the token-shaped name is masked, refused names are left out, and normal names pass", { skip: hostileSkip }, async (t) => {
  const token = "ghp_abcdefghijklmnopqrstuvwx";
  const layers = await mapOf(t, {
    "line\nbreak/package.json": "{}\n",
    'quote"name/package.json': "{}\n",
    "\u202Ebidi/package.json": "{}\n",
    "..a/package.json": "{}\n",
    [`${token}/package.json`]: "{}\n",
    "back\\slash/package.json": "{}\n",
    ".../package.json": "{}\n",
    "packages/plain/package.json": "{}\n",
  });

  const text = toStableJson(layers);
  assert.deepEqual(JSON.parse(text), layers, "the output is valid JSON that reads back as the same data");
  assert.ok(!text.includes("abcdefghijklmnopqrstuvwx"), "the token body is not written");
  const paths = layers.units.map((unit) => unit.path);
  for (const name of ["line\nbreak", 'quote"name', "\u202Ebidi", "..a", "ghp_\u2026uvwx", "packages/plain"]) {
    assert.ok(paths.includes(name), `the unit ${JSON.stringify(name)} is listed`);
  }
  assert.deepEqual(unitOf(layers, "packages/plain").signals, [{ type: "manifest", file: "package.json" }]);
  assert.ok(!paths.some((item) => item.includes("back")), "a name with a backslash is refused");
  assert.ok(!paths.includes("..."), "a parent-like name is refused");
  const refused = layers.warnings.filter((item) => item.reason === "unsafe-path").map((item) => item.path);
  assert.deepEqual(refused.sort(), ["...", "back\\slash"]);
});

test("inside a git repository the file list comes from git, and the layers match the monorepo", async (t) => {
  const fixture = makeFixture({ git: true, files: { ...MONOREPO } });
  t.after(fixture.cleanup);
  const layers = await mapLayers({ root: fixture.root, now: FIXED_NOW });

  assert.equal(layers.structure, "units");
  assert.deepEqual(workspaceOf(layers, "package.json").members, ["apps/web", "packages/a", "packages/b"]);
  assert.ok(!layers.warnings.some((item) => item.reason === "file-list-from-walk"), "git listed the files");
});

test("an empty target maps to the root alone, flat, with no folders", async (t) => {
  const layers = await mapOf(t, {});

  assert.equal(layers.structure, "flat");
  assert.deepEqual(layers.units.map((unit) => [unit.path, unit.files, unit.bytes]), [[".", 0, 0]]);
  assert.deepEqual(layers.tree, { path: ".", files: 0, children: [], truncated: 0 });
  assert.deepEqual(layers.folders, ["."]);
  assert.deepEqual(layers.suggestion, { layers: [{ name: "whole repository", folders: ["."], options: [] }] });
  assert.deepEqual(layers.workspaces, []);
});

test("a symbolic link inside the target that leads outside is not followed, and nothing outside is read", { skip: symlinkSkip }, async (t) => {
  const fixture = makeFixture({
    files: { "src/index.js": "export {};\n", "packages/a/package.json": "{}\n" },
    outside: {
      "secret/pyproject.toml": '[tool.uv.workspace]\nmembers = ["stolen/*"]\n',
      "secret/notes.txt": "private notes\n",
    },
    symlinks: [
      { path: "linked", target: "../outside/secret" },
      { path: "pyproject.toml", target: "../outside/secret/pyproject.toml" },
    ],
  });
  t.after(fixture.cleanup);
  const layers = await mapLayers({ root: fixture.root, now: FIXED_NOW });

  const text = toStableJson(layers);
  assert.ok(!text.includes("stolen") && !text.includes("private notes"), "nothing outside is in the output");
  assert.equal(layers.workspaces.some((item) => item.manager === "uv"), false, "the linked manifest is not read");
  assert.ok(!layers.units.some((unit) => unit.path === "linked"), "a linked folder is not a unit");
  assert.ok(
    layers.warnings.some((item) => item.path === "linked" && item.reason === "outside-root"),
    "the link is refused as outside the target",
  );
});

test("the same target gives the same layers except meta", async (t) => {
  const fixture = freshFixture(t, MONOREPO);
  const first = await mapLayers({ root: fixture.root, now: FIXED_NOW });
  const second = await mapLayers({ root: fixture.root, now: new Date("2026-10-18T08:00:00.000Z") });

  assert.equal(first.meta.mappedAt, "2026-10-17T12:00:00.000Z");
  assert.equal(second.meta.mappedAt, "2026-10-18T08:00:00.000Z");
  const { meta: metaFirst, ...restFirst } = first;
  const { meta: metaSecond, ...restSecond } = second;
  assert.equal(toStableJson(restFirst), toStableJson(restSecond));
  assert.equal(metaFirst.targetRoot, metaSecond.targetRoot);
  assert.equal(metaFirst.targetRoot, fs.realpathSync.native(fixture.root), "targetRoot is the one absolute path");
});

// Each workspace parser gets a hostile line of about 1 MB. The earlier patterns took seconds or more on lines like these, and
// the parsers now read a line with string operations, so each one finishes in milliseconds. A normal file is read next to them.
test("the workspace parsers finish fast on hostile lines of about 1 MB, and a normal file is read", () => {
  const hostile = [
    ["Cargo.toml", `[${" ".repeat(MIB)}x\n`],
    ["Cargo.toml", `[workspace]\nmembers = [${" ".repeat(MIB)}"a"\n`],
    ["pyproject.toml", `[tool.uv.workspace]\nmembers = ["a"${" ".repeat(MIB)}\u2028\n`],
    ["go.work", `use${" ".repeat(MIB)}\u2028./a\n`],
    ["go.work", `${"//".repeat(MIB / 2)}\u2028\nuse ./a\n`],
    ["pnpm-workspace.yaml", `packages:\n  -${" ".repeat(MIB)}\u2028\n`],
    ["package.json", `{"workspaces":["${"./".repeat(MIB / 2)}x"]}`],
  ];
  for (const [file, text] of hostile) {
    const started = performance.now();
    readWorkspaceFile(file, text);
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 1000, `${file} took ${elapsed.toFixed(0)} ms on a hostile line`);
  }

  assert.deepEqual(readWorkspaceFile("go.work", "use ./a // note\nuse (\n\t./b\n)\n"), {
    ok: true,
    patterns: ["./a", "./b"],
    excludes: [],
  }, "positive control");
  assert.deepEqual(readWorkspaceFile("Cargo.toml", '[workspace]\nmembers = ["crates/*"]\nexclude = ["crates/x"]\n'), {
    ok: true,
    patterns: ["crates/*"],
    excludes: ["crates/x"],
  }, "positive control");
  assert.deepEqual(readWorkspaceFile("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n"), {
    ok: true,
    patterns: ["packages/*"],
    excludes: [],
  }, "positive control");
  assert.equal(readWorkspaceFile("Cargo.toml", "[workspace]\nmembers = [\"a\"\n").ok, false, "an unclosed list is refused");
});

test("a hostile workspace line in a mapped repository is skipped quickly, and the normal pattern still matches", async (t) => {
  const layers = await mapOf(t, {
    "package.json": JSON.stringify({ workspaces: ["./".repeat(MIB / 2) + "x", "packages/*"] }),
    "packages/a/package.json": "{}\n",
  });

  assert.deepEqual(workspaceOf(layers, "package.json").members, ["packages/a"]);
  assert.deepEqual(workspaceOf(layers, "package.json").patterns, ["packages/*"], "the long pattern is not listed");
  assert.ok(
    layers.warnings.some((item) => item.reason === "workspace-pattern-skipped" && item.detail === "unsupported"),
    "the long pattern is skipped as unsupported",
  );
});

test("the emitted layers match schemas/layers.schema.json", async (t) => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  const monorepo = await mapOf(t, { ...MONOREPO, "services/api/CLAUDE.md": "# API\n" });
  assert.deepEqual(problemsOf(schema, monorepo, "layers", schema), []);
  const flat = await mapOf(t, { "package.json": "{}\n", "src/index.js": "x\n", "tests/a.test.js": "y\n" });
  assert.deepEqual(problemsOf(schema, flat, "layers", schema), []);
  assert.ok(problemsOf(schema, { ...flat, extra: 1 }, "layers", schema).length > 0, "an extra key is a problem");
});

test("the caps are non-negative integers and no other limit is accepted", async (t) => {
  const fixture = freshFixture(t, { "a.txt": "x\n" });
  await assert.rejects(mapLayers({ root: fixture.root, limits: { maxStats: -1 } }), TypeError);
  await assert.rejects(mapLayers({ root: fixture.root, limits: { maxTreeDepth: 1.5 } }), TypeError);
  await assert.rejects(mapLayers({ root: fixture.root, limits: { bogus: 1 } }), TypeError);
  await assert.rejects(mapLayers({ root: "" }), TypeError);
});
