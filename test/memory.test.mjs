import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { claudeConfigMeasure } from "../scripts/lib/claude-config.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { createMemoryMeasure, memoryMeasure } from "../scripts/lib/memory.mjs";
import { DEFAULT_MAX_BYTES } from "../scripts/lib/safe-fs.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { estimateTokens } from "../scripts/lib/tokens.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
// Text that only the files outside the target contain. No output and no memory entry may include it.
const WITNESS = "witness-5d1e-outside-the-target";

// A copy of a versioned fixture in a temp folder, with extra files written on top of the copy.
function copyOf(t, name, files = {}) {
  const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), files });
  t.after(fixture.cleanup);
  return fixture;
}

// A new fixture in a temp folder.
function freshFixture(t, description = {}) {
  const fixture = makeFixture(description);
  t.after(fixture.cleanup);
  return fixture;
}

// Runs the memory measure. The ancestor walk stops at the fixture folder, so the real parent folders
// of the temp folder never count. The home folder defaults to a folder that does not exist.
function memoryScan(root, base, { home, extra = [] } = {}) {
  return scan({
    root,
    measures: [createMemoryMeasure({ ancestorLimit: base, home: home ?? path.join(base, "no-home") }), ...extra],
    now: FIXED_NOW,
  });
}

// A measure placed after the memory measure. It copies what the memory measure left in ctx.memory.
function memoryProbe() {
  const seen = { entries: [] };
  const probe = {
    id: "probe",
    collect: (ctx) => {
      seen.entries = [...ctx.memory.entries()];
      return {};
    },
  };
  return { seen, probe };
}

function item(result, rel) {
  const found = result.inventory.find((entry) => entry.path === rel);
  assert.ok(found, `${rel} is in the inventory`);
  return found;
}

const memoryWarnings = (result) => result.warnings.filter((warning) => warning.source === "memory");
const importsOf = (result) => result.context.imports;

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

test("memory: the production measure has its id and a collect function", () => {
  assert.equal(memoryMeasure.id, "memory");
  assert.equal(typeof memoryMeasure.collect, "function");
});

test("memory: the test seam refuses a relative or non-absolute folder", () => {
  assert.throws(() => createMemoryMeasure({ ancestorLimit: "relative/folder" }), TypeError);
  assert.throws(() => createMemoryMeasure({ home: "relative-home" }), TypeError);
});

test("memory: an ancestor limit that is not a parent of the target makes the scan fail", async (t) => {
  const fixture = freshFixture(t, { files: { "AGENTS.md": "# Agents\n" } });
  await assert.rejects(
    memoryScan(fixture.root, path.join(fixture.base, "elsewhere")),
    /ancestorLimit is not the target or one of its parent folders/,
  );
});

test("memory: agents-only, AGENTS.md is always loaded because there is no CLAUDE.md", async (t) => {
  const fixture = copyOf(t, "agents-only");
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(item(result, "AGENTS.md"), {
    path: "AGENTS.md",
    kind: "memory",
    loadMode: "always",
    loadReason: "no CLAUDE.md in the target or its ancestors",
    bytes: fs.statSync(path.join(fixture.root, "AGENTS.md")).size,
    lines: 3,
    estTokens: item(result, "AGENTS.md").estTokens,
  });
  assert.ok(item(result, "AGENTS.md").estTokens > 0);
  assert.deepEqual(result.context.alwaysLoaded.byComponent, [
    { component: "memory", estTokens: item(result, "AGENTS.md").estTokens, items: [{ path: "AGENTS.md", estTokens: item(result, "AGENTS.md").estTokens }] },
  ]);
  assert.deepEqual(importsOf(result), []);
});

test("memory: claude-and-agents, AGENTS.md is read but not loaded when CLAUDE.md does not import it", async (t) => {
  const fixture = copyOf(t, "claude-and-agents");
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  assert.equal(item(result, "CLAUDE.md").loadMode, "always");
  assert.equal(item(result, "CLAUDE.md").lines, 3);
  const agents = item(result, "AGENTS.md");
  assert.equal(agents.loadMode, "not-loaded");
  assert.equal(agents.loadReason, "a CLAUDE.md exists and does not import it");
  assert.equal(agents.lines, 3, "an AGENTS.md that is not loaded is still read for its size");
  assert.deepEqual(
    result.context.alwaysLoaded.byComponent[0].items.map((entry) => entry.path),
    ["CLAUDE.md"],
    "only the loaded file is in the budget",
  );
  assert.deepEqual(
    seen.entries.map(([rel, value]) => [rel, value.loadMode]),
    [
      ["AGENTS.md", "not-loaded"],
      ["CLAUDE.md", "always"],
    ],
  );
});

test("memory: claude-and-agents with @AGENTS.md, AGENTS.md is loaded once, through the import", async (t) => {
  const fixture = copyOf(t, "claude-and-agents", { "CLAUDE.md": "# Claude memory\n\n@AGENTS.md\n" });
  const result = await memoryScan(fixture.root, fixture.base);

  const agents = item(result, "AGENTS.md");
  assert.equal(agents.loadMode, "always");
  assert.equal(agents.loadReason, "imported by CLAUDE.md");
  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 3, ref: "AGENTS.md", path: "AGENTS.md", depth: 1, status: "ok" },
  ]);
  const [memory] = result.context.alwaysLoaded.byComponent;
  assert.deepEqual(
    memory.items.map((entry) => entry.path),
    ["AGENTS.md", "CLAUDE.md"],
    "each file is counted once",
  );
  assert.equal(memory.estTokens, item(result, "CLAUDE.md").estTokens + agents.estTokens);
});

test("memory: rules-scoped, rules without paths load at the start and rules with paths load on demand", async (t) => {
  const fixture = copyOf(t, "rules-scoped");
  const result = await memoryScan(fixture.root, fixture.base);

  assert.equal(item(result, ".claude/rules/general.md").loadMode, "always");
  assert.equal(item(result, ".claude/rules/general.md").kind, "rule");
  assert.equal(item(result, ".claude/rules/described.md").loadMode, "always", "a description is not a paths key");
  assert.equal(item(result, ".claude/rules/typescript.md").loadMode, "on-demand");
  assert.equal(item(result, ".claude/rules/nested/docs.md").loadMode, "on-demand");
  assert.equal(
    item(result, ".claude/rules/typescript.md").loadReason,
    "rule with paths, loaded when a matching file is read",
  );
  assert.deepEqual(
    result.context.alwaysLoaded.byComponent[0].items.map((entry) => entry.path),
    [".claude/rules/described.md", ".claude/rules/general.md", "CLAUDE.md"],
  );
  assert.deepEqual(memoryWarnings(result), []);
});

test("memory: imports-deep, five hops, a fenced block and an inline code span are ignored, and a home path is external", async (t) => {
  const fixture = copyOf(t, "imports-deep");
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  // Positive control: the files that must not be read really exist.
  assert.ok(fs.existsSync(path.join(fixture.root, "chain", "five.md")));
  assert.ok(fs.existsSync(path.join(fixture.root, "chain", "fenced-target.md")));
  assert.ok(fs.existsSync(path.join(fixture.root, "chain", "inline-target.md")));

  assert.deepEqual(
    result.inventory.map((entry) => entry.path),
    ["CLAUDE.md", "chain/four.md", "chain/one.md", "chain/three.md", "chain/two.md", "shared/common.md"],
    "the file at hop 5 and the files named only in code are not in the inventory",
  );
  assert.deepEqual(
    result.inventory.map((entry) => entry.loadMode),
    ["always", "always", "always", "always", "always", "always"],
  );
  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 3, ref: "chain/one.md", path: "chain/one.md", depth: 1, status: "ok" },
    { from: "CLAUDE.md", line: 4, ref: "shared/common.md", path: "shared/common.md", depth: 1, status: "ok" },
    { from: "CLAUDE.md", line: 14, ref: "~/.ssh/config", path: null, depth: 1, status: "external" },
    { from: "chain/four.md", line: 1, ref: "five.md", path: "chain/five.md", depth: 5, status: "too-deep" },
    { from: "chain/one.md", line: 1, ref: "../shared/common.md", path: "shared/common.md", depth: 2, status: "ok" },
    { from: "chain/one.md", line: 1, ref: "two.md", path: "chain/two.md", depth: 2, status: "ok" },
    { from: "chain/three.md", line: 1, ref: "four.md", path: "chain/four.md", depth: 4, status: "ok" },
    { from: "chain/two.md", line: 1, ref: "three.md", path: "chain/three.md", depth: 3, status: "ok" },
  ]);
  assert.equal(
    seen.entries.some(([rel]) => rel === "chain/five.md"),
    false,
    "the file at hop 5 is never read",
  );
  assert.equal(
    result.context.alwaysLoaded.byComponent[0].items.length,
    6,
    "a file imported twice is counted once",
  );
});

test("memory: bloated, a CLAUDE.md of 250 lines is reported as a memory-lines limit", async (t) => {
  const fixture = copyOf(t, "bloated");
  const result = await memoryScan(fixture.root, fixture.base);

  assert.equal(item(result, "CLAUDE.md").lines, 250);
  assert.equal(item(result, "CLAUDE.md").loadMode, "always");
  assert.deepEqual(result.context.limits, [
    { path: "CLAUDE.md", limit: "memory-lines", value: 250, threshold: 200 },
  ]);
});

test("memory: the import syntax, only @ after whitespace with a path-like token, outside code", async (t) => {
  const syntax = [
    "# Syntax",
    "Ask @maintainer about this.",
    "Mail someone@example.com.",
    "See @notes.md.",
    "Use (@notes.md) here.",
    "Path @docs/guide.md, then more.",
    "Code `@notes.md` is not an import.",
    "```",
    "@notes.md",
    "```",
    "",
  ].join("\n");
  const fixture = freshFixture(t, { files: { "notes.md": "Notes.\n" } });
  fs.writeFileSync(path.join(fixture.root, "CLAUDE.md"), syntax);
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 4, ref: "notes.md", path: "notes.md", depth: 1, status: "ok" },
    { from: "CLAUDE.md", line: 6, ref: "docs/guide.md", path: "docs/guide.md", depth: 1, status: "broken" },
  ]);
  assert.deepEqual(
    result.inventory.map((entry) => entry.path),
    ["CLAUDE.md", "notes.md"],
  );
});

test("memory: a broken import is reported with the path it names, and it is not in the inventory", async (t) => {
  const fixture = freshFixture(t, { files: { "CLAUDE.md": "Missing: @docs/missing.md\n" } });
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 1, ref: "docs/missing.md", path: "docs/missing.md", depth: 1, status: "broken" },
  ]);
  assert.deepEqual(result.inventory.map((entry) => entry.path), ["CLAUDE.md"]);
});

test("memory: a cycle is reported once per back edge, and no file is read twice", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "CLAUDE.md": "See @a.md\n",
      "a.md": "Back to @CLAUDE.md and on to @b.md\n",
      "b.md": "Loops back: @a.md\n",
    },
  });
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 1, ref: "a.md", path: "a.md", depth: 1, status: "ok" },
    { from: "a.md", line: 1, ref: "CLAUDE.md", path: "CLAUDE.md", depth: 2, status: "cycle" },
    { from: "a.md", line: 1, ref: "b.md", path: "b.md", depth: 2, status: "ok" },
    { from: "b.md", line: 1, ref: "a.md", path: "a.md", depth: 3, status: "cycle" },
  ]);
  assert.deepEqual(result.inventory.map((entry) => entry.path), ["CLAUDE.md", "a.md", "b.md"]);
});

test("memory: a file imported by two others is counted once, and it is not a cycle", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "CLAUDE.md": "First @one.md and second @two.md\n",
      "one.md": "Shared @shared.md\n",
      "two.md": "Shared too @shared.md\n",
      "shared.md": "Shared text.\n",
    },
  });
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(
    importsOf(result).map((entry) => [entry.from, entry.ref, entry.status]),
    [
      ["CLAUDE.md", "one.md", "ok"],
      ["CLAUDE.md", "two.md", "ok"],
      ["one.md", "shared.md", "ok"],
      ["two.md", "shared.md", "ok"],
    ],
  );
  assert.deepEqual(
    result.inventory.map((entry) => entry.path),
    ["CLAUDE.md", "one.md", "shared.md", "two.md"],
  );
});

test("memory: an absolute path inside the target resolves, and the reference is shown as a target path", async (t) => {
  const fixture = freshFixture(t, { files: { "notes.md": "Notes.\n" } });
  const posixRoot = fixture.root.replaceAll("\\", "/");
  fs.writeFileSync(path.join(fixture.root, "CLAUDE.md"), `Inside: @${posixRoot}/notes.md\n`);
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 1, ref: "<target>/notes.md", path: "notes.md", depth: 1, status: "ok" },
  ]);
  assert.equal(item(result, "notes.md").loadMode, "always");
});

test("memory: an absolute path outside the target is external, and its reference is shown as <outside>", async (t) => {
  const fixture = freshFixture(t, { outside: { "absolute.md": WITNESS } });
  const outsidePosix = fixture.outsideDir.replaceAll("\\", "/");
  fs.writeFileSync(path.join(fixture.root, "CLAUDE.md"), `Secret: @${outsidePosix}/absolute.md\n`);
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  // Positive control: the witness file exists.
  assert.ok(fs.readFileSync(path.join(fixture.outsideDir, "absolute.md"), "utf8").includes(WITNESS));
  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 1, ref: "<outside>", path: null, depth: 1, status: "external" },
  ]);
  assertNoWitness(result, seen);
});

test("memory: a home path import is external, and the file behind it is never read", async (t) => {
  const fixture = freshFixture(t, { files: { "CLAUDE.md": "Config: @~/.ssh/config\n" }, outside: { ".ssh/config": WITNESS } });
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { home: fixture.outsideDir, extra: [probe] });

  assert.ok(fs.readFileSync(path.join(fixture.outsideDir, ".ssh", "config"), "utf8").includes(WITNESS));
  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 1, ref: "~/.ssh/config", path: null, depth: 1, status: "external" },
  ]);
  assertNoWitness(result, seen);
});

test("memory: a relative import that leaves the target is external, and the file behind it is never read", async (t) => {
  const fixture = freshFixture(t, { files: { "CLAUDE.md": "Secret: @../outside/secret.md\n" }, outside: { "secret.md": WITNESS } });
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  assert.ok(fs.readFileSync(path.join(fixture.outsideDir, "secret.md"), "utf8").includes(WITNESS));
  assert.deepEqual(importsOf(result), [
    { from: "CLAUDE.md", line: 1, ref: "../outside/secret.md", path: null, depth: 1, status: "external" },
  ]);
  assertNoWitness(result, seen);
});

test("memory: a CLAUDE.md that is a link to a file outside the target is not read, and AGENTS.md is not loaded", { skip: symlinkSupport().supported ? false : symlinkSupport().reason }, async (t) => {
  const fixture = makeFixture({
    files: { "AGENTS.md": "# Agents\n" },
    outside: { "secret.md": WITNESS },
    symlinks: [{ path: "CLAUDE.md", target: "../outside/secret.md" }],
  });
  t.after(fixture.cleanup);
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  assert.ok(fs.readFileSync(path.join(fixture.outsideDir, "secret.md"), "utf8").includes(WITNESS));
  assert.equal(
    result.inventory.some((entry) => entry.path === "CLAUDE.md"),
    false,
    "a link that leaves the target is not an inventory item",
  );
  assert.equal(item(result, "AGENTS.md").loadMode, "not-loaded", "the CLAUDE.md link still counts as a CLAUDE.md");
  assert.ok(result.warnings.some((warning) => warning.source === "fs" && warning.path === "CLAUDE.md" && warning.reason === "outside-root"));
  assertNoWitness(result, seen);
});

test("memory: a CLAUDE.md larger than 4 MiB is skipped, not read, and reported", async (t) => {
  const size = DEFAULT_MAX_BYTES + 1;
  const fixture = freshFixture(t, { files: { "CLAUDE.md": Buffer.alloc(size, 0x61) } });
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  assert.deepEqual(item(result, "CLAUDE.md"), {
    path: "CLAUDE.md",
    kind: "memory",
    loadMode: "not-loaded",
    loadReason: "not read: larger than 4 MiB",
    bytes: size,
    lines: null,
    estTokens: null,
  });
  assert.deepEqual(result.context.limits, [
    { path: "CLAUDE.md", limit: "memory-bytes", value: size, threshold: DEFAULT_MAX_BYTES },
  ]);
  assert.deepEqual(memoryWarnings(result), [{ source: "memory", path: "CLAUDE.md", reason: "too-large" }]);
  assert.deepEqual(result.context.alwaysLoaded.byComponent[0], { component: "memory", estTokens: 0, items: [] });
  assert.equal(seen.entries.some(([rel]) => rel === "CLAUDE.md"), false);
});

test("memory: a CLAUDE.md in a subfolder is listed on demand and is never read", async (t) => {
  // The binary content makes a read visible: a read would add a "binary" warning for this path.
  const fixture = freshFixture(t, {
    files: {
      "CLAUDE.md": "# Root memory\n",
      "sub/CLAUDE.md": Buffer.from("# Subfolder memory\n\u0000binary", "utf8"),
      "sub/inner/AGENTS.md": "# Inner agents\n",
    },
  });
  const { seen, probe } = memoryProbe();
  const result = await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  const sub = item(result, "sub/CLAUDE.md");
  assert.equal(sub.loadMode, "on-demand");
  assert.equal(sub.lines, null);
  assert.equal(sub.estTokens, null);
  assert.equal(sub.bytes, fs.statSync(path.join(fixture.root, "sub", "CLAUDE.md")).size);
  assert.equal(item(result, "sub/inner/AGENTS.md").loadMode, "on-demand");
  assert.deepEqual(
    result.warnings.filter((warning) => warning.path === "sub/CLAUDE.md"),
    [],
    "no read was attempted",
  );
  assert.deepEqual(
    seen.entries.map(([rel]) => rel),
    ["CLAUDE.md"],
    "only the root file is in ctx.memory",
  );
  assert.deepEqual(result.context.alwaysLoaded.byComponent[0].items.map((entry) => entry.path), ["CLAUDE.md"]);
});

test("memory: a rule with broken frontmatter is a warning, and it loads as a rule without paths", async (t) => {
  const fixture = freshFixture(t, {
    files: { "CLAUDE.md": "# Root memory\n", ".claude/rules/broken.md": "---\npaths: src/**\n" },
  });
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(memoryWarnings(result), [{ source: "memory", path: ".claude/rules/broken.md", reason: "invalid-frontmatter" }]);
  assert.equal(item(result, ".claude/rules/broken.md").loadMode, "always");
});

test("memory: a rule whose paths value has the wrong type is a warning and loads as a rule without paths", async (t) => {
  const fixture = freshFixture(t, {
    files: { "CLAUDE.md": "# Root memory\n", ".claude/rules/number.md": "---\npaths: 5\n---\n\n# Rule\n" },
  });
  const result = await memoryScan(fixture.root, fixture.base);

  assert.deepEqual(memoryWarnings(result), [{ source: "memory", path: ".claude/rules/number.md", reason: "invalid-frontmatter" }]);
  assert.equal(item(result, ".claude/rules/number.md").loadMode, "always");
});

test("memory: a CLAUDE.local.md that is not versioned is still found", async (t) => {
  const fixture = freshFixture(t, { git: true, files: { "CLAUDE.md": "# Tracked\n" } });
  fs.writeFileSync(path.join(fixture.root, "CLAUDE.local.md"), "# Local only\n");
  const result = await memoryScan(fixture.root, fixture.base);

  assert.equal(result.target.fileListSource, "git");
  assert.equal(item(result, "CLAUDE.local.md").loadMode, "always");
  assert.equal(item(result, "CLAUDE.local.md").loadReason, "memory file at the root, loaded at session start");
});

test("memory: a CLAUDE.md in a parent folder is listed, and the AGENTS.md of the target is not loaded", async (t) => {
  const fixture = freshFixture(t, { files: { "CLAUDE.md": "# Parent memory\n", "sub/AGENTS.md": "# Sub agents\n" } });
  const result = await memoryScan(path.join(fixture.root, "sub"), fixture.base);

  assert.deepEqual(result.context.ancestors, [
    { path: "../CLAUDE.md", bytes: fs.statSync(path.join(fixture.root, "CLAUDE.md")).size },
  ]);
  assert.deepEqual(result.inventory.map((entry) => entry.path), ["AGENTS.md"], "ancestors are not in the inventory");
  assert.equal(item(result, "AGENTS.md").loadMode, "not-loaded");
});

test("memory: the ancestor walk goes through every parent folder up to the limit", async (t) => {
  const fixture = freshFixture(t, { files: { "sub/deeper/AGENTS.md": "# Deeper agents\n" } });
  fs.writeFileSync(path.join(fixture.base, "CLAUDE.md"), "# Base memory\n");
  fs.mkdirSync(path.join(fixture.root, ".claude"));
  fs.writeFileSync(path.join(fixture.root, ".claude", "CLAUDE.md"), "# Repo parent\n");
  const result = await memoryScan(path.join(fixture.root, "sub", "deeper"), fixture.base);

  assert.deepEqual(
    result.context.ancestors.map((entry) => entry.path),
    ["../../../CLAUDE.md", "../../.claude/CLAUDE.md"],
  );
  assert.equal(item(result, "AGENTS.md").loadMode, "not-loaded");
});

test("memory: the .claude/CLAUDE.md of the home folder is user memory, so it is skipped", async (t) => {
  const fixture = freshFixture(t, { files: { "sub/AGENTS.md": "# Sub agents\n" } });
  fs.mkdirSync(path.join(fixture.base, ".claude"));
  fs.writeFileSync(path.join(fixture.base, ".claude", "CLAUDE.md"), "# User memory\n");
  const root = path.join(fixture.root, "sub");

  const asHome = await memoryScan(root, fixture.base, { home: fixture.base });
  assert.deepEqual(asHome.context.ancestors, []);
  assert.equal(item(asHome, "AGENTS.md").loadMode, "always", "user memory does not stop AGENTS.md from loading");

  const elsewhere = await memoryScan(root, fixture.base, { home: path.join(fixture.base, "other-home") });
  assert.deepEqual(elsewhere.context.ancestors.map((entry) => entry.path), ["../../.claude/CLAUDE.md"]);
  assert.equal(item(elsewhere, "AGENTS.md").loadMode, "not-loaded");
});

test("memory: a loaded file's text is kept in ctx.memory with its kind and load mode", async (t) => {
  const fixture = copyOf(t, "rules-scoped");
  const { seen, probe } = memoryProbe();
  await memoryScan(fixture.root, fixture.base, { extra: [probe] });

  const byPath = new Map(seen.entries);
  assert.deepEqual(
    [...byPath.keys()].sort(),
    [".claude/rules/described.md", ".claude/rules/general.md", ".claude/rules/nested/docs.md", ".claude/rules/typescript.md", "CLAUDE.md"],
  );
  assert.deepEqual(
    { kind: byPath.get("CLAUDE.md").kind, loadMode: byPath.get("CLAUDE.md").loadMode },
    { kind: "memory", loadMode: "always" },
  );
  assert.equal(byPath.get(".claude/rules/typescript.md").loadMode, "on-demand");
  assert.match(byPath.get("CLAUDE.md").text, /^# Rules fixture\n/);
});

test("memory: the CLI gives the same JSON twice, except meta, on the imports fixture", async (t) => {
  const fixture = copyOf(t, "imports-deep");
  const first = path.join(fixture.base, "first");
  const second = path.join(fixture.base, "second");
  const firstRun = await runScan([fixture.root, "--out", first]);
  const secondRun = await runScan([fixture.root, "--out", second]);
  assert.equal(firstRun.code, 0, firstRun.stderr);
  assert.equal(secondRun.code, 0, secondRun.stderr);

  const rawFirst = fs.readFileSync(path.join(first, "measurements.json"), "utf8");
  const rawSecond = fs.readFileSync(path.join(second, "measurements.json"), "utf8");
  const dataFirst = JSON.parse(rawFirst);
  const dataSecond = JSON.parse(rawSecond);
  assert.equal(dataFirst.context.imports.length, 8);
  delete dataFirst.meta;
  delete dataSecond.meta;
  assert.deepEqual(dataFirst, dataSecond);
  assert.equal(withoutMetaText(rawFirst), withoutMetaText(rawSecond));
});

// Memory and claude-config together, as in the production scan: the exclusion list comes from claude-config.
async function scanWithConfig(t, files, extra = []) {
  const fixture = freshFixture(t, { files });
  return memoryScan(fixture.root, fixture.base, { extra: [...extra, claudeConfigMeasure] });
}

const SKILL = (name) => `---\nname: ${name}\ndescription: The ${name} skill.\n---\nBody.\n`;

test("memory: claudeMdExcludes lists the files it matches as not-loaded, never reads them, and keeps the others", async (t) => {
  const { seen, probe } = memoryProbe();
  const result = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["**/vendor/**"] }),
    ".claude/settings.local.json": JSON.stringify({ claudeMdExcludes: ["**/drafts/**"] }),
    "CLAUDE.md": "# Root\n\nRoot memory.\n",
    "vendor/lib/CLAUDE.md": `# Vendor\n\n${WITNESS}\n`,
    "vendor/lib/AGENTS.md": "# Vendor agents\n",
    "drafts/CLAUDE.md": "# Drafts\n",
    "app/CLAUDE.md": "# App\n\nApp memory.\n",
  }, [probe]);

  const vendor = item(result, "vendor/lib/CLAUDE.md");
  assert.equal(vendor.loadMode, "not-loaded");
  assert.equal(vendor.loadReason, "claude-md-excludes");
  assert.equal(vendor.excludedBy, "**/vendor/**");
  assert.equal(vendor.lines, null, "an excluded file is never read");
  assert.equal(vendor.estTokens, null);
  assert.ok(vendor.bytes > 0, "its size is still known");
  assert.equal(item(result, "vendor/lib/AGENTS.md").excludedBy, "**/vendor/**");
  // The pattern of the local file excludes this one; the shared file's pattern does not match it.
  assert.equal(item(result, "drafts/CLAUDE.md").excludedBy, "**/drafts/**");
  // Positive control: a file that no pattern matches stays on demand, and has no excludedBy.
  const app = item(result, "app/CLAUDE.md");
  assert.equal(app.loadMode, "on-demand");
  assert.equal(app.loadReason, "subfolder memory, loaded when a file in its folder is read");
  assert.equal("excludedBy" in app, false);
  assert.equal(item(result, "CLAUDE.md").loadMode, "always");

  // The budget counts the root file only. The excluded files are not in it, and nothing reads them.
  const budget = result.context.alwaysLoaded.byComponent.find((component) => component.component === "memory");
  assert.deepEqual(budget.items.map((entry) => entry.path), ["CLAUDE.md"]);
  assert.equal(budget.estTokens, estimateTokens("# Root\n\nRoot memory.\n").estTokens);
  assert.deepEqual(seen.entries.map(([file]) => file), ["CLAUDE.md"], "only the root file is in ctx.memory");
  assertNoWitness(result, seen);
});

test("memory: an import of an excluded file is listed as excluded, and the imports of that file are not followed", async (t) => {
  const scanned = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["**/vendor/**"] }),
    "CLAUDE.md": "# Root\n\n@vendor/notes.md\n@docs/extra.md\n",
    "vendor/notes.md": "# Notes\n\n@deep/file.md\n",
    "deep/file.md": "# Deep\n",
    "docs/extra.md": "# Extra\n",
  });
  const result = scanned;

  const imports = result.context.imports;
  assert.equal(imports.find((entry) => entry.ref === "vendor/notes.md").status, "excluded");
  assert.equal(imports.find((entry) => entry.ref === "docs/extra.md").status, "ok", "positive control: an import that is not excluded is loaded");
  assert.equal(item(result, "vendor/notes.md").loadReason, "claude-md-excludes");
  assert.equal(item(result, "docs/extra.md").loadMode, "always");
  assert.equal(result.inventory.some((entry) => entry.path === "deep/file.md"), false, "an import of an excluded file is not followed");
});

test("memory: a rule that claudeMdExcludes matches is not loaded, and other rules keep their mode", async (t) => {
  const scanned = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["**/shared.md"] }),
    "CLAUDE.md": "# Root\n",
    ".claude/rules/shared.md": "# Shared rule\n",
    ".claude/rules/general.md": "# General rule\n",
    ".claude/rules/scoped.md": "---\npaths: src/**\n---\n# Scoped rule\n",
  });
  const result = scanned;

  const shared = item(result, ".claude/rules/shared.md");
  assert.equal(shared.loadMode, "not-loaded");
  assert.equal(shared.excludedBy, "**/shared.md");
  assert.equal(shared.lines, null);
  assert.equal(item(result, ".claude/rules/general.md").loadMode, "always", "positive control: a rule without paths still loads");
  assert.equal(item(result, ".claude/rules/scoped.md").loadMode, "on-demand", "positive control: a rule with paths is on demand");
  const budget = result.context.alwaysLoaded.byComponent.find((component) => component.component === "memory");
  assert.equal(budget.items.some((entry) => entry.path === ".claude/rules/shared.md"), false);
});

test("memory: a claudeMdExcludes entry that is invalid does not stop a valid pattern from excluding a file", async (t) => {
  const scanned = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["[", "**/vendor/**", 4] }),
    "CLAUDE.md": "# Root\n",
    "vendor/CLAUDE.md": "# Vendor\n",
    "app/CLAUDE.md": "# App\n",
  });

  assert.equal(item(scanned, "vendor/CLAUDE.md").excludedBy, "**/vendor/**");
  assert.equal(item(scanned, "app/CLAUDE.md").loadMode, "on-demand", "positive control: a file no valid pattern matches");
});

test("memory: a repository that excludes its own test fixtures lists their memory files as excluded and their skills as nested", async (t) => {
  const scanned = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["**/test/fixtures/**"] }),
    "CLAUDE.md": "# Repository\n",
    "test/fixtures/a/CLAUDE.md": "# Fixture\n",
    "test/fixtures/a/AGENTS.md": "# Fixture agents\n",
    "test/fixtures/a/.claude/skills/x/SKILL.md": SKILL("x"),
  });

  assert.equal(item(scanned, "test/fixtures/a/CLAUDE.md").excludedBy, "**/test/fixtures/**");
  assert.equal(item(scanned, "test/fixtures/a/AGENTS.md").loadMode, "not-loaded");
  assert.equal(item(scanned, "CLAUDE.md").loadMode, "always");
  const [skill] = scanned.claudeConfig.skills;
  assert.equal(skill.path, "test/fixtures/a/.claude/skills/x/SKILL.md");
  assert.equal(skill.scope, "nested");
  assert.equal(skill.loadMode, "on-demand");
});

test("memory: when the only root CLAUDE.md is excluded, AGENTS.md has its own reason; a CLAUDE.md that loads keeps the old one", async (t) => {
  const excluded = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["CLAUDE.md"] }),
    "CLAUDE.md": "# Root\n",
    "AGENTS.md": "# Agents\n",
  });
  assert.equal(item(excluded, "CLAUDE.md").loadReason, "claude-md-excludes");
  const agents = item(excluded, "AGENTS.md");
  assert.equal(agents.loadMode, "not-loaded", "the budget is unchanged: AGENTS.md is not loaded");
  assert.equal(agents.loadReason, "claude-md-excluded-agents-unverified");
  assert.equal(agents.lines, 1, "the AGENTS file is still read for its size");

  // Positive control: a root CLAUDE.md that is not excluded keeps the existing reason.
  const loads = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["**/vendor/**"] }),
    "CLAUDE.md": "# Root\n",
    "AGENTS.md": "# Agents\n",
  });
  assert.equal(item(loads, "CLAUDE.md").loadMode, "always");
  assert.equal(item(loads, "AGENTS.md").loadReason, "a CLAUDE.md exists and does not import it");

  // Mixed: one root CLAUDE file is excluded and another loads, so the existing reason stays.
  const mixed = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["CLAUDE.md"] }),
    "CLAUDE.md": "# Root\n",
    "CLAUDE.local.md": "# Local\n",
    "AGENTS.md": "# Agents\n",
  });
  assert.equal(item(mixed, "CLAUDE.local.md").loadMode, "always", "positive control: the local file is not excluded");
  assert.equal(item(mixed, "AGENTS.md").loadReason, "a CLAUDE.md exists and does not import it");
});

test("memory: an absolute claudeMdExcludes pattern is a warning and excludes nothing, while a relative pattern excludes (positive control)", async (t) => {
  const absolute = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["/CLAUDE.md", "C:/work/**"] }),
    "CLAUDE.md": "# Root\n",
  });
  assert.ok(
    absolute.warnings.some((warning) => warning.source === "claude-config" && warning.reason === "unsupported-pattern"),
    "an absolute pattern is an unsupported-pattern warning",
  );
  assert.equal(item(absolute, "CLAUDE.md").loadMode, "always", "the root CLAUDE.md stays loaded");
  assert.equal("excludedBy" in item(absolute, "CLAUDE.md"), false);

  const relative = await scanWithConfig(t, {
    ".claude/settings.json": JSON.stringify({ claudeMdExcludes: ["CLAUDE.md"] }),
    "CLAUDE.md": "# Root\n",
  });
  assert.equal(item(relative, "CLAUDE.md").loadReason, "claude-md-excludes", "positive control: a relative pattern excludes the file");
  assert.equal(relative.warnings.some((warning) => warning.reason === "unsupported-pattern"), false);
});

test("memory: the measurements schema documents the memory fields", () => {
  const schema = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "measurements.schema.json"), "utf8"));
  const context = schema.properties.context;
  assert.deepEqual([...context.required].sort(), ["alwaysLoaded", "ancestors", "imports", "limits"]);
  assert.deepEqual(context.properties.imports.items.properties.status.enum, ["ok", "broken", "external", "too-deep", "cycle", "excluded"]);
  assert.deepEqual(context.properties.limits.items.properties.limit.enum, ["memory-lines", "memory-bytes"]);
  assert.ok(context.properties.ancestors.items.required.includes("bytes"));
  assert.deepEqual(
    schema.properties.inventory.items.required,
    ["path", "kind", "loadMode", "loadReason", "bytes", "lines", "estTokens"],
  );
});

// Removes the meta block from the raw text. In the output, meta is a top-level key, so its block
// ends at the first line that is exactly "  },".
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

// The witness text must appear neither in the measurements nor in any memory text that a later
// measure can read.
function assertNoWitness(result, seen) {
  assert.equal(toStableJson(result).includes(WITNESS), false, "the witness is not in the output");
  assert.equal(JSON.stringify(seen.entries).includes(WITNESS), false, "the witness is not in ctx.memory");
}
