import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createAgentInventoryMeasure } from "../scripts/lib/agent-inventory.mjs";
import { deriveMeasuredOutput } from "../scripts/lib/measured-findings.mjs";
import { createMemoryMeasure } from "../scripts/lib/memory.mjs";
import { referencesMeasure } from "../scripts/lib/references.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const FIXED_NOW = new Date("2026-10-17T12:00:00.000Z");
// The redaction test needs a folder name without spaces: a code span with a space is not one token.
const TEMP_HAS_SPACE = /\s/.test(os.tmpdir());

// Every reference that the broken-refs fixture seeds, and nothing else. Sorted by file, line and text.
const SEEDED_BROKEN = [
  { file: ".claude/rules/tooling.md", line: 6, text: "yarn deploy", kind: "script", reason: "missing-script", script: "deploy" },
  { file: ".claude/rules/tooling.md", line: 7, text: "npm run start", kind: "script", reason: "missing-script", script: "start" },
  { file: ".claude/rules/tooling.md", line: 8, text: "docs/guide.md", kind: "link", reason: "not-found" },
  { file: "AGENTS.md", line: 4, text: "scripts/legacy-lint.sh", kind: "path", reason: "not-found" },
  { file: "AGENTS.md", line: 5, text: "CHANGELOG.md", kind: "link", reason: "not-found" },
  { file: "CLAUDE.md", line: 3, text: "src/parser/parse.mjs", kind: "path", reason: "not-found" },
  { file: "CLAUDE.md", line: 4, text: "docs/design.md", kind: "link", reason: "not-found" },
  { file: "CLAUDE.md", line: 5, text: "npm run deploy", kind: "script", reason: "missing-script", script: "deploy" },
  { file: "CLAUDE.md", line: 6, text: "pnpm release", kind: "script", reason: "missing-script", script: "release" },
  { file: "CLAUDE.md", line: 12, text: "npm run ghost", kind: "script", reason: "missing-script", script: "ghost" },
  { file: "CLAUDE.md", line: 16, text: "npm run build:legacy", kind: "script", reason: "missing-script", script: "build:legacy" },
  { file: "CLAUDE.md", line: 17, text: "assets/diagram.png", kind: "link", reason: "not-found" },
];
const SEEDED_EXTERNAL = [
  { file: "AGENTS.md", line: 3, text: "../shared/conventions.md", kind: "path" },
  { file: "CLAUDE.md", line: 7, text: "/opt/shared/settings.json", kind: "path" },
];

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

// Runs the memory measure, then the references measure. The ancestor walk stops at the fixture's base
// folder and the home folder does not exist, so the real parent folders of the temp folder never count.
function referencesScan(fixture) {
  return scan({
    root: fixture.root,
    measures: [
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      referencesMeasure,
    ],
    now: FIXED_NOW,
  });
}

const referenceWarnings = (result) => result.warnings.filter((warning) => warning.source === "references");

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

// Removes the meta block from the raw text. In the output, meta is a top-level key, so its block ends
// at the first line that is exactly "  },".
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

test("broken-refs: every seeded broken reference is listed with its file, line, text and kind, and nothing else", async (t) => {
  const fixture = copyOf(t, "broken-refs");
  const result = await referencesScan(fixture);

  // Positive control: the memory measure read the rule, the not-loaded AGENTS.md and CLAUDE.md.
  assert.deepEqual(
    result.inventory.map((entry) => [entry.path, entry.loadMode]),
    [
      [".claude/rules/tooling.md", "on-demand"],
      ["AGENTS.md", "not-loaded"],
      ["CLAUDE.md", "always"],
    ],
  );
  assert.deepEqual(result.instructions.brokenRefs, SEEDED_BROKEN);
  assert.deepEqual(result.instructions.externalRefs, SEEDED_EXTERNAL);
  assert.deepEqual(referenceWarnings(result), []);
});

test("minimal-good: healthy references and the negative cases give no finding", async (t) => {
  const fixture = copyOf(t, "minimal-good");
  const result = await referencesScan(fixture);

  assert.deepEqual(result.inventory.map((entry) => entry.path), ["CLAUDE.md"]);
  assert.deepEqual(result.instructions, { brokenRefs: [], externalRefs: [] });
  assert.deepEqual(referenceWarnings(result), []);
});

test("minimal-good: one reference added to the same file is reported, so the empty result is not a blind spot", async (t) => {
  const original = fs.readFileSync(path.join(FIXTURES, "minimal-good", "CLAUDE.md"), "utf8");
  const line = original.split("\n").length;
  const fixture = copyOf(t, "minimal-good", { "CLAUDE.md": `${original}Control: \`docs/gone.md\`.\n` });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "CLAUDE.md", line, text: "docs/gone.md", kind: "path", reason: "not-found" },
  ]);
});

test("fenced blocks: their paths are not checked, their script calls are, and prose is not checked", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": JSON.stringify({ scripts: { lint: "node --check src/index.mjs" } }),
      "src/index.mjs": "export const value = 1;\n",
      "CLAUDE.md": [
        "# Fenced",
        "",
        "~~~bash",
        "cat docs/only-in-fence.md",
        "npm run lint",
        "$ npm run missing-in-fence",
        "~~~",
        "",
        "Outside a block, npm run missing-in-prose is not checked.",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [
      {
        file: "CLAUDE.md",
        line: 6,
        text: "npm run missing-in-fence",
        kind: "script",
        reason: "missing-script",
        script: "missing-in-fence",
      },
    ],
    externalRefs: [],
  });
});

test("shell comments: a # word starts a comment, so nothing after it is a script call", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": JSON.stringify({ scripts: { build: "node --check src/index.mjs" } }),
      "src/index.mjs": "export const value = 1;\n",
      "CLAUDE.md": [
        "~~~sh",
        "yarn # install deps",
        "npm run build # compile",
        "pnpm nope # comment",
        "npm run build # compile; npm run ghost",
        "~~~",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 4, text: "pnpm nope", kind: "script", reason: "missing-script", script: "nope" },
  ]);
});

test("code spans: a #fragment is not part of the file name, and the text is shown as written", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "docs/guide.md": "# Guide\n\n## Intro\n",
      "CLAUDE.md": "Anchor: `docs/guide.md#intro`.\nMissing file: `docs/missing.md#intro`.\n",
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [
      { file: "CLAUDE.md", line: 2, text: "docs/missing.md#intro", kind: "path", reason: "not-found" },
    ],
    externalRefs: [],
  });
});

test("no package.json: every script call is no-package-json, and paths are still checked", async (t) => {
  const fixture = freshFixture(t, {
    files: { "CLAUDE.md": "Run `npm test` and `pnpm lint`.\nSee `docs/none.md`.\n" },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 1, text: "npm test", kind: "script", reason: "no-package-json", script: "test" },
    { file: "CLAUDE.md", line: 1, text: "pnpm lint", kind: "script", reason: "no-package-json", script: "lint" },
    { file: "CLAUDE.md", line: 2, text: "docs/none.md", kind: "path", reason: "not-found" },
  ]);
  assert.deepEqual(referenceWarnings(result), [], "a missing package.json is not a warning");
});

test("an unparseable package.json: no script call is reported, and the file is a warning", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": '{ "scripts": ',
      "CLAUDE.md": "Run `npm test`.\nSee `docs/none.md`.\n",
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 2, text: "docs/none.md", kind: "path", reason: "not-found" },
  ]);
  assert.deepEqual(referenceWarnings(result), [
    { source: "references", path: "package.json", reason: "invalid-package-json", detail: "not-json" },
  ]);
});

const UNUSABLE_PACKAGE_JSON = [
  ["scripts is an array", '{ "scripts": ["test"] }', "scripts-not-object"],
  ["scripts is null", '{ "scripts": null }', "scripts-not-object"],
  ["the file is an array", "[]", "not-object"],
  ["the file is null", "null", "not-object"],
];

for (const [name, content, detail] of UNUSABLE_PACKAGE_JSON) {
  test(`an unusable package.json (${name}): no script call is reported, and the file is a warning`, async (t) => {
    const fixture = freshFixture(t, { files: { "package.json": content, "CLAUDE.md": "Run `npm test`.\n" } });
    const result = await referencesScan(fixture);

    assert.deepEqual(result.instructions.brokenRefs, []);
    assert.deepEqual(referenceWarnings(result), [
      { source: "references", path: "package.json", reason: "invalid-package-json", detail },
    ]);
  });
}

test("a package.json that is a folder: no script call is reported, and the file is a warning", async (t) => {
  const fixture = freshFixture(t, {
    files: { "package.json/inner.txt": "not a manifest\n", "CLAUDE.md": "Run `npm test`.\n" },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, []);
  assert.deepEqual(referenceWarnings(result), [
    { source: "references", path: "package.json", reason: "unreadable-package-json" },
  ]);
});

test("a package.json without scripts: every script call is missing-script, and nothing is a warning", async (t) => {
  const fixture = freshFixture(t, {
    files: { "package.json": '{ "name": "bare" }\n', "CLAUDE.md": "Run `npm test`.\n" },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 1, text: "npm test", kind: "script", reason: "missing-script", script: "test" },
  ]);
  assert.deepEqual(referenceWarnings(result), []);
});

test("a relative path that leaves the target is external: not broken, and not stat-ed", async (t) => {
  const fixture = freshFixture(t, {
    files: { "CLAUDE.md": "Shared: `../shared/config.json` and [up](../README.md).\n" },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [],
    externalRefs: [
      { file: "CLAUDE.md", line: 1, text: "../README.md", kind: "link" },
      { file: "CLAUDE.md", line: 1, text: "../shared/config.json", kind: "path" },
    ],
  });
  // The fixture is not a git repository, so the file list warns about that; nothing else may warn.
  assert.deepEqual(
    result.warnings.filter((warning) => warning.source === "fs" || warning.source === "references"),
    [],
    "the reference is not read, so no file-system warning is recorded",
  );
});

test("absolute, home and drive paths are external, and their text is kept as written", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "CLAUDE.md": [
        "Home: `~/notes/todo.md`, settings `C:\\Users\\example\\settings.json`.",
        "Share: `\\\\server\\share\\doc.md`.",
        "Drive: [drive](C:/Users/example/guide.md).",
        "Not paths: `//cdn.example.com/lib.js`, `/`, and `\\n`.",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [],
    externalRefs: [
      { file: "CLAUDE.md", line: 1, text: "C:\\Users\\example\\settings.json", kind: "path" },
      { file: "CLAUDE.md", line: 1, text: "~/notes/todo.md", kind: "path" },
      { file: "CLAUDE.md", line: 2, text: "\\\\server\\share\\doc.md", kind: "path" },
      { file: "CLAUDE.md", line: 3, text: "C:/Users/example/guide.md", kind: "link" },
    ],
  });
});

test("an absolute path inside the target is external, and its text shows <target> instead of the folder", { skip: TEMP_HAS_SPACE ? "the temporary folder has a space" : false }, async (t) => {
  const fixture = freshFixture(t);
  const inside = path.join(fixture.root, "src", "index.mjs");
  fs.writeFileSync(path.join(fixture.root, "CLAUDE.md"), `Config: \`${inside}\`.\n`);
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.externalRefs, [
    { file: "CLAUDE.md", line: 1, text: path.join("<target>", "src", "index.mjs"), kind: "path" },
  ]);
  const body = JSON.stringify(result.instructions);
  for (const folder of [fixture.root, fs.realpathSync.native(fixture.root)]) {
    assert.equal(body.includes(JSON.stringify(folder).slice(1, -1)), false, "no absolute path of this machine");
  }
});

test("links: titles, angle brackets, anchors, images and code inside link text are read as written", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "docs/guide.md": "# Guide\n",
      "CLAUDE.md": [
        '[titled](docs/guide.md "The guide")',
        "[angled](<docs/guide.md>)",
        "[anchored](docs/guide.md#usage)",
        "[missing](docs/missing.md#frag)",
        "[local](#usage) and [web](https://example.com/a.md)",
        "![picture](docs/picture.png)",
        "[code `docs/guide.md` inside](docs/guide.md)",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [
      { file: "CLAUDE.md", line: 4, text: "docs/missing.md#frag", kind: "link", reason: "not-found" },
      { file: "CLAUDE.md", line: 6, text: "docs/picture.png", kind: "link", reason: "not-found" },
    ],
    externalRefs: [],
  });
});

test("code spans: a single token is checked with its line suffix and outer spaces removed; a phrase is not a path", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "docs/guide.md": "# Guide\n",
      "CLAUDE.md": [
        "Spaces: `  docs/guide.md  `, lines: `docs/guide.md:3` and `docs/guide.md:3:7`.",
        "Phrases such as `docs/absent.md and more` are not paths, but `docs/absent.md` is.",
        "A bare name `guide.md` is checked too, and `.md` alone is not.",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [
      { file: "CLAUDE.md", line: 2, text: "docs/absent.md", kind: "path", reason: "not-found" },
      { file: "CLAUDE.md", line: 3, text: "guide.md", kind: "path", reason: "not-found" },
    ],
    externalRefs: [],
  });
});

test("code spans: a path is looked for from the root and from the folder of the memory file", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "docs/guide.md": "# Guide\n",
      ".claude/rules/notes.md": [
        "From the root: `docs/guide.md`. From this folder: `../../docs/guide.md`.",
        "Neither place: `nowhere/else.md`.",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions, {
    brokenRefs: [
      { file: ".claude/rules/notes.md", line: 2, text: "nowhere/else.md", kind: "path", reason: "not-found" },
    ],
    externalRefs: [],
  });
});

test("commands: pnpm and yarn built-ins, flags and bun or npm forms are handled as the rules say", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": JSON.stringify({ scripts: { test: "node --test", lint: "node --check x.mjs" } }),
      "CLAUDE.md": [
        "Not script calls: `pnpm install`, `pnpm -r test`, `yarn add left-pad`, `bun test`, `npm run -- lint`.",
        "Checked and present: `yarn run lint`, `bun run lint`, `pnpm lint`, `yarn test`, `npm test -- --watch`.",
        "Checked and missing: `pnpm build`, `npm run constructor`, `yarn run deploy.`.",
        "",
      ].join("\n"),
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 3, text: "npm run constructor", kind: "script", reason: "missing-script", script: "constructor" },
    { file: "CLAUDE.md", line: 3, text: "pnpm build", kind: "script", reason: "missing-script", script: "build" },
    { file: "CLAUDE.md", line: 3, text: "yarn run deploy.", kind: "script", reason: "missing-script", script: "deploy" },
  ]);
});

test("commands: several calls on one line are each checked", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": JSON.stringify({ scripts: { lint: "node --check x.mjs" } }),
      "CLAUDE.md": "Run `npm run lint && npm run ghost; npm run lint || npm run spooky | npm run wraith`.\n",
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs.map((entry) => [entry.text, entry.script]), [
    ["npm run ghost", "ghost"],
    ["npm run spooky", "spooky"],
    ["npm run wraith", "wraith"],
  ]);
});

test("rules and AGENTS.md are scanned in the same way as CLAUDE.md, and their references keep their own file", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "package.json": JSON.stringify({ scripts: { test: "node --test" } }),
      "CLAUDE.md": "Start here.\n",
      "AGENTS.md": "Read `docs/notes.md`.\n",
      ".claude/rules/style.md": "Use `npm run format`.\n",
    },
  });
  const result = await referencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: ".claude/rules/style.md", line: 1, text: "npm run format", kind: "script", reason: "missing-script", script: "format" },
    { file: "AGENTS.md", line: 1, text: "docs/notes.md", kind: "path", reason: "not-found" },
  ]);
});

test("two CLI runs on a copy of broken-refs give the same JSON, except meta", async (t) => {
  const fixture = copyOf(t, "broken-refs");
  const first = path.join(fixture.base, "first");
  const second = path.join(fixture.base, "second");
  assert.equal((await runScan([fixture.root, "--out", first])).code, 0);
  assert.equal((await runScan([fixture.root, "--out", second])).code, 0);

  const rawFirst = fs.readFileSync(path.join(first, "measurements.json"), "utf8");
  const rawSecond = fs.readFileSync(path.join(second, "measurements.json"), "utf8");
  const dataFirst = JSON.parse(rawFirst);
  const dataSecond = JSON.parse(rawSecond);
  assert.deepEqual(dataFirst.instructions.brokenRefs, SEEDED_BROKEN);
  assert.deepEqual(dataFirst.instructions.externalRefs, SEEDED_EXTERNAL);
  delete dataFirst.meta;
  delete dataSecond.meta;
  assert.deepEqual(dataFirst, dataSecond);
  assert.equal(withoutMetaText(rawFirst), withoutMetaText(rawSecond));
  assert.equal(
    withoutMetaText(rawFirst).includes(JSON.stringify(fixture.root).slice(1, -1)),
    false,
    "no absolute path of this machine outside meta",
  );
});

// The memory measure, the agent-inventory measure and the references measure, with the measured findings derived.
function agentReferencesScan(fixture) {
  return scan({
    root: fixture.root,
    measures: [
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      createAgentInventoryMeasure(),
      referencesMeasure,
    ],
    derive: deriveMeasuredOutput,
    now: FIXED_NOW,
  });
}

test("other agents' instruction files: a broken reference in .cursorrules and GEMINI.md is reported and gives a RUL-04 finding; a valid reference there is not (positive control)", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/index.mjs": "export {};\n",
      ".cursorrules": "Keep the entry in `src/index.mjs`.\nSee `docs/cursor-guide.md` for the rules.\n",
      "GEMINI.md": "Read `docs/gemini-style.md` first.\nEntry: `src/index.mjs`.\n",
    },
  });
  const result = await agentReferencesScan(fixture);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: ".cursorrules", line: 2, text: "docs/cursor-guide.md", kind: "path", reason: "not-found" },
    { file: "GEMINI.md", line: 1, text: "docs/gemini-style.md", kind: "path", reason: "not-found" },
  ]);
  const findings = result.measuredFindings.filter((finding) => finding.rule === "RUL-04");
  assert.deepEqual(
    findings.map((finding) => [finding.measurementRef, finding.evidence]),
    [
      ["/instructions/brokenRefs/0", [{ file: ".cursorrules", line: 2 }]],
      ["/instructions/brokenRefs/1", [{ file: "GEMINI.md", line: 1 }]],
    ],
  );
  // Without the agent-inventory measure, nothing reads those files, so nothing is reported (the channel is what carries them).
  const withoutAgents = await referencesScan(fixture);
  assert.deepEqual(withoutAgents.instructions.brokenRefs, []);
});

// Runs the memory measure, then the references measure, with a scope (see scope.mjs). The ancestor walk and the home folder
// are as in referencesScan.
function scopedReferencesScan(fixture, scope) {
  return scan({
    root: fixture.root,
    measures: [
      createMemoryMeasure({ ancestorLimit: fixture.base, home: path.join(fixture.base, "no-home") }),
      referencesMeasure,
    ],
    now: FIXED_NOW,
    scope,
  });
}

const packageJsonText = (fields) => `${JSON.stringify(fields)}\n`;

// A monorepo: the root package.json has test, the web app has lint, and the memory files name the scripts. The root CLAUDE.md
// names lint too, but a root file keeps the root scripts only.
const LAYERED = {
  "package.json": packageJsonText({ scripts: { test: "node --test" } }),
  "CLAUDE.md": "Run `npm run test`, and `npm run lint` for the web app.\n",
  "apps/web/package.json": packageJsonText({ name: "web", scripts: { lint: "eslint ." } }),
  "apps/web/CLAUDE.md": "Run `npm run lint`.\nAlso `npm run ghost`.\n",
  "apps/web/src/AGENTS.md": "Test with `npm test` and lint with `npm run lint`.\n",
};

test("scoped references: a script of the scope's own package.json is known to its files, and a script that exists nowhere is broken", async (t) => {
  const fixture = freshFixture(t, { files: LAYERED });
  const scoped = await scopedReferencesScan(fixture, ["apps/web"]);

  assert.deepEqual(scoped.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 1, text: "npm run lint", kind: "script", reason: "missing-script", script: "lint" },
    { file: "apps/web/CLAUDE.md", line: 2, text: "npm run ghost", kind: "script", reason: "missing-script", script: "ghost" },
  ]);
  // Positive control: without a scope the subfolder files are not read, so only the root file is checked, against the root scripts.
  const plain = await referencesScan(fixture);
  assert.deepEqual(plain.instructions.brokenRefs, [
    { file: "CLAUDE.md", line: 1, text: "npm run lint", kind: "script", reason: "missing-script", script: "lint" },
  ]);
});

test("scoped references: a file below the scope is judged by the folders above its harness folder, up to the root", async (t) => {
  const fixture = freshFixture(t, { files: LAYERED });
  const scoped = await scopedReferencesScan(fixture, ["apps/web"]);

  // apps/web/src/AGENTS.md names test (the root) and lint (apps/web): both are known to it, so it adds no entry.
  assert.equal(scoped.instructions.brokenRefs.some((entry) => entry.file === "apps/web/src/AGENTS.md"), false);
  // Positive control: the same file with a script that nothing defines is reported.
  const control = freshFixture(t, { files: { ...LAYERED, "apps/web/src/AGENTS.md": "Run `npm run deploy`.\n" } });
  const reported = await scopedReferencesScan(control, ["apps/web"]);
  assert.deepEqual(
    reported.instructions.brokenRefs.filter((entry) => entry.file === "apps/web/src/AGENTS.md"),
    [{ file: "apps/web/src/AGENTS.md", line: 1, text: "npm run deploy", kind: "script", reason: "missing-script", script: "deploy" }],
  );
});

test("scoped references: a missing package.json adds nothing, and an invalid one gives no answer and no warning", async (t) => {
  const invalid = freshFixture(t, {
    files: {
      "package.json": packageJsonText({ scripts: { test: "node --test" } }),
      "apps/web/package.json": '{ "scripts": ',
      "apps/web/CLAUDE.md": "Run `npm run lint`.\nAlso `npm run ghost`.\n",
    },
  });
  const result = await scopedReferencesScan(invalid, ["apps/web"]);

  assert.deepEqual(result.instructions.brokenRefs, [], "the invalid file may define lint and ghost, so neither is reported");
  assert.deepEqual(referenceWarnings(result), [], "a package.json below the root is never a warning of this measure");
  // Positive control: the same folder with a valid package.json that does not define ghost reports it, and lint is still known.
  const valid = freshFixture(t, {
    files: {
      "package.json": packageJsonText({ scripts: { test: "node --test" } }),
      "apps/web/package.json": packageJsonText({ scripts: { lint: "eslint ." } }),
      "apps/web/CLAUDE.md": "Run `npm run lint`.\nAlso `npm run ghost`.\n",
    },
  });
  const validResult = await scopedReferencesScan(valid, ["apps/web"]);
  assert.deepEqual(validResult.instructions.brokenRefs, [
    { file: "apps/web/CLAUDE.md", line: 2, text: "npm run ghost", kind: "script", reason: "missing-script", script: "ghost" },
  ]);
});

test("scoped references: when no folder above a file has a package.json, its script calls are no-package-json", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "apps/api/CLAUDE.md": "Run `npm test`.\n",
      "apps/web/package.json": packageJsonText({ scripts: { lint: "eslint ." } }),
      "apps/web/CLAUDE.md": "Run `npm run lint`, then `npm run test`.\n",
    },
  });
  const result = await scopedReferencesScan(fixture, ["apps"]);

  assert.deepEqual(result.instructions.brokenRefs, [
    { file: "apps/api/CLAUDE.md", line: 1, text: "npm test", kind: "script", reason: "no-package-json", script: "test" },
    { file: "apps/web/CLAUDE.md", line: 1, text: "npm run test", kind: "script", reason: "missing-script", script: "test" },
  ]);
});
