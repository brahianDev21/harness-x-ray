import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  CODE_EXTENSIONS,
  MEASURE_ID,
  MAX_GROUPS,
  createDuplicationMeasure,
  duplicationMeasure,
  isTestPath,
  normalizeLines,
} from "../scripts/lib/duplication.mjs";
import { generatedPatternOf } from "../scripts/lib/structure.mjs";
import { scan } from "../scripts/lib/scanner.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "measurements.schema.json");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const FIXED_NOW = new Date("2026-10-18T12:00:00.000Z");

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

// A new fixture in a temp folder, removed when the test ends.
function freshFixture(t, description = {}) {
  const fixture = makeFixture(description);
  t.after(fixture.cleanup);
  return fixture;
}

// A copy of a versioned fixture in a temp folder, with files written on top of the copy.
function copyOf(t, name, description = {}) {
  const fixture = makeFixture({ ...description, fromDir: path.join(FIXTURES, name) });
  t.after(fixture.cleanup);
  return fixture;
}

// Runs only the duplication measure and returns its section and the warnings that it wrote. A scope is optional.
async function scanDuplication(root, options, scope) {
  const result = await scan({ root, measures: [createDuplicationMeasure(options)], now: FIXED_NOW, scope });
  return { section: result.code.duplication, warnings: ownWarnings(result) };
}

// The warnings written by the duplication measure, without the file-list ones of the core.
const ownWarnings = (result) => result.warnings.filter((warning) => warning.source === MEASURE_ID);

// The same measure, with every read of ctx.readText recorded. Reads are the only way the measure sees the target.
function recordingReads(options, reads) {
  const measure = createDuplicationMeasure(options);
  return Object.freeze({
    id: measure.id,
    collect: (ctx) =>
      measure.collect({
        ...ctx,
        readText(rel, readOptions) {
          reads.push(rel);
          return ctx.readText(rel, readOptions);
        },
      }),
  });
}

// A comment line of exactly `size` bytes, with its newline. A comment has no normalized line, so this file is only a
// candidate for the byte caps.
const commentOfSize = (size) => `// ${"a".repeat(size - 4)}\n`;

// Removes the meta block from the raw text. In the output, meta is a top-level key, so its block ends at the first line
// that is exactly "  },".
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

// Negative when copy a comes before copy b: by file, then by the first line.
function compareCopies(a, b) {
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return a.line - b.line;
}

// The seeded fixture (see test/fixtures/duplicated): main numbers are over five files, test numbers over two.
const DUPLICATED_MAIN = {
  filesScanned: 5,
  linesScanned: 80,
  redundantLines: 26,
  duplicatedLinesPct: 32.5,
  groupCount: 2,
  groups: [
    {
      lines: 9,
      redundantLines: 18,
      copies: [
        { file: "src/checkout/receipt.js", line: 7, endLine: 19 },
        { file: "src/checkout/totals.js", line: 5, endLine: 14 },
        { file: "src/reports/export.js", line: 4, endLine: 13 },
      ],
    },
    {
      lines: 8,
      redundantLines: 8,
      copies: [
        { file: "src/checkout/totals.js", line: 18, endLine: 25 },
        { file: "src/checkout/totals.js", line: 30, endLine: 39 },
      ],
    },
  ],
};

const DUPLICATED_TESTS = {
  filesScanned: 2,
  linesScanned: 20,
  redundantLines: 9,
  duplicatedLinesPct: 45,
  groupCount: 1,
  groups: [
    {
      lines: 9,
      redundantLines: 9,
      copies: [
        { file: "tests/checkout.helpers.js", line: 5, endLine: 13 },
        { file: "tests/checkout.more.js", line: 5, endLine: 13 },
      ],
    },
  ],
};

test("duplicated: the seeded groups have the right original line numbers, redundant lines and percentage", async (t) => {
  const fixture = copyOf(t, "duplicated", { git: true });
  const { section, warnings } = await scanDuplication(fixture.root);

  assert.deepEqual(warnings, []);
  assert.equal(section.windowLines, 8);
  assert.deepEqual(section, { windowLines: 8, ...DUPLICATED_MAIN, inTests: DUPLICATED_TESTS });
});

test("duplicated: the short block and the file with the instruction comment are in no group", async (t) => {
  const fixture = copyOf(t, "duplicated", { git: true });
  const { section } = await scanDuplication(fixture.root);

  // notes.js and format.js share a block of seven normalized lines, which is below the window length.
  const files = [...section.groups, ...section.inTests.groups].flatMap((group) => group.copies.map((copy) => copy.file));
  assert.equal(files.includes("src/checkout/notes.js"), false);
  assert.equal(files.includes("src/util/format.js"), false);
  // The test copies of the helper are only in the test numbers.
  assert.equal(section.groups.some((group) => group.copies.some((copy) => copy.file.startsWith("tests/"))), false);
});

test("minimal-good: repeated braces and short repeated lines give no group", async (t) => {
  const shortLines = ["const ok = true;", "if (!ok) {", "return null;", "}", "return ok;"].join("\n");
  const fixture = copyOf(t, "minimal-good", {
    git: true,
    files: {
      "src/alpha.mjs": `${shortLines}\n`,
      "src/beta.mjs": `export function beta() {\n${shortLines}\n}\n`,
      "src/gamma.mjs": `{\n}\n});\n${shortLines}\n`,
      "src/braces.mjs": `${"}\n});\n{\n".repeat(10)}`,
    },
  });
  const { section, warnings } = await scanDuplication(fixture.root);

  assert.deepEqual(warnings, []);
  assert.equal(section.filesScanned, 5, "src/index.mjs and the four files above");
  assert.deepEqual(section.groups, []);
  assert.equal(section.groupCount, 0);
  assert.equal(section.redundantLines, 0);
  assert.equal(section.duplicatedLinesPct, 0);
  assert.deepEqual(section.inTests, { filesScanned: 0, linesScanned: 0, redundantLines: 0, duplicatedLinesPct: 0, groupCount: 0, groups: [] });
});

test("test copies go to inTests and leave the main numbers unchanged", async (t) => {
  const withTests = copyOf(t, "duplicated");
  const withoutTests = copyOf(t, "duplicated");
  fs.rmSync(path.join(withoutTests.root, "tests"), { recursive: true, force: true });

  const both = (await scanDuplication(withTests.root)).section;
  const mainOnly = (await scanDuplication(withoutTests.root)).section;

  const { inTests: testsInBoth, ...mainInBoth } = both;
  const { inTests: testsAlone, ...mainAlone } = mainOnly;
  assert.deepEqual(mainInBoth, mainAlone, "the main numbers do not change when the test copies are added");
  assert.equal(testsInBoth.groupCount, 1);
  assert.deepEqual(testsAlone, { filesScanned: 0, linesScanned: 0, redundantLines: 0, duplicatedLinesPct: 0, groupCount: 0, groups: [] });
});

test("a block of seven normalized lines is not reported, and a block of eight is", async (t) => {
  const seven = ["const a1 = input.alpha();", "const a2 = input.beta();", "const a3 = input.gamma();", "const a4 = input.delta();", "const a5 = input.epsilon();", "const a6 = input.zeta();", "const a7 = input.eta();"];
  const eight = [...seven, "const a8 = input.theta();"];
  const fixture = freshFixture(t, {
    files: {
      "src/one.js": `export function one(input) {\n${seven.join("\n")}\n  return a1;\n}\n`,
      "src/two.js": `export function two(input) {\n${seven.join("\n")}\n  return a7;\n}\n`,
      "src/three.js": `export function three(input) {\n${eight.join("\n")}\n  return a1;\n}\n`,
      "src/four.js": `export function four(input) {\n${eight.join("\n")}\n  return a8;\n}\n`,
    },
  });
  const { section } = await scanDuplication(fixture.root);

  assert.deepEqual(
    section.groups.map((group) => [group.lines, group.copies.map((copy) => copy.file)]),
    [[8, ["src/four.js", "src/three.js"]]],
  );
});

test("repeated lines in one file: an overlap is not a copy of itself, and two separate repeats are", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      // Twelve identical lines: every window overlaps the first one, so nothing is reported.
      "src/short-repeat.js": `${"count += 1;\n".repeat(12)}`,
      // Sixteen identical lines: lines 1-8 and 9-16 are two copies that do not overlap, so they are reported.
      "src/long-repeat.js": `${"total += 1;\n".repeat(16)}`,
    },
  });
  const { section } = await scanDuplication(fixture.root);

  assert.equal(section.filesScanned, 2);
  assert.equal(section.linesScanned, 28);
  assert.deepEqual(section.groups, [
    {
      lines: 8,
      redundantLines: 8,
      copies: [
        { file: "src/long-repeat.js", line: 1, endLine: 8 },
        { file: "src/long-repeat.js", line: 9, endLine: 16 },
      ],
    },
  ]);
  assert.equal(section.redundantLines, 8);
  assert.equal(section.duplicatedLinesPct, 28.57);
});

// Distinct statements, so that no two lines of a test file are equal by accident.
const statements = (count, prefix) => Array.from({ length: count }, (_, i) => `const ${prefix}${i} = step${prefix}${i}(value);`);

test("a ten-line block in three files and an eight-line part of it in a fourth: both groups are listed, with copies that do not overlap", async (t) => {
  const block = statements(10, "t");
  const unique = (prefix) => Array.from({ length: 3 }, (_, i) => `const ${prefix}${i} = other${prefix}${i}(value);`);
  const fixture = freshFixture(t, {
    files: {
      "src/a.js": `${block.join("\n")}\n`,
      "src/b.js": `${block.join("\n")}\n`,
      "src/c.js": `${block.join("\n")}\n`,
      "src/d.js": `${[...unique("u"), ...block.slice(2, 10), ...unique("v")].join("\n")}\n`,
    },
  });
  const { section } = await scanDuplication(fixture.root);

  assert.deepEqual(section.groups, [
    {
      lines: 8,
      redundantLines: 24,
      copies: [
        { file: "src/a.js", line: 3, endLine: 10 },
        { file: "src/b.js", line: 3, endLine: 10 },
        { file: "src/c.js", line: 3, endLine: 10 },
        { file: "src/d.js", line: 4, endLine: 11 },
      ],
    },
    {
      lines: 10,
      redundantLines: 20,
      copies: [
        { file: "src/a.js", line: 1, endLine: 10 },
        { file: "src/b.js", line: 1, endLine: 10 },
        { file: "src/c.js", line: 1, endLine: 10 },
      ],
    },
  ]);
  assert.equal(section.groupCount, 2);
  assert.equal(section.linesScanned, 44);
  assert.equal(section.redundantLines, 28, "B and C lines 1-10 and D lines 4-11, each counted once");
  assert.equal(section.duplicatedLinesPct, 63.64);
});

test("two files identical over forty lines, and an eight-line window of them also in a third file: a two-copy group and a three-copy group", async (t) => {
  const long = statements(40, "x");
  const fixture = freshFixture(t, {
    files: {
      "src/p.js": `${long.join("\n")}\n`,
      "src/q.js": `${long.join("\n")}\n`,
      "src/r.js": `${["const r0 = seed();", ...long.slice(16, 24), "const r1 = done();"].join("\n")}\n`,
    },
  });
  const { section } = await scanDuplication(fixture.root);

  assert.deepEqual(section.groups, [
    {
      lines: 40,
      redundantLines: 40,
      copies: [
        { file: "src/p.js", line: 1, endLine: 40 },
        { file: "src/q.js", line: 1, endLine: 40 },
      ],
    },
    {
      lines: 8,
      redundantLines: 16,
      copies: [
        { file: "src/p.js", line: 17, endLine: 24 },
        { file: "src/q.js", line: 17, endLine: 24 },
        { file: "src/r.js", line: 2, endLine: 9 },
      ],
    },
  ]);
  assert.equal(section.groupCount, 2);
  assert.equal(section.linesScanned, 90);
  assert.equal(section.redundantLines, 48);
  assert.equal(section.duplicatedLinesPct, 53.33);
});

test("eight distinct lines repeated five times in one file: one group of five copies that do not overlap, and the rotations are not listed", async (t) => {
  const cycle = statements(8, "c");
  const fixture = freshFixture(t, { files: { "src/cycle.js": `${Array.from({ length: 5 }, () => cycle).flat().join("\n")}\n` } });
  const { section } = await scanDuplication(fixture.root);

  assert.equal(section.groupCount, 1);
  assert.deepEqual(section.groups, [
    {
      lines: 8,
      redundantLines: 32,
      copies: [
        { file: "src/cycle.js", line: 1, endLine: 8 },
        { file: "src/cycle.js", line: 9, endLine: 16 },
        { file: "src/cycle.js", line: 17, endLine: 24 },
        { file: "src/cycle.js", line: 25, endLine: 32 },
        { file: "src/cycle.js", line: 33, endLine: 40 },
      ],
    },
  ]);
  assert.equal(section.redundantLines, 32);
  assert.equal(section.duplicatedLinesPct, 80);
});

// The measure alone, timed. The bound is generous: these cases took seconds or minutes before the keys were processed once.
async function timedDuplication(root) {
  const started = performance.now();
  const { section } = await scanDuplication(root);
  return { section, elapsed: performance.now() - started };
}

test("performance: one eight-line block repeated 500 times in each of 16 files, with a separator line, finishes in under five seconds", async (t) => {
  const block = statements(8, "b");
  const repeated = Array.from({ length: 500 }, () => [...block, "const separator = true;"]).flat();
  const files = {};
  for (let f = 0; f < 16; f += 1) files[`src/file-${String(f).padStart(2, "0")}.js`] = `${repeated.join("\n")}\n`;
  const fixture = freshFixture(t, { files });
  const { section, elapsed } = await timedDuplication(fixture.root);

  assert.ok(elapsed < 5000, `took ${Math.round(elapsed)} ms`);
  assert.equal(section.groupCount, 1);
  assert.equal(section.groups[0].lines, 9);
  assert.equal(section.groups[0].copies.length, 8000);
  assert.equal(section.linesScanned, 72000);
  assert.equal(section.redundantLines, 71991);
  assert.equal(section.duplicatedLinesPct, 99.99);
});

test("performance: one eight-line block repeated 500 times in a row in each of 16 files finishes in under five seconds", async (t) => {
  const block = statements(8, "r");
  const repeated = Array.from({ length: 500 }, () => block).flat();
  const files = {};
  for (let f = 0; f < 16; f += 1) files[`src/file-${String(f).padStart(2, "0")}.js`] = `${repeated.join("\n")}\n`;
  const fixture = freshFixture(t, { files });
  const { section, elapsed } = await timedDuplication(fixture.root);

  assert.ok(elapsed < 5000, `took ${Math.round(elapsed)} ms`);
  assert.equal(section.groupCount, 1);
  assert.equal(section.groups[0].lines, 8);
  assert.equal(section.groups[0].copies.length, 8000);
  assert.equal(section.redundantLines, 63992);
  assert.equal(section.duplicatedLinesPct, 99.99);
});

test("performance: a 100-line boilerplate in 1000 files finishes in under five seconds, as one group", async (t) => {
  const boilerplate = statements(100, "line").join("\n");
  const files = {};
  for (let f = 0; f < 1000; f += 1) files[`src/pkg-${String(f).padStart(4, "0")}.js`] = `${boilerplate}\n`;
  const fixture = freshFixture(t, { files });
  const { section, elapsed } = await timedDuplication(fixture.root);

  assert.ok(elapsed < 5000, `took ${Math.round(elapsed)} ms`);
  assert.equal(section.groupCount, 1);
  assert.equal(section.groups[0].lines, 100);
  assert.equal(section.groups[0].copies.length, 1000);
  assert.equal(section.redundantLines, 99900);
  assert.equal(section.duplicatedLinesPct, 99.9);
});

test("scope: only the files inside the scope are read and measured, so a copy outside the scope is not seen", async (t) => {
  const block = statements(10, "s");
  const fixture = freshFixture(t, {
    files: {
      "apps/web/src/a.js": `${block.join("\n")}\n`,
      "apps/web/src/b.js": `${block.join("\n")}\n`,
      "apps/api/src/c.js": `${block.join("\n")}\n`,
      "apps/api/src/d.js": `${block.join("\n")}\n`,
    },
  });
  const { section, warnings } = await scanDuplication(fixture.root, undefined, ["apps/web"]);

  assert.equal(section.filesScanned, 2);
  assert.equal(section.linesScanned, 20);
  assert.deepEqual(section.groups, [
    {
      lines: 10,
      redundantLines: 10,
      copies: [
        { file: "apps/web/src/a.js", line: 1, endLine: 10 },
        { file: "apps/web/src/b.js", line: 1, endLine: 10 },
      ],
    },
  ]);
  assert.equal(section.duplicatedLinesPct, 50, "the share is over the files inside the scope");
  assert.deepEqual(warnings, []);
});

test("scope: positive control, the same four files without a scope give one group of four copies and a share of 75", async (t) => {
  const block = statements(10, "s");
  const fixture = freshFixture(t, {
    files: {
      "apps/web/src/a.js": `${block.join("\n")}\n`,
      "apps/web/src/b.js": `${block.join("\n")}\n`,
      "apps/api/src/c.js": `${block.join("\n")}\n`,
      "apps/api/src/d.js": `${block.join("\n")}\n`,
    },
  });
  const { section } = await scanDuplication(fixture.root);

  assert.equal(section.filesScanned, 4);
  assert.equal(section.groupCount, 1);
  assert.deepEqual(
    section.groups[0].copies.map((copy) => copy.file),
    ["apps/api/src/c.js", "apps/api/src/d.js", "apps/web/src/a.js", "apps/web/src/b.js"],
  );
  assert.equal(section.duplicatedLinesPct, 75);
});

test("scope: the scope filter runs before the caps, so files outside the scope are neither read nor counted as cut", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "apps/web/src/a.js": "export const a = 1;\n",
      "apps/web/src/b.js": "export const b = 2;\n",
      "apps/api/src/c.js": "export const c = 3;\n",
      "apps/api/src/d.js": "export const d = 4;\n",
    },
  });
  const reads = [];
  const result = await scan({
    root: fixture.root,
    measures: [recordingReads({ maxFiles: 2 }, reads)],
    now: FIXED_NOW,
    scope: ["apps/web"],
  });

  assert.deepEqual(reads, ["apps/web/src/a.js", "apps/web/src/b.js"]);
  assert.equal(result.code.duplication.filesScanned, 2);
  assert.deepEqual(ownWarnings(result), [], "the two files outside the scope are not a cut");

  // Positive control: the same target without a scope cuts the two files beyond the cap.
  const unscoped = await scan({ root: fixture.root, measures: [createDuplicationMeasure({ maxFiles: 2 })], now: FIXED_NOW });
  assert.deepEqual(ownWarnings(unscoped), [{ source: MEASURE_ID, path: ".", reason: "code-files-cut", detail: "count=2" }]);
});

test("generated, vendored and non-code files are never read", async (t) => {
  const shared = "export function shared(value) {\n  const doubled = value * 2;\n  const tripled = value * 3;\n  const sum = doubled + tripled;\n  const half = sum / 2;\n  const square = value * value;\n  const cube = square * value;\n  return { doubled, tripled, sum, half, square, cube };\n}\n";
  const fixture = freshFixture(t, {
    git: true,
    files: {
      "src/real.js": shared.replace("shared", "real"),
      "dist/bundle.js": shared,
      "build/out.js": shared,
      "vendor/lib.js": shared,
      "node_modules/pkg/index.js": shared,
      "src/app.min.js": shared,
      "src/types.pb.go": shared,
      "docs/guide.md": shared,
      "config/data.json": shared,
    },
  });
  const reads = [];
  const result = await scan({ root: fixture.root, measures: [recordingReads({}, reads)], now: FIXED_NOW });

  assert.deepEqual(reads, ["src/real.js"]);
  assert.equal(result.code.duplication.filesScanned, 1);
  assert.deepEqual(result.code.duplication.groups, []);
});

test("caps: a file above the byte limit is skipped before it is read", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/small.js": "export const small = 1;\n",
      "src/big.js": commentOfSize(400),
    },
  });
  const reads = [];
  const result = await scan({
    root: fixture.root,
    measures: [recordingReads({ maxFileBytes: 200 }, reads)],
    now: FIXED_NOW,
  });

  assert.deepEqual(reads, ["src/small.js"]);
  assert.equal(result.code.duplication.filesScanned, 1);
  assert.deepEqual(ownWarnings(result), [{ source: MEASURE_ID, path: "src/big.js", reason: "code-file-too-large" }]);
});

test("caps: a file with a line over the minified limit is skipped, and a minified name is never read", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/bundle-line.js": `const data = "${"x".repeat(200)}";\n`,
      "src/plain.js": "export const plain = 2;\n",
      "src/vendor-min.js": "export const other = 3;\n",
    },
  });
  const reads = [];
  const result = await scan({
    root: fixture.root,
    measures: [recordingReads({ minifiedLineChars: 120 }, reads)],
    now: FIXED_NOW,
  });

  assert.equal(result.code.duplication.filesScanned, 1);
  assert.equal(reads.includes("src/vendor-min.js"), false, "a name that looks minified is not read");
  assert.deepEqual(ownWarnings(result), [
    { source: MEASURE_ID, path: "src/bundle-line.js", reason: "code-file-minified" },
    { source: MEASURE_ID, path: "src/vendor-min.js", reason: "code-file-minified" },
  ]);
});

test("caps: files beyond the file limit are skipped and counted in one warning", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/a.js": "export const a = 1;\n",
      "src/b.js": "export const b = 2;\n",
      "src/c.js": "export const c = 3;\n",
      "src/d.js": "export const d = 4;\n",
    },
  });
  const reads = [];
  const result = await scan({
    root: fixture.root,
    measures: [recordingReads({ maxFiles: 2 }, reads)],
    now: FIXED_NOW,
  });

  assert.deepEqual(reads, ["src/a.js", "src/b.js"]);
  assert.equal(result.code.duplication.filesScanned, 2);
  assert.deepEqual(ownWarnings(result), [{ source: MEASURE_ID, path: ".", reason: "code-files-cut", detail: "count=2" }]);
});

test("caps: a file that would pass the total byte limit is skipped, and a smaller one after it still fits", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/a.js": commentOfSize(60),
      "src/b.js": commentOfSize(60),
      "src/c.js": commentOfSize(30),
    },
  });
  const reads = [];
  const result = await scan({
    root: fixture.root,
    measures: [recordingReads({ maxTotalBytes: 100 }, reads)],
    now: FIXED_NOW,
  });

  assert.deepEqual(reads, ["src/a.js", "src/c.js"]);
  assert.equal(result.code.duplication.filesScanned, 2);
  assert.deepEqual(ownWarnings(result), [{ source: MEASURE_ID, path: ".", reason: "code-bytes-cut", detail: "count=1" }]);
});

test("caps: main files take the limit before test files, whatever their names", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/main.js": "export const main = 1;\n",
      "tests/main.test.js": "export const testMain = 1;\n",
    },
  });
  const reads = [];
  const result = await scan({
    root: fixture.root,
    measures: [recordingReads({ maxFiles: 1 }, reads)],
    now: FIXED_NOW,
  });

  assert.deepEqual(reads, ["src/main.js"]);
  assert.equal(result.code.duplication.filesScanned, 1);
  assert.equal(result.code.duplication.inTests.filesScanned, 0);
  assert.deepEqual(ownWarnings(result), [{ source: MEASURE_ID, path: ".", reason: "code-files-cut", detail: "count=1" }]);
});

test("a code file that is not text is skipped with the safe-fs reason", async (t) => {
  const fixture = freshFixture(t, {
    files: {
      "src/blob.js": Buffer.from([0x63, 0x00, 0x64, 0x0a]),
      "src/text.js": "export const text = 1;\n",
    },
  });
  const { section, warnings } = await scanDuplication(fixture.root);

  assert.equal(section.filesScanned, 1);
  assert.deepEqual(warnings, [{ source: MEASURE_ID, path: "src/blob.js", reason: "code-file-unreadable", detail: "binary" }]);
});

test("the output has no code text and no absolute path, and the injected instruction is not carried out", async (t) => {
  const fixture = copyOf(t, "duplicated", { git: true });
  const out = path.join(fixture.base, "out");
  const cli = await runScan([fixture.root, "--out", out]);
  assert.equal(cli.code, 0, cli.stderr);

  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  for (const text of ["amount is not finite", "RangeError", "AI agent", "AGENT-NOTE", "Totals for one checkout"]) {
    assert.equal(raw.includes(text), false, `the output holds fixture code: ${text}`);
  }
  assert.equal(
    withoutMetaText(raw).includes(JSON.stringify(fixture.root).slice(1, -1)),
    false,
    "no absolute path of this machine outside meta",
  );
  assert.equal(fs.existsSync(path.join(fixture.root, "AGENT-NOTE.txt")), false);
});

test("two CLI runs give the same JSON except meta, and every array is sorted", async (t) => {
  const fixture = copyOf(t, "duplicated", { git: true });
  const first = path.join(fixture.base, "first");
  const second = path.join(fixture.base, "second");
  assert.equal((await runScan([fixture.root, "--out", first])).code, 0);
  assert.equal((await runScan([fixture.root, "--out", second])).code, 0);

  const rawFirst = fs.readFileSync(path.join(first, "measurements.json"), "utf8");
  const rawSecond = fs.readFileSync(path.join(second, "measurements.json"), "utf8");
  assert.equal(withoutMetaText(rawFirst), withoutMetaText(rawSecond));

  const duplication = JSON.parse(rawFirst).code.duplication;
  for (const section of [duplication, duplication.inTests]) {
    assert.ok(section.groups.length <= MAX_GROUPS);
    section.groups.forEach((group, index) => {
      for (let n = 1; n < group.copies.length; n += 1) {
        assert.ok(compareCopies(group.copies[n - 1], group.copies[n]) < 0, "copies are sorted by file, then by line");
      }
      if (index > 0) {
        const before = section.groups[index - 1];
        assert.ok(before.redundantLines >= group.redundantLines, "groups are sorted by redundant lines, most first");
      }
    });
  }
});

test("the measurements schema documents the code section and its fields", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  assert.ok(schema.required.includes("code"));
  assert.deepEqual(Object.keys(schema.properties.code.properties), ["duplication"]);

  const duplication = schema.properties.code.properties.duplication;
  const keys = ["filesScanned", "duplicatedLinesPct", "groupCount", "groups", "inTests", "linesScanned", "redundantLines"];
  assert.deepEqual([...duplication.required].sort(), [...keys, "windowLines"].sort());
  assert.deepEqual(Object.keys(duplication.properties.inTests.properties).sort(), keys.filter((key) => key !== "inTests").sort());
  assert.deepEqual(
    [...duplication.properties.groups.items.required].sort(),
    ["copies", "lines", "redundantLines"],
  );
  assert.deepEqual([...duplication.properties.groups.items.properties.copies.items.required].sort(), ["endLine", "file", "line"]);
  assert.equal(duplication.properties.duplicatedLinesPct.maximum, 100);
  // The warnings that the measure writes are listed in the schema description.
  assert.match(schema.properties.warnings.items.properties.detail.description, /count=N/);
  const reasons = schema.properties.warnings.items.properties.reason.description;
  for (const code of ["code-file-too-large", "code-file-minified", "code-file-unreadable", "code-files-cut", "code-bytes-cut"]) {
    assert.ok(reasons.includes(code), `the warning reason ${code} is documented`);
  }
});

test("the default measure has the constants of the module, and bad options are refused", () => {
  assert.equal(duplicationMeasure.id, "duplication");
  assert.ok(CODE_EXTENSIONS.includes(".ts"));
  assert.ok(CODE_EXTENSIONS.includes(".py"));
  assert.ok(CODE_EXTENSIONS.includes(".astro"));
  assert.equal(CODE_EXTENSIONS.includes(".md"), false);
  assert.equal(CODE_EXTENSIONS.includes(".json"), false);
  assert.throws(() => createDuplicationMeasure({ windowLines: 0 }), TypeError);
  assert.throws(() => createDuplicationMeasure({ unknownOption: 1 }), TypeError);
  assert.throws(() => createDuplicationMeasure({ codeExtensions: ["js"] }), TypeError);
});

// The numbers and texts that normalizeLines keeps, for one text and extension.
const kept = (text, extension) => normalizeLines(text, extension).map((line) => [line.number, line.text]);

test("normalizeLines keeps the original numbers and drops imports, comments and punctuation-only lines", () => {
  const sample = [
    `${String.fromCharCode(0xfeff)}import { a } from "./a.js";`,
    "// line comment",
    "/* one line */",
    "/**",
    " * continuation",
    " */",
    "<!-- markup comment -->",
    "const b = require('b');",
    "from os import path",
    "using System;",
    "use std::fs;",
    "export * from './c.js';",
    "}",
    "  });  ",
    "",
    "  const kept = compute(1); // trailing",
    "/* lead */ const alsoKept = 2;",
    "const dynamic = await import('./d.js');",
    "#count = 0;",
    "#bump() {",
    "*p = 1;",
    "* text",
    "/* x */ total = total + 1; /* y */",
  ].join("\r\n");

  assert.deepEqual(kept(sample, ".js"), [
    [16, "const kept = compute(1); // trailing"],
    [17, "/* lead */ const alsoKept = 2;"],
    [18, "const dynamic = await import('./d.js');"],
    [19, "#count = 0;"],
    [20, "#bump() {"],
    [21, "*p = 1;"],
    [23, "/* x */ total = total + 1; /* y */"],
  ]);
});

test("normalizeLines: a line that starts with /* inside a template literal drops only itself", () => {
  const sample = ["const doc = `", "/*.js", "const a = 1;", "const b = 2;", "return a + b;", "`;"].join("\n");

  assert.deepEqual(kept(sample, ".js"), [
    [1, "const doc = `"],
    [3, "const a = 1;"],
    [4, "const b = 2;"],
    [5, "return a + b;"],
    [6, "`;"],
  ]);
});

test("normalizeLines: a JSDoc block is dropped, and a comment body that starts with * followed by text is too", () => {
  const jsdoc = ["/**", " * Doc.", " * @param x", " */", "function f(x) {}"].join("\n");
  assert.deepEqual(kept(jsdoc, ".js"), [[5, "function f(x) {}"]]);
  assert.deepEqual(kept("*p = 1;\n* text\n*/\n*\n*x", ".c"), [
    [1, "*p = 1;"],
    [5, "*x"],
  ]);
  assert.deepEqual(kept("/* a */\n/* a */ /* b */\n<!-- a -->\n/* x */ y = 1; /* z */", ".js"), [[4, "/* x */ y = 1; /* z */"]]);
});

test("normalizeLines: a hash starts a comment only in the languages that have one, and #! is dropped on line 1 anywhere", () => {
  assert.deepEqual(kept("# note\nx = 1", ".py"), [[2, "x = 1"]]);
  assert.deepEqual(kept("# comment\necho hi", ".sh"), [[2, "echo hi"]]);
  assert.deepEqual(kept("#!/usr/bin/env node\nconst a = 1;", ".js"), [[2, "const a = 1;"]]);
  assert.deepEqual(kept("#!/usr/bin/env python3\nx = 1", ".py"), [[2, "x = 1"]]);
  assert.deepEqual(kept("# note\nx = 1", ".js"), [
    [1, "# note"],
    [2, "x = 1"],
  ], "in JavaScript a line that starts with # is code");
  assert.deepEqual(kept("#include <stdio.h>\n#import <x.h>\n#define SIZE 4\n#region io", ".c"), [
    [3, "#define SIZE 4"],
    [4, "#region io"],
  ], "#include and #import are imports; other directives are code");
});

test("normalizeLines: the lines inside a multi-line block comment that do not start with * are kept (a known limit)", () => {
  assert.deepEqual(kept("/* open block\nplain text inside\n*/\nconst afterBlock = 3;", ".js"), [
    [2, "plain text inside"],
    [4, "const afterBlock = 3;"],
  ]);
});

test("isTestPath recognizes the test folders and the test names, and nothing that only contains the word", () => {
  for (const file of ["src/a.test.ts", "src/a.spec.js", "src/a_test.go", "pkg/test_util.py", "tests/x.js", "src/__tests__/x.js", "e2e/login.js", "src/__mocks__/api.js", "fixtures/a.js", "src/a.test.d.ts"]) {
    assert.equal(isTestPath(file), true, file);
  }
  for (const file of ["src/latest.js", "src/testing.js", "src/contest.js", "src/attest.js", "src/spec.js", "src/index.mjs"]) {
    assert.equal(isTestPath(file), false, file);
  }
});

test("generatedPatternOf uses the folder and file rules of the structure measure", () => {
  assert.equal(generatedPatternOf("dist/app.js"), "dist");
  assert.equal(generatedPatternOf("packages/a/dist/index.js"), "dist");
  assert.equal(generatedPatternOf("node_modules/pkg/dist/x.js"), "node-modules", "the first generated folder from the left decides");
  assert.equal(generatedPatternOf("src/app.min.js"), "minified-js");
  assert.equal(generatedPatternOf("src/api_pb2.py"), "protobuf-python");
  assert.equal(generatedPatternOf("src/dist"), null, "a file named like a folder is not inside one");
  assert.equal(generatedPatternOf("dist.js"), null);
  assert.equal(generatedPatternOf("src/index.mjs"), null);
});
