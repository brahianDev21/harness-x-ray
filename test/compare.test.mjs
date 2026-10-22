import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { toStableJson, writeStableJson } from "../scripts/lib/json-out.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";
import { main } from "../scripts/compare.mjs";
import { symlinkSupport } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";
import { HARNESS_ROOT, makeRun, readGoldenFindings } from "./helpers/report-run.mjs";

// The command line of scripts/compare.mjs. main() runs in this process, with the console output collected, so no child process
// is started for the cases; one spawned process runs with no argument, to show that the entry-point guard runs main. Every
// run folder is in the system temp folder, and the real scan of the permissive fixture is the base of all of them.
const COMPARE = path.join(HARNESS_ROOT, "scripts", "compare.mjs");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "comparison.schema.json"), "utf8"));
const OUTPUTS = ["comparison.json", "comparison.md", "comparison.html"];
const USAGE = "usage: node scripts/compare.mjs <runA> <runB>";
const COD_01 = { rule: "COD-01", axis: "code", kind: "judgment", impact: "low", summary: "Copied block.", evidence: [{ file: "src/a.js", line: 10 }] };
const STR_01 = { rule: "STR-01", axis: "structure", kind: "judgment", impact: "low", summary: "Unmapped folder.", evidence: [{ file: "docs/x.md", line: 1 }] };
const CATALOG_A = { count: 19, sha256: "aaaaaaaaaaaa" };
const CATALOG_B = { count: 19, sha256: "bbbbbbbbbbbb" };
// Text of a broken findings.json. The parser message could quote it, so the test checks that none of it is printed.
const BROKEN_MARKER = "BROKEN-MARKER-41c2";
// Hostile text. It has no quote and no ampersand, so escapeText gives its exact text in the HTML.
const HOSTILE = "<script>alert(1)</script> <img src=x onerror=alert(1)> </style> javascript:alert(1)";
// The folder name of run B cannot hold a slash, and Windows refuses <, > and " too, so on Windows it is a plain name.
const HOSTILE_FOLDER = process.platform === "win32" ? "hostile-b" : 'hostile-b <img src=x onerror=alert(1)> "javascript:alert(1)"';
const CONTROL = "Plain control summary of the check.";
const isWindows = process.platform === "win32";
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;
const rootSkip = typeof process.getuid === "function" && process.getuid() === 0 ? "running as root: the permissions do not stop a write" : false;
const permissionSkip = rootSkip || (isWindows ? "chmod does not restrict reads or writes on Windows" : false);

let real;
let baseDir;

before(async () => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-compare-test-"));
  real = await makeRun();
  fs.writeFileSync(path.join(real.runDir, "findings.json"), jsonText(readGoldenFindings("findings.en.json")));
});

after(() => {
  real?.cleanup();
  if (baseDir) fs.rmSync(baseDir, { recursive: true, force: true });
});

function jsonText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// The HTML text of a string whose special characters are only <, > and &.
function escapeText(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// A run folder in baseDir: the measurements of the real scan and the golden findings, each changed by its function. The head is
// null: the target is a copy outside any repository, and null is a valid head.
function derivedRun(name, { measurements = (m) => m, findings = (f) => f } = {}) {
  const dir = path.join(baseDir, name);
  fs.mkdirSync(dir);
  const base = clone(real.measurements);
  base.target.git.head = null;
  writeStableJson(path.join(dir, "measurements.json"), measurements(base));
  fs.writeFileSync(path.join(dir, "findings.json"), jsonText(findings(clone(readGoldenFindings("findings.en.json")))));
  return dir;
}

// Two runs that differ: A has a judgment finding that B lacks (resolved), B has one that A lacks (new), RUL-01 and the measured
// finding mf-1 change their impact, and four settings differ (target, scope, depth, catalog).
function pairRuns(prefix) {
  const a = derivedRun(`${prefix}-a`, {
    measurements: (m) => {
      m.meta.targetRoot = "/synthetic/alpha-target";
      m.target.name = "alpha-target";
      m.depth = "standard";
      m.meta.catalog = CATALOG_A;
      return m;
    },
    findings: (f) => {
      f.findings.push(COD_01);
      return f;
    },
  });
  const b = derivedRun(`${prefix}-b`, {
    measurements: (m) => {
      m.meta.targetRoot = "/synthetic/beta-target";
      m.target.name = "beta-target";
      m.depth = "deep";
      m.meta.catalog = CATALOG_B;
      m.scope = { folders: ["apps"], inherited: ["."], files: { inScope: 1, outside: 2 } };
      m.measuredFindings.find((item) => item.id === "mf-1").impact = "low";
      return m;
    },
    findings: (f) => {
      for (const item of f.findings) if (item.rule === "RUL-01") item.impact = "medium";
      f.findings.push(STR_01);
      return f;
    },
  });
  return { a, b };
}

function listing(dir) {
  return fs.readdirSync(dir).sort();
}

function readOutputs(dir) {
  return Object.fromEntries(OUTPUTS.map((name) => [name, fs.readFileSync(path.join(dir, name))]));
}

// Runs main with its console output collected. The console is restored when it returns.
async function runCli(argv) {
  const out = [];
  const err = [];
  const log = console.log;
  const error = console.error;
  console.log = (...parts) => out.push(parts.join(" "));
  console.error = (...parts) => err.push(parts.join(" "));
  try {
    const code = await main(argv);
    return { code, out, err };
  } finally {
    console.log = log;
    console.error = error;
  }
}

function readComparison(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, "comparison.json"), "utf8"));
}

test("a real scan compared with itself: every item is same, the exit code is 0 and the three files are written", async () => {
  const { code, err } = await runCli([real.runDir, real.runDir]);
  assert.equal(code, 0);
  for (const name of OUTPUTS) assert.ok(listing(real.runDir).includes(name), name);
  const comparison = readComparison(real.runDir);
  assert.deepEqual(err, [], "no warning for a run compared with itself");
  assert.deepEqual(comparison.warnings, []);
  assert.equal(comparison.counts.resolved, 0);
  assert.equal(comparison.counts.new, 0);
  assert.equal(comparison.counts["impact-changed"], 0);
  assert.ok(comparison.counts.same > 0, "the run has items");
  assert.ok(comparison.items.every((item) => item.class === "same"));
  assert.equal(comparison.runs.a.name, comparison.runs.b.name);
});

test("two runs that differ: the four classes, the warnings on stderr, and the warnings in the three files", async () => {
  const { a, b } = pairRuns("classes");
  const { code, out, err } = await runCli([a, b]);
  assert.equal(code, 0);
  assert.deepEqual(err, ["warning: target-changed", "warning: scope-changed", "warning: depth-changed", "warning: catalog-changed"]);
  assert.ok(out.includes(`warnings: 4`), out.join("\n"));
  assert.ok(out.includes(`language: en`));

  const comparison = readComparison(b);
  const judgment = (rule) => comparison.items.find((item) => item.kind === "judgment" && item.rule === rule);
  assert.equal(judgment("COD-01").class, "resolved");
  assert.equal(judgment("STR-01").class, "new");
  assert.equal(judgment("RUL-01").class, "impact-changed");
  assert.equal(judgment("VER-01").class, "same");
  assert.equal(judgment("RUL-01").a.impact, "low");
  assert.equal(judgment("RUL-01").b.impact, "medium");
  const measured = comparison.items.find((item) => item.kind === "measured" && item.a?.id === "mf-1");
  assert.equal(measured.class, "impact-changed");
  assert.equal(comparison.counts.resolved, 1);
  assert.equal(comparison.counts.new, 1);
  assert.equal(comparison.counts["impact-changed"], 2);
  assert.deepEqual(
    comparison.warnings.map((warning) => warning.code),
    ["target-changed", "scope-changed", "depth-changed", "catalog-changed"],
  );
  assert.deepEqual(comparison.warnings[0], { code: "target-changed", a: "alpha-target", b: "beta-target" });

  const markdown = fs.readFileSync(path.join(b, "comparison.md"), "utf8");
  const html = fs.readFileSync(path.join(b, "comparison.html"), "utf8");
  assert.ok(markdown.includes("The target changed. Run A: `alpha-target`. Run B: `beta-target`."), "the target warning in Markdown");
  for (const sentence of ["The target changed.", "The scope changed.", "The depth changed.", "The rule catalog changed."]) {
    assert.ok(markdown.includes(sentence), `Markdown: ${sentence}`);
    assert.ok(html.includes(sentence), `HTML: ${sentence}`);
  }
});

test("two runs of the same inputs give three files identical byte by byte, and no temporary file is left", async () => {
  const { a, b } = pairRuns("twice");
  assert.equal((await runCli([a, b])).code, 0);
  const first = readOutputs(b);
  const inputs = listing(b).filter((name) => !OUTPUTS.includes(name));
  assert.equal((await runCli([a, b])).code, 0);
  const second = readOutputs(b);
  assert.deepEqual(second, first);
  assert.deepEqual(listing(b), [...inputs, ...OUTPUTS].sort());
});

test("comparison.json is the stable JSON of the comparison and validates against its schema; an extra field does not", async () => {
  const { a, b } = pairRuns("schema");
  assert.equal((await runCli([a, b])).code, 0);
  const text = fs.readFileSync(path.join(b, "comparison.json"), "utf8");
  const parsed = JSON.parse(text);
  assert.equal(text, toStableJson(parsed), "the file is written with the stable JSON writer");
  assert.deepEqual(schemaProblems(SCHEMA, parsed), []);
  const same = derivedRun("schema-same");
  assert.equal((await runCli([same, same])).code, 0);
  assert.deepEqual(schemaProblems(SCHEMA, readComparison(same)), []);
  // Control: the same object with an extra field must fail.
  assert.ok(schemaProblems(SCHEMA, { ...parsed, extra: 1 }).length > 0);
});

test("a run without meta.catalog gives the catalog-unknown warning and no other", async () => {
  const a = derivedRun("unknown-a", { measurements: (m) => (delete m.meta.catalog, m) });
  const b = derivedRun("unknown-b", { measurements: (m) => ((m.meta.catalog = CATALOG_B), m) });
  const { code, err } = await runCli([a, b]);
  assert.equal(code, 0);
  assert.deepEqual(err, ["warning: catalog-unknown"]);
  assert.deepEqual(readComparison(b).warnings.map((warning) => warning.code), ["catalog-unknown"]);
});

test("the language is the one of the findings of run B, and the labels follow it", async () => {
  const a = derivedRun("language-a");
  const b = derivedRun("language-b", { findings: (f) => ((f.language = "es"), f) });
  const { code, out } = await runCli([a, b]);
  assert.equal(code, 0);
  assert.ok(out.includes("language: es"));
  assert.equal(readComparison(b).language, "es");
  const title = loadLabels(HARNESS_ROOT, "es")["compare.title"];
  assert.ok(fs.readFileSync(path.join(b, "comparison.md"), "utf8").includes(title));
});

test("usage errors exit 2 and write nothing; a valid pair is the positive control", async () => {
  const a = derivedRun("usage-a");
  const b = derivedRun("usage-b");
  const before = listing(b);
  const refused = [
    [[], "expected two run folders, got 0"],
    [[a], "expected two run folders, got 1"],
    [[a, b, b], "expected two run folders, got 3"],
    [["", b], "the run folder must not be empty"],
    [[b, ""], "the run folder must not be empty"],
    [["--json", a, b], "Unknown option"],
    [[a, path.join(HARNESS_ROOT, "scripts")], "must be inside runs/"],
    [[a, path.join(baseDir, "missing-run")], "the run folder does not exist"],
    [[a, path.join(b, "findings.json")], "not a folder"],
  ];
  for (const [argv, text] of refused) {
    const { code, err } = await runCli(argv);
    assert.equal(code, 2, JSON.stringify(argv));
    assert.ok(err[0].startsWith("error: ") && err[0].includes(text), `${JSON.stringify(argv)}: ${JSON.stringify(err)}`);
    assert.equal(err[1], USAGE);
    assert.deepEqual(listing(b), before, "nothing is written");
  }
  const control = derivedRun("usage-control");
  assert.equal((await runCli([a, control])).code, 0, "a valid pair exits 0");
  assert.deepEqual(listing(control).filter((name) => OUTPUTS.includes(name)), OUTPUTS.slice().sort());
});

test("input errors exit 2 and write nothing; a valid pair is the positive control", async () => {
  const outside = path.join(baseDir, "outside-inputs");
  fs.mkdirSync(outside, { recursive: true });
  const outsideFindings = path.join(outside, "findings.json");
  fs.writeFileSync(outsideFindings, jsonText(readGoldenFindings("findings.en.json")));

  const cases = [
    ["a missing measurements.json", "b", (dir) => fs.rmSync(path.join(dir, "measurements.json")), "missing input file"],
    ["a missing findings.json", "a", (dir) => fs.rmSync(path.join(dir, "findings.json")), "missing input file"],
    [
      "a findings.json that is not JSON",
      "b",
      (dir) => fs.writeFileSync(path.join(dir, "findings.json"), `{ "marker": "${BROKEN_MARKER}", not json`),
      "is not valid JSON",
    ],
    ["a measurements.json of another tool", "b", (dir) => fs.writeFileSync(path.join(dir, "measurements.json"), "{}\n"), "is not a scan of this tool"],
    ["a findings.json of another tool", "a", (dir) => fs.writeFileSync(path.join(dir, "findings.json"), "{}\n"), "needs a findings list"],
  ];
  for (const [label, side, breakInput, text] of cases) {
    const a = derivedRun(`input-${label.replace(/\W+/g, "-")}-a`);
    const b = derivedRun(`input-${label.replace(/\W+/g, "-")}-b`);
    breakInput(side === "a" ? a : b);
    const before = [listing(a), listing(b)];
    const { code, err } = await runCli([a, b]);
    assert.equal(code, 2, label);
    assert.ok(err[0].includes(text), `${label}: ${JSON.stringify(err)}`);
    const printed = err.join("\n");
    assert.ok(!printed.includes("position"), `${label}: no parser position is printed`);
    assert.ok(!printed.includes(BROKEN_MARKER), `${label}: no part of the broken file is printed`);
    assert.deepEqual([listing(a), listing(b)], before, `${label}: nothing is written`);
  }
  const control = derivedRun("input-control");
  assert.equal((await runCli([real.runDir, control])).code, 0, "a valid pair exits 0");

  const hardLinked = derivedRun("input-hardlink-b");
  fs.rmSync(path.join(hardLinked, "findings.json"));
  fs.linkSync(outsideFindings, path.join(hardLinked, "findings.json"));
  const hardBefore = listing(hardLinked);
  const hardRun = await runCli([real.runDir, hardLinked]);
  assert.equal(hardRun.code, 2, "a hard-linked input is refused");
  assert.ok(hardRun.err[0].includes("more than one hard link"));
  assert.deepEqual(listing(hardLinked), hardBefore);
});

test("a measurements.json that is a symbolic link exits 2 and nothing is written", { skip: symlinkSkip }, async () => {
  const outside = path.join(baseDir, "outside-symlink-input");
  fs.mkdirSync(outside);
  writeStableJson(path.join(outside, "measurements.json"), real.measurements);
  const symlinked = derivedRun("input-symlink-b");
  fs.rmSync(path.join(symlinked, "measurements.json"));
  fs.symlinkSync(path.join(outside, "measurements.json"), path.join(symlinked, "measurements.json"));
  const before = listing(symlinked);
  const { code, err } = await runCli([real.runDir, symlinked]);
  assert.equal(code, 2, "a symbolic link input is refused");
  assert.ok(err[0].includes("not a regular file"), JSON.stringify(err));
  assert.deepEqual(listing(symlinked), before);
});

test("an input file that exists but cannot be read exits 2 with its path only, and the same pair exits 0 once it can be read", { skip: permissionSkip }, async () => {
  const a = derivedRun("unreadable-a");
  const b = derivedRun("unreadable-b");
  const file = path.join(fs.realpathSync.native(b), "findings.json");
  const before = listing(b);
  fs.chmodSync(file, 0o000);
  try {
    const { code, err } = await runCli([a, b]);
    assert.equal(code, 2);
    assert.deepEqual(err.slice(0, 2), [`error: cannot read input file: ${file}`, USAGE]);
    assert.deepEqual(listing(b), before, "nothing is written");
  } finally {
    fs.chmodSync(file, 0o600);
  }
  assert.equal((await runCli([a, b])).code, 0, "the same pair exits 0 once the file is readable");
});

test("an output that is a symbolic link is refused with exit 2, and the link target is not written", { skip: symlinkSkip }, async () => {
  const { a, b } = pairRuns("out-symlink");
  const outside = path.join(baseDir, "outside-output-link.json");
  fs.writeFileSync(outside, "outside\n");
  fs.symlinkSync(outside, path.join(b, "comparison.json"));
  const before = listing(b);
  const { code, err } = await runCli([a, b]);
  assert.equal(code, 2);
  assert.ok(err[0].includes("not a regular file"));
  assert.deepEqual(listing(b), before);
  assert.equal(fs.readFileSync(outside, "utf8"), "outside\n");
});

test("an output that is a folder, or a hard link, is refused with exit 2 and nothing is written", async () => {
  const folderRun = pairRuns("out-folder");
  fs.mkdirSync(path.join(folderRun.b, "comparison.md"));
  const folderBefore = listing(folderRun.b);
  const folderResult = await runCli([folderRun.a, folderRun.b]);
  assert.equal(folderResult.code, 2);
  assert.ok(folderResult.err[0].includes("not a regular file"));
  assert.deepEqual(listing(folderRun.b), folderBefore);

  const linked = pairRuns("out-hardlink");
  const outside = path.join(baseDir, "outside-output-hardlink.html");
  fs.writeFileSync(outside, "outside\n");
  fs.linkSync(outside, path.join(linked.b, "comparison.html"));
  const linkedBefore = listing(linked.b);
  const linkedResult = await runCli([linked.a, linked.b]);
  assert.equal(linkedResult.code, 2);
  assert.ok(linkedResult.err[0].includes("more than one hard link"));
  assert.deepEqual(listing(linked.b), linkedBefore);
  assert.equal(fs.readFileSync(outside, "utf8"), "outside\n");

  // Control: regular outputs from an earlier comparison are replaced.
  const control = pairRuns("out-control");
  fs.writeFileSync(path.join(control.b, "comparison.json"), "old\n");
  assert.equal((await runCli([control.a, control.b])).code, 0);
  assert.notEqual(fs.readFileSync(path.join(control.b, "comparison.json"), "utf8"), "old\n");
});

test("a write that fails exits 1 and leaves no file in run B", { skip: permissionSkip }, async () => {
  const { a, b } = pairRuns("write-fail");
  const before = listing(b);
  fs.chmodSync(b, 0o500);
  try {
    const { code, err } = await runCli([a, b]);
    assert.equal(code, 1);
    assert.ok(err[0].startsWith("error: "));
    assert.ok(!err.includes(USAGE));
    assert.deepEqual(listing(b), before, "no temporary and no final file");
  } finally {
    fs.chmodSync(b, 0o700);
  }
  const control = pairRuns("write-control");
  assert.equal((await runCli([control.a, control.b])).code, 0, "the same pair exits 0 when run B is writable");
});

test("a second temporary file that cannot be written exits 1, and the first temporary file is removed", async (t) => {
  const { a, b } = pairRuns("temp-write");
  const before = listing(b);
  const writeFileSync = fs.writeFileSync;
  let writes = 0;
  t.mock.method(fs, "writeFileSync", (...args) => {
    // compare.mjs writes its temporary files through a descriptor, so only those calls are counted.
    if (typeof args[0] === "number" && ++writes === 2) throw new Error("simulated write failure");
    return writeFileSync.apply(fs, args);
  });
  const { code, err } = await runCli([a, b]);
  assert.equal(writes, 2, "the second temporary write is reached");
  assert.equal(code, 1);
  assert.deepEqual(err, ["error: simulated write failure"]);
  assert.deepEqual(listing(b), before, "no temporary file and no output file is left");
});

test("a second rename that fails exits 1: the file renamed first stays, and the temporary files not renamed are removed", async (t) => {
  const { a, b } = pairRuns("rename-fail");
  const before = listing(b);
  const renameSync = fs.renameSync;
  let renames = 0;
  t.mock.method(fs, "renameSync", (...args) => {
    if (++renames === 2) throw new Error("simulated rename failure");
    return renameSync.apply(fs, args);
  });
  const { code, err } = await runCli([a, b]);
  assert.equal(renames, 2, "the second rename is reached");
  assert.equal(code, 1);
  assert.deepEqual(err, ["error: simulated rename failure"]);
  // The header of compare.mjs: the renames are three steps, so the first renamed file stays and no temporary file is left.
  assert.deepEqual(listing(b), [...before, "comparison.json"].sort());
  assert.ok(Array.isArray(readComparison(b).items));
});

test("hostile text in the names, a scope folder, an evidence file and the summaries stays text in the HTML, next to a plain control", async () => {
  const a = derivedRun("hostile-a");
  const b = derivedRun(HOSTILE_FOLDER, {
    measurements: (m) => {
      m.target.name = HOSTILE;
      m.scope = { folders: ["apps", `packages/${HOSTILE}`], inherited: ["."], files: { inScope: 1, outside: 2 } };
      return m;
    },
    findings: (f) => {
      for (const item of f.findings) {
        if (item.rule === "RUL-01") item.summary = HOSTILE;
        if (item.rule === "VER-01") item.summary = CONTROL;
      }
      f.findings.push({ ...STR_01, summary: HOSTILE, evidence: [{ file: `docs/${HOSTILE}.md`, line: 1 }] });
      return f;
    },
  });
  const { code } = await runCli([a, b]);
  assert.equal(code, 0);
  const html = fs.readFileSync(path.join(b, "comparison.html"), "utf8");
  assert.ok(!/<script/i.test(html), "no script element");
  assert.ok(!/<img/i.test(html), "no image element");
  assert.equal(html.split("</style>").length - 1, 1, "only the closing tag of the page style");
  for (const match of html.matchAll(/href\s*=\s*["']?([^"'\s>]*)/gi)) {
    assert.ok(match[1].startsWith("https://"), `a link that is not https: ${match[1]}`);
  }
  // The hostile text is shown escaped in the target name, the summaries, a scope folder and an evidence file.
  assert.ok(html.includes(escapeText(HOSTILE)), "the hostile text is shown, escaped");
  assert.ok(html.includes("&lt;/style&gt;"), "the closing style tag is shown, escaped");
  if (!isWindows) assert.ok(html.includes("hostile-b &lt;img src=x onerror=alert(1)&gt;"), "the run B folder name is shown, escaped");
  assert.ok(html.includes(CONTROL), "the plain control text is shown");
});

test("run folders given as relative paths are compared from the working directory, and the files are written in run B", async () => {
  derivedRun("relative-a");
  const dirB = derivedRun("relative-b");
  const realB = fs.realpathSync.native(dirB);
  const cwd = process.cwd();
  try {
    process.chdir(baseDir);
    const first = await runCli(["./relative-a", "./relative-b"]);
    assert.equal(first.code, 0, JSON.stringify(first.err));
    assert.ok(first.out.includes(`json: ${path.join(realB, "comparison.json")}`), JSON.stringify(first.out));

    // From a folder one level down, the same runs are reached with "..".
    fs.mkdirSync(path.join(baseDir, "relative-nested"));
    process.chdir(path.join(baseDir, "relative-nested"));
    const second = await runCli(["../relative-a", "../relative-b"]);
    assert.equal(second.code, 0, JSON.stringify(second.err));
    assert.ok(second.out.includes(`json: ${path.join(realB, "comparison.json")}`), JSON.stringify(second.out));
  } finally {
    process.chdir(cwd);
  }
  for (const name of OUTPUTS) assert.ok(listing(dirB).includes(name), name);
});

test("run as the entry point with no argument exits 2 with the usage line", () => {
  const result = spawnSync(process.execPath, [COMPARE], { encoding: "utf8", timeout: 30000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: node scripts\/compare\.mjs <runA> <runB>/);
  assert.equal(result.stdout, "");
});
