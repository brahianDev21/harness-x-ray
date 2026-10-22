import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { writeStableJson } from "../scripts/lib/json-out.mjs";
import { MARKERS, buildReportModel, fillTemplate, missingField, renderMarkdown, renderReport } from "../scripts/lib/report.mjs";
import { readCatalog } from "../scripts/lib/report-catalog.mjs";
import { formatNumber } from "../scripts/lib/report-markdown.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";
import { AXES, loadRules } from "../scripts/lib/findings-validate.mjs";
import {
  APPENDED_LINE,
  HARNESS_ROOT,
  makeRun,
  readGolden,
  readGoldenFindings,
  runRender,
} from "./helpers/report-run.mjs";
import { symlinkSupport } from "./helpers/make-fixture.mjs";

const REPORT = "report.md";
const HTML = "report.html";
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;

let run;

before(async () => {
  run = await makeRun();
});

after(() => run?.cleanup());

// An older report, with bytes that a rewrite would change: CRLF, non-ASCII and Markdown characters.
const OLD_REPORT = Buffer.from("# An older report\r\n\r\nécrit | `code` — kept\r\n", "utf8");
// An older page, with the same kind of bytes, for the same checks on report.html.
const OLD_HTML = Buffer.from("<!doctype html>\r\n<p>écrit — kept</p>\r\n", "utf8");

// A run folder with the scan's measurements, the given findings, and optionally older reports.
function makeCase({ findings, measurements = run.measurements, oldReport = false }) {
  const dir = fs.mkdtempSync(path.join(run.fixture.base, "case-"));
  writeStableJson(path.join(dir, "measurements.json"), measurements);
  fs.writeFileSync(path.join(dir, "findings.json"), `${JSON.stringify(findings, null, 2)}\n`);
  if (oldReport) {
    fs.writeFileSync(path.join(dir, REPORT), OLD_REPORT);
    fs.writeFileSync(path.join(dir, HTML), OLD_HTML);
  }
  return dir;
}

function reportOf(dir) {
  const file = path.join(dir, REPORT);
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
}

function htmlOf(dir) {
  const file = path.join(dir, HTML);
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
}

// The bytes of a report file of the run folder (report.md by default), or null when there is no file.
function bytesOf(dir, name = REPORT) {
  const file = path.join(dir, name);
  return fs.existsSync(file) ? fs.readFileSync(file) : null;
}

// The number tokens of a text, in order. A token is a digit run with the group and decimal separators inside it, so "1,234" is
// one number and "1.234" another. It starts and ends with a digit, so a sentence-final period is not part of it. A space is
// no separator here: the HTML has one between two table cells, where the Markdown has a pipe.
const numbersOf = (text) => text.match(/\d(?:[\d.,]*\d)?/g) ?? [];

// The five entities that escapeHtml writes, and any numeric character reference, decoded in one pass.
function decodeEntities(text) {
  const named = { amp: "&", lt: "<", gt: ">", quot: '"' };
  return text.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot);/gi, (entity, body) => {
    if (body[0] !== "#") return named[body.toLowerCase()];
    const hex = body[1] === "x" || body[1] === "X";
    return String.fromCodePoint(hex ? Number.parseInt(body.slice(2), 16) : Number(body.slice(1)));
  });
}

// The text a reader sees in an HTML page: the head is dropped (its meta values and its style are not visible), then each tag
// becomes a space, since a cell or a list item ends where its tag is, then the references are decoded.
function visibleText(html) {
  return decodeEntities(html.replace(/<head>[\s\S]*?<\/head>/, "").replace(/<[^>]*>/g, " "));
}

// Paths of this machine that a report must never show: the target, the temp folder above it and the home folder.
function absolutePathsIn(text) {
  const forms = [run.fixture.root, run.fixture.base, os.homedir()];
  const found = forms.filter((form) => text.includes(form));
  if (/(?<![A-Za-z])[A-Za-z]:[\\/]/.test(text)) found.push("a drive path such as C:\\");
  if (/\/Users\//.test(text)) found.push("/Users/");
  if (/\/home\//.test(text)) found.push("/home/");
  return found;
}

describe("golden reports", () => {
  test("without language, the reports are in English and match the golden English Markdown and HTML", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.en.md"));
    assert.equal(htmlOf(dir), readGolden("report.en.html"));
  });

  test("language en written explicitly gives the same bytes as the English golden reports", async () => {
    const findings = { language: "en", ...readGoldenFindings("findings.en.json") };
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.en.md"));
    assert.equal(htmlOf(dir), readGolden("report.en.html"));
  });

  test("language es gives the golden Spanish Markdown and HTML", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.es.md"));
    assert.equal(htmlOf(dir), readGolden("report.es.html"));
  });

  test("two renders of the same input give identical bytes in both files", async () => {
    const first = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const second = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([first])).code, 0);
    assert.equal((await runRender([second])).code, 0);
    assert.equal(reportOf(first), reportOf(second));
    assert.equal(htmlOf(first), htmlOf(second));
  });

  test("the quote with a pipe and a backtick stays one readable code span", () => {
    const report = readGolden("report.en.md");
    assert.ok(report.includes(`\`\`Never run \`rm -rf \\| git reset --hard\` without asking first.\`\``), APPENDED_LINE);
  });

  test("the golden reports hold no absolute path of this machine", () => {
    for (const name of ["report.en.md", "report.es.md", "report.en.html", "report.es.html"]) {
      assert.deepEqual(absolutePathsIn(readGolden(name)), [], name);
    }
  });

  // The HTML shows the same numbers as the Markdown, in the same order. The Markdown link targets are left out of its count:
  // they are the addresses of the sources, and in the HTML an address sits in an href attribute, which is not visible text.
  test("the golden HTML shows the same numbers as the golden Markdown, in the same order (en and es)", () => {
    for (const language of ["en", "es"]) {
      const markdown = numbersOf(readGolden(`report.${language}.md`).replace(/\]\([^)]*\)/g, ""));
      const html = numbersOf(visibleText(readGolden(`report.${language}.html`)));
      assert.ok(markdown.length > 0, `positive control: the ${language} Markdown has numbers`);
      assert.deepEqual(html, markdown, language);
    }
  });

  test("the number tokens keep their separators, and a sentence-final period is not one (positive control of the extractor)", () => {
    assert.deepEqual(numbersOf("1,234 and 1.234"), ["1,234", "1.234"]);
    assert.deepEqual(numbersOf("Checked on 2026-10-18."), ["2026", "10", "18"]);
  });
});

describe("scope", () => {
  // The labels of both languages, read from templates/, so that the tests compare with the exact text of the report.
  const labelsEn = loadLabels(HARNESS_ROOT, "en");
  const labelsEs = loadLabels(HARNESS_ROOT, "es");

  // The scan's measurements with a scope: 3 files inside it and 5 outside.
  function scopedMeasurements() {
    const measurements = structuredClone(run.measurements);
    measurements.scope = { folders: ["apps/web"], inherited: [".", "apps"], files: { inScope: 3, outside: 5 } };
    return measurements;
  }

  test("with a scope, the header names the scope and the inherited folders, and the limits say what was measured and read", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: scopedMeasurements() });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes("- **Scope:** folders `apps/web`; inherited folders `.`, `apps`\n"), "the Scope header field");
    assert.ok(report.includes(`${labelsEn["limits.scope"].replace("{outside}", "5")}\n`), "the scope paragraph of the limits");
    assert.match(report, /^## Limits of this scan\n\n/m);
  });

  test("with a scope in Spanish, the report has the Alcance field and the Spanish scope paragraph", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json"), measurements: scopedMeasurements() });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes("- **Alcance:** carpetas `apps/web`; carpetas heredadas `.`, `apps`\n"), "the Alcance header field");
    assert.ok(report.includes(`${labelsEs["limits.scope"].replace("{outside}", "5")}\n`), "the Spanish scope paragraph");
    assert.doesNotMatch(report, /\*\*Scope:\*\*|The scan was limited to a scope/, "no English scope text in a Spanish report");
  });

  test("positive control: without a scope there is no scope field and no scope paragraph", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.doesNotMatch(report, /\*\*Scope:\*\*/);
    assert.doesNotMatch(report, /The scan was limited to a scope/);
  });
});

describe("context by layer", () => {
  const labelsEn = loadLabels(HARNESS_ROOT, "en");
  const labelsEs = loadLabels(HARNESS_ROOT, "es");

  // The scan's measurements with a layer plan: a layer whose name has a pipe, and one with two folders.
  function layeredMeasurements() {
    const measurements = structuredClone(run.measurements);
    measurements.context.byLayer = [
      {
        name: "web | front",
        folders: ["apps/web"],
        agent: "claude-code",
        onDemand: { estTokens: 120, items: [{ path: "apps/web/CLAUDE.md", kind: "memory", estTokens: 120 }] },
        nestedSkills: { estTokens: 30, items: [{ path: "apps/web/.claude/skills/x/SKILL.md", estTokens: 30 }] },
        notCounted: [],
      },
      {
        name: "api",
        folders: ["apps/api", "apps/api/src"],
        agent: "claude-code",
        onDemand: { estTokens: 0, items: [] },
        nestedSkills: { estTokens: 0, items: [] },
        notCounted: [],
      },
    ];
    return measurements;
  }

  // The row of a layer in the table: its cells, with the numbers formatted for the language of the findings.
  function rowsOf(language, always) {
    const num = (value) => formatNumber(value, language);
    return {
      web: `| web \\| front | \`apps/web\` | ${num(always)} | ${num(120)} | ${num(always + 120)} | ${num(30)} |`,
      api: `| api | \`apps/api\`, \`apps/api/src\` | ${num(always)} | ${num(0)} | ${num(always)} | ${num(0)} |`,
    };
  }

  test("with a layer plan, the context section has a row per layer, the total, and the nested skills apart (English)", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: layeredMeasurements() });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    const always = run.measurements.context.alwaysLoaded.estTokensTotal;
    const rows = rowsOf("en", always);
    assert.ok(report.includes(`**${labelsEn["context.byLayer"]}:**\n\n`), "the lead-in of the table");
    assert.ok(report.includes("| Layer | Folders | Always loaded | On demand in the layer | Total | Nested skills (not verified) |\n"), "the headers");
    assert.ok(report.includes(`${rows.web}\n${rows.api}\n`), "one row per layer, in plan order, with the pipe escaped");
    assert.ok(report.includes(`${labelsEn["context.byLayerNote"]}\n`), "the sentence that says what on demand means");
    assert.ok(report.indexOf("**Context by layer:**") > report.indexOf("## Context budget"), "the table is in the context section");
    assert.ok(report.indexOf("**Context by layer:**") < report.indexOf("## Limits of this scan"), "and before the limits");
  });

  test("the same table in Spanish carries the Spanish labels and the Spanish number format", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json"), measurements: layeredMeasurements() });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    const always = run.measurements.context.alwaysLoaded.estTokensTotal;
    const rows = rowsOf("es", always);
    const headers = ["table.layer", "table.folders", "table.alwaysLoaded", "table.onDemand", "table.total", "table.nestedSkills"];
    assert.ok(report.includes(`| ${headers.map((key) => labelsEs[key]).join(" | ")} |\n`), "the Spanish headers, from the labels");
    assert.ok(report.includes(`${rows.web}\n${rows.api}\n`), "the rows with Spanish numbers");
    assert.ok(report.includes(`${labelsEs["context.byLayerNote"]}\n`), "the Spanish sentence");
    assert.doesNotMatch(report, /Context by layer|On demand in the layer/, "no English label in the Spanish report");
  });

  test("positive control: without a layer plan there is no table and no sentence of it", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.doesNotMatch(report, /Context by layer/);
    assert.doesNotMatch(report, new RegExp(labelsEn["context.byLayerNote"].slice(0, 40).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });
});

describe("trigger notes", () => {
  // A copy of the scan with one measured SEC-02 finding, whose only trigger is hook-not-verified.
  function withHookNotVerified() {
    const measurements = structuredClone(run.measurements);
    const ref = "/security/destructiveCoverage/commands/0";
    measurements.measuredFindings.push({
      id: `mf-${measurements.measuredFindings.length + 1}`,
      rule: "SEC-02",
      axis: "security",
      impact: "low",
      measurementRef: ref,
      evidence: [{ file: ".claude/settings.json" }],
      triggers: [{ trigger: "hook-not-verified", impact: "low", measurementRef: ref }],
    });
    return measurements;
  }

  test("the hook-not-verified row shows its name and the note of its state, in English", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: withHookNotVerified() });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(
      report.includes("`hook-not-verified` (a hook runs on this command, but the scan cannot tell whether it blocks it)"),
      "the English note is missing",
    );
  });

  test("the same row in the Spanish report carries the Spanish note", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json"), measurements: withHookNotVerified() });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    const note = loadLabels(HARNESS_ROOT, "es")["trigger.hookNotVerified"];
    assert.ok(report.includes(`\`hook-not-verified\` (${note})`), "the Spanish note is missing");
  });

  test("a trigger without a note is shown by its name alone, as before (positive control)", () => {
    const report = readGolden("report.en.md");
    assert.ok(report.includes("| `destructive-command-passes` | "), "the name-only row is missing");
    assert.equal(report.includes("hook-not-verified"), false, "the golden scan has no hook-not-verified trigger");
  });
});

describe("evidence outside the target", () => {
  // A copy of the scan with the flags given: the user layer and the parent folders. Only what the validator reads is
  // written: the paths and the line counts. Without a flag, the copy is the scan as it is (no meta.include, as the scan writes).
  function withLayers({ userLayer = false, ancestors = false }) {
    const measurements = structuredClone(run.measurements);
    if (!userLayer && !ancestors) return measurements;
    measurements.meta.include = { userLayer, ancestors };
    if (userLayer) {
      measurements.userLayer = {
        root: "~/.claude",
        found: true,
        memory: [{ path: "~/.claude/CLAUDE.md", lines: 12 }],
        settings: { path: "~/.claude/settings.json", found: true, lines: 4 },
        skills: [{ path: "~/.claude/skills/review/SKILL.md" }],
        subagents: [],
      };
    }
    if (ancestors) measurements.context.ancestors = [{ path: "../CLAUDE.md", bytes: 500, read: true, lines: 3 }];
    return measurements;
  }

  // The golden findings, with one evidence entry from each layer on the first finding.
  function findingsWithLayers(language) {
    const findings = readGoldenFindings(language === "es" ? "findings.es.json" : "findings.en.json");
    findings.findings[0].evidence.push(
      { file: "~/.claude/settings.json", line: 2, endLine: 3, layer: "user" },
      { file: "../CLAUDE.md", line: 1, layer: "ancestor" },
    );
    return findings;
  }

  test("an evidence entry from each layer is marked in the English report, after its location", async () => {
    const dir = makeCase({ findings: findingsWithLayers("en"), measurements: withLayers({ userLayer: true, ancestors: true }) });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes("`~/.claude/settings.json:2-3` (user layer, outside the repository)"), "the user mark is missing");
    assert.ok(report.includes("`../CLAUDE.md:1` (parent folder, outside the repository)"), "the parent-folder mark is missing");
  });

  test("the same marks in the Spanish report carry the Spanish labels", async () => {
    const labels = loadLabels(HARNESS_ROOT, "es");
    const dir = makeCase({ findings: findingsWithLayers("es"), measurements: withLayers({ userLayer: true, ancestors: true }) });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes(`\`~/.claude/settings.json:2-3\` (${labels["layer.user"]})`), "the Spanish user mark is missing");
    assert.ok(report.includes(`\`../CLAUDE.md:1\` (${labels["layer.ancestor"]})`), "the Spanish parent-folder mark is missing");
  });

  test("the limits name what the scan read beyond the target, and only what meta.include says (positive controls: each flag)", async () => {
    const labels = loadLabels(HARNESS_ROOT, "en");
    const cases = [
      [{}, "limits.notRead", "context.layers"],
      [{ userLayer: true }, "limits.readUser", "context.layers"],
      [{ ancestors: true }, "limits.readAncestors", "context.layersAncestors"],
      [{ userLayer: true, ancestors: true }, "limits.readBoth", "context.layersAncestors"],
    ];
    const limitKeys = cases.map(([, key]) => key);
    const contextKeys = ["context.layers", "context.layersAncestors"];
    for (const [flags, expectedLimit, expectedContext] of cases) {
      const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: withLayers(flags) });
      const result = await runRender([dir]);
      assert.equal(result.code, 0, result.stderr);
      const report = reportOf(dir);
      for (const key of limitKeys) {
        assert.equal(report.includes(labels[key]), key === expectedLimit, `${key} for ${JSON.stringify(flags)}`);
      }
      for (const key of contextKeys) {
        assert.equal(report.includes(labels[key]), key === expectedContext, `${key} for ${JSON.stringify(flags)}`);
      }
    }
  });

  test("the golden reports have no mark and no flag text, since no evidence there has a layer (positive control)", () => {
    assert.equal(readGolden("report.en.md").includes("outside the repository"), false);
    assert.equal(readGolden("report.es.md").includes("fuera del repositorio"), false);
  });
});

// The matrix table as the report writes it: a header with the Command label and the modes as code, a divider, and one
// row per command. The cells are read from the measurements, so the test does not copy any outcome by hand.
function matrixTableOf(measurements, labels) {
  const { commands, matrixModes: modes } = measurements.security.destructiveCoverage;
  const headers = [labels["table.command"], ...modes.map((mode) => `\`${mode}\``)];
  const rows = commands.map((command) => [`\`${command.id}\``, ...modes.map((mode) => `\`${command.modes[mode]}\``)]);
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n");
}

// The deep matrix table: a row per command and location, with the location's label after the command, read from the
// measurements in the same way.
function deepMatrixTableOf(measurements, labels) {
  const { commands, matrixModes: modes, matrixLocations: locations } = measurements.security.destructiveCoverage;
  const headers = [labels["table.command"], labels["table.location"], ...modes.map((mode) => `\`${mode}\``)];
  const rows = commands.flatMap((command) =>
    locations.map((location) => [
      `\`${command.id}\``,
      labels[`location.${location}`],
      ...modes.map((mode) => `\`${command.locations[location][mode]}\``),
    ]),
  );
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n");
}

describe("permission matrix", () => {
  test("the limits section shows the matrix, one row per command and one column per mode, with its legend", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    const labels = loadLabels(HARNESS_ROOT, "en");
    const table = matrixTableOf(run.measurements, labels);
    assert.ok(report.includes(table), "the matrix table is missing or differs from the measurements");
    assert.ok(report.includes(labels["limits.matrixLegend"]), "the legend is missing");
    const at = report.indexOf(table);
    assert.ok(at > report.indexOf("## Limits of this scan") && at < report.indexOf("## Sources"), "the matrix is not in the limits section");
  });

  test("the SEC-02 limit does not state the auto start as fact, and says the start mode is not verified", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([dir])).code, 0);
    const report = reportOf(dir);
    assert.equal(report.includes("v2.1.283"), false, "the version claim is still in the report");
    assert.ok(report.includes("(not verified against the documentation)"), "the unverified note is missing");
  });

  test("the columns follow matrixModes in the order the scan wrote them (positive control: the reversed table differs)", async () => {
    const measurements = structuredClone(run.measurements);
    measurements.security.destructiveCoverage.matrixModes.reverse();
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const labels = loadLabels(HARNESS_ROOT, "en");
    assert.ok(reportOf(dir).includes(matrixTableOf(measurements, labels)), "the reversed matrix is missing");
    assert.notEqual(matrixTableOf(measurements, labels), matrixTableOf(run.measurements, labels));
  });

  test("a Spanish report shows the same table with the Spanish header and legend", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const labels = loadLabels(HARNESS_ROOT, "es");
    const report = reportOf(dir);
    assert.ok(report.includes(matrixTableOf(run.measurements, labels)), "the Spanish matrix table is missing");
    assert.ok(report.includes(labels["limits.matrixLegend"]), "the Spanish legend is missing");
  });

  test("a scan without matrixModes shows no matrix, and the rest of the limits section stays (positive control)", async () => {
    const measurements = structuredClone(run.measurements);
    delete measurements.security.destructiveCoverage.matrixModes;
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const labels = loadLabels(HARNESS_ROOT, "en");
    const report = reportOf(dir);
    assert.equal(report.includes(labels["limits.matrix"]), false, "the matrix lead-in is shown");
    assert.equal(report.includes(labels["limits.matrixLegend"]), false, "the legend is shown");
    assert.ok(report.includes(labels["limits.noUndeterminable"]), "the rest of the limits section is missing");
  });

  test("a command without a value for one mode shows the empty value, never an invented outcome", async () => {
    const measurements = structuredClone(run.measurements);
    const { commands, matrixModes: modes } = measurements.security.destructiveCoverage;
    const labels = loadLabels(HARNESS_ROOT, "en");
    const [first, second] = commands;
    const expected = `| \`${first.id}\` | ${modes
      .map((mode) => (mode === "auto" ? labels["value.empty"] : `\`${first.modes[mode]}\``))
      .join(" | ")} |`;
    delete first.modes.auto;
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes(expected), "the row with the missing value is wrong");
    assert.equal(report.includes("undefined"), false, "an undefined value reached the report");
    // Positive control: the next command, which has a value for every mode, keeps its own cells.
    const secondRow = `| \`${second.id}\` | ${modes.map((mode) => `\`${second.modes[mode]}\``).join(" | ")} |`;
    assert.ok(report.includes(secondRow), "the complete row of the next command is missing");
  });
});

describe("depth levels", () => {
  // Real scans of the same fixture at quick and at deep. The standard run is the run of the file, as in the golden reports.
  let quickRun = null;
  let deepRun = null;
  before(async () => {
    quickRun = await makeRun({ depth: "quick" });
    deepRun = await makeRun({ depth: "deep" });
  });
  after(() => {
    quickRun?.cleanup();
    deepRun?.cleanup();
  });

  const labelsEn = loadLabels(HARNESS_ROOT, "en");
  const labelsEs = loadLabels(HARNESS_ROOT, "es");
  // The golden findings of a file, without the judgment findings: a quick run cannot cite them.
  const measuredFindings = (name) => {
    const findings = readGoldenFindings(name);
    return { ...findings, findings: findings.findings.filter((item) => item.kind === "measured") };
  };
  // The value of the Depth field: the label of the level, and at quick the note that the judgment rules are not applied.
  const depthValue = (labels, depth) =>
    depth === "quick" ? labels["header.depthNoJudgment"].replace("{level}", labels["depth.quick"]) : labels[`depth.${depth}`];

  test("the header shows the depth of the run in the Markdown and the HTML report, for quick, standard and deep", async () => {
    const cases = [
      { depth: "quick", measurements: quickRun.measurements, findings: measuredFindings("findings.en.json") },
      { depth: "standard", measurements: run.measurements, findings: readGoldenFindings("findings.en.json") },
      { depth: "deep", measurements: deepRun.measurements, findings: readGoldenFindings("findings.en.json") },
    ];
    for (const { depth, measurements, findings } of cases) {
      const dir = makeCase({ findings, measurements });
      const result = await runRender([dir]);
      assert.equal(result.code, 0, `${depth}: ${result.stderr}`);
      const value = depthValue(labelsEn, depth);
      assert.ok(reportOf(dir).includes(`- **${labelsEn["header.depth"]}:** ${value}\n`), `${depth}: the Markdown header`);
      assert.ok(htmlOf(dir).includes(`<dt>${labelsEn["header.depth"]}</dt><dd>${value}</dd>`), `${depth}: the HTML header`);
    }
  });

  test("the Spanish quick report says the depth and the note in Spanish, in both files", async () => {
    const dir = makeCase({ findings: measuredFindings("findings.es.json"), measurements: quickRun.measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.ok(reportOf(dir).includes("- **Profundidad:** Rápida (reglas de juicio no aplicadas)\n"), "the Spanish Markdown header");
    assert.ok(htmlOf(dir).includes("<dt>Profundidad</dt><dd>Rápida (reglas de juicio no aplicadas)</dd>"), "the Spanish HTML header");
  });

  test("positive control: standard has no note, and a scan that gives no depth is the standard golden report", async () => {
    const standard = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([standard])).code, 0);
    assert.equal(reportOf(standard).includes("judgment rules not applied"), false, "the standard report has the quick note");

    const older = structuredClone(run.measurements);
    delete older.depth;
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: older });
    assert.equal((await runRender([dir])).code, 0);
    assert.equal(reportOf(dir), readGolden("report.en.md"), "a scan with no depth differs from the standard golden Markdown");
    assert.equal(htmlOf(dir), readGolden("report.en.html"), "a scan with no depth differs from the standard golden HTML");
  });

  test("a quick report with a judgment finding fails validation with the quick-depth error, and writes no report", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: quickRun.measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, /error: findings\[\d+\] \(RUL-\d+\), field findings\[\d+\]\.rule: quick depth: judgment rules are not applied/);
    assert.equal(reportOf(dir), null);
    assert.equal(htmlOf(dir), null);
  });

  test("a quick report shows the standard matrix, with no location rows (positive control of the deep matrix)", async () => {
    const dir = makeCase({ findings: measuredFindings("findings.en.json"), measurements: quickRun.measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes(matrixTableOf(quickRun.measurements, labelsEn)), "the standard matrix is missing");
    assert.equal(report.includes(labelsEn["limits.matrixLocations"]), false, "the location legend is shown at quick");
  });

  test("deep renders the full matrix, one row per command and location, with the location labels and the legend", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: deepRun.measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes(deepMatrixTableOf(deepRun.measurements, labelsEn)), "the deep matrix is missing or differs");
    assert.ok(report.includes(labelsEn["limits.matrixLocations"]), "the legend of the locations is missing");
    assert.equal(report.includes(matrixTableOf(deepRun.measurements, labelsEn)), false, "the standard matrix is shown as well");
    assert.ok(htmlOf(dir).includes(`<th scope="col">${labelsEn["table.location"]}</th>`), "the HTML table has no Location column");
  });

  test("a Spanish deep report shows the Spanish location rows and legend, and the Spanish depth", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json"), measurements: deepRun.measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes(deepMatrixTableOf(deepRun.measurements, labelsEs)), "the Spanish deep matrix is missing");
    assert.ok(report.includes(labelsEs["limits.matrixLocations"]), "the Spanish legend is missing");
    assert.ok(report.includes("- **Profundidad:** Profunda\n"), "the Spanish depth of the header");
  });

  test("positive control: standard shows each command at its own location only, with no location column, row or legend", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.equal(report.includes(`| ${labelsEn["table.location"]} |`), false, "a Location column");
    assert.equal(report.includes(`| ${labelsEn["location.critical"]} |`), false, "a location row");
    assert.equal(report.includes(labelsEn["limits.matrixLocations"]), false, "the location legend");
  });

  test("a depth that is not quick, standard or deep is a TypeError in the model (positive control: the golden depth builds)", () => {
    const catalog = readCatalog(HARNESS_ROOT, loadRules(HARNESS_ROOT));
    const labels = loadLabels(HARNESS_ROOT, "en");
    const findings = readGoldenFindings("findings.en.json");
    const fast = structuredClone(run.measurements);
    fast.depth = "fast";
    assert.throws(
      () => buildReportModel({ measurements: fast, findings, catalog, labels }),
      /a depth that is not quick, standard or deep/,
    );
    assert.ok(buildReportModel({ measurements: run.measurements, findings, catalog, labels }).sections.header.length > 0);
  });
});

describe("privacy", () => {
  test("a path of the target that the agent writes is shown as <target>", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[4].summary = `The file is at ${path.join(run.fixture.root, ".claude", "settings.json")}, which is small.`;
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    assert.ok(report.includes("<target>"));
    assert.deepEqual(absolutePathsIn(report), []);
  });

  test("the report has no absolute path even when the agent quotes one, in either file", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[0].recommendation = `Move the folder ${os.homedir()} out of the allow list.`;
    const dir = makeCase({ findings });
    assert.equal((await runRender([dir])).code, 0);
    assert.deepEqual(absolutePathsIn(reportOf(dir)), []);
    assert.deepEqual(absolutePathsIn(htmlOf(dir)), []);
  });
});

describe("warnings and errors", () => {
  test("a measured finding that no finding cites is shown and named on the console", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stderr, /warning: measured finding mf-3 \(SEC-03\) is not cited by findings\.json/);
    assert.match(reportOf(dir), /The scan measured this, but findings\.json does not cite it/);
  });

  // The scan's measurements with the flags given, and what they skipped outside the target: the user layer's warnings and the
  // parent-folder files that were not read. The file that was read is there too, as a positive control.
  function withSkippedOutside() {
    const measurements = structuredClone(run.measurements);
    measurements.meta.include = { userLayer: true, ancestors: true };
    measurements.userLayer = {
      root: "~/.claude",
      found: true,
      memory: [],
      settings: {
        path: "~/.claude/settings.json",
        found: true,
        lines: 1,
        permissions: { allow: [], ask: [], deny: [] },
        defaultMode: null,
        hooks: { count: 0, evaluated: false },
      },
      skills: [],
      subagents: [],
      warnings: [
        { source: "fs", path: "~/.claude/rules/leak.md", reason: "outside-root" },
        { source: "user-layer", path: "~/.claude/settings.json", reason: "invalid-json" },
      ],
      notes: [],
    };
    measurements.context.ancestors = [
      { path: "../../.claude/AGENTS.md", bytes: 70, read: false, reason: "user-layer" },
      { path: "../CLAUDE.md", bytes: 500, read: true, lines: 3, estTokens: 30, loadMode: "always", loadReason: "x" },
    ];
    return measurements;
  }

  // The table row that holds a text, or undefined when no row does.
  const rowWith = (report, text) => report.split("\n").find((line) => line.startsWith("|") && line.includes(text));

  for (const language of ["en", "es"]) {
    test(`the skipped items outside the target are in the limits table, each with its layer mark and reason (${language})`, async () => {
      const labels = loadLabels(HARNESS_ROOT, language);
      const dir = makeCase({ findings: readGoldenFindings(`findings.${language}.json`), measurements: withSkippedOutside() });
      const result = await runRender([dir]);
      assert.equal(result.code, 0, result.stderr);
      const report = reportOf(dir);

      const userRow = rowWith(report, "`~/.claude/rules/leak.md`");
      assert.ok(userRow, "the user-layer warning is missing from the limits table");
      assert.ok(userRow.includes(`\`fs\``) && userRow.includes(`(${labels["layer.user"]})`) && userRow.includes("`outside-root`"), userRow);
      const parentRow = rowWith(report, "`../../.claude/AGENTS.md`");
      assert.ok(parentRow, "the unread parent file is missing from the limits table");
      assert.ok(parentRow.includes(`\`memory\``) && parentRow.includes(`(${labels["layer.ancestor"]})`) && parentRow.includes("`user-layer`"), parentRow);
      assert.equal(rowWith(report, "`../CLAUDE.md`"), undefined, "positive control: a parent file that was read is not in the table");
      assert.equal(report.includes(labels["limits.noWarnings"]), false, "the table is not replaced by the no-warning text");
    });
  }

  test("without the flags, the limits table is the scan's own warnings only (positive control: the golden has no layer mark)", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir).includes("(user layer, outside the repository)"), false);
    assert.equal(reportOf(dir).includes("(parent folder, outside the repository)"), false);
  });

  test("a finding that fails validation prints each error, exits 1 and writes no report", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[3].evidence = [{ file: ".claude/settings.json", line: 99 }];
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /error: findings\[3\] \(VER-01\), field findings\[3\]\.evidence\[0\]\.line/);
    assert.match(result.stderr, /no report was written/);
    assert.equal(reportOf(dir), null);
  });

  test("a failed validation writes neither report and leaves older report.md and report.html byte for byte as they were", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[0].rule = "XXX-99";
    const dir = makeCase({ findings, oldReport: true });
    const result = await runRender([dir]);
    assert.equal(result.code, 1);
    assert.deepEqual(bytesOf(dir), OLD_REPORT);
    assert.deepEqual(bytesOf(dir, HTML), OLD_HTML);
  });

  test("a failed validation writes neither report when no report existed before", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.language = "fr";
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 1);
    assert.deepEqual(fs.readdirSync(dir).sort(), ["findings.json", "measurements.json"]);
  });

  test("an unexpected error after the inputs are read leaves older report.md and report.html byte for byte as they were", async () => {
    // The validator does not check measurementRef, so the failure comes from the renderer (or, while the template is
    // missing, from reading it). Either way the run exits 1 and must not touch either report.
    const measurements = structuredClone(run.measurements);
    measurements.measuredFindings[0].measurementRef = "/security/nothing/here";
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements, oldReport: true });
    const result = await runRender([dir]);
    assert.equal(result.code, 1, result.stderr);
    assert.deepEqual(bytesOf(dir), OLD_REPORT);
    assert.deepEqual(bytesOf(dir, HTML), OLD_HTML);
  });

  test("an unexpected error after the inputs are read writes no report when none existed before", async () => {
    const measurements = structuredClone(run.measurements);
    measurements.measuredFindings[0].measurementRef = "/security/nothing/here";
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 1, result.stderr);
    assert.equal(bytesOf(dir), null);
    assert.equal(bytesOf(dir, HTML), null);
  });

  test("usage errors exit 2 and name the usage", async () => {
    const none = await runRender([]);
    assert.equal(none.code, 2);
    assert.match(none.stderr, /missing the run folder/);
    const two = await runRender([run.runDir, run.runDir]);
    assert.equal(two.code, 2);
    const missingDir = await runRender([path.join(run.fixture.base, "no-such-run")]);
    assert.equal(missingDir.code, 2);
    assert.match(missingDir.stderr, /usage: node scripts\/render-report\.mjs <runDir>/);
  });

  test("a missing or unparsable input file exits 2", async () => {
    const withoutFindings = makeCase({ findings: { findings: [] } });
    fs.rmSync(path.join(withoutFindings, "findings.json"));
    assert.equal((await runRender([withoutFindings])).code, 2);

    const broken = makeCase({ findings: { findings: [] } });
    fs.writeFileSync(path.join(broken, "findings.json"), "{ not json");
    const result = await runRender([broken]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /not valid JSON/);
    assert.equal(reportOf(broken), null);
  });

  test("a measurements.json that is not a scan of this tool exits 2", async () => {
    const dir = makeCase({ findings: { findings: [] }, measurements: { meta: {} } });
    const result = await runRender([dir]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /not a scan of this tool/);
  });
});

describe("the renderer function", () => {
  test("a template with an unknown, a missing or a repeated marker is an error", () => {
    const sections = Object.fromEntries(
      ["header", "summary", "findings", "context", "function2", "limits", "sources", "appendix"].map((name) => [name, name]),
    );
    const complete = Object.keys(sections).map((name) => `{{${name}}}`).join("\n");
    assert.equal(fillTemplate(complete, sections), `${Object.keys(sections).join("\n")}`);
    assert.throws(() => fillTemplate("{{header}}\n{{nope}}", sections), /unknown marker \{\{nope\}\}/);
    assert.throws(() => fillTemplate("{{header}}", sections), /must have the marker \{\{summary\}\} once, found 0/);
    assert.throws(() => fillTemplate(`${complete}\n{{header}}`, sections), /\{\{header\}\} once, found 2/);
  });

  test("a section text is not read again as a marker", () => {
    const names = ["header", "summary", "findings", "context", "function2", "limits", "sources", "appendix"];
    const sections = Object.fromEntries(names.map((name) => [name, ""]));
    sections.header = "{{summary}}";
    sections.summary = "x";
    const template = names.map((name) => `{{${name}}}`).join("\n");
    // header and summary, then six empty sections, one per line break.
    assert.equal(fillTemplate(template, sections), `{{summary}}\nx${"\n".repeat(6)}`);
  });

  test("missingField names the first field the report needs", () => {
    const copy = structuredClone(run.measurements);
    assert.equal(missingField(copy), null);
    delete copy.code.duplication.filesScanned;
    assert.equal(missingField(copy), "/code/duplication/filesScanned");
    assert.equal(missingField("not an object"), "a JSON object");
  });

  test("a measurementRef that does not resolve is an error", () => {
    const measurements = structuredClone(run.measurements);
    measurements.measuredFindings[0].measurementRef = "/security/nothing/here";
    const catalog = readCatalog(HARNESS_ROOT, loadRules(HARNESS_ROOT));
    const labels = loadLabels(HARNESS_ROOT, "en");
    // The reference is checked before any section is placed, so a template with every marker is enough here.
    const template = MARKERS.map((name) => `{{${name}}}`).join("\n");
    assert.throws(
      () => renderReport({ measurements, findings: readGoldenFindings("findings.en.json"), catalog, labels, template }),
      /does not resolve in measurements\.json/,
    );
  });
});

describe("agents", () => {
  // The scan's measurements with three detected agents, listed by id as the scan writes them. Cursor's kinds come in the
  // given order, which is not the order of KINDS, so its cells must be sorted by KINDS.
  function withAgents(cursorKinds = ["mcp", "instructions", "hooks"]) {
    const kindsByAgent = {
      "agents-md": ["instructions"],
      "claude-code": ["settings", "subagents"],
      cursor: cursorKinds,
    };
    const measurements = structuredClone(run.measurements);
    measurements.agentHarness = {
      registry: "data/agent-harness.json",
      agents: Object.entries(kindsByAgent).map(([id, kinds]) => ({
        id,
        name: id,
        type: id === "agents-md" ? "convention" : "agent",
        verified: true,
        items: kinds.length,
        budget: id === "claude-code" ? "/context/alwaysLoaded" : "unknownStatic",
        unverifiedInBudget: [],
      })),
      items: Object.entries(kindsByAgent).flatMap(([agent, kinds]) =>
        kinds.map((kind, index) => ({ path: `${agent}/${index}`, agent, entry: `${agent}-${index}`, kind })),
      ),
      files: [],
      unknownStatic: [],
    };
    return measurements;
  }

  // The labels of the table, built from the language's labels so that no text of the test is fixed to one language. The rows are
  // withAgents() in its default form: the agents-md, claude-code and cursor rows, in the order of agentHarness.agents.
  const headerRow = (labels) =>
    `| ${[labels["table.agent"], labels["table.evaluated"], labels["table.detectedOnly"]].join(" | ")} |`;
  const agentTableOf = (labels) => {
    const sep = labels["list.separator"];
    const row = (cells) => `| ${cells.join(" | ")} |`;
    return [
      headerRow(labels),
      row(["---", "---", "---"]),
      row([labels["agent.agents-md"], labels["harnessKind.instructions"], labels["value.none"]]),
      row([labels["agent.claude-code"], [labels["harnessKind.settings"], labels["harnessKind.subagents"]].join(sep), labels["value.none"]]),
      row([labels["agent.cursor"], labels["harnessKind.instructions"], [labels["harnessKind.hooks"], labels["harnessKind.mcp"]].join(sep)]),
    ].join("\n");
  };

  test("the header lists one row per detected agent, in order, with the kinds it evaluates and those it does not (en and es)", async () => {
    for (const language of ["en", "es"]) {
      const labels = loadLabels(HARNESS_ROOT, language);
      const dir = makeCase({ findings: readGoldenFindings(`findings.${language}.json`), measurements: withAgents() });
      const result = await runRender([dir]);
      assert.equal(result.code, 0, result.stderr);
      const title = `**${labels["header.agents"]}:**`;
      assert.ok(reportOf(dir).includes(`${title}\n\n${agentTableOf(labels)}\n\n---`), `${language}: the agents table is not in the header`);
    }
  });

  test("an agent with no instructions evaluates nothing and lists its kinds as not evaluated (positive control: Claude Code evaluates all of its kinds)", async () => {
    const labels = loadLabels(HARNESS_ROOT, "en");
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements: withAgents(["hooks"]) });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    const report = reportOf(dir);
    const cursorRow = `| ${labels["agent.cursor"]} | ${labels["value.none"]} | ${labels["harnessKind.hooks"]} |`;
    const claudeRow = `| ${labels["agent.claude-code"]} | ${labels["harnessKind.settings"]}${labels["list.separator"]}${labels["harnessKind.subagents"]} | ${labels["value.none"]} |`;
    assert.ok(report.includes(cursorRow), "the Cursor row is wrong");
    assert.ok(report.includes(claudeRow), "the Claude Code row is wrong");
  });

  test("a scan that detected no agent says so in one field line, with no table (positive control: the golden header has the table)", async () => {
    const labels = loadLabels(HARNESS_ROOT, "en");
    const withoutSection = structuredClone(run.measurements);
    delete withoutSection.agentHarness;
    const emptyList = structuredClone(run.measurements);
    emptyList.agentHarness.agents = [];
    for (const measurements of [withoutSection, emptyList]) {
      const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
      const result = await runRender([dir]);
      assert.equal(result.code, 0, result.stderr);
      const report = reportOf(dir);
      assert.ok(report.includes(`\n- **${labels["header.agents"]}:** ${labels["value.none"]}\n\n---`), "the one field line is missing");
      assert.equal(report.includes(`| ${labels["table.agent"]} | `), false, "an empty table is shown");
    }
    assert.ok(readGolden("report.en.md").includes(headerRow(labels)), "positive control: the golden header has the table");
  });

  for (const language of ["en", "es"]) {
    test(`a finding that names agents shows them as one Agents field, after its impact (${language})`, async () => {
      const labels = loadLabels(HARNESS_ROOT, language);
      const findings = readGoldenFindings(`findings.${language}.json`);
      findings.findings[0].agents = ["claude-code", "cursor"];
      const dir = makeCase({ findings, measurements: withAgents() });
      const result = await runRender([dir]);
      assert.equal(result.code, 0, result.stderr);
      const names = `${labels["agent.claude-code"]}${labels["list.separator"]}${labels["agent.cursor"]}`;
      // The first golden finding is SEC-01, whose measured impact is high.
      const expected = [
        `- **${labels["field.impact"]}:** ${labels["impact.high"]}`,
        `- **${labels["field.agents"]}:** ${names}`,
        `- **${labels["field.evidenceLevel"]}:**`,
      ];
      assert.ok(reportOf(dir).includes(expected.join("\n")), `the Agents field is not after the impact (${language})`);
    });
  }

  test("a measured finding's agents show on the finding that cites it, and on its own when no agent finding cites it (positive control: an own list wins)", async () => {
    const labels = loadLabels(HARNESS_ROOT, "en");
    const measurements = withAgents();
    const id = `mf-${measurements.measuredFindings.length + 1}`;
    measurements.measuredFindings.push({
      id,
      rule: "CTX-07",
      axis: "context",
      impact: "medium",
      measurementRef: "/agentHarness/agents/0/items",
      evidence: [{ file: ".claude/settings.json" }],
      triggers: [],
      agents: ["agents-md"],
    });
    const field = `- **${labels["field.agents"]}:**`;
    const shared = `${field} ${labels["agent.agents-md"]}`;

    // Cited by a CTX-07 finding that names no agent: the measured finding's agents are shown.
    const citing = readGoldenFindings("findings.en.json");
    citing.findings.push({
      rule: "CTX-07",
      axis: "context",
      kind: "measured",
      measuredFindingId: id,
      evidence: [{ file: ".claude/settings.json" }],
      impact: "medium",
      summary: "The shared convention file is not read by this agent.",
      recommendation: "Keep the shared instructions in one file.",
      testInFunction2: null,
    });
    const dirCited = makeCase({ findings: citing, measurements });
    assert.equal((await runRender([dirCited])).code, 0);
    assert.ok(reportOf(dirCited).includes(shared), "the measured agents are missing");
    assert.equal(reportOf(dirCited).split(field).length - 1, 1, "only the CTX-07 finding names agents");

    // Not cited: the measured finding is shown as not explained, with its agents.
    const dirUncited = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
    assert.equal((await runRender([dirUncited])).code, 0);
    assert.ok(reportOf(dirUncited).includes(shared), "the uncited measured finding loses its agents");

    // Its own list wins over the measured one.
    citing.findings[citing.findings.length - 1].agents = ["cursor"];
    const dirOwn = makeCase({ findings: citing, measurements });
    assert.equal((await runRender([dirOwn])).code, 0);
    assert.ok(reportOf(dirOwn).includes(`${field} ${labels["agent.cursor"]}`), "the own list is missing");
    assert.equal(reportOf(dirOwn).includes(shared), false, "the measured list is shown beside the own list");
  });

  test("the golden reports have no Agents field, since no golden finding names agents (positive control)", () => {
    for (const language of ["en", "es"]) {
      const field = `- **${loadLabels(HARNESS_ROOT, language)["field.agents"]}:**`;
      assert.equal(readGolden(`report.${language}.md`).includes(field), false, `${language}: the golden report has an Agents field`);
    }
  });

  test("a finding that names an agent the scan did not detect fails validation and writes no report", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[0].agents = ["cursor"];
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /error: findings\[0\] \(SEC-01\), field findings\[0\]\.agents\[0\]/);
    assert.equal(reportOf(dir), null);
  });
});

describe("run folders", () => {
  const RUNS_DIR = path.join(HARNESS_ROOT, "runs");
  const TEMPLATES_DIR = path.join(HARNESS_ROOT, "templates");

  // A random name, so that a test never reuses a folder of an earlier run.
  const randomName = (prefix) => `${prefix}-${randomUUID().slice(0, 8)}`;

  test("a run folder outside runs/ and the temp folder exits 2 with the new message, and nothing in it changes", async () => {
    const names = fs.readdirSync(TEMPLATES_DIR).sort();
    const template = fs.readFileSync(path.join(TEMPLATES_DIR, REPORT));

    const result = await runRender([TEMPLATES_DIR]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /^error: folder must be inside runs\/ or the system temp folder: /m);
    assert.deepEqual(fs.readdirSync(TEMPLATES_DIR).sort(), names);
    assert.deepEqual(fs.readFileSync(path.join(TEMPLATES_DIR, REPORT)), template);
  });

  test("a run folder that does not exist outside runs/ and the temp folder exits 2 and is not created", async (t) => {
    const missing = path.join(HARNESS_ROOT, "test", randomName("hxr-not-allowed"));
    t.after(() => fs.rmSync(missing, { recursive: true, force: true }));

    const result = await runRender([missing]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /must be inside runs\//);
    assert.equal(fs.existsSync(missing), false);
  });

  test("a run folder inside runs/ renders to the golden report (positive control)", async (t) => {
    const dir = path.join(RUNS_DIR, randomName("hxr-render"));
    fs.mkdirSync(dir, { recursive: true });
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    writeStableJson(path.join(dir, "measurements.json"), run.measurements);
    fs.writeFileSync(path.join(dir, "findings.json"), `${JSON.stringify(readGoldenFindings("findings.en.json"), null, 2)}\n`);

    const result = await runRender([dir]);

    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.en.md"));
    assert.equal(htmlOf(dir), readGolden("report.en.html"));
  });

  test("a run folder inside runs/ that is a link to a folder outside exits 2 and writes nothing", { skip: symlinkSkip }, async (t) => {
    fs.mkdirSync(RUNS_DIR, { recursive: true });
    const link = path.join(RUNS_DIR, randomName("hxr-render-link"));
    fs.symlinkSync(TEMPLATES_DIR, link, "dir");
    t.after(() => fs.unlinkSync(link));
    const names = fs.readdirSync(TEMPLATES_DIR).sort();

    const result = await runRender([link]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /must be inside runs\//);
    assert.deepEqual(fs.readdirSync(TEMPLATES_DIR).sort(), names);
  });

  test("a report.md that is a link exits 2, and the file it points to is left alone", { skip: symlinkSkip }, async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const target = path.join(run.fixture.base, "kept.md");
    fs.writeFileSync(target, "kept\n");
    fs.symlinkSync(target, path.join(dir, REPORT), "file");

    const result = await runRender([dir]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /not a regular file/);
    assert.equal(fs.readFileSync(target, "utf8"), "kept\n");

    // Positive control: the same run folder without the link renders.
    const plain = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([plain])).code, 0);
  });
});

describe("report files", () => {
  test("a successful run writes report.md and report.html, and names both on the console", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);

    assert.equal(result.code, 0, result.stderr);
    assert.notEqual(reportOf(dir), null);
    assert.notEqual(htmlOf(dir), null);
    const lines = result.stdout.split("\n");
    assert.ok(lines.includes(`report: ${path.join(dir, REPORT)}`), result.stdout);
    assert.ok(lines.includes(`html: ${path.join(dir, HTML)}`), result.stdout);
  });

  test("a report.html that is a folder exits 2, writes no report.md, and the folder is left alone", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const folder = path.join(dir, HTML);
    fs.mkdirSync(folder);
    fs.writeFileSync(path.join(folder, "kept.txt"), "kept\n");

    const result = await runRender([dir]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /not a regular file/);
    assert.equal(reportOf(dir), null);
    assert.deepEqual(fs.readdirSync(folder), ["kept.txt"]);
    assert.equal(fs.readFileSync(path.join(folder, "kept.txt"), "utf8"), "kept\n");

    // Positive control: the same run folder without the folder renders both files.
    const plain = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([plain])).code, 0);
    assert.notEqual(reportOf(plain), null);
    assert.notEqual(htmlOf(plain), null);
  });

  test("a report.html that is a link exits 2, writes no report.md either, and the file it points to is left alone", { skip: symlinkSkip }, async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const target = path.join(run.fixture.base, "kept.html");
    fs.writeFileSync(target, "kept\n");
    fs.symlinkSync(target, path.join(dir, HTML), "file");

    const result = await runRender([dir]);

    assert.equal(result.code, 2, result.stderr);
    assert.match(result.stderr, /not a regular file/);
    assert.equal(reportOf(dir), null);
    assert.equal(fs.readFileSync(target, "utf8"), "kept\n");

    // Positive control: the same run folder without the link renders both files.
    const plain = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([plain])).code, 0);
    assert.notEqual(reportOf(plain), null);
    assert.notEqual(htmlOf(plain), null);
  });
});

describe("report model", () => {
  // The model of the golden run: the same inputs as the golden English report.
  function goldenModel() {
    const catalog = readCatalog(HARNESS_ROOT, loadRules(HARNESS_ROOT));
    const labels = loadLabels(HARNESS_ROOT, "en");
    return buildReportModel({
      measurements: run.measurements,
      findings: readGoldenFindings("findings.en.json"),
      catalog,
      labels,
    });
  }

  // Every node of the model that has a type (runs, blocks and findings), at any depth.
  function typedNodes(value, found = []) {
    if (Array.isArray(value)) value.forEach((item) => typedNodes(item, found));
    else if (value !== null && typeof value === "object") {
      if (typeof value.type === "string") found.push(value);
      Object.values(value).forEach((item) => typedNodes(item, found));
    }
    return found;
  }

  // Every string of the model, at any depth.
  function stringsIn(value, found = []) {
    if (typeof value === "string") found.push(value);
    else if (Array.isArray(value)) value.forEach((item) => stringsIn(item, found));
    else if (value !== null && typeof value === "object") Object.values(value).forEach((item) => stringsIn(item, found));
    return found;
  }

  test("the model round-trips through JSON unchanged", () => {
    const model = goldenModel();
    assert.deepEqual(JSON.parse(JSON.stringify(model)), model);
  });

  test("the model holds the appended line with its raw pipe, and no backslash escape", () => {
    const model = goldenModel();
    const holding = typedNodes(model.sections).filter((node) => node.type === "code" && node.text === APPENDED_LINE);
    assert.equal(holding.length, 1, "the appended line is one code run");
    assert.ok(
      stringsIn(model).every((text) => !text.includes("\\|")),
      "no string of the model holds an escaped pipe",
    );
  });

  test("positive control: the Markdown view of that model escapes the pipe, and is the golden English report", () => {
    const template = fs.readFileSync(path.join(HARNESS_ROOT, "templates", "report.md"), "utf8");
    const markdown = renderMarkdown(goldenModel(), template);
    assert.ok(markdown.includes(`\`\`Never run \`rm -rf \\| git reset --hard\` without asking first.\`\``), APPENDED_LINE);
    assert.equal(markdown, readGolden("report.en.md"));
  });

  test("the code marks of a label are code runs, so no label run holds a backtick (positive control: the setting is code)", () => {
    const nodes = typedNodes(goldenModel().sections);
    assert.ok(
      nodes.filter((node) => node.type === "label").every((node) => !node.text.includes("`")),
      "a label run holds a backtick",
    );
    assert.ok(nodes.some((node) => node.type === "code" && node.text === "defaultMode"));
  });

  test("each finding block carries its rule, its axis and its impact", () => {
    const findings = typedNodes(goldenModel().sections).filter((node) => node.type === "finding");
    assert.ok(findings.length > 0);
    for (const finding of findings) {
      assert.match(finding.ruleId, /^[A-Z]{2,4}-\d{2}$/);
      assert.ok(AXES.includes(finding.axis), finding.axis);
      assert.ok(["high", "medium", "low"].includes(finding.impact), finding.impact);
    }
    assert.ok(findings.some((finding) => finding.ruleId === "SEC-01" && finding.impact === "high"));
  });

  test("renderReport returns the model that buildReportModel builds, and the Markdown of it", () => {
    const template = fs.readFileSync(path.join(HARNESS_ROOT, "templates", "report.md"), "utf8");
    const result = renderReport({
      measurements: run.measurements,
      findings: readGoldenFindings("findings.en.json"),
      catalog: readCatalog(HARNESS_ROOT, loadRules(HARNESS_ROOT)),
      labels: loadLabels(HARNESS_ROOT, "en"),
      template,
    });
    assert.deepEqual(result.model, goldenModel());
    assert.equal(result.markdown, renderMarkdown(result.model, template));
  });
});
