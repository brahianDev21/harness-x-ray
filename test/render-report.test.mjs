import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { writeStableJson } from "../scripts/lib/json-out.mjs";
import { MARKERS, fillTemplate, missingField, renderReport } from "../scripts/lib/report.mjs";
import { readCatalog } from "../scripts/lib/report-catalog.mjs";
import { loadLabels } from "../scripts/lib/report-labels.mjs";
import { loadRules } from "../scripts/lib/findings-validate.mjs";
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
const support = symlinkSupport();
const symlinkSkip = support.supported ? false : support.reason;

let run;

before(async () => {
  run = await makeRun();
});

after(() => run?.cleanup());

// An older report, with bytes that a rewrite would change: CRLF, non-ASCII and Markdown characters.
const OLD_REPORT = Buffer.from("# An older report\r\n\r\nécrit | `code` — kept\r\n", "utf8");

// A run folder with the scan's measurements, the given findings, and optionally an older report.md.
function makeCase({ findings, measurements = run.measurements, oldReport = false }) {
  const dir = fs.mkdtempSync(path.join(run.fixture.base, "case-"));
  writeStableJson(path.join(dir, "measurements.json"), measurements);
  fs.writeFileSync(path.join(dir, "findings.json"), `${JSON.stringify(findings, null, 2)}\n`);
  if (oldReport) fs.writeFileSync(path.join(dir, REPORT), OLD_REPORT);
  return dir;
}

function reportOf(dir) {
  const file = path.join(dir, REPORT);
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
}

// The bytes of report.md, or null when there is no file.
function bytesOf(dir) {
  const file = path.join(dir, REPORT);
  return fs.existsSync(file) ? fs.readFileSync(file) : null;
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
  test("without language, the report is in English and matches the golden English report", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.en.md"));
  });

  test("language en written explicitly gives the same bytes as the English golden report", async () => {
    const findings = { language: "en", ...readGoldenFindings("findings.en.json") };
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.en.md"));
  });

  test("language es gives the golden Spanish report", async () => {
    const dir = makeCase({ findings: readGoldenFindings("findings.es.json") });
    const result = await runRender([dir]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(reportOf(dir), readGolden("report.es.md"));
  });

  test("two renders of the same input give identical bytes", async () => {
    const first = makeCase({ findings: readGoldenFindings("findings.en.json") });
    const second = makeCase({ findings: readGoldenFindings("findings.en.json") });
    assert.equal((await runRender([first])).code, 0);
    assert.equal((await runRender([second])).code, 0);
    assert.equal(reportOf(first), reportOf(second));
  });

  test("the quote with a pipe and a backtick stays one readable code span", () => {
    const report = readGolden("report.en.md");
    assert.ok(report.includes(`\`\`Never run \`rm -rf \\| git reset --hard\` without asking first.\`\``), APPENDED_LINE);
  });

  test("the golden reports hold no absolute path of this machine", () => {
    for (const name of ["report.en.md", "report.es.md"]) {
      assert.deepEqual(absolutePathsIn(readGolden(name)), [], name);
    }
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

describe("permission matrix", () => {
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

  test("the report has no absolute path even when the agent quotes one", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[0].recommendation = `Move the folder ${os.homedir()} out of the allow list.`;
    const dir = makeCase({ findings });
    assert.equal((await runRender([dir])).code, 0);
    assert.deepEqual(absolutePathsIn(reportOf(dir)), []);
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

  test("a failed validation writes nothing and leaves an older report.md byte for byte as it was", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.findings[0].rule = "XXX-99";
    const dir = makeCase({ findings, oldReport: true });
    const result = await runRender([dir]);
    assert.equal(result.code, 1);
    assert.deepEqual(bytesOf(dir), OLD_REPORT);
  });

  test("a failed validation writes nothing when no report existed before", async () => {
    const findings = readGoldenFindings("findings.en.json");
    findings.language = "fr";
    const dir = makeCase({ findings });
    const result = await runRender([dir]);
    assert.equal(result.code, 1);
    assert.deepEqual(fs.readdirSync(dir).sort(), ["findings.json", "measurements.json"]);
  });

  test("an unexpected error after the inputs are read leaves an older report.md byte for byte as it was", async () => {
    // The validator does not check measurementRef, so the failure comes from the renderer (or, while the template is
    // missing, from reading it). Either way the run exits 1 and must not touch report.md.
    const measurements = structuredClone(run.measurements);
    measurements.measuredFindings[0].measurementRef = "/security/nothing/here";
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements, oldReport: true });
    const result = await runRender([dir]);
    assert.equal(result.code, 1, result.stderr);
    assert.deepEqual(bytesOf(dir), OLD_REPORT);
  });

  test("an unexpected error after the inputs are read writes no report when none existed before", async () => {
    const measurements = structuredClone(run.measurements);
    measurements.measuredFindings[0].measurementRef = "/security/nothing/here";
    const dir = makeCase({ findings: readGoldenFindings("findings.en.json"), measurements });
    const result = await runRender([dir]);
    assert.equal(result.code, 1, result.stderr);
    assert.equal(bytesOf(dir), null);
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
