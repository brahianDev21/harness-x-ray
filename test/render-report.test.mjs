import assert from "node:assert/strict";
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

const REPORT = "report.md";

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
