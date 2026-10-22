import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { formatIssue, loadRules, validateFindings } from "../scripts/lib/findings-validate.mjs";
import { isMasked, mask } from "../scripts/lib/secret-patterns.mjs";
import { makeFixture, symlinkSupport } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const PERMISSIVE = path.join(TEST_DIR, "fixtures", "permissive");
const RULES = loadRules(HARNESS_ROOT);
// A password-shaped value, built here so that the literal is not committed in this file.
const PLAIN_SECRET = ["hunter", "2", "hunter", "2", "hunter", "2"].join("");

// Runs the command line through execFile (never a shell). Resolves with the exit code and the output.
async function runScan(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [SCAN_SCRIPT, ...args], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

// A copy of a fixture (made from the description) scanned with the command line. The extra arguments, such as --depth quick,
// are added to the command line. Returns the copy and its measurements. The caller calls cleanup().
async function scanFixture(description, args = []) {
  const fixture = makeFixture(description);
  const out = path.join(fixture.base, "out");
  const result = await runScan([fixture.root, "--out", out, ...args]);
  if (result.code !== 0) {
    fixture.cleanup();
    throw new Error(`the scan failed: ${result.stderr}`);
  }
  const measurements = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  return { fixture, measurements, cleanup: fixture.cleanup };
}

// The 1-based number of the first line of a file of the permissive fixture that contains needle.
function lineOf(relPath, needle) {
  const lines = fs.readFileSync(path.join(PERMISSIVE, relPath), "utf8").split("\n");
  const index = lines.findIndex((line) => line.includes(needle));
  if (index === -1) throw new Error(`"${needle}" is not in ${relPath}`);
  return index + 1;
}

// The id of the first measured finding of a rule in the scan.
function measuredIdOf(measurements, rule) {
  const found = measurements.measuredFindings.find((item) => item.rule === rule);
  assert.ok(found, `the scan has no measured finding of ${rule}`);
  return found.id;
}

// A findings.json that passes against the permissive scan: a measured finding with a quote that has extra spaces, a judgment
// finding with a range, a file-only evidence, a masked token in the text, and no language (so en).
function goodFindings(measurements) {
  const token = ["sk", "ant", "api03", "B".repeat(24)].join("-");
  return {
    findings: [
      {
        rule: "SEC-01",
        axis: "security",
        kind: "measured",
        measuredFindingId: measuredIdOf(measurements, "SEC-01"),
        evidence: [
          {
            file: ".claude/settings.json",
            line: lineOf(".claude/settings.json", '"allow"'),
            quote: '"allow":   ["Bash(git *)"]',
          },
        ],
        impact: "high",
        summary: `The allow rule passes git commands without a prompt. The key ${mask(token, "sk-ant-")} is shown masked.`,
        recommendation: "Narrow the allow rule to the git commands the team reads.",
        testInFunction2: null,
      },
      {
        rule: "SEC-02",
        axis: "security",
        kind: "measured",
        measuredFindingId: measuredIdOf(measurements, "SEC-02"),
        evidence: [{ file: ".claude/settings.json", line: lineOf(".claude/settings.json", '"defaultMode"') }],
        impact: "high",
        summary: "Destructive git commands pass without a prompt.",
        recommendation: "Put the destructive forms in deny, and drop acceptEdits from the project settings.",
        testInFunction2: null,
      },
      {
        rule: "RUL-01",
        axis: "instructions",
        kind: "judgment",
        measuredSupport: [measuredIdOf(measurements, "SEC-01")],
        evidence: [
          {
            file: ".claude/agents/edit-helper.md",
            line: lineOf(".claude/agents/edit-helper.md", "Make the requested edit"),
            quote: "Make the requested edit  and report what changed.",
          },
          { file: ".claude/agents/fast-runner.md" },
        ],
        impact: "low",
        summary: "The subagent prompt is one generic sentence.",
        recommendation: "Name the files the subagent may edit and the checks it must run.",
        testInFunction2: "Compare the diff size with and without the sentence over the same tasks.",
      },
    ],
  };
}

// Checks that an issue is printed with its finding and its field, and returns it.
function expectIssue(list, { index, field, rule, message }) {
  const issue = list.find((item) => item.field === field);
  const seen = list.map((item) => item.field).join(", ") || "(none)";
  assert.ok(issue, `no issue on field ${field}; the fields with issues are: ${seen}`);
  assert.equal(issue.finding, index, `wrong finding for ${field}`);
  if (rule !== undefined) assert.equal(issue.rule, rule, `wrong rule for ${field}`);
  if (message !== undefined) assert.match(issue.message, message);
  const line = formatIssue(issue);
  const where = index === null ? "findings.json" : `findings[${index}]`;
  assert.ok(line.includes(where), `the printed issue does not name ${where}: ${line}`);
  assert.ok(line.includes(field), `the printed issue does not name ${field}: ${line}`);
  return issue;
}

function validate(findings, measurements, targetRoot) {
  return validateFindings({ findings, measurements, rules: RULES, targetRoot });
}

describe("validator: findings.json against a real scan of the permissive fixture", () => {
  let scanned = null;
  before(async () => {
    scanned = await scanFixture({ fromDir: PERMISSIVE });
  });
  after(() => {
    scanned?.cleanup();
  });
  const targetOf = () => scanned.measurements.meta.targetRoot;

  test("a good findings.json has no errors and no warnings, and its language is en", () => {
    const findings = goodFindings(scanned.measurements);
    assert.equal(findings.language, undefined, "the good case leaves language out");
    const result = validate(findings, scanned.measurements, targetOf());
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.warnings, []);
    assert.equal(result.ok, true);
    assert.equal(result.language, "en");
  });

  test("language es is accepted and returned", () => {
    const findings = { language: "es", ...goodFindings(scanned.measurements) };
    const result = validate(findings, scanned.measurements, targetOf());
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    assert.equal(result.language, "es");
  });

  test("an empty findings list is valid", () => {
    const result = validate({ findings: [] }, scanned.measurements, targetOf());
    assert.deepEqual(result, { ok: true, language: "en", errors: [], warnings: [] });
  });

  test("a measured finding whose impact differs from its measured finding is a warning, not an error", () => {
    const findings = goodFindings(scanned.measurements);
    findings.findings[0].impact = "low";
    const result = validate(findings, scanned.measurements, targetOf());
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    expectIssue(result.warnings, {
      index: 0,
      field: "findings[0].impact",
      rule: "SEC-01",
      message: /has impact high/,
    });
  });

  // One bad findings.json per error type. Each case changes the good one and names the error it must produce.
  const cases = [
    ["a rule that is not in the catalog", (f) => { f.findings[0].rule = "XYZ-01"; },
      { index: 0, field: "findings[0].rule", message: /not a rule of the catalog/ }],
    ["an axis that differs from the rule", (f) => { f.findings[0].axis = "code"; },
      { index: 0, field: "findings[0].axis", rule: "SEC-01", message: /must be "security"/ }],
    ["a kind that differs from the rule", (f) => { f.findings[0].kind = "judgment"; delete f.findings[0].measuredFindingId; },
      { index: 0, field: "findings[0].kind", rule: "SEC-01", message: /must be "measured"/ }],
    ["a measured finding without measuredFindingId", (f) => { delete f.findings[0].measuredFindingId; },
      { index: 0, field: "findings[0].measuredFindingId", rule: "SEC-01", message: /required for a measured finding/ }],
    ["a measuredFindingId that the scan does not have", (f) => { f.findings[0].measuredFindingId = "mf-999"; },
      { index: 0, field: "findings[0].measuredFindingId", rule: "SEC-01", message: /not a measured finding/ }],
    ["a measuredFindingId of another rule", (f, m) => { f.findings[0].measuredFindingId = measuredIdOf(m, "SEC-02"); },
      { index: 0, field: "findings[0].measuredFindingId", rule: "SEC-01", message: /is a finding of SEC-02/ }],
    ["a measuredSupport id that the scan does not have", (f) => { f.findings[2].measuredSupport = ["mf-999"]; },
      { index: 2, field: "findings[2].measuredSupport[0]", rule: "RUL-01", message: /not a measured finding/ }],
    ["measuredSupport on a measured finding", (f) => { f.findings[0].measuredSupport = ["mf-1"]; },
      { index: 0, field: "findings[0].measuredSupport", rule: "SEC-01", message: /only for judgment/ }],
    ["measuredFindingId on a judgment finding", (f, m) => { f.findings[2].measuredFindingId = measuredIdOf(m, "SEC-01"); },
      { index: 2, field: "findings[2].measuredFindingId", rule: "RUL-01", message: /only for measured/ }],
    ["an evidence file with a .. segment", (f) => { f.findings[2].evidence[0].file = "../outside/secret.txt"; },
      { index: 2, field: "findings[2].evidence[0].file", rule: "RUL-01", message: /\.\. segments/ }],
    ["an absolute evidence file", (f) => { f.findings[2].evidence[0].file = "/etc/hosts"; },
      { index: 2, field: "findings[2].evidence[0].file", rule: "RUL-01", message: /not an absolute path/ }],
    ["a drive-letter evidence file", (f) => { f.findings[2].evidence[0].file = "C:/Windows/win.ini"; },
      { index: 2, field: "findings[2].evidence[0].file", rule: "RUL-01", message: /not an absolute path/ }],
    ["an evidence file with backslashes", (f) => { f.findings[0].evidence[0].file = ".claude\\settings.json"; },
      { index: 0, field: "findings[0].evidence[0].file", rule: "SEC-01", message: /backslashes/ }],
    ["an empty evidence file", (f) => { f.findings[0].evidence[0].file = ""; },
      { index: 0, field: "findings[0].evidence[0].file", rule: "SEC-01", message: /is blank/ }],
    ["an evidence file that does not exist", (f) => { f.findings[2].evidence[0].file = "CLAUDE.md"; },
      { index: 2, field: "findings[2].evidence[0].file", rule: "RUL-01", message: /does not exist in the target/ }],
    ["an evidence folder without a line", (f) => { f.findings[0].evidence[0] = { file: ".claude" }; },
      { index: 0, field: "findings[0].evidence[0].file", rule: "SEC-01", message: /is a folder/ }],
    ["an evidence folder with a line", (f) => { f.findings[0].evidence[0].file = ".claude"; },
      { index: 0, field: "findings[0].evidence[0].file", rule: "SEC-01", message: /is not a regular file/ }],
    ["a line past the end of the file", (f) => { f.findings[0].evidence[0].line = 99; },
      { index: 0, field: "findings[0].evidence[0].line", rule: "SEC-01", message: /past the end of/ }],
    ["a line of zero", (f) => { f.findings[0].evidence[0].line = 0; },
      { index: 0, field: "findings[0].evidence[0].line", rule: "SEC-01", message: /whole number from 1/ }],
    ["a line that is not a whole number", (f) => { f.findings[0].evidence[0].line = 1.5; },
      { index: 0, field: "findings[0].evidence[0].line", rule: "SEC-01", message: /whole number from 1/ }],
    ["an endLine before line", (f) => { f.findings[2].evidence[0].endLine = 2; },
      { index: 2, field: "findings[2].evidence[0].endLine", rule: "RUL-01", message: /not be before line/ }],
    ["an endLine without line", (f) => { f.findings[2].evidence[1] = { file: ".claude/agents/fast-runner.md", endLine: 2 }; },
      { index: 2, field: "findings[2].evidence[1].endLine", rule: "RUL-01", message: /needs line/ }],
    ["an endLine past the end of the file", (f) => { f.findings[0].evidence[0] = { file: ".claude/settings.json", line: 1, endLine: 99 }; },
      { index: 0, field: "findings[0].evidence[0].endLine", rule: "SEC-01", message: /past the end of/ }],
    ["a quote that is not on the line", (f) => { f.findings[0].evidence[0].quote = "Bash(npm publish)"; },
      { index: 0, field: "findings[0].evidence[0].quote", rule: "SEC-01", message: /does not appear on line/ }],
    ["a quote that is only outside the range", (f) => { f.findings[2].evidence[0] = { file: ".claude/agents/edit-helper.md", line: 1, endLine: 2, quote: "Make the requested edit" }; },
      { index: 2, field: "findings[2].evidence[0].quote", rule: "RUL-01", message: /does not appear on lines 1-2/ }],
    ["a quote without a line", (f) => { f.findings[0].evidence[0] = { file: ".claude/settings.json", quote: '"allow"' }; },
      { index: 0, field: "findings[0].evidence[0].quote", rule: "SEC-01", message: /needs line/ }],
    ["a blank quote", (f) => { f.findings[0].evidence[0].quote = "   "; },
      { index: 0, field: "findings[0].evidence[0].quote", rule: "SEC-01", message: /is blank/ }],
    ["an impact outside high, medium and low", (f) => { f.findings[0].impact = "critical"; },
      { index: 0, field: "findings[0].impact", rule: "SEC-01", message: /high, medium or low/ }],
    ["an empty summary", (f) => { f.findings[0].summary = ""; },
      { index: 0, field: "findings[0].summary", rule: "SEC-01", message: /is blank/ }],
    ["a blank recommendation", (f) => { f.findings[1].recommendation = " \n "; },
      { index: 1, field: "findings[1].recommendation", rule: "SEC-02", message: /is blank/ }],
    ["a missing recommendation", (f) => { delete f.findings[0].recommendation; },
      { index: 0, field: "findings[0].recommendation", rule: "SEC-01", message: /missing required field/ }],
    ["a missing testInFunction2", (f) => { delete f.findings[0].testInFunction2; },
      { index: 0, field: "findings[0].testInFunction2", rule: "SEC-01", message: /missing required field/ }],
    ["a testInFunction2 that is not text or null", (f) => { f.findings[2].testInFunction2 = 3; },
      { index: 2, field: "findings[2].testInFunction2", rule: "RUL-01", message: /text or null/ }],
    ["a misspelled finding field", (f) => { f.findings[0].summry = f.findings[0].summary; delete f.findings[0].summary; },
      { index: 0, field: "findings[0].summry", rule: "SEC-01", message: /unknown field/ }],
    ["an unknown evidence field", (f) => { f.findings[0].evidence[0].lines = 3; },
      { index: 0, field: "findings[0].evidence[0].lines", rule: "SEC-01", message: /unknown field/ }],
    ["a finding that is not an object", (f) => { f.findings[1] = "SEC-02"; },
      { index: 1, field: "findings[1]", message: /must be an object/ }],
    ["a raw token in the summary", (f, m, token) => { f.findings[0].summary += ` Key ${token}.`; },
      { index: 0, field: "findings[0].summary", rule: "SEC-01", message: /not masked \(anthropic-api-key\)/ }],
    ["a raw generic secret in the recommendation", (f) => { f.findings[1].recommendation = `Set password = ${PLAIN_SECRET} in the config.`; },
      { index: 1, field: "findings[1].recommendation", rule: "SEC-02", message: /not masked \(generic-assignment\)/ }],
  ];
  for (const [name, mutate, expected] of cases) {
    test(`an error for ${name}, which names the finding and the field`, () => {
      const token = ["sk", "ant", "api03", "A".repeat(24)].join("-");
      const findings = goodFindings(scanned.measurements);
      mutate(findings, scanned.measurements, token);
      const result = validate(findings, scanned.measurements, targetOf());
      assert.equal(result.ok, false, "the validator must reject this findings.json");
      const issue = expectIssue(result.errors, expected);
      assert.ok(!formatIssue(issue).includes("AAAA"), "the printed error must not show a secret value");
    });
  }

  test("a top-level error names the file and its field, and an unknown language gives no language", () => {
    const findings = goodFindings(scanned.measurements);
    findings.language = "fr";
    findings.version = 2;
    const result = validate(findings, scanned.measurements, targetOf());
    assert.equal(result.ok, false);
    assert.equal(result.language, null);
    expectIssue(result.errors, { index: null, field: "language", message: /must be "en" or "es"/ });
    expectIssue(result.errors, { index: null, field: "version", message: /unknown field/ });
  });

  test("a findings field that is not a list is an error named findings", () => {
    const result = validate({ findings: "SEC-01" }, scanned.measurements, targetOf());
    expectIssue(result.errors, { index: null, field: "findings", message: /must be a list/ });
  });

  test("a masked token in the text passes, and a raw token in the same place fails", () => {
    const token = ["sk", "ant", "api03", "C".repeat(24)].join("-");
    const masked = goodFindings(scanned.measurements);
    masked.findings[0].summary = `Key ${mask(token, "sk-ant-")} is shown masked.`;
    assert.equal(validate(masked, scanned.measurements, targetOf()).ok, true);

    const raw = goodFindings(scanned.measurements);
    raw.findings[0].summary = `Key ${token} is shown raw.`;
    const result = validate(raw, scanned.measurements, targetOf());
    expectIssue(result.errors, { index: 0, field: "findings[0].summary", rule: "SEC-01", message: /anthropic-api-key/ });
    assert.ok(!JSON.stringify(result.errors).includes(token), "the raw token must not be printed");
  });

  test("a masked generic value with a registered prefix passes, as mask() gives it", () => {
    const value = `github_pat_${"D".repeat(22)}`;
    const masked = goodFindings(scanned.measurements);
    masked.findings[1].recommendation = `Rotate token=${mask(value, "github_pat_")} before the next release.`;
    assert.equal(validate(masked, scanned.measurements, targetOf()).ok, true);

    const raw = goodFindings(scanned.measurements);
    raw.findings[1].recommendation = `Rotate token=${value} before the next release.`;
    const result = validate(raw, scanned.measurements, targetOf());
    expectIssue(result.errors, { index: 1, field: "findings[1].recommendation", rule: "SEC-02", message: /generic-assignment/ });
  });

  test("a masked short generic value passes, and so does a quote written as the file shows it", () => {
    const findings = goodFindings(scanned.measurements);
    findings.findings[1].recommendation = `Set password = ${mask(PLAIN_SECRET)} in the config.`;
    assert.equal(validate(findings, scanned.measurements, targetOf()).ok, true);
  });

  test("a finding with no evidence file is valid, because an absence has nothing to cite", () => {
    const findings = goodFindings(scanned.measurements);
    findings.findings[1].evidence = [];
    assert.equal(validate(findings, scanned.measurements, targetOf()).ok, true);
  });
});

describe("validator: the depth of the scan", () => {
  let scanned = null;
  before(async () => {
    scanned = await scanFixture({ fromDir: PERMISSIVE });
  });
  after(() => {
    scanned?.cleanup();
  });
  const targetOf = () => scanned.measurements.meta.targetRoot;
  // The measurements of the scan at another depth, or with no depth at all (a scan from before the field existed).
  const atDepth = (depth) => {
    const measurements = structuredClone(scanned.measurements);
    if (depth === undefined) delete measurements.depth;
    else measurements.depth = depth;
    return measurements;
  };
  // The findings that a quick scan can cite: the measured ones only.
  const measuredOnly = (findings) => ({ ...findings, findings: findings.findings.filter((item) => item.kind === "measured") });

  test("a judgment finding is an error at quick depth, with the quick-judgment code and its field named", () => {
    const result = validate(goodFindings(scanned.measurements), atDepth("quick"), targetOf());
    assert.equal(result.ok, false, "a quick scan must not accept a judgment finding");
    assert.deepEqual(result.errors.map((issue) => issue.finding), [2], "only the judgment finding fails");
    const issue = expectIssue(result.errors, {
      index: 2,
      field: "findings[2].rule",
      rule: "RUL-01",
      message: /quick depth: judgment rules are not applied/,
    });
    assert.equal(issue.code, "quick-judgment");
  });

  test("positive control: the same judgment finding passes at standard depth and with no depth", () => {
    for (const depth of ["standard", undefined]) {
      const result = validate(goodFindings(scanned.measurements), atDepth(depth), targetOf());
      assert.deepEqual(result.errors, [], `depth ${depth ?? "(none)"}`);
      assert.equal(result.ok, true, `depth ${depth ?? "(none)"}`);
    }
  });

  test("positive control: measured findings pass at quick depth", () => {
    const result = validate(measuredOnly(goodFindings(scanned.measurements)), atDepth("quick"), targetOf());
    assert.deepEqual(result.errors, []);
    assert.equal(result.ok, true);
  });

  test("an error that has no code has code null, and the quick check does not add one to it", () => {
    const findings = goodFindings(scanned.measurements);
    findings.findings[0].rule = "XYZ-01";
    const result = validate(findings, atDepth("quick"), targetOf());
    const issue = expectIssue(result.errors, { index: 0, field: "findings[0].rule", message: /not a rule of the catalog/ });
    assert.equal(issue.code, null);
  });

  test("a real quick scan writes depth quick, and its judgment finding fails validation", async () => {
    const quick = await scanFixture({ fromDir: PERMISSIVE }, ["--depth", "quick"]);
    try {
      assert.equal(quick.measurements.depth, "quick");
      const result = validate(goodFindings(quick.measurements), quick.measurements, quick.measurements.meta.targetRoot);
      expectIssue(result.errors, { index: 2, field: "findings[2].rule", rule: "RUL-01", message: /judgment rules are not applied/ });
    } finally {
      quick.cleanup();
    }
  });
});

describe("validator: numbers in the free text give warnings, never errors", () => {
  // A scan is not needed: the findings below cite no file, and the numbers come from this object.
  const measurements = {
    target: { fileCount: 2300 },
    context: { alwaysLoaded: { estTokensTotal: 1234 } },
    ratio: 0.37,
    gap: 3.5,
  };
  const numberFindings = (summary, recommendation = "Keep the file short.", testInFunction2 = null) => ({
    findings: [
      {
        rule: "RUL-01",
        axis: "instructions",
        kind: "judgment",
        evidence: [],
        impact: "low",
        summary,
        recommendation,
        testInFunction2,
      },
    ],
  });
  const warningsOf = (summary) => {
    const result = validate(numberFindings(summary), measurements, HARNESS_ROOT);
    assert.equal(result.ok, true, JSON.stringify(result.errors));
    return result.warnings.map((item) => item.message);
  };

  test("numbers that the measurements hold give no warning, in every thousands and decimal form", () => {
    for (const text of ["2,300 files", "2.300 files", "2300 files", "1,234 tokens", "1.234 tokens", "0,37 ratio", "0.37 ratio", "3.5 gap"]) {
      assert.deepEqual(warningsOf(text), [], text);
    }
  });

  test("a number that the measurements do not hold gives a warning", () => {
    const messages = warningsOf("The target has 7,777 files and a gap of 9.876.");
    assert.equal(messages.length, 2);
    assert.match(messages[0], /number 7,777 does not appear/);
    assert.match(messages[1], /number 9\.876 does not appear/);
  });

  test("ids, file references, dates and versions give no warning", () => {
    const text = [
      "Rules SEC-02 and COD-04 cite mf-99999 and cand-88888.",
      "See .claude/settings.json, CLAUDE.md:4444-5555 and docs/v3/guide.md.",
      "Scanned on 2026-10-18 with harness-x-ray 2.1.277.",
      "The folder src/2024/x is not a number.",
    ].join(" ");
    assert.deepEqual(warningsOf(text), []);
  });

  test("the same heuristic applies to the recommendation and to testInFunction2", () => {
    const result = validate(
      numberFindings("Fine.", "Cut it to 4321 lines.", "Run 5555 sessions."),
      measurements,
      HARNESS_ROOT,
    );
    assert.equal(result.ok, true);
    expectIssue(result.warnings, { index: 0, field: "findings[0].recommendation", rule: "RUL-01", message: /number 4321/ });
    expectIssue(result.warnings, { index: 0, field: "findings[0].testInFunction2", rule: "RUL-01", message: /number 5555/ });
  });
});

describe("validator: the target is read only for evidence, and only through safe-fs", () => {
  test("a link that points out of the target is an error, and nothing outside the target is opened", { skip: symlinkSupport().supported ? false : symlinkSupport().reason }, (t) => {
    const sentinel = "OUTSIDE-SENTINEL-7f3a";
    const fixture = makeFixture({
      files: { "inside.txt": "inside line\n" },
      outside: { "secret.txt": `${sentinel}\n` },
      symlinks: [{ path: "link.txt", target: "../outside/secret.txt" }],
    });
    t.after(fixture.cleanup);
    const opened = [];
    const realOpen = fs.openSync;
    const realRead = fs.readFileSync;
    t.mock.method(fs, "openSync", (file, ...rest) => {
      opened.push(String(file));
      return realOpen(file, ...rest);
    });
    t.mock.method(fs, "readFileSync", (file, ...rest) => {
      opened.push(String(file));
      return realRead(file, ...rest);
    });

    const judgment = (evidence) => ({
      findings: [{ rule: "RUL-01", axis: "instructions", kind: "judgment", evidence, impact: "low", summary: "A check.", recommendation: "A change.", testInFunction2: null }],
    });
    const linked = validateFindings({
      findings: judgment([{ file: "link.txt", line: 1 }]),
      measurements: {},
      rules: RULES,
      targetRoot: fixture.root,
    });
    expectIssue(linked.errors, { index: 0, field: "findings[0].evidence[0].file", rule: "RUL-01", message: /outside the target folder/ });

    const lexical = validateFindings({
      findings: judgment([{ file: "../outside/secret.txt", line: 1 }]),
      measurements: {},
      rules: RULES,
      targetRoot: fixture.root,
    });
    expectIssue(lexical.errors, { index: 0, field: "findings[0].evidence[0].file", rule: "RUL-01", message: /\.\. segments/ });

    const absolute = validateFindings({
      findings: judgment([{ file: path.join(fixture.outsideDir, "secret.txt").replaceAll("\\", "/"), line: 1 }]),
      measurements: {},
      rules: RULES,
      targetRoot: fixture.root,
    });
    expectIssue(absolute.errors, { index: 0, field: "findings[0].evidence[0].file", rule: "RUL-01", message: /not an absolute path/ });

    const inside = validateFindings({
      findings: judgment([{ file: "inside.txt", line: 1 }]),
      measurements: {},
      rules: RULES,
      targetRoot: fixture.root,
    });
    assert.deepEqual(inside.errors, [], "a file inside the target is read");

    const outsideDir = path.resolve(fixture.outsideDir);
    assert.ok(opened.some((file) => file.startsWith(fs.realpathSync.native(fixture.root))), "the control read did not happen");
    assert.ok(!opened.some((file) => path.resolve(file).startsWith(outsideDir)), `a path outside the target was opened: ${opened.join(", ")}`);
    assert.ok(!JSON.stringify([linked.errors, lexical.errors, absolute.errors]).includes(sentinel), "the content outside the target leaked into the errors");
  });
});

describe("validator: evidence with a layer names a file outside the target", () => {
  // The scan's user layer and parent folders, as synthetic measurements: the paths and the line counts the validator reads.
  // A skill has no line count, and an unread parent file is listed with read false.
  const LAYERED = {
    userLayer: {
      root: "~/.claude",
      found: true,
      memory: [{ path: "~/.claude/CLAUDE.md", lines: 4 }],
      settings: { path: "~/.claude/settings.json", found: true, lines: 6 },
      skills: [{ path: "~/.claude/skills/review/SKILL.md" }],
      subagents: [],
    },
    context: {
      ancestors: [
        { path: "../CLAUDE.md", bytes: 500, read: true, lines: 3 },
        { path: "../AGENTS.md", bytes: 90, read: false, reason: "too-large" },
      ],
    },
  };
  let fixture = null;
  before(() => {
    fixture = makeFixture({ files: { "CLAUDE.md": "one\ntwo\nthree\n" } });
  });
  after(() => {
    fixture?.cleanup();
  });

  // The result of one judgment finding that cites the evidence, checked against the given measurements.
  const check = (evidence, measurements = LAYERED) =>
    validate(
      {
        findings: [{ rule: "RUL-01", axis: "instructions", kind: "judgment", evidence: [evidence], impact: "low", summary: "A check.", recommendation: "A change.", testInFunction2: null }],
      },
      measurements,
      fixture.root,
    );

  test("a user file that measurements.json lists passes, with a line inside its lines count (positive control)", () => {
    for (const evidence of [
      { file: "~/.claude/settings.json", layer: "user" },
      { file: "~/.claude/settings.json", line: 2, endLine: 6, layer: "user" },
      { file: "~/.claude/CLAUDE.md", line: 4, layer: "user" },
      { file: "~/.claude/skills/review/SKILL.md", layer: "user" },
    ]) {
      const result = check(evidence);
      assert.deepEqual(result.errors, [], JSON.stringify(evidence));
      assert.deepEqual(result.warnings, [], JSON.stringify(evidence));
    }
  });

  test("a parent-folder file that the scan read passes, with a line inside its lines count (positive control)", () => {
    assert.deepEqual(check({ file: "../CLAUDE.md", layer: "ancestor" }).errors, []);
    assert.deepEqual(check({ file: "../CLAUDE.md", line: 1, endLine: 3, layer: "ancestor" }).errors, []);
  });

  test("a user file that measurements.json does not list is an error", () => {
    const result = check({ file: "~/.claude/hooks.json", layer: "user" });
    expectIssue(result.errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /is not listed in the userLayer section of measurements.json/,
    });
  });

  test("a parent-folder file that measurements.json does not list is an error", () => {
    const result = check({ file: "../README.md", layer: "ancestor" });
    expectIssue(result.errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /is not listed in context.ancestors of measurements.json/,
    });
  });

  test("a parent-folder file that the scan did not read is an error, even though it is listed", () => {
    const result = check({ file: "../AGENTS.md", layer: "ancestor" });
    expectIssue(result.errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /was not read by the scan/,
    });
  });

  test("a layer whose section the scan did not write (the flag was off) lists no file", () => {
    const withoutSections = { inventory: [] };
    expectIssue(check({ file: "~/.claude/settings.json", layer: "user" }, withoutSections).errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /is not listed in the userLayer section/,
    });
    expectIssue(check({ file: "../CLAUDE.md", layer: "ancestor" }, withoutSections).errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /is not listed in context.ancestors/,
    });
  });

  test("a quote with a layer is an error, because the file outside the target is not read", () => {
    const result = check({ file: "~/.claude/CLAUDE.md", line: 1, quote: "one", layer: "user" });
    expectIssue(result.errors, {
      index: 0,
      field: "findings[0].evidence[0].quote",
      rule: "RUL-01",
      message: /cannot be checked/,
    });
  });

  test("a line past the lines count of the file is an error, and a line inside it passes (positive control)", () => {
    const past = check({ file: "~/.claude/CLAUDE.md", line: 5, layer: "user" });
    expectIssue(past.errors, {
      index: 0,
      field: "findings[0].evidence[0].line",
      rule: "RUL-01",
      message: /line 5 is past the end of "~\/\.claude\/CLAUDE\.md", which has 4 lines/,
    });
    const endPast = check({ file: "../CLAUDE.md", line: 2, endLine: 4, layer: "ancestor" });
    expectIssue(endPast.errors, {
      index: 0,
      field: "findings[0].evidence[0].endLine",
      rule: "RUL-01",
      message: /line 4 is past the end of "\.\.\/CLAUDE\.md", which has 3 lines/,
    });
    assert.deepEqual(check({ file: "~/.claude/CLAUDE.md", line: 4, layer: "user" }).errors, []);
  });

  test("a line on a file that has no lines count is an error, since the validator cannot check it", () => {
    const result = check({ file: "~/.claude/skills/review/SKILL.md", line: 1, layer: "user" });
    expectIssue(result.errors, {
      index: 0,
      field: "findings[0].evidence[0].line",
      rule: "RUL-01",
      message: /has no line count in measurements.json/,
    });
  });

  test("an unknown layer is an error, and so is a file with the wrong start for its layer", () => {
    expectIssue(check({ file: "CLAUDE.md", layer: "project" }).errors, {
      index: 0,
      field: "findings[0].evidence[0].layer",
      rule: "RUL-01",
      message: /must be "user" or "ancestor", found "project"/,
    });
    expectIssue(check({ file: "CLAUDE.md", layer: "ancestor" }).errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /with layer ancestor, must start with \.\.\/, found "CLAUDE\.md"/,
    });
    expectIssue(check({ file: "../CLAUDE.md", layer: "user" }).errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /with layer user, must start with ~\/\.claude\//,
    });
  });

  test("without a layer, a parent-folder path still fails as before, and a file of the target still passes (positive control)", () => {
    expectIssue(check({ file: "../CLAUDE.md", line: 1 }).errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /\.\. segments/,
    });
    assert.deepEqual(check({ file: "CLAUDE.md", line: 1 }).errors, []);
  });

  test("without a layer, a path under ~/.claude is a file of the target, as before, so it does not exist there", () => {
    expectIssue(check({ file: "~/.claude/settings.json" }).errors, {
      index: 0,
      field: "findings[0].evidence[0].file",
      rule: "RUL-01",
      message: /does not exist in the target/,
    });
  });
});

describe("validator: a secret inside the target", () => {
  test("a line that holds a secret is cited without a quote: its masked form is not in the file, so the quote is refused", () => {
    const token = ["sk", "ant", "api03", "E".repeat(24)].join("-");
    const fixture = makeFixture({ files: { "notes/config.txt": `# setup\nexport TOKEN=${token}\n` } });
    try {
      const finding = (evidence) => ({
        findings: [{
          rule: "RUL-01",
          axis: "instructions",
          kind: "judgment",
          evidence: [evidence],
          impact: "low",
          summary: "The config holds a token on line 2.",
          recommendation: "Move the token to an ignored file.",
          testInFunction2: null,
        }],
      });
      const withMaskedQuote = validate(finding({ file: "notes/config.txt", line: 2, quote: `export TOKEN=${mask(token, "sk-ant-")}` }), {}, fixture.root);
      expectIssue(withMaskedQuote.errors, { index: 0, field: "findings[0].evidence[0].quote", rule: "RUL-01", message: /does not appear on line 2/ });
      const withoutQuote = validate(finding({ file: "notes/config.txt", line: 2 }), {}, fixture.root);
      assert.deepEqual(withoutQuote.errors, []);
    } finally {
      fixture.cleanup();
    }
  });

  test("a quote that holds a raw secret is an error, and the secret is not printed", () => {
    const secret = ["sk", "ant", "api03", "C".repeat(24)].join("-");
    const fixture = makeFixture({ files: { "notes/config.txt": `# setup\nexport TOKEN=${secret}\n` } });
    try {
      const findings = {
        findings: [{
          rule: "RUL-01",
          axis: "instructions",
          kind: "judgment",
          evidence: [{ file: "notes/config.txt", line: 2, quote: `export TOKEN=${secret}` }],
          impact: "low",
          summary: "The config holds a token.",
          recommendation: "Move the token to an ignored file.",
          testInFunction2: null,
        }],
      };
      const result = validate(findings, {}, fixture.root);
      expectIssue(result.errors, { index: 0, field: "findings[0].evidence[0].quote", rule: "RUL-01", message: /anthropic-api-key/ });
      assert.equal(result.errors.length, 1, "the quote matches the line, so only the secret is reported");
      assert.ok(!JSON.stringify(result.errors).includes("CCCC"), "the secret must not be printed");
    } finally {
      fixture.cleanup();
    }
  });
});

describe("validator: the agents of a finding", () => {
  let scanned = null;
  before(async () => {
    scanned = await scanFixture({ fromDir: PERMISSIVE });
  });
  after(() => {
    scanned?.cleanup();
  });
  const targetOf = () => scanned.measurements.meta.targetRoot;
  // The good findings, with the agents given to the measured finding of SEC-01 (its first finding).
  const withAgents = (agents) => {
    const findings = goodFindings(scanned.measurements);
    findings.findings[0].agents = agents;
    return findings;
  };

  test("agents that the scan detected pass, on a measured and on a judgment finding (positive control)", () => {
    assert.deepEqual(
      scanned.measurements.agentHarness.agents.map((agent) => agent.id),
      ["claude-code"],
      "the permissive scan detects Claude Code only",
    );
    const findings = goodFindings(scanned.measurements);
    findings.findings[0].agents = ["claude-code"];
    findings.findings[2].agents = ["claude-code"];
    const result = validate(findings, scanned.measurements, targetOf());
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.warnings, []);
    assert.equal(result.ok, true);
  });

  test("an agent that the scan did not detect is an error, and the message names the detected agents", () => {
    const result = validate(withAgents(["cursor"]), scanned.measurements, targetOf());
    assert.equal(result.ok, false);
    expectIssue(result.errors, {
      index: 0,
      field: "findings[0].agents[0]",
      rule: "SEC-01",
      message: /is not an agent that the scan detected; the detected agents are claude-code$/,
    });
  });

  test("a second entry of the same agent is an error on that entry, and the first one is kept", () => {
    const result = validate(withAgents(["claude-code", "claude-code"]), scanned.measurements, targetOf());
    expectIssue(result.errors, { index: 0, field: "findings[0].agents[1]", rule: "SEC-01", message: /listed more than once/ });
    assert.equal(result.errors.filter((issue) => issue.field.startsWith("findings[0].agents")).length, 1);
  });

  test("a value that is not a list, or an empty list, is an error on agents", () => {
    for (const value of ["claude-code", null, { id: "claude-code" }]) {
      const result = validate(withAgents(value), scanned.measurements, targetOf());
      expectIssue(result.errors, { index: 0, field: "findings[0].agents", rule: "SEC-01", message: /must be a list of agent ids/ });
    }
    const empty = validate(withAgents([]), scanned.measurements, targetOf());
    expectIssue(empty.errors, { index: 0, field: "findings[0].agents", rule: "SEC-01", message: /is an empty list/ });
  });

  test("an entry that is not an agent id (a name, a number, an upper-case id) is an error", () => {
    for (const id of ["Claude Code", 7, "Cursor", ""]) {
      const result = validate(withAgents([id]), scanned.measurements, targetOf());
      expectIssue(result.errors, { index: 0, field: "findings[0].agents[0]", rule: "SEC-01", message: /is not an agent id/ });
    }
  });

  test("a secret-shaped agent id is an error, and its value is not printed", () => {
    const token = ["sk", "ant", "api03", "b".repeat(24)].join("-");
    const result = validate(withAgents([token]), scanned.measurements, targetOf());
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((issue) => issue.field === "findings[0].agents[0]"), "the entry is not reported");
    const printed = result.errors.map((issue) => formatIssue(issue)).join("\n");
    assert.equal(printed.includes(token), false, "the secret is printed");
  });

  test("a scan that detected no agent (no agentHarness, or an empty list) rejects any agent, and accepts no agent (positive control)", () => {
    const noSection = structuredClone(scanned.measurements);
    delete noSection.agentHarness;
    const emptyList = structuredClone(scanned.measurements);
    emptyList.agentHarness.agents = [];
    for (const measurements of [noSection, emptyList]) {
      assert.deepEqual(validate(goodFindings(scanned.measurements), measurements, targetOf()).errors, []);
      const result = validate(withAgents(["claude-code"]), measurements, targetOf());
      expectIssue(result.errors, {
        index: 0,
        field: "findings[0].agents[0]",
        rule: "SEC-01",
        message: /the detected agents are none$/,
      });
    }
  });
});

describe("validator: argument checks", () => {
  test("a wrong argument throws a TypeError that names the argument", () => {
    assert.throws(() => validateFindings({ findings: {}, measurements: null, rules: RULES, targetRoot: HARNESS_ROOT }), /measurements must be/);
    assert.throws(() => validateFindings({ findings: {}, measurements: {}, rules: {}, targetRoot: HARNESS_ROOT }), /rules must be/);
    assert.throws(() => validateFindings({ findings: {}, measurements: {}, rules: [{ id: "RUL-01" }], targetRoot: HARNESS_ROOT }), /each rule needs/);
    assert.throws(() => validateFindings({ findings: {}, measurements: {}, rules: RULES, targetRoot: "" }), /targetRoot must be/);
  });
});

describe("loadRules: the rule catalog of the harness", () => {
  test("it reads the 17 rules of rules/, sorted by id, and skips README.md", () => {
    assert.equal(RULES.length, 17);
    assert.deepEqual(RULES.map((rule) => rule.id), [...RULES.map((rule) => rule.id)].sort());
    assert.ok(RULES.every((rule) => rule.file.startsWith("rules/") && rule.file.endsWith(".md")));
    assert.ok(!RULES.some((rule) => rule.file.endsWith("README.md")));
    assert.deepEqual(
      RULES.filter((rule) => rule.id === "SEC-02").map(({ axis, kind }) => ({ axis, kind })),
      [{ axis: "security", kind: "measured" }],
    );
    assert.deepEqual(
      RULES.filter((rule) => rule.id === "RUL-01").map(({ axis, kind }) => ({ axis, kind })),
      [{ axis: "instructions", kind: "judgment" }],
    );
    assert.deepEqual(
      RULES.filter((rule) => rule.id === "SEC-06").map(({ axis, kind }) => ({ axis, kind })),
      [{ axis: "security", kind: "judgment" }],
    );
  });

  test("a rule whose frontmatter cannot be read throws, and the message names the file", () => {
    const fixture = makeFixture({ files: { "rules/SEC-01-broken.md": "---\nid: [\n---\n" } });
    try {
      assert.throws(() => loadRules(fixture.root), /rules\/SEC-01-broken\.md/);
    } finally {
      fixture.cleanup();
    }
  });
});

describe("secret-patterns: isMasked", () => {
  test("mask() output is masked, and a raw token or a plain word is not", () => {
    const token = ["sk", "ant", "api03", "F".repeat(24)].join("-");
    assert.equal(isMasked(mask(token, "sk-ant-")), true);
    assert.equal(isMasked(mask(PLAIN_SECRET)), true);
    assert.equal(isMasked(token), false);
    assert.equal(isMasked(PLAIN_SECRET), false);
    assert.equal(isMasked("a long head before the ellipsis\u2026abcd"), false, "a head longer than a prefix is not a mask");
    assert.equal(isMasked(null), false);
  });
});
