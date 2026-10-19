// Checks the xray-scan skill: its frontmatter, its trigger phrases, its hard rules, and the findings.json example in its body.
// The example must validate, with no errors and no warnings, against a real scan of an unmodified copy of the permissive
// fixture, and it must cite every measured finding of that scan. The copy and its run folder are removed afterwards.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { formatIssue, loadRules, validateFindings } from "../scripts/lib/findings-validate.mjs";
import { parseFrontmatter } from "../scripts/lib/frontmatter.mjs";
import { findGenericSecrets, findSpecificSecrets } from "../scripts/lib/secret-patterns.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";
import { HARNESS_ROOT, PERMISSIVE, SCAN_SCRIPT, runRender } from "./helpers/report-run.mjs";

const execFileAsync = promisify(execFile);
const SKILL_FILE = path.join(HARNESS_ROOT, ".claude", "skills", "xray-scan", "SKILL.md");
const MAX_DESCRIPTION_LENGTH = 350;
const TRIGGER_PHRASES = ["evalúa este proyecto", "revisa la seguridad de", "scan this repo's harness"];
// Line endings may be CRLF on a Windows checkout, so every pattern that spans a line break allows \r before \n.
const JSON_BLOCK = /```json\r?\n([\s\S]*?)\r?\n```/g;
const FRONTMATTER = /^---\r?\n[\s\S]*?\r?\n---\r?\n/;

const skillText = fs.readFileSync(SKILL_FILE, "utf8");
const frontmatter = parseFrontmatter(skillText);
const body = skillText.replace(FRONTMATTER, "");

test("the frontmatter has only a name and a short description", () => {
  assert.equal(frontmatter.error, undefined, `frontmatter cannot be read: ${frontmatter.error}`);
  assert.deepEqual(Object.keys(frontmatter.data).sort(), ["description", "name"]);
  assert.equal(frontmatter.data.name, "xray-scan");
  const { description } = frontmatter.data;
  assert.equal(typeof description, "string");
  assert.ok(description.trim() !== "", "the description is blank");
  assert.ok(
    description.length <= MAX_DESCRIPTION_LENGTH,
    `the description has ${description.length} characters, more than ${MAX_DESCRIPTION_LENGTH}`,
  );
});

test("the description carries the trigger phrases in Spanish and English", () => {
  const description = frontmatter.data.description.toLowerCase();
  for (const phrase of TRIGGER_PHRASES) {
    assert.ok(description.includes(phrase), `the description does not contain "${phrase}"`);
  }
});

test("the body has the steps in order and the hard rules", () => {
  const headings = [...body.matchAll(/^## (.+?)\r?$/gm)].map((match) => match[1]);
  assert.deepEqual(headings, [
    "Hard rules",
    "Step 1: Target and report language",
    "Step 2: Scan",
    "Step 3: Read only what the scan names",
    "Step 4: Apply the six axes",
    "Step 5: Write findings.json",
    "Step 6: Render and check",
    "Step 7: Answer in the chat",
  ]);
  assert.match(body, /--add-dir/, "the hard rule about --add-dir is missing");
  assert.match(body, /never copy a secret/i);
});

test("the body is in English outside the quoted trigger phrases", () => {
  const unquoted = body.replace(/"[^"\n]*"/g, "");
  assert.doesNotMatch(unquoted, /[áéíóúñ¿¡]/i, "the body has Spanish text outside the quoted phrases");
});

test("the body names no ticket, spec or docs path, and no scan cost step or axis option", () => {
  assert.doesNotMatch(skillText, /docs\/|SPEC\.md|\bticket/i);
  assert.doesNotMatch(skillText, /session-cost|--axes/);
});

test("the skill text holds no unmasked secret-shaped value", () => {
  assert.deepEqual(findSpecificSecrets(skillText).map((match) => match.id), []);
  assert.deepEqual(findGenericSecrets(skillText).map((match) => match.id), []);
});

test("the body has exactly one json example, and its language is en or absent", () => {
  const blocks = [...body.matchAll(JSON_BLOCK)];
  assert.equal(blocks.length, 1, `expected one json block in the body, found ${blocks.length}`);
  const example = JSON.parse(blocks[0][1]);
  assert.ok(example.language === undefined || example.language === "en", `language is ${JSON.stringify(example.language)}`);
});

test("the json example validates against a scan of an unmodified copy of the permissive fixture", async () => {
  const blocks = [...body.matchAll(JSON_BLOCK)];
  const example = JSON.parse(blocks[0][1]);
  const fixture = makeFixture({ fromDir: PERMISSIVE });
  try {
    const runDir = path.join(fixture.base, "run");
    await execFileAsync(process.execPath, [SCAN_SCRIPT, fixture.root, "--out", runDir], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    const measurements = JSON.parse(fs.readFileSync(path.join(runDir, "measurements.json"), "utf8"));

    const result = validateFindings({
      findings: example,
      measurements,
      rules: loadRules(HARNESS_ROOT),
      targetRoot: measurements.meta.targetRoot,
    });
    assert.deepEqual(result.errors.map(formatIssue), [], "the example has validation errors");
    assert.equal(result.ok, true);
    assert.deepEqual(result.warnings.map(formatIssue), [], "the example has validation warnings");

    const cited = example.findings.map((finding) => finding.measuredFindingId).filter((id) => id !== undefined).sort();
    const measured = measurements.measuredFindings.map((finding) => finding.id).sort();
    assert.deepEqual(cited, measured, "the example does not cite every measured finding of the scan");

    fs.writeFileSync(path.join(runDir, "findings.json"), `${JSON.stringify(example, null, 2)}\n`);
    const rendered = await runRender([runDir]);
    assert.equal(rendered.code, 0, `render failed: ${rendered.stderr}`);
    const report = fs.readFileSync(path.join(runDir, "report.md"), "utf8");
    assert.match(report, /Summary by axis/);
  } finally {
    fixture.cleanup();
  }
});
