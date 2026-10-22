import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadRules } from "../scripts/lib/findings-validate.mjs";
import { deriveMeasuredOutput } from "../scripts/lib/measured-findings.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { measuresFor } from "../scripts/lib/measures.mjs";
import { SARIF_SCHEMA, SARIF_VERSION, buildSarif } from "../scripts/lib/sarif.mjs";
import { DEFAULT_DEPTH, scan } from "../scripts/lib/scanner.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";
import { SECRET_FIXTURE_FILES } from "./helpers/secret-fixture-files.mjs";
import { sarifProblems } from "./helpers/sarif-check.mjs";

// lib/sarif.mjs is a pure function: these tests give it measurements built by hand, or the measurements of a real scan of a
// copy of a fixture. The rule catalog is the real one of this harness.
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const SCHEMA = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", "sarif.schema.json"), "utf8"));
const RULES = loadRules(HARNESS_ROOT);
const MEASURED = RULES.filter((rule) => rule.kind === "measured").sort((a, b) => (a.id < b.id ? -1 : 1));
const JUDGMENT_COUNT = RULES.filter((rule) => rule.kind === "judgment").length;
// The fixtures that a real scan reads for the checker. Each one has measured findings of some impact (secrets needs its
// unversioned files, as the fixture tests add them).
const SCANNED = [
  { name: "permissive" },
  { name: "duplicated" },
  { name: "broken-refs" },
  { name: "hostile-injection" },
  { name: "full-config" },
  { name: "default-only" },
  { name: "guarded" },
  { name: "secrets", files: SECRET_FIXTURE_FILES },
];

// A measured finding with every field that buildSarif reads. The overrides replace any of them.
function finding(overrides = {}) {
  return {
    id: "mf-1",
    rule: "SEC-02",
    axis: "security",
    impact: "medium",
    measurementRef: "/security/destructiveCoverage/commands/0",
    evidence: [{ file: "CLAUDE.md" }],
    triggers: [{ trigger: "hook-fails-open", impact: "medium", measurementRef: "/security/destructiveCoverage/preToolUseHooks/0" }],
    ...overrides,
  };
}

// The measurements that buildSarif reads, for the findings given and the tool of the run.
function measurementsWith(findings, tool = "harness-x-ray@1.2.3") {
  return { meta: { tool }, measuredFindings: findings };
}

// The measurements of a scan of a copy of a fixture, as scan.mjs with no flags makes them.
async function scanFixture(t, { name, files = {} }) {
  const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), git: true, files });
  t.after(fixture.cleanup);
  return scan({
    root: fixture.root,
    measures: measuresFor({ userLayer: false, ancestors: false, depth: DEFAULT_DEPTH }),
    derive: deriveMeasuredOutput,
    depth: DEFAULT_DEPTH,
  });
}

// The log of the findings, with the real catalog.
function logOf(findings) {
  return buildSarif(measurementsWith(findings), RULES);
}

test("sarif: the log has the SARIF 2.1.0 version and a schema string, and the tool is harness-x-ray at the version of meta.tool", () => {
  const log = logOf([finding()]);
  assert.equal(log.version, "2.1.0");
  assert.equal(SARIF_VERSION, "2.1.0");
  assert.equal(log.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
  assert.equal(SARIF_SCHEMA, log.$schema);
  assert.equal(log.runs.length, 1);
  assert.equal(log.runs[0].tool.driver.name, "harness-x-ray");
  assert.equal(log.runs[0].tool.driver.version, "1.2.3");
  assert.deepEqual(sarifProblems(log), []);
});

test("sarif: the rules are the measured rules of the catalog, sorted by id, with their titles", () => {
  const { rules } = logOf([]).runs[0].tool.driver;
  assert.deepEqual(
    rules.map((rule) => rule.id),
    MEASURED.map((rule) => rule.id),
  );
  for (const rule of rules) {
    const source = RULES.find((item) => item.id === rule.id);
    assert.equal(rule.shortDescription.text, source.title);
  }
  assert.ok(rules.every((rule) => RULES.find((item) => item.id === rule.id).kind === "measured"), "no judgment rule is listed");
});

test("sarif: each result names its rule by ruleId and by ruleIndex, and the index is the rule's place in the rules list", () => {
  const log = logOf([finding({ rule: "SEC-02" }), finding({ id: "mf-2", rule: "CTX-01", axis: "context" })]);
  const { rules } = log.runs[0].tool.driver;
  for (const result of log.runs[0].results) {
    assert.equal(rules[result.ruleIndex].id, result.ruleId);
  }
  assert.deepEqual(
    log.runs[0].results.map((result) => result.ruleIndex),
    [rules.findIndex((rule) => rule.id === "SEC-02"), rules.findIndex((rule) => rule.id === "CTX-01")],
  );
});

test("sarif: the impact maps to the level, high to error, medium to warning and low to note", () => {
  const log = logOf([
    finding({ impact: "high" }),
    finding({ id: "mf-2", impact: "medium" }),
    finding({ id: "mf-3", impact: "low" }),
  ]);
  assert.deepEqual(
    log.runs[0].results.map((result) => result.level),
    ["error", "warning", "note"],
  );
});

test("sarif: a file of the target is a relative uri with each segment percent-encoded, and it decodes to the same path", () => {
  const file = "docs/my notes/a#b%c?.md";
  const colon = "x:y/z\\w.md";
  const log = logOf([finding({ evidence: [{ file }, { file: colon }] })]);
  const [first, second] = log.runs[0].results[0].locations.map((location) => location.physicalLocation.artifactLocation.uri);
  assert.equal(first, "docs/my%20notes/a%23b%25c%3F.md");
  assert.equal(second, "x%3Ay/z%5Cw.md");
  assert.deepEqual(first.split("/").map(decodeURIComponent), file.split("/"));
  assert.deepEqual(sarifProblems(log), []);
});

test("sarif: evidence with a layer lies outside the target, so it has no location, and a finding with no file evidence has no locations key", () => {
  const outside = finding({ evidence: [{ file: "~/.claude/settings.json", layer: "user" }] });
  const mixed = finding({
    id: "mf-2",
    evidence: [
      { file: "CLAUDE.md", line: 3, endLine: 5 },
      { file: "~/.claude/CLAUDE.md", layer: "user" },
      { file: "../AGENTS.md", layer: "ancestor" },
    ],
  });
  const none = finding({ id: "mf-3", evidence: [] });
  const [onlyOutside, withTarget, withoutFiles] = logOf([outside, mixed, none]).runs[0].results;

  assert.equal(Object.hasOwn(onlyOutside, "locations"), false, "evidence with a layer has no location");
  assert.equal(withTarget.locations.length, 1, "only the file of the target has a location");
  assert.equal(withTarget.locations[0].physicalLocation.artifactLocation.uri, "CLAUDE.md");
  assert.equal(Object.hasOwn(withoutFiles, "locations"), false, "no file evidence means no locations key");
});

test("sarif: a line gives the start of the region, and an endLine that is not before it gives the end; a bad endLine is left out", () => {
  const log = logOf([
    finding({ evidence: [{ file: "a.md", line: 4, endLine: 9 }] }),
    finding({ id: "mf-2", evidence: [{ file: "b.md", line: 4, endLine: 2 }] }),
    finding({ id: "mf-3", evidence: [{ file: "c.md" }] }),
  ]);
  const [withEnd, badEnd, withoutLine] = log.runs[0].results.map((result) => result.locations[0].physicalLocation);
  assert.deepEqual(withEnd.region, { startLine: 4, endLine: 9 });
  assert.deepEqual(badEnd.region, { startLine: 4 });
  assert.equal(Object.hasOwn(withoutLine, "region"), false, "a file without a line has no region");
  assert.deepEqual(sarifProblems(log), []);
});

test("sarif: the judgment rules are said in the properties and in a note notification, with the count of the catalog", () => {
  const log = logOf([finding()]);
  const run = log.runs[0];
  assert.equal(run.properties.judgmentRulesApplied, false);
  assert.equal(run.properties.judgmentRules, JUDGMENT_COUNT);
  assert.ok(JUDGMENT_COUNT > 0, "the catalog has judgment rules");
  assert.equal(run.invocations[0].executionSuccessful, true);
  const [note] = run.invocations[0].toolExecutionNotifications;
  assert.equal(note.level, "note");
  assert.match(note.message.text, /judgment rules were not applied/);
});

test("sarif: the message names the rule and its title, the impact, the triggers with their counts, and the first evidence entries", () => {
  const triggers = [
    { trigger: "hook-fails-open", impact: "medium", measurementRef: "/a" },
    { trigger: "hook-fails-open", impact: "medium", measurementRef: "/b" },
    { trigger: "bare-shell-allow", impact: "high", measurementRef: "/c" },
  ];
  const evidence = ["a.md", "b.md", "c.md", "d.md"].map((file) => ({ file }));
  const [result] = logOf([finding({ impact: "high", triggers, evidence })]).runs[0].results;
  const title = RULES.find((rule) => rule.id === "SEC-02").title;
  assert.equal(
    result.message.text,
    `SEC-02 ${title}. Impact: high. Triggers: hook-fails-open (2), bare-shell-allow (1). Evidence: a.md, b.md, c.md, and 1 more.`,
  );
  const [line] = logOf([finding({ evidence: [{ file: "x.md", line: 7 }] })]).runs[0].results;
  assert.match(line.message.text, /Evidence: x\.md:7\.$/);
});

test("sarif: a finding that cannot be placed is refused: a rule that is not measured, an impact outside the three, a tool that is not harness-x-ray, or a file that is not relative", () => {
  const cases = {
    "a judgment rule": measurementsWith([finding({ rule: "RUL-01" })]),
    "an unknown rule": measurementsWith([finding({ rule: "XYZ-99" })]),
    "an impact that is not one of the three": measurementsWith([finding({ impact: "critical" })]),
    "a tool of another name": measurementsWith([], "other-tool@1.0.0"),
    "a file with a parent segment": measurementsWith([finding({ evidence: [{ file: "../CLAUDE.md" }] })]),
    "a file with an empty segment": measurementsWith([finding({ evidence: [{ file: "a//b.md" }] })]),
  };
  for (const [name, measurements] of Object.entries(cases)) {
    assert.throws(() => buildSarif(measurements, RULES), TypeError, `${name} is refused`);
  }
  assert.doesNotThrow(() => buildSarif(measurementsWith([finding()]), RULES), "positive control: a valid finding is built");
});

test("sarif: the same measurements give the same text, and the text has no timestamp", () => {
  const measurements = measurementsWith([finding(), finding({ id: "mf-2", rule: "CTX-01", axis: "context" })]);
  const first = toStableJson(buildSarif(measurements, RULES));
  const second = toStableJson(buildSarif(measurements, RULES));
  assert.equal(first, second);
  assert.doesNotMatch(first, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, "no timestamp is written");
});

test("sarif: a real scan with duplicated copies gives locations with a start and an end line", async (t) => {
  const measurements = await scanFixture(t, { name: "duplicated" });
  const locations = buildSarif(measurements, RULES).runs[0].results.flatMap((result) => result.locations ?? []);
  const regions = locations.map((location) => location.physicalLocation.region).filter((region) => region !== undefined);
  assert.ok(regions.length > 0, "the scan has copies with lines");
  assert.ok(regions.some((region) => Number.isInteger(region.endLine)), "a copy has an end line");
});

for (const fixture of SCANNED) {
  test(`sarif: the log of a real scan of the ${fixture.name} fixture passes the checker and the schema, with one result per measured finding`, async (t) => {
    const measurements = await scanFixture(t, fixture);
    const log = buildSarif(measurements, RULES);
    assert.deepEqual(sarifProblems(log), []);
    assert.deepEqual(schemaProblems(SCHEMA, log), [], "the log passes schemas/sarif.schema.json");
    assert.equal(log.runs[0].results.length, measurements.measuredFindings.length);
    assert.equal(log.runs[0].properties.judgmentRules, JUDGMENT_COUNT);
  });
}

test("sarif: the checker refuses each defect of a broken log, and passes the valid one (positive control)", () => {
  const valid = logOf([
    finding({ evidence: [{ file: "CLAUDE.md", line: 2, endLine: 4 }] }),
    finding({ id: "mf-2", rule: "COD-01", axis: "code", impact: "high", evidence: [{ file: "src/a.js", line: 1 }] }),
  ]);
  assert.deepEqual(sarifProblems(valid), [], "positive control: the valid log passes");

  const defects = {
    "a version that is not 2.1.0": (log) => (log.version = "2.0.0"),
    "no schema string": (log) => delete log.$schema,
    "no runs": (log) => (log.runs = []),
    "a driver without a name": (log) => (log.runs[0].tool.driver.name = ""),
    "a rule without a shortDescription": (log) => delete log.runs[0].tool.driver.rules[0].shortDescription,
    "a rule listed twice": (log) => log.runs[0].tool.driver.rules.push({ ...log.runs[0].tool.driver.rules[0] }),
    "a ruleId that is not a rule": (log) => (log.runs[0].results[0].ruleId = "NOPE-01"),
    "a ruleIndex out of range": (log) => (log.runs[0].results[0].ruleIndex = 99),
    "a ruleIndex that names another rule": (log) => (log.runs[0].results[0].ruleIndex = log.runs[0].results[1].ruleIndex),
    "a level that is not a SARIF level": (log) => (log.runs[0].results[0].level = "info"),
    "an empty message": (log) => (log.runs[0].results[0].message.text = ""),
    "an absolute uri": (log) => (log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = "/etc/passwd"),
    "a uri with a scheme": (log) => (log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = "file:///x.md"),
    "a uri with a backslash": (log) => (log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = "a\\b.md"),
    "a uri with a parent segment": (log) => (log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = "a/../b.md"),
    "a startLine of 0": (log) => (log.runs[0].results[0].locations[0].physicalLocation.region.startLine = 0),
    "an endLine before the startLine": (log) => (log.runs[0].results[0].locations[0].physicalLocation.region.endLine = 1),
    "a judgmentRulesApplied that is true": (log) => (log.runs[0].properties.judgmentRulesApplied = true),
    "no note that the judgment rules were not applied": (log) => (log.runs[0].invocations[0].toolExecutionNotifications = []),
    "no executionSuccessful": (log) => delete log.runs[0].invocations[0].executionSuccessful,
  };
  for (const [name, break_] of Object.entries(defects)) {
    const broken = structuredClone(valid);
    break_(broken);
    assert.notDeepEqual(sarifProblems(broken), [], `the checker refuses ${name}`);
  }
});

test("sarif: the schema refuses each defect of a broken log, and passes the valid one (positive control)", () => {
  const valid = logOf([
    finding({ evidence: [{ file: "CLAUDE.md", line: 2, endLine: 4 }] }),
    finding({ id: "mf-2", rule: "COD-01", axis: "code", impact: "high", evidence: [{ file: "src/a.js", line: 1 }] }),
    finding({ id: "mf-3", evidence: [{ file: "docs/my notes/a#b.md" }] }),
  ]);
  assert.deepEqual(schemaProblems(SCHEMA, valid), [], "positive control: the valid log passes the schema");

  const defects = {
    "an extra field in a result": (log) => (log.runs[0].results[0].extra = true),
    "a level that is not a SARIF level": (log) => (log.runs[0].results[0].level = "info"),
    "a negative ruleIndex": (log) => (log.runs[0].results[0].ruleIndex = -1),
    "a startLine of 0": (log) => (log.runs[0].results[0].locations[0].physicalLocation.region.startLine = 0),
    "a judgmentRulesApplied that is true": (log) => (log.runs[0].properties.judgmentRulesApplied = true),
    "a driver with another name": (log) => (log.runs[0].tool.driver.name = "other-tool"),
    "a version that is not 2.1.0": (log) => (log.version = "2.0.0"),
    "no runs": (log) => (log.runs = []),
    "no notification of the judgment rules": (log) => (log.runs[0].invocations[0].toolExecutionNotifications = []),
    "a uri with a scheme": (log) => (log.runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "file:x.md"),
    "a uri with a colon": (log) => (log.runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "x:y.md"),
    "an absolute uri": (log) => (log.runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "/etc/passwd"),
    "a uri with a backslash": (log) => (log.runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "a\\b.md"),
    "a uri with a parent segment": (log) => (log.runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "a/../b.md"),
    "a uri with an empty segment": (log) => (log.runs[0].results[2].locations[0].physicalLocation.artifactLocation.uri = "a//b.md"),
  };
  for (const [name, break_] of Object.entries(defects)) {
    const broken = structuredClone(valid);
    break_(broken);
    assert.notDeepEqual(schemaProblems(SCHEMA, broken), [], `the schema refuses ${name}`);
  }
});

// The keywords of JSON Schema that schema-check.mjs does not check. It ignores them, so a schema that used one would accept any value.
const UNCHECKED_KEYWORDS = Object.freeze([
  "contains",
  "default",
  "dependentRequired",
  "examples",
  "exclusiveMaximum",
  "exclusiveMinimum",
  "format",
  "maxProperties",
  "minProperties",
  "multipleOf",
  "patternProperties",
  "prefixItems",
  "unevaluatedProperties",
]);

// The unchecked keywords used in a schema. The names under properties and $defs are not keywords, so they are not read as such.
function uncheckedKeywordsOf(node, found = []) {
  if (Array.isArray(node)) {
    for (const item of node) uncheckedKeywordsOf(item, found);
  } else if (node !== null && typeof node === "object") {
    for (const [key, value] of Object.entries(node)) {
      if (UNCHECKED_KEYWORDS.includes(key)) found.push(key);
      if (key === "properties" || key === "$defs") {
        for (const child of Object.values(value)) uncheckedKeywordsOf(child, found);
      } else {
        uncheckedKeywordsOf(value, found);
      }
    }
  }
  return found;
}

test("sarif: the schema uses only the keywords that the schema checker checks (positive control: a format is found)", () => {
  assert.deepEqual(uncheckedKeywordsOf({ properties: { a: { type: "string", format: "uri" } } }), ["format"]);
  assert.deepEqual(uncheckedKeywordsOf(SCHEMA), [], "no keyword of the schema is ignored by the checker");
});
