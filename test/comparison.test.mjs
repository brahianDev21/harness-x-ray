// Tests for scripts/lib/comparison.mjs: the input checks, the pairing of the units of two runs, the order of the items, and the
// warnings. The runs are synthetic objects built in memory, with every field that the input checks read.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { COMPARISON_SCHEMA_VERSION, WARNING_CODES, checkRunInputs, compareRuns } from "../scripts/lib/comparison.mjs";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { UsageError } from "../scripts/lib/target.mjs";
import { schemaProblems } from "./helpers/schema-check.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "comparison.schema.json");
const HEAD = "a".repeat(40);
const CATALOG = { count: 19, sha256: "7bf4e797546c" };
const HOSTILE = "HOSTILE-VALUE-7f3a";
const CTX_REF = "/context/alwaysLoaded/estTokensTotal";
const SEC_REF = "/security/destructiveCoverage/mode";

// A measurements.json with every field that checkRunInputs reads, with the values a scan writes. catalog: null leaves the
// key out, as a scan made before it existed does. Options that are left out have the values of an ordinary scan.
function measurementsOf(options = {}) {
  const {
    target: targetName = "app",
    root = "/synthetic/app",
    measuredFindings = [],
    depth,
    scope,
    catalog = CATALOG,
    schemaVersion = 1,
    scannedAt = "2026-10-17T12:00:00.000Z",
  } = options;
  const meta = { tool: "harness-x-ray@0.0.0", scannedAt, targetRoot: root };
  if (catalog !== null) meta.catalog = catalog;
  const measurements = {
    schemaVersion,
    meta,
    target: { name: targetName, git: { isRepo: true, head: HEAD }, fileListSource: "git", fileCount: 3 },
    inventory: [],
    warnings: [],
    measuredFindings,
    candidates: [],
    undeterminable: [],
    context: { alwaysLoaded: { estTokensTotal: 0, estMethod: "chars/4", byComponent: [], unknownStatic: [] } },
    security: { destructiveCoverage: { mode: "standard" } },
    code: { duplication: { duplicatedLinesPct: 0, filesScanned: 0 } },
    structure: { mapCoverage: { dirs: 0, mentioned: 0 } },
  };
  if (depth !== undefined) measurements.depth = depth;
  if (scope !== undefined) measurements.scope = { folders: scope, inherited: ["."], files: { inScope: 1, outside: 2 } };
  return measurements;
}

// A measured finding. Its trigger carries the impact, and names the measurementRef unless triggers is given.
function measured(id, { rule = "CTX-01", axis = "context", impact = "high", measurementRef = CTX_REF, trigger = "budget-total", triggers } = {}) {
  return {
    id,
    rule,
    axis,
    impact,
    measurementRef,
    evidence: [],
    triggers: triggers ?? [{ trigger, impact, measurementRef, threshold: { key: "budget", value: 5000 }, detail: { tokens: 6000 } }],
  };
}

// A judgment finding of findings.json, by default a RUL-01 finding in CLAUDE.md.
function finding(overrides = {}) {
  return {
    rule: "RUL-01",
    axis: "instructions",
    kind: "judgment",
    impact: "medium",
    summary: "A rule is vague.",
    evidence: [{ file: "CLAUDE.md", line: 3 }],
    recommendation: "Make the rule concrete.",
    testInFunction2: null,
    ...overrides,
  };
}

// A measured finding of findings.json that cites the measured finding of the given id.
function citing(id, overrides = {}) {
  return finding({
    rule: "CTX-01",
    axis: "context",
    kind: "measured",
    measuredFindingId: id,
    impact: "high",
    summary: `The budget of ${id} is over.`,
    evidence: [],
    ...overrides,
  });
}

// A run with the given findings. The options go to measurementsOf; language, when given, is written to findings.json.
function runOf(name, { measuredFindings = [], findings = [], language, ...options } = {}) {
  const parsed = { findings };
  if (language !== undefined) parsed.language = language;
  return { name, measurements: measurementsOf({ ...options, measuredFindings }), findings: parsed };
}

// The same data with the keys of every object in the reverse order. Arrays keep their order.
function reverseKeys(value) {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).reverse().map((key) => [key, reverseKeys(value[key])]));
  }
  return value;
}

// Two runs with one measured finding that is resolved (SEC-01), one that changes impact (CTX-01), one that is new (VER-01),
// a judgment finding that is resolved (COD-01), one that is new (STR-01) and one that stays the same (RUL-01).
function changedRuns() {
  const a = runOf("first", {
    measuredFindings: [measured("mf-1"), measured("mf-2", { rule: "SEC-01", axis: "security", measurementRef: SEC_REF, trigger: "destructive" })],
    findings: [
      finding({ evidence: [{ file: "CLAUDE.md", line: 3 }] }),
      finding({ rule: "COD-01", axis: "code", summary: "Copied block.", impact: "low", evidence: [{ file: "src/a.js", line: 10 }] }),
      citing("mf-1"),
    ],
  });
  const b = runOf("second", {
    measuredFindings: [
      measured("mf-1", { impact: "medium" }),
      measured("mf-3", { rule: "VER-01", axis: "verification", measurementRef: "/verification/x", trigger: "missing" }),
    ],
    findings: [
      finding({ evidence: [{ file: "CLAUDE.md", line: 40 }] }),
      finding({ rule: "STR-01", axis: "structure", summary: "Unmapped folder.", impact: "low", evidence: [{ file: "docs/x.md", line: 1 }] }),
      citing("mf-1", { impact: "medium" }),
    ],
  });
  return { a, b };
}

// Tests of the output -------------------------------------------------------------------------------

test("a run compared with itself is all same, with no warnings and counts that match its units", () => {
  const measuredFindings = [measured("mf-1"), measured("mf-2", { rule: "SEC-01", axis: "security", measurementRef: SEC_REF, trigger: "destructive" })];
  const findings = [finding({}), citing("mf-1")];
  const result = compareRuns({
    a: runOf("first", { measuredFindings, findings }),
    b: runOf("second", { measuredFindings, findings }),
  });

  assert.deepEqual(result.counts, { resolved: 0, new: 0, "impact-changed": 0, same: 3 });
  assert.deepEqual(result.warnings, []);
  assert.equal(result.schemaVersion, COMPARISON_SCHEMA_VERSION);
  assert.equal(result.language, "en");
  // Sorted by axis: instructions, context, then security.
  assert.deepEqual(
    result.items.map((item) => [item.class, item.rule, item.kind]),
    [["same", "RUL-01", "judgment"], ["same", "CTX-01", "measured"], ["same", "SEC-01", "measured"]],
  );
});

test("resolved, new, impact-changed and same items, for measured and judgment findings", () => {
  const { a, b } = changedRuns();
  const result = compareRuns({ a, b });
  const withClass = (itemClass) => result.items.filter((item) => item.class === itemClass);

  assert.deepEqual(result.counts, { resolved: 2, new: 2, "impact-changed": 1, same: 1 });
  assert.deepEqual(withClass("resolved").map((item) => item.rule), ["SEC-01", "COD-01"]);
  assert.deepEqual(withClass("new").map((item) => item.rule), ["VER-01", "STR-01"]);
  assert.deepEqual(withClass("impact-changed").map((item) => item.rule), ["CTX-01"]);
  assert.deepEqual(withClass("same").map((item) => item.rule), ["RUL-01"]);

  for (const item of withClass("resolved")) assert.equal(item.b, null);
  for (const item of withClass("new")) assert.equal(item.a, null);
  const [changed] = withClass("impact-changed");
  assert.equal(changed.a.impact, "high");
  assert.equal(changed.b.impact, "medium");
  assert.equal(changed.kind, "measured");
  assert.equal(changed.a.cited, true);
  assert.equal(changed.a.summary, "The budget of mf-1 is over.");
  assert.deepEqual(changed.key, { measurementRef: CTX_REF, trigger: "budget-total" });
});

test("a measured side keeps its triggers in order, without threshold or detail, and says whether it is cited", () => {
  const { a, b } = changedRuns();
  const result = compareRuns({ a, b });
  const sec = result.items.find((item) => item.rule === "SEC-01");
  const ctx = result.items.find((item) => item.rule === "CTX-01");

  assert.deepEqual(sec.a.triggers, [{ trigger: "destructive", impact: "high", measurementRef: SEC_REF }]);
  assert.equal(sec.a.cited, false);
  assert.equal(sec.a.summary, null);
  assert.deepEqual(Object.keys(ctx.a.triggers[0]).sort(), ["impact", "measurementRef", "trigger"]);
});

test("a measured finding takes the summary of the first citing finding by index", () => {
  const measuredFindings = [measured("mf-1"), measured("mf-2", { trigger: "other" })];
  const findings = [citing("mf-1", { summary: "First." }), citing("mf-1", { summary: "Second." })];
  const result = compareRuns({
    a: runOf("first", { measuredFindings, findings }),
    b: runOf("second", { measuredFindings, findings }),
  });

  const first = result.items.find((item) => item.a.id === "mf-1");
  const second = result.items.find((item) => item.a.id === "mf-2");
  assert.equal(first.a.summary, "First.");
  assert.equal(second.a.cited, false);
  assert.equal(second.a.summary, null);
});

test("runs has the summary of each run: the target, head, depth, sorted scope, catalog and counts", () => {
  const a = runOf("first", { target: "app", scope: ["apps/web", "apps/api"], measuredFindings: [measured("mf-1")], findings: [finding({})] });
  const b = runOf("second", { target: "app", catalog: null, depth: "deep", findings: [] });
  const result = compareRuns({ a, b });

  assert.deepEqual(result.runs.a, {
    name: "first",
    target: "app",
    head: HEAD,
    scannedAt: "2026-10-17T12:00:00.000Z",
    schemaVersion: 1,
    depth: "standard",
    scope: ["apps/api", "apps/web"],
    catalog: CATALOG,
    findings: 1,
    measuredFindings: 1,
  });
  assert.deepEqual(result.runs.b, {
    name: "second",
    target: "app",
    head: HEAD,
    scannedAt: "2026-10-17T12:00:00.000Z",
    schemaVersion: 1,
    depth: "deep",
    scope: null,
    catalog: null,
    findings: 0,
    measuredFindings: 0,
  });
});

test("language is the one of findings.json of run B, and en when it has none", () => {
  const es = runOf("es", { language: "es", findings: [finding({})] });
  const plain = runOf("plain", { findings: [finding({})] });

  assert.equal(compareRuns({ a: es, b: plain }).language, "en");
  assert.equal(compareRuns({ a: plain, b: es }).language, "es");
});

// Pairing -------------------------------------------------------------------------------------------

test("pass 2 pairs a measured finding whose trigger name changes with the level, and keys the pair by B", () => {
  const a = runOf("first", { measuredFindings: [measured("mf-1", { impact: "medium", trigger: "always-loaded-total-medium" })] });
  const b = runOf("second", { measuredFindings: [measured("mf-1", { impact: "high", trigger: "always-loaded-total-high" })] });
  const result = compareRuns({ a, b });

  assert.equal(result.items.length, 1);
  const [item] = result.items;
  assert.equal(item.class, "impact-changed");
  assert.deepEqual(item.key, { measurementRef: CTX_REF, trigger: "always-loaded-total-high" });
  assert.deepEqual(item.a.triggers.map((trigger) => trigger.trigger), ["always-loaded-total-medium"]);
});

test("pass 2 needs the same measurementRef: another one is resolved and new (positive control)", () => {
  const a = runOf("first", { measuredFindings: [measured("mf-1", { trigger: "always-loaded-total-medium" })] });
  const b = runOf("second", {
    measuredFindings: [measured("mf-1", { measurementRef: "/context/other", trigger: "always-loaded-total-high" })],
  });
  const result = compareRuns({ a, b });

  assert.deepEqual(result.counts, { resolved: 1, new: 1, "impact-changed": 0, same: 0 });
});

test("pass 1 wins over pass 2: the B with the same trigger is paired, even when a B with another trigger comes first", () => {
  // Both B units have the rule and the measurementRef of A's unit. mf-1 comes first by its number and has another trigger,
  // so only the trigger tells that mf-2 is the same finding.
  const a = runOf("first", { measuredFindings: [measured("mf-1", { trigger: "budget-total", impact: "high" })] });
  const b = runOf("second", {
    measuredFindings: [
      measured("mf-1", { trigger: "other-trigger", impact: "medium" }),
      measured("mf-2", { trigger: "budget-total", impact: "high" }),
    ],
  });
  const result = compareRuns({ a, b });

  assert.deepEqual(result.counts, { resolved: 0, new: 1, "impact-changed": 0, same: 1 });
  assert.equal(result.items.find((item) => item.class === "same").b.id, "mf-2");
  assert.equal(result.items.find((item) => item.class === "new").b.id, "mf-1");
});

test("measured findings with the same key pair by the number of their id: mf-2 with mf-2, and mf-10 is left over", () => {
  const a = runOf("first", { measuredFindings: [measured("mf-10", { impact: "high" }), measured("mf-2", { impact: "low" })] });
  const b = runOf("second", { measuredFindings: [measured("mf-2", { impact: "low" })] });
  const result = compareRuns({ a, b });

  assert.deepEqual(result.counts, { resolved: 1, new: 0, "impact-changed": 0, same: 1 });
  const same = result.items.find((item) => item.class === "same");
  assert.equal(same.a.id, "mf-2");
  assert.equal(same.b.id, "mf-2");
  assert.equal(result.items.find((item) => item.class === "resolved").a.id, "mf-10");
});

test("judgment findings with the same key pair by index, and the one left over is resolved", () => {
  const a = runOf("first", {
    findings: [finding({ impact: "low", summary: "First." }), finding({ impact: "high", summary: "Second." })],
  });
  const b = runOf("second", { findings: [finding({ impact: "low", summary: "Only." })] });
  const result = compareRuns({ a, b });

  const same = result.items.find((item) => item.class === "same");
  const resolved = result.items.find((item) => item.class === "resolved");
  assert.equal(same.a.index, 0);
  assert.equal(same.a.summary, "First.");
  assert.equal(resolved.a.index, 1);
  assert.equal(resolved.a.summary, "Second.");
});

test("a judgment finding whose lines moved is still same, and its quote is not kept", () => {
  const a = runOf("first", { findings: [finding({ evidence: [{ file: "CLAUDE.md", line: 3, endLine: 4, quote: "Use pnpm." }] })] });
  const b = runOf("second", { findings: [finding({ evidence: [{ file: "CLAUDE.md", line: 40 }] })] });
  const result = compareRuns({ a, b });

  assert.deepEqual(result.counts, { resolved: 0, new: 0, "impact-changed": 0, same: 1 });
  const [item] = result.items;
  assert.deepEqual(item.a.evidence, [{ file: "CLAUDE.md", line: 3, endLine: 4 }]);
  assert.deepEqual(item.b.evidence, [{ file: "CLAUDE.md", line: 40 }]);
});

test("a judgment finding in another file is not the same (positive control for the case above)", () => {
  const a = runOf("first", { findings: [finding({ evidence: [{ file: "CLAUDE.md", line: 3 }] })] });
  const b = runOf("second", { findings: [finding({ evidence: [{ file: "AGENTS.md", line: 3 }] })] });

  assert.deepEqual(compareRuns({ a, b }).counts, { resolved: 1, new: 1, "impact-changed": 0, same: 0 });
});

test("a judgment finding whose impact changed is impact-changed, with its two impacts; the same impact is same (positive control)", () => {
  const a = runOf("first", { findings: [finding({ impact: "low" })] });
  const b = runOf("second", { findings: [finding({ impact: "high" })] });
  const result = compareRuns({ a, b });

  assert.deepEqual(result.counts, { resolved: 0, new: 0, "impact-changed": 1, same: 0 });
  const [item] = result.items;
  assert.equal(item.kind, "judgment");
  assert.equal(item.a.impact, "low");
  assert.equal(item.b.impact, "high");
  assert.deepEqual(item.key, { files: ["CLAUDE.md"] });

  const sameImpact = compareRuns({ a, b: runOf("second", { findings: [finding({ impact: "low" })] }) });
  assert.deepEqual(sameImpact.counts, { resolved: 0, new: 0, "impact-changed": 0, same: 1 });
});

test("the judgment key is the sorted list of the distinct files of the evidence", () => {
  const a = runOf("first", {
    findings: [finding({ evidence: [{ file: "b.md" }, { file: "a.md", line: 2 }, { file: "a.md" }] })],
  });
  const b = runOf("second", { findings: [finding({ evidence: [{ file: "a.md" }, { file: "b.md", line: 5 }] })] });
  const [item] = compareRuns({ a, b }).items;

  assert.equal(item.class, "same");
  assert.deepEqual(item.key, { files: ["a.md", "b.md"] });
});

test("a measured key with no matching trigger has a null trigger, which sorts before the named ones", () => {
  const a = runOf("first", {
    measuredFindings: [
      measured("mf-5", { trigger: "b-trigger" }),
      measured("mf-6", { triggers: [{ trigger: "other", impact: "high", measurementRef: "/other" }] }),
    ],
  });
  const b = runOf("second");
  const result = compareRuns({ a, b });

  assert.deepEqual(result.items.map((item) => [item.class, item.a.id, item.key.trigger]), [
    ["resolved", "mf-6", null],
    ["resolved", "mf-5", "b-trigger"],
  ]);
});

// Warnings -------------------------------------------------------------------------------------------

test("a run compared with a run that differs only in its name has no warnings (control)", () => {
  const result = compareRuns({ a: runOf("first"), b: runOf("second") });

  assert.deepEqual(result.warnings, []);
});

test("target-changed names the two targets, never their paths", () => {
  const result = compareRuns({
    a: runOf("first", { target: "app", root: "/synthetic/app" }),
    b: runOf("second", { target: "app", root: "/elsewhere/app" }),
  });

  assert.deepEqual(result.warnings, [{ code: "target-changed", a: "app", b: "app" }]);
  const text = toStableJson(result);
  assert.ok(!text.includes("/synthetic") && !text.includes("/elsewhere"));
});

test("scope-changed holds the scope of each run, or null for the whole target; the same folders in another order are not a change", () => {
  const warnings = compareRuns({
    a: runOf("first", { scope: ["apps/web"] }),
    b: runOf("second"),
  }).warnings;
  assert.deepEqual(warnings, [{ code: "scope-changed", a: ["apps/web"], b: null }]);

  const sameFolders = compareRuns({
    a: runOf("first", { scope: ["apps/web", "apps/api"] }),
    b: runOf("second", { scope: ["apps/api", "apps/web"] }),
  }).warnings;
  assert.deepEqual(sameFolders, []);
});

test("depth-changed holds the two depths; a run with no depth is standard (control)", () => {
  const warnings = compareRuns({ a: runOf("first", { depth: "quick" }), b: runOf("second") }).warnings;
  assert.deepEqual(warnings, [{ code: "depth-changed", a: "quick", b: "standard" }]);

  assert.deepEqual(compareRuns({ a: runOf("first", { depth: "standard" }), b: runOf("second") }).warnings, []);
});

test("catalog-changed holds the two catalogs when both runs have one and they differ", () => {
  const other = { count: 19, sha256: "000000000000" };
  const warnings = compareRuns({ a: runOf("first"), b: runOf("second", { catalog: other }) }).warnings;

  assert.deepEqual(warnings, [{ code: "catalog-changed", a: CATALOG, b: other }]);
});

test("catalog-unknown holds the catalog of each run, null where it has none", () => {
  const warnings = compareRuns({ a: runOf("first"), b: runOf("second", { catalog: null }) }).warnings;
  assert.deepEqual(warnings, [{ code: "catalog-unknown", a: CATALOG, b: null }]);

  const none = compareRuns({ a: runOf("first", { catalog: null }), b: runOf("second", { catalog: null }) }).warnings;
  assert.deepEqual(none, [{ code: "catalog-unknown", a: null, b: null }]);
});

test("schema-changed holds the two schema versions", () => {
  const warnings = compareRuns({ a: runOf("first"), b: runOf("second", { schemaVersion: 2 }) }).warnings;

  assert.deepEqual(warnings, [{ code: "schema-changed", a: 1, b: 2 }]);
});

test("several warnings come one per code, in the order of WARNING_CODES", () => {
  const result = compareRuns({
    a: runOf("first", { root: "/synthetic/app" }),
    b: runOf("second", { root: "/elsewhere/app", depth: "deep", schemaVersion: 2 }),
  });

  assert.deepEqual(result.warnings.map((warning) => warning.code), ["target-changed", "depth-changed", "schema-changed"]);
  assert.deepEqual(WARNING_CODES.filter((code) => result.warnings.some((warning) => warning.code === code)), [
    "target-changed",
    "depth-changed",
    "schema-changed",
  ]);
});

// Determinism -----------------------------------------------------------------------------------------

test("the result does not depend on the order of the keys of the inputs, nor on the order of the measured findings; two calls give the same bytes", () => {
  const { a, b } = changedRuns();
  const first = compareRuns({ a, b });
  const reversedKeys = compareRuns({ a: reverseKeys(a), b: reverseKeys(b) });
  const reversedList = compareRuns({
    a,
    b: { ...b, measurements: { ...b.measurements, measuredFindings: [...b.measurements.measuredFindings].reverse() } },
  });

  assert.deepEqual(reversedKeys, first);
  assert.deepEqual(reversedList, first);
  assert.equal(toStableJson(reversedKeys), toStableJson(first));
  assert.equal(toStableJson(compareRuns(changedRuns())), toStableJson(first));
});

// Input checks ---------------------------------------------------------------------------------------

// A valid run for the input checks: one measured finding that findings.json cites, and one judgment finding.
function validRun() {
  return {
    name: "run",
    measurements: measurementsOf({ measuredFindings: [measured("mf-1")], depth: "deep", scope: ["apps/web"] }),
    findings: { findings: [citing("mf-1"), finding({})] },
  };
}

// Gives the measured finding of validRun the id, and the finding that cites it.
function renameMeasured(run, id) {
  run.measurements.measuredFindings[0].id = id;
  run.findings.findings[0].measuredFindingId = id;
}

// Each refusal has a bad form, a good form that must pass (the positive control), the value of the file that the message
// must not quote (hostile), when there is one, and the field that the message must name (names), when there is one.
const REFUSALS = [
  {
    name: "measurements that are not an object",
    bad: (run) => { run.measurements = HOSTILE; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "measurements with a field of the report missing",
    bad: (run) => { delete run.measurements.code; },
    good: (run) => { run.measurements.code = { duplication: { duplicatedLinesPct: 0, filesScanned: 0 } }; },
  },
  {
    name: "a schemaVersion that is not a whole number",
    bad: (run) => { run.measurements.schemaVersion = HOSTILE; },
    good: (run) => { run.measurements.schemaVersion = 2; },
    hostile: HOSTILE,
  },
  {
    name: "a depth that is not a level",
    bad: (run) => { run.measurements.depth = HOSTILE; },
    good: (run) => { run.measurements.depth = "quick"; },
    hostile: HOSTILE,
  },
  {
    name: "a meta.scannedAt that is not text",
    bad: (run) => { run.measurements.meta.scannedAt = 17; },
    good: (run) => { run.measurements.meta.scannedAt = "2026-10-18T08:00:00.000Z"; },
  },
  {
    name: "a meta.scannedAt that is text but not a time",
    bad: (run) => { run.measurements.meta.scannedAt = HOSTILE; },
    good: (run) => { run.measurements.meta.scannedAt = "2026-10-18T08:00:00Z"; },
    hostile: HOSTILE,
    names: "meta.scannedAt",
  },
  {
    name: "a meta.scannedAt that reads as a date in words",
    bad: (run) => { run.measurements.meta.scannedAt = "yesterday"; },
    good: (run) => { run.measurements.meta.scannedAt = "2026-10-18T08:00:00.000Z"; },
    names: "meta.scannedAt",
  },
  {
    name: "a meta.scannedAt with an offset that is not UTC",
    bad: (run) => { run.measurements.meta.scannedAt = "2026-10-18T08:00:00+02:00"; },
    good: (run) => { run.measurements.meta.scannedAt = "2026-10-18T06:00:00.000Z"; },
    names: "meta.scannedAt",
  },
  {
    name: "a meta.targetRoot that is not text",
    bad: (run) => { run.measurements.meta.targetRoot = ["/synthetic/app"]; },
    good: (run) => { run.measurements.meta.targetRoot = "/synthetic/other"; },
  },
  {
    name: "a target.name that is not text",
    bad: (run) => { run.measurements.target.name = { value: HOSTILE }; },
    good: (run) => { run.measurements.target.name = "other"; },
    hostile: HOSTILE,
  },
  {
    name: "a target.git.head that is neither text nor null",
    bad: (run) => { run.measurements.target.git.head = 42; },
    good: (run) => { run.measurements.target.git.head = null; },
  },
  {
    name: "a target.git.head that is text but not a commit",
    bad: (run) => { run.measurements.target.git.head = HOSTILE; },
    good: (run) => { run.measurements.target.git.head = "b".repeat(64); },
    hostile: HOSTILE,
    names: "target.git.head",
  },
  {
    name: "a target.git.head in upper-case hex",
    bad: (run) => { run.measurements.target.git.head = "A".repeat(40); },
    good: (run) => { run.measurements.target.git.head = "c".repeat(40); },
    names: "target.git.head",
  },
  {
    name: "a scope that is not an object",
    bad: (run) => { run.measurements.scope = HOSTILE; },
    good: (run) => { delete run.measurements.scope; },
    hostile: HOSTILE,
  },
  {
    name: "a scope folder that is not text",
    bad: (run) => { run.measurements.scope.folders = ["apps/web", 3]; },
    good: (run) => { run.measurements.scope.folders = ["apps/web", "apps/api"]; },
    names: "scope.folders[1]",
  },
  {
    name: "a catalog with a negative count",
    bad: (run) => { run.measurements.meta.catalog = { count: -1, sha256: CATALOG.sha256 }; },
    good: (run) => { run.measurements.meta.catalog = { count: 0, sha256: "000000000000" }; },
  },
  {
    name: "a catalog with an upper-case hash",
    bad: (run) => { run.measurements.meta.catalog = { count: 19, sha256: "7BF4E797546C" }; },
    good: (run) => { run.measurements.meta.catalog = { count: 19, sha256: CATALOG.sha256 }; },
  },
  {
    name: "measuredFindings that is not a list",
    bad: (run) => { run.measurements.measuredFindings = HOSTILE; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "a measured finding that is not an object",
    bad: (run) => { run.measurements.measuredFindings = [HOSTILE]; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "a measured id with no mf- form",
    bad: (run) => renameMeasured(run, HOSTILE),
    good: (run) => renameMeasured(run, "mf-2"),
    hostile: HOSTILE,
  },
  {
    name: "two measured findings with one id",
    bad: (run) => { run.measurements.measuredFindings.push(measured("mf-1")); },
    good: (run) => { run.measurements.measuredFindings.push(measured("mf-3")); },
  },
  {
    name: "a measured rule that is not a rule id",
    bad: (run) => { run.measurements.measuredFindings[0].rule = HOSTILE; },
    good: (run) => { run.measurements.measuredFindings[0].rule = "CTX-02"; },
    hostile: HOSTILE,
  },
  {
    name: "a measured axis that is unknown",
    bad: (run) => { run.measurements.measuredFindings[0].axis = HOSTILE; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "a measured impact that is unknown",
    bad: (run) => { run.measurements.measuredFindings[0].impact = HOSTILE; },
    good: (run) => { run.measurements.measuredFindings[0].impact = "low"; },
    hostile: HOSTILE,
  },
  {
    name: "a measurementRef that is not text",
    bad: (run) => { run.measurements.measuredFindings[0].measurementRef = 3; },
    good: () => {},
  },
  {
    name: "a measured finding with no trigger",
    bad: (run) => { run.measurements.measuredFindings[0].triggers = []; },
    good: (run) => { run.measurements.measuredFindings[0].triggers = measured("mf-1").triggers; },
  },
  {
    name: "a trigger with an unknown impact",
    bad: (run) => { run.measurements.measuredFindings[0].triggers[0].impact = HOSTILE; },
    good: (run) => { run.measurements.measuredFindings[0].triggers[0].impact = "medium"; },
    hostile: HOSTILE,
  },
  {
    name: "a trigger with no measurementRef text",
    bad: (run) => { run.measurements.measuredFindings[0].triggers[0].measurementRef = null; },
    good: () => {},
  },
  {
    name: "findings that are not an object",
    bad: (run) => { run.findings = [HOSTILE]; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "a language that is not en or es",
    bad: (run) => { run.findings.language = HOSTILE; },
    good: (run) => { run.findings.language = "es"; },
    hostile: HOSTILE,
  },
  {
    name: "a findings list that is not a list",
    bad: (run) => { run.findings.findings = HOSTILE; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "a finding that is not an object",
    bad: (run) => { run.findings.findings[1] = HOSTILE; },
    good: (run) => { run.findings.findings[1] = finding({}); },
    hostile: HOSTILE,
  },
  {
    name: "a rule id that is not a rule",
    bad: (run) => { run.findings.findings[1].rule = HOSTILE; },
    good: (run) => { run.findings.findings[1].rule = "RUL-02"; },
    hostile: HOSTILE,
  },
  {
    name: "a kind that is not measured or judgment",
    bad: (run) => { run.findings.findings[1].kind = HOSTILE; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "an impact that is not high, medium or low",
    bad: (run) => { run.findings.findings[1].impact = HOSTILE; },
    good: (run) => { run.findings.findings[1].impact = "low"; },
    hostile: HOSTILE,
  },
  {
    name: "a summary that is not text",
    bad: (run) => { run.findings.findings[1].summary = 5; },
    good: (run) => { run.findings.findings[1].summary = "Text."; },
  },
  {
    name: "evidence that is not a list",
    bad: (run) => { run.findings.findings[1].evidence = HOSTILE; },
    good: (run) => { run.findings.findings[1].evidence = []; },
    hostile: HOSTILE,
  },
  {
    name: "an evidence line below 1",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md", line: 0 }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md", line: 1 }]; },
  },
  {
    name: "an evidence endLine that is text",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md", line: 2, endLine: HOSTILE }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md", line: 2, endLine: 4 }]; },
    hostile: HOSTILE,
  },
  {
    name: "an evidence file that is not text",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: 7 }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md" }]; },
  },
  {
    name: "an evidence layer that is not text",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "~/.claude/a.md", layer: 9 }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "~/.claude/a.md", layer: "user" }]; },
  },
  {
    name: "a measured finding that names no measured finding",
    bad: (run) => { run.findings.findings[0].measuredFindingId = "mf-9"; },
    good: () => {},
  },
  {
    name: "a measured finding with no measuredFindingId",
    bad: (run) => { delete run.findings.findings[0].measuredFindingId; },
    good: (run) => { run.findings.findings[0].measuredFindingId = "mf-1"; },
  },
  {
    name: "a measuredFindingId that is hostile text",
    bad: (run) => { run.findings.findings[0].measuredFindingId = HOSTILE; },
    good: () => {},
    hostile: HOSTILE,
  },
  {
    name: "an evidence file that is absolute, without a layer",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: `/${HOSTILE}.md` }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md" }]; },
    hostile: HOSTILE,
    names: "findings[1].evidence[0].file",
  },
  {
    name: "an evidence file with a backslash, without a layer",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "docs\\a.md" }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "docs/a.md" }]; },
    names: "findings[1].evidence[0].file",
  },
  {
    name: "an evidence file with a .. segment, without a layer",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: `../${HOSTILE}.md` }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "docs/a.md" }]; },
    hostile: HOSTILE,
    names: "findings[1].evidence[0].file",
  },
  {
    name: "an evidence file of layer user that is not under ~/.claude/",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "CLAUDE.md", layer: "user" }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "~/.claude/settings.json", layer: "user" }]; },
    names: "findings[1].evidence[0].file",
  },
  {
    name: "an evidence file of layer ancestor that does not start with ../",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "~/.claude/settings.json", layer: "ancestor" }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "../CLAUDE.md", layer: "ancestor" }]; },
    names: "findings[1].evidence[0].file",
  },
  {
    name: "an evidence layer that is not user or ancestor",
    bad: (run) => { run.findings.findings[1].evidence = [{ file: "~/.claude/a.md", layer: HOSTILE }]; },
    good: (run) => { run.findings.findings[1].evidence = [{ file: "~/.claude/a.md", layer: "user" }]; },
    hostile: HOSTILE,
    names: "findings[1].evidence[0].layer",
  },
];

function assertRefused(run, { hostile, names } = {}) {
  assert.throws(
    () => checkRunInputs(run, "A"),
    (error) => {
      assert.ok(error instanceof UsageError, "the refusal is a UsageError, so the command line exits with 2");
      assert.match(error.message, /^run A: /);
      if (hostile !== undefined) assert.ok(!error.message.includes(hostile), "the message holds no value of the file");
      if (names !== undefined) assert.ok(error.message.includes(names), `the message names ${names}: ${error.message}`);
      return true;
    },
  );
}

test("checkRunInputs accepts the valid run (positive control)", () => {
  assert.doesNotThrow(() => checkRunInputs(validRun(), "A"));
});

for (const refusal of REFUSALS) {
  test(`checkRunInputs refuses ${refusal.name}, and accepts the good form (positive control)`, () => {
    const bad = validRun();
    refusal.bad(bad);
    assertRefused(bad, refusal);

    const good = validRun();
    refusal.good(good);
    assert.doesNotThrow(() => checkRunInputs(good, "A"));
  });
}

test("compareRuns names the run that is not an input, A or B, and refuses a run without a name", () => {
  const badA = validRun();
  badA.measurements.schemaVersion = HOSTILE;
  assert.throws(
    () => compareRuns({ a: { ...badA, name: "first" }, b: { ...validRun(), name: "second" } }),
    (error) => error instanceof UsageError && error.message.startsWith("run A: "),
  );

  const badB = validRun();
  badB.findings.findings[1].kind = HOSTILE;
  assert.throws(
    () => compareRuns({ a: { ...validRun(), name: "first" }, b: { ...badB, name: "second" } }),
    (error) => error instanceof UsageError && error.message.startsWith("run B: "),
  );

  assert.throws(() => compareRuns({ a: { ...validRun(), name: 3 }, b: { ...validRun(), name: "second" } }), TypeError);
});

// Schema ----------------------------------------------------------------------------------------------

test("the comparison validates against schemas/comparison.schema.json, and a broken value is reported (positive control)", () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
  const { a, b } = changedRuns();
  b.measurements.meta.targetRoot = "/synthetic/other";
  b.measurements.depth = "deep";
  b.measurements.scope = { folders: ["apps/web"], inherited: ["."], files: { inScope: 1, outside: 2 } };
  delete b.measurements.meta.catalog;
  b.findings.language = "es";
  const result = compareRuns({ a, b });

  assert.deepEqual(schemaProblems(schema, result), []);
  assert.deepEqual(result.warnings.map((warning) => warning.code), ["target-changed", "scope-changed", "depth-changed", "catalog-unknown"]);
  assert.equal(result.language, "es");

  const broken = structuredClone(result);
  broken.counts.same = -1;
  assert.notDeepEqual(schemaProblems(schema, broken), []);
  const brokenItem = structuredClone(result);
  brokenItem.items[0].class = "other";
  assert.notDeepEqual(schemaProblems(schema, brokenItem), []);
});
