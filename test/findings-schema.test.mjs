import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  AXES,
  EVIDENCE_FIELDS,
  EVIDENCE_LAYERS,
  FINDING_FIELDS,
  IMPACTS,
  KINDS,
  LANGUAGES,
  REQUIRED_FINDING_FIELDS,
  TOP_LEVEL_FIELDS,
  loadRules,
} from "../scripts/lib/findings-validate.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCHEMA_FILE = path.join(HARNESS_ROOT, "schemas", "findings.schema.json");
const SCHEMA = JSON.parse(fs.readFileSync(SCHEMA_FILE, "utf8"));
const sorted = (values) => [...values].sort();

test("findings schema: the top-level fields and the finding fields are the ones the validator accepts", () => {
  assert.deepEqual(sorted(Object.keys(SCHEMA.properties)), sorted(TOP_LEVEL_FIELDS));
  assert.deepEqual(sorted(Object.keys(SCHEMA.$defs.finding.properties)), sorted(FINDING_FIELDS));
  assert.deepEqual(sorted(Object.keys(SCHEMA.$defs.evidence.properties)), sorted(EVIDENCE_FIELDS));
});

test("findings schema: unknown fields are errors at every level", () => {
  assert.equal(SCHEMA.additionalProperties, false, "the top level");
  assert.equal(SCHEMA.$defs.finding.additionalProperties, false, "a finding");
  assert.equal(SCHEMA.$defs.evidence.additionalProperties, false, "an evidence entry");
});

test("findings schema: the required fields are the ones the validator checks", () => {
  assert.deepEqual(SCHEMA.required, ["findings"]);
  assert.deepEqual(sorted(SCHEMA.$defs.finding.required), sorted(REQUIRED_FINDING_FIELDS));
  assert.deepEqual(SCHEMA.$defs.evidence.required, ["file"]);
});

test("findings schema: the evidence layers are the validator's set, and a layer is optional", () => {
  assert.deepEqual(SCHEMA.$defs.evidence.properties.layer.enum, [...EVIDENCE_LAYERS]);
  assert.deepEqual(SCHEMA.$defs.evidence.required, ["file"]);
});

test("findings schema: the enumerations are the validator's sets", () => {
  assert.deepEqual(SCHEMA.properties.language.enum, [...LANGUAGES]);
  assert.deepEqual(SCHEMA.$defs.finding.properties.kind.enum, [...KINDS]);
  assert.deepEqual(SCHEMA.$defs.finding.properties.impact.enum, [...IMPACTS]);
  assert.deepEqual(SCHEMA.$defs.finding.properties.axis.enum, [...AXES]);
});

test("findings schema: the rule pattern accepts every rule of the catalog", () => {
  const pattern = new RegExp(SCHEMA.$defs.finding.properties.rule.pattern);
  const rules = loadRules(HARNESS_ROOT);
  assert.ok(rules.length > 0);
  for (const rule of rules) assert.match(rule.id, pattern);
});

test("findings schema: measuredFindingId is for measured findings only, and measuredSupport for judgment only", () => {
  const conditions = SCHEMA.$defs.finding.allOf;
  assert.equal(conditions.length, 2);
  const measured = conditions.find((item) => item.if.properties.kind.const === "measured");
  const judgment = conditions.find((item) => item.if.properties.kind.const === "judgment");
  assert.deepEqual(measured.then.required, ["measuredFindingId"]);
  assert.deepEqual(measured.then.not, { required: ["measuredSupport"] });
  assert.deepEqual(judgment.then.not, { required: ["measuredFindingId"] });
});
