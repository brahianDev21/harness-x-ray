// Every fixture of test/fixtures is scanned as a temp copy, and its measured findings, candidates and undeterminable
// cases are compared with the snapshot in test/snapshots/measured-findings/<fixture>.json. The snapshots were checked by
// hand against the rule tables before they were committed. Each measurementRef must resolve in the scanned
// measurements, and each evidence file must exist in the copy (or be an ancestor path). Two scans must agree, except meta.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { toStableJson } from "../scripts/lib/json-out.mjs";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const SNAPSHOTS = path.join(TEST_DIR, "snapshots", "measured-findings");
// catalog-good is a catalog for check-catalog.mjs. It is not a folder of a project, so it is not scanned.
const CATALOG_FIXTURES = new Set(["catalog-good"]);
const TARGETS = fs
  .readdirSync(FIXTURES, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && !CATALOG_FIXTURES.has(entry.name))
  .map((entry) => entry.name)
  .sort();
const SNAPSHOT_KEYS = ["candidates", "measuredFindings", "undeterminable"];

// Runs the command line on a copy and returns the parsed and the raw measurements.
async function scanInto(root, out) {
  await execFileAsync(process.execPath, [SCAN_SCRIPT, root, "--out", out], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
  const raw = fs.readFileSync(path.join(out, "measurements.json"), "utf8");
  return { data: JSON.parse(raw), raw };
}

// The meta block is written with the scan time, so determinism checks leave it out.
function withoutMetaText(raw) {
  const stripped = raw.replace(/^  "meta": \{\n[\s\S]*?^  \},\n/m, "");
  assert.notEqual(stripped, raw, "the meta block was not found");
  return stripped;
}

function pick(data) {
  return Object.fromEntries(SNAPSHOT_KEYS.map((key) => [key, data[key]]));
}

// Every pointer that the derived lists carry.
function refsOf(data) {
  const refs = [];
  for (const finding of data.measuredFindings) {
    refs.push(finding.measurementRef, ...finding.triggers.map((item) => item.measurementRef));
  }
  refs.push(...data.candidates.map((candidate) => candidate.measurementRef));
  refs.push(...data.undeterminable.map((item) => item.measurementRef));
  return refs;
}

// The value at an RFC 6901 pointer, or a marker when it does not exist.
const MISSING = Symbol("missing");
function resolvePointer(root, pointer) {
  if (!pointer.startsWith("/")) return MISSING;
  let node = root;
  for (const raw of pointer.split("/").slice(1)) {
    const key = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (node === null || typeof node !== "object" || !Object.hasOwn(node, key)) return MISSING;
    node = node[key];
  }
  return node;
}

// The forms a path can take in JSON text: as given, with forward slashes, and escaped as JSON.
function pathForms(folder) {
  const forms = new Set();
  for (const value of [folder, folder.replaceAll("\\", "/")]) {
    forms.add(value);
    forms.add(JSON.stringify(value).slice(1, -1));
  }
  return [...forms].filter((form) => form.length >= 4);
}

test("there is one snapshot for each target fixture and no other", () => {
  const snapshots = fs
    .readdirSync(SNAPSHOTS)
    .filter((name) => name.endsWith(".json"))
    .map((name) => name.slice(0, -".json".length))
    .sort();
  assert.deepEqual(snapshots, TARGETS);
});

for (const name of TARGETS) {
  test(`fixture ${name}: measured findings match the snapshot, refs resolve, evidence exists, and two scans agree`, async (t) => {
    const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), git: true });
    t.after(fixture.cleanup);
    const first = await scanInto(fixture.root, path.join(fixture.base, "first"));
    const second = await scanInto(fixture.root, path.join(fixture.base, "second"));

    const expected = JSON.parse(fs.readFileSync(path.join(SNAPSHOTS, `${name}.json`), "utf8"));
    const actual = pick(first.data);
    assert.deepEqual(actual, expected, "the measured findings differ from the snapshot");

    for (const ref of refsOf(first.data)) {
      assert.notEqual(resolvePointer(first.data, ref), MISSING, `measurementRef ${ref} points to no value`);
    }

    const evidenceFiles = [
      ...first.data.measuredFindings.flatMap((finding) => finding.evidence),
      ...first.data.candidates.flatMap((candidate) => (candidate.file === undefined ? [] : [{ file: candidate.file }])),
    ].map((item) => item.file);
    for (const file of evidenceFiles) {
      if (file.startsWith("../")) continue;
      assert.equal(fs.existsSync(path.join(fixture.root, file)), true, `evidence file ${file} is not in the target`);
    }

    assert.equal(withoutMetaText(first.raw), withoutMetaText(second.raw), "two scans of the same copy differ outside meta");
    const { meta: _firstMeta, ...restFirst } = first.data;
    const { meta: _secondMeta, ...restSecond } = second.data;
    assert.deepEqual(restFirst, restSecond);

    const text = toStableJson(actual);
    for (const folder of [fixture.root, fixture.base, HARNESS_ROOT]) {
      for (const form of pathForms(folder)) {
        assert.equal(text.includes(form), false, `an absolute path leaked into the derived lists: ${form}`);
      }
    }
  });
}
