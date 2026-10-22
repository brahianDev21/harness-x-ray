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
import { SECRET_FIXTURE_FILES } from "./helpers/secret-fixture-files.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const FIXTURES = path.join(TEST_DIR, "fixtures");
const SNAPSHOTS = path.join(TEST_DIR, "snapshots", "measured-findings");
// catalog-good is a catalog for check-catalog.mjs. It is not a folder of a project, so it is not scanned.
const CATALOG_FIXTURES = new Set(["catalog-good"]);
// Secret files that a fixture needs but does not version (see test/helpers/secret-fixture-files.mjs).
const UNVERSIONED_FILES = new Map([["secrets", SECRET_FIXTURE_FILES]]);
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
    const fixture = makeFixture({ fromDir: path.join(FIXTURES, name), git: true, files: UNVERSIONED_FILES.get(name) ?? {} });
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

// The self-scan shape: this repository's own .claude/settings.json has one PreToolUse hook on Read, Grep, Bash and
// PowerShell that fails closed, and no permission rule and no defaultMode. Its script is written here empty and is never
// run. The scan cannot tell that the hook blocks the destructive commands, so SEC-02 is low, one trigger per command.
const SELF_SCAN_SETTINGS = {
  hooks: {
    PreToolUse: [
      {
        matcher: "Read|Grep|Bash|PowerShell",
        hooks: [
          { type: "command", command: "node", args: ["${CLAUDE_PROJECT_DIR}/scripts/hooks/guard-secret-reads.mjs"], onFailure: "block" },
        ],
      },
    ],
  },
};

test("the self-scan shape: a fail-closed PreToolUse hook on Bash gives SEC-02 low, with one hook-not-verified per command", async (t) => {
  const fixture = makeFixture({
    files: {
      ".claude/settings.json": `${JSON.stringify(SELF_SCAN_SETTINGS, null, 2)}\n`,
      "scripts/hooks/guard-secret-reads.mjs": "// Never run by the scan; its content does not matter here.\n",
    },
  });
  t.after(fixture.cleanup);
  const { data } = await scanInto(fixture.root, path.join(fixture.base, "self"));

  const commands = data.security.destructiveCoverage.commands;
  assert.equal(commands.length, 16, "the scanner lists the 16 destructive commands");
  const findings = data.measuredFindings.filter((finding) => finding.rule === "SEC-02");
  assert.equal(findings.length, 1);
  const [finding] = findings;
  assert.equal(finding.impact, "low");
  assert.deepEqual(
    finding.triggers.map((item) => [item.trigger, item.impact, item.measurementRef]),
    commands.map((_, index) => ["hook-not-verified", "low", `/security/destructiveCoverage/commands/${index}`]),
  );
  assert.deepEqual(finding.evidence, [{ file: ".claude/settings.json" }, { file: "scripts/hooks/guard-secret-reads.mjs" }]);
  assert.ok(
    data.candidates.some((item) => item.kind === "hook-script" && item.file === "scripts/hooks/guard-secret-reads.mjs"),
    "the hook script is a candidate for the agent to read",
  );
});

test("the positive controls keep their SEC-02 finding: default-only medium, permissive high, guarded none", async (t) => {
  for (const [name, impact] of [
    ["default-only", "medium"],
    ["permissive", "high"],
    ["guarded", null],
  ]) {
    const fixture = makeFixture({ fromDir: path.join(FIXTURES, name) });
    t.after(fixture.cleanup);
    const { data } = await scanInto(fixture.root, path.join(fixture.base, "out"));
    const findings = data.measuredFindings.filter((finding) => finding.rule === "SEC-02");
    if (impact === null) {
      assert.deepEqual(findings, [], name);
    } else {
      assert.equal(findings.length, 1, name);
      assert.equal(findings[0].impact, impact, name);
    }
  }
});
