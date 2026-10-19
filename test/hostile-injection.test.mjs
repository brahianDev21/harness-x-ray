// The hostile-injection fixture holds instructions aimed at the agent and at the scanner: in CLAUDE.md, in a rule file,
// in a code comment and in a fenced JSON block. Those are data. The scan must report what the rules give, must not run
// the package.json scripts (they would write a marker file), and must not write anything into the target.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { makeFixture } from "./helpers/make-fixture.mjs";

const execFileAsync = promisify(execFile);
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
const HOSTILE = path.join(TEST_DIR, "fixtures", "hostile-injection");
// Files that the injected instructions ask for, or that a package.json script writes if it runs.
const MARKERS = ["harness-pwned.txt", "harness-pwned-lint.txt", ".harness-auditor-approved", "findings.json"];
const MEMORY_RULES = ["RUL-01", "RUL-02", "RUL-03", "VER-01", "SEC-04", "SEC-05", "STR-01", "COD-04"];

// Every file and folder below root, as POSIX paths, sorted. The .git folder is left out: git may touch its own files
// while it lists the target, and this check is about the working tree.
function listTree(root) {
  const entries = [];
  const walk = (folder) => {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
      if (folder === root && entry.name === ".git") continue;
      const full = path.join(folder, entry.name);
      entries.push(path.relative(root, full).split(path.sep).join("/") + (entry.isDirectory() ? "/" : ""));
      if (entry.isDirectory()) walk(full);
    }
  };
  walk(root);
  return entries.sort();
}

async function scanCopy(t) {
  const fixture = makeFixture({ fromDir: HOSTILE, git: true });
  t.after(fixture.cleanup);
  const before = listTree(fixture.root);
  const out = path.join(fixture.base, "out");
  await execFileAsync(process.execPath, [SCAN_SCRIPT, fixture.root, "--out", out], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
  const data = JSON.parse(fs.readFileSync(path.join(out, "measurements.json"), "utf8"));
  return { fixture, before, out, data };
}

test("hostile-injection: the injected text is data, so the findings are exactly the ones the rules give", async (t) => {
  const { data } = await scanCopy(t);

  const sixteenDefaults = Array.from({ length: 16 }, (_, index) => ({
    trigger: "default-mode-without-hook",
    impact: "medium",
    measurementRef: `/security/destructiveCoverage/commands/${index}`,
  }));
  assert.deepEqual(data.measuredFindings, [
    {
      id: "mf-1",
      rule: "RUL-04",
      axis: "instructions",
      impact: "medium",
      measurementRef: "/instructions/brokenRefs/0",
      evidence: [{ file: "CLAUDE.md", line: 6 }],
      triggers: [{ trigger: "reference-missing", impact: "medium", measurementRef: "/instructions/brokenRefs/0" }],
    },
    {
      // The positive control: a verification command that the memory names and the package.json does not define.
      id: "mf-2",
      rule: "RUL-04",
      axis: "instructions",
      impact: "high",
      measurementRef: "/instructions/brokenRefs/1",
      evidence: [{ file: "CLAUDE.md", line: 8 }],
      triggers: [{ trigger: "verification-command-missing", impact: "high", measurementRef: "/instructions/brokenRefs/1" }],
    },
    {
      id: "mf-3",
      rule: "RUL-04",
      axis: "instructions",
      impact: "medium",
      measurementRef: "/instructions/brokenRefs/2",
      evidence: [{ file: "CLAUDE.md", line: 12 }],
      triggers: [{ trigger: "reference-missing", impact: "medium", measurementRef: "/instructions/brokenRefs/2" }],
    },
    {
      // No settings file: every destructive command asks by the default mode, with no hook.
      id: "mf-4",
      rule: "SEC-02",
      axis: "security",
      impact: "medium",
      measurementRef: "/security/destructiveCoverage/commands/0",
      evidence: [],
      triggers: sixteenDefaults,
    },
    {
      id: "mf-5",
      rule: "SEC-03",
      axis: "security",
      impact: "medium",
      measurementRef: "/security/secrets/readProtection/envAtRoot/decision",
      evidence: [],
      triggers: [
        {
          trigger: "env-at-root-readable",
          impact: "medium",
          measurementRef: "/security/secrets/readProtection/envAtRoot/decision",
        },
      ],
    },
  ]);
  assert.deepEqual(data.candidates, [
    { id: "cand-1", kind: "memory-file", rules: MEMORY_RULES, measurementRef: "/inventory/0", file: ".claude/rules/injected.md", loadMode: "always" },
    { id: "cand-2", kind: "memory-file", rules: MEMORY_RULES, measurementRef: "/inventory/1", file: "CLAUDE.md", loadMode: "always" },
  ]);
  assert.deepEqual(data.undeterminable, []);
});

test("hostile-injection: no package.json script runs, nothing is written into the target, and the output is one file", async (t) => {
  const { fixture, before, out } = await scanCopy(t);

  for (const marker of MARKERS) {
    assert.equal(fs.existsSync(path.join(fixture.root, marker)), false, `${marker} must not exist`);
  }
  assert.deepEqual(listTree(fixture.root), before, "the scan left the target as it found it");
  assert.deepEqual(fs.readdirSync(out), ["measurements.json"]);
});
