import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { isPlainObject } from "../scripts/lib/json-out.mjs";
import {
  EMITTERS,
  THRESHOLDS as REEXPORTED_THRESHOLDS,
  THRESHOLDS_STATUS as REEXPORTED_STATUS,
  countByAxis,
  deriveMeasuredOutput,
} from "../scripts/lib/measured-findings.mjs";
import { THRESHOLDS, THRESHOLDS_STATUS } from "../scripts/lib/thresholds.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");

const CLEAN_ENV = Object.freeze({ decision: "deny", reason: "deny-rule", rule: "Read(**/.env)", source: ".claude/settings.json" });
const DEFAULT_ENV = Object.freeze({ decision: "default", reason: "no-rule-matched", rule: null, source: null });
const DEFAULT_READ = Object.freeze({ decision: "default", reason: "no-rule-matched", rule: null, source: null });
const DENY_READ = Object.freeze({ decision: "deny", reason: "deny-rule", rule: "Read(./dist/**)", source: ".claude/settings.json" });
const ASK_READ = Object.freeze({ decision: "ask", reason: "ask-rule", rule: "Read(./docs/**)", source: ".claude/settings.json" });
const SETTINGS = ".claude/settings.json";

// A measurements object with no finding: every section is present and empty, as a scan of a clean folder writes them.
function baseMeasurements() {
  return {
    inventory: [],
    context: { alwaysLoaded: { estTokensTotal: 0, byComponent: [], unknownStatic: [] }, ancestors: [] },
    instructions: { brokenRefs: [] },
    security: {
      permissions: { allow: [], ask: [], deny: [], additionalDirectories: [], defaultMode: null },
      destructiveCoverage: { mode: null, commands: [], preToolUseHooks: [], subagents: [] },
      secrets: { fileListSource: "git", files: [], literals: [], readProtection: { envAtRoot: CLEAN_ENV, preToolUseReadHooks: [] } },
    },
    structure: { generatedFiles: [], largeFiles: [] },
    code: { duplication: { duplicatedLinesPct: 0, groups: [] } },
    claudeConfig: { hooks: [] },
  };
}

// Plain objects merge recursively; arrays and other values replace the base.
function merge(base, changes) {
  const out = { ...base };
  for (const [key, value] of Object.entries(changes)) {
    out[key] = isPlainObject(value) && isPlainObject(base[key]) ? merge(base[key], value) : value;
  }
  return out;
}

function measured(changes = {}) {
  return merge(baseMeasurements(), changes);
}

function withSecurity(changes) {
  return { security: changes };
}

function shellCommand(id, outcome, decidedBy, preToolUseHook = "none") {
  return { id, tool: "Bash", command: id, outcome, decidedBy, reason: `${outcome}-reason`, preToolUseHook };
}

const MODE_DEFAULT = Object.freeze({ kind: "mode", mode: "default" });
const MODE_ACCEPT = Object.freeze({ kind: "mode", mode: "acceptEdits" });
const ALLOW = (rule, source = SETTINGS) => ({ kind: "rule", list: "allow", rule, source });

function hook(changes) {
  return {
    source: SETTINGS,
    matcher: "Bash",
    if: null,
    type: "command",
    command: "node .claude/hooks/guard.mjs",
    script: { path: ".claude/hooks/guard.mjs", external: false, exists: true },
    onFailure: "block",
    failsOpen: false,
    tools: ["Bash"],
    ...changes,
  };
}

// The derived output of a measurements object.
function derived(m) {
  return deriveMeasuredOutput(m);
}

// The findings of one rule, reduced to what the assertions need.
function summaryOf(m, rule) {
  return derived(m)
    .measuredFindings.filter((finding) => finding.rule === rule)
    .map((finding) => ({
      id: finding.id,
      impact: finding.impact,
      ref: finding.measurementRef,
      triggers: finding.triggers.map((item) => [item.trigger, item.impact, item.measurementRef]),
    }));
}

function undeterminableOf(m, rule) {
  return derived(m).undeterminable.filter((item) => item.rule === rule);
}

function findingsOf(m, rule) {
  return derived(m).measuredFindings.filter((finding) => finding.rule === rule);
}

// ---------------------------------------------------------------------------------------------------
// The table and the exports

test("thresholds: the six keys the rules cite, all provisional, frozen, and re-exported unchanged", () => {
  assert.deepEqual(Object.keys(THRESHOLDS).sort(), [
    "alwaysLoadedTokensHigh",
    "alwaysLoadedTokensMedium",
    "duplicationPctHigh",
    "duplicationPctMedium",
    "largeFileBytes",
    "memoryFileMaxLines",
  ]);
  assert.deepEqual(THRESHOLDS, {
    memoryFileMaxLines: 200,
    alwaysLoadedTokensMedium: 3000,
    alwaysLoadedTokensHigh: 6000,
    largeFileBytes: 262144,
    duplicationPctMedium: 5,
    duplicationPctHigh: 15,
  });
  assert.equal(THRESHOLDS_STATUS, "provisional");
  assert.ok(Object.isFrozen(THRESHOLDS));
  assert.equal(REEXPORTED_THRESHOLDS, THRESHOLDS);
  assert.equal(REEXPORTED_STATUS, THRESHOLDS_STATUS);
});

test("thresholds.mjs has no imports, so any module can import it without a cycle", () => {
  const source = fs.readFileSync(path.join(HARNESS_ROOT, "scripts", "lib", "thresholds.mjs"), "utf8");
  assert.doesNotMatch(source, /^\s*import\s/m);
  assert.doesNotMatch(source, /\bfrom\s+["']/);
});

test("EMITTERS: frozen, one emitter per measured MVP rule, in axis order", () => {
  assert.ok(Object.isFrozen(EMITTERS));
  assert.deepEqual(Object.keys(EMITTERS), ["RUL-04", "CTX-01", "CTX-07", "SEC-01", "SEC-02", "SEC-03", "STR-02", "COD-01"]);
  for (const emitter of Object.values(EMITTERS)) assert.equal(typeof emitter, "function");
});

test("derive: a measurements object without any section gives empty lists, not an error", () => {
  assert.deepEqual(deriveMeasuredOutput({}), { measuredFindings: [], candidates: [], undeterminable: [] });
});

test("derive: a clean scan has no findings, no undeterminable case and no candidate", () => {
  assert.deepEqual(derived(measured()), { measuredFindings: [], candidates: [], undeterminable: [] });
});

test("derive: does not change its input", () => {
  const m = measured({ instructions: { brokenRefs: [{ file: "CLAUDE.md", kind: "path", line: 1, reason: "not-found", text: "a/b.md" }] } });
  const before = JSON.stringify(m);
  derived(m);
  assert.equal(JSON.stringify(m), before);
});

test("derive: ids are mf-N in emitter order and cand-N in list order", () => {
  const m = measured({
    instructions: {
      brokenRefs: [
        { file: "CLAUDE.md", kind: "path", line: 2, reason: "not-found", text: "a/b.md" },
        { file: "CLAUDE.md", kind: "path", line: 3, reason: "not-found", text: "c/d.md" },
      ],
    },
    inventory: [{ path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: 2, estTokens: 5, bytes: 9 }],
    code: { duplication: { duplicatedLinesPct: 6, groups: [{ lines: 8, redundantLines: 8, copies: [{ file: "a.js", line: 1, endLine: 8 }, { file: "b.js", line: 1, endLine: 8 }] }] } },
  });
  const out = derived(m);
  assert.deepEqual(out.measuredFindings.map((finding) => finding.id), ["mf-1", "mf-2", "mf-3"]);
  assert.deepEqual(out.measuredFindings.map((finding) => finding.rule), ["RUL-04", "RUL-04", "COD-01"]);
  assert.deepEqual(out.candidates.map((candidate) => candidate.id), ["cand-1", "cand-2"]);
  assert.deepEqual(out.candidates.map((candidate) => candidate.kind), ["duplication-group", "memory-file"]);
});

test("countByAxis: a count for every axis, in axis order", () => {
  const counts = countByAxis([{ axis: "security" }, { axis: "security" }, { axis: "code" }]);
  assert.deepEqual(Object.entries(counts), [
    ["instructions", 0],
    ["context", 0],
    ["security", 2],
    ["verification", 0],
    ["structure", 0],
    ["code", 1],
  ]);
});

const MEMORY_RULES = ["RUL-01", "RUL-02", "RUL-03", "VER-01", "SEC-04", "SEC-05", "STR-01", "COD-04"];

// ---------------------------------------------------------------------------------------------------
// RUL-04

test("RUL-04: a missing check script is high, a missing other script or a missing path is medium", () => {
  const m = measured({
    instructions: {
      brokenRefs: [
        { file: "CLAUDE.md", kind: "script", line: 4, reason: "missing-script", script: "test:e2e", text: "npm run test:e2e" },
        { file: "CLAUDE.md", kind: "script", line: 5, reason: "missing-script", script: "deploy", text: "npm run deploy" },
        { file: "CLAUDE.md", kind: "path", line: 6, reason: "not-found", text: "src/lib/api.ts" },
        { file: "AGENTS.md", kind: "script", line: 2, reason: "missing-script", script: "check:secrets", text: "npm run check:secrets" },
        { file: "AGENTS.md", kind: "script", line: 3, reason: "missing-script", script: "build:legacy", text: "npm run build:legacy" },
      ],
    },
  });
  assert.deepEqual(summaryOf(m, "RUL-04"), [
    { id: "mf-1", impact: "high", ref: "/instructions/brokenRefs/0", triggers: [["verification-command-missing", "high", "/instructions/brokenRefs/0"]] },
    { id: "mf-2", impact: "medium", ref: "/instructions/brokenRefs/1", triggers: [["reference-missing", "medium", "/instructions/brokenRefs/1"]] },
    { id: "mf-3", impact: "medium", ref: "/instructions/brokenRefs/2", triggers: [["reference-missing", "medium", "/instructions/brokenRefs/2"]] },
    { id: "mf-4", impact: "high", ref: "/instructions/brokenRefs/3", triggers: [["verification-command-missing", "high", "/instructions/brokenRefs/3"]] },
    { id: "mf-5", impact: "medium", ref: "/instructions/brokenRefs/4", triggers: [["reference-missing", "medium", "/instructions/brokenRefs/4"]] },
  ]);
  assert.deepEqual(findingsOf(m, "RUL-04")[0].evidence, [{ file: "CLAUDE.md", line: 4 }]);
});

test("RUL-04: a path named like a check is not a verification command", () => {
  const m = measured({
    instructions: { brokenRefs: [{ file: "CLAUDE.md", kind: "path", line: 1, reason: "not-found", text: "scripts/lint.sh" }] },
  });
  assert.equal(summaryOf(m, "RUL-04")[0].impact, "medium");
});

test("RUL-04: no broken reference, no finding", () => {
  assert.deepEqual(summaryOf(measured(), "RUL-04"), []);
});

// ---------------------------------------------------------------------------------------------------
// CTX-01

test("CTX-01: a memory file of 200 lines is not a finding; 201 lines is medium, with a ref to its lines", () => {
  const file = (lines) => ({ path: "CLAUDE.md", kind: "memory", loadMode: "always", lines, estTokens: 10, bytes: 100 });
  assert.deepEqual(summaryOf(measured({ inventory: [file(200)] }), "CTX-01"), []);
  assert.deepEqual(summaryOf(measured({ inventory: [file(201)] }), "CTX-01"), [
    {
      id: "mf-1",
      impact: "medium",
      ref: "/context/alwaysLoaded/estTokensTotal",
      triggers: [["memory-file-over-limit", "medium", "/inventory/0/lines"]],
    },
  ]);
});

test("CTX-01: a total of 3000 tokens is not a finding; 3001 is medium, and its ref is the number", () => {
  const at = measured({ context: { alwaysLoaded: { estTokensTotal: 3000 } } });
  const over = measured({ context: { alwaysLoaded: { estTokensTotal: 3001 } } });
  assert.deepEqual(summaryOf(at, "CTX-01"), []);
  assert.deepEqual(summaryOf(over, "CTX-01"), [
    {
      id: "mf-1",
      impact: "medium",
      ref: "/context/alwaysLoaded/estTokensTotal",
      triggers: [["always-loaded-total-medium", "medium", "/context/alwaysLoaded/estTokensTotal"]],
    },
  ]);
  assert.deepEqual(findingsOf(over, "CTX-01")[0].triggers[0].threshold, { key: "alwaysLoadedTokensMedium", value: 3000 });
});

test("CTX-01: a total above 6000 is high; exactly 6000 is medium", () => {
  assert.equal(summaryOf(measured({ context: { alwaysLoaded: { estTokensTotal: 6000 } } }), "CTX-01")[0].impact, "medium");
  const high = summaryOf(measured({ context: { alwaysLoaded: { estTokensTotal: 6001 } } }), "CTX-01");
  assert.equal(high[0].impact, "high");
  assert.deepEqual(high[0].triggers, [["always-loaded-total-high", "high", "/context/alwaysLoaded/estTokensTotal"]]);
});

test("CTX-01: a file over 200 lines and a total over 3000 are one medium finding with two triggers", () => {
  const m = measured({
    inventory: [{ path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: 250, estTokens: 3277, bytes: 9000 }],
    context: { alwaysLoaded: { estTokensTotal: 3277 } },
  });
  const [finding] = findingsOf(m, "CTX-01");
  assert.equal(finding.impact, "medium");
  assert.equal(finding.measurementRef, "/context/alwaysLoaded/estTokensTotal");
  assert.deepEqual(finding.triggers.map((item) => item.trigger), ["memory-file-over-limit", "always-loaded-total-medium"]);
  assert.deepEqual(finding.evidence, [{ file: "CLAUDE.md" }]);
});

test("CTX-01: a long file on demand or a long rule is not a memory file of the rule; no finding", () => {
  const m = measured({
    inventory: [
      { path: "packages/web/CLAUDE.md", kind: "memory", loadMode: "on-demand", lines: 300, estTokens: 4000, bytes: 9000 },
      { path: ".claude/rules/api.md", kind: "rule", loadMode: "always", lines: 260, estTokens: 3000, bytes: 9000 },
    ],
  });
  assert.deepEqual(summaryOf(m, "CTX-01"), []);
});

test("CTX-01: ancestor files never count, because the scan has no lines or tokens for them", () => {
  const m = measured({ context: { alwaysLoaded: { estTokensTotal: 10 }, ancestors: [{ path: "../CLAUDE.md", bytes: 900000 }] } });
  assert.deepEqual(summaryOf(m, "CTX-01"), []);
});

test("CTX-01: a file with null lines (not read) gives no line trigger", () => {
  const m = measured({ inventory: [{ path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: null, estTokens: null, bytes: 9 }] });
  assert.deepEqual(summaryOf(m, "CTX-01"), []);
});

// ---------------------------------------------------------------------------------------------------
// CTX-07

test("CTX-07: AGENTS.md not loaded beside a CLAUDE.md in the target is medium, with the cause", () => {
  const m = measured({
    inventory: [
      { path: "AGENTS.md", kind: "memory", loadMode: "not-loaded", lines: 120, estTokens: 800, bytes: 4000 },
      { path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: 30, estTokens: 200, bytes: 900 },
    ],
  });
  const [finding] = findingsOf(m, "CTX-07");
  assert.equal(finding.impact, "medium");
  assert.equal(finding.measurementRef, "/inventory/0");
  assert.deepEqual(finding.triggers, [
    { trigger: "agents-md-not-loaded", impact: "medium", measurementRef: "/inventory/0", detail: { causedBy: "target" } },
  ]);
  assert.deepEqual(finding.evidence, [{ file: "AGENTS.md" }, { file: "CLAUDE.md" }]);
});

test("CTX-07: the cause is an ancestor CLAUDE.md when the target has none", () => {
  const m = measured({
    inventory: [{ path: "AGENTS.md", kind: "memory", loadMode: "not-loaded", lines: 40, estTokens: 300, bytes: 1300 }],
    context: { ancestors: [{ path: "../AGENTS.md", bytes: 10 }, { path: "../CLAUDE.md", bytes: 500 }] },
  });
  const [finding] = findingsOf(m, "CTX-07");
  assert.deepEqual(finding.triggers[0].detail, { causedBy: "ancestor" });
  assert.deepEqual(finding.evidence, [{ file: "AGENTS.md" }, { file: "../CLAUDE.md" }]);
});

test("CTX-07: .claude/AGENTS.md counts too; an AGENTS.md that loads is no finding", () => {
  const notLoaded = measured({
    inventory: [
      { path: ".claude/AGENTS.md", kind: "memory", loadMode: "not-loaded", lines: 5, estTokens: 40, bytes: 200 },
      { path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: 2, estTokens: 10, bytes: 80 },
    ],
  });
  assert.deepEqual(summaryOf(notLoaded, "CTX-07").map((item) => item.ref), ["/inventory/0"]);
  const loads = measured({
    inventory: [{ path: "AGENTS.md", kind: "memory", loadMode: "always", lines: 5, estTokens: 40, bytes: 200 }],
  });
  assert.deepEqual(summaryOf(loads, "CTX-07"), []);
});

test("CTX-07: an AGENTS.md that claudeMdExcludes matches is not a finding, while one that a CLAUDE.md causes still is (positive control)", () => {
  const excluded = {
    path: "AGENTS.md",
    kind: "memory",
    loadMode: "not-loaded",
    loadReason: "claude-md-excludes",
    excludedBy: "AGENTS.md",
    lines: null,
    estTokens: null,
    bytes: 4000,
  };
  const claude = { path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: 30, estTokens: 200, bytes: 900 };
  assert.deepEqual(summaryOf(measured({ inventory: [excluded, claude] }), "CTX-07"), []);

  const notExcluded = {
    path: "AGENTS.md",
    kind: "memory",
    loadMode: "not-loaded",
    loadReason: "a CLAUDE.md exists and does not import it",
    lines: 120,
    estTokens: 800,
    bytes: 4000,
  };
  assert.deepEqual(summaryOf(measured({ inventory: [notExcluded, claude] }), "CTX-07").map((item) => item.ref), ["/inventory/0"]);
});

test("CTX-07: an AGENTS.md whose only root CLAUDE.md files are excluded is undeterminable, not a finding (positive control: a CLAUDE.md that loads still gives a finding)", () => {
  const unverified = {
    path: "AGENTS.md",
    kind: "memory",
    loadMode: "not-loaded",
    loadReason: "claude-md-excluded-agents-unverified",
    lines: 3,
    estTokens: 20,
    bytes: 40,
  };
  const excluded = measured({ inventory: [unverified] });
  assert.deepEqual(summaryOf(excluded, "CTX-07"), []);
  const undetermined = derived(excluded).undeterminable.filter((entry) => entry.rule === "CTX-07");
  assert.deepEqual(undetermined.map((entry) => entry.measurementRef), ["/inventory/0"]);
  assert.equal(typeof undetermined[0].reason, "string");

  const control = measured({ inventory: [{ ...unverified, loadReason: "a CLAUDE.md exists and does not import it" }] });
  assert.deepEqual(summaryOf(control, "CTX-07").map((item) => item.ref), ["/inventory/0"]);
  assert.deepEqual(derived(control).undeterminable.filter((entry) => entry.rule === "CTX-07"), []);
});

// ---------------------------------------------------------------------------------------------------
// SEC-01

test("SEC-01: a bare Bash allow, or Bash(*), is high", () => {
  for (const rule of ["Bash", "Bash(*)", "PowerShell"]) {
    const m = measured({ security: { permissions: { allow: [{ rule, source: SETTINGS }] } } });
    const [finding] = findingsOf(m, "SEC-01");
    assert.equal(finding.impact, "high", rule);
    assert.deepEqual(finding.triggers, [{ trigger: "bare-shell-allow", impact: "high", measurementRef: "/security/permissions/allow/0" }]);
  }
});

test("SEC-01: a wildcard allow that lets a listed destructive command pass is high, with the command ids", () => {
  const m = measured({
    security: {
      permissions: { allow: [{ rule: "Bash(git *)", source: SETTINGS }] },
      destructiveCoverage: {
        commands: [
          shellCommand("git-push-force", "passes", ALLOW("Bash(git *)")),
          shellCommand("git-reset-hard", "passes", ALLOW("Bash(git *)")),
          shellCommand("rm-recursive-force", "asks", MODE_DEFAULT),
        ],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-01");
  assert.equal(finding.impact, "high");
  assert.deepEqual(finding.triggers, [
    {
      trigger: "destructive-allow-passes",
      impact: "high",
      measurementRef: "/security/permissions/allow/0",
      detail: { commands: ["git-push-force", "git-reset-hard"] },
    },
  ]);
  assert.deepEqual(finding.evidence, [{ file: SETTINGS }]);
});

test("SEC-01: a wildcard allow that passes no listed destructive command is medium", () => {
  const m = measured({
    security: {
      permissions: { allow: [{ rule: "Bash(npm run *)", source: SETTINGS }] },
      destructiveCoverage: { commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT)] },
    },
  });
  const [finding] = findingsOf(m, "SEC-01");
  assert.equal(finding.impact, "medium");
  assert.deepEqual(finding.triggers, [{ trigger: "wildcard-shell-allow", impact: "medium", measurementRef: "/security/permissions/allow/0" }]);
});

test("SEC-01: an exact allow is no finding", () => {
  const m = measured({ security: { permissions: { allow: [{ rule: "Bash(npm test)", source: SETTINGS }] } } });
  assert.deepEqual(summaryOf(m, "SEC-01"), []);
});

test("SEC-01: deny and ask entries, even wildcards, are never triggers: they only narrow what runs", () => {
  const m = measured({
    security: {
      permissions: {
        deny: [{ rule: "Bash(*)", source: SETTINGS }],
        ask: [{ rule: "Bash(git *)", source: SETTINGS }],
        allow: [],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-01"), []);
});

test("SEC-01: a compound decidedBy names several allow rules, and each part is looked up on its own", () => {
  const m = measured({
    security: {
      permissions: {
        allow: [
          { rule: "Bash(git *)", source: SETTINGS },
          { rule: "Bash(npm *)", source: SETTINGS },
          { rule: "Bash(npm test)", source: SETTINGS },
        ],
      },
      destructiveCoverage: {
        commands: [shellCommand("compound-reset", "passes", ALLOW("Bash(git *) && Bash(npm test)"))],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-01");
  assert.deepEqual(finding.triggers, [
    { trigger: "destructive-allow-passes", impact: "high", measurementRef: "/security/permissions/allow/0", detail: { commands: ["compound-reset"] } },
    { trigger: "wildcard-shell-allow", impact: "medium", measurementRef: "/security/permissions/allow/1" },
  ]);
});

test("SEC-01: acceptEdits in the project is high; auto and bypassPermissions are ignored, not triggers", () => {
  const applies = measured({
    security: { permissions: { defaultMode: { value: "acceptEdits", effect: "applies", source: SETTINGS } } },
  });
  assert.deepEqual(summaryOf(applies, "SEC-01"), [
    {
      id: "mf-1",
      impact: "high",
      ref: "/security/permissions/defaultMode",
      triggers: [["accept-edits-in-project", "high", "/security/permissions/defaultMode"]],
    },
  ]);
  for (const value of ["auto", "bypassPermissions"]) {
    const ignored = measured({
      security: { permissions: { defaultMode: { value, effect: "ignored-from-project", source: SETTINGS } } },
    });
    assert.deepEqual(summaryOf(ignored, "SEC-01"), [], value);
  }
});

test("SEC-01: a subagent with a shell tool in acceptEdits is high; without a shell tool it is not", () => {
  const shell = measured({
    security: {
      destructiveCoverage: {
        subagents: [{ path: ".claude/agents/fixer.md", name: "fixer", permissionMode: "default", effectiveMode: "acceptEdits", shellTools: ["Bash"], results: [] }],
      },
    },
  });
  assert.deepEqual(summaryOf(shell, "SEC-01")[0].triggers, [
    ["subagent-accept-edits-shell", "high", "/security/destructiveCoverage/subagents/0"],
  ]);
  assert.equal(findingsOf(shell, "SEC-01")[0].evidence[0].file, ".claude/agents/fixer.md");

  const noShell = measured({
    security: {
      destructiveCoverage: {
        subagents: [{ path: ".claude/agents/reader.md", name: "reader", permissionMode: "acceptEdits", effectiveMode: "acceptEdits", shellTools: [], results: [] }],
      },
    },
  });
  assert.deepEqual(summaryOf(noShell, "SEC-01"), []);
});

test("SEC-01: a root, home or drive-root additional directory is medium; a folder is not", () => {
  const broad = measured({
    security: {
      permissions: {
        additionalDirectories: [
          { path: "/", source: SETTINGS },
          { path: "C:/", source: SETTINGS },
          { path: "~", source: SETTINGS },
          { path: "../shared-docs", source: SETTINGS },
        ],
      },
    },
  });
  assert.deepEqual(
    findingsOf(broad, "SEC-01")[0].triggers.map((item) => [item.trigger, item.measurementRef]),
    [
      ["broad-additional-directory", "/security/permissions/additionalDirectories/0"],
      ["broad-additional-directory", "/security/permissions/additionalDirectories/1"],
      ["broad-additional-directory", "/security/permissions/additionalDirectories/2"],
    ],
  );
  assert.equal(findingsOf(broad, "SEC-01")[0].impact, "medium");
});

// ---------------------------------------------------------------------------------------------------
// SEC-02

test("SEC-02: a passing command is high, and a passing subagent result is high, each with its own ref", () => {
  const m = measured({
    security: {
      permissions: { defaultMode: null },
      destructiveCoverage: {
        mode: { value: "acceptEdits", effect: "applies", source: SETTINGS },
        commands: [
          shellCommand("rm-recursive-force", "passes", MODE_ACCEPT),
          shellCommand("curl-pipe-shell", "asks", MODE_ACCEPT),
        ],
        subagents: [
          {
            path: ".claude/agents/fixer.md",
            name: "fixer",
            permissionMode: "acceptEdits",
            effectiveMode: "acceptEdits",
            shellTools: ["Bash"],
            results: [{ id: "git-reset-hard", outcome: "passes", decidedBy: ALLOW("Bash(git *)"), reason: "allow-rule" }],
          },
        ],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-02");
  assert.equal(finding.impact, "high");
  assert.deepEqual(finding.triggers, [
    { trigger: "destructive-command-passes", impact: "high", measurementRef: "/security/destructiveCoverage/commands/0" },
    { trigger: "destructive-command-passes", impact: "high", measurementRef: "/security/destructiveCoverage/subagents/0/results/0" },
  ]);
  assert.deepEqual(finding.evidence, [{ file: SETTINGS }, { file: ".claude/agents/fixer.md" }]);
});

test("SEC-02: a command that only the default-mode prompt stops is medium, with no hook", () => {
  const m = measured({
    security: { destructiveCoverage: { commands: [shellCommand("npm-publish", "asks", MODE_DEFAULT, "none")] } },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), [
    {
      id: "mf-1",
      impact: "medium",
      ref: "/security/destructiveCoverage/commands/0",
      triggers: [["default-mode-without-hook", "medium", "/security/destructiveCoverage/commands/0"]],
    },
  ]);
});

const ASK_PUSH = Object.freeze({ kind: "rule", list: "ask", rule: "Bash(git push *)", source: SETTINGS });

test("SEC-02: a command that an ask rule covers is no finding, with or without a hook that fails closed", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [
          shellCommand("git-push-force", "asks", ASK_PUSH, "none"),
          shellCommand("git-push-force-long", "asks", ASK_PUSH, "runs"),
        ],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), []);
});

test("SEC-02: a default-mode command behind a hook that runs and fails closed is low, and the ask rule beside it is not", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [
          shellCommand("git-push-force", "asks", ASK_PUSH, "none"),
          shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs"),
        ],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), [
    {
      id: "mf-1",
      impact: "low",
      ref: "/security/destructiveCoverage/commands/1",
      triggers: [["hook-not-verified", "low", "/security/destructiveCoverage/commands/1"]],
    },
  ]);
  const [finding] = findingsOf(m, "SEC-02");
  assert.deepEqual(finding.evidence, [{ file: SETTINGS }, { file: ".claude/hooks/guard.mjs" }]);
});

test("SEC-02: the low row needs the default mode, and a command with no hook is still the medium row", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("npm-publish", "asks", MODE_DEFAULT, "none")],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02").map((item) => item.triggers[0][0]), ["default-mode-without-hook"]);
  const accept = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("curl-pipe-shell", "asks", MODE_ACCEPT, "runs")],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  assert.deepEqual(summaryOf(accept, "SEC-02"), []);
});

test("SEC-02: a hook that covers the command and fails open is medium, and the low row does not join it", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs")],
        preToolUseHooks: [hook({ failsOpen: false }), hook({ failsOpen: true, onFailure: null })],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-02");
  assert.equal(finding.impact, "medium");
  assert.deepEqual(finding.triggers, [{ trigger: "hook-fails-open", impact: "medium", measurementRef: "/security/destructiveCoverage/preToolUseHooks/1" }]);
});

test("SEC-02: a fail-open hook that covers only PowerShell does not stop the Bash command from being low", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs")],
        preToolUseHooks: [
          hook({ failsOpen: false }),
          hook({ failsOpen: true, onFailure: null, matcher: "PowerShell", tools: ["PowerShell"] }),
        ],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), [
    {
      id: "mf-1",
      impact: "medium",
      ref: "/security/destructiveCoverage/preToolUseHooks/1",
      triggers: [
        ["hook-fails-open", "medium", "/security/destructiveCoverage/preToolUseHooks/1"],
        ["hook-not-verified", "low", "/security/destructiveCoverage/commands/0"],
      ],
    },
  ]);
});

test("SEC-02: a fail-open hook whose matcher cannot be settled does not stop a fail-closed covering hook from giving low, and is undeterminable, not medium", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs")],
        preToolUseHooks: [hook({ failsOpen: false }), hook({ failsOpen: true, onFailure: null, tools: "undeterminable" })],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), [
    {
      id: "mf-1",
      impact: "low",
      ref: "/security/destructiveCoverage/commands/0",
      triggers: [["hook-not-verified", "low", "/security/destructiveCoverage/commands/0"]],
    },
  ]);
  assert.deepEqual(findingsOf(m, "SEC-02")[0].evidence, [{ file: SETTINGS }, { file: ".claude/hooks/guard.mjs" }]);
  assert.deepEqual(undeterminableOf(m, "SEC-02").map((item) => item.measurementRef), [
    "/security/destructiveCoverage/preToolUseHooks/1/tools",
  ]);
});

test("SEC-02: a runs state with an empty list of PreToolUse hooks gives no hook-not-verified (defensive)", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs")],
        preToolUseHooks: [],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), []);
  assert.deepEqual(undeterminableOf(m, "SEC-02"), []);
});

test("SEC-02: a default-mode command with an ignored mode, behind a fail-closed covering hook, is low (positive control)", () => {
  const ignoredAuto = Object.freeze({ kind: "mode", mode: "default", ignoredMode: "auto" });
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", ignoredAuto, "runs")],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), [
    {
      id: "mf-1",
      impact: "low",
      ref: "/security/destructiveCoverage/commands/0",
      triggers: [["hook-not-verified", "low", "/security/destructiveCoverage/commands/0"]],
    },
  ]);
});

test("SEC-02: a fail-closed hook whose matcher cannot be settled is not in the low evidence, next to a fail-closed covering hook (positive control)", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs")],
        preToolUseHooks: [
          hook({ failsOpen: false, tools: "undeterminable", script: { path: ".claude/hooks/other.mjs", external: false, exists: true } }),
          hook({ failsOpen: false }),
        ],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-02");
  assert.equal(finding.impact, "low");
  assert.deepEqual(finding.triggers, [
    { trigger: "hook-not-verified", impact: "low", measurementRef: "/security/destructiveCoverage/commands/0" },
  ]);
  assert.deepEqual(finding.evidence, [{ file: SETTINGS }, { file: ".claude/hooks/guard.mjs" }]);
  assert.deepEqual(undeterminableOf(m, "SEC-02"), []);
});

test("SEC-02: when a command passes, only the high row is shown, even with a hook that fails closed", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [
          shellCommand("rm-recursive-force", "passes", ALLOW("Bash(rm -rf *)"), "runs"),
          shellCommand("npm-publish", "asks", MODE_DEFAULT, "runs"),
        ],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-02");
  assert.equal(finding.impact, "high");
  assert.deepEqual(finding.triggers, [
    { trigger: "destructive-command-passes", impact: "high", measurementRef: "/security/destructiveCoverage/commands/0" },
  ]);
});

test("SEC-02: a PreToolUse hook that fails open and covers Bash is medium, with the settings file and the script", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "asks", MODE_DEFAULT, "runs")],
        preToolUseHooks: [hook({ failsOpen: true, onFailure: null })],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-02");
  assert.equal(finding.impact, "medium");
  assert.deepEqual(finding.triggers, [{ trigger: "hook-fails-open", impact: "medium", measurementRef: "/security/destructiveCoverage/preToolUseHooks/0" }]);
  assert.deepEqual(finding.evidence, [{ file: SETTINGS }, { file: ".claude/hooks/guard.mjs" }]);
});

test("SEC-02: a fail-open hook whose script is missing cites only its settings file", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        preToolUseHooks: [hook({ failsOpen: true, script: { path: "scripts/missing.mjs", external: false, exists: false } })],
      },
    },
  });
  assert.deepEqual(findingsOf(m, "SEC-02")[0].evidence, [{ file: SETTINGS }]);
});

test("SEC-02: a hook that fails closed, and blocked commands, are no finding", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        commands: [shellCommand("rm-recursive-force", "blocked", { kind: "rule", list: "deny", rule: "Bash(rm -rf *)", source: SETTINGS }, "runs")],
        preToolUseHooks: [hook({ failsOpen: false })],
      },
    },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), []);
  assert.deepEqual(undeterminableOf(m, "SEC-02"), []);
});

test("SEC-02: when something passes, the medium rows do not apply", () => {
  const m = measured({
    security: {
      destructiveCoverage: {
        mode: { value: "acceptEdits", effect: "applies", source: SETTINGS },
        commands: [shellCommand("rm-recursive-force", "passes", MODE_ACCEPT), shellCommand("npm-publish", "asks", MODE_DEFAULT, "none")],
        preToolUseHooks: [hook({ failsOpen: true })],
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-02");
  assert.deepEqual(finding.triggers.map((item) => item.trigger), ["destructive-command-passes"]);
});

test("SEC-02: an undeterminable outcome, or an undeterminable hook state, is listed and is not a finding", () => {
  const outcome = measured({
    security: { destructiveCoverage: { commands: [{ ...shellCommand("rm-recursive-force", "undeterminable", null), reason: "compound-command" }] } },
  });
  assert.deepEqual(summaryOf(outcome, "SEC-02"), []);
  assert.deepEqual(undeterminableOf(outcome, "SEC-02"), [
    { rule: "SEC-02", measurementRef: "/security/destructiveCoverage/commands/0/outcome", reason: "outcome undeterminable: compound-command" },
  ]);

  const hookState = measured({
    security: { destructiveCoverage: { commands: [shellCommand("npm-publish", "asks", MODE_DEFAULT, "undeterminable")] } },
  });
  assert.deepEqual(summaryOf(hookState, "SEC-02"), []);
  assert.deepEqual(undeterminableOf(hookState, "SEC-02"), [
    {
      rule: "SEC-02",
      measurementRef: "/security/destructiveCoverage/commands/0/preToolUseHook",
      reason: "the PreToolUse hook state is undeterminable",
    },
  ]);
});

test("SEC-02: a fail-open hook whose matcher cannot be settled is undeterminable, not a finding", () => {
  const m = measured({
    security: { destructiveCoverage: { preToolUseHooks: [hook({ failsOpen: true, tools: "undeterminable" })] } },
  });
  assert.deepEqual(summaryOf(m, "SEC-02"), []);
  assert.deepEqual(undeterminableOf(m, "SEC-02"), [
    {
      rule: "SEC-02",
      measurementRef: "/security/destructiveCoverage/preToolUseHooks/0/tools",
      reason: "the hook matcher does not settle which tools it covers",
    },
  ]);
});

// ---------------------------------------------------------------------------------------------------
// SEC-03

test("SEC-03: a secret-named file in git is high; in a walked folder it is not versioned", () => {
  const file = { path: ".env", kind: "dotenv", readDecision: { decision: "deny", reason: "deny-rule", rule: "Read(**/.env)", source: SETTINGS } };
  const versioned = measured({ security: { secrets: { fileListSource: "git", files: [file] } } });
  assert.deepEqual(summaryOf(versioned, "SEC-03")[0].triggers, [["secret-file-versioned", "high", "/security/secrets/files/0"]]);
  const walked = measured({ security: { secrets: { fileListSource: "walk", files: [file] } } });
  assert.deepEqual(summaryOf(walked, "SEC-03"), []);
});

test("SEC-03: a secret-named file that the agent reads without a prompt is high; one that asks is medium", () => {
  const readable = measured({
    security: { secrets: { fileListSource: "walk", files: [{ path: "config/server.pem", kind: "pem", readDecision: DEFAULT_READ }] } },
  });
  assert.deepEqual(summaryOf(readable, "SEC-03")[0].triggers, [["secret-file-readable", "high", "/security/secrets/files/0/readDecision"]]);
  assert.equal(summaryOf(readable, "SEC-03")[0].impact, "high");

  const asks = measured({
    security: { secrets: { fileListSource: "walk", files: [{ path: "config/server.pem", kind: "pem", readDecision: ASK_READ }] } },
  });
  assert.deepEqual(summaryOf(asks, "SEC-03")[0].triggers, [["secret-file-read-with-prompt", "medium", "/security/secrets/files/0/readDecision"]]);
  assert.equal(summaryOf(asks, "SEC-03")[0].impact, "medium");
});

test("SEC-03: a secret-named file that a deny covers, and a literal-free harness, are no finding", () => {
  const denied = measured({
    security: { secrets: { fileListSource: "walk", files: [{ path: "config/server.pem", kind: "pem", readDecision: { ...DENY_READ, rule: "Read(**/*.pem)" } }] } },
  });
  assert.deepEqual(summaryOf(denied, "SEC-03"), []);
});

test("SEC-03: a literal secret is high, with its file and line", () => {
  const m = measured({
    security: { secrets: { literals: [{ file: ".mcp.json", line: 7, kind: "github-token", masked: "ghp_…a1b2", location: "mcpServers.docs.env.TOKEN" }] } },
  });
  const [finding] = findingsOf(m, "SEC-03");
  assert.equal(finding.impact, "high");
  assert.deepEqual(finding.triggers, [{ trigger: "literal-secret", impact: "high", measurementRef: "/security/secrets/literals/0" }]);
  assert.deepEqual(finding.evidence, [{ file: ".mcp.json", line: 7 }]);
});

test("SEC-03: a root .env that the agent can read is medium; a deny or an ask gives no finding", () => {
  const readable = measured({ security: { secrets: { readProtection: { envAtRoot: DEFAULT_ENV, preToolUseReadHooks: [] } } } });
  assert.deepEqual(summaryOf(readable, "SEC-03"), [
    {
      id: "mf-1",
      impact: "medium",
      ref: "/security/secrets/readProtection/envAtRoot/decision",
      triggers: [["env-at-root-readable", "medium", "/security/secrets/readProtection/envAtRoot/decision"]],
    },
  ]);
  const allowed = measured({ security: { secrets: { readProtection: { envAtRoot: { ...DEFAULT_ENV, decision: "allow" }, preToolUseReadHooks: [] } } } });
  assert.equal(summaryOf(allowed, "SEC-03")[0].impact, "medium");
  const asks = measured({ security: { secrets: { readProtection: { envAtRoot: { ...DEFAULT_ENV, decision: "ask" }, preToolUseReadHooks: [] } } } });
  assert.deepEqual(summaryOf(asks, "SEC-03"), []);
  const denied = measured({ security: { secrets: { readProtection: { envAtRoot: CLEAN_ENV, preToolUseReadHooks: [] } } } });
  assert.deepEqual(summaryOf(denied, "SEC-03"), []);
});

test("SEC-03: a read hook that runs and fails closed clears the .env row; one that fails open does not", () => {
  const closed = measured({
    security: {
      secrets: {
        readProtection: {
          envAtRoot: DEFAULT_ENV,
          preToolUseReadHooks: [{ source: SETTINGS, matcher: "Read", runsForEnv: "runs", failsOpen: false }],
        },
      },
    },
  });
  assert.deepEqual(summaryOf(closed, "SEC-03"), []);
  const open = measured({
    security: {
      secrets: {
        readProtection: {
          envAtRoot: DEFAULT_ENV,
          preToolUseReadHooks: [{ source: SETTINGS, matcher: "Read", runsForEnv: "runs", failsOpen: true }],
        },
      },
    },
  });
  assert.deepEqual(summaryOf(open, "SEC-03")[0].triggers, [["env-at-root-readable", "medium", "/security/secrets/readProtection/envAtRoot/decision"]]);
});

test("SEC-03: an undeterminable .env decision is listed, not a finding; so is an undeterminable hook that could cover it", () => {
  const decision = measured({
    security: { secrets: { readProtection: { envAtRoot: { decision: "undeterminable", reason: "unknown-mode", rule: null, source: null }, preToolUseReadHooks: [] } } },
  });
  assert.deepEqual(summaryOf(decision, "SEC-03"), []);
  assert.deepEqual(undeterminableOf(decision, "SEC-03"), [
    { rule: "SEC-03", measurementRef: "/security/secrets/readProtection/envAtRoot/decision", reason: "read decision for .env undeterminable: unknown-mode" },
  ]);

  const hookState = measured({
    security: {
      secrets: {
        readProtection: {
          envAtRoot: DEFAULT_ENV,
          preToolUseReadHooks: [{ source: SETTINGS, matcher: "Read", runsForEnv: "undeterminable", failsOpen: true }],
        },
      },
    },
  });
  assert.deepEqual(summaryOf(hookState, "SEC-03"), []);
  assert.deepEqual(undeterminableOf(hookState, "SEC-03"), [
    {
      rule: "SEC-03",
      measurementRef: "/security/secrets/readProtection/preToolUseReadHooks/0/runsForEnv",
      reason: "a PreToolUse hook may cover a read of .env; it is undeterminable",
    },
  ]);
});

test("SEC-03: an undeterminable file read is listed; a versioned file with one is still a finding for being versioned", () => {
  const undetermined = { path: "config/server.pem", kind: "pem", readDecision: { decision: "undeterminable", reason: "wrapper", rule: null, source: null } };
  const walked = measured({ security: { secrets: { fileListSource: "walk", files: [undetermined] } } });
  assert.deepEqual(summaryOf(walked, "SEC-03"), []);
  assert.deepEqual(undeterminableOf(walked, "SEC-03"), [
    { rule: "SEC-03", measurementRef: "/security/secrets/files/0/readDecision", reason: "read decision undeterminable: wrapper" },
  ]);
  const git = measured({ security: { secrets: { fileListSource: "git", files: [undetermined] } } });
  assert.deepEqual(summaryOf(git, "SEC-03")[0].triggers, [["secret-file-versioned", "high", "/security/secrets/files/0"]]);
  assert.equal(undeterminableOf(git, "SEC-03").length, 1);
});

// ---------------------------------------------------------------------------------------------------
// STR-02

function entry(changes) {
  return {
    kind: "folder",
    path: "dist",
    pattern: "dist",
    files: 1,
    bytes: 6,
    protection: { read: DEFAULT_READ, edit: DEFAULT_READ },
    memory: { marked: false, mentions: [] },
    ...changes,
  };
}

test("STR-02: a generated entry with no deny and no mark is medium", () => {
  const m = measured({ structure: { generatedFiles: [entry({})] } });
  assert.deepEqual(summaryOf(m, "STR-02"), [
    {
      id: "mf-1",
      impact: "medium",
      ref: "/structure/generatedFiles/0",
      triggers: [["generated-entry-unprotected", "medium", "/structure/generatedFiles/0"]],
    },
  ]);
  assert.deepEqual(findingsOf(m, "STR-02")[0].evidence, [{ file: "dist" }]);
  assert.deepEqual(findingsOf(m, "STR-02")[0].triggers[0].detail, { read: { decision: "default" }, edit: { decision: "default" } });
});

test("STR-02: a large file with no deny and no mark is low", () => {
  const m = measured({
    structure: { largeFiles: [{ path: "data/dump.bin", bytes: 300000, protection: { read: DEFAULT_READ, edit: DEFAULT_READ }, memory: { marked: false, mentions: [] } }] },
  });
  assert.deepEqual(summaryOf(m, "STR-02"), [
    {
      id: "mf-1",
      impact: "low",
      ref: "/structure/largeFiles/0",
      triggers: [["large-file-unprotected", "low", "/structure/largeFiles/0"]],
    },
  ]);
});

test("STR-02: a Read deny, an Edit deny or a do-not-touch mark covers the entry; ask does not", () => {
  const covered = [
    entry({ protection: { read: DENY_READ, edit: DEFAULT_READ } }),
    entry({ protection: { read: DEFAULT_READ, edit: DENY_READ } }),
    entry({ memory: { marked: true, mentions: [{ file: "CLAUDE.md", line: 3 }] } }),
  ];
  for (const item of covered) assert.deepEqual(summaryOf(measured({ structure: { generatedFiles: [item] } }), "STR-02"), []);
  const asks = entry({ protection: { read: ASK_READ, edit: ASK_READ } });
  assert.equal(summaryOf(measured({ structure: { generatedFiles: [asks] } }), "STR-02")[0].impact, "medium");
});

test("STR-02: a mixed folder is not covered; its counts are in the trigger detail", () => {
  const mixed = {
    decision: "mixed",
    rule: null,
    source: null,
    reason: "several-decisions",
    counts: { allow: 0, ask: 0, default: 1, deny: 1, undeterminable: 0 },
  };
  const m = measured({ structure: { generatedFiles: [entry({ files: 2, protection: { read: mixed, edit: DEFAULT_READ } })] } });
  const [finding] = findingsOf(m, "STR-02");
  assert.equal(finding.impact, "medium");
  assert.deepEqual(finding.triggers[0].detail, {
    read: { decision: "mixed", counts: mixed.counts },
    edit: { decision: "default" },
  });
});

test("STR-02: an undeterminable decision that nothing covers is listed, not a finding", () => {
  const undetermined = { decision: "undeterminable", rule: null, source: null, reason: "plan-mode-depends-on-session" };
  const m = measured({ structure: { generatedFiles: [entry({ protection: { read: undetermined, edit: DEFAULT_READ } })] } });
  assert.deepEqual(summaryOf(m, "STR-02"), []);
  assert.deepEqual(undeterminableOf(m, "STR-02"), [
    {
      rule: "STR-02",
      measurementRef: "/structure/generatedFiles/0/protection/read",
      reason: "read decision undeterminable: plan-mode-depends-on-session",
    },
  ]);
});

test("STR-02: an undeterminable decision that a deny covers is no case at all", () => {
  const m = measured({
    structure: { generatedFiles: [entry({ protection: { read: { decision: "undeterminable", rule: null, source: null, reason: "x" }, edit: DENY_READ } })] },
  });
  assert.deepEqual(undeterminableOf(m, "STR-02"), []);
  assert.deepEqual(summaryOf(m, "STR-02"), []);
});

test("STR-02: generated entries come before large files in the numbering", () => {
  const m = measured({
    structure: {
      generatedFiles: [entry({ path: "build" })],
      largeFiles: [{ path: "data/dump.bin", bytes: 300000, protection: { read: DEFAULT_READ, edit: DEFAULT_READ }, memory: { marked: false, mentions: [] } }],
    },
  });
  assert.deepEqual(findingsOf(m, "STR-02").map((item) => [item.id, item.impact]), [
    ["mf-1", "medium"],
    ["mf-2", "low"],
  ]);
});

// ---------------------------------------------------------------------------------------------------
// COD-01

function duplicated(pct, extra = {}) {
  return measured({
    code: {
      duplication: {
        duplicatedLinesPct: pct,
        groups: [
          {
            lines: 9,
            redundantLines: 18,
            copies: [
              { file: "src/a.js", line: 3, endLine: 11 },
              { file: "src/b.js", line: 7, endLine: 15 },
              { file: "src/c.js", line: 1, endLine: 9 },
            ],
          },
        ],
        ...extra,
      },
    },
  });
}

test("COD-01: 15 percent is medium, and 15.1 is high", () => {
  assert.equal(summaryOf(duplicated(15), "COD-01")[0].impact, "medium");
  assert.equal(summaryOf(duplicated(15.1), "COD-01")[0].impact, "high");
  assert.deepEqual(summaryOf(duplicated(15.1), "COD-01")[0].triggers, [
    ["duplication-high", "high", "/code/duplication/duplicatedLinesPct"],
  ]);
});

test("COD-01: 5 percent is no finding, 5.1 is medium", () => {
  assert.deepEqual(summaryOf(duplicated(5), "COD-01"), []);
  const [finding] = findingsOf(duplicated(5.1), "COD-01");
  assert.equal(finding.impact, "medium");
  assert.equal(finding.measurementRef, "/code/duplication/duplicatedLinesPct");
  assert.deepEqual(finding.triggers[0].threshold, { key: "duplicationPctMedium", value: 5 });
});

test("COD-01: the evidence is every copy of every group, with line and endLine", () => {
  const [finding] = findingsOf(duplicated(32.5), "COD-01");
  assert.deepEqual(finding.evidence, [
    { file: "src/a.js", line: 3, endLine: 11 },
    { file: "src/b.js", line: 7, endLine: 15 },
    { file: "src/c.js", line: 1, endLine: 9 },
  ]);
});

test("COD-01: duplication in tests is counted apart and does not change the finding", () => {
  const m = duplicated(3, {
    inTests: { duplicatedLinesPct: 60, groups: [{ lines: 9, redundantLines: 9, copies: [{ file: "t/a.test.js", line: 1, endLine: 9 }] }] },
  });
  assert.deepEqual(summaryOf(m, "COD-01"), []);
});

test("COD-01: a scan without a duplication section gives no finding", () => {
  assert.deepEqual(summaryOf(measured({ code: {} }), "COD-01"), []);
});

// ---------------------------------------------------------------------------------------------------
// Candidates

test("candidates: duplication groups list the file and line of each copy, and never code text", () => {
  const m = duplicated(3);
  const [candidate] = derived(m).candidates;
  assert.deepEqual(candidate, {
    id: "cand-1",
    kind: "duplication-group",
    rules: ["COD-01", "COD-04"],
    measurementRef: "/code/duplication/groups/0",
    lines: 9,
    redundantLines: 18,
    copies: [
      { file: "src/a.js", line: 3, endLine: 11 },
      { file: "src/b.js", line: 7, endLine: 15 },
      { file: "src/c.js", line: 1, endLine: 9 },
    ],
  });
});

test("candidates: a memory or rule file that claudeMdExcludes matches is not a candidate; a file no pattern matches still is", () => {
  const m = measured({
    inventory: [
      { path: "vendor/CLAUDE.md", kind: "memory", loadMode: "not-loaded", loadReason: "claude-md-excludes", excludedBy: "**/vendor/**", lines: null, estTokens: null, bytes: 90 },
      { path: ".claude/rules/shared.md", kind: "rule", loadMode: "not-loaded", loadReason: "claude-md-excludes", excludedBy: "**/shared.md", lines: null, estTokens: null, bytes: 40 },
      { path: "app/CLAUDE.md", kind: "memory", loadMode: "on-demand", loadReason: "subfolder memory, loaded when a file in its folder is read", lines: null, estTokens: null, bytes: 50 },
    ],
  });
  const memoryCandidates = derived(m).candidates.filter((candidate) => candidate.kind === "memory-file");
  assert.deepEqual(memoryCandidates.map((candidate) => candidate.file), ["app/CLAUDE.md"]);
});

test("candidates: hook scripts inside the target, one per path, sorted by path; external or missing scripts are left out", () => {
  const m = measured({
    claudeConfig: {
      hooks: [
        { event: "PreToolUse", script: { path: ".claude/hooks/zeta.mjs", external: false, exists: true } },
        { event: "PreToolUse", script: { path: ".claude/hooks/alpha.mjs", external: false, exists: true } },
        { event: "PreToolUse", script: { path: ".claude/hooks/alpha.mjs", external: false, exists: true } },
        { event: "PreToolUse", script: { path: "/opt/shared/hook.mjs", external: true, exists: true } },
        { event: "PreToolUse", script: { path: "scripts/missing.mjs", external: false, exists: false } },
        { event: "SessionStart", script: null },
      ],
    },
  });
  // zeta is hooks[0] and alpha is hooks[1]; alpha is listed first because the paths are sorted. The ref is the first hook of each path.
  const hooks = derived(m).candidates.filter((candidate) => candidate.kind === "hook-script");
  assert.deepEqual(hooks, [
    { id: "cand-1", kind: "hook-script", rules: ["SEC-02", "SEC-04"], measurementRef: "/claudeConfig/hooks/1/script", file: ".claude/hooks/alpha.mjs" },
    { id: "cand-2", kind: "hook-script", rules: ["SEC-02", "SEC-04"], measurementRef: "/claudeConfig/hooks/0/script", file: ".claude/hooks/zeta.mjs" },
  ]);
});

test("candidates: memory and rule files in inventory order, with the judgment rules that read them", () => {
  const m = measured({
    inventory: [
      { path: ".claude/rules/api.md", kind: "rule", loadMode: "on-demand", lines: 5, estTokens: 40, bytes: 200 },
      { path: "AGENTS.md", kind: "memory", loadMode: "not-loaded", lines: 5, estTokens: 40, bytes: 200 },
      { path: "CLAUDE.md", kind: "memory", loadMode: "always", lines: 5, estTokens: 40, bytes: 200 },
      { path: "skills/x/SKILL.md", kind: "skill", loadMode: "on-demand", lines: 5, estTokens: 40, bytes: 200 },
    ],
  });
  assert.deepEqual(
    derived(m).candidates.map((candidate) => [candidate.id, candidate.file, candidate.loadMode, candidate.measurementRef]),
    [
      ["cand-1", ".claude/rules/api.md", "on-demand", "/inventory/0"],
      ["cand-2", "AGENTS.md", "not-loaded", "/inventory/1"],
      ["cand-3", "CLAUDE.md", "always", "/inventory/2"],
    ],
  );
  assert.deepEqual(derived(m).candidates[2].rules, MEMORY_RULES);
});

// ---------------------------------------------------------------------------------------------------
// The highest impact and the ref of a finding

test("a finding takes the highest impact of its triggers, and the ref of the first trigger with that impact", () => {
  const m = measured({
    security: {
      secrets: {
        fileListSource: "git",
        files: [{ path: ".env", kind: "dotenv", readDecision: DEFAULT_READ }],
        readProtection: { envAtRoot: DEFAULT_ENV, preToolUseReadHooks: [] },
      },
    },
  });
  const [finding] = findingsOf(m, "SEC-03");
  assert.equal(finding.impact, "high");
  assert.equal(finding.measurementRef, "/security/secrets/files/0");
  assert.deepEqual(finding.triggers.map((item) => item.impact), ["high", "high", "medium"]);
});
