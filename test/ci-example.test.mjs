import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

// The example workflow of the CI mode, examples/ci/harness-xray.yml. It is YAML, read here with plain line checks: no YAML parser
// is a dependency of this repository. The checks are the rules that examples/ci/README.md states for it.
const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = path.resolve(TEST_DIR, "..");
const WORKFLOW_FILE = path.join(HARNESS_ROOT, "examples", "ci", "harness-xray.yml");
const REGISTRY_FILE = path.join(HARNESS_ROOT, "data", "agent-harness.json");
const WORKFLOW = fs.readFileSync(WORKFLOW_FILE, "utf8");
const REGISTRY_GLOBS = JSON.parse(fs.readFileSync(REGISTRY_FILE, "utf8")).files.map((entry) => entry.glob);

// The items of the paths filter under pull_request, without their quotes, in file order.
function pathsOf(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => line === "    paths:");
  if (start === -1) return [];
  const items = [];
  for (const line of lines.slice(start + 1)) {
    const match = /^      - (.+)$/.exec(line);
    if (match === null) break;
    items.push(unquote(match[1].trim()));
  }
  return items;
}

function unquote(value) {
  return /^'(.*)'$/.exec(value)?.[1] ?? value;
}

// The entries of the top-level permissions block, in file order.
function permissionsOf(text) {
  const lines = text.split("\n");
  const start = lines.indexOf("permissions:");
  if (start === -1) return [];
  const entries = [];
  for (const line of lines.slice(start + 1)) {
    if (!/^  \S/.test(line)) break;
    entries.push(line.trim());
  }
  return entries;
}

// The lines of each step that uses actions/checkout, from its uses line to the next step.
function checkoutSteps(text) {
  return stepsUsing(text, "actions/checkout@");
}

// The lines of each step that uses the given action, from its uses line to the next step.
function stepsUsing(text, action) {
  const lines = text.split("\n");
  const steps = [];
  lines.forEach((line, index) => {
    if (!line.trimStart().startsWith(`uses: ${action}`)) return;
    const rest = lines.slice(index + 1);
    const end = rest.findIndex((item) => /^      - /.test(item));
    steps.push(end === -1 ? rest : rest.slice(0, end));
  });
  return steps;
}

// The problems of a workflow text, one message each. An empty list means it follows the rules of the example.
function workflowProblems(text) {
  const problems = [];
  if (/pull_request_target/.test(text)) problems.push("the workflow uses pull_request_target");
  if (!/^on:\n  pull_request:\n/m.test(text)) problems.push("the only trigger must be pull_request");
  if (!/^    paths:\n/m.test(text)) problems.push("the pull_request trigger has no paths filter");
  if (/\bnpm\s+(install|ci|i)\b/.test(text)) problems.push("the workflow installs npm packages");

  const permissions = permissionsOf(text);
  const expected = ["contents: read", "security-events: write"];
  if (JSON.stringify(permissions) !== JSON.stringify(expected)) {
    problems.push(`the permissions must be exactly ${expected.join(" and ")}, not ${permissions.join(", ") || "none"}`);
  }
  if (text.split("\n").filter((line) => /^\s*permissions:/.test(line)).length !== 1) {
    problems.push("the workflow must have one permissions block, at the top");
  }

  const checkouts = checkoutSteps(text);
  if (checkouts.length !== 2) problems.push(`the workflow has ${checkouts.length} checkouts, not 2`);
  for (const [index, step] of checkouts.entries()) {
    if (!step.includes("          persist-credentials: false")) problems.push(`checkout ${index + 1} keeps its credentials`);
  }

  const missing = REGISTRY_GLOBS.filter((glob) => !pathsOf(text).includes(glob));
  if (missing.length > 0) problems.push(`the paths filter lacks ${missing.join(", ")}`);

  if (!/if: always\(\)\n        uses: github\/codeql-action\/upload-sarif@v3/.test(text)) {
    problems.push("the SARIF upload does not run under if: always()");
  }
  const uploads = stepsUsing(text, "github/codeql-action/upload-sarif@");
  if (uploads.length !== 1) problems.push(`the workflow has ${uploads.length} SARIF uploads, not 1`);
  if (!uploads.every((step) => step.includes("          checkout_path: target"))) {
    problems.push("the SARIF upload does not set checkout_path to the target checkout");
  }
  return problems;
}

test("ci example: the paths filter holds every glob of data/agent-harness.json, once each, and no other", () => {
  const paths = pathsOf(WORKFLOW);
  assert.ok(paths.length > 0, "the workflow has a paths filter");
  assert.equal(new Set(paths).size, paths.length, "no glob is listed twice");
  for (const glob of REGISTRY_GLOBS) assert.ok(paths.includes(glob), `the paths filter lists ${glob}`);
  assert.deepEqual([...new Set(paths)].sort(), [...new Set(REGISTRY_GLOBS)].sort(), "the filter and the registry name the same globs");
});

test("ci example: the workflow follows the rules of the example (positive control: the file itself passes)", () => {
  assert.deepEqual(workflowProblems(WORKFLOW), []);
});

test("ci example: the checks refuse each change that breaks a rule (hostile variants of the file)", () => {
  const variants = {
    "pull_request_target": WORKFLOW.replace("on:\n  pull_request:\n", "on:\n  pull_request_target:\n"),
    "a second trigger": WORKFLOW.replace("on:\n  pull_request:\n", "on:\n  push:\n  pull_request:\n"),
    "an npm install": WORKFLOW.replace("node harness-x-ray/scripts/ci.mjs", "npm install && node harness-x-ray/scripts/ci.mjs"),
    "an extra permission": WORKFLOW.replace("  security-events: write\n", "  security-events: write\n  actions: read\n"),
    "a checkout with its credentials": WORKFLOW.replace(
      "          path: target\n          persist-credentials: false\n",
      "          path: target\n",
    ),
    "a missing glob": WORKFLOW.replace("      - '.clinerules'\n", ""),
    "an upload that is not always run": WORKFLOW.replace("        if: always()\n", ""),
    "an upload without checkout_path": WORKFLOW.replace("          checkout_path: target\n", ""),
  };
  for (const [name, text] of Object.entries(variants)) {
    assert.notEqual(text, WORKFLOW, `the variant "${name}" changes the file`);
    assert.notDeepEqual(workflowProblems(text), [], `the checks refuse ${name}`);
  }
});

test("ci example: the upload reads the SARIF file that the scan writes", () => {
  assert.match(WORKFLOW, /--sarif harness-x-ray\/runs\/ci\/results\.sarif/);
  assert.match(WORKFLOW, /sarif_file: harness-x-ray\/runs\/ci\/results\.sarif/);
});
