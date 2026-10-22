// Command line entry point of the remediation: node scripts/remediate.mjs <runDir>.
//
// It reads <runDir>/measurements.json and, when the file exists, <runDir>/agent-fragments.json (the fragments that the agent
// proposes for judgment findings, see schemas/agent-fragments.schema.json). It builds the remediation with lib/remediation.mjs
// and writes two files into the run folder: remediation.json (the data, see schemas/remediation.schema.json) and remediation.md
// (the same content for a person). The target is never read, nothing is run, and nothing is written into the target. The
// remediation changes nothing by itself: the person copies each fragment into their settings by hand, after review.
//
// The run folder must lie inside runs/ of harness-x-ray or inside the system temp folder (see lib/run-dir.mjs). Each input
// file must be a regular file with one name, no larger than its cap, and each output file is checked the same way before anything
// is written. A link or a hard link is refused, and so is a missing measurements.json. The fields of measurements.json that the
// remediation reads are checked for their presence and type before anything is built.
//
// Writing is all or nothing as far as the checks and the texts go: the remediation is checked against its schema and its cap, and
// both texts are built and their files checked, before any write. Then each text goes to a temporary name in the run folder, and
// only when both are written are they renamed over the final names. The two renames are two steps, not one: a failure during them
// removes the temporary file that was not renamed yet and exits 1, but a file renamed before the failure stays, so that case can
// leave remediation.json new beside an older remediation.md (see lib/run-io.mjs). remediation.json is written with toStableJson
// through writeRunFiles, not with writeStableJson, because the two files must be written together, all or nothing.
//
// Warnings are not used: the checks of the agent's fragments are errors. Exit codes: 0 when both files are written, even with
// zero fragments; 2 for a usage or input error (the arguments, a run folder that is not allowed or is missing, measurements.json
// that is missing, is not JSON, is a link, is not a scan of this tool, or has a field of the wrong type, an agent-fragments.json
// that is a link, is larger than its cap, fails its schema or one of its checks, or an output file that is a link, a folder or a
// hard link); 1 for anything else, such as a remediation that does not match its own schema or is larger than its cap. The first
// line of an error is printed. The texts of the agent and the values of the scan are not printed.
//
// main(argv) is exported for the tests. The command runs only when this file is the entry point, so importing it starts nothing.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { loadRules } from "./lib/findings-validate.mjs";
import { isPlainObject, toStableJson } from "./lib/json-out.mjs";
import { checkRunDir, checkRunFile } from "./lib/run-dir.mjs";
import {
  AGENT_FRAGMENTS_MAX_BYTES,
  REMEDIATION_MAX_BYTES,
  buildRemediation,
  checkAgentFragments,
  redactorFor,
} from "./lib/remediation.mjs";
import { buildRemediationBlocks } from "./lib/remediation-view.mjs";
import { blocksMarkdown } from "./lib/report.mjs";
import { loadLabels } from "./lib/report-labels.mjs";
import { schemaProblems } from "./lib/schema-check.mjs";
import { exists, readRunJson, writeRunFiles } from "./lib/run-io.mjs";
import { UsageError } from "./lib/target.mjs";

const SELF = fileURLToPath(import.meta.url);
const HARNESS_ROOT = path.resolve(path.dirname(SELF), "..");
const USAGE = "usage: node scripts/remediate.mjs <runDir>";
const MEASUREMENTS_NAME = "measurements.json";
const AGENT_NAME = "agent-fragments.json";
const AGENT_SCHEMA = "agent-fragments.schema.json";
const JSON_NAME = "remediation.json";
const MARKDOWN_NAME = "remediation.md";
const REMEDIATION_SCHEMA = "remediation.schema.json";
// The values of measurements.json that the remediation reads, with the type each must have. The first missing or mistyped one
// is reported by its path, never by its value.
const REQUIRED_VALUES = Object.freeze([
  { keys: ["meta", "scannedAt"], type: "string" },
  { keys: ["meta", "targetRoot"], type: "string" },
  { keys: ["target", "name"], type: "string" },
  { keys: ["security", "destructiveCoverage", "mode"], type: "mode" },
]);
// The lists of measurements.json that the remediation reads, and the fields that each entry needs, with their types.
const REQUIRED_LISTS = Object.freeze([
  { keys: ["measuredFindings"], fields: { rule: "string", id: "string" } },
  { keys: ["security", "permissions", "allow"], fields: { rule: "string" } },
  { keys: ["security", "permissions", "ask"], fields: { rule: "string" } },
  { keys: ["security", "permissions", "deny"], fields: { rule: "string" } },
  {
    keys: ["security", "destructiveCoverage", "commands"],
    fields: { id: "string", tool: "string", command: "string", outcome: "string", insideProject: "boolean", criticalPath: "boolean" },
  },
  { keys: ["security", "secrets", "files"], fields: { path: "string", readDecision: "decision" } },
  {
    keys: ["security", "secrets", "literals"],
    fields: { file: "string", kind: "string", location: "string", line: "integer-or-null" },
  },
]);

if (isEntryPoint()) process.exitCode = main(process.argv.slice(2));

/**
 * Builds the remediation of one run folder and writes remediation.json and remediation.md into it.
 * @param {string[]} argv The arguments after the script name: exactly one run folder.
 * @returns {number} The exit code.
 */
export function main(argv) {
  try {
    const runDir = parseCommandLine(argv);
    const real = checkRunDir(runDir, HARNESS_ROOT);
    if (!fs.existsSync(real)) throw new UsageError(`the run folder does not exist: ${runDir}`);
    const measurements = readMeasurements(real);
    const agentFragments = readAgentFragments(real, measurements);
    const remediation = buildRemediation({ measurements, agentFragments: agentFragments ?? [] });
    checkRemediation(remediation);

    // Both texts are built, and their files checked, before anything is written.
    const labels = loadLabels(HARNESS_ROOT, "en");
    const markdown = `${blocksMarkdown(buildRemediationBlocks(remediation, { labels, level: 1 }))}\n`;
    const outputs = [
      { name: JSON_NAME, text: toStableJson(remediation) },
      { name: MARKDOWN_NAME, text: markdown },
    ];
    if (Buffer.byteLength(outputs[0].text, "utf8") > REMEDIATION_MAX_BYTES) {
      throw new Error(`${JSON_NAME} would be larger than its cap of ${REMEDIATION_MAX_BYTES} bytes; nothing is written`);
    }
    for (const output of outputs) checkRunFile(path.join(real, output.name), { harnessRoot: HARNESS_ROOT });
    writeRunFiles(real, outputs);

    const { summary } = remediation;
    console.log(`remediation: ${path.join(real, JSON_NAME)}`);
    console.log(`markdown: ${path.join(real, MARKDOWN_NAME)}`);
    console.log(`fragments: ${summary.fragments} (${summary.simulatedFragments} simulated, ${summary.notSimulatedFragments} not simulated)`);
    console.log(
      `commands: ${summary.commandsPassingToday} pass today; ${summary.commandsMoved} moved, ` +
        `${summary.commandsStillPassing} still pass, ${summary.commandsNotSimulated} not simulated`,
    );
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`error: ${firstLine(error)}`);
      console.error(USAGE);
      return 2;
    }
    console.error(`error: ${firstLine(error)}`);
    return 1;
  }
}

// True when the script was started directly: argv[1] and this file are the same file after resolving links.
function isEntryPoint() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync.native(process.argv[1]) === fs.realpathSync.native(SELF);
  } catch {
    return false;
  }
}

function parseCommandLine(argv) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, allowPositionals: true, strict: true, options: {} });
  } catch (error) {
    throw new UsageError(firstLine(error));
  }
  const { positionals } = parsed;
  if (positionals.length !== 1) throw new UsageError(`expected one run folder, got ${positionals.length}`);
  if (positionals[0] === "") throw new UsageError("the run folder must not be empty");
  return positionals[0];
}

// Reads measurements.json. A missing file, a link, or a file that is not JSON is a usage error, and so is a file that is not a
// scan of this tool (a field the remediation needs is missing, or has the wrong type).
function readMeasurements(dir) {
  const measurements = readRunJson(path.join(dir, MEASUREMENTS_NAME));
  const problem = shapeProblem(measurements);
  if (problem !== null) throw new UsageError(`${MEASUREMENTS_NAME} is not a scan of this tool: ${problem}`);
  return measurements;
}

// The first problem of measurements.json for the remediation, as a path and a fixed phrase, or null when the file has what the
// remediation reads. The values are never printed.
function shapeProblem(measurements) {
  if (!isPlainObject(measurements)) return "it is not a JSON object";
  for (const { keys, type } of REQUIRED_VALUES) {
    const value = valueAt(measurements, keys);
    if (value === undefined) return `it has no ${keys.join(".")}`;
    if (!typeMatches(value, type)) return `${keys.join(".")} has a wrong type`;
  }
  for (const { keys, fields } of REQUIRED_LISTS) {
    const list = valueAt(measurements, keys);
    if (list === undefined) return `it has no ${keys.join(".")}`;
    if (!Array.isArray(list)) return `${keys.join(".")} is not a list`;
    for (const [index, entry] of list.entries()) {
      const where = `${keys.join(".")}[${index}]`;
      if (!isPlainObject(entry)) return `${where} is not an object`;
      const wrong = Object.entries(fields).find(([field, type]) => !typeMatches(entry[field], type));
      if (wrong !== undefined) return `${where}.${wrong[0]} is missing or has a wrong type`;
    }
  }
  return optionalShapeProblem(measurements);
}

// The optional parts that the remediation reads when they are there: the subagents' results and the .env read decision.
function optionalShapeProblem(measurements) {
  const subagents = valueAt(measurements, ["security", "destructiveCoverage", "subagents"]);
  if (subagents !== undefined) {
    if (!Array.isArray(subagents)) return "security.destructiveCoverage.subagents is not a list";
    for (const [index, agent] of subagents.entries()) {
      const where = `security.destructiveCoverage.subagents[${index}]`;
      if (!isPlainObject(agent)) return `${where} is not an object`;
      if (agent.results === undefined) continue;
      if (!Array.isArray(agent.results)) return `${where}.results is not a list`;
      for (const [position, item] of agent.results.entries()) {
        if (!isPlainObject(item) || typeof item.id !== "string" || typeof item.outcome !== "string") {
          return `${where}.results[${position}] is missing its id or outcome, or has the wrong type`;
        }
      }
    }
  }
  const envAtRoot = valueAt(measurements, ["security", "secrets", "readProtection", "envAtRoot"]);
  if (envAtRoot !== undefined && envAtRoot !== null && !typeMatches(envAtRoot, "decision")) {
    return "security.secrets.readProtection.envAtRoot has no decision of the right type";
  }
  return null;
}

// True when a value has the type the checks name: a string, a boolean, an integer or null, an object, a read decision (an object
// with a string decision), or the defaultMode (null or an object with a string value).
function typeMatches(value, type) {
  switch (type) {
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "integer-or-null":
      return value === null || Number.isInteger(value);
    case "decision":
      return isPlainObject(value) && typeof value.decision === "string";
    case "mode":
      return value === null || (isPlainObject(value) && typeof value.value === "string");
    default:
      throw new Error(`unknown check type: ${type}`);
  }
}

function valueAt(root, keys) {
  let node = root;
  for (const key of keys) {
    if (!isPlainObject(node) || !Object.hasOwn(node, key)) return undefined;
    node = node[key];
  }
  return node;
}

// Reads and checks agent-fragments.json when the run folder has one: null when it has none. A file larger than its cap, its
// schema, and its checks are errors (usage errors), and the checks name the fragment by its index only.
function readAgentFragments(dir, measurements) {
  const file = path.join(dir, AGENT_NAME);
  if (!exists(file)) return null;
  const data = readRunJson(file, { maxBytes: AGENT_FRAGMENTS_MAX_BYTES });
  const problems = schemaProblems(readSchema(AGENT_SCHEMA), data);
  if (problems.length > 0) throw new UsageError(`${AGENT_NAME} does not match its schema: ${problems[0]}`);
  const judgmentRules = new Set(
    loadRules(HARNESS_ROOT)
      .filter((rule) => rule.kind === "judgment")
      .map((rule) => rule.id),
  );
  return checkAgentFragments(data.fragments, { judgmentRules, redact: redactorFor(measurements) });
}

// The built remediation must match its schema, which render-report.mjs requires of it. A mismatch is a fault of this tool, so it is
// an error (exit 1), and nothing is written. The message names the first problem by its path only.
function checkRemediation(remediation) {
  const problems = schemaProblems(readSchema(REMEDIATION_SCHEMA), remediation);
  if (problems.length > 0) throw new Error(`${JSON_NAME} does not match its schema: ${problems[0]}`);
}

function readSchema(name) {
  return JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", name), "utf8"));
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}
