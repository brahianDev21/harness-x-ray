// Command line entry point of the threshold calibration: node scripts/calibrate.mjs <target>... [--out <dir>]
//
// It scans each target in read-only mode with the measures of the CI mode (no user layer, no ancestors, standard depth), through
// the scan core, and nothing is written into a target. lib/calibration.mjs builds the distribution of each measure over the
// sample: the statistics of its values, and how many targets are above each threshold. Two files are written into the run folder:
// calibration.json and calibration.md, the same sample for a person. The only text from a target is its folder name, which the
// files hold as the basename. Two targets with the same basename are two rows of the sample.
//
// The default run folder is runs/calibration-<date>, with the date in UTC. When that name is taken, the next one is tried:
// -2, -3 and so on. The name is claimed by a mkdir without the recursive flag (lib/calibration.mjs claimCalibrationDir), so two
// runs of the same day never write into one folder. runs/ itself is created when it is missing, and it must be the runs folder of
// this harness by its real path. --out gives another folder instead; it must lie inside runs/ of harness-x-ray or inside the system
// temp folder (see lib/run-dir.mjs), and not inside a target. Each target must be a folder outside harness-x-ray, given once: two
// inputs that name the same real path are a usage error. A folder name with a control or format character, or a line separator, is
// a usage error too, since it cannot be shown as it is in a document. All the checks of the targets and of the folder run before the
// scans.
//
// Both texts are built, checked against their schema and their cross-field constraints (checkCalibration), and their files are
// checked, before any folder is claimed or any file is written. Then writeRunFiles writes them (lib/run-io.mjs). A default folder that
// this run claimed and could not write into is removed when it is still empty.
//
// Exit codes: 0 when both files are written; 2 for a usage or input error (the arguments, a target that is not allowed, given twice
// or with a control character in its name, a folder that is not allowed or lies inside a target, an --out value that is empty or
// given twice, a runs folder that is not usable, or an output file that is a link, a folder or a hard link); 1 for anything else,
// such as a target that cannot be scanned, a calibration that does not pass its checks, or a file that cannot be written (nothing is
// written then). An error prints its first line. A scan failure names the target's folder only, never the message of the error, which
// may hold paths of the target.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { buildCalibration, checkCalibration, claimCalibrationDir, renderCalibrationMarkdown, checkTargetName } from "./lib/calibration.mjs";
import { toStableJson } from "./lib/json-out.mjs";
import { measuresFor } from "./lib/measures.mjs";
import { checkRunDir, checkRunFile } from "./lib/run-dir.mjs";
import { writeRunFiles } from "./lib/run-io.mjs";
import { schemaProblems } from "./lib/schema-check.mjs";
import { DEFAULT_DEPTH, scan } from "./lib/scanner.mjs";
import { UsageError, checkOutputDir, resolveTarget } from "./lib/target.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/calibrate.mjs <target>... [--out <dir>]";
const JSON_NAME = "calibration.json";
const MARKDOWN_NAME = "calibration.md";
const SCHEMA_NAME = "calibration.schema.json";

process.exitCode = await main(process.argv.slice(2));

async function main(argv) {
  try {
    const { targets: inputs, out } = parseCommandLine(argv);
    const targets = inputs.map((input) => resolveTarget(input, HARNESS_ROOT));
    checkDistinct(targets);
    for (const target of targets) checkTargetName(target.name);

    // The date is read once, so the run folder and the document carry the same day.
    const date = new Date().toISOString().slice(0, 10);
    const explicitOut = out === undefined ? undefined : path.resolve(out);
    if (explicitOut !== undefined) {
      for (const target of targets) checkOutputDir(explicitOut, target.root);
      // The first check of the run folder, before the scans: a folder that is not allowed fails at once.
      checkRunDir(explicitOut, HARNESS_ROOT);
    }

    const scans = [];
    for (const target of targets) scans.push(await scanTarget(target));
    const calibration = buildCalibration(scans, {
      date,
      tool: scans[0].meta.tool,
      catalog: scans[0].meta.catalog,
    });
    checkBeforeWrite(calibration);
    // Both texts are built and checked before any folder is claimed or any file is written.
    const outputs = [
      { name: JSON_NAME, text: toStableJson(calibration) },
      { name: MARKDOWN_NAME, text: renderCalibrationMarkdown(calibration) },
    ];

    const claimed = explicitOut === undefined ? claimDefaultRunDir(date) : undefined;
    const outDir = claimed ?? explicitOut;
    try {
      if (claimed === undefined) makeRunDir(outDir);
      for (const output of outputs) checkRunFile(path.join(outDir, output.name), { harnessRoot: HARNESS_ROOT });
      writeRunFiles(outDir, outputs);
    } catch (error) {
      if (claimed !== undefined) removeIfEmpty(claimed);
      throw error;
    }

    console.log(`targets: ${calibration.sample.count}`);
    console.log(`calibration: ${path.join(outDir, JSON_NAME)}`);
    console.log(`markdown: ${path.join(outDir, MARKDOWN_NAME)}`);
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

function parseCommandLine(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: { out: { type: "string", multiple: true } },
    });
  } catch (error) {
    throw new UsageError(firstLine(error));
  }
  const { values, positionals } = parsed;
  if (positionals.length === 0) throw new UsageError("missing the target folders: at least one is needed");
  const outValues = values.out ?? [];
  if (outValues.length > 1) throw new UsageError("the --out option was given more than once");
  if (outValues[0] === "") throw new UsageError("the --out folder must not be empty");
  return { targets: positionals, out: outValues[0] };
}

// Two targets with the same real path are a usage error. The real paths are the ones that resolveTarget returns.
function checkDistinct(targets) {
  const roots = new Set();
  for (const target of targets) {
    if (roots.has(target.root)) throw new UsageError("the same target was given more than once");
    roots.add(target.root);
  }
}

// The schema of calibration.json, then the constraints that the schema cannot state. A failure is a fault of this tool, so it is an
// error (exit 1) and nothing is written. The message names the first problem, which is a fixed phrase, never a value of a target.
function checkBeforeWrite(calibration) {
  const schema = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, "schemas", SCHEMA_NAME), "utf8"));
  const problems = [...schemaProblems(schema, calibration), ...checkCalibration(calibration)];
  if (problems.length > 0) throw new Error(`${JSON_NAME} does not pass its checks: ${problems[0]}`);
}

// The default run folder: the first free name of runs/calibration-<date>, claimed by a mkdir without the recursive flag. runs/ is
// created when it is missing, and it must be the runs folder of this harness by its real path: checkRunDir refuses the runs folder
// itself, so it is checked here by its real path, and each claimed folder gets the check of a run folder after its mkdir.
function claimDefaultRunDir(date) {
  const runs = path.join(HARNESS_ROOT, "runs");
  try {
    fs.mkdirSync(runs, { recursive: true });
  } catch {
    throw new UsageError("the runs folder of harness-x-ray cannot be used");
  }
  if (fs.realpathSync.native(runs) !== path.join(fs.realpathSync.native(HARNESS_ROOT), "runs")) {
    throw new UsageError("the runs folder of harness-x-ray is a link or lies elsewhere");
  }
  const name = claimCalibrationDir(date, (candidate) => {
    const folder = path.join(runs, candidate);
    try {
      fs.mkdirSync(folder);
    } catch (error) {
      // A name that is taken goes on to the next suffix; any other failure is a usage error.
      if (error?.code === "EEXIST") throw error;
      throw new UsageError("the calibration folder cannot be created in runs/");
    }
    checkRunDir(folder, HARNESS_ROOT);
  });
  return path.join(runs, name);
}

// Removes a folder that this run claimed, when it is still empty. rmdir removes nothing else.
function removeIfEmpty(folder) {
  try {
    fs.rmdirSync(folder);
  } catch {
    // The first error is the one reported.
  }
}

// The scan of one target with the measures of the CI mode. Nothing is written into the target. A failure names the target's folder
// and the error code only.
async function scanTarget(target) {
  try {
    return await scan({
      root: target.root,
      measures: measuresFor({ userLayer: false, ancestors: false, depth: DEFAULT_DEPTH }),
      depth: DEFAULT_DEPTH,
    });
  } catch (error) {
    const code = typeof error?.code === "string" && /^[A-Z0-9_]+$/.test(error.code) ? ` (${error.code})` : "";
    throw new Error(`the scan of the target ${target.name} failed${code}`);
  }
}

// The run folder for --out: the second check before mkdir, the mkdir, and the third check after it, as scan.mjs and ci.mjs make them.
function makeRunDir(dir) {
  checkRunDir(dir, HARNESS_ROOT);
  fs.mkdirSync(dir, { recursive: true });
  checkRunDir(dir, HARNESS_ROOT);
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}
