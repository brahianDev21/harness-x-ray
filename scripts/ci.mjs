// Command line entry point of the CI mode: node scripts/ci.mjs <target> [--out <dir>] [--fail-on high|medium|low] [--sarif <file>]
//
// It runs the measures of scan.mjs with no flags (standard depth, no user layer, no ancestors, no scope, no layers) through scan(),
// and derives the measured findings with deriveMeasuredOutput. It writes measurements.json as scan.mjs does. No agent runs and no
// findings.json is read or written: the judgment rules are not applied, and the summary and the SARIF say so.
//
// --out is the run folder, as in scan.mjs: a new folder under runs/ by default. It must lie inside runs/ or the system temp folder.
// --sarif <file> also writes a SARIF 2.1.0 log of the measured findings (lib/sarif.mjs). The file must lie inside runs/ or the system
// temp folder, directly in either being allowed, and not inside the target. It must not be the measurements.json of the run, and
// the two paths are compared by real path, so a link to the run folder does not hide it. Its folder may not exist yet: it is created
// as the run folder is, and runs/ itself is created when it is missing. All the checks of --out and --sarif run before the scan, so
// a folder or file that is not allowed fails at once. The checks of the SARIF file run again before it is written.
//
// The writes come in this order. The SARIF log is built first, so an error in building it writes no file. Then measurements.json is
// written, and then the SARIF log. A SARIF write that fails exits 1 and leaves the new measurements.json.
//
// --fail-on sets the impact at which the run fails. The order is high, medium, low, so a threshold of low fails on any finding.
// A measured finding at or above the threshold makes the exit code 3, decided after every file is written. Without --fail-on the
// run never exits 3.
//
// Exit codes: 0 when the run ran and no finding is at or above the threshold (or there is no threshold); 3 when one is; 2 for a
// usage or input error (the arguments, a target, a folder or a file that is not allowed, a value given twice or empty); 1 for
// anything unexpected, such as a file that cannot be written. The summary prints the target's folder name, not its path, and the
// paths of the files it writes. An error prints the first line of its message.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { IMPACTS, loadRules } from "./lib/findings-validate.mjs";
import { writeStableJson } from "./lib/json-out.mjs";
import { IMPACT_RANK, deriveMeasuredOutput } from "./lib/measured-findings.mjs";
import { measuresFor } from "./lib/measures.mjs";
import { checkRunDir, checkRunFile, runRoots } from "./lib/run-dir.mjs";
import { buildSarif } from "./lib/sarif.mjs";
import { DEFAULT_DEPTH, scan } from "./lib/scanner.mjs";
import { UsageError, checkOutputDir, defaultOutputDir, isInside, realpathOfNearest, resolveTarget } from "./lib/target.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/ci.mjs <target> [--out <dir>] [--fail-on high|medium|low] [--sarif <file>]";
const FAIL_ON_MESSAGE = "the --fail-on value must be high, medium or low";
const MEASUREMENTS_NAME = "measurements.json";

process.exitCode = await main(process.argv.slice(2));

async function main(argv) {
  try {
    const { target: input, out, failOn, sarif } = parseCommandLine(argv);
    const target = resolveTarget(input, HARNESS_ROOT);
    const outDir =
      out === undefined
        ? defaultOutputDir({ harnessRoot: HARNESS_ROOT, targetName: target.name, now: new Date() })
        : path.resolve(out);
    checkOutputDir(outDir, target.root);
    // The first checks, before the scan: a folder or file that is not allowed fails at once, as in scan.mjs.
    checkRunDir(outDir, HARNESS_ROOT);
    const sarifFile = sarif === undefined ? undefined : sarifFileOf(sarif, target.root, outDir);

    const measurements = await scan({
      root: target.root,
      measures: measuresFor({ userLayer: false, ancestors: false, depth: DEFAULT_DEPTH }),
      derive: deriveMeasuredOutput,
      depth: DEFAULT_DEPTH,
    });
    const rules = loadRules(HARNESS_ROOT);
    // The log is built before any file is written, so an error in buildSarif writes no file at all.
    const sarifLog = sarifFile === undefined ? undefined : buildSarif(measurements, rules);

    // The second and third checks of each run folder, with the mkdir between them, as in scan.mjs.
    makeRunDir(outDir);
    const file = path.join(outDir, MEASUREMENTS_NAME);
    // Refuses a measurements.json that is a link, a folder or a hard link, so no other file is written.
    checkRunFile(file);
    writeStableJson(file, measurements);
    if (sarifFile !== undefined) {
      makeSarifFolder(path.dirname(sarifFile));
      checkSarifFile(sarifFile, target.root, file);
      writeStableJson(sarifFile, sarifLog);
    }

    printSummary({
      target,
      measuredFindings: measurements.measuredFindings,
      failOn,
      judgmentRules: rules.filter((rule) => rule.kind === "judgment").length,
      measurements: file,
      sarif: sarifFile,
    });
    return exitCodeOf(measurements.measuredFindings, failOn);
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`error: ${error.message}`);
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
      options: {
        out: { type: "string", multiple: true },
        "fail-on": { type: "string", multiple: true },
        sarif: { type: "string", multiple: true },
      },
    });
  } catch (error) {
    // parseArgs says "argument missing" for a --fail-on without a value; that case names the three values, as --depth does in scan.mjs.
    if (error.code === "ERR_PARSE_ARGS_INVALID_OPTION_VALUE" && error.message.includes("'--fail-on")) {
      throw new UsageError(FAIL_ON_MESSAGE);
    }
    throw new UsageError(firstLine(error));
  }
  const { values, positionals } = parsed;
  if (positionals.length === 0) throw new UsageError("missing the target folder");
  if (positionals.length > 1) throw new UsageError("expected one target folder");
  const failOn = onlyValue(values["fail-on"], "--fail-on", `${FAIL_ON_MESSAGE}, not ""`);
  if (failOn !== undefined && !IMPACTS.includes(failOn)) throw new UsageError(`${FAIL_ON_MESSAGE}, not "${failOn}"`);
  return {
    target: positionals[0],
    out: onlyValue(values.out, "--out", "the --out folder must not be empty"),
    failOn,
    sarif: onlyValue(values.sarif, "--sarif", "the --sarif file must not be empty"),
  };
}

// The one value of an option that may be repeated in the parser, or undefined when it is not given. A repeated option and an
// empty value are usage errors.
function onlyValue(values, option, emptyMessage) {
  if (values === undefined) return undefined;
  if (values.length > 1) throw new UsageError(`the ${option} option was given more than once`);
  if (values[0] === "") throw new UsageError(emptyMessage);
  return values[0];
}

// The --sarif file, checked before the scan: its folder must be allowed (created later), and the file must pass checkSarifFile.
function sarifFileOf(input, targetRoot, outDir) {
  const file = path.resolve(input);
  checkSarifFolder(path.dirname(file));
  checkSarifFile(file, targetRoot, path.join(outDir, MEASUREMENTS_NAME));
  return file;
}

// The checks of the --sarif file, before the scan and again before its write. The file must be a plain file in runs/ or the temp
// folder (checkRunFile with the harness root), it must not lie inside the target, and it must not be the measurements.json of the
// run. The two paths are compared by real path, so a symbolic link to the run folder does not hide the measurements.json.
function checkSarifFile(file, targetRoot, measurementsFile) {
  checkRunFile(file, { harnessRoot: HARNESS_ROOT });
  const real = realpathOfNearest(file);
  if (isInside(targetRoot, real)) throw new UsageError(`the --sarif file must not be inside the target: ${file}`);
  if (real === realpathOfNearest(measurementsFile)) {
    throw new UsageError(`the --sarif file must not be the ${MEASUREMENTS_NAME} of the run: ${file}`);
  }
}

// The folder of the --sarif file must be allowed. It may be runs/ or the temp folder itself, where the file may lie directly.
function checkSarifFolder(folder) {
  if (!isRootFolder(folder)) checkRunDir(folder, HARNESS_ROOT);
}

// Creates the folder of the --sarif file. Any other folder gets the checks of a run folder; a root needs none, and runs/ is created
// when it is missing.
function makeSarifFolder(folder) {
  if (isRootFolder(folder)) {
    fs.mkdirSync(folder, { recursive: true });
    return;
  }
  makeRunDir(folder);
}

// True when the real path of the folder is runs/ or the system temp folder itself.
function isRootFolder(folder) {
  const roots = runRoots(HARNESS_ROOT);
  const real = realpathOfNearest(folder);
  return real === roots.runs || real === roots.temp;
}

// The second check of a run folder, its mkdir and the third check, as scan.mjs makes them. The first check ran before the scan.
function makeRunDir(dir) {
  checkRunDir(dir, HARNESS_ROOT);
  fs.mkdirSync(dir, { recursive: true });
  checkRunDir(dir, HARNESS_ROOT);
}

// Exit 3 when a measured finding is at or above the threshold. Without a threshold the exit code is never 3.
function exitCodeOf(measuredFindings, failOn) {
  if (failOn === undefined) return 0;
  return atOrAbove(measuredFindings, failOn) > 0 ? 3 : 0;
}

function atOrAbove(measuredFindings, failOn) {
  return measuredFindings.filter((finding) => IMPACT_RANK[finding.impact] >= IMPACT_RANK[failOn]).length;
}

// Six lines at most, deterministic apart from the paths. The judgment line says the judgment rules were not applied.
function printSummary({ target, measuredFindings, failOn, judgmentRules, measurements, sarif }) {
  const counts = Object.fromEntries(IMPACTS.map((impact) => [impact, 0]));
  for (const finding of measuredFindings) counts[finding.impact] += 1;
  console.log(`target: ${target.name}`);
  console.log(`measured findings: ${IMPACTS.map((impact) => `${impact} ${counts[impact]}`).join(", ")}`);
  if (failOn !== undefined) console.log(`fail-on: ${failOn}, findings at or above it: ${atOrAbove(measuredFindings, failOn)}`);
  console.log(
    `judgment rules: not applied (CI runs the measured rules only; the catalog has ${judgmentRules} judgment rules)`,
  );
  console.log(`measurements: ${measurements}`);
  if (sarif !== undefined) console.log(`sarif: ${sarif}`);
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}
