// Command line entry point of the scanner: node scripts/scan.mjs <target> [--out <dir>].
//
// It checks the arguments and the target, runs the measures and writes measurements.json to the
// output folder, then prints a short summary. Exit codes: 0 when the scan ran, even if it found
// problems; 2 for an invalid target or invalid usage; 1 for anything unexpected.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { claudeConfigMeasure } from "./lib/claude-config.mjs";
import { destructiveCommandsMeasure } from "./lib/destructive-commands.mjs";
import { duplicationMeasure } from "./lib/duplication.mjs";
import { writeStableJson } from "./lib/json-out.mjs";
import { memoryMeasure } from "./lib/memory.mjs";
import { referencesMeasure } from "./lib/references.mjs";
import { scan } from "./lib/scanner.mjs";
import { secretsMeasure } from "./lib/secrets.mjs";
import { structureMeasure } from "./lib/structure.mjs";
import { UsageError, checkOutputDir, defaultOutputDir, resolveTarget } from "./lib/target.mjs";
import { verificationMeasure } from "./lib/verification.mjs";

// The measures, in the order they run. Each measure adds its import and one line here. The references, verification
// and structure measures read the memory texts, so they run after the memory measure.
const MEASURES = [
  claudeConfigMeasure,
  memoryMeasure,
  referencesMeasure,
  verificationMeasure,
  destructiveCommandsMeasure,
  secretsMeasure,
  structureMeasure,
  duplicationMeasure,
];

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/scan.mjs <target> [--out <dir>]";

process.exitCode = await main(process.argv.slice(2));

async function main(argv) {
  try {
    const { target: input, out } = parseCommandLine(argv);
    const target = resolveTarget(input, HARNESS_ROOT);
    const outDir =
      out === undefined
        ? defaultOutputDir({ harnessRoot: HARNESS_ROOT, targetName: target.name, now: new Date() })
        : path.resolve(out);
    checkOutputDir(outDir, target.root);

    const measurements = await scan({ root: target.root, measures: MEASURES });
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, "measurements.json");
    writeStableJson(file, measurements);
    printSummary(measurements, file);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`error: ${error.message}`);
      console.error(USAGE);
      return 2;
    }
    console.error(`error: ${String(error?.message ?? error).split("\n")[0]}`);
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
      options: { out: { type: "string" } },
    });
  } catch (error) {
    throw new UsageError(error.message);
  }
  const { values, positionals } = parsed;
  if (positionals.length === 0) throw new UsageError("missing the target folder");
  if (positionals.length > 1) throw new UsageError("expected one target folder");
  if (values.out === "") throw new UsageError("the --out folder must not be empty");
  return { target: positionals[0], out: values.out };
}

// Five lines at most. Nothing else is printed on success.
function printSummary(measurements, file) {
  const { target, warnings } = measurements;
  const listed = target.fileListSource === "git" ? "listed by git" : "listed by walking the folder";
  console.log(`target: ${target.name}`);
  console.log(`files: ${target.fileCount} (${listed})`);
  console.log(`commit: ${target.git.head ?? "none"}`);
  console.log(`warnings: ${warnings.length}`);
  console.log(`measurements: ${file}`);
}
