// Command line entry point of the layer map: node scripts/map.mjs <target> [--out <dir>].
//
// It checks the arguments and the target, maps the layers and writes layers.json to the output folder. The output folder
// must lie inside runs/ of harness-x-ray or inside the system temp folder (see lib/run-dir.mjs); by default it is a new folder
// under runs/. Exit codes, as scan.mjs: 0 when the map was written; 2 for an invalid target, an output folder that is not
// allowed, or invalid usage; 1 for anything unexpected. Nothing else is written, and nothing is written into the target.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { mapLayers } from "./lib/layers.mjs";
import { writeStableJson } from "./lib/json-out.mjs";
import { checkRunDir, checkRunFile } from "./lib/run-dir.mjs";
import { UsageError, checkOutputDir, defaultOutputDir, resolveTarget } from "./lib/target.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/map.mjs <target> [--out <dir>]";

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
    // First check, before the mapping: a folder that is not allowed fails at once, not after the work.
    checkRunDir(outDir, HARNESS_ROOT);

    const layers = await mapLayers({ root: target.root, now: new Date() });
    // Second check, right before mkdir: the mapping takes time, and a link put into runs/ meanwhile must be refused.
    checkRunDir(outDir, HARNESS_ROOT);
    fs.mkdirSync(outDir, { recursive: true });
    // Third check, after mkdir: the folder exists now, so its real path is settled.
    checkRunDir(outDir, HARNESS_ROOT);
    const file = path.join(outDir, "layers.json");
    // Refuses a layers.json that is a link, a folder or a hard link, so no other file is written.
    checkRunFile(file);
    writeStableJson(file, layers);
    console.log(`layers: ${file}`);
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
