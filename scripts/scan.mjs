// Command line entry point of the scanner: node scripts/scan.mjs <target> [--out <dir>] [--include-user-layer]
// [--include-ancestors] [--scope <folder>]... [--layers <runDir>]
//
// It checks the arguments and the target, runs the measures and writes measurements.json to the
// output folder, then prints a short summary. The output folder must lie inside runs/ of
// harness-x-ray or inside the system temp folder (see lib/run-dir.mjs); by default it is a new folder
// under runs/. Exit codes: 0 when the scan ran, even if it found problems; 2 for an invalid target,
// an output folder that is not allowed, a layer plan that cannot be used, or invalid usage; 1 for anything unexpected.
//
// The two flags are opt-in. --include-user-layer reads ~/.claude (user layer, see lib/user-layer.mjs) and
// --include-ancestors reads the memory files of the parent folders. Without them nothing outside the target is read.
//
// --scope, which can be repeated, limits the scan to folders of the target (see lib/scope.mjs). Each folder is relative to
// the target and must exist inside it; a folder that does not exist, is not a folder or leaves the target exits with 2. The
// harness of the root and of the folders between the root and the scope is still read, and --include-ancestors still reads
// the parent folders of the target, not those of the scope.
//
// --layers <runDir> reads the layer plan of a map run (see lib/layer-plan.mjs): <runDir>/layers.json must have been written for
// this target, the plan must pass its check, and each layer folder must still be a folder of the target reached without a link.
// The scan then adds context.byLayer, the context that Claude Code loads in each layer (see lib/layer-context.mjs). The run
// folder must lie inside runs/ or the system temp folder, as the output folder does. Any of these problems exits with 2.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { agentInventoryMeasure } from "./lib/agent-inventory.mjs";
import { claudeConfigMeasure } from "./lib/claude-config.mjs";
import { destructiveCommandsMeasure } from "./lib/destructive-commands.mjs";
import { duplicationMeasure } from "./lib/duplication.mjs";
import { writeStableJson } from "./lib/json-out.mjs";
import { createLayerContextMeasure, layerFolderProblem } from "./lib/layer-context.mjs";
import { LAYERS_FILE, PLAN_FILE, loadLayerPlan } from "./lib/layer-plan.mjs";
import { countByAxis, deriveMeasuredOutput } from "./lib/measured-findings.mjs";
import { createMemoryMeasure, memoryMeasure } from "./lib/memory.mjs";
import { referencesMeasure } from "./lib/references.mjs";
import { checkRunDir, checkRunFile } from "./lib/run-dir.mjs";
import { scan } from "./lib/scanner.mjs";
import { ScopeError, resolveScopeFolders } from "./lib/scope.mjs";
import { secretsMeasure } from "./lib/secrets.mjs";
import { structureMeasure } from "./lib/structure.mjs";
import { UsageError, checkOutputDir, defaultOutputDir, resolveTarget } from "./lib/target.mjs";
import { createUserLayerMeasure } from "./lib/user-layer.mjs";
import { verificationMeasure } from "./lib/verification.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE =
  "usage: node scripts/scan.mjs <target> [--out <dir>] [--include-user-layer] [--include-ancestors] [--scope <folder>]... [--layers <runDir>]";

// The measures, in the order they run, for the given flags. Each measure adds its import and one line here. The references,
// verification and structure measures read the memory texts, so they run after the memory measure. The user layer runs right
// after the project configuration, because the permission measures read the rules it adds to ctx.outside. The agent-harness
// measure runs right after the memory measure: it reads the files of the other agents, and it needs neither the memory texts
// nor the output of the measures that follow it. The layer-context measure runs after the agent-harness measure, and only with
// a layer plan: it reads the memory files and rules that the memory measure has already read.
function measuresFor({ userLayer, ancestors, layers }) {
  const memory = ancestors ? createMemoryMeasure({ includeAncestors: true }) : memoryMeasure;
  return [
    claudeConfigMeasure,
    ...(userLayer ? [createUserLayerMeasure()] : []),
    memory,
    agentInventoryMeasure,
    ...(layers === undefined ? [] : [createLayerContextMeasure({ layers })]),
    referencesMeasure,
    verificationMeasure,
    destructiveCommandsMeasure,
    secretsMeasure,
    structureMeasure,
    duplicationMeasure,
  ];
}

process.exitCode = await main(process.argv.slice(2));

async function main(argv) {
  try {
    const { target: input, out, userLayer, ancestors, scopes, layers: layersInput } = parseCommandLine(argv);
    const target = resolveTarget(input, HARNESS_ROOT);
    const scope = scopes.length === 0 ? undefined : scopeFoldersOf(target.root, scopes);
    const layers = layersInput === undefined ? undefined : layerPlanOf(target.root, layersInput);
    const outDir =
      out === undefined
        ? defaultOutputDir({ harnessRoot: HARNESS_ROOT, targetName: target.name, now: new Date() })
        : path.resolve(out);
    checkOutputDir(outDir, target.root);
    // First check, before the scan: a folder that is not allowed fails at once, not after the scan.
    checkRunDir(outDir, HARNESS_ROOT);

    // meta.include is written only when a flag is on, so a run without flags keeps its output.
    const include = userLayer || ancestors ? { userLayer, ancestors } : undefined;
    const measurements = await scan({
      root: target.root,
      measures: measuresFor({ userLayer, ancestors, layers }),
      derive: deriveMeasuredOutput,
      include,
      scope,
    });
    // Second check, right before mkdir: the scan takes time, and a link put into runs/ meanwhile must be
    // refused before mkdir could create folders behind it. A link swapped in after this check can still
    // get past it, which is why the check after mkdir below is needed.
    checkRunDir(outDir, HARNESS_ROOT);
    fs.mkdirSync(outDir, { recursive: true });
    // Third check, after mkdir: the folder exists now, so its real path is settled. If a link was swapped in
    // before mkdir, the folder it made lies outside runs/, and this check refuses the run before
    // measurements.json is written there.
    checkRunDir(outDir, HARNESS_ROOT);
    const file = path.join(outDir, "measurements.json");
    // Refuses a measurements.json that is a link, a folder or a hard link, so no other file is written.
    checkRunFile(file);
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
      options: {
        out: { type: "string" },
        "include-user-layer": { type: "boolean" },
        "include-ancestors": { type: "boolean" },
        scope: { type: "string", multiple: true },
        layers: { type: "string" },
      },
    });
  } catch (error) {
    throw new UsageError(error.message);
  }
  const { values, positionals } = parsed;
  if (positionals.length === 0) throw new UsageError("missing the target folder");
  if (positionals.length > 1) throw new UsageError("expected one target folder");
  if (values.out === "") throw new UsageError("the --out folder must not be empty");
  if (values.layers === "") throw new UsageError("the --layers folder must not be empty");
  return {
    target: positionals[0],
    out: values.out,
    userLayer: values["include-user-layer"] === true,
    ancestors: values["include-ancestors"] === true,
    scopes: values.scope ?? [],
    layers: values.layers,
  };
}

// The layers of --layers, read from its run folder and checked against the target. The folder must be allowed, its two files
// must be plain files, and the plan must pass its check. layers.json must name this target, and each layer folder must still
// be a folder of the target reached without a link. Any problem is a usage error, so the run exits with 2 before the scan.
function layerPlanOf(root, input) {
  const runDir = path.resolve(input);
  checkRunDir(runDir, HARNESS_ROOT);
  for (const name of [LAYERS_FILE, PLAN_FILE]) checkRunFile(path.join(runDir, name), { harnessRoot: HARNESS_ROOT });
  const loaded = loadLayerPlan(runDir);
  if (!loaded.ok) {
    const [first] = loaded.errors;
    const where = first.pointer === "" ? "" : `${first.pointer}: `;
    throw new UsageError(`the run folder has no valid layer plan: ${where}${first.message}`);
  }
  if (!isSameFolder(loaded.layers.meta?.targetRoot, root)) {
    throw new UsageError(`${LAYERS_FILE} was not written for this target: ${root}`);
  }
  const problem = layerFolderProblem(root, loaded.plan.layers);
  if (problem !== null) throw new UsageError(`the layer plan does not match the target: ${problem}`);
  return loaded.plan.layers;
}

// Whether a recorded target folder is the target. Both are compared as absolute paths, without letter case on Windows,
// as target.mjs does.
function isSameFolder(recorded, root) {
  if (typeof recorded !== "string" || !path.isAbsolute(recorded)) return false;
  const fold = (value) => (process.platform === "win32" ? value.toLowerCase() : value);
  return fold(path.resolve(recorded)) === fold(path.resolve(root));
}

// The checked scope folders. A folder that cannot be used is a usage error, so the run exits with 2 before the scan.
function scopeFoldersOf(root, scopes) {
  try {
    return resolveScopeFolders(root, scopes);
  } catch (error) {
    if (error instanceof ScopeError) throw new UsageError(error.message);
    throw error;
  }
}

// Six lines at most. Nothing else is printed on success. With a scope, the files line also counts the files inside it.
function printSummary(measurements, file) {
  const { target, warnings, measuredFindings, scope } = measurements;
  const listing = target.fileListSource === "git" ? "listed by git" : "listed by walking the folder";
  const listed = scope === undefined ? listing : `${listing}; ${scope.files.inScope} in the scope`;
  const perAxis = Object.entries(countByAxis(measuredFindings)).map(([axis, count]) => `${axis} ${count}`).join(", ");
  console.log(`target: ${target.name}`);
  console.log(`files: ${target.fileCount} (${listed})`);
  console.log(`commit: ${target.git.head ?? "none"}`);
  console.log(`warnings: ${warnings.length}`);
  console.log(`measured findings: ${perAxis}`);
  console.log(`measurements: ${file}`);
}
