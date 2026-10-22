// Command line entry point that compares two scans of one harness: node scripts/compare.mjs <runA> <runB>.
//
// It reads measurements.json and findings.json of each run and compares them with lib/comparison.mjs. The target is never read.
// The result is written into <runB> as comparison.json, comparison.md and comparison.html, in the language of the findings.json
// of run B. Both run folders must lie inside runs/ of harness-x-ray or inside the system temp folder (see lib/run-dir.mjs), and
// they may be the same folder. Each input file must be a regular file with one name: a link or a hard link is refused, and a
// missing file is a usage error. An input is opened without following a link, and its descriptor is checked and read, so a
// change after the first check cannot make it a link. An input that exists but cannot be read is a usage error that names
// only its path (cannot read input file: <path>), not the system message. Each output file is checked the same way before
// anything is written.
//
// Writing is all or nothing as far as the checks and the texts go: the three texts are built and their files are checked
// before any write. Then each text goes to a temporary name in <runB> (<file>.<random hex>.tmp, created with the wx flag),
// and only when all three are written are they renamed over the final names. The three renames are three steps, not one: a
// failure during them removes the temporary files that were not renamed yet and exits 1, but the files renamed before the
// failure stay, so that case can leave some of the new files beside older ones.
//
// Warnings go to stderr, one line per code, after the files are written. stdout gives the three paths, the count of each class,
// the number of warnings and the language. Exit codes: 0 when the three files are written; 2 for a usage or input error (the
// arguments, a run folder that is not allowed, is missing or is not a folder, an input file that is missing, cannot be read, is not JSON, is a
// link, or is not a scan of this tool, or an output file that is a link, a folder or a hard link); 1 for anything else. The
// first line of an error is printed, and nothing from the target is printed.
//
// main(argv) is exported for the tests. The command runs only when this file is the entry point, so importing it starts nothing.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { CLASSES, compareRuns } from "./lib/comparison.mjs";
import { renderComparisonHtml, renderComparisonMarkdown } from "./lib/comparison-view.mjs";
import { loadTheme } from "./lib/html.mjs";
import { loadRules } from "./lib/findings-validate.mjs";
import { toStableJson } from "./lib/json-out.mjs";
import { loadLabels } from "./lib/report-labels.mjs";
import { checkRunDir, checkRunFile } from "./lib/run-dir.mjs";
import { readRunJson, writeRunFiles } from "./lib/run-io.mjs";
import { UsageError } from "./lib/target.mjs";

const SELF = fileURLToPath(import.meta.url);
const HARNESS_ROOT = path.resolve(path.dirname(SELF), "..");
const USAGE = "usage: node scripts/compare.mjs <runA> <runB>";
const JSON_NAME = "comparison.json";
const MARKDOWN_NAME = "comparison.md";
const HTML_NAME = "comparison.html";

if (isEntryPoint()) process.exitCode = await main(process.argv.slice(2));

/**
 * Compares two runs and writes the three comparison files into the second one.
 * @param {string[]} argv The arguments after the script name: exactly two run folders.
 * @returns {Promise<number>} The exit code.
 */
export async function main(argv) {
  try {
    const [dirA, dirB] = parseCommandLine(argv);
    const a = readRun(dirA);
    const b = readRun(dirB);
    const comparison = compareRuns({
      a: { name: a.name, measurements: a.measurements, findings: a.findings },
      b: { name: b.name, measurements: b.measurements, findings: b.findings },
    });
    // The texts are all built, and the files checked, before anything is written.
    const labels = loadLabels(HARNESS_ROOT, comparison.language);
    const ruleTitles = new Map(loadRules(HARNESS_ROOT).map((rule) => [rule.id, rule.title]));
    const outputs = [
      { label: "json", name: JSON_NAME, text: toStableJson(comparison) },
      { label: "markdown", name: MARKDOWN_NAME, text: renderComparisonMarkdown(comparison, { labels, ruleTitles }) },
      {
        label: "html",
        name: HTML_NAME,
        text: renderComparisonHtml(comparison, {
          labels,
          ruleTitles,
          template: readText("templates", "comparison.html"),
          theme: loadTheme(HARNESS_ROOT),
          css: readText("templates", "report.css"),
        }).html,
      },
    ];
    for (const output of outputs) checkRunFile(path.join(b.dir, output.name), { harnessRoot: HARNESS_ROOT });
    writeRunFiles(b.dir, outputs);

    for (const output of outputs) console.log(`${output.label}: ${path.join(b.dir, output.name)}`);
    const { counts } = comparison;
    console.log(`counts: ${CLASSES.map((name) => `${name} ${counts[name]}`).join(", ")}`);
    console.log(`warnings: ${comparison.warnings.length}`);
    console.log(`language: ${comparison.language}`);
    for (const warning of comparison.warnings) console.error(`warning: ${warning.code}`);
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
  if (positionals.length !== 2) throw new UsageError(`expected two run folders, got ${positionals.length}`);
  if (positionals.some((dir) => dir === "")) throw new UsageError("the run folder must not be empty");
  return positionals;
}

// Checks one run folder and reads its two files. Returns the real folder, its name (the base name of the real path), and the
// parsed files. Nothing from the target is read.
function readRun(dir) {
  const real = checkRunDir(dir, HARNESS_ROOT);
  if (!fs.existsSync(real)) throw new UsageError(`the run folder does not exist: ${dir}`);
  return {
    dir: real,
    name: path.basename(real),
    measurements: readRunJson(path.join(real, "measurements.json")),
    findings: readRunJson(path.join(real, "findings.json")),
  };
}

function readText(...parts) {
  return fs.readFileSync(path.join(HARNESS_ROOT, ...parts), "utf8");
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}
