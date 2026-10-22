// Command line entry point of the report: node scripts/render-report.mjs <runDir>.
//
// It reads <runDir>/measurements.json and <runDir>/findings.json, validates the findings against the rule catalog,
// the scan and the target, and writes <runDir>/report.md. The run folder must lie inside runs/ of harness-x-ray or inside
// the system temp folder (see lib/run-dir.mjs). Warnings go to stderr; a measured finding that findings.json does not cite
// is one of them. Exit codes: 0 when the report is written; 2 for a usage error, for a run folder that is not allowed or is
// not a folder, for a report.md that exists and is not a regular file with one name, or for an input file that is missing,
// is not JSON, or is not a scan of this tool; 1 when validation fails or anything unexpected happens. A failed run writes nothing and leaves an existing
// report.md untouched. Nothing from the target is executed, and the target is read only by the validator.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formatIssue, loadRules, validateFindings } from "./lib/findings-validate.mjs";
import { readCatalog } from "./lib/report-catalog.mjs";
import { loadLabels } from "./lib/report-labels.mjs";
import { missingField, renderReport } from "./lib/report.mjs";
import { checkRunDir, checkRunFile } from "./lib/run-dir.mjs";
import { UsageError } from "./lib/target.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const USAGE = "usage: node scripts/render-report.mjs <runDir>";
const REPORT_NAME = "report.md";

process.exitCode = await main(process.argv.slice(2));

async function main(argv) {
  try {
    const runDir = path.resolve(parseCommandLine(argv));
    checkRunDir(runDir, HARNESS_ROOT);
    const { measurements, findings } = readInputs(runDir);
    const reportFile = path.join(runDir, REPORT_NAME);
    // Checked before validation, so a link in the way is reported as the usage error it is, and nothing is written.
    checkRunFile(reportFile);

    const rules = loadRules(HARNESS_ROOT);
    const result = validateFindings({
      findings,
      measurements,
      rules,
      targetRoot: measurements.meta.targetRoot,
    });
    if (!result.ok) {
      for (const issue of result.errors) console.error(`error: ${formatIssue(issue)}`);
      console.error(`validation failed with ${result.errors.length} error(s); no report was written`);
      return 1;
    }
    for (const issue of result.warnings) console.error(`warning: ${formatIssue(issue)}`);

    const catalog = readCatalog(HARNESS_ROOT, rules);
    const labels = loadLabels(HARNESS_ROOT, result.language);
    const template = fs.readFileSync(path.join(HARNESS_ROOT, "templates", "report.md"), "utf8");
    const { markdown, unexplained } = renderReport({ measurements, findings, catalog, labels, template });
    for (const item of unexplained) {
      console.error(`warning: measured finding ${item.id} (${item.rule}) is not cited by findings.json`);
    }
    fs.writeFileSync(reportFile, markdown, "utf8");

    console.log(`report: ${reportFile}`);
    console.log(`findings: ${findings.findings.length} from the agent, ${unexplained.length} measured and not cited`);
    console.log(`language: ${result.language}`);
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
    parsed = parseArgs({ args: argv, allowPositionals: true, strict: true, options: {} });
  } catch (error) {
    throw new UsageError(error.message);
  }
  const { positionals } = parsed;
  if (positionals.length === 0) throw new UsageError("missing the run folder");
  if (positionals.length > 1) throw new UsageError("expected one run folder");
  if (positionals[0] === "") throw new UsageError("the run folder must not be empty");
  return positionals[0];
}

// Reads both inputs. A missing or unreadable file, or one that is not JSON, is a usage error (exit 2). The findings
// are not checked here: the validator reports every problem in them.
function readInputs(runDir) {
  if (!fs.existsSync(runDir) || !fs.statSync(runDir).isDirectory()) {
    throw new UsageError(`the run folder does not exist: ${runDir}`);
  }
  const measurements = readJson(path.join(runDir, "measurements.json"));
  const findings = readJson(path.join(runDir, "findings.json"));
  const field = missingField(measurements);
  if (field !== null) {
    throw new UsageError(`measurements.json is not a scan of this tool: it has no ${field}`);
  }
  return { measurements, findings };
}

function readJson(file) {
  if (!fs.existsSync(file)) throw new UsageError(`missing input file: ${file}`);
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    // The parser message is not printed: it may quote part of the file.
    throw new UsageError(`input file is not valid JSON: ${file}`);
  }
}
