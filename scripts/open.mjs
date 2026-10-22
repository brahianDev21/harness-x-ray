// Command line entry point that opens one file or URL of a run in the browser: node scripts/open.mjs <file|url>.
//
// It accepts only an .html file inside runs/ of harness-x-ray (checked on its real path), or a URL
// http://127.0.0.1:<port>/... of the local intake server. The checks and the platform command are in lib/open-target.mjs,
// which starts the command with spawn and never through a shell. Exit codes: 0 when the opener was started; 2 for a
// refused input or a usage error; 3 when there is no graphical environment or the opener is missing, so the caller
// can fall back to printing the path; 1 for anything unexpected.
//
// main(argv, { exec, env, platform }) is exported for the tests: they inject the opener and never start one. The
// command runs only when this file is the entry point, so importing it starts nothing.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { openTarget } from "./lib/open-target.mjs";
import { UsageError } from "./lib/target.mjs";

const SELF = fileURLToPath(import.meta.url);
const HARNESS_ROOT = path.resolve(path.dirname(SELF), "..");
const USAGE = "usage: node scripts/open.mjs <file|url>";

if (isEntryPoint()) process.exitCode = await main(process.argv.slice(2));

/**
 * Runs one open request and prints its result.
 * @param {string[]} argv The arguments after the script name.
 * @param {{ exec?: Function, env?: object, platform?: string }} [options] Passed to openTarget; the defaults are the process values.
 * @returns {Promise<number>} The exit code.
 */
export async function main(argv, { exec, env, platform } = {}) {
  let input;
  try {
    input = parseCommandLine(argv);
  } catch (error) {
    console.error(`error: ${error.message}`);
    console.error(USAGE);
    return 2;
  }
  const result = await openTarget(input, { harnessRoot: HARNESS_ROOT, exec, env, platform });
  if (result.code === 0) {
    console.log(result.message);
    return 0;
  }
  console.error(`error: ${result.message}`);
  if (result.code === 2) console.error(USAGE);
  return result.code;
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
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {},
    });
  } catch (error) {
    throw new UsageError(error.message);
  }
  if (parsed.positionals.length !== 1) throw new UsageError("expected exactly one file or URL");
  return parsed.positionals[0];
}
