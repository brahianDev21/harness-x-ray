// Command line entry point of the intake form and of the questions form:
//   node scripts/intake.mjs <runDir> [--questions] [--timeout <seconds>] [--lang en|es].
//
// Without --questions, it starts the local intake server (lib/intake-server.mjs) for the layers of <runDir>/layer-plan.json and
// prints its address as `intake: <url>`, with the one-use token in it. The person opens the address, answers the form and sends
// it. A valid submission writes <runDir>/intake.json and the command exits 0.
// With --questions, it starts the questions server for the questions of <runDir>/questions.json (at most five) and prints
// `questions: <url>`. A valid submission writes <runDir>/answers.json and the command exits 0.
// Nothing is opened in a browser by this script.
// --timeout is the wait in seconds, from 1 to 3600 (default 600). When it runs out, nothing is written and the command exits 4.
// --lang is the language of the pages, en or es (default en).
//
// Exit codes: 0 when the output file was written; 4 when the wait ran out, with nothing written; 2 for a usage or input error (a
// run folder that is not allowed, a missing or invalid layer-plan.json or questions.json, an output file that already exists, an
// invalid option); 1 for anything unexpected.
//
// main(argv, { startIntake, startQuestions, harnessRoot }) is exported for the tests. The server starts only when this file is
// the entry point, so importing it starts nothing.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { LANGUAGES, startIntake as startServer, startQuestions as startQuestionsServer } from "./lib/intake-server.mjs";
import { UsageError } from "./lib/target.mjs";

const SELF = fileURLToPath(import.meta.url);
const HARNESS_ROOT = path.resolve(path.dirname(SELF), "..");
const USAGE = "usage: node scripts/intake.mjs <runDir> [--questions] [--timeout <seconds>] [--lang en|es]";
const DEFAULT_TIMEOUT_SECONDS = 600;
const MAX_TIMEOUT_SECONDS = 3600;

if (isEntryPoint()) process.exitCode = await main(process.argv.slice(2));

/**
 * Runs one intake session (the intake form, or the questions form with --questions) and prints what happens.
 * @param {string[]} argv The arguments after the script name.
 * @param {{ startIntake?: Function, startQuestions?: Function, harnessRoot?: string }} [options] The two servers default to
 *   those of lib/intake-server.mjs.
 * @returns {Promise<number>} The exit code.
 */
export async function main(argv, { startIntake = startServer, startQuestions = startQuestionsServer, harnessRoot = HARNESS_ROOT } = {}) {
  let options;
  try {
    options = parseCommandLine(argv);
  } catch (error) {
    console.error(`error: ${error.message}`);
    console.error(USAGE);
    return 2;
  }
  const start = options.questions ? startQuestions : startIntake;
  const label = options.questions ? "questions" : "intake";
  const outputName = options.questions ? "answers.json" : "intake.json";
  let started;
  try {
    started = await start({
      runDir: options.runDir,
      harnessRoot,
      timeoutMs: options.timeoutSeconds * 1000,
      language: options.language,
    });
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`error: ${error.message}`);
      return 2;
    }
    console.error(`error: ${firstLine(error)}`);
    return 1;
  }
  console.log(`${label}: ${started.url}`);
  const result = await started.done;
  if (result.code === 0) {
    console.log(`written: ${path.join(options.runDir, outputName)}`);
    return 0;
  }
  if (result.code === 4) {
    console.error(`error: timed out after ${options.timeoutSeconds}s; nothing was written`);
    return 4;
  }
  console.error(`error: ${result.message ?? "the intake stopped"}; nothing was written`);
  return 1;
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
      options: { questions: { type: "boolean" }, timeout: { type: "string" }, lang: { type: "string" } },
    });
  } catch (error) {
    throw new UsageError(error.message);
  }
  const { values, positionals } = parsed;
  if (positionals.length === 0) throw new UsageError("missing the run folder");
  if (positionals.length > 1) throw new UsageError("expected one run folder");
  if (positionals[0] === "") throw new UsageError("the run folder must not be empty");
  return {
    runDir: path.resolve(positionals[0]),
    questions: values.questions === true,
    timeoutSeconds: parseTimeout(values.timeout),
    language: parseLanguage(values.lang),
  };
}

function parseTimeout(value) {
  if (value === undefined) return DEFAULT_TIMEOUT_SECONDS;
  const seconds = /^[0-9]+$/.test(value) ? Number(value) : NaN;
  if (!(seconds >= 1 && seconds <= MAX_TIMEOUT_SECONDS)) {
    throw new UsageError(`--timeout must be a whole number of seconds from 1 to ${MAX_TIMEOUT_SECONDS}`);
  }
  return seconds;
}

function parseLanguage(value) {
  if (value === undefined) return "en";
  if (!LANGUAGES.includes(value)) throw new UsageError(`--lang must be ${LANGUAGES.join(" or ")}`);
  return value;
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}
