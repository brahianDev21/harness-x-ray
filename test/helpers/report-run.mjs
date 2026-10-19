// Builds a run folder for the report tests from the permissive fixture, in the system temp folder.
//
// The target is a temp copy of the fixture, with one line appended to .claude/agents/edit-helper.md. The line holds a
// pipe and backticks, so the golden report proves that a quote with them stays readable. The scan runs through the
// command line, and meta.scannedAt is then set to a fixed value, so the report does not depend on the clock.

import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { writeStableJson } from "../../scripts/lib/json-out.mjs";
import { makeFixture } from "./make-fixture.mjs";

const execFileAsync = promisify(execFile);
const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SCAN_SCRIPT = path.join(HARNESS_ROOT, "scripts", "scan.mjs");
export const RENDER_SCRIPT = path.join(HARNESS_ROOT, "scripts", "render-report.mjs");
export const GOLDEN_DIR = path.join(HARNESS_ROOT, "test", "golden");
export const PERMISSIVE = path.join(HARNESS_ROOT, "test", "fixtures", "permissive");
export const SCANNED_AT = "2026-10-18T12:00:00.000Z";
export const APPENDED_LINE = "Never run `rm -rf | git reset --hard` without asking first.";

/**
 * Makes the run folder: a temp target, scanned, with measurements.json whose scannedAt is SCANNED_AT.
 * @returns {Promise<{ fixture: object, runDir: string, measurements: object, cleanup: () => void }>}
 */
export async function makeRun() {
  const fixture = makeFixture({ fromDir: PERMISSIVE });
  try {
    const file = path.join(fixture.root, ".claude", "agents", "edit-helper.md");
    const text = fs.readFileSync(file, "utf8");
    fs.writeFileSync(file, `${text.endsWith("\n") ? text : `${text}\n`}${APPENDED_LINE}\n`);

    const runDir = path.join(fixture.base, "run");
    await execFileAsync(process.execPath, [SCAN_SCRIPT, fixture.root, "--out", runDir], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    const measurementsFile = path.join(runDir, "measurements.json");
    const measurements = JSON.parse(fs.readFileSync(measurementsFile, "utf8"));
    measurements.meta.scannedAt = SCANNED_AT;
    writeStableJson(measurementsFile, measurements);
    return { fixture, runDir, measurements, cleanup: fixture.cleanup };
  } catch (error) {
    fixture.cleanup();
    throw error;
  }
}

/** Runs the render command line on a run folder. Resolves with the exit code and the output, never rejects on exit. */
export async function runRender(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [RENDER_SCRIPT, ...args], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 120_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    return { code: error.code, stdout: error.stdout, stderr: error.stderr };
  }
}

/** The text of a golden file in test/golden. */
export function readGolden(name) {
  return fs.readFileSync(path.join(GOLDEN_DIR, name), "utf8");
}

/** The parsed golden findings input, with the same shape as findings.json. */
export function readGoldenFindings(name) {
  return JSON.parse(readGolden(name));
}

export { HARNESS_ROOT };
