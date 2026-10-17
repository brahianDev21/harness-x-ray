// Checks where a scan reads from and writes to. The target must be a folder outside harness-x-ray,
// and the output folder must lie outside the target, so the scanner never writes into the repository
// it audits. Containment compares path segments, not text, and ignores letter case on Windows.

import fs from "node:fs";
import path from "node:path";

/** An invalid target or invalid usage. The command line reports it with exit code 2. */
export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * Checks the target folder. It must exist and be a folder, and it must be neither harness-x-ray,
 * nor inside it, nor a folder that contains it.
 * @param {string} input The target as the user typed it.
 * @param {string} harnessRoot Absolute path of the harness-x-ray folder.
 * @returns {{ root: string, name: string }} root is the real path of the target; name is its basename.
 * @throws {UsageError} If the target is not valid.
 */
export function resolveTarget(input, harnessRoot) {
  if (input === "") throw new UsageError("the target folder must not be empty");
  const root = realpathOrNull(path.resolve(input));
  if (root === null) throw new UsageError(`target does not exist or cannot be opened: ${input}`);
  if (!fs.statSync(root).isDirectory()) throw new UsageError(`target is not a folder: ${input}`);
  const harness = fs.realpathSync.native(harnessRoot);
  if (isInside(harness, root)) throw new UsageError(`target is harness-x-ray or lies inside it: ${input}`);
  if (isInside(root, harness)) throw new UsageError(`target contains harness-x-ray: ${input}`);
  return { root, name: path.basename(root) || "root" };
}

/**
 * Checks the output folder. It may not exist yet, but it may not lie inside the target.
 * @param {string} outDir Absolute path of the output folder.
 * @param {string} targetRoot Real path of the target, as resolveTarget returns it.
 * @throws {UsageError} If the output folder is inside the target.
 */
export function checkOutputDir(outDir, targetRoot) {
  if (isInside(targetRoot, realpathOfNearest(outDir))) {
    throw new UsageError(`output folder is inside the target: ${outDir}`);
  }
}

/**
 * True when candidate is base or lies below it. Compares path segments, so "C:\a\b" does not
 * contain "C:\a\bc". On Windows the comparison ignores letter case.
 * @param {string} base Absolute path.
 * @param {string} candidate Absolute path.
 * @returns {boolean}
 */
export function isInside(base, candidate) {
  const fold = (value) => (process.platform === "win32" ? value.toLowerCase() : value);
  const relative = path.relative(fold(base), fold(candidate));
  if (relative === "") return true;
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

/**
 * Default output folder: runs/<target name>-<YYYYMMDD-HHmmss> under the harness-x-ray folder.
 * The time is local.
 * @param {{ harnessRoot: string, targetName: string, now: Date }} options
 * @returns {string}
 */
export function defaultOutputDir({ harnessRoot, targetName, now }) {
  return path.join(harnessRoot, "runs", `${targetName}-${formatStamp(now)}`);
}

/** Local date and time as YYYYMMDD-HHmmss. */
export function formatStamp(date) {
  const part = (value, width = 2) => String(value).padStart(width, "0");
  const day = `${part(date.getFullYear(), 4)}${part(date.getMonth() + 1)}${part(date.getDate())}`;
  const time = `${part(date.getHours())}${part(date.getMinutes())}${part(date.getSeconds())}`;
  return `${day}-${time}`;
}

// Real path of a file or folder, or null when it cannot be resolved.
function realpathOrNull(target) {
  try {
    return fs.realpathSync.native(target);
  } catch {
    return null;
  }
}

// Real path of the nearest existing ancestor, with the names that do not exist yet appended. A
// folder that is not created yet has no real path of its own, so this is how it is compared.
function realpathOfNearest(target) {
  const missing = [];
  let current = target;
  for (;;) {
    try {
      return path.join(fs.realpathSync.native(current), ...missing);
    } catch (error) {
      const parent = path.dirname(current);
      if (parent === current || !["ENOENT", "ENOTDIR"].includes(error?.code)) throw error;
      missing.unshift(path.basename(current));
      current = parent;
    }
  }
}
