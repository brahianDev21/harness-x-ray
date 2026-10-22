// Checks where a run writes its files. A run folder must lie strictly inside the runs folder of
// harness-x-ray or, unless a caller forbids it, inside the system temp folder (the tests use it).
// The check works on real paths and compares path segments, so a link inside runs/ that points
// elsewhere is refused, and so is a name such as runs-evil. A folder inside the harness folder is
// allowed only below runs/, even when the temp folder contains the harness folder. Every script that
// writes or reads a run folder imports these checks; the helpers of target.mjs do the comparison.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { UsageError, isInside, realpathOfNearest } from "./target.mjs";

/**
 * The two folders a run may use.
 * @param {string} harnessRoot Absolute path of the harness-x-ray folder.
 * @param {{ tempRoot?: string }} [options] tempRoot defaults to os.tmpdir(); tests inject their own.
 * @returns {{ runs: string, temp: string | null }} runs is the real harness folder joined with "runs", and
 *   "runs" itself is not resolved, so a runs folder that is a link elsewhere is not allowed. temp is the
 *   real path of tempRoot, or null when tempRoot does not exist: then there is no temp base, and the
 *   unresolved path is never used in its place.
 */
export function runRoots(harnessRoot, { tempRoot = os.tmpdir() } = {}) {
  return {
    runs: path.join(fs.realpathSync.native(harnessRoot), "runs"),
    temp: tempFolder(tempRoot),
  };
}

/**
 * Checks a run folder. It may not exist yet, and nothing is created. Its real path (the nearest existing
 * ancestor resolved, the missing names appended) must lie strictly below runs/ or, when allowTemp is true,
 * strictly below the temp folder. A real path inside the harness folder is allowed only below runs/,
 * whatever the temp folder is. The runs folder and the temp folder themselves are refused, and so is a
 * path that exists and is not a folder.
 * @param {string} dir The run folder, absolute or relative to the working directory.
 * @param {string} harnessRoot Absolute path of the harness-x-ray folder.
 * @param {{ allowTemp?: boolean, tempRoot?: string }} [options] tempRoot defaults to os.tmpdir(). The temp
 *   folder is resolved only when allowTemp is true, so a check that refuses it never touches it.
 * @returns {string} The real path of dir.
 * @throws {UsageError} If dir is not allowed, if it exists and is not a folder, or if a link on its way is broken.
 */
export function checkRunDir(dir, harnessRoot, { allowTemp = true, tempRoot = os.tmpdir() } = {}) {
  const real = checkRunPlace(dir, harnessRoot, { allowTemp, tempRoot, noun: "folder" });
  if (isNotFolder(real)) throw new UsageError(`not a folder: ${dir}`);
  return real;
}

/**
 * Checks a file that a run is about to write or that a script is about to open. A missing file is fine. A file
 * that exists must be a regular file with one name: a link (report.md -> another file) or a folder is refused, and
 * so is a hard link, which is a second name for a file that may lie outside runs/. The file that a refused name
 * points to is never written.
 * With harnessRoot, the file is also checked for location with the rule of checkRunDir: its real path must lie
 * strictly below runs/ or, when allowTemp is true, below the temp folder. Without harnessRoot, no location is checked,
 * which is what the writing scripts relied on before this option existed.
 * @param {string} file Absolute path of the file.
 * @param {{ harnessRoot?: string, allowTemp?: boolean, tempRoot?: string }} [options] allowTemp defaults to true,
 *   and tempRoot defaults to os.tmpdir(). The location is checked only when harnessRoot is given.
 * @throws {UsageError} If the file lies outside the allowed places, exists and is not a regular file, or has more than one hard link.
 */
export function checkRunFile(file, { harnessRoot, allowTemp = true, tempRoot = os.tmpdir() } = {}) {
  if (harnessRoot !== undefined) checkRunPlace(file, harnessRoot, { allowTemp, tempRoot, noun: "file" });
  let stats;
  try {
    stats = fs.lstatSync(file);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  if (!stats.isFile()) throw new UsageError(`refused: the file exists and is not a regular file: ${file}`);
  if (stats.nlink > 1) throw new UsageError(`refused: the file has more than one hard link: ${file}`);
}

// The location rule of checkRunDir and checkRunFile. Returns the real path of target when it lies in an allowed place, and
// throws otherwise. noun names the kind of target in the message.
function checkRunPlace(target, harnessRoot, { allowTemp, tempRoot, noun }) {
  const harness = fs.realpathSync.native(harnessRoot);
  const runs = path.join(harness, "runs");
  const temp = allowTemp ? tempFolder(tempRoot) : null;
  const real = realpathOfNearest(path.resolve(target));
  // The temp folder can contain the harness folder (the repository cloned under /tmp, or TMPDIR set to it),
  // so inside the harness folder it is not a base: only the folders below runs/ are allowed there.
  const allowed = isInside(harness, real) ? isBelow(runs, real) : temp !== null && isBelow(temp, real);
  if (!allowed) {
    const places = allowTemp ? "runs/ or the system temp folder" : "runs/";
    throw new UsageError(`${noun} must be inside ${places}: ${target}`);
  }
  return real;
}

// Real path of the temp folder, or null when it does not exist: ENOENT, or ENOTDIR when a part of the path is a file.
function tempFolder(tempRoot) {
  try {
    return fs.realpathSync.native(tempRoot);
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return null;
    throw error;
  }
}

// True when the real path exists and is not a folder, or when a part of it is a file. A missing path is not refused here:
// mkdir creates it.
function isNotFolder(real) {
  try {
    return !fs.statSync(real).isDirectory();
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    if (error?.code === "ENOTDIR") return true;
    throw error;
  }
}

// True when candidate lies strictly below base: inside it, and not the same folder.
function isBelow(base, candidate) {
  return isInside(base, candidate) && path.relative(base, candidate) !== "";
}
