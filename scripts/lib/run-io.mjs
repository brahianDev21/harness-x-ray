// Reads and writes the files of a run folder for the commands that take one (compare.mjs, remediate.mjs, render-report.mjs).
// readRunJson reads an input file that must be a regular file with one name, and it can refuse a file larger than a cap.
// writeRunFiles writes several output files as one step, as far as the checks and the texts go. exists tells whether a name is
// present, as itself. The location of the folder and the links of each file are checked by lib/run-dir.mjs, which the callers
// run before they call these functions. Errors that are the caller's fault are UsageError (see lib/target.mjs), and the caller
// maps them to exit code 2.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { checkRunFile } from "./run-dir.mjs";
import { UsageError } from "./target.mjs";

/**
 * Reads one JSON input file of a run. A link or a hard link is refused before it is opened, as checkRunFile reports it. The file
 * is then opened and checked again on its descriptor (see readOpenedFile). A file larger than maxBytes is refused before it is
 * read. A parser message is not printed, since it may quote part of the file.
 * @param {string} file Absolute path of the file.
 * @param {{ maxBytes?: number }} [options] The largest size in bytes that is read. Default: no cap.
 * @returns {unknown} The parsed JSON.
 * @throws {UsageError} If the file is missing, is a link or a hard link, is not a regular file, is larger than maxBytes, cannot be
 *   read, or is not JSON.
 */
export function readRunJson(file, { maxBytes = Number.POSITIVE_INFINITY } = {}) {
  checkRunFile(file);
  const text = readOpenedFile(file, maxBytes);
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`input file is not valid JSON: ${file}`);
  }
}

/**
 * True when a name exists, as itself: a dangling link counts, so that a caller's checkRunFile refuses it instead of ignoring it.
 * @param {string} file
 * @returns {boolean}
 * @throws {Error} For a system error other than a missing name.
 */
export function exists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

/**
 * Writes the output files of a run, all or nothing as far as the checks and the texts go. Each text goes to a temporary name in
 * dir (<file>.<random hex>.tmp, created with the wx flag). Only when all of them are written are they renamed over the final
 * names. The renames are one step each: a failure during them removes the temporary files that were not renamed yet and throws,
 * but the files renamed before the failure stay, so that case can leave some of the new files beside older ones. A failure while
 * the temporary files are written removes all of them and leaves the final names alone.
 * @param {string} dir The run folder, which must exist.
 * @param {Array<{ name: string, text: string }>} outputs The file names (plain names, no folder) and their texts.
 * @throws {TypeError} If a name is empty, has a path separator, or is "." or "..". Nothing is written then.
 * @throws {Error} The system error of the write that failed. The caller reports its first line.
 */
export function writeRunFiles(dir, outputs) {
  for (const { name } of outputs) checkPlainName(name);
  const pending = [];
  try {
    for (const { name, text } of outputs) {
      const temp = path.join(dir, `${name}.${crypto.randomBytes(8).toString("hex")}.tmp`);
      // openSync with wx throws when the name exists. That file is not ours, so it is not listed for removal.
      const fd = fs.openSync(temp, "wx");
      pending.push({ temp, final: path.join(dir, name) });
      try {
        fs.writeFileSync(fd, text, "utf8");
      } finally {
        fs.closeSync(fd);
      }
    }
  } catch (error) {
    removeFiles(pending.map((item) => item.temp));
    throw error;
  }

  const renamed = new Set();
  try {
    for (const item of pending) {
      fs.renameSync(item.temp, item.final);
      renamed.add(item.temp);
    }
  } catch (error) {
    removeFiles(pending.map((item) => item.temp).filter((temp) => !renamed.has(temp)));
    throw error;
  }
}

// An output name is a file name of the run folder: no folder part, and not "." or "..".
function checkPlainName(name) {
  const plain = typeof name === "string" && name !== "" && name !== "." && name !== ".." && !/[\\/]/.test(name);
  if (!plain) throw new TypeError("an output name must be a plain file name: no folder part, not empty, not . or ..");
}

// Opens one input file without following a link (O_NOFOLLOW where the system has it) and reads it through its descriptor, so
// a change between checkRunFile and the read cannot make it a link or a second name. A missing file, a file that became a
// link, and a file that is not a regular file with one name are usage errors. A file larger than maxBytes is a usage error,
// refused on its size before it is read. A file that exists and cannot be read is a usage error with its path only: the system
// message (EACCES and the like) is not printed.
function readOpenedFile(file, maxBytes) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (error?.code === "ENOENT") throw new UsageError(`missing input file: ${file}`);
    if (error?.code === "ELOOP") throw new UsageError(`refused: the file exists and is not a regular file: ${file}`);
    throw new UsageError(`cannot read input file: ${file}`);
  }
  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) throw new UsageError(`refused: the file exists and is not a regular file: ${file}`);
    if (stats.nlink !== 1) throw new UsageError(`refused: the file does not have exactly one name: ${file}`);
    if (stats.size > maxBytes) throw new UsageError(`refused: the file is larger than ${maxBytes} bytes: ${file}`);
    return fs.readFileSync(fd, "utf8");
  } catch (error) {
    if (error instanceof UsageError) throw error;
    throw new UsageError(`cannot read input file: ${file}`);
  } finally {
    fs.closeSync(fd);
  }
}

// Removes temporary files that this run created. A file that cannot be removed does not hide the error that is reported.
function removeFiles(files) {
  for (const file of files) {
    try {
      fs.rmSync(file, { force: true });
    } catch {
      // The first error is the one reported.
    }
  }
}
