// Read-only access to one target repository. Every read of a target that may be hostile goes
// through this module. It never reads outside the target root, including through symbolic
// links and junctions, and it never follows a link while listing or stat-ing an entry.
//
// Methods do not throw for a skipped path. They return { ok: false, reason } and record a
// warning. The reasons are: outside-root, not-found, not-a-file, too-large, binary, read-error.
// "not-found" is a normal outcome, so it is returned but not recorded as a warning.

import fs from "node:fs";
import path from "node:path";

/** Default cap for readText, in bytes (4 MiB). */
export const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;

// A NUL byte within the first 8 KB marks a file as binary. Bytes after that window are not checked.
const BINARY_SCAN_BYTES = 8 * 1024;

// A name made only of dots and spaces with at least two dots. Windows drops trailing dots and
// spaces, so "..", ".. " and "..." are all treated as the parent folder (the conservative choice).
const PARENT_LIKE = /^[. ]*\.\.[. ]*$/;

/**
 * Opens a read-only view of one target folder.
 * @param {string} root Path of the target folder. It is resolved through symbolic links once.
 * @throws {TypeError | Error} If root is not a non-empty string, does not exist, or is not a folder.
 * @returns {{
 *   readText: (rel: string, options?: { maxBytes?: number }) => object,
 *   stat: (rel: string) => object,
 *   exists: (rel: string) => boolean,
 *   listDir: (rel: string) => object,
 *   warnings: () => Array<{ path: string, reason: string }>,
 * }}
 */
export function createTargetFs(root) {
  if (typeof root !== "string" || root === "") {
    throw new TypeError("createTargetFs expects the path of a folder");
  }
  let realRoot;
  try {
    realRoot = fs.realpathSync.native(root);
  } catch (error) {
    throw new Error(`Target folder does not exist or cannot be opened: ${root}`, { cause: error });
  }
  if (!fs.statSync(realRoot).isDirectory()) {
    throw new Error(`Target is not a folder: ${root}`);
  }

  const recorded = new Map();

  function warn(shown, reason) {
    if (reason === "not-found") return;
    recorded.set(JSON.stringify([shown, reason]), { path: shown, reason });
  }

  function fail(shown, reason) {
    warn(shown, reason);
    return { ok: false, path: shown, reason };
  }

  // Resolves rel to its real path, which must be the root or inside it. A failure is returned
  // as { ok: false, path, reason }; a success as { ok: true, path, real }.
  function locate(rel) {
    const parsed = parseRelative(rel);
    if (parsed.reason !== undefined) return fail(parsed.path, parsed.reason);
    let real;
    try {
      real = fs.realpathSync.native(path.join(realRoot, ...parsed.segments));
    } catch (error) {
      return fail(parsed.path, errorReason(error));
    }
    if (!isInside(realRoot, real)) return fail(parsed.path, "outside-root");
    return { ok: true, path: parsed.path, real };
  }

  function readText(rel, { maxBytes = DEFAULT_MAX_BYTES } = {}) {
    assertRelativeArg(rel);
    assertMaxBytes(maxBytes);
    const target = locate(rel);
    if (!target.ok) return target;
    const outcome = readRegularFile(target.real, maxBytes);
    if (!outcome.ok) return fail(target.path, outcome.reason);
    return { ok: true, path: target.path, text: outcome.text, bytes: outcome.bytes };
  }

  function stat(rel) {
    assertRelativeArg(rel);
    const target = locate(rel);
    if (!target.ok) return target;
    let entry;
    try {
      entry = fs.lstatSync(target.real);
    } catch (error) {
      return fail(target.path, errorReason(error));
    }
    // Directories report 0 bytes: their on-disk size depends on the file system.
    if (entry.isDirectory()) return { ok: true, path: target.path, type: "dir", bytes: 0 };
    if (entry.isFile()) return { ok: true, path: target.path, type: "file", bytes: entry.size };
    return fail(target.path, "not-a-file");
  }

  function exists(rel) {
    assertRelativeArg(rel);
    return locate(rel).ok;
  }

  function listDir(rel) {
    assertRelativeArg(rel);
    const target = locate(rel);
    if (!target.ok) return target;
    let names;
    try {
      if (!fs.lstatSync(target.real).isDirectory()) return fail(target.path, "not-a-file");
      names = fs.readdirSync(target.real);
    } catch (error) {
      return fail(target.path, errorReason(error));
    }
    const entries = [];
    for (const name of names) {
      let entry;
      try {
        entry = fs.lstatSync(path.join(target.real, name));
      } catch (error) {
        if (errorReason(error) === "not-found") continue; // Removed while the folder was listed.
        warn(target.path === "." ? name : `${target.path}/${name}`, "read-error");
        entries.push({ name, type: "other" });
        continue;
      }
      entries.push({ name, type: entryType(entry) });
    }
    entries.sort((a, b) => compareText(a.name, b.name));
    return { ok: true, path: target.path, entries };
  }

  function warnings() {
    return [...recorded.values()]
      .map((item) => ({ path: item.path, reason: item.reason }))
      .sort((a, b) => compareText(a.path, b.path) || compareText(a.reason, b.reason));
  }

  return { readText, stat, exists, listDir, warnings };
}

/**
 * Existence, type and size of an absolute path outside the target, such as the memory files of
 * the folders above it. Only metadata is read: the content is never opened. Links are followed,
 * the same way Claude Code follows them when it loads a memory file.
 * @param {string} absPath Absolute path. Relative input throws.
 * @returns {{ exists: boolean, type?: "file" | "dir" | "other", bytes?: number }}
 */
export function statOutside(absPath) {
  if (typeof absPath !== "string" || !isAbsoluteHostPath(absPath)) {
    throw new TypeError("statOutside expects an absolute path");
  }
  let entry;
  try {
    entry = fs.statSync(absPath);
  } catch {
    return { exists: false };
  }
  if (entry.isDirectory()) return { exists: true, type: "dir", bytes: 0 };
  if (entry.isFile()) return { exists: true, type: "file", bytes: entry.size };
  return { exists: true, type: "other", bytes: 0 };
}

function assertRelativeArg(rel) {
  if (typeof rel !== "string") {
    throw new TypeError(`Path must be a string, got ${rel === null ? "null" : typeof rel}`);
  }
}

function assertMaxBytes(maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("maxBytes must be a non-negative safe integer");
  }
}

// Lexical normalization of a caller path. Returns the display path (POSIX, relative to the root)
// and the segments below the root, or the reason the path cannot be inside the root. The
// segments are what gets joined and read, so the operating system never sees a "..".
function parseRelative(rel) {
  const shown = displayPath(rel);
  if (rel.includes("\0")) return { path: shown, reason: "not-found" };
  if (isRootedOrDriveRelative(rel)) return { path: shown, reason: "outside-root" };
  const segments = [];
  for (const part of rel.split(/[\\/]+/)) {
    if (part === "" || part === ".") continue;
    if (PARENT_LIKE.test(part)) {
      if (segments.length === 0) return { path: shown, reason: "outside-root" };
      segments.pop();
    } else {
      segments.push(part);
    }
  }
  return { path: shown, segments };
}

// POSIX form of the caller's path, with separators converted and "." for the root. Used for
// results and warnings, so they never show a resolved path.
function displayPath(rel) {
  const normalized = path.posix.normalize(rel.replaceAll("\\", "/"));
  return normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

// "/x", "\x", "\\server\share", "\\?\C:\x", "\\.\x", "C:\x", "C:/x" and drive-relative "C:x".
// The drive test also refuses names such as "a:b" on POSIX, which is the conservative choice.
function isRootedOrDriveRelative(rel) {
  return /^[\\/]/.test(rel) || /^[A-Za-z]:/.test(rel);
}

// Containment by path comparison, not by string prefix: "C:\repo" must not admit "C:\repo-evil".
function isInside(base, target) {
  const rel = path.relative(base, target);
  if (rel === "") return true;
  return rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
}

// Reads a regular file that was resolved inside the root. The size is checked before any byte is
// read, and at most the size seen on the open descriptor is read. A binary file is detected from
// its first 8 KB, so the rest of it is not read.
function readRegularFile(real, maxBytes) {
  let before;
  try {
    before = fs.lstatSync(real, { bigint: true });
  } catch (error) {
    return { ok: false, reason: errorReason(error) };
  }
  if (!before.isFile()) return { ok: false, reason: "not-a-file" };
  if (Number(before.size) > maxBytes) return { ok: false, reason: "too-large" };

  let fd;
  try {
    fd = fs.openSync(real, "r");
  } catch (error) {
    return { ok: false, reason: errorReason(error) };
  }
  try {
    // The descriptor must be the entry that was checked. If the path was replaced in between
    // (for example by a link), nothing is read.
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) {
      return { ok: false, reason: "read-error" };
    }
    const size = Number(opened.size);
    if (size > maxBytes) return { ok: false, reason: "too-large" };
    const head = readBytes(fd, Math.min(size, BINARY_SCAN_BYTES));
    if (head.includes(0)) return { ok: false, reason: "binary" };
    const content = Buffer.concat([head, readBytes(fd, size - head.length)]);
    return { ok: true, text: decodeText(content), bytes: content.length };
  } catch (error) {
    return { ok: false, reason: errorReason(error) };
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // Closing a read-only descriptor has nothing useful to report.
    }
  }
}

// Reads up to `length` bytes from the current position. Fewer bytes come back only at end of file.
function readBytes(fd, length) {
  const buffer = Buffer.alloc(length);
  let filled = 0;
  while (filled < length) {
    const count = fs.readSync(fd, buffer, filled, length - filled, null);
    if (count === 0) break;
    filled += count;
  }
  return filled === length ? buffer : buffer.subarray(0, filled);
}

// Decodes UTF-8, drops a leading BOM and turns CRLF and lone CR into LF, so that
// text.split("\n")[i] is line i + 1 as an editor shows it.
function decodeText(content) {
  let text = content.toString("utf8");
  if (text.startsWith("\uFEFF")) text = text.slice(1);
  return text.replace(/\r\n?/g, "\n");
}

function entryType(entry) {
  if (entry.isSymbolicLink()) return "symlink";
  if (entry.isDirectory()) return "dir";
  if (entry.isFile()) return "file";
  return "other";
}

function errorReason(error) {
  return error?.code === "ENOENT" || error?.code === "ENOTDIR" ? "not-found" : "read-error";
}

// Absolute on this system. On Windows a rooted path without a drive ("\x") is refused.
function isAbsoluteHostPath(absPath) {
  if (process.platform !== "win32") return path.posix.isAbsolute(absPath);
  return /^(?:[A-Za-z]:[\\/]|[\\/]{2})/.test(absPath);
}

// Plain code-unit comparison. It does not depend on the locale, so the output is the same everywhere.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
