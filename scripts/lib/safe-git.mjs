// Read-only file list and commit of one target folder. Inside a git repository the list is what
// git tracks. Anywhere else, or when git cannot be used, it is a walk of the disk through safe-fs.
//
// Every git command is hardened. It runs through execFile (never a shell), with fsmonitor and
// hooks turned off and with GIT_* variables removed from the environment, so the .git/config of
// the target cannot run anything. Nothing here passes safe.directory: git's ownership check stays on.
//
// Every path is checked and sized through safe-fs, which never reads or stats outside the root.
// Warnings carry fixed codes only. git's stderr is never copied into a result, because it contains
// absolute paths of this machine.

import { execFile } from "node:child_process";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { createTargetFs } from "./safe-fs.mjs";

const execFileAsync = promisify(execFile);

/** Time limit for each git command, in milliseconds, unless the caller sets timeoutMs. */
export const DEFAULT_GIT_TIMEOUT_MS = 30_000;

// Room for a very large repository. A larger output is reported as "output-too-large".
const GIT_MAX_BUFFER_BYTES = 64 * 1024 * 1024;

// Folders the walk never enters, at any depth. Names are compared after foldName().
const WALK_SKIPPED_NAMES = new Set([".git", "node_modules"]);

// Same rule as safe-fs: a name made only of dots and spaces, with at least two dots.
const PARENT_LIKE = /^[. ]*\.\.[. ]*$/;

// Characters Windows refuses in a name. The colon also blocks alternate data streams ("name:stream").
const WINDOWS_FORBIDDEN = /[<>:"|?*\u0000-\u001f]/;

const FULL_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const NO_COMMIT_TEXT = /unknown revision|ambiguous argument/i;
const DUBIOUS_OWNERSHIP_TEXT = /detected dubious ownership|unsafe repository \(.+ is owned by someone else\)/i;
const NOT_A_REPOSITORY_TEXT = /not a git repository/i;

// core.hooksPath names a folder that does not exist. The name has a random part, so no folder can
// be planted there in advance. Forward slashes keep the value free of escapes on Windows.
const NO_HOOKS_PATH = path.join(os.tmpdir(), `hxr-no-hooks-${crypto.randomUUID()}`).replaceAll("\\", "/");

/**
 * Lists the files under a folder and reads the commit of its repository.
 * @param {string} root Folder to list. It may be a subfolder of a git repository: then only the
 *   files below it are listed, with paths relative to it.
 * @param {{ gitExecutable?: string, timeoutMs?: number }} [options]
 *   gitExecutable: the program to run instead of "git". timeoutMs: the time limit for each git command.
 * @returns {Promise<{
 *   files: Array<{ path: string, bytes: number }>,
 *   fileListSource: "git" | "walk",
 *   commit: string | null,
 *   warnings: Array<{ path: string, reason: string, detail?: string }>,
 * }>} Files sorted by path (code-unit order). Paths are POSIX and relative to root.
 * @throws {TypeError | Error} For invalid options, or when root is not an existing folder.
 */
export async function listFiles(root, options = {}) {
  const settings = readOptions(options);
  const target = createTargetFs(root);
  const repo = path.resolve(root);
  const notes = [];
  const note = (notePath, reason, detail) => notes.push({ path: notePath, reason, detail });

  const listing = await runGit(settings, repo, ["ls-files", "-z"]);
  if (!listing.ok) {
    note(".", "file-list-from-walk", classifyGitFailure(listing.error));
    return buildResult(sortFiles(walkFolder(target, note)), "walk", null, notes, target);
  }

  const files = [];
  const seen = new Set();
  for (const name of splitNames(listing.stdout)) {
    // An unmerged path is listed once per stage, so the same name can come back several times.
    if (seen.has(name)) continue;
    seen.add(name);
    if (!isSafeGitPath(name)) {
      note(name, "unsafe-path");
      continue;
    }
    const entry = target.stat(name);
    if (!entry.ok) {
      note(name, entry.reason);
      continue;
    }
    if (entry.type !== "file") {
      note(name, "not-a-file");
      continue;
    }
    files.push({ path: name, bytes: entry.bytes });
  }

  const commit = await readCommit(settings, repo, note);
  return buildResult(sortFiles(files), "git", commit, notes, target);
}

/**
 * Maps a failed git command to a fixed detail code. Only the code is kept, never the message.
 * @param {{ code?: unknown, killed?: unknown, stderr?: unknown }} error The error from execFile.
 * @returns {"git-not-found" | "output-too-large" | "timeout" | "dubious-ownership" | "not-a-repository" | "git-error"}
 */
export function classifyGitFailure(error) {
  if (error?.code === "ENOENT") return "git-not-found";
  if (error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return "output-too-large";
  if (error?.killed === true) return "timeout";
  const text = stderrText(error);
  if (DUBIOUS_OWNERSHIP_TEXT.test(text)) return "dubious-ownership";
  if (NOT_A_REPOSITORY_TEXT.test(text)) return "not-a-repository";
  return "git-error";
}

function readOptions(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("listFiles expects an options object");
  }
  for (const key of Object.keys(options)) {
    if (key !== "gitExecutable" && key !== "timeoutMs") throw new TypeError(`Unknown listFiles option: "${key}"`);
  }
  const { gitExecutable = "git", timeoutMs = DEFAULT_GIT_TIMEOUT_MS } = options;
  if (typeof gitExecutable !== "string" || gitExecutable === "" || gitExecutable.includes("\0")) {
    throw new TypeError("gitExecutable must be a non-empty string");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive safe integer");
  }
  return { gitExecutable, timeoutMs };
}

// Runs one read-only git command in the repository at repo. Returns { ok: true, stdout } with the
// raw bytes, or { ok: false, error }. The caller classifies the error and never stores it.
async function runGit(settings, repo, subcommand) {
  const args = [
    "--no-pager",
    "-c", "core.fsmonitor=false",
    "-c", `core.hooksPath=${NO_HOOKS_PATH}`,
    "-C", repo,
    ...subcommand,
  ];
  try {
    const { stdout } = await execFileAsync(settings.gitExecutable, args, {
      env: gitEnvironment(),
      encoding: "buffer",
      maxBuffer: GIT_MAX_BUFFER_BYTES,
      timeout: settings.timeoutMs,
      windowsHide: true,
    });
    return { ok: true, stdout };
  } catch (error) {
    return { ok: false, error };
  }
}

// A copy of the environment without any GIT_* variable, so none of them can point git at another
// repository, config or hook. Prompts are disabled, index locks are not taken, and LC_ALL=C keeps
// git's messages in English for classifyGitFailure.
function gitEnvironment() {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !key.toUpperCase().startsWith("GIT_")) env[key] = value;
  }
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_OPTIONAL_LOCKS = "0";
  env.LC_ALL = "C";
  return env;
}

// HEAD of the repository, or null with a warning when there is none.
async function readCommit(settings, repo, note) {
  const head = await runGit(settings, repo, ["rev-parse", "HEAD"]);
  if (!head.ok) {
    note(".", "commit-unavailable", classifyCommitFailure(head.error));
    return null;
  }
  const sha = head.stdout.toString("utf8").trim();
  if (FULL_SHA.test(sha)) return sha;
  note(".", "commit-unavailable", "unexpected-output");
  return null;
}

function classifyCommitFailure(error) {
  if (NO_COMMIT_TEXT.test(stderrText(error))) return "no-commit";
  return classifyGitFailure(error);
}

// Depth-first walk of the folder through safe-fs. It does not enter symbolic links to folders.
function walkFolder(target, note) {
  const files = [];
  const pending = [""];
  while (pending.length > 0) {
    const dir = pending.pop();
    const listing = target.listDir(dir === "" ? "." : dir);
    if (!listing.ok) continue;
    for (const entry of listing.entries) {
      if (WALK_SKIPPED_NAMES.has(foldName(entry.name))) continue;
      const rel = dir === "" ? entry.name : `${dir}/${entry.name}`;
      if (!isSafeSegment(entry.name)) {
        note(rel, "unsafe-path");
        continue;
      }
      if (entry.type === "dir") {
        pending.push(rel);
        continue;
      }
      if (entry.type !== "file" && entry.type !== "symlink") {
        note(rel, "not-a-file");
        continue;
      }
      const stat = target.stat(rel);
      if (!stat.ok) {
        note(rel, stat.reason);
      } else if (stat.type === "file") {
        files.push({ path: rel, bytes: stat.bytes });
      } else if (entry.type === "symlink") {
        note(rel, "symlinked-folder");
      } else {
        note(rel, "not-a-file");
      }
    }
  }
  return files;
}

// Splits the NUL-separated output of "ls-files -z". Bytes that are not valid UTF-8 become
// replacement characters, and isSafeSegment refuses those names.
function splitNames(buffer) {
  return buffer.toString("utf8").split("\0").filter((name) => name !== "");
}

// A git path is safe to use only if every segment is. Git does not list ".git" components, so one
// of those is treated as hostile metadata.
function isSafeGitPath(name) {
  return name.split("/").every((segment) => isSafeSegment(segment) && foldName(segment) !== ".git");
}

// Refuses names that would mean something other than the one segment they are: "..", a backslash
// (a separator for safe-fs), and on Windows reserved characters, a trailing dot or space (Windows
// drops them, so the name would reach another file) and alternate data streams.
function isSafeSegment(segment) {
  if (segment === "" || segment === "." || PARENT_LIKE.test(segment)) return false;
  if (segment.includes("\\") || segment.includes("�")) return false;
  if (process.platform === "win32") return !WINDOWS_FORBIDDEN.test(segment) && !/[. ]$/.test(segment);
  return true;
}

// Case, trailing dots and trailing spaces are ignored, as Windows ignores them.
function foldName(name) {
  return name.replace(/[. ]+$/, "").toLowerCase();
}

function stderrText(error) {
  const stderr = error?.stderr;
  if (stderr === undefined || stderr === null) return "";
  return Buffer.isBuffer(stderr) ? stderr.toString("utf8") : String(stderr);
}

function sortFiles(files) {
  return files.sort((a, b) => compareText(a.path, b.path));
}

// Merges the notes of this call with the warnings safe-fs recorded, removes duplicates and sorts.
function buildResult(files, fileListSource, commit, notes, target) {
  const byKey = new Map();
  for (const item of [...notes, ...target.warnings()]) {
    const warning = item.detail === undefined
      ? { path: item.path, reason: item.reason }
      : { path: item.path, reason: item.reason, detail: item.detail };
    byKey.set(JSON.stringify([warning.path, warning.reason, warning.detail ?? null]), warning);
  }
  const warnings = [...byKey.values()].sort(
    (a, b) => compareText(a.path, b.path) || compareText(a.reason, b.reason) || compareText(a.detail ?? "", b.detail ?? ""),
  );
  return { files, fileListSource, commit, warnings };
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
