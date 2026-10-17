// Builds throwaway mini-repositories for tests, in the system temp folder.
//
// Every fixture has the same layout:
//   <base>/repo      the fixture root (the folder the code under test looks at)
//   <base>/outside   a sibling folder outside the root, for symlinks that point outward
// cleanup() removes <base> completely. Nothing is created inside this repository.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const KNOWN_OPTIONS = new Set(["files", "outside", "git", "gitConfig", "symlinks"]);

// Identity and safety flags for the git commands this helper runs itself. They make the
// result independent of the user's global config: no GPG signing, no CRLF conversion, and
// no fsmonitor (a configured fsmonitor would run code while git reads the index).
const GIT_OPTIONS = [
  "-c", "user.name=Harness X-Ray Fixture",
  "-c", "user.email=fixture@example.invalid",
  "-c", "commit.gpgsign=false",
  "-c", "core.autocrlf=false",
  "-c", "core.fsmonitor=false",
];

let cachedSymlinkSupport = null;

/**
 * Tells whether this system can create symbolic links. The probe runs once per process.
 * Tests use it as: test(name, { skip: support.supported ? false : support.reason }, fn)
 * @returns {{ supported: boolean, reason: string | null }}
 */
export function symlinkSupport() {
  cachedSymlinkSupport ??= probeSymlinks();
  return { ...cachedSymlinkSupport };
}

/**
 * Creates a fixture in the system temp folder.
 * @param {object} [description]
 * @param {Record<string, string | Uint8Array>} [description.files] POSIX relative path -> content.
 *   Strings are written as UTF-8 with no newline conversion; Buffers are written as they are.
 * @param {Record<string, string | Uint8Array>} [description.outside] Same shape, written to <base>/outside.
 * @param {boolean} [description.git] Run `git init -b main`, stage everything and commit it.
 * @param {Record<string, string>} [description.gitConfig] Keys for `git config --local`, applied after the commit.
 * @param {Array<{ path: string, target: string, type?: "file" | "dir" }>} [description.symlinks]
 *   A relative target is resolved from the folder that contains the link, as with any symlink.
 * @returns {{ root: string, base: string, outsideDir: string, cleanup: () => void }}
 *   cleanup() is idempotent. The helper also removes the folder itself if creation fails.
 */
export function makeFixture(description = {}) {
  const { files = {}, outside = {}, git = false, gitConfig = {}, symlinks = [] } = validateDescription(description);

  if (symlinks.length > 0) {
    const support = symlinkSupport();
    if (!support.supported) {
      const error = new Error(support.reason);
      error.code = "ERR_SYMLINK_UNSUPPORTED";
      throw error;
    }
  }

  const base = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-fixture-"));
  const root = path.join(base, "repo");
  const outsideDir = path.join(base, "outside");
  let removed = false;
  const cleanup = () => {
    if (removed) return;
    removeTree(base);
    removed = true;
  };

  try {
    fs.mkdirSync(root);
    fs.mkdirSync(outsideDir);
    writeFiles(root, files, git);
    writeFiles(outsideDir, outside, false);
    createSymlinks(root, symlinks, git);
    if (git) initGitRepo(root, base, gitConfig);
  } catch (error) {
    try {
      cleanup();
    } catch {
      // Ignored on purpose: the original error is the one the caller needs.
    }
    throw error;
  }

  return { root, base, outsideDir, cleanup };
}

/**
 * Runs git with execFile (never a shell) in an isolated environment. GIT_* variables from the
 * caller are dropped, so they cannot point git at another repository (a git hook sets GIT_DIR
 * and GIT_INDEX_FILE, for example). Terminal prompts are disabled.
 * @returns {string} stdout
 */
export function runGit(cwd, args) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.toUpperCase().startsWith("GIT_")) env[key] = value;
  }
  env.GIT_TERMINAL_PROMPT = "0";
  return execFileSync("git", args, {
    cwd,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 60_000,
    windowsHide: true,
  });
}

function validateDescription(description) {
  if (description === null || typeof description !== "object" || Array.isArray(description)) {
    throw new TypeError("makeFixture expects an object");
  }
  for (const key of Object.keys(description)) {
    if (!KNOWN_OPTIONS.has(key)) throw new TypeError(`Unknown fixture option: "${key}"`);
  }
  const { git = false, gitConfig = {}, symlinks = [] } = description;
  if (typeof git !== "boolean") throw new TypeError('"git" must be a boolean');
  if (Object.keys(gitConfig).length > 0 && !git) throw new TypeError('"gitConfig" requires git: true');
  for (const [key, value] of Object.entries(gitConfig)) {
    if (typeof value !== "string") throw new TypeError(`gitConfig value for "${key}" must be a string`);
  }
  if (!Array.isArray(symlinks)) throw new TypeError('"symlinks" must be an array');
  for (const link of symlinks) {
    if (typeof link?.path !== "string" || typeof link?.target !== "string") {
      throw new TypeError("Each symlink needs a string path and a string target");
    }
    if (link.type !== undefined && link.type !== "file" && link.type !== "dir") {
      throw new TypeError(`Symlink type must be "file" or "dir": "${link.path}"`);
    }
  }
  return description;
}

function probeSymlinks() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hxr-symlink-probe-"));
  try {
    fs.writeFileSync(path.join(dir, "target.txt"), "probe");
    fs.mkdirSync(path.join(dir, "target-dir"));
    fs.symlinkSync("target.txt", path.join(dir, "file-link"), "file");
    fs.symlinkSync("target-dir", path.join(dir, "dir-link"), "dir");
    if (!fs.lstatSync(path.join(dir, "file-link")).isSymbolicLink()) {
      throw new Error("the link was created as a regular file");
    }
    return { supported: true, reason: null };
  } catch (error) {
    return { supported: false, reason: unsupportedReason(error) };
  } finally {
    removeTree(dir);
  }
}

function unsupportedReason(error) {
  const detail = error?.code ?? error?.message ?? "unknown error";
  const hint =
    process.platform === "win32"
      ? "On Windows enable Developer Mode or run as administrator."
      : "Check whether this file system supports symbolic links.";
  return `Cannot create symlinks on this system (${detail}). ${hint}`;
}

function writeFiles(dir, entries, rejectGitDir) {
  for (const [relPath, content] of Object.entries(entries)) {
    const abs = resolveInside(dir, relPath);
    if (rejectGitDir) assertNotGitDir(relPath);
    if (typeof content !== "string" && !(content instanceof Uint8Array)) {
      throw new TypeError(`Content of "${relPath}" must be a string or a Buffer`);
    }
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
}

function createSymlinks(root, symlinks, git) {
  for (const link of symlinks) {
    const abs = resolveInside(root, link.path);
    if (git) assertNotGitDir(link.path);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.symlinkSync(link.target, abs, link.type ?? "file");
  }
}

function initGitRepo(root, base, gitConfig) {
  // The hooks folder is never created. This stops hooks from the user's global git config
  // (core.hooksPath) from running during the fixture commit. --no-verify does not cover
  // post-commit, so the override is needed.
  const hooksPath = path.join(base, "no-hooks");
  const options = [...GIT_OPTIONS, "-c", `core.hooksPath=${hooksPath}`];

  runGit(root, [...options, "init", "-q", "-b", "main"]);
  runGit(root, [...options, "add", "--force", "--all"]);
  runGit(root, [...options, "commit", "--no-verify", "--allow-empty", "-q", "-m", "Fixture commit"]);

  // Keep this last. A hostile core.fsmonitor would run on the next command that reads the
  // index. From here on only `git config --local` runs, and it does not read the index.
  for (const [key, value] of Object.entries(gitConfig)) {
    runGit(root, ["config", "--local", key, value]);
  }
}

// Returns the absolute path for relPath inside dir. Throws if relPath escapes dir.
function resolveInside(dir, relPath) {
  const abs = path.resolve(dir, relPath);
  const rel = path.relative(dir, abs);
  if (rel === "" || rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error(`Path must stay inside its fixture folder: "${relPath}"`);
  }
  return abs;
}

// With git: true, the helper owns the .git folder. A .git written as plain files would have
// its config (core.fsmonitor) applied before the helper's own git commands run.
// Windows ignores trailing dots and spaces and is case-insensitive, so both are normalized.
function assertNotGitDir(relPath) {
  const first = relPath.split(/[\\/]/)[0].replace(/[. ]+$/, "").toLowerCase();
  if (first === ".git") {
    throw new Error(`With git: true, "${relPath}" is not allowed; use gitConfig for .git settings`);
  }
}

function removeTree(target) {
  // maxRetries: on Windows, antivirus or indexers can hold a file for a moment.
  // Read-only files (git loose objects) and symlinks are handled by fs.rmSync: links are
  // removed, not followed.
  fs.rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
