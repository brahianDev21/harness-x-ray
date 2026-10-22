// Opens one run file or one local intake URL in the browser (see scripts/open.mjs). Only two inputs are opened: an
// .html file inside runs/ of harness-x-ray, checked on its real path (lib/run-dir.mjs), and a URL
// http://127.0.0.1:<port>/... of the local intake server. The platform command is started with spawn, never a shell,
// with the target as one argument. The child is detached and not waited for, so a browser that inherits the pipes of
// the opener does not hold the caller: the exit code says that the opener started, not that the page loaded.
// Exit codes: 0 when the opener was started; 2 for a refused input; 3 when there is no graphical environment or the
// opener cannot be found; 1 for anything unexpected.
//
// Platforms: xdg-open on Linux and other Unix, open on macOS, and cmd.exe with `start` on Windows. The Windows command
// is NOT verified on a Windows machine. cmd.exe is started by its full path (ComSpec, else SystemRoot\System32\cmd.exe),
// never by a bare name the search path could resolve in the current folder. cmd.exe interprets & | < > ^ % ! " ( ) , ; =
// and quotes, so a target must contain none of them: below runs/ a file name may use only letters, digits, . _ - and
// spaces, and on win32 the whole real path is checked, which covers the folder of the harness itself.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { checkRunFile, runRoots } from "./run-dir.mjs";
import { UsageError } from "./target.mjs";

const URL_PATTERN = /^http:\/\/127\.0\.0\.1:(\d{1,5})(\/[A-Za-z0-9._~/-]*)?(\?[A-Za-z0-9._~=-]*)?$/;
// Two or more characters before the colon, so that a drive letter (C:\...) is taken for a path, not a scheme.
const SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]+:/;
const NAME_PART_PATTERN = /^[A-Za-z0-9._ -]+$/;
const CMD_METACHARACTERS = /[%!"&<>^|(),;=]/;
const CMD_NAME = "cmd.exe";

/**
 * Checks an input and opens it with the platform command.
 * @param {string} input An .html file (a path, absolute or relative to the working directory) or an intake URL.
 * @param {{ harnessRoot: string, platform?: string, env?: NodeJS.ProcessEnv, exec?: Function }} options
 *   harnessRoot is the harness-x-ray folder. platform and env default to the process values. exec(file, args, options)
 *   starts the command and returns a promise that resolves once it has started; it defaults to a detached spawn that
 *   is not waited for, and tests inject their own. The options passed are { shell: false, windowsHide: true }.
 * @returns {Promise<{ code: number, message: string, command?: string, args?: string[] }>} The exit code (see the
 *   header) and a one-line message. command and args are set once the opener has been called.
 */
export async function openTarget(
  input,
  { harnessRoot, platform = process.platform, env = process.env, exec = spawnDetached } = {},
) {
  let target;
  try {
    if (typeof input !== "string" || input === "") throw new UsageError("no file or URL given");
    target = SCHEME_PATTERN.test(input) ? checkUrl(input) : checkFile(input, harnessRoot, platform);
  } catch (error) {
    if (error instanceof UsageError) return { code: 2, message: `refused: ${error.message}` };
    return { code: 1, message: `unexpected error: ${firstLine(error)}` };
  }

  if (needsDisplay(platform) && !env.DISPLAY && !env.WAYLAND_DISPLAY) {
    return {
      code: 3,
      message: `no graphical environment (DISPLAY and WAYLAND_DISPLAY are not set); open it by hand: ${target}`,
    };
  }

  const opener = openerFor(platform, target, env);
  if (opener === null) {
    return {
      code: 3,
      message: `cannot find ${CMD_NAME}: ComSpec is not an absolute path to it and SystemRoot is not absolute; open it by hand: ${target}`,
    };
  }
  const { command, args } = opener;
  try {
    await exec(command, args, { shell: false, windowsHide: true });
  } catch (error) {
    if (error?.code === "ENOENT") return { code: 3, message: `opener not found: ${command}`, command, args };
    return { code: 1, message: `could not open ${target}: ${firstLine(error)}`, command, args };
  }
  return { code: 0, message: `opened ${target}`, command, args };
}

// The default opener: a detached child that is unref'd. The promise resolves when the child has started, and rejects
// when it cannot be started (ENOENT). No timeout and no wait: the opener may hand off to a browser that keeps the pipes.
// A failure after the start (an opener that finds no handler) is not seen.
function spawnDetached(file, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { ...options, detached: true, stdio: "ignore" });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

// A file under runs/: it must exist, its real path must lie below runs/ (no temp folder), it must be a regular file with
// one name, its name must end in .html, and the part below runs/ must use only the characters of NAME_PART_PATTERN.
// Returns the real path, which is what the opener receives.
function checkFile(input, harnessRoot, platform) {
  let real;
  try {
    real = fs.realpathSync.native(path.resolve(input));
  } catch (error) {
    if (["ENOENT", "ENOTDIR", "ELOOP"].includes(error?.code)) throw new UsageError(`not an existing file: ${input}`);
    throw error;
  }
  checkRunFile(real, { harnessRoot, allowTemp: false });
  if (!path.basename(real).endsWith(".html")) throw new UsageError(`not an .html file (lower case): ${input}`);
  const below = path.relative(runRoots(harnessRoot).runs, real);
  if (!below.split(path.sep).every((part) => NAME_PART_PATTERN.test(part))) {
    throw new UsageError(`the path below runs/ may use only letters, digits, . _ - and spaces: ${input}`);
  }
  if (platform === "win32" && CMD_METACHARACTERS.test(real)) {
    throw new UsageError(`the path has characters that cmd.exe interprets: ${input}`);
  }
  return real;
}

// The one allowed URL shape. The original string must match the pattern, and the parsed URL must agree: http, host
// 127.0.0.1, no user or password, and the same port (URL leaves the default port 80 empty). Returns the parsed href.
function checkUrl(input) {
  const match = URL_PATTERN.exec(input);
  if (match === null) throw new UsageError(`not a local intake URL (http://127.0.0.1:<port>/...): ${input}`);
  const port = Number(match[1]);
  if (!(port >= 1 && port <= 65535)) throw new UsageError(`port out of range: ${input}`);
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new UsageError(`not a valid URL: ${input}`);
  }
  const parsedPort = Number(url.port === "" ? "80" : url.port);
  const agrees =
    url.protocol === "http:" &&
    url.hostname === "127.0.0.1" &&
    url.username === "" &&
    url.password === "" &&
    parsedPort === port;
  if (!agrees) throw new UsageError(`not a local intake URL (http://127.0.0.1:<port>/...): ${input}`);
  return url.href;
}

// The command for a platform, or null when Windows has no usable cmd.exe. Windows uses `start` through cmd.exe. The
// empty title is passed as an empty argument: Node quotes it as "" itself, whereas a literal "\"\"" would be escaped
// and cmd.exe would not read it as an empty title.
function openerFor(platform, target, env) {
  if (platform === "darwin") return { command: "open", args: [target] };
  if (platform === "win32") {
    const command = cmdPath(env);
    if (command === null) return null;
    return { command, args: ["/d", "/s", "/c", "start", "", target] };
  }
  return { command: "xdg-open", args: [target] };
}

// The full path of cmd.exe: ComSpec when it is an absolute path whose file name is cmd.exe (any case), else
// SystemRoot\System32\cmd.exe when SystemRoot is absolute, else null. The paths are read as Windows paths, so the answer
// does not depend on the host running the check.
function cmdPath(env) {
  const comspec = env.ComSpec ?? "";
  if (path.win32.isAbsolute(comspec) && path.win32.basename(comspec).toLowerCase() === CMD_NAME) return comspec;
  const systemRoot = env.SystemRoot ?? "";
  if (path.win32.isAbsolute(systemRoot)) return path.win32.join(systemRoot, "System32", CMD_NAME);
  return null;
}

function needsDisplay(platform) {
  return platform !== "darwin" && platform !== "win32";
}

function firstLine(error) {
  return String(error?.message ?? error).split("\n")[0];
}
