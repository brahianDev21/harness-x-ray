// Removes the folders of this machine from text copied out of the target. The target root becomes
// <target> and the home folder becomes ~. Every spelling of a folder is covered: backslashes, forward
// slashes, and the drive forms of Git Bash (/c/... and //c/...). On Windows the match ignores letter
// case. A folder with no segments, such as "/" or "C:\", is never replaced, because it would match
// almost any text.
//
// Token-shaped text (the specific patterns of secret-patterns.mjs) is masked as well, anywhere in the
// string. Generic assignments are not: a key name alone does not show a secret.

import fs from "node:fs";
import os from "node:os";
import { maskSpecificSecrets } from "./secret-patterns.mjs";

// Matches one or more separators, either kind.
const SEPARATOR = "[\\\\/]+";
// A match starts at the beginning of a path, not inside a longer name or another path.
const BEFORE = "(?<![A-Za-z0-9_.\\\\/-])";
// A match ends at the end of a folder name, not inside a longer one ("repo" is not "repo-evil").
const AFTER = "(?![A-Za-z0-9_.-])";
const DRIVE = /^([A-Za-z]):$/;

/**
 * Builds the redaction function for one scan.
 * @param {object} [options]
 * @param {string} [options.root] Target root, as the scanner received it.
 * @param {string} [options.home] Home folder. Defaults to os.homedir().
 * @param {string} [options.platform] Defaults to process.platform.
 * @returns {(value: unknown) => unknown} Redacts strings; any other value is returned unchanged.
 */
export function createRedactor({ root, home = os.homedir(), platform = process.platform } = {}) {
  const windows = platform === "win32";
  // The root first: it may lie inside the home folder, and it must become <target>, not ~.
  const rules = [...rulesFor(root, "<target>", windows), ...rulesFor(home, "~", windows)];
  return function redact(value) {
    if (typeof value !== "string") return value;
    let text = value;
    for (const rule of rules) text = text.replace(rule.pattern, rule.replacement);
    return maskSpecificSecrets(text);
  };
}

// One rule for a folder: a single pattern with one alternative per spelling. The given path and its
// real path (which may differ by letter case or by short names) are both covered.
function rulesFor(folder, replacement, windows) {
  if (typeof folder !== "string" || folder === "") return [];
  const spellings = new Set([folder]);
  const real = realPathOrNull(folder);
  if (real !== null) spellings.add(real);
  const alternatives = [];
  for (const spelling of spellings) alternatives.push(...alternativesFor(spelling, windows));
  if (alternatives.length === 0) return [];
  const pattern = new RegExp(`${BEFORE}(?:${alternatives.join("|")})${AFTER}`, windows ? "gi" : "g");
  return [{ pattern, replacement }];
}

// The regular expressions that match one folder. A drive folder matches "C:\x" (and "C:/x") and the
// Git Bash forms "/c/x" and "//c/x". Any other absolute folder (POSIX, or a UNC share) matches with
// any separators between its segments.
function alternativesFor(folder, windows) {
  const parts = folder.split(/[\\/]+/).filter((part) => part !== "");
  const drive = DRIVE.exec(parts[0] ?? "");
  if (drive !== null) {
    const rest = parts.slice(1);
    if (rest.length === 0) return [];
    const letter = caseless(drive[1]);
    const tail = rest.map(escapeRegExp).join(SEPARATOR);
    return [`${letter}:${SEPARATOR}${tail}`, `[\\\\/]{1,2}${letter}${SEPARATOR}${tail}`];
  }
  if (!/^[\\/]/.test(folder) || parts.length === 0) return [];
  return [`${SEPARATOR}${parts.map(escapeRegExp).join(SEPARATOR)}`];
}

// The drive letter in either case, for any platform.
function caseless(letter) {
  return `[${letter.toLowerCase()}${letter.toUpperCase()}]`;
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// The real path of a folder, or null when it does not exist (the given spelling is then enough).
function realPathOrNull(folder) {
  try {
    return fs.realpathSync.native(folder);
  } catch {
    return null;
  }
}
