// The scope of a scan (--scope): the folders of the target that the size measures look at, and the harness that working
// in them inherits.
//
// A scope folder is a folder of the target, given relative to it. resolveScopeFolders checks each one through safe-fs: it
// must exist, be a folder, lie inside the target and be reached without a symbolic link, so the folder that is checked is
// the one that the file list names. The checked folders are reduced to the smallest set that covers them: a folder inside
// another scope folder adds nothing, and duplicates are dropped.
//
// The inherited folders are the folders between the root and each scope folder, the root included and the scope folders
// left out: for the scope apps/web they are "." and apps. The harness of the scope is the harness of the root, of each
// inherited folder and of every folder inside the scope (keepsHarness). A harness file belongs to the folder before its first
// harness folder name (harnessFolderOf): a dot folder that a glob of data/agent-harness.json starts with, such as .claude,
// .agents or .cursor. apps/.claude/skills/a/SKILL.md belongs to apps, and .cursor/rules/a.mdc to the root. Any other dot
// folder is an ordinary folder: apps/.venv/pkg/AGENTS.md belongs to apps/.venv/pkg, not to apps.
//
// Nothing here reads a file of the target. The checks only stat and resolve paths. The registry of this repository is read
// once, for the harness folder names.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadAgentHarness } from "./agent-harness.mjs";
import { createTargetFs } from "./safe-fs.mjs";

const HARNESS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
let harnessFolderNames = null;

/** The most scope folders one scan accepts. */
export const MAX_SCOPE_FOLDERS = 64;

/** A scope folder that cannot be used. The command line reports it with exit code 2. */
export class ScopeError extends Error {
  constructor(message) {
    super(message);
    this.name = "ScopeError";
  }
}

/**
 * Checks the scope folders of a scan and reduces them to the smallest set that covers them.
 * @param {string} root Absolute path of the target, as the scanner resolved it.
 * @param {string[]} inputs The folders as the user typed them, relative to the target.
 * @returns {string[]} Sorted POSIX paths relative to the target, none inside another.
 * @throws {ScopeError} When a folder is empty, absolute, the target itself, outside the target, missing, not a folder,
 *   reached through a link, or when there are more than MAX_SCOPE_FOLDERS of them.
 */
export function resolveScopeFolders(root, inputs) {
  if (!Array.isArray(inputs) || inputs.length === 0) throw new TypeError("inputs must be a non-empty array");
  if (inputs.length > MAX_SCOPE_FOLDERS) throw new ScopeError(`at most ${MAX_SCOPE_FOLDERS} scope folders are accepted`);
  const view = createTargetFs(root);
  return minimalFolders(inputs.map((input) => checkFolder(view, input)));
}

function checkFolder(view, input) {
  if (typeof input !== "string" || input === "") throw new ScopeError("the scope folder must not be empty");
  if (input.includes("\0")) throw new ScopeError("the scope folder must not hold a NUL character");
  const rel = normalized(input);
  if (path.posix.isAbsolute(rel) || /^[A-Za-z]:/.test(rel) || input.startsWith("\\")) {
    throw new ScopeError(`the scope folder must be relative to the target: ${input}`);
  }
  if (rel === ".") throw new ScopeError("the scope folder must be a subfolder of the target; leave out --scope to scan all of it");
  if (rel === ".." || rel.startsWith("../")) throw new ScopeError(`the scope folder leaves the target: ${input}`);
  const entry = view.stat(rel);
  if (!entry.ok) {
    if (entry.reason === "not-found") throw new ScopeError(`the scope folder does not exist in the target: ${input}`);
    if (entry.reason === "outside-root") throw new ScopeError(`the scope folder leaves the target: ${input}`);
    throw new ScopeError(`the scope folder cannot be used (${entry.reason}): ${input}`);
  }
  if (entry.type !== "dir") throw new ScopeError(`the scope folder is not a folder: ${input}`);
  // The real location must be the folder as named: a link on the way, or a name whose letter case differs from the disk, would
  // make the scope name files that the file list does not hold.
  const resolved = view.resolve(rel);
  if (!resolved.ok || resolved.target !== rel) {
    throw new ScopeError(`the scope folder is reached through a link, or its name differs from the disk: ${input}`);
  }
  return rel;
}

// POSIX form, with "." segments, repeated slashes and a trailing slash removed. A backslash is a separator, as safe-fs reads it.
function normalized(input) {
  const posix = path.posix.normalize(input.replaceAll("\\", "/"));
  return posix.length > 1 && posix.endsWith("/") ? posix.slice(0, -1) : posix;
}

// The folders sorted, without duplicates and without a folder that lies inside another one of the list.
function minimalFolders(folders) {
  const sorted = [...new Set(folders)].sort(compareText);
  return sorted.filter((folder) => !sorted.some((other) => other !== folder && isWithin(other, folder)));
}

/**
 * The scope of a scan, from folders that resolveScopeFolders has checked.
 * @param {string[]} folders Sorted, minimal POSIX folders relative to the target.
 * @returns {Readonly<{
 *   folders: readonly string[],
 *   inherited: readonly string[],
 *   contains: (rel: string) => boolean,
 *   isInherited: (folder: string) => boolean,
 *   keepsHarness: (rel: string) => boolean,
 * }>}
 *   contains: the path is a scope folder or lies inside one. isInherited: the folder is the root or a folder between the root
 *   and a scope folder. keepsHarness: a harness file at the path belongs to the scope, because it lies inside a scope folder
 *   or its harness folder (harnessFolderOf) is inherited.
 */
export function createScope(folders) {
  if (!Array.isArray(folders) || folders.length === 0 || !folders.every((folder) => typeof folder === "string")) {
    throw new TypeError("folders must be a non-empty array of strings");
  }
  const list = Object.freeze([...folders]);
  const inherited = new Set();
  for (const folder of list) {
    for (let current = path.posix.dirname(folder); ; current = path.posix.dirname(current)) {
      inherited.add(current);
      if (current === ".") break;
    }
  }
  const contains = (rel) => list.some((folder) => isWithin(folder, rel));
  const isInherited = (folder) => inherited.has(folder);
  return Object.freeze({
    folders: list,
    inherited: Object.freeze([...inherited].sort(compareText)),
    contains,
    isInherited,
    keepsHarness: (rel) => contains(rel) || isInherited(harnessFolderOf(rel)),
  });
}

/**
 * The folder that a harness file belongs to: the folders of its path before the first folder named as a harness folder (see
 * harnessFolders), or before its file name when no folder is. "." for the root.
 * @param {string} rel POSIX path of a file, relative to the target.
 * @returns {string}
 */
export function harnessFolderOf(rel) {
  const names = harnessFolders();
  const segments = rel.split("/").slice(0, -1);
  const found = segments.findIndex((segment) => names.has(segment));
  const kept = found === -1 ? segments : segments.slice(0, found);
  return kept.length === 0 ? "." : kept.join("/");
}

/**
 * The harness folder names: the first segment of every glob of data/agent-harness.json that starts with a literal dot
 * folder (.claude/settings.json gives .claude). Read once per process.
 * @returns {ReadonlySet<string>}
 */
export function harnessFolders() {
  if (harnessFolderNames === null) {
    const names = new Set();
    for (const entry of loadAgentHarness(HARNESS_ROOT).files) {
      const segments = entry.glob.split("/");
      if (segments.length > 1 && segments[0].startsWith(".") && !segments[0].includes("*")) names.add(segments[0]);
    }
    harnessFolderNames = Object.freeze(names);
  }
  return harnessFolderNames;
}

// The path is the folder itself or lies inside it.
function isWithin(folder, rel) {
  return rel === folder || rel.startsWith(`${folder}/`);
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
