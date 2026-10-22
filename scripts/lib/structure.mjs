// Measure "structure": the folders of the target, how far the memory maps them, and the large and generated files
// that need care. It reads the file list (ctx.files), the memory texts that the memory measure left in ctx.memory and
// the permission rules through loadClaudeConfig. It opens no file of the target and runs nothing. The patterns are the
// harness's own data, in data/generated-patterns.json.
//
// Output, under structure (the enforcementTools key belongs to the verification measure):
// - tree: one entry per top-level folder and per second-level folder, with the number of files below it.
// - mapCoverage: the top-level folders that are not generated, and the memory files that mention each one.
// - largeFiles: versioned files above THRESHOLDS.largeFileBytes, without lockfiles and without generated files.
// - generatedFiles: one entry per generated folder and one per generated file.
// Each large and generated entry has protection (what the permission rules decide for Read and Edit) and memory (the
// memory lines that name the entry, and whether one of them marks it as not to touch).
//
// With a scope (ctx.scope, see scope.mjs), only the files inside the scope folders are measured, and the folders are
// counted from each scope folder instead of from the root. tree has the first and second folder levels below each scope
// folder, and mapCoverage the first-level folders below each one; both use full paths (apps/web/src). The generated and
// large files are the scope's. A memory file mentions such a folder by its full path, as without a scope, and also, when its
// harness folder H (harnessFolderOf) is not the root and the folder lies inside H, by its path relative to H: a line in
// apps/web/CLAUDE.md that names src/ maps apps/web/src. Protection still uses the global permission rules. Without a scope,
// the base of every path is the root and the output is the one described above.
//
// Heuristics. All of them are conservative, and the memory text is data: nothing in it is followed.
// - A path is mentioned by a memory line when the path begins the line, or follows whitespace, a backtick, a quote,
//   "(" or "[", optionally after "./". A path that follows other text (x/src/, ../src/, xsrc/, **src/**) is part of a
//   longer path or word, so it does not count. Fenced code blocks count too, which is how tree listings mention folders.
// - A mapCoverage folder is also mentioned by a code span that is exactly its path, or its path with a slash. The path
//   relative to the harness folder counts the same way (see above).
// - A folder entry is mentioned by its path followed by a slash. A file entry is mentioned by its path, or by its
//   pattern glob (for example `*.min.js`), when no path character follows.
// - A mention marks the entry as not to touch when the same line also contains a do-not-touch phrase from the data
//   file. Phrases are compared without regard to case, and a curly apostrophe counts as a straight one.
// Memory files marked not-loaded are skipped everywhere in this measure.

import fs from "node:fs";
import { loadClaudeConfig } from "./claude-config.mjs";
import { codeSpans, markdownLines } from "./markdown.mjs";
import { isPlainObject } from "./json-out.mjs";
import { USER_LAYER, decide, decisionRules } from "./permissions.mjs";
import { harnessFolderOf } from "./scope.mjs";
import { THRESHOLDS } from "./thresholds.mjs";

export const MEASURE_ID = "structure";

// Provisional caps on the number of entries of each list. What is cut is counted in one warning.
export const MAX_LARGE_ENTRIES = 200;
export const MAX_GENERATED_ENTRIES = 200;

const DATA_URL = new URL("../../data/generated-patterns.json", import.meta.url);
const TOP_LEVEL = new Set(["directories", "files", "lockfiles", "doNotTouchPhrases"]);
const DIRECTORY_FIELDS = new Set(["id", "folder", "why"]);
const FILE_FIELDS = new Set(["id", "glob", "regex", "why"]);
const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DECISIONS = ["allow", "ask", "default", "deny", "undeterminable"];
// What may come right before a path that starts a mention (nothing, or one of the characters of the header comment), and
// what must not come right after a file path: a path character, or a dot that continues a name (app.min.js is not
// app.min.jsx). A dot that ends a sentence is allowed.
const PATH_START = /(?<![^\s"'`(\[])/.source;
const PATH_END = /(?![\w\/-]|\.\w)/.source;

let loaded = null;

export const structureMeasure = Object.freeze({ id: MEASURE_ID, collect: collectStructure });

/**
 * The generated-file patterns of data/generated-patterns.json, checked and compiled. The file is read and checked once
 * per process. The object is shared: callers must not change it.
 * @returns {{ directories: Array<{ id: string, folder: string }>, files: Array<{ id: string, glob: string, regex: RegExp }>,
 *   lockfiles: Set<string>, phrases: string[] }} Lockfile names and phrases are lowercase; phrases use straight apostrophes.
 * @throws {Error} When the data file does not have the expected shape.
 */
export function loadGeneratedPatterns() {
  loaded ??= compilePatterns(validatePatternData(JSON.parse(fs.readFileSync(DATA_URL, "utf8"))));
  return loaded;
}

/**
 * The id of the generated-file pattern that a path matches, or null. It uses the same rules as classifyGenerated: a file
 * is generated when one of its folders (not its base name) is a directory pattern, and the first such folder from the
 * left decides the id; otherwise the base name must match a file pattern. The path is not read or stat-ed.
 * @param {string} relPath POSIX path relative to the target.
 * @param {ReturnType<typeof loadGeneratedPatterns>} [patterns] The patterns to use. Defaults to the data file.
 * @returns {string | null} The pattern id, such as "dist" or "minified-js".
 */
export function generatedPatternOf(relPath, patterns = loadGeneratedPatterns()) {
  const segments = relPath.split("/");
  for (let index = 0; index < segments.length - 1; index += 1) {
    const folder = patterns.directories.find((item) => item.folder === segments[index]);
    if (folder !== undefined) return folder.id;
  }
  const name = segments[segments.length - 1];
  const file = patterns.files.find((item) => item.regex.test(name));
  return file === undefined ? null : file.id;
}

// Reads the target through ctx only. Returns the section that the scan core merges. With a scope, the size measures see
// only the files inside the scope folders; the memory and the permission rules are read as before.
function collectStructure(ctx) {
  const config = loadClaudeConfig(ctx);
  const rules = decisionRules(config.permissions, ctx.outside);
  const patterns = loadGeneratedPatterns();
  const lines = memoryLines(ctx.memory);
  const files = filesInScope(ctx.files, ctx.scope);
  const generated = classifyGenerated(files, patterns);
  const warnings = [];

  const generatedKept = capped(generated.entries, MAX_GENERATED_ENTRIES, "generated-entries-cut", warnings);
  const largeKept = capped(
    largeCandidates(files, generated.members, patterns.lockfiles),
    MAX_LARGE_ENTRIES,
    "large-files-cut",
    warnings,
  );

  return {
    structure: {
      tree: treeOf(files, ctx.scope),
      mapCoverage: mapCoverageOf(files, generated.generatedFolders, lines, ctx.scope),
      largeFiles: largeKept.map((file) => largeEntry(file, rules, lines, patterns.phrases)),
      generatedFiles: generatedKept.map((entry) => generatedEntry(entry, rules, lines, patterns.phrases)),
    },
    warnings,
  };
}

/**
 * The files that the size measures read: every file without a scope, and with a scope the files inside its folders.
 * @param {Array<{ path: string, bytes: number }>} files ctx.files.
 * @param {{ contains: (rel: string) => boolean } | null} scope ctx.scope: the scope of scope.mjs, or null.
 * @returns {Array<{ path: string, bytes: number }>} The same objects, in the same order.
 */
export function filesInScope(files, scope) {
  return !scope ? files : files.filter((file) => scope.contains(file.path));
}

// The folder that a path is measured from: the scope folder that holds it, or the root ("") without a scope. Every path given
// here lies inside a scope folder when there is a scope (filesInScope).
function baseOf(rel, scope) {
  if (!scope) return "";
  const folder = scope.folders.find((item) => rel.startsWith(`${item}/`));
  if (folder === undefined) throw new Error(`${rel} lies outside the scope`);
  return folder;
}

// The part of a path below its base folder. The base "" is the root, so the path itself.
function belowBase(rel, base) {
  return base === "" ? rel : rel.slice(base.length + 1);
}

// A folder path made of the base and the given segments below it.
function folderAt(base, segments) {
  const below = segments.join("/");
  return base === "" ? below : `${base}/${below}`;
}

// The first-level folder of a path, from the target, or null when the path lies directly in the base.
function firstLevelDirOf(rel, base) {
  const segments = belowBase(rel, base).split("/");
  return segments.length < 2 ? null : folderAt(base, segments.slice(0, 1));
}

// ---------------------------------------------------------------------------------------------------
// The tree

// One entry per first and second folder level below each base (the root, or each scope folder). files counts the files below
// the folder, at any depth. Files directly in a base are not counted.
function treeOf(files, scope) {
  const counts = new Map();
  for (const { path } of files) {
    const base = baseOf(path, scope);
    const segments = belowBase(path, base).split("/");
    for (let depth = 1; depth <= Math.min(2, segments.length - 1); depth += 1) {
      const folder = folderAt(base, segments.slice(0, depth));
      counts.set(folder, (counts.get(folder) ?? 0) + 1);
    }
  }
  return [...counts].map(([path, count]) => ({ path, files: count })).sort(byPath);
}

// ---------------------------------------------------------------------------------------------------
// Map coverage

// The first-level folders that are not generated, and for each one the memory files that mention it. Without a scope these
// are the top-level folders; with one, the first-level folders below each scope folder, by full path.
function mapCoverageOf(files, generatedFolders, lines, scope) {
  const counts = new Map();
  for (const { path } of files) {
    const dir = firstLevelDirOf(path, baseOf(path, scope));
    if (dir === null) continue;
    counts.set(dir, (counts.get(dir) ?? 0) + 1);
  }
  const byDir = [...counts.keys()]
    .filter((dir) => !generatedFolders.has(dir))
    .sort(compareText)
    .map((dir) => {
      const mentions = firstMentionPerFile(lines, mentionsDir(dir));
      return { dir, files: counts.get(dir), mentioned: mentions.length > 0, mentions };
    });
  return { dirs: byDir.length, mentioned: byDir.filter((item) => item.mentioned).length, byDir };
}

// The predicate that tells whether a memory line mentions a mapCoverage folder. The folder counts by its full path. It also
// counts by its path relative to the harness folder of the memory file, when that folder is not the root and holds the folder.
function mentionsDir(dir) {
  const regex = folderRegex(dir);
  return (line) => {
    if (dirMentioned(line, dir, regex)) return true;
    const relative = relativeToHarness(dir, harnessFolderOf(line.file));
    return relative !== null && dirMentioned(line, relative, folderRegex(relative));
  };
}

// A folder is mentioned by its path with a slash, or by a code span that is exactly the path or the path with a slash.
function dirMentioned(line, dir, regex) {
  return regex.test(line.text) || line.spans.some((span) => span.text === dir || span.text === `${dir}/`);
}

// The path of a folder relative to a harness folder, when the folder lies inside it. Null for the root harness "." and for a
// folder outside the harness folder.
function relativeToHarness(folder, harness) {
  if (harness === "." || !folder.startsWith(`${harness}/`)) return null;
  return folder.slice(harness.length + 1);
}

// The first matching line of each memory file. The lines are ordered by file, so this keeps the first one of each.
function firstMentionPerFile(lines, predicate) {
  const seen = new Set();
  const mentions = [];
  for (const line of lines) {
    if (seen.has(line.file) || !predicate(line)) continue;
    seen.add(line.file);
    mentions.push({ file: line.file, line: line.number });
  }
  return mentions;
}

// ---------------------------------------------------------------------------------------------------
// Generated and large files

// The generated entries before the cap. A folder whose name is a directory pattern is one entry, at the outermost
// level where that name appears; every file below it belongs to that entry. A file outside such a folder is one entry
// when its base name matches a file pattern. members holds the path of every file that belongs to an entry.
// generatedFolders holds the path of every folder entry.
function classifyGenerated(files, patterns) {
  const folderByName = new Map(patterns.directories.map((item) => [item.folder, item]));
  const folders = new Map();
  const singles = [];
  const members = new Set();
  for (const { path, bytes } of files) {
    const segments = path.split("/");
    const index = segments.findIndex((segment, at) => at < segments.length - 1 && folderByName.has(segment));
    if (index !== -1) {
      const folderPath = segments.slice(0, index + 1).join("/");
      if (!folders.has(folderPath)) {
        folders.set(folderPath, { kind: "folder", path: folderPath, pattern: folderByName.get(segments[index]), members: [] });
      }
      folders.get(folderPath).members.push({ path, bytes });
      members.add(path);
      continue;
    }
    const name = segments[segments.length - 1];
    const pattern = patterns.files.find((item) => item.regex.test(name));
    if (pattern !== undefined) {
      singles.push({ kind: "file", path, pattern, members: [{ path, bytes }] });
      members.add(path);
    }
  }
  const entries = [...folders.values(), ...singles].sort((a, b) => compareText(a.path, b.path));
  return { entries, members, generatedFolders: new Set(folders.keys()) };
}

// The versioned files above THRESHOLDS.largeFileBytes, sorted by path. Lockfiles are left out by base name, in any
// folder, and so are the files that already belong to a generated entry.
function largeCandidates(files, generatedMembers, lockfiles) {
  return files
    .filter(
      (file) =>
        file.bytes > THRESHOLDS.largeFileBytes &&
        !lockfiles.has(baseName(file.path).toLowerCase()) &&
        !generatedMembers.has(file.path),
    )
    .map(({ path, bytes }) => ({ path, bytes }))
    .sort(byPath);
}

// The first max entries of a sorted list. What is cut is counted in one warning, with a fixed reason.
function capped(list, max, reason, warnings) {
  if (list.length > max) warnings.push({ path: ".", reason, detail: `count=${list.length - max}` });
  return list.slice(0, max);
}

function largeEntry(file, rules, lines, phrases) {
  return {
    path: file.path,
    bytes: file.bytes,
    protection: protectionOf(rules, [file.path]),
    memory: memoryOf(lines, [fileRegex(file.path)], phrases),
  };
}

function generatedEntry(entry, rules, lines, phrases) {
  const paths = entry.members.map((member) => member.path);
  const matchers =
    entry.kind === "folder" ? [folderRegex(entry.path)] : [fileRegex(entry.path), globRegex(entry.pattern.glob)];
  return {
    kind: entry.kind,
    path: entry.path,
    pattern: entry.pattern.id,
    files: paths.length,
    bytes: entry.members.reduce((sum, member) => sum + member.bytes, 0),
    protection: protectionOf(rules, paths),
    memory: memoryOf(lines, matchers, phrases),
  };
}

// ---------------------------------------------------------------------------------------------------
// Protection and memory of one entry

// The verdict of Read and of Edit for the entry. A folder with several files gives the verdict of its files when they
// all agree. When the decisions differ, the decision is mixed and counts says how many files had each decision. When the
// decisions agree but the rules differ, the decision stays and no rule is named. Undeterminable stays undeterminable.
function protectionOf(rules, paths) {
  return { read: verdictFor(rules, "Read", paths), edit: verdictFor(rules, "Edit", paths) };
}

function verdictFor(rules, tool, paths) {
  const verdicts = paths.map((path) => verdictOf(decide(rules, { tool, path })));
  const decisions = new Set(verdicts.map((verdict) => verdict.decision));
  if (decisions.size > 1) {
    const counts = Object.fromEntries(DECISIONS.map((decision) => [decision, 0]));
    for (const verdict of verdicts) counts[verdict.decision] += 1;
    return { decision: "mixed", rule: null, source: null, reason: "several-decisions", counts };
  }
  const [first] = verdicts;
  const same = verdicts.every(
    (verdict) => verdict.rule === first.rule && verdict.source === first.source && verdict.reason === first.reason,
  );
  return same ? first : { decision: first.decision, rule: null, source: null, reason: "several-rules" };
}

// The four fields of a verdict that the output shows. The layer is kept only when the rule comes from the user's settings, so
// a project verdict has the same four fields as before.
function verdictOf(verdict) {
  const shown = { decision: verdict.decision, rule: verdict.rule, source: verdict.source, reason: verdict.reason };
  return verdict.layer === USER_LAYER ? { ...shown, layer: USER_LAYER } : shown;
}

// The memory lines that mention the entry, one per line, in file and line order. marked is true when one of them also
// contains a do-not-touch phrase.
function memoryOf(lines, matchers, phrases) {
  const mentions = [];
  let marked = false;
  for (const line of lines) {
    if (!matchers.some((regex) => regex.test(line.text))) continue;
    mentions.push({ file: line.file, line: line.number });
    if (phrases.some((phrase) => line.normal.includes(phrase))) marked = true;
  }
  return { marked, mentions };
}

// ---------------------------------------------------------------------------------------------------
// Memory lines and regular expressions

// The lines of the memory files that Claude Code loads: every memory file except those marked not-loaded. Rules are
// included (their loadMode is null). Ordered by file, then line.
function memoryLines(memory) {
  const lines = [];
  for (const file of [...memory.keys()].sort(compareText)) {
    const entry = memory.get(file);
    if (entry.loadMode === "not-loaded") continue;
    for (const line of markdownLines(entry.text)) {
      lines.push({
        file,
        number: line.number,
        text: line.text,
        spans: codeSpans(line.text),
        normal: normalizeText(line.text),
      });
    }
  }
  return lines;
}

// A folder path followed by a slash, starting at a path boundary, with an optional "./" in front.
function folderRegex(folder) {
  return new RegExp(`${PATH_START}(?:\\./)?${escapeRegExp(folder)}/`);
}

// A file path, starting at a path boundary and not followed by a path character.
function fileRegex(filePath) {
  return new RegExp(`${PATH_START}(?:\\./)?${escapeRegExp(filePath)}${PATH_END}`);
}

// A pattern glob as written in memory text, at a path boundary and not followed by a path character.
function globRegex(glob) {
  return new RegExp(`${PATH_START}${escapeRegExp(glob)}${PATH_END}`);
}

// ---------------------------------------------------------------------------------------------------
// Data file

function validatePatternData(data) {
  const where = "generated-patterns";
  if (!isPlainObject(data)) throw new Error(`${where}: the data must be an object`);
  for (const key of Object.keys(data)) {
    if (!TOP_LEVEL.has(key)) throw new Error(`${where}: unknown field "${key}"`);
  }
  const ids = new Set();
  const claim = (id, entry) => {
    if (typeof id !== "string" || !KEBAB_CASE.test(id)) throw new Error(`${entry}: id must be kebab-case`);
    if (ids.has(id)) throw new Error(`${entry}: duplicate id "${id}"`);
    ids.add(id);
  };
  const folders = new Set();
  nonEmptyList(data, "directories", where).forEach((item, index) => {
    const entry = `${where}: directories[${index}]`;
    checkFields(item, DIRECTORY_FIELDS, entry);
    claim(item.id, entry);
    if (!isName(item.folder)) throw new Error(`${entry}.folder must be a folder name, without a slash`);
    if (folders.has(item.folder)) throw new Error(`${entry}.folder "${item.folder}" is listed twice`);
    folders.add(item.folder);
    nonEmptyText(item.why, `${entry}.why`);
  });
  nonEmptyList(data, "files", where).forEach((item, index) => {
    const entry = `${where}: files[${index}]`;
    checkFields(item, FILE_FIELDS, entry);
    claim(item.id, entry);
    nonEmptyText(item.glob, `${entry}.glob`);
    compileRegex(item.regex, `${entry}.regex`);
    nonEmptyText(item.why, `${entry}.why`);
  });
  nonEmptyList(data, "lockfiles", where).forEach((name, index) => {
    if (!isName(name)) throw new Error(`${where}: lockfiles[${index}] must be a file name, without a slash`);
  });
  nonEmptyList(data, "doNotTouchPhrases", where).forEach((phrase, index) => {
    nonEmptyText(phrase, `${where}: doNotTouchPhrases[${index}]`);
  });
  return data;
}

function compilePatterns(data) {
  return {
    directories: data.directories.map((item) => ({ id: item.id, folder: item.folder })),
    files: data.files.map((item) => ({ id: item.id, glob: item.glob, regex: new RegExp(item.regex) })),
    lockfiles: new Set(data.lockfiles.map((name) => name.toLowerCase())),
    phrases: data.doNotTouchPhrases.map(normalizeText),
  };
}

function nonEmptyList(data, key, where) {
  if (!Array.isArray(data[key]) || data[key].length === 0) throw new Error(`${where}: ${key} must be a non-empty list`);
  return data[key];
}

function checkFields(item, allowed, entry) {
  if (!isPlainObject(item)) throw new Error(`${entry} is not an object`);
  for (const key of Object.keys(item)) {
    if (!allowed.has(key)) throw new Error(`${entry} has the unknown field "${key}"`);
  }
}

function nonEmptyText(value, entry) {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${entry} must be a non-empty string`);
}

function isName(value) {
  return typeof value === "string" && value !== "" && !value.includes("/");
}

function compileRegex(source, entry) {
  nonEmptyText(source, entry);
  try {
    return new RegExp(source);
  } catch (error) {
    throw new Error(`${entry} is not a valid regular expression: ${error.message}`, { cause: error });
  }
}

// ---------------------------------------------------------------------------------------------------
// Helpers

// Lowercase, with curly apostrophes read as straight ones, so that a phrase matches either spelling.
function normalizeText(text) {
  return text.replaceAll("’", "'").toLowerCase();
}

function baseName(relPath) {
  return relPath.slice(relPath.lastIndexOf("/") + 1);
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const byPath = (a, b) => compareText(a.path, b.path);

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
