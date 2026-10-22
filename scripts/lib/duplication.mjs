// Measure "duplication": blocks of code that repeat, between files or inside one file. It is the only module that reads
// the source code of the target, and it reads that code as data: nothing in a file is run, followed or copied into the
// output. The output holds paths, line numbers and counts, never code text.
//
// Candidates. The files of ctx.files with an extension in CODE_EXTENSIONS, that are not generated (generatedPatternOf
// from structure.mjs; they are left out without a warning, because the structure measure lists them) and whose name does
// not look minified (a warning). A test file (isTestPath) is counted apart, in inTests, and never enters the main numbers.
// With a scope (ctx.scope), only the files inside the scope folders are candidates: the scope filter runs before the caps,
// so a file outside the scope is not read and is in no warning.
// Caps apply in this order: non-test files by path, then test files by path. A file above MAX_FILE_BYTES is skipped
// before it is read, using the size from ctx.files. Files beyond MAX_FILES and files beyond MAX_TOTAL_BYTES are skipped,
// and each cap writes one warning with the count. A file that is read and has a line longer than MINIFIED_LINE_CHARS is
// skipped as minified. Every read that fails is skipped with a warning that carries the safe-fs reason.
//
// Normalization (normalizeLines). Each line is trimmed, and its original line number is kept. These lines are dropped:
// - empty lines;
// - comments: lines that start with "//"; lines that start with "#" in a language where "#" starts a comment
//   (HASH_COMMENT_EXTENSIONS: Python, shell, PowerShell, Ruby, Elixir, PHP); "#!" on the first line of any file; lines
//   that start with "/*" (or "<!--") and either have no closing mark ("*/", "-->") or hold nothing but comments once every
//   complete comment on the line is removed; lines that start with "*" followed by a space, a "/" or nothing (the body
//   and the closing line of a JSDoc block);
// - imports: import statements, export ... from, from ... import (Python), require calls (with or without a const
//   assignment), using and use statements (C#, Rust, PHP), and #include and #import;
// - punctuation-only lines, made only of braces, brackets, parentheses, semicolons and commas (such as "}" or "});").
// So "#count = 0;" is code in a JavaScript file, "*p = 1;" is code, and "/* x */ total = total + 1; /* y */" is kept.
// Python docstrings and multi-line strings are code. Trailing comments stay in the line text and must match between copies.
//
// Detection. Every run of windowLines consecutive normalized lines is a window, keyed by the SHA-1 of its lines joined
// with "\n". The occurrences of a key are kept in (file, index) order; inside one file an occurrence that overlaps the
// previous kept one (an index difference below windowLines) is dropped. A key with at least two kept occurrences is
// duplicated. Each duplicated key is processed once, from its first kept occurrence, unless the window before that
// occurrence is a copy of the same block (its kept list, shifted by one, is this key's kept list): then the block was
// found from an earlier window. A block starts with the copies of the key and extends to the left and to the right while
// every copy keeps the key of the first copy at each offset. Copies of one file never overlap, so the block length stays
// at most the gap between two consecutive copies of the same file. Blocks with the same copies are one candidate.
//
// Groups. The candidates are sorted by redundantLines (most first), then by the file and line of the first copy. A
// candidate is listed, and counted in groupCount, only when it has a redundant line that no listed group before it
// already counts. This drops the rotations of a repeating cycle and a block whose copies a larger group already marks.
//
// Metric. For a group, lines is the normalized line count of the block. redundantLines of the group is lines multiplied
// by (copies - 1): every copy except the first one (by file, then by line). The redundantLines of the whole scan counts
// each normalized line once over all candidates. duplicatedLinesPct is that number divided by the normalized lines
// scanned, times 100, rounded to two decimals; it is 0 when nothing was scanned. With a scope, the share is over the
// files inside the scope, and a copy outside it is not seen.
//
// Known limits. The lines inside a multi-line block comment are kept as code unless they start with "*", so the closing
// text of such a comment is measured. HTML and CSS are not measured (not in CODE_EXTENSIONS). Two groups can share lines of
// one copy when the copy sets differ: a window that a third file also has is a group of its own, and redundantLines still
// counts each line once.

import crypto from "node:crypto";
import path from "node:path";
import { filesInScope, generatedPatternOf, loadGeneratedPatterns } from "./structure.mjs";

export const MEASURE_ID = "duplication";

// Provisional, not calibrated on real repositories: the length, in normalized lines, of the windows that make a block.
export const WINDOW_LINES = 8;
// Provisional: how many groups the output lists, the ones with the most redundant lines.
export const MAX_GROUPS = 20;
// Provisional: how many code files are read in one scan, main and test files together.
export const MAX_FILES = 2000;
// Provisional: the size above which a code file is skipped before it is read, in bytes.
export const MAX_FILE_BYTES = 256 * 1024;
// Provisional: the total size of the code files that are read in one scan, in bytes.
export const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
// Provisional: a file with a line longer than this, in characters, is treated as minified and skipped.
export const MINIFIED_LINE_CHARS = 1000;
// The deep caps (--depth deep). They are raised so that more of a large repository is measured. They bound the files and
// bytes that one scan reads; the memory use of a deep scan was not measured. windowLines and MINIFIED_LINE_CHARS are the
// same in deep. Provisional, not calibrated on real repositories.
export const MAX_GROUPS_DEEP = 50;
export const MAX_FILES_DEEP = 6000;
export const MAX_FILE_BYTES_DEEP = 512 * 1024;
export const MAX_TOTAL_BYTES_DEEP = 96 * 1024 * 1024;
/** The settings that --depth deep passes to createDuplicationMeasure. The other settings keep their defaults. */
export const DEEP_DUPLICATION_OPTIONS = Object.freeze({
  maxGroups: MAX_GROUPS_DEEP,
  maxFiles: MAX_FILES_DEEP,
  maxFileBytes: MAX_FILE_BYTES_DEEP,
  maxTotalBytes: MAX_TOTAL_BYTES_DEEP,
});
// Provisional list of extensions (lowercase, with the dot) of source code. Data formats (JSON, YAML, TOML, XML, CSV),
// Markdown and the markup and style languages are left out on purpose.
export const CODE_EXTENSIONS = Object.freeze([
  // JavaScript and TypeScript family
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
  // Single-file components
  ".vue", ".svelte", ".astro",
  // Python
  ".py",
  // Go, Rust, Java, Kotlin, Scala
  ".go", ".rs", ".java", ".kt", ".kts", ".scala",
  // C and C++
  ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx",
  // C#, Ruby, PHP, Swift, Dart, Elixir
  ".cs", ".rb", ".php", ".swift", ".dart", ".ex", ".exs",
  // Shell and PowerShell
  ".sh", ".bash", ".zsh", ".ps1", ".psm1",
]);
// Provisional list of the extensions in which "#" starts a comment. In the other languages a line that starts with "#"
// is code, such as a JavaScript private member ("#count = 0;") or a C directive.
export const HASH_COMMENT_EXTENSIONS = Object.freeze([".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".rb", ".ex", ".exs", ".php"]);

const DEFAULT_SETTINGS = Object.freeze({
  windowLines: WINDOW_LINES,
  maxGroups: MAX_GROUPS,
  maxFiles: MAX_FILES,
  maxFileBytes: MAX_FILE_BYTES,
  maxTotalBytes: MAX_TOTAL_BYTES,
  minifiedLineChars: MINIFIED_LINE_CHARS,
  codeExtensions: CODE_EXTENSIONS,
});
const POSITIVE_SETTINGS = ["windowLines", "maxGroups", "maxFiles", "maxFileBytes", "maxTotalBytes", "minifiedLineChars"];

// A file is a test file when one of its folders has one of these names, or its base name matches one of TEST_NAMES.
const TEST_FOLDERS = new Set(["test", "tests", "__tests__", "spec", "e2e", "__mocks__", "fixtures"]);
const TEST_NAMES = [/\.(?:test|spec)(?:\.[^.]+)+$/i, /_test\.[^.]+$/i, /^test_.+\.py$/i];
// Base names that look minified without matching the generated patterns, such as app.min.ts or app-min.js.
const MINIFIED_NAME = /[.-]min\.[a-z0-9]+$/i;

// Import-like lines, matched on the trimmed text.
const IMPORT_LINES = [
  /^import[\s{*'"]/,
  /^export\b.*\bfrom\s*['"]/,
  /^from\s+\S+\s+import\s/,
  /^(?:(?:const|let|var)\b.*=\s*)?require(?:_relative)?\s*(?:\(|['"])/,
  /^(?:using|use)\s+[^;(]+;$/,
  /^#\s*(?:include|import)\b/,
];
// A line that starts with "*" and then a space, a "/" or nothing: the body or the closing line of a block comment.
const STAR_COMMENT = /^\*(?:\s|\/|$)/;
const PUNCTUATION_ONLY = /^[{}()[\];,]+$/;
// Block comments that a line may start with: the opening mark, the closing mark, and the complete comments on the line.
const C_BLOCK_COMMENT = { open: "/*", close: "*/", complete: /\/\*.*?\*\//g };
const MARKUP_COMMENT = { open: "<!--", close: "-->", complete: /<!--.*?-->/g };
// The byte order mark, as a UTF-16 code unit. A file that starts with it has it removed before the lines are split.
const BYTE_ORDER_MARK = 0xfeff;

export const duplicationMeasure = createDuplicationMeasure();

/**
 * Builds the duplication measure. The defaults are the constants of this module; the options override them (tests use
 * small values so that the caps are reached with small files).
 * @param {object} [options]
 * @param {number} [options.windowLines] Length of a window, in normalized lines. Default WINDOW_LINES.
 * @param {number} [options.maxGroups] Groups listed in the output. Default MAX_GROUPS.
 * @param {number} [options.maxFiles] Code files read per scan. Default MAX_FILES.
 * @param {number} [options.maxFileBytes] Largest code file read, in bytes. Default MAX_FILE_BYTES.
 * @param {number} [options.maxTotalBytes] Bytes of code read per scan. Default MAX_TOTAL_BYTES.
 * @param {number} [options.minifiedLineChars] Longest line allowed in a file. Default MINIFIED_LINE_CHARS.
 * @param {string[]} [options.codeExtensions] Extensions treated as code, such as ".js". Default CODE_EXTENSIONS.
 * @returns {{ id: string, collect: (ctx: object) => object }}
 * @throws {TypeError} For an unknown option or a value of the wrong kind.
 */
export function createDuplicationMeasure(options = {}) {
  const settings = readSettings(options);
  return Object.freeze({ id: MEASURE_ID, collect: (ctx) => collectDuplication(ctx, settings) });
}

/**
 * Whether a path belongs to the test files: a folder with a test name, or a base name that matches TEST_NAMES.
 * @param {string} relPath POSIX path relative to the target.
 * @returns {boolean}
 */
export function isTestPath(relPath) {
  const segments = relPath.split("/");
  const name = segments.pop();
  return segments.some((segment) => TEST_FOLDERS.has(segment.toLowerCase())) || TEST_NAMES.some((pattern) => pattern.test(name));
}

/**
 * The normalized lines of a file text, with their original 1-based numbers. The rules are in the header comment.
 * @param {string} text The file text, as safe-fs returns it.
 * @param {string} [extension] The extension of the file, with the dot, such as ".py". It decides whether "#" is a comment.
 * @returns {Array<{ number: number, text: string }>}
 */
export function normalizeLines(text, extension = "") {
  const hashIsComment = HASH_COMMENT_EXTENSIONS.includes(extension.toLowerCase());
  const body = text.charCodeAt(0) === BYTE_ORDER_MARK ? text.slice(1) : text;
  const lines = [];
  body.split(/\r?\n/).forEach((raw, index) => {
    const trimmed = raw.trim();
    if (!isDroppedLine(trimmed, index === 0, hashIsComment)) lines.push({ number: index + 1, text: trimmed });
  });
  return lines;
}

function readSettings(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("createDuplicationMeasure expects an options object");
  }
  for (const key of Object.keys(options)) {
    if (!Object.hasOwn(DEFAULT_SETTINGS, key)) throw new TypeError(`Unknown duplication option: "${key}"`);
  }
  const settings = { ...DEFAULT_SETTINGS, ...options };
  for (const key of POSITIVE_SETTINGS) {
    if (!Number.isSafeInteger(settings[key]) || settings[key] < 1) {
      throw new TypeError(`Duplication option "${key}" must be a positive integer`);
    }
  }
  const { codeExtensions } = settings;
  const validExtension = (ext) => typeof ext === "string" && /^\.[a-z0-9]+$/i.test(ext);
  if (!Array.isArray(codeExtensions) || !codeExtensions.every(validExtension)) {
    throw new TypeError('Duplication option "codeExtensions" must be a list of extensions such as ".js"');
  }
  return { ...settings, codeExtensions: codeExtensions.map((ext) => ext.toLowerCase()) };
}

// Reads the target only through ctx: ctx.files for the list and sizes, ctx.readText for the content.
function collectDuplication(ctx, settings) {
  const warnings = [];
  const candidates = selectCandidates(filesInScope(ctx.files, ctx.scope), settings, warnings);
  const files = readCandidates(ctx, candidates, settings, warnings);
  const main = analyse(files.filter((file) => !file.inTests), settings);
  const tests = analyse(files.filter((file) => file.inTests), settings);
  return { code: { duplication: { windowLines: settings.windowLines, ...main, inTests: tests } }, warnings };
}

// The candidates in the order of the caps: non-test files by path, then test files by path. No file is read here.
function selectCandidates(files, settings, warnings) {
  const patterns = loadGeneratedPatterns();
  const main = [];
  const tests = [];
  for (const file of [...files].sort(byPath)) {
    if (!settings.codeExtensions.includes(path.posix.extname(file.path).toLowerCase())) continue;
    if (generatedPatternOf(file.path, patterns) !== null) continue;
    if (MINIFIED_NAME.test(path.posix.basename(file.path))) {
      warnings.push(warning(file.path, "code-file-minified"));
      continue;
    }
    const inTests = isTestPath(file.path);
    (inTests ? tests : main).push({ path: file.path, bytes: file.bytes, inTests });
  }
  return [...main, ...tests];
}

// Reads the candidates in order and applies the caps. A file counts toward the file and byte caps when it is read.
function readCandidates(ctx, candidates, settings, warnings) {
  const files = [];
  let filesRead = 0;
  let bytesRead = 0;
  let filesCut = 0;
  let bytesCut = 0;
  for (const candidate of candidates) {
    if (candidate.bytes > settings.maxFileBytes) {
      warnings.push(warning(candidate.path, "code-file-too-large"));
      continue;
    }
    if (filesRead >= settings.maxFiles) {
      filesCut += 1;
      continue;
    }
    if (bytesRead + candidate.bytes > settings.maxTotalBytes) {
      bytesCut += 1;
      continue;
    }
    filesRead += 1;
    bytesRead += candidate.bytes;
    const read = ctx.readText(candidate.path, { maxBytes: settings.maxFileBytes });
    if (!read.ok) {
      warnings.push(warning(candidate.path, "code-file-unreadable", read.reason));
      continue;
    }
    if (longestLine(read.text) > settings.minifiedLineChars) {
      warnings.push(warning(candidate.path, "code-file-minified"));
      continue;
    }
    const lines = normalizeLines(read.text, path.posix.extname(candidate.path));
    files.push({ path: candidate.path, inTests: candidate.inTests, lines });
  }
  if (filesCut > 0) warnings.push({ path: ".", reason: "code-files-cut", detail: `count=${filesCut}` });
  if (bytesCut > 0) warnings.push({ path: ".", reason: "code-bytes-cut", detail: `count=${bytesCut}` });
  return files;
}

// Detection over one set of files (the main files or the test files). The files come sorted by path.
function analyse(files, settings) {
  const width = settings.windowLines;
  const keysByFile = files.map((file) => windowKeys(file.lines, width));
  const occurrences = groupOccurrences(keysByFile);

  // Duplicated keys, with their kept occurrences in (file, index) order.
  const kept = new Map();
  for (const [key, list] of occurrences) {
    if (list.length < 2) continue;
    const keep = keptOccurrences(list, width);
    if (keep.length >= 2) kept.set(key, keep);
  }

  // Every duplicated key is processed once, at its first kept occurrence. Scanning the windows in (file, index) order
  // reaches that occurrence first.
  const blocks = new Map();
  keysByFile.forEach((keys, file) => {
    keys.forEach((key, at) => {
      const list = kept.get(key);
      if (list === undefined || list[0].file !== file || list[0].at !== at) return;
      if (at > 0 && shiftedBy(kept.get(keys[at - 1]), list)) return;
      const { left, right } = extendBlock(list, keysByFile, width);
      const span = left + right + width;
      const copies = list.map((occurrence) => copyAt(files, occurrence, left, span));
      const signature = `${span}|${copies.map((copy) => `${copy.index}:${copy.first}`).join(",")}`;
      if (!blocks.has(signature)) blocks.set(signature, { signature, copies });
    });
  });

  const candidates = [...blocks.values()]
    .map(({ signature, copies }) => {
      const lines = copies[0].last - copies[0].first + 1;
      return { signature, copies, lines, redundantLines: (copies.length - 1) * lines };
    })
    .sort(compareCandidates);

  // A candidate is listed when it marks a redundant line that no listed group before it marks.
  const counted = new Set();
  const allRedundant = new Set();
  const listed = [];
  for (const candidate of candidates) {
    const marks = redundantMarks(candidate.copies);
    for (const mark of marks) allRedundant.add(mark);
    if (marks.some((mark) => !counted.has(mark))) {
      for (const mark of marks) counted.add(mark);
      listed.push(candidate);
    }
  }

  const linesScanned = files.reduce((sum, file) => sum + file.lines.length, 0);
  const redundantLines = allRedundant.size;
  return {
    filesScanned: files.length,
    linesScanned,
    redundantLines,
    duplicatedLinesPct: linesScanned === 0 ? 0 : Math.round((redundantLines / linesScanned) * 10000) / 100,
    groupCount: listed.length,
    groups: listed.slice(0, settings.maxGroups).map(({ lines, redundantLines: marked, copies }) => ({
      lines,
      redundantLines: marked,
      copies: copies.map(({ file, line, endLine }) => ({ file, line, endLine })),
    })),
  };
}

// How far a block extends from its key, in windows: `left` windows before the first kept occurrence and `right` after it.
// At each offset every copy must have a window with the key of the first copy's window at that offset. The block length
// (left + right + width) must stay at most the gap between two consecutive copies of the same file, so copies never overlap.
function extendBlock(list, keysByFile, width) {
  const [first] = list;
  const firstKeys = keysByFile[first.file];
  const limit = minimumGap(list);
  const sameKeyAt = (offset) => {
    const key = firstKeys[first.at + offset];
    return list.every(({ file, at }) => {
      const keys = keysByFile[file];
      const index = at + offset;
      return index >= 0 && index < keys.length && keys[index] === key;
    });
  };
  let left = 0;
  let right = 0;
  for (;;) {
    let grew = false;
    if (left + right + width < limit && sameKeyAt(right + 1)) {
      right += 1;
      grew = true;
    }
    if (left + right + width < limit && sameKeyAt(-(left + 1))) {
      left += 1;
      grew = true;
    }
    if (!grew) return { left, right };
  }
}

// The smallest distance between two consecutive copies of one file, or Infinity when no file has two copies. The list is
// in (file, index) order, so the copies of one file are next to each other.
function minimumGap(list) {
  let gap = Infinity;
  for (let n = 1; n < list.length; n += 1) {
    if (list[n].file === list[n - 1].file) gap = Math.min(gap, list[n].at - list[n - 1].at);
  }
  return gap;
}

// One copy of a block: the file index, the first and last normalized line index, and the original line numbers.
function copyAt(files, { file, at }, left, span) {
  const { path: filePath, lines } = files[file];
  const first = at - left;
  const last = first + span - 1;
  return { index: file, first, last, file: filePath, line: lines[first].number, endLine: lines[last].number };
}

// The redundant normalized lines of a block: every line of every copy except the first copy, as "file index:line index".
function redundantMarks(copies) {
  const marks = [];
  for (const copy of copies.slice(1)) {
    for (let number = copy.first; number <= copy.last; number += 1) marks.push(`${copy.index}:${number}`);
  }
  return marks;
}

// Candidates with the most redundant lines first, then by the file and line of the first copy.
function compareCandidates(a, b) {
  return (
    b.redundantLines - a.redundantLines ||
    compareText(a.copies[0].file, b.copies[0].file) ||
    a.copies[0].line - b.copies[0].line ||
    a.lines - b.lines ||
    compareText(a.signature, b.signature)
  );
}

// The SHA-1 of every window of a file, in window order. A file shorter than the window has no keys.
function windowKeys(lines, width) {
  const keys = [];
  for (let at = 0; at + width <= lines.length; at += 1) {
    const text = lines
      .slice(at, at + width)
      .map((line) => line.text)
      .join("\n");
    keys.push(crypto.createHash("sha1").update(text).digest("hex"));
  }
  return keys;
}

// Key -> every occurrence as { file, at }, in (file, index) order.
function groupOccurrences(keysByFile) {
  const occurrences = new Map();
  keysByFile.forEach((keys, file) => {
    keys.forEach((key, at) => {
      const list = occurrences.get(key);
      if (list === undefined) occurrences.set(key, [{ file, at }]);
      else list.push({ file, at });
    });
  });
  return occurrences;
}

// The occurrences that are kept: an occurrence that overlaps the previously kept one of the same file is dropped.
function keptOccurrences(list, width) {
  const keep = [];
  for (const occurrence of list) {
    const last = keep.at(-1);
    if (last !== undefined && last.file === occurrence.file && occurrence.at - last.at < width) continue;
    keep.push(occurrence);
  }
  return keep;
}

// True when the second list is the first one with every index moved by one. Both lists are in (file, index) order.
function shiftedBy(current, following) {
  if (current === undefined || following === undefined || current.length !== following.length) return false;
  return current.every((occurrence, n) => occurrence.file === following[n].file && occurrence.at + 1 === following[n].at);
}

// True when a line of normalized text is left out of the normalized lines.
function isDroppedLine(text, isFirstLine, hashIsComment) {
  if (text === "" || text.startsWith("//") || isHashComment(text, isFirstLine, hashIsComment)) return true;
  if (STAR_COMMENT.test(text) || isBlockCommentOnly(text, C_BLOCK_COMMENT) || isBlockCommentOnly(text, MARKUP_COMMENT)) {
    return true;
  }
  return IMPORT_LINES.some((pattern) => pattern.test(text)) || PUNCTUATION_ONLY.test(text);
}

// "#!" on the first line is a comment in any file. "#" starts a comment only in the languages that have one; in the
// others "#include" and "#import" are imports (see IMPORT_LINES) and every other "#" line is code.
function isHashComment(text, isFirstLine, hashIsComment) {
  if (!text.startsWith("#")) return false;
  if (isFirstLine && text.startsWith("#!")) return true;
  return hashIsComment;
}

// A line that starts with the opening mark of a block comment, and that has no closing mark or nothing but comments.
function isBlockCommentOnly(text, comment) {
  if (!text.startsWith(comment.open)) return false;
  if (!text.includes(comment.close)) return true;
  return text.replace(comment.complete, "").trim() === "";
}

function longestLine(text) {
  let longest = 0;
  for (const line of text.split(/\r?\n/)) longest = Math.max(longest, line.length);
  return longest;
}

// A warning with a fixed reason. The detail is added only when it is given.
function warning(filePath, reason, detail) {
  return detail === undefined ? { path: filePath, reason } : { path: filePath, reason, detail };
}

const byPath = (a, b) => compareText(a.path, b.path);

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
