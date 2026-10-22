// Measure "injection": text in the target that is aimed at a coding agent, as data/injection-patterns.json describes it (see
// injection-patterns.mjs). Each match is a candidate of SEC-06: the agent confirms it in context, because a match can be a
// legitimate sentence. The target is read only through ctx.fs; nothing from it is run, followed or parsed as code.
//
// Files. Two groups, in this order, each sorted by path:
// - instruction files (fileKind "instructions"): the candidates of the agent-harness measure that an entry of a context kind
//   owns (contextFilesOf: the instruction files of every agent, skills, commands and subagents, nested ones included) and the
//   files of ctx.memory (the memory files, rules and imports that Claude Code reads);
// - Markdown files (fileKind "markdown"): the other files of ctx.files whose name ends in .md, in any letter case.
// With a scope (ctx.scope), a file of the agent-harness measure is kept when ctx.scope.keepsHarness keeps it, and a Markdown
// file when it lies inside a scope folder. The files of ctx.memory are always kept: the memory measure has already applied the
// scope to them, and an import of a root memory file loads wherever the agent works. A file whose name is a secret name
// (secretFileKind) is skipped without a read and without a warning.
//
// Reading. A file whose text ctx.memory or ctx.agentInstructions already holds is not read again, and it is not charged to
// the byte cap. Any other file is stat-ed and read with ctx.fs.readText. At most maxFiles files are scanned; a file above
// maxFileBytes is skipped with the warning injection-file-too-large; a file that would take the bytes read past maxTotalBytes
// is skipped. The two caps write injection-files-cut and injection-bytes-cut with the count. A read that fails leaves the
// usual fs warning.
//
// Matching. Every line of a file is matched (matchLine), fenced code blocks included, except the html-comment patterns: they
// apply only to the lines of an instruction file that lie outside a fenced code block, since a rendered Markdown file shows
// the text of a fenced block. A line gives at most one match per pattern. At most maxMatchesPerFile matches of one file are
// kept, in line order (injection-file-matches-cut on the file counts the rest), and at most maxMatches in all, in scan order
// (injection-matches-cut counts the rest).
//
// Excerpt. Each kept match carries an excerpt of its line, at most MAX_EXCERPT_CHARS characters. The whole line is redacted
// first (redact.mjs: the target and home folders, and token-shaped secrets; a password in a plain assignment is not masked),
// a token that a hidden code point splits is masked as well (unsplitSecrets), and the match is found again in that text. The
// excerpt starts at the line start, or a few characters before a match that lies further on, measured in the width that the
// excerpt gives each code point (see EXCERPT_TAIL). Every control, format, separator, surrogate, private-use, unassigned or
// default-ignorable code point is written as U+XXXX, so an invisible character never reaches the output, and a tab becomes a
// space. An ellipsis (U+2026) marks text cut at either end. Each line is prepared once, however many of its matches are kept.
// The file name is copied as it is, as the other measures copy paths.
//
// Known limit: the fence walk does not follow HTML comments, so a fence line inside a multi-line comment is read as a fence.
//
// Output. security.injection, only when there is at least one match: filesScanned and matches, sorted by file, line,
// category and patternId. Without a match the measure writes no section, so the rest of measurements.json does not change.

import { contextFilesOf } from "./agent-inventory.mjs";
import { loadInjectionPatterns, matchLine } from "./injection-patterns.mjs";
import { closesFence, opensFence } from "./markdown.mjs";
import { createRedactor } from "./redact.mjs";
import { secretFileKind } from "./secret-patterns.mjs";

export const MEASURE_ID = "injection";

// Provisional caps, not calibrated on real repositories. The file and byte caps follow duplication.mjs; the per-file cap is
// four times its size cap, because an instruction file may be long and is read in full by an agent.
export const MAX_FILES = 2000;
export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
// Provisional: the matches kept in one scan, and in one file, so that one noisy file does not hide the others.
export const MAX_MATCHES = 100;
export const MAX_MATCHES_PER_FILE = 10;
/** The longest excerpt, in characters. */
export const MAX_EXCERPT_CHARS = 120;
// The excerpt starts at the line start when the match begins in the first MAX_EXCERPT_CHARS - EXCERPT_TAIL characters, so at
// least EXCERPT_TAIL characters of the match and what follows it are shown. Otherwise it starts EXCERPT_LEAD characters before
// the match.
const EXCERPT_TAIL = 40;
const EXCERPT_LEAD = 20;
const ELLIPSIS = "\u2026";
const MARKDOWN_NAME = /\.md$/i;
// The code points that an excerpt writes as U+XXXX: controls, format characters, line and paragraph separators, surrogates,
// private use, unassigned and default-ignorable code points (variation selectors, Hangul fillers and the like).
const HIDDEN = /^[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Co}\p{Cn}\p{Default_Ignorable_Code_Point}]$/u;

/**
 * Builds the injection measure.
 * @param {object} [options] Each cap is a non-negative safe integer; see the header.
 * @param {number} [options.maxFiles]
 * @param {number} [options.maxFileBytes]
 * @param {number} [options.maxTotalBytes]
 * @param {number} [options.maxMatches]
 * @param {number} [options.maxMatchesPerFile]
 * @returns {{ id: string, collect: (ctx: object) => object }}
 */
export function createInjectionMeasure({
  maxFiles = MAX_FILES,
  maxFileBytes = MAX_FILE_BYTES,
  maxTotalBytes = MAX_TOTAL_BYTES,
  maxMatches = MAX_MATCHES,
  maxMatchesPerFile = MAX_MATCHES_PER_FILE,
} = {}) {
  const settings = { maxFiles, maxFileBytes, maxTotalBytes, maxMatches, maxMatchesPerFile };
  for (const [name, value] of Object.entries(settings)) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative safe integer`);
  }
  return Object.freeze({ id: MEASURE_ID, collect: (ctx) => collectInjection(ctx, settings) });
}

function collectInjection(ctx, settings) {
  const patterns = loadInjectionPatterns();
  const warnings = [];
  const texts = readFiles(ctx, selectFiles(ctx), settings, warnings);
  const found = [];
  for (const file of texts) {
    const matches = matchFile(patterns, file);
    if (matches.length > settings.maxMatchesPerFile) {
      const cut = matches.length - settings.maxMatchesPerFile;
      warnings.push({ path: file.path, reason: "injection-file-matches-cut", detail: `count=${cut}` });
    }
    found.push(...matches.slice(0, settings.maxMatchesPerFile));
  }
  if (found.length > settings.maxMatches) {
    warnings.push({ path: ".", reason: "injection-matches-cut", detail: `count=${found.length - settings.maxMatches}` });
  }
  const kept = found.slice(0, settings.maxMatches).sort(compareMatches);
  if (kept.length === 0) return { warnings };
  const redact = createRedactor({ root: ctx.root });
  // Each line is redacted and matched again once, however many of its matches are kept.
  const prepared = new Map();
  const preparedLine = (match) => {
    const key = `${match.line}:${match.file}`;
    if (!prepared.has(key)) prepared.set(key, prepareLine(patterns, match.text, redact));
    return prepared.get(key);
  };
  const matches = kept.map((match) => ({
    file: match.file,
    line: match.line,
    category: match.category,
    patternId: match.patternId,
    fileKind: match.fileKind,
    excerpt: excerptOf(preparedLine(match), match.patternId),
  }));
  return { security: { injection: { filesScanned: texts.length, matches } }, warnings };
}

// The files to scan, instruction files first, each group sorted by path. No file is read here.
function selectFiles(ctx) {
  const scope = ctx.scope;
  const harness = [...contextFilesOf(ctx)].filter((rel) => scope === null || scope.keepsHarness(rel));
  const instructionPaths = new Set([...harness, ...ctx.memory.keys()]);
  const instructions = [...instructionPaths]
    .sort(compareText)
    .map((rel) => ({ path: rel, fileKind: "instructions" }));
  const markdown = ctx.files
    .filter((file) => MARKDOWN_NAME.test(file.path) && !instructionPaths.has(file.path))
    .filter((file) => scope === null || scope.contains(file.path))
    .map((file) => file.path)
    .sort(compareText)
    .map((rel) => ({ path: rel, fileKind: "markdown" }));
  return [...instructions, ...markdown].filter((file) => secretFileKind(file.path) === null);
}

// The texts of the files, in order, within the caps.
function readFiles(ctx, files, settings, warnings) {
  const texts = [];
  let bytesRead = 0;
  let filesCut = 0;
  let bytesCut = 0;
  for (const file of files) {
    if (texts.length >= settings.maxFiles) {
      filesCut += 1;
      continue;
    }
    const known = ctx.memory.get(file.path)?.text ?? ctx.agentInstructions.get(file.path)?.text;
    if (typeof known === "string") {
      texts.push({ ...file, text: known });
      continue;
    }
    const entry = ctx.fs.stat(file.path);
    if (!entry.ok || entry.type !== "file") continue;
    if (entry.bytes > settings.maxFileBytes) {
      warnings.push({ path: file.path, reason: "injection-file-too-large" });
      continue;
    }
    if (bytesRead + entry.bytes > settings.maxTotalBytes) {
      bytesCut += 1;
      continue;
    }
    bytesRead += entry.bytes;
    const read = ctx.fs.readText(file.path, { maxBytes: settings.maxFileBytes });
    if (read.ok) texts.push({ ...file, text: read.text });
  }
  if (filesCut > 0) warnings.push({ path: ".", reason: "injection-files-cut", detail: `count=${filesCut}` });
  if (bytesCut > 0) warnings.push({ path: ".", reason: "injection-bytes-cut", detail: `count=${bytesCut}` });
  return texts;
}

// The matches of one file, in line order. The html-comment patterns apply to the lines of an instruction file outside a fence.
function matchFile(patterns, file) {
  const matches = [];
  const instructions = file.fileKind === "instructions";
  let fence = null;
  file.text.split("\n").forEach((text, index) => {
    let fenced = fence !== null;
    if (instructions) {
      if (fence !== null) {
        if (closesFence(text, fence)) fence = null;
      } else {
        fence = opensFence(text);
        fenced = fence !== null;
      }
    }
    for (const match of matchLine(patterns, text, { comments: instructions && !fenced })) {
      matches.push({ ...match, file: file.path, fileKind: file.fileKind, line: index + 1, text });
    }
  });
  return matches;
}

// A line ready for its excerpts: redacted, with the secrets that hidden code points split masked too (unsplitSecrets), and the
// index of each pattern in that text.
function prepareLine(patterns, line, redact) {
  const text = unsplitSecrets(redact(line), redact);
  const indexes = new Map(matchLine(patterns, text, { comments: true }).map((match) => [match.patternId, match.index]));
  return { text, indexes };
}

// A run of non-space characters that holds a hidden code point is redacted again without its hidden code points, so a token
// that a zero-width space splits is still masked. When that changes the run, the run becomes the masked text followed by its
// hidden code points (which visibleExcerpt then writes as U+XXXX); otherwise it stays as it is. Each run is read once.
function unsplitSecrets(text, redact) {
  let out = "";
  let index = 0;
  while (index < text.length) {
    let end = index;
    while (end < text.length && !isSpace(text[end])) end += 1;
    out += end > index ? unsplitRun(text.slice(index, end), redact) : "";
    let next = end;
    while (next < text.length && isSpace(text[next])) next += 1;
    out += text.slice(end, next);
    index = next;
  }
  return out;
}

function unsplitRun(run, redact) {
  if (isPrintableAscii(run)) return run;
  let visible = "";
  let hidden = "";
  for (const char of run) {
    if (HIDDEN.test(char)) hidden += char;
    else visible += char;
  }
  if (hidden === "") return run;
  const masked = redact(visible);
  return masked === visible ? run : `${masked}${hidden}`;
}

function isPrintableAscii(run) {
  for (let index = 0; index < run.length; index += 1) {
    const unit = run.charCodeAt(index);
    if (unit < 0x20 || unit > 0x7e) return false;
  }
  return true;
}

function isSpace(char) {
  return char === " " || char === "\t";
}

// The excerpt of one match: from the line start, or from a little before the match, measured in the width that the excerpt
// gives each code point (six for a U+XXXX piece), so hidden code points before the match cannot push it out of the excerpt.
function excerptOf(line, patternId) {
  const { text } = line;
  const index = line.indexes.get(patternId) ?? 0;
  // Walk back from the match while the width stays within the excerpt; stop at the line start, or note where the lead ends.
  let width = 0;
  let start = index;
  let leadStart = index;
  while (start > 0 && width <= MAX_EXCERPT_CHARS - EXCERPT_TAIL) {
    const before = isLowSurrogate(text.charCodeAt(start - 1)) && start > 1 && isHighSurrogate(text.charCodeAt(start - 2)) ? 2 : 1;
    start -= before;
    width += pieceOf(text.codePointAt(start)).length;
    if (width <= EXCERPT_LEAD) leadStart = start;
  }
  if (start > 0 || width > MAX_EXCERPT_CHARS - EXCERPT_TAIL) {
    start = leadStart;
    // Start after a space when one lies between the start and the match, so the excerpt does not open inside a word.
    for (let at = start; at < index; at += 1) {
      if (text[at] === " ") {
        start = at + 1;
        break;
      }
    }
  }
  while (start < text.length && isSpace(text[start])) start += 1;
  return visibleExcerpt(text, start);
}

// How the excerpt writes one code point.
function pieceOf(code) {
  if (code === 0x09) return " ";
  const char = String.fromCodePoint(code);
  return HIDDEN.test(char) ? `U+${code.toString(16).toUpperCase().padStart(4, "0")}` : char;
}

/**
 * The text from start, with hidden code points written as U+XXXX and tabs as spaces, cut to MAX_EXCERPT_CHARS characters.
 * An ellipsis (U+2026) marks text cut at either end, and counts toward the length.
 * @param {string} text
 * @param {number} start
 * @returns {string}
 */
export function visibleExcerpt(text, start = 0) {
  const head = start > 0 ? ELLIPSIS : "";
  let out = head;
  let index = start;
  while (index < text.length) {
    const code = text.codePointAt(index);
    const piece = pieceOf(code);
    const width = code > 0xffff ? 2 : 1;
    const rest = text.length - (index + width);
    // Room for the piece, and for the closing ellipsis when text remains after it.
    if (out.length + piece.length + (rest > 0 ? ELLIPSIS.length : 0) > MAX_EXCERPT_CHARS) return `${out.trimEnd()}${ELLIPSIS}`;
    out += piece;
    index += width;
  }
  return out.trimEnd();
}

function isHighSurrogate(unit) {
  return unit >= 0xd800 && unit <= 0xdbff;
}

function isLowSurrogate(unit) {
  return unit >= 0xdc00 && unit <= 0xdfff;
}

function compareMatches(a, b) {
  return (
    compareText(a.file, b.file) || a.line - b.line || compareText(a.category, b.category) || compareText(a.patternId, b.patternId)
  );
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/** The measure with the default caps. */
export const injectionMeasure = createInjectionMeasure();
