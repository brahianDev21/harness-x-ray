// The patterns of text aimed at a coding agent: data/injection-patterns.json, its validator, its loader and the matching of one
// line. The injection measure (injection.mjs) runs them on the target's files, and check-catalog.mjs reports the issues of the
// validator. The module imports nothing from the scanner, so the catalog check does not load the scanner through it.
//
// The file has one field, categories: a list of { id, match, patterns }. match says how the patterns of the category are
// matched, and each pattern has an id. The ids of the categories and of the patterns are kebab-case and unique in the file.
// - "phrase": each pattern has text, a phrase in folded form (see foldLine) that starts with a letter, a digit or _. A phrase
//   matches where the folded line holds it, starting at a token (a run of a-z, 0-9, _ and ', without the apostrophes at its
//   ends, which are quotes) and not followed by a letter, a digit or _. "ignore your rules" matches "Ignore   your rules." and
//   "'ignore your rules'", and not "ignore your rulesets".
// - "download-pipe": each pattern has downloaders, prefixes and shells, lists of command words. It matches a line that holds a
//   downloader with an argument after it, followed later on the line by a pipe whose command is a shell, after prefixes, flags,
//   flag arguments or assignments, up to MAX_PIPE_WORDS words: "curl -fsSL https://x | sudo -u root bash" and
//   "iwr https://x | iex". "||" is not a pipe, a downloader with nothing before the next pipe ("| curl | sh |" in a table) is
//   not a download, and a shell run with -c, -e or -m ("| python -m json.tool") does not run what it reads.
// - "html-comment": each pattern has text, matched as written. The measure checks it only in instruction files and outside
//   fenced code blocks, where a rendered Markdown file does not show it.
// - "code-point-range": each pattern has from and to, code points written U+XXXX. It matches a line that holds a code point in
//   the range. The text the scanner reads has no leading byte order mark (safe-fs drops it), so U+FEFF matches only inside.
//
// Matching takes linear time in the length of the line, and the matcher runs no regular expression on the line (folding tests
// one code point at a time). The phrases and the downloaders are looked up by their first token, in one pass over the folded
// line. The pipe check reads each pipe once.
//
// Folding (foldLine): letters become lower case, the curly apostrophes become ', every run of whitespace (U+0085 and the Unicode
// spaces included) becomes one space, and the code points of the code-point-range patterns and every default-ignorable code
// point (the soft hyphen, the joiners, the variation selectors, the Hangul fillers...) are dropped. So an invisible character
// inside a phrase does not hide it, and a character of a code-point-range pattern is still reported by its own pattern. Each
// folded character keeps the index of the character of the line it comes from.

import fs from "node:fs";
import { isPlainObject } from "./json-out.mjs";

const DATA_URL = new URL("../../data/injection-patterns.json", import.meta.url);
const DATA_FILE = "data/injection-patterns.json";
const TOP_FIELDS = ["categories"];
const CATEGORY_FIELDS = ["id", "match", "patterns"];
const PATTERN_FIELDS = Object.freeze({
  phrase: ["id", "text"],
  "download-pipe": ["id", "downloaders", "prefixes", "shells"],
  "html-comment": ["id", "text"],
  "code-point-range": ["id", "from", "to"],
});
/** The ways a category can be matched, in the order the validator lists them. */
export const MATCH_TYPES = Object.freeze(Object.keys(PATTERN_FIELDS));
const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
// A command word: lower case, starting with a letter or a digit. A downloader is matched by its first token, so it has no dot.
const COMMAND_WORD = /^[a-z0-9][a-z0-9_.-]*$/;
const DOWNLOADER_WORD = /^[a-z0-9][a-z0-9_-]*$/;
const CODE_POINT = /^U\+([0-9A-F]{4,6})$/;
const MAX_PHRASE_LENGTH = 100;
const MAX_CODE_POINT = 0x10ffff;
/** The most words read after a pipe: prefixes, flags and assignments, then the command. */
export const MAX_PIPE_WORDS = 6;
// Whitespace other than ASCII that folds to a space: no-break, Ogham, the spaces of U+2000 to U+200A, the line and paragraph
// separators, the narrow no-break space, the medium mathematical space and the ideographic space.
const WIDE_SPACES = new Set([0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]);
// Code points that have no visible form of their own (Unicode's Default_Ignorable_Code_Point): the soft hyphen, the joiners,
// the variation selectors, the Hangul fillers, the tag characters and others. Folding drops them.
const IGNORABLE = /^\p{Default_Ignorable_Code_Point}$/u;
const APOSTROPHES = new Set([0x2018, 0x2019, 0x02bc]);

let loaded = null;

/**
 * Checks the parsed data/injection-patterns.json. It reports every problem it finds and never throws on bad data.
 * @param {unknown} data The parsed file.
 * @returns {{ pointer: string, message: string }[]} pointer is a JSON pointer, and "" is the whole document. Empty for a valid
 *   file.
 */
export function validateInjectionPatterns(data) {
  const issues = [];
  const report = (pointer, message) => issues.push({ pointer, message });
  if (!isPlainObject(data)) {
    report("", "must be an object with the field categories");
    return issues;
  }
  unknownFields(data, TOP_FIELDS, "", report);
  if (!Array.isArray(data.categories) || data.categories.length === 0) {
    report("/categories", "must be a non-empty list");
    return issues;
  }
  const ids = new Map();
  const claim = (id, pointer) => {
    if (typeof id !== "string" || !KEBAB_CASE.test(id)) {
      report(`${pointer}/id`, "must be a kebab-case string");
    } else if (ids.has(id)) {
      report(`${pointer}/id`, `duplicate id "${id}"; ${ids.get(id)} has it too`);
    } else {
      ids.set(id, `${pointer}/id`);
    }
  };
  data.categories.forEach((category, index) => checkCategory(category, `/categories/${index}`, { report, claim }));
  return issues;
}

function checkCategory(category, pointer, { report, claim }) {
  if (!isPlainObject(category)) {
    report(pointer, "must be an object with the fields id, match and patterns");
    return;
  }
  unknownFields(category, CATEGORY_FIELDS, pointer, report);
  claim(category.id, pointer);
  if (!MATCH_TYPES.includes(category.match)) {
    report(`${pointer}/match`, `must be one of ${MATCH_TYPES.join(", ")}`);
    return;
  }
  if (!Array.isArray(category.patterns) || category.patterns.length === 0) {
    report(`${pointer}/patterns`, "must be a non-empty list");
    return;
  }
  category.patterns.forEach((pattern, index) => {
    const at = `${pointer}/patterns/${index}`;
    if (!isPlainObject(pattern)) {
      report(at, "must be an object");
      return;
    }
    unknownFields(pattern, PATTERN_FIELDS[category.match], at, report);
    claim(pattern.id, at);
    PATTERN_CHECKS[category.match](pattern, at, report);
  });
}

const PATTERN_CHECKS = Object.freeze({
  phrase(pattern, at, report) {
    const { text } = pattern;
    if (typeof text !== "string" || text === "") {
      report(`${at}/text`, "must be a non-empty string");
    } else if (text.length > MAX_PHRASE_LENGTH) {
      report(`${at}/text`, `must be at most ${MAX_PHRASE_LENGTH} characters long`);
    } else if (/[\p{Cc}\p{Cf}]/u.test(text) || foldLine(text, []).text !== text || text.startsWith(" ") || text.endsWith(" ")) {
      report(`${at}/text`, "must be folded: lower case, single spaces, no leading or trailing space, no invisible character");
    } else if (!isWordCode(text.charCodeAt(0))) {
      report(`${at}/text`, "must start with a letter, a digit or an underscore");
    }
  },
  "download-pipe"(pattern, at, report) {
    checkWords(pattern.downloaders, `${at}/downloaders`, DOWNLOADER_WORD, { report, allowEmpty: false });
    checkWords(pattern.prefixes, `${at}/prefixes`, COMMAND_WORD, { report, allowEmpty: true });
    checkWords(pattern.shells, `${at}/shells`, COMMAND_WORD, { report, allowEmpty: false });
  },
  "html-comment"(pattern, at, report) {
    const { text } = pattern;
    if (typeof text !== "string" || text === "" || /[\s\p{Cc}\p{Cf}]/u.test(text)) {
      report(`${at}/text`, "must be a non-empty string with no whitespace and no control or format character");
    }
  },
  "code-point-range"(pattern, at, report) {
    const from = codePointOf(pattern.from);
    const to = codePointOf(pattern.to);
    if (from === null) report(`${at}/from`, "must be a code point written U+XXXX, at most U+10FFFF and not a surrogate");
    if (to === null) report(`${at}/to`, "must be a code point written U+XXXX, at most U+10FFFF and not a surrogate");
    if (from !== null && to !== null && from > to) report(`${at}/to`, "must not be below from");
  },
});

function checkWords(list, pointer, shape, { report, allowEmpty }) {
  if (!Array.isArray(list) || (!allowEmpty && list.length === 0)) {
    report(pointer, allowEmpty ? "must be a list" : "must be a non-empty list");
    return;
  }
  list.forEach((word, index) => {
    if (typeof word !== "string" || !shape.test(word)) {
      report(`${pointer}/${index}`, `must be a lower-case command word matching ${shape.source}`);
    } else if (list.indexOf(word) !== index) {
      report(`${pointer}/${index}`, `"${word}" is listed twice`);
    }
  });
}

function unknownFields(object, allowed, pointer, report) {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) report(`${pointer}/${escapePointer(key)}`, `unknown field; the fields are ${allowed.join(", ")}`);
  }
  for (const key of allowed) {
    if (!Object.hasOwn(object, key)) report(`${pointer}/${key}`, "missing required field");
  }
}

// The code point of a U+XXXX string, or null when the string is not one or names a surrogate or a value above U+10FFFF.
function codePointOf(value) {
  const match = typeof value === "string" ? CODE_POINT.exec(value) : null;
  if (match === null) return null;
  const code = Number.parseInt(match[1], 16);
  if (code > MAX_CODE_POINT || (code >= 0xd800 && code <= 0xdfff)) return null;
  return code;
}

function escapePointer(key) {
  return String(key).replaceAll("~", "~0").replaceAll("/", "~1");
}

/**
 * The patterns of data/injection-patterns.json, compiled for matchLine. The file is read and checked once per process.
 * @returns {object} The compiled patterns. Callers must not change them.
 * @throws {Error} When the file is not valid, naming the first problem.
 */
export function loadInjectionPatterns() {
  if (loaded === null) {
    const data = JSON.parse(fs.readFileSync(DATA_URL, "utf8"));
    const [first] = validateInjectionPatterns(data);
    if (first !== undefined) throw new Error(`${DATA_FILE}: ${first.pointer || "(root)"}: ${first.message}`);
    loaded = compileInjectionPatterns(data);
  }
  return loaded;
}

/**
 * Compiles patterns that validateInjectionPatterns accepts.
 * @param {object} data
 * @returns {object} The compiled patterns, for matchLine.
 */
export function compileInjectionPatterns(data) {
  const ranges = [];
  const phrasesByKey = new Map();
  const downloads = [];
  const comments = [];
  const order = new Map();
  for (const category of data.categories) {
    for (const pattern of category.patterns) {
      order.set(pattern.id, order.size);
      const base = { category: category.id, patternId: pattern.id };
      if (category.match === "phrase") addByKey(phrasesByKey, firstToken(pattern.text), { ...base, text: pattern.text });
      if (category.match === "html-comment") comments.push({ ...base, text: pattern.text });
      if (category.match === "code-point-range") {
        ranges.push({ ...base, from: codePointOf(pattern.from), to: codePointOf(pattern.to) });
      }
      if (category.match === "download-pipe") {
        const downloadersByKey = new Map();
        for (const word of pattern.downloaders) addByKey(downloadersByKey, firstToken(word), word);
        downloads.push({ ...base, downloadersByKey, prefixes: new Set(pattern.prefixes), shells: new Set(pattern.shells) });
      }
    }
  }
  const keys = [...phrasesByKey.keys(), ...downloads.flatMap((download) => [...download.downloadersByKey.keys()])];
  const dropped = ranges.map((range) => [range.from, range.to]);
  return Object.freeze({
    ranges,
    dropped,
    phrasesByKey,
    downloads,
    comments,
    order,
    longestKey: Math.max(0, ...keys.map((key) => key.length)),
  });
}

function addByKey(map, key, value) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

function firstToken(text) {
  let end = 0;
  while (end < text.length && isTokenCode(text.charCodeAt(end))) end += 1;
  return text.slice(0, end);
}

/**
 * The matches of one line, at most one per pattern, in the order of the patterns in the file.
 * @param {object} compiled From loadInjectionPatterns or compileInjectionPatterns.
 * @param {string} line One line, with no line break.
 * @param {{ comments?: boolean }} [options] comments: check the html-comment patterns (default false).
 * @returns {Array<{ category: string, patternId: string, index: number }>} index is the position in the line where the match
 *   starts: the first character of the phrase, the downloader, the comment or the code point.
 */
export function matchLine(compiled, line, { comments = false } = {}) {
  const found = new Map();
  for (const range of compiled.ranges) {
    const index = firstInRange(line, range.from, range.to);
    if (index !== -1) found.set(range.patternId, { category: range.category, patternId: range.patternId, index });
  }
  if (comments) {
    for (const comment of compiled.comments) {
      const index = line.indexOf(comment.text);
      if (index !== -1) found.set(comment.patternId, { category: comment.category, patternId: comment.patternId, index });
    }
  }
  const folded = foldLine(line, compiled.dropped);
  for (const match of foldedMatches(compiled, folded.text)) {
    found.set(match.patternId, { category: match.category, patternId: match.patternId, index: folded.at[match.index] });
  }
  return [...found.values()].sort((a, b) => compiled.order.get(a.patternId) - compiled.order.get(b.patternId));
}

// The phrase and download matches of a folded line, with indexes in the folded line. One pass reads the tokens; the pipes are
// read once, after the first downloader of each download pattern.
function foldedMatches(compiled, text) {
  const matches = [];
  const seen = new Set();
  const firstDownloader = compiled.downloads.map(() => -1);
  let index = 0;
  while (index < text.length) {
    if (!isTokenCode(text.charCodeAt(index))) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < text.length && isTokenCode(text.charCodeAt(end))) end += 1;
    // Apostrophes at either end of a token are quotes, not part of its key: 'ignore previous instructions' still matches.
    let start = index;
    while (start < end && text[start] === "'") start += 1;
    let keyEnd = end;
    while (keyEnd > start && text[keyEnd - 1] === "'") keyEnd -= 1;
    if (keyEnd > start && keyEnd - start <= compiled.longestKey) {
      const token = text.slice(start, keyEnd);
      for (const phrase of compiled.phrasesByKey.get(token) ?? []) {
        if (seen.has(phrase.patternId) || !text.startsWith(phrase.text, start)) continue;
        if (isWordCode(text.charCodeAt(start + phrase.text.length))) continue;
        seen.add(phrase.patternId);
        matches.push({ category: phrase.category, patternId: phrase.patternId, index: start });
      }
      compiled.downloads.forEach((download, at) => {
        if (firstDownloader[at] === -1 && isDownloaderAt(text, start, download.downloadersByKey.get(token))) {
          firstDownloader[at] = start;
        }
      });
    }
    index = end;
  }
  compiled.downloads.forEach((download, at) => {
    const start = firstDownloader[at];
    if (start !== -1 && pipesToShell(text, start, download)) {
      matches.push({ category: download.category, patternId: download.patternId, index: start });
    }
  });
  return matches;
}

// True when one of the words is at index, ends at a command boundary and has an argument before the next pipe.
function isDownloaderAt(text, index, words) {
  if (words === undefined) return false;
  return words.some((word) => {
    if (!text.startsWith(word, index)) return false;
    const end = index + word.length;
    if (isCommandCode(text.charCodeAt(end)) && text[end] !== ".") return false;
    // The folded line has single spaces, so the argument is the next character, or the one after a space.
    const next = text[end] === " " ? end + 1 : end;
    return next < text.length && text[next] !== "|";
  });
}

// True when a pipe after start runs a shell on what it reads: "|" (not "||"), then up to MAX_PIPE_WORDS words, where every
// word before the shell is a prefix, a flag, the argument of a flag or an assignment, and the shell is not run with -c, -e or
// -m (inline code or a module, which do not read the download: "| python -m json.tool"). A word is read up to the first
// character that is not a command character, so the words of one pipe end before the next pipe and each part of the line is
// read once.
function pipesToShell(text, start, download) {
  let pipe = text.indexOf("|", start);
  while (pipe !== -1) {
    if (text[pipe + 1] === "|") {
      pipe = text.indexOf("|", pipe + 2);
      continue;
    }
    if (runsShell(text, pipe + 1, download)) return true;
    pipe = text.indexOf("|", pipe + 1);
  }
  return false;
}

function runsShell(text, from, download) {
  const words = [];
  let at = from;
  // One word more than MAX_PIPE_WORDS, to see the flag after the shell.
  while (words.length <= MAX_PIPE_WORDS) {
    if (text[at] === " ") at += 1;
    const wordStart = at;
    while (at < text.length && isCommandCode(text.charCodeAt(at))) at += 1;
    if (at === wordStart) break;
    words.push(commandName(text.slice(wordStart, at)));
  }
  for (let index = 0; index < Math.min(words.length, MAX_PIPE_WORDS); index += 1) {
    const name = words[index];
    if (download.shells.has(name)) return !isInlineFlag(words[index + 1]);
    const flagArgument = index > 0 && words[index - 1].startsWith("-");
    if (!download.prefixes.has(name) && !name.startsWith("-") && !name.includes("=") && !flagArgument) return false;
  }
  return false;
}

// -c, -e and -m (also written -mjson.tool) run inline code or a module instead of what the shell reads.
function isInlineFlag(word) {
  return word === "-c" || word === "-e" || (word !== undefined && word.startsWith("-m"));
}

// The name of a command word: the part after the last slash, without a trailing .exe.
function commandName(word) {
  const name = word.slice(word.lastIndexOf("/") + 1);
  return name.endsWith(".exe") ? name.slice(0, -".exe".length) : name;
}

function firstInRange(line, from, to) {
  for (let index = 0; index < line.length; index += 1) {
    const unit = line.charCodeAt(index);
    if (unit < 0x200b && from >= 0x200b) continue;
    const code = line.codePointAt(index);
    if (code >= from && code <= to) return index;
    if (code > 0xffff) index += 1;
  }
  return -1;
}

/**
 * Folds a line for the phrase and download patterns (see the header).
 * @param {string} line
 * @param {Array<[number, number]>} dropped Code point ranges to drop, from and to included.
 * @returns {{ text: string, at: number[] }} at[i] is the index in line of the character that gave text[i].
 */
export function foldLine(line, dropped) {
  const units = [];
  const at = [];
  let space = false;
  for (let index = 0; index < line.length; index += 1) {
    const unit = line.charCodeAt(index);
    if (unit < 0x80) {
      if (unit === 0x20 || (unit >= 0x09 && unit <= 0x0d)) {
        if (!space) {
          units.push(0x20);
          at.push(index);
          space = true;
        }
        continue;
      }
      units.push(unit >= 0x41 && unit <= 0x5a ? unit + 0x20 : unit);
      at.push(index);
      space = false;
      continue;
    }
    const code = line.codePointAt(index);
    const start = index;
    if (code > 0xffff) index += 1;
    if (WIDE_SPACES.has(code) || (code >= 0x2000 && code <= 0x200a)) {
      if (!space) {
        units.push(0x20);
        at.push(start);
        space = true;
      }
      continue;
    }
    if (dropped.some(([from, to]) => code >= from && code <= to) || IGNORABLE.test(String.fromCodePoint(code))) continue;
    const lower = APOSTROPHES.has(code) ? "'" : String.fromCodePoint(code).toLowerCase();
    for (let unitIndex = 0; unitIndex < lower.length; unitIndex += 1) {
      units.push(lower.charCodeAt(unitIndex));
      at.push(start);
    }
    space = false;
  }
  return { text: fromUnits(units), at };
}

// String.fromCharCode in chunks, so a long line does not pass too many arguments at once.
function fromUnits(units) {
  const chunk = 8192;
  let text = "";
  for (let start = 0; start < units.length; start += chunk) {
    text += String.fromCharCode(...units.slice(start, start + chunk));
  }
  return text;
}

// a-z, 0-9, _ and the apostrophe: the characters of a token.
function isTokenCode(code) {
  return isWordCode(code) || code === 0x27;
}

// a-z, 0-9 and _: the characters that may not follow a phrase.
function isWordCode(code) {
  return (code >= 0x61 && code <= 0x7a) || (code >= 0x30 && code <= 0x39) || code === 0x5f;
}

// The characters of a command word: a-z, 0-9, _, ., -, / and =.
function isCommandCode(code) {
  return isWordCode(code) || code === 0x2e || code === 0x2d || code === 0x2f || code === 0x3d;
}
