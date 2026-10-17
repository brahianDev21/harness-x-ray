// Minimal reader for the YAML frontmatter of Markdown files: skills, subagents, rules and memory.
//
// It understands the subset those files use in practice:
//   - plain, single-quoted and double-quoted scalars;
//   - null (null, Null, NULL, ~, or an empty value); booleans (true, True, TRUE, false, False,
//     FALSE, the spellings of the YAML 1.2 core schema); integers and decimals as numbers. Any other
//     plain scalar is a string;
//   - block scalars | and > with the chomping indicators - and + and an indentation digit;
//   - inline lists [a, b] of scalars, and dash lists of scalars;
//   - full-line comments, and a " # comment" after a plain, quoted or inline value.
//
// It does not guess. A top-level value outside that subset (a nested mapping, a list of mappings,
// a value written on the lines below its key, a flow mapping, an anchor or an alias) becomes
// { error: "line N: ..." } in place of the value, and the other keys still parse. Broken structure
// (no closing ---, a top-level line that is not key: value, a tab used for indentation, bad
// indentation, a duplicate key) makes the whole result { error, body }.
//
// Line numbers count from the first line of the file, as an editor shows them.

const DELIMITER = /^---[ \t]*$/;
// A top-level key: a name of letters, digits, "_", "." and "-", then ":" followed by a space or the
// end of the line. "key:value" is not a key.
const TOP_LEVEL_KEY = /^([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*:(?:[ \t]+(.*))?$/;
// The start of a mapping inside a value, such as "PreToolUse:" in a nested block.
const MAPPING_START = /^[A-Za-z_][A-Za-z0-9_.-]*[ \t]*:(?:[ \t]|$)/;
const LIST_ITEM = /^[ \t]*-(?:[ \t]|$)/;
const LIST_MARKER = /^[ \t]*-[ \t]*/;
// Block scalar header: | or >, then an indentation digit and a chomping indicator, in either order.
const BLOCK_HEADER = /^([|>])((?:[+-][1-9]?|[1-9][+-]?)?)(?:[ \t]+#.*)?$/;
const NULL_SPELLING = /^(?:null|Null|NULL|~)$/;
const TRUE_SPELLING = /^(?:true|True|TRUE)$/;
const FALSE_SPELLING = /^(?:false|False|FALSE)$/;
const NUMBER = /^[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?$/;
// Escapes of double-quoted scalars that stand for one fixed character.
const ESCAPES = new Map([
  ["0", "\0"], ["a", "\x07"], ["b", "\b"], ["t", "\t"], ["\t", "\t"], ["n", "\n"], ["v", "\v"],
  ["f", "\f"], ["r", "\r"], ["e", "\x1b"], [" ", " "], ['"', '"'], ["/", "/"], ["\\", "\\"],
  ["N", "\u0085"], ["_", " "], ["L", " "], ["P", " "],
]);
// Escapes of double-quoted scalars followed by a fixed number of hexadecimal digits.
const HEX_ESCAPES = new Map([["x", 2], ["u", 4], ["U", 8]]);

/**
 * Reads the frontmatter of a Markdown text. Never throws.
 *
 * The result is one of:
 * - { data: null, body } when there is no frontmatter (or the input is not a string, with body "");
 * - { data, body } when it parses. A key whose value is outside the subset has the value
 *   { error: "line N: ..." }, and no other object value is ever produced;
 * - { error, body } when the frontmatter is broken. body is the text after the closing ---, or the
 *   whole text when that line is missing.
 *
 * Every error message starts with "line N: ". body never has a BOM and uses LF line endings.
 * @param {unknown} text The file text.
 * @returns {{ data: object | null, body: string } | { error: string, body: string }}
 */
export function parseFrontmatter(text) {
  if (typeof text !== "string") return { data: null, body: "" };
  try {
    return parseText(text);
  } catch {
    // Every path above returns a result, so this should not run. It is kept so that the promise of
    // this function holds even if a later change breaks one of those paths.
    return { error: "line 1: the frontmatter could not be read", body: normalizeText(text) };
  }
}

function parseText(text) {
  const normalized = normalizeText(text);
  const lines = normalized.split("\n");
  if (!DELIMITER.test(lines[0])) return { data: null, body: normalized };
  const close = lines.findIndex((line, index) => index > 0 && DELIMITER.test(line));
  if (close === -1) {
    return {
      error: "line 1: the frontmatter opened with --- is never closed; add a --- line after it",
      body: normalized,
    };
  }
  const body = lines.slice(close + 1).join("\n");
  const fields = readFields(lines, close);
  if (fields.fatal !== undefined) return { error: fields.fatal, body };
  return { data: fields.data, body };
}

// Reads the top-level keys between the delimiters. lines[0] is the opening ---, lines[close] the
// closing one. Returns { data } or { fatal } for a structural error, which makes the whole result
// an error. A value that is outside the subset is stored as { error } and reading goes on.
function readFields(lines, close) {
  for (let index = 1; index < close; index += 1) {
    if (hasTabIndentation(lines[index])) {
      return { fatal: `line ${index + 1}: tabs cannot be used for indentation; use spaces` };
    }
  }

  const data = {};
  const keyLines = new Map();
  let index = 1;
  while (index < close) {
    const line = lines[index];
    if (isBlankOrComment(line)) {
      index += 1;
      continue;
    }
    const lineNo = index + 1;
    if (leadingSpaces(line) > 0) {
      return { fatal: `line ${lineNo}: unexpected indentation; top-level keys start at the first column` };
    }
    const match = TOP_LEVEL_KEY.exec(line);
    if (match === null) return { fatal: `line ${lineNo}: expected "key: value" at the top level` };
    const key = match[1];
    if (keyLines.has(key)) {
      return { fatal: `line ${lineNo}: duplicate key "${key}" (first on line ${keyLines.get(key)})` };
    }
    keyLines.set(key, lineNo);

    let inline = (match[2] ?? "").trim();
    // "key: # comment" has no value on its line, so its value is the block below it.
    if (inline.startsWith("#")) inline = "";
    let result;
    let next;
    if (inline.startsWith("|") || inline.startsWith(">")) {
      ({ result, next } = readBlockScalar(lines, index + 1, close, inline, lineNo));
    } else if (inline === "") {
      next = endOfBlock(lines, index + 1, close, true);
      const bad = firstBadIndentation(lines, index + 1, next);
      if (bad !== -1) {
        return { fatal: `line ${bad + 1}: bad indentation; this line is indented less than the lines of the value above it` };
      }
      result = readBlock(lines, index + 1, next);
    } else {
      next = endOfBlock(lines, index + 1, close, false);
      result = parseInline(inline, lineNo);
      const extra = firstContentLine(lines, index + 1, next);
      if (extra !== -1 && result.error === undefined) {
        result = { error: `line ${extra + 1}: a value continued on the next lines is not supported` };
      }
    }
    defineValue(data, key, unwrap(result));
    index = next;
  }
  return { data };
}

// Returns the index of the first line after the value of a key whose value starts below it.
// Blank and comment lines belong to the value wherever they are. The value is made of indented
// lines. When allowDash is set (the key has nothing after its colon), a dash list may also sit at
// the key's own column, which YAML allows.
function endOfBlock(lines, from, close, allowDash) {
  let index = from;
  let hasContent = false;
  let dashAtKeyColumn = false;
  while (index < close) {
    const line = lines[index];
    if (isBlankOrComment(line)) {
      index += 1;
      continue;
    }
    if (leadingSpaces(line) > 0) {
      hasContent = true;
      index += 1;
      continue;
    }
    const continuesDashList = allowDash && LIST_ITEM.test(line) && (!hasContent || dashAtKeyColumn);
    if (!continuesDashList) break;
    dashAtKeyColumn = true;
    hasContent = true;
    index += 1;
  }
  return index;
}

// A value below its key must not be indented less than its first line. Such a line is broken
// structure, not an unsupported construct, so it makes the whole frontmatter an error.
function firstBadIndentation(lines, from, to) {
  let base = -1;
  for (let index = from; index < to; index += 1) {
    if (isBlankOrComment(lines[index])) continue;
    const spaces = leadingSpaces(lines[index]);
    if (base === -1) {
      base = spaces;
    } else if (spaces < base) {
      return index;
    }
  }
  return -1;
}

function firstContentLine(lines, from, to) {
  for (let index = from; index < to; index += 1) {
    if (!isBlankOrComment(lines[index])) return index;
  }
  return -1;
}

// Reads a value written on the lines below its key: a dash list of scalars, or nothing.
function readBlock(lines, from, to) {
  const contentIndexes = [];
  for (let index = from; index < to; index += 1) {
    if (!isBlankOrComment(lines[index])) contentIndexes.push(index);
  }
  if (contentIndexes.length === 0) return { value: null };

  const first = lines[contentIndexes[0]];
  const base = leadingSpaces(first);
  if (LIST_ITEM.test(first)) {
    const items = [];
    for (const index of contentIndexes) {
      const line = lines[index];
      const lineNo = index + 1;
      if (leadingSpaces(line) > base) return { error: `line ${lineNo}: lines under a list item are not supported` };
      if (!LIST_ITEM.test(line)) return { error: `line ${lineNo}: expected a list item that starts with "- "` };
      const item = parseListItem(line.replace(LIST_MARKER, "").trim(), lineNo);
      if (item.error !== undefined) return item;
      items.push(item.value);
    }
    return { value: items };
  }
  const lineNo = contentIndexes[0] + 1;
  if (MAPPING_START.test(first.trim())) return { error: `line ${lineNo}: nested mappings are not supported` };
  return {
    error: `line ${lineNo}: a value on the lines below its key is not supported; put it on the key line`,
  };
}

// The item of a dash list: a scalar, or null for an empty item.
function parseListItem(text, lineNo) {
  if (text === "") return { value: null };
  if (MAPPING_START.test(text)) return { error: `line ${lineNo}: list items that are mappings are not supported` };
  if (text.startsWith("[")) return { error: `line ${lineNo}: nested lists are not supported` };
  return parseInline(text, lineNo);
}

// Reads a block scalar (| or >). Its content is every following line that is blank or indented at
// least as far as the first content line (or as far as the indentation digit says). Returns the
// value and the index of the first line after the block.
function readBlockScalar(lines, from, close, header, keyLineNo) {
  const match = BLOCK_HEADER.exec(header);
  if (match === null) {
    const next = endOfBlock(lines, from, close, false);
    return { result: { error: `line ${keyLineNo}: invalid block scalar header "${header}"` }, next };
  }
  const indicators = match[2];
  const chomping = indicators.includes("+") ? "keep" : indicators.includes("-") ? "strip" : "clip";
  const digit = /[1-9]/.exec(indicators);
  const folded = match[1] === ">";

  let indent = digit === null ? null : Number(digit[0]);
  const content = [];
  let index = from;
  for (; index < close; index += 1) {
    const line = lines[index];
    // A line with only spaces counts as blank. Spaces beyond the indentation of a blank line are
    // not kept; the estimate and the reports do not need them.
    if (line.trim() === "") {
      content.push("");
      continue;
    }
    if (indent === null) {
      if (leadingSpaces(line) === 0) break;
      indent = leadingSpaces(line);
    }
    if (leadingSpaces(line) < indent) break;
    content.push(line.slice(indent));
  }

  // Blank lines at the end belong to the block only for the "keep" chomping indicator.
  let trailing = 0;
  while (content.length > 0 && content[content.length - 1] === "") {
    content.pop();
    trailing += 1;
  }
  const text = content.length === 0 ? "" : folded ? foldLines(content) : content.join("\n");
  let value;
  if (content.length === 0) {
    value = chomping === "keep" ? "\n".repeat(trailing) : "";
  } else if (chomping === "strip") {
    value = text;
  } else if (chomping === "keep") {
    value = `${text}\n${"\n".repeat(trailing)}`;
  } else {
    value = `${text}\n`;
  }
  return { result: { value }, next: index };
}

// Folds the lines of a > block (YAML 1.2, 8.1.3, without the final line break). One line break
// between two ordinary lines becomes a space, each blank line becomes a line break, and a line
// break next to a more-indented line is kept.
function foldLines(lines) {
  let out = "";
  let pending = 0;
  let previous = null;
  for (const line of lines) {
    if (line === "") {
      pending += 1;
      continue;
    }
    const moreIndented = line[0] === " ";
    if (previous === null) {
      out += "\n".repeat(pending);
    } else if (previous === "text" && !moreIndented) {
      out += pending === 0 ? " " : "\n".repeat(pending);
    } else {
      out += "\n".repeat(pending + 1);
    }
    out += line;
    previous = moreIndented ? "more" : "text";
    pending = 0;
  }
  return out;
}

// Reads a scalar, inline list or flow-style value that sits on the key's line. Returns { value } or
// { error }. The text has no leading or trailing spaces.
function parseInline(text, lineNo) {
  if (text === "" || text.startsWith("#")) return { value: null };
  const first = text[0];
  if (first === "[") return parseFlowSequence(text, lineNo);
  if (first === "'" || first === '"') return parseQuotedValue(text, lineNo);
  if (first === "{") return fail(lineNo, "flow mappings ({ }) are not supported");
  if (first === "|" || first === ">") {
    return fail(lineNo, "block scalars (| and >) are only supported as the value of a key");
  }
  if (first === "&" || first === "*" || first === "!") {
    return fail(lineNo, `a value that starts with "${first}" is read by YAML as an anchor, alias or tag; quote it`);
  }
  if (first === "%" || first === "@" || first === "`" || first === "," || first === "]" || first === "}") {
    return fail(lineNo, `a value cannot start with "${first}"; quote it`);
  }
  const indicator = (first === "-" || first === "?" || first === ":") && (text.length === 1 || /[ \t]/.test(text[1]));
  if (indicator) return fail(lineNo, `a value cannot start with "${first} "; quote it`);
  return parsePlainValue(text, lineNo);
}

// A plain scalar ends at " #". YAML reads ": " inside a plain scalar as a mapping, which this
// subset does not support, so such a value is an error and not a string.
function parsePlainValue(text, lineNo) {
  const comment = text.search(/[ \t]#/);
  const raw = (comment === -1 ? text : text.slice(0, comment)).trimEnd();
  if (/:(?:[ \t]|$)/.test(raw)) return fail(lineNo, 'a plain value cannot contain ": "; quote the value');
  return { value: resolvePlain(raw) };
}

// The type of a plain scalar, by the YAML 1.2 core schema. Anything else is a string.
function resolvePlain(raw) {
  if (NULL_SPELLING.test(raw)) return null;
  if (TRUE_SPELLING.test(raw)) return true;
  if (FALSE_SPELLING.test(raw)) return false;
  if (NUMBER.test(raw)) return Number(raw);
  return raw;
}

function parseQuotedValue(text, lineNo) {
  const scanned = scanQuoted(text, 0, lineNo);
  if (scanned.error !== undefined) return scanned;
  if (!trailingOk(text.slice(scanned.end))) return fail(lineNo, "unexpected text after the closing quote");
  return { value: scanned.value };
}

// Reads the quoted scalar that starts at text[start]. Returns { value, end } where end is the index
// after the closing quote, or { error }. A quoted scalar is always a string.
function scanQuoted(text, start, lineNo) {
  const quote = text[start];
  let value = "";
  let index = start + 1;
  while (index < text.length) {
    const char = text[index];
    if (quote === "'") {
      if (char === "'" && text[index + 1] === "'") {
        value += "'";
        index += 2;
        continue;
      }
      if (char === "'") return { value, end: index + 1 };
    } else {
      if (char === '"') return { value, end: index + 1 };
      if (char === "\\") {
        const escape = readEscape(text, index + 1);
        if (escape.error !== undefined) return fail(lineNo, escape.error);
        value += escape.text;
        index = escape.end;
        continue;
      }
    }
    value += char;
    index += 1;
  }
  const kind = quote === "'" ? "single" : "double";
  return fail(lineNo, `the ${kind}-quoted value does not end on this line; multi-line quoted values are not supported`);
}

// Reads the escape whose character is text[index]. Returns the text it stands for and the index
// after it, or an error message.
function readEscape(text, index) {
  const code = text[index];
  if (code === undefined) return { error: "a backslash must be followed by an escape character" };
  if (ESCAPES.has(code)) return { text: ESCAPES.get(code), end: index + 1 };
  const length = HEX_ESCAPES.get(code);
  if (length === undefined) return { error: `unknown escape sequence "\\${code}"` };
  const digits = text.slice(index + 1, index + 1 + length);
  const point = digits.length === length && /^[0-9A-Fa-f]+$/.test(digits) ? Number.parseInt(digits, 16) : NaN;
  if (!(point <= 0x10ffff)) return { error: `invalid escape sequence "\\${code}${digits}"` };
  return { text: String.fromCodePoint(point), end: index + 1 + length };
}

// An inline list "[a, 'b', 3]" of scalars, on one line.
function parseFlowSequence(text, lineNo) {
  const unclosed = "inline list is not closed on this line; multi-line lists are not supported";
  const items = [];
  let index = 1;
  for (;;) {
    index = skipBlanks(text, index);
    if (index >= text.length) return fail(lineNo, unclosed);
    if (text[index] === "]") {
      index += 1;
      break;
    }
    if (text[index] === '"' || text[index] === "'") {
      const scanned = scanQuoted(text, index, lineNo);
      if (scanned.error !== undefined) return scanned;
      items.push(scanned.value);
      index = scanned.end;
    } else {
      let end = index;
      while (end < text.length && text[end] !== "," && text[end] !== "]") end += 1;
      if (end >= text.length) return fail(lineNo, unclosed);
      const raw = text.slice(index, end).trim();
      if (raw === "") return fail(lineNo, "inline list has an empty item");
      if (raw[0] === "[" || raw[0] === "{") return fail(lineNo, "nested collections are not supported in inline lists");
      if (/[ \t]#/.test(raw)) return fail(lineNo, "comments inside an inline list are not supported");
      if (/:(?:[ \t]|$)/.test(raw)) return fail(lineNo, "mappings inside an inline list are not supported");
      items.push(resolvePlain(raw));
      index = end;
    }
    index = skipBlanks(text, index);
    if (index >= text.length) return fail(lineNo, unclosed);
    if (text[index] === ",") {
      index += 1;
    } else if (text[index] === "]") {
      index += 1;
      break;
    } else {
      return fail(lineNo, "unexpected text inside the inline list");
    }
  }
  if (!trailingOk(text.slice(index))) return fail(lineNo, "unexpected text after the inline list");
  return { value: items };
}

// True when what follows a value on its line is blank or a " # comment".
function trailingOk(rest) {
  return rest.trim() === "" || /^[ \t]+#/.test(rest);
}

function skipBlanks(text, index) {
  let position = index;
  while (text[position] === " " || text[position] === "\t") position += 1;
  return position;
}

function fail(lineNo, message) {
  return { error: `line ${lineNo}: ${message}` };
}

// A parsed value, or { error } for a value this subset cannot read. The error object has no other key.
function unwrap(result) {
  return result.error === undefined ? result.value : { error: result.error };
}

// Keys are defined as own properties, so a key such as "__proto__" stays an ordinary key.
function defineValue(target, key, value) {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function hasTabIndentation(line) {
  return line.trim() !== "" && /^[ \t]*\t/.test(line);
}

function isBlankOrComment(line) {
  const trimmed = line.trim();
  return trimmed === "" || trimmed.startsWith("#");
}

function leadingSpaces(line) {
  let count = 0;
  while (line[count] === " ") count += 1;
  return count;
}

// Drops a leading BOM and turns CRLF and lone CR into LF.
function normalizeText(text) {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  return withoutBom.replace(/\r\n?/g, "\n");
}
