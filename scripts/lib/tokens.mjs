// Token estimation for the text that Claude Code loads into context. The only method is a
// heuristic: one token for every four characters. Reports must show the number as an estimate,
// with the method name next to it. The Claude Code documentation gives no ratio of its own.

/** The only estimation method. Every report that shows an estimate shows this name with it. */
export const ESTIMATE_METHOD = "chars/4";

// Start of a block-level HTML comment: at most three spaces, then "<!--". Four or more spaces make
// an indented code block in CommonMark, so a comment there is kept.
const COMMENT_START = /^ {0,3}<!--/;
const COMMENT_END = "-->";
// Opening fence: at most three spaces, then three or more backticks or tildes. The info string of a
// backtick fence cannot contain a backtick, so such a line is not a fence.
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})(.*)$/;
// Closing fence: a marker of the same kind, then nothing but spaces and tabs.
const FENCE_CLOSE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;

/**
 * Estimates the tokens of a text, as Claude Code would load it: block-level HTML comments are
 * removed first (see stripHtmlComments), then the Unicode code points are counted. Code points,
 * not UTF-16 units, so an emoji counts once.
 * @param {unknown} text Any value. A non-string counts as empty.
 * @returns {{ estTokens: number, method: "chars/4" }}
 */
export function estimateTokens(text) {
  const content = stripHtmlComments(text);
  let characters = 0;
  // Counted by code unit instead of spreading into an array, so a 4 MiB memory file needs no
  // large temporary array. A low surrogate that follows a high one is the second half of a code
  // point, so it is not counted again.
  for (let index = 0; index < content.length; index += 1) {
    const code = content.charCodeAt(index);
    const completesPair = isLowSurrogate(code) && index > 0 && isHighSurrogate(content.charCodeAt(index - 1));
    if (!completesPair) characters += 1;
  }
  return { estTokens: Math.ceil(characters / 4), method: ESTIMATE_METHOD };
}

/**
 * Removes block-level HTML comments, the way Claude Code does before it injects a memory file.
 *
 * Removed: a comment whose "<!--" starts a line (after up to three spaces), through the first
 * "-->" that follows, which may be on later lines. If only whitespace remains on the line where
 * the comment ends, that line goes too. Text after "-->" on that line is kept.
 *
 * Kept, and therefore counted:
 * - comments inside a fenced code block (``` or ~~~). The block ends at a fence of the same
 *   character and at least the same length, or at the end of the text. The docs say comments
 *   inside code blocks are preserved.
 * - comments that start in the middle of a line. The docs describe block-level comments only, and
 *   a comment inside a paragraph is not documented as removed. Keeping it can only overcount.
 * - a comment that is never closed. Removing text that may be content would undercount.
 * - a comment indented four or more spaces, which is an indented code block in CommonMark.
 *
 * The rule for "block-level" follows CommonMark's HTML block start. The docs do not define the
 * term, so this is the closest published definition.
 *
 * The output uses LF line endings and has no BOM, so CRLF and LF text give the same result.
 * @param {unknown} text Any value. A non-string gives "".
 * @returns {string}
 */
export function stripHtmlComments(text) {
  if (typeof text !== "string") return "";
  const lines = normalizeText(text).split("\n");
  const lastClosing = lastIndexContaining(lines, COMMENT_END);
  const kept = [];
  let fence = null;
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (fence !== null) {
      // Inside a fenced code block everything is kept, comments included.
      if (closesFence(line, fence)) fence = null;
      kept.push(line);
      index += 1;
      continue;
    }
    const opening = opensFence(line);
    if (opening !== null) {
      fence = opening;
      kept.push(line);
      index += 1;
      continue;
    }
    const comment = findCommentEnd(lines, index, lastClosing);
    if (comment === null) {
      kept.push(line);
      index += 1;
      continue;
    }
    const rest = lines[comment.line].slice(comment.end);
    if (rest.trim() !== "") kept.push(rest);
    index = comment.line + 1;
  }
  return kept.join("\n");
}

// Returns where the comment that starts at lines[index] ends, or null when there is none.
// lastClosing is the last line that contains "-->", so an unclosed comment is found quickly.
function findCommentEnd(lines, index, lastClosing) {
  if (index > lastClosing) return null;
  const opening = COMMENT_START.exec(lines[index]);
  if (opening === null) return null;
  for (let line = index; line <= lastClosing; line += 1) {
    // The search on the first line starts after "<!--", so "<!---->" closes on its own line.
    const from = line === index ? opening[0].length : 0;
    const at = lines[line].indexOf(COMMENT_END, from);
    if (at !== -1) return { line, end: at + COMMENT_END.length };
  }
  return null;
}

function opensFence(line) {
  const match = FENCE_OPEN.exec(line);
  if (match === null) return null;
  const marker = match[1];
  if (marker[0] === "`" && match[2].includes("`")) return null;
  return { char: marker[0], length: marker.length };
}

function closesFence(line, fence) {
  const match = FENCE_CLOSE.exec(line);
  return match !== null && match[1][0] === fence.char && match[1].length >= fence.length;
}

function lastIndexContaining(lines, needle) {
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (lines[index].includes(needle)) return index;
  }
  return -1;
}

// Drops a leading BOM and turns CRLF and lone CR into LF. The estimate depends on the content,
// not on the line endings of the file.
function normalizeText(text) {
  const withoutBom = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  return withoutBom.replace(/\r\n?/g, "\n");
}

function isHighSurrogate(code) {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code) {
  return code >= 0xdc00 && code <= 0xdfff;
}
