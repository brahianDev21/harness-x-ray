// Markdown helpers shared by the measures that read memory text: fenced blocks and inline code spans.
// They work one line at a time, as memory.mjs always has, so a code span that runs over two lines is
// not seen as a span. Nothing here reads a file.

// A fence opening or closing line: up to three spaces of indent, then three or more backticks or tildes.
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})(.*)$/;
const FENCE_CLOSE = /^ {0,3}(`{3,}|~{3,})[ \t]*$/;

// The character that stands for the text of a code span in a masked line. It is not a space, so a
// pattern that needs whitespace before a token never matches inside a span.
export const MASK = "\u0001";

/**
 * The fence that a line opens, or null. A backtick fence whose info string holds a backtick is not a fence.
 * @param {string} line
 * @returns {{ char: string, length: number } | null}
 */
export function opensFence(line) {
  const match = FENCE_OPEN.exec(line);
  if (match === null) return null;
  const marker = match[1];
  if (marker[0] === "`" && match[2].includes("`")) return null;
  return { char: marker[0], length: marker.length };
}

/**
 * True when a line closes the fence: same character, at least the same length, nothing else on the line.
 * @param {string} line
 * @param {{ char: string, length: number }} fence
 * @returns {boolean}
 */
export function closesFence(line, fence) {
  const match = FENCE_CLOSE.exec(line);
  return match !== null && match[1][0] === fence.char && match[1].length >= fence.length;
}

/**
 * The inline code spans of one line. A run of backticks without a closing run of the same length on
 * the same line is not a span. A backtick that follows a backslash is escaped and is not a span either.
 * @param {string} line
 * @returns {Array<{ start: number, end: number, text: string }>} start is the index of the opening run,
 *   end is the index just after the closing run, and text is what lies between the runs, as written.
 */
export function codeSpans(line) {
  const spans = [];
  let index = 0;
  while (index < line.length) {
    if (line[index] !== "`" || (index > 0 && line[index - 1] === "\\")) {
      index += 1;
      continue;
    }
    const run = backtickRunAt(line, index);
    const closeEnd = closingRunEnd(line, index + run, run);
    if (closeEnd === -1) {
      index += run;
    } else {
      spans.push({ start: index, end: closeEnd, text: line.slice(index + run, closeEnd - run) });
      index = closeEnd;
    }
  }
  return spans;
}

/**
 * The line with the text of each code span replaced by MASK, one MASK per character. The length of the
 * line does not change, so an index in the masked line is the same index in the original.
 * @param {string} line
 * @returns {string}
 */
export function maskCodeSpans(line) {
  let out = "";
  let last = 0;
  for (const span of codeSpans(line)) {
    out += line.slice(last, span.start) + MASK.repeat(span.end - span.start);
    last = span.end;
  }
  return out + line.slice(last);
}

/**
 * The lines of a Markdown text, without the fence delimiter lines. A line inside a fenced block has
 * fenced set to true. A fence that is never closed runs to the end of the text.
 * @param {string} text LF line endings.
 * @returns {Array<{ number: number, text: string, fenced: boolean }>} number is 1-based.
 */
export function markdownLines(text) {
  const lines = [];
  let fence = null;
  text.split("\n").forEach((line, index) => {
    const number = index + 1;
    if (fence !== null) {
      if (closesFence(line, fence)) fence = null;
      else lines.push({ number, text: line, fenced: true });
      return;
    }
    const opening = opensFence(line);
    if (opening !== null) {
      fence = opening;
      return;
    }
    lines.push({ number, text: line, fenced: false });
  });
  return lines;
}

function backtickRunAt(line, index) {
  let end = index;
  while (line[end] === "`") end += 1;
  return end - index;
}

// The index just after the first backtick run of the given length at or after from, or -1.
function closingRunEnd(line, from, length) {
  let index = from;
  while (index < line.length) {
    if (line[index] !== "`") {
      index += 1;
    } else {
      const run = backtickRunAt(line, index);
      if (run === length) return index + run;
      index += run;
    }
  }
  return -1;
}
