// Markdown helpers of the report: escaping of text that comes from the target, the measurements or the agent,
// the forms of code spans and links, the GFM table, and the formatting of numbers and dates. They are pure, and
// the locale of a number comes from the language of findings.json, never from the machine.
//
// Escaping rules. A line break becomes a space, so a value cannot start a new block. A pipe is escaped as \| in a
// table cell, because GFM reads it as a cell boundary even inside a code span. A code span is fenced with one
// backtick more than the longest run of backticks in its text, so a backtick in a quote cannot end the span.

const LOCALES = Object.freeze({ en: "en-US", es: "es-ES" });
const numberFormats = new Map();

/**
 * The locale that formats the numbers of a language.
 * @param {string} language "en" or "es".
 * @returns {string} "en-US" or "es-ES".
 * @throws {Error} If the language has no locale.
 */
export function localeOf(language) {
  if (!Object.hasOwn(LOCALES, language)) throw new Error(`no number format for language "${language}"`);
  return LOCALES[language];
}

/**
 * Formats a finite number with the fixed locale of the language, at most two decimals.
 * @param {number} value
 * @param {string} language
 * @returns {string}
 */
export function formatNumber(value, language) {
  if (!Number.isFinite(value)) throw new TypeError(`cannot format ${String(value)} as a number`);
  if (!numberFormats.has(language)) {
    numberFormats.set(language, new Intl.NumberFormat(localeOf(language), { maximumFractionDigits: 2 }));
  }
  return numberFormats.get(language).format(value);
}

/**
 * The UTC date of an ISO 8601 date-time, as YYYY-MM-DD. The same in every language.
 * @param {string} iso
 * @returns {string}
 * @throws {TypeError} If the text is not a date-time.
 */
export function utcDate(iso) {
  const date = typeof iso === "string" ? new Date(iso) : new Date(Number.NaN);
  if (Number.isNaN(date.getTime())) throw new TypeError("meta.scannedAt must be an ISO 8601 date-time");
  return date.toISOString().slice(0, 10);
}

/** One line: every line break becomes a space, and the ends are trimmed. */
export function inline(text) {
  return String(text).replace(/\r\n|\r|\n/g, " ").trim();
}

/** A pipe as GFM reads it inside a table cell: escaped. */
export function escapePipes(text) {
  return text.replace(/\|/g, "\\|");
}

/**
 * A code span. The fence is one backtick longer than the longest run inside the text. A text that starts or ends
 * with a backtick gets one space on each side, so the fence is not joined to it.
 * @param {string} text One line, not empty.
 * @returns {string}
 */
export function codeSpan(text) {
  if (text === "") throw new TypeError("a code span needs text");
  const longest = (text.match(/`+/g) ?? []).reduce((max, run) => Math.max(max, run.length), 0);
  const fence = "`".repeat(longest + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${pad}${text}${pad}${fence}`;
}

/**
 * A link. The text escapes brackets and backslashes. The URL is written only when it is http or https, and its
 * parentheses, angle brackets and spaces are percent-encoded; any other URL is written as plain code.
 * @param {string} label One line of text.
 * @param {string} url
 * @returns {string}
 */
export function link(label, url) {
  const text = label.replace(/[\\[\]]/g, (char) => `\\${char}`);
  if (!/^https?:\/\//.test(url)) return codeSpan(url);
  // encodeURIComponent keeps parentheses, so the few characters that would end a link are encoded by hand.
  const safe = url.replace(/[()<> ]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
  return `[${text}](${safe})`;
}

/**
 * A GFM table. The headers and the cells are already escaped by the caller; every row needs one cell per header.
 * @param {string[]} headers
 * @param {string[][]} rows
 * @returns {string}
 */
export function table(headers, rows) {
  const head = `| ${headers.join(" | ")} |`;
  const divider = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((row) => {
    if (row.length !== headers.length) throw new TypeError("a table row must have one cell per header");
    return `| ${row.join(" | ")} |`;
  });
  return [head, divider, ...body].join("\n");
}
