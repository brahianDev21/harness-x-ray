// Measure "references": the paths and the commands that the memory files mention, and which of them
// the target does not have. It reads the texts that the memory measure left in ctx.memory, and the root
// package.json through ctx.readText, which it parses as data. It runs nothing and reads nothing else.
//
// Paths are looked for in inline code spans whose content is one token, and in relative Markdown links
// and images. A token must contain "/" or end in a known extension. Commands (npm, pnpm, yarn and bun)
// are looked for in inline code and in fenced blocks, and are compared with the scripts of the root
// package.json. Fenced blocks are never checked for paths.
//
// Absolute paths and home paths are external: they are listed, and never stat-ed or read. A relative path
// that leaves the target is external too, and it is recognized without a stat. Every text in the output
// is redacted.
//
// Output: instructions.brokenRefs and instructions.externalRefs, both sorted, and a warning when the
// root package.json cannot be read or parsed.

import path from "node:path";
import { codeSpans, markdownLines, maskCodeSpans, MASK } from "./markdown.mjs";
import { packageScripts, readPackageJson } from "./package-json.mjs";
import { scriptCallsInLine } from "./script-calls.mjs";
import { createRedactor } from "./redact.mjs";

export const MEASURE_ID = "references";

// Extensions that make a token look like a file, lowercase and with the dot. ".env.example" is a whole
// file name, so it is matched without a base name before it.
const EXTENSIONS = [
  ".md", ".mdx", ".txt", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".js", ".mjs", ".cjs", ".ts", ".mts",
  ".cts", ".tsx", ".jsx", ".sh", ".ps1", ".py", ".css", ".scss", ".html", ".astro", ".vue", ".svelte", ".sql",
  ".env.example", ".lock", ".xml", ".csv",
];
const DOTFILE_EXTENSION = ".env.example";

const DRIVE = /^[A-Za-z]:[\\/]/;
// "scheme:" starts a URL, such as https:, mailto: or node:. A drive letter is not a scheme.
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
const WWW = /^www\./i;
const GLOB = /[*?]/;
// Placeholders: angle brackets, braces, a dollar sign, an ellipsis, and the "path/to/" example.
const PLACEHOLDER = /[<>{}$]|\.\.\.|…|path\/to\//;
// A line reference at the end of a code token: ":12" or ":12:5".
const LINE_SUFFIX = /:\d+(?::\d+)?$/;
// A Markdown link or image: [text](target) or [text](target "title"). The target is group 1.
const LINK = /\[[^\]]*\]\(\s*(<[^>]*>|[^()\s]+)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/dg;

const BROKEN = "broken";
const EXTERNAL = "external";

export const referencesMeasure = Object.freeze({
  id: MEASURE_ID,
  collect: collectReferences,
});

function collectReferences(ctx) {
  const redact = createRedactor({ root: ctx.root });
  const warnings = [];
  const scripts = readScripts(ctx, warnings);
  const found = new Map();
  // Every text is redacted before it is kept, so the sort and the output use the shown text.
  const report = (entry) => {
    const clean = { ...entry, text: redact(entry.text) };
    if (entry.script !== undefined) clean.script = redact(entry.script);
    const key = JSON.stringify([clean.file, clean.line, clean.text, clean.kind, clean.reason ?? null, clean.script ?? null]);
    if (!found.has(key)) found.set(key, clean);
  };
  const state = { ctx, scripts, report };

  // Memory files in path order. Each one is checked by its own text; nothing is read again.
  for (const file of [...ctx.memory.keys()].sort(compareText)) {
    for (const line of markdownLines(ctx.memory.get(file).text)) {
      const where = { file, line: line.number };
      for (const call of scriptCallsInLine(line)) {
        checkCommand(state, where, call);
      }
      if (line.fenced) continue;
      for (const span of codeSpans(line.text)) {
        checkCodeSpanPath(state, where, span.text);
      }
      for (const target of linkTargets(line.text)) {
        checkLink(state, where, target);
      }
    }
  }

  const entries = [...found.values()].sort(compareEntries);
  return {
    instructions: {
      brokenRefs: entries.filter((entry) => entry.status === BROKEN).map(toBroken),
      externalRefs: entries.filter((entry) => entry.status === EXTERNAL).map(toExternal),
    },
    warnings,
  };
}

function toBroken(entry) {
  const item = { file: entry.file, line: entry.line, text: entry.text, kind: entry.kind, reason: entry.reason };
  return entry.script === undefined ? item : { ...item, script: entry.script };
}

function toExternal(entry) {
  return { file: entry.file, line: entry.line, text: entry.text, kind: entry.kind };
}

// ---------------------------------------------------------------------------------------------------
// Paths

// A code span whose trimmed content is one token is checked as a path. The path check uses the token
// without a line suffix or a #fragment; the reported text is the content as written.
function checkCodeSpanPath(state, where, content) {
  const shown = content.trim();
  if (shown === "") return;
  if (/\s/.test(shown)) return;
  const token = withoutFragment(shown.replace(LINE_SUFFIX, ""));
  checkPath(state, { ...where, kind: "path", shown, token, inline: true });
}

// A link target as written. The fragment is not part of the file name.
function checkLink(state, where, target) {
  const token = withoutFragment(target);
  checkPath(state, { ...where, kind: "link", shown: target, token, inline: false });
}

// The text before a "#fragment", or the whole text when there is none.
function withoutFragment(text) {
  const hash = text.indexOf("#");
  return hash === -1 ? text : text.slice(0, hash);
}

function checkPath(state, { file, line, kind, shown, token, inline }) {
  if (token === "" || isNotAPath(token) || !looksLikePath(token)) return;
  if (token.replace(/[\\/~]/g, "") === "") return;
  const entry = { file, line, text: shown, kind };
  if (isExternalForm(token)) {
    state.report({ ...entry, status: EXTERNAL });
    return;
  }
  const relative = token.replaceAll("\\", "/");
  const fromFolder = path.posix.join(path.posix.dirname(file), relative);
  // A code token may name a path from the root or from the folder of the memory file. A link is
  // relative to its own folder, as Markdown renders it.
  const candidates = inline ? unique([path.posix.normalize(relative), fromFolder]) : [fromFolder];
  const result = locate(state.ctx, candidates);
  if (result === EXTERNAL) state.report({ ...entry, status: EXTERNAL });
  else if (result === BROKEN) state.report({ ...entry, status: BROKEN, reason: "not-found" });
}

// Whether any candidate exists (ok), leaves the target (external) or is missing (broken). An error
// other than "not found" gives no answer, so the reference is not reported.
function locate(ctx, candidates) {
  let outside = false;
  let missing = false;
  let unknown = false;
  for (const rel of candidates) {
    // A path that leaves the root is recognized without a stat, so no warning is recorded for it.
    if (rel === ".." || rel.startsWith("../")) {
      outside = true;
      continue;
    }
    const entry = ctx.fs.stat(rel);
    if (entry.ok) return "found";
    if (entry.reason === "outside-root") outside = true;
    else if (entry.reason === "not-found") missing = true;
    else unknown = true;
  }
  if (outside) return EXTERNAL;
  return missing && !unknown ? BROKEN : "unknown";
}

// URLs, mailto:, protocol-relative links, www. names, @-scoped names, globs, placeholders.
function isNotAPath(token) {
  if (token.startsWith("@") || token.startsWith("//") || WWW.test(token)) return true;
  if (SCHEME.test(token) && !DRIVE.test(token)) return true;
  return GLOB.test(token) || PLACEHOLDER.test(token);
}

// A token looks like a path when it has a "/", ends in a known extension, is a drive path, or is a
// backslash path ("\dir\file" or "\\server\share"). A single backslash escape such as "\n" is not one.
function looksLikePath(token) {
  if (token.includes("/") || hasKnownExtension(token) || DRIVE.test(token)) return true;
  return token.startsWith("\\") && token.indexOf("\\", 1) > 0;
}

function hasKnownExtension(token) {
  const base = token.slice(token.lastIndexOf("/") + 1).toLowerCase();
  return EXTENSIONS.some((ext) => {
    if (!base.endsWith(ext)) return false;
    return base.length > ext.length || ext === DOTFILE_EXTENSION;
  });
}

// Absolute (leading "/" or "\", a drive letter) or home ("~") paths. They are never read.
function isExternalForm(token) {
  return token.startsWith("/") || token.startsWith("\\") || token.startsWith("~") || DRIVE.test(token);
}

// The targets of the links of one line. Targets inside code spans are not links.
function linkTargets(text) {
  const masked = maskCodeSpans(text);
  const targets = [];
  for (const match of masked.matchAll(LINK)) {
    const [start, end] = match.indices[1];
    if (masked.slice(start, end).includes(MASK)) continue;
    let target = text.slice(start, end);
    if (target.startsWith("<") && target.endsWith(">")) target = target.slice(1, -1);
    targets.push(target);
  }
  return targets;
}

// ---------------------------------------------------------------------------------------------------
// Commands

// Checks one script call (see script-calls.mjs) against the root package.json.
function checkCommand(state, where, command) {
  const { scripts } = state;
  // A package.json that cannot be read or parsed gives no answer: its commands are not reported.
  if (scripts.status === "absent") {
    reportCommand(state, where, command, "no-package-json");
  } else if (scripts.status === "ok" && !scripts.names.has(command.script)) {
    reportCommand(state, where, command, "missing-script");
  }
}

function reportCommand(state, where, command, reason) {
  state.report({
    file: where.file,
    line: where.line,
    text: command.text,
    kind: "script",
    reason,
    script: command.script,
    status: BROKEN,
  });
}

// The scripts of the root package.json, read as data. "absent" when there is no file. A file that cannot
// be read or parsed is "invalid", with a warning. A missing "scripts" key is an empty list of scripts.
function readScripts(ctx, warnings) {
  const read = readPackageJson(ctx);
  if (read.status === "absent") return { status: "absent" };
  if (read.status === "unreadable") {
    warnings.push({ path: "package.json", reason: "unreadable-package-json" });
    return { status: "invalid" };
  }
  if (read.status === "invalid") {
    warnings.push({ path: "package.json", reason: "invalid-package-json", detail: read.detail });
    return { status: "invalid" };
  }
  const listed = packageScripts(read.data);
  if (!listed.ok) {
    warnings.push({ path: "package.json", reason: "invalid-package-json", detail: listed.detail });
    return { status: "invalid" };
  }
  return { status: "ok", names: new Set(listed.scripts.keys()) };
}

// ---------------------------------------------------------------------------------------------------
// Helpers

function unique(values) {
  return [...new Set(values)];
}

// Sorted by file, line, text, then kind, reason and script, so the order never depends on the walk.
function compareEntries(a, b) {
  return (
    compareText(a.file, b.file) ||
    a.line - b.line ||
    compareText(a.text, b.text) ||
    compareText(a.kind, b.kind) ||
    compareText(a.reason ?? "", b.reason ?? "") ||
    compareText(a.script ?? "", b.script ?? "")
  );
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
