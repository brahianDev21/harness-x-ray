// Script calls in memory text: the npm, npx, pnpm, yarn and bun commands that run a script of package.json.
// The references measure checks each call against the scripts of the target, and the verification measure
// classifies the calls of the scripts it lists. Both read the calls with this module, so they agree on what
// a call is. Nothing here runs a command: the text is only read.
//
// A call is the command at the start of a shell segment, after environment assignments and prompt signs.
// The separators (&&, ||, ;, |, &) split a line into segments. A "#" word starts a shell comment that runs
// to the end of the line. Built-in subcommands of pnpm and yarn are not scripts. npm runs a script with
// "run"; "npm test" is the only shortcut that is read.

import { codeSpans } from "./markdown.mjs";

const MANAGERS = new Set(["npm", "pnpm", "yarn", "bun"]);
// Built-in subcommands of pnpm and yarn. A word that is one of these is not a script.
const BUILT_IN = new Set([
  "install", "i", "add", "remove", "rm", "update", "up", "upgrade", "exec", "dlx", "create", "init", "link",
  "unlink", "outdated", "list", "ls", "why", "audit", "publish", "pack", "config", "store", "import", "rebuild",
  "prune", "patch", "info", "view", "login", "logout", "whoami", "version", "help", "cache", "set", "workspace",
  "workspaces", "env", "dedupe", "licenses", "fetch", "setup", "global", "node", "self-update",
]);
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const PROMPTS = new Set(["$", ">", "%"]);
// Shell separators that end a command. A redirection such as 2>&1 splits too, which is harmless here.
const SEPARATORS = /&&|\|\||[;|&]/;
// A "#" that starts a word: the start of a shell comment.
const COMMENT_START = /(^|\s)#/;
const SCRIPT_EDGE_PUNCTUATION = /^["'`(]+/;
const SCRIPT_TRAILING_PUNCTUATION = /[.,;:!?)"'`]+$/;

/**
 * The script calls of one line of memory text, as markdownLines returns it. A fenced line is read as one
 * shell text. Any other line is read through its inline code spans, each one trimmed; prose is not read.
 * @param {{ text: string, fenced: boolean }} line
 * @returns {Array<{ text: string, script: string }>} text is the call as written, from the manager on;
 *   script is the name of the script that it runs.
 */
export function scriptCallsInLine(line) {
  if (line.fenced) return commandsIn(line.text);
  const calls = [];
  for (const span of codeSpans(line.text)) {
    const shown = span.text.trim();
    if (shown !== "") calls.push(...commandsIn(shown));
  }
  return calls;
}

// Each shell segment of the text may hold one command. A "#" word starts a shell comment that runs to the
// end of the line, so the text is cut there before it is split into segments: a separator after the "#" is
// part of the comment.
function commandsIn(text) {
  const found = [];
  const comment = text.search(COMMENT_START);
  const code = comment === -1 ? text : text.slice(0, comment);
  for (const segment of code.split(SEPARATORS)) {
    const command = commandIn(segment.trim().split(/\s+/));
    if (command !== null) found.push(command);
  }
  return found;
}

function commandIn(tokens) {
  let at = 0;
  while (at < tokens.length && (ENV_ASSIGNMENT.test(tokens[at]) || PROMPTS.has(tokens[at]))) at += 1;
  const manager = tokens[at];
  if (!MANAGERS.has(manager)) return null;
  const word = tokens[at + 1];
  let script;
  let last;
  if (word === "run") {
    script = tokens[at + 2];
    last = at + 2;
  } else if (manager === "npm") {
    if (word !== "test") return null;
    script = "test";
    last = at + 1;
  } else if (manager === "bun" || word === undefined || word.startsWith("-") || BUILT_IN.has(word)) {
    return null;
  } else {
    script = word;
    last = at + 1;
  }
  if (script === undefined || script.startsWith("-")) return null;
  const name = script.replace(SCRIPT_EDGE_PUNCTUATION, "").replace(SCRIPT_TRAILING_PUNCTUATION, "");
  if (name === "") return null;
  return { text: tokens.slice(at, last + 1).join(" "), script: name };
}
