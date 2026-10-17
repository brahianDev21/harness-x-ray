// Reads the command of a hook handler without running it. It splits the command into words the way a
// shell would, finds the script that the command runs, and classifies that script's path. Nothing
// here executes anything or touches the file system: the caller checks whether the script exists.

import path from "node:path";

// A word made only of shell operators, such as "&&", ";" or "|".
const OPERATOR_WORD = /^[;&|<>]+$/;
const OPERATOR_CHAR = /[;&|<>]/;
const SPACE_CHAR = /\s/;
// The interpreters whose first file argument is the script that runs.
const FAMILY_OF = new Map([
  ["node", "node"],
  ["nodejs", "node"],
  ["python", "python"],
  ["python3", "python"],
  ["py", "python"],
  ["bash", "shell"],
  ["sh", "shell"],
  ["zsh", "shell"],
  ["pwsh", "powershell"],
  ["powershell", "powershell"],
]);
// Options of node and python that take a value in the next word.
const NODE_VALUE_OPTIONS = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions"]);
const PYTHON_VALUE_OPTIONS = new Set(["-W", "-X"]);
const NODE_INLINE_CODE = new Set(["-e", "--eval", "-p", "--print"]);
// $CLAUDE_PROJECT_DIR and ${CLAUDE_PROJECT_DIR}, with an optional default, which Claude Code sets to the project.
const PROJECT_DIR_VARIABLE = /^\$(?:\{CLAUDE_PROJECT_DIR(?::-[^}]*)?\}|CLAUDE_PROJECT_DIR)(?=[\\/]|$)/;

/**
 * The words of a hook command, as a shell would split them. A command in exec form (with args) is its
 * command followed by its args, with no shell. A shell command stops at its first operator, so only
 * the first simple command is read.
 * @param {string} command
 * @param {string[]} [args]
 * @returns {string[]}
 */
export function hookWords(command, args) {
  if (Array.isArray(args)) return [command, ...args];
  const words = splitShellWords(command);
  const stop = words.findIndex((word) => OPERATOR_WORD.test(word));
  return stop === -1 ? words : words.slice(0, stop);
}

/**
 * The path of the script that the command runs, as written, or null when the command runs no script
 * file that this reader can name. For an interpreter (node, python, sh, pwsh...) that is its first
 * file argument. For a command whose first word is a path (./x.sh, .claude/hooks/x.sh) it is that word.
 * @param {string[]} words The output of hookWords.
 * @returns {string | null}
 */
export function findScriptWord(words) {
  const [first, ...rest] = words;
  if (first === undefined || first === "") return null;
  const family = FAMILY_OF.get(interpreterName(first));
  if (family === undefined) return /[\\/]/.test(first) ? first : null;
  return scriptArgument(family, rest);
}

/**
 * Classifies a script path. A path that starts with $CLAUDE_PROJECT_DIR is read as relative to the
 * project. A relative path that stays inside the project is returned as a POSIX path from the project
 * root. Anything absolute, under ~, behind another variable, or resolving outside the project is
 * external, and it is not checked.
 * @param {string} raw The path as written.
 * @returns {{ external: true } | { external: false, rel: string }}
 */
export function classifyScriptPath(raw) {
  let text = raw;
  const variable = PROJECT_DIR_VARIABLE.exec(raw);
  if (variable !== null) text = `.${raw.slice(variable[0].length)}`;
  else if (/^[~$%]/.test(text)) return { external: true };
  const slashed = text.replaceAll("\\", "/");
  if (slashed.startsWith("/") || /^[A-Za-z]:/.test(text)) return { external: true };
  const rel = path.posix.normalize(slashed);
  if (rel === ".." || rel.startsWith("../")) return { external: true };
  return { external: false, rel };
}

// The name of an interpreter from its path: "C:\...\node.exe" is "node". Null for any other word.
function interpreterName(word) {
  const base = word.split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, "");
  return FAMILY_OF.has(base) ? base : null;
}

// The first file argument of an interpreter, or null when the command runs code or a module instead.
function scriptArgument(family, args) {
  if (family === "powershell") {
    const file = args.findIndex((arg) => arg.toLowerCase() === "-file");
    return file === -1 ? null : nonEmpty(args[file + 1]);
  }
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (family === "node" && NODE_INLINE_CODE.has(arg)) return null;
    if (family === "python" && (arg === "-c" || arg === "-m")) return null;
    if (family === "shell" && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg)) return null;
    if (family === "node" && NODE_VALUE_OPTIONS.has(arg)) index += 1;
    else if (family === "python" && PYTHON_VALUE_OPTIONS.has(arg)) index += 1;
    else if (arg.startsWith("-")) continue;
    else return nonEmpty(arg);
  }
  return null;
}

function nonEmpty(word) {
  return word === undefined || word === "" || word === "-" ? null : word;
}

// Splits a command the way a POSIX shell does for plain words: spaces separate words, single and double
// quotes group them and are removed, and runs of ;&|<> become operator words. A backslash is an ordinary
// character, so Windows paths survive. Nothing is expanded.
function splitShellWords(text) {
  const words = [];
  let word = null;
  let quote = null;
  let inOperator = false;
  for (const char of text) {
    if (quote !== null) {
      if (char === quote) quote = null;
      else word += char;
    } else if (char === '"' || char === "'") {
      word = word ?? "";
      quote = char;
      inOperator = false;
    } else if (OPERATOR_CHAR.test(char)) {
      if (word !== null) {
        words.push(word);
        word = null;
      }
      if (inOperator) words[words.length - 1] += char;
      else words.push(char);
      inOperator = true;
    } else if (SPACE_CHAR.test(char)) {
      if (word !== null) {
        words.push(word);
        word = null;
      }
      inOperator = false;
    } else {
      word = `${word ?? ""}${char}`;
      inOperator = false;
    }
  }
  if (word !== null) words.push(word);
  return words.filter((item) => item !== "");
}
