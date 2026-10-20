// PreToolUse hook of this repository: blocks a Read, Grep, Bash or PowerShell call that names a secret file.
//
// Claude Code runs it before each call of those tools (see .claude/settings.json) and sends the call as JSON on stdin.
// The hook judges only the names in that JSON, with the patterns of data/secret-patterns.json. It never opens, stats or
// lists a path from the input, and it runs no program.
//
// Exit codes: 0 allows the call and prints nothing. 2 blocks it, and the one line on stderr starts with
// "guard-secret-reads: blocked". Every failure to judge a call also exits 2 (empty or invalid input, a field of the
// wrong type, pattern data that does not load, an unexpected error), so the hook fails closed.
//
// Limits: the hook judges the names in the call, not content. A secret under another name (a copy or a symlink) passes.
// A Grep over a folder, or with a wide glob such as "*" or ".*", can still match lines inside a secret file in it. Glob
// is not covered, because it lists names only. Bash and PowerShell commands are judged as words of text, so shell
// expansion (wildcards, braces, variables, quotes joined to a name) can reach a secret without naming it. This guards
// ordinary commands; it is not a sandbox. Grep globs with braces or brackets are not expanded.

const PATTERNS_URL = new URL("../lib/secret-patterns.mjs", import.meta.url);
// What separates words of a shell command: whitespace, quotes, backticks and the shell operators.
const SEPARATORS = /[\s"'`;|&<>()=,]+/;
const MAX_SHOWN_LENGTH = 120;

// A call the hook cannot judge. Its reason is a fixed text, never part of the input.
class Refusal extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

await main();

async function main() {
  let line = null;
  try {
    line = judge(parseCall(await readStdin()), await loadPatterns());
  } catch (error) {
    const reason = error instanceof Refusal ? error.reason : "unexpected error";
    line = `guard-secret-reads: blocked: ${reason}`;
  }
  if (line !== null) {
    process.stderr.write(`${line}\n`);
    process.exitCode = 2;
  }
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

function parseCall(raw) {
  if (raw.trim() === "") throw new Refusal("stdin is empty");
  let call;
  try {
    call = JSON.parse(raw);
  } catch {
    throw new Refusal("input is not JSON");
  }
  if (!isObject(call)) throw new Refusal("input is not an object");
  if (typeof call.tool_name !== "string") throw new Refusal("tool_name is missing or not a string");
  if (!isObject(call.tool_input)) throw new Refusal("tool_input is not an object");
  return call;
}

// The secret-pattern library, loaded from this file's own location. The data is checked here, so broken data refuses.
async function loadPatterns() {
  try {
    const library = await import(PATTERNS_URL.href);
    library.loadSecretPatterns();
    return library;
  } catch {
    throw new Refusal("pattern data cannot load");
  }
}

// The block line for the call, or null when the call may run.
function judge(call, library) {
  const tool = call.tool_name;
  const input = call.tool_input;
  switch (tool) {
    case "Read": {
      const file = baseName(textOf(input, "file_path", tool, true));
      return blockFor(tool, file, [file], library);
    }
    case "Grep": {
      const path = textOf(input, "path", tool, false);
      const glob = textOf(input, "glob", tool, false);
      if (path !== undefined) {
        const name = baseName(path);
        const line = blockFor(tool, name, [name], library);
        if (line !== null) return line;
      }
      if (glob !== undefined) {
        const name = baseName(glob);
        return blockFor(tool, name, wildcardVariants(name), library);
      }
      return null;
    }
    case "Bash":
    case "PowerShell": {
      for (const word of textOf(input, "command", tool, true).split(SEPARATORS)) {
        if (word === "") continue;
        const name = baseName(word);
        const line = blockFor(tool, name, wildcardVariants(name), library);
        if (line !== null) return line;
      }
      return null;
    }
    default:
      return null;
  }
}

// The block line when one of the candidate names is a secret file name, or null.
function blockFor(tool, shown, candidates, library) {
  for (const candidate of candidates) {
    const kind = library.secretFileKind(candidate);
    if (kind !== null) {
      return `guard-secret-reads: blocked ${tool}: "${printable(shown)}" is a secret file name (${kind}). Secret files are not read in this repository.`;
    }
  }
  return null;
}

// A glob segment or a shell word that may stand for a name: its wildcards removed, and each replaced by a letter.
function wildcardVariants(segment) {
  return [segment.replace(/[*?]/g, ""), segment.replace(/[*?]/g, "x")];
}

// The last segment of a path or a word. Trailing separators are ignored, so "dir/.env/" names ".env".
function baseName(text) {
  return text.replace(/[\\/]+$/, "").split(/[\\/]/).pop();
}

// A field of the tool input. An absent optional field is undefined; a present field must be a string.
function textOf(input, key, tool, required) {
  const value = input[key];
  if (value === undefined) {
    if (required) throw new Refusal(`${tool}: ${key} is missing`);
    return undefined;
  }
  if (typeof value !== "string") throw new Refusal(`${tool}: ${key} is not a string`);
  return value;
}

// Control characters become "?", and a long name is cut, so one line on stderr stays one line.
function printable(name) {
  const clean = name.replace(/[\u0000-\u001f\u007f]/g, "?");
  return clean.length > MAX_SHOWN_LENGTH ? `${clean.slice(0, MAX_SHOWN_LENGTH)}...` : clean;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
