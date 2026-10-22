// Simulates Claude Code's permission rules for one call: would this rule set let this command, file access,
// domain or MCP tool through? It reimplements only the documented rule syntax (Bash and PowerShell patterns,
// Read and Edit gitignore paths, WebFetch domains, MCP names) and the effect of defaultMode on Bash and
// PowerShell calls. It is pure: it reads no file, runs no process and imports nothing. Every case it cannot
// settle is "undeterminable", never allow, deny, passes or blocked.

// Characters that split a shell command into several (docs: compound commands). `$(` opens a substitution.
const COMPOUND_CHARS = /[;&|<>`\r\n]|\$\(/;
// Wrappers that Claude Code strips before it matches a Bash rule (docs: wrappers). Not configurable.
const WRAPPERS = new Set(["timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob", "xargs"]);
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
// Parameter rules name a top-level input field (docs: match by input parameter). run_in_background is undeterminable
// in deny and ask rules. Claude Code ignores command: rules (with a startup warning), so they never match.
const PARAMETER_RULE = /^\s*run_in_background\s*:/;
const IGNORED_PARAMETER_RULE = /^\s*command\s*:/;
// Built-in read-only commands, which run without a prompt in every mode (docs: read-only commands).
const READ_ONLY = new Set(["ls", "cat", "echo", "pwd", "head", "tail", "grep", "find", "wc", "which", "diff", "stat", "du", "cd"]);
// Bash commands that acceptEdits approves inside the project (docs: acceptEdits mode: mkdir, touch, rm, rmdir, mv, cp
// and sed inside the working directory).
const ACCEPT_EDITS_BASH = new Set(["mkdir", "touch", "rm", "rmdir", "mv", "cp", "sed"]);
// PowerShell commands that the matrix treats as approved by acceptEdits inside the project, with their aliases. NOT
// VERIFIED: the cited acceptEdits note names none of them (it names only the Bash commands above), so they are pending
// verification: set-content, add-content, clear-content and remove-item.
const ACCEPT_EDITS_POWERSHELL = new Set(["set-content", "add-content", "clear-content", "remove-item"]);
// Standard PowerShell aliases, lowercase. Matching canonicalizes them, so a rule or call that uses one is not settled.
const POWERSHELL_ALIASES = new Set([
  "ls", "dir", "gci", "rm", "del", "erase", "rd", "rmdir", "ri", "cp", "copy", "cpi", "mv", "move", "mi",
  "cat", "gc", "type", "sc", "ac", "clc", "echo", "cd", "chdir", "pwd", "cls", "clear", "sls", "ps", "kill",
  "sort", "select", "where", "foreach",
]);
// Removal commands that critical paths guard (docs: critical paths).
const REMOVAL_COMMANDS = new Set(["rm", "rmdir"]);
// Modes that Claude Code ignores when a project settings file sets them (docs: permission modes).
const IGNORED_MODES = new Set(["auto", "bypassPermissions"]);
// The session modes of the permission matrix, in the order they are reported. The cited notes say what acceptEdits
// approves (mkdir, touch, rm, rmdir, mv, cp and sed inside the working directory), that deny applies in every mode,
// that auto is decided by a model classifier, and that project settings ignore auto and bypassPermissions. What
// bypassPermissions passes without a rule (the critical-path gate for removals) is a repo choice, not note content.
// dontAsk is left out: no note names what it approves. plan is left out too: that its outcome depends on the session
// is a repo choice, not note content. The matrix does not simulate hooks.
export const MATRIX_MODES = Object.freeze(["default", "acceptEdits", "auto", "bypassPermissions"]);
const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
const KIND_OF_TOOL = new Map([
  ["Bash", "bash"],
  ["PowerShell", "powershell"],
  ["Read", "path"],
  ["Edit", "path"],
  ["WebFetch", "webfetch"],
]);
const LIST_REASON = { deny: "deny-rule", ask: "ask-rule", allow: "allow-rule" };
const NONE = Object.freeze({ state: "none" });
const MATCH = Object.freeze({ state: "match" });
// A `!` path rule that covers the path: it makes the whole list undeterminable (see scanList).
const NEGATION_UNKNOWN = Object.freeze({ state: "unknown", reason: "negation-rule", neg: true });

/**
 * Parses one permission rule, `Tool` or `Tool(specifier)`. The specifier starts at the first "(" and ends at the
 * final ")", so parentheses inside it are literal (docs: permission rule syntax). The kind says how the rule is
 * matched: bash, powershell, path (Read, Edit), webfetch, mcp, tool-glob (a tool-name glob), parameter,
 * ignored-parameter, other
 * (any other tool, which never matches the calls this module simulates) or unsupported.
 * @param {string} text
 * @returns {{ ok: true, tool: string, specifier: string | null, kind: string, skipped?: true } | { ok: false, reason: string }}
 */
export function parseRule(text) {
  if (typeof text !== "string" || text === "") return { ok: false, reason: "empty-rule" };
  const open = text.indexOf("(");
  let tool = text;
  let specifier = null;
  if (open !== -1) {
    if (!text.endsWith(")")) return { ok: false, reason: "missing-closing-parenthesis" };
    tool = text.slice(0, open);
    specifier = text.slice(open + 1, -1);
    if (specifier === "") return { ok: false, reason: "empty-specifier" };
  }
  if (tool === "") return { ok: false, reason: "empty-tool-name" };
  return { ok: true, tool, specifier, ...classify(tool, specifier) };
}

// The kind of a parsed rule. An mcp__ rule with parentheses is skipped by Claude Code when it loads settings (docs: MCP).
function classify(tool, specifier) {
  if (tool.startsWith("mcp__") && specifier !== null) return { kind: "mcp", skipped: true };
  if (tool.includes("*")) return { kind: specifier === null ? "tool-glob" : "unsupported" };
  if (tool.startsWith("mcp__")) return { kind: "mcp" };
  if (specifier !== null && SHELL_TOOLS.has(tool) && PARAMETER_RULE.test(specifier)) return { kind: "parameter" };
  if (specifier !== null && SHELL_TOOLS.has(tool) && IGNORED_PARAMETER_RULE.test(specifier)) {
    return { kind: "ignored-parameter" };
  }
  return { kind: KIND_OF_TOOL.get(tool) ?? "other" };
}

/**
 * Matches a Bash pattern against one command (docs: wildcard patterns). `*` matches any text, including spaces,
 * at any position. A trailing `:*` equals a trailing ` *`, and a trailing ` *` that is the only wildcard also
 * matches the bare command. Any other colon is literal. PowerShell matching is case-insensitive.
 * @param {string} pattern
 * @param {string} command
 * @param {{ caseInsensitive?: boolean }} [options]
 * @returns {boolean}
 */
export function matchBash(pattern, command, options = {}) {
  const text = pattern.endsWith(":*") ? `${pattern.slice(0, -2)} *` : pattern;
  const stars = text.split("*").length - 1;
  const source =
    stars === 1 && text.endsWith(" *")
      ? `^${escapeRegex(text.slice(0, -2))}(?: [\\s\\S]*)?$`
      : `^${text.split("*").map(escapeRegex).join("[\\s\\S]*")}$`;
  return new RegExp(source, options.caseInsensitive === true ? "i" : "").test(command);
}

// Escapes literal text for a regular expression.
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// A gitignore pattern as a regular expression over a POSIX path relative to the project root. `*` stays in one
// segment, `?` is one character and `**` spans segments. Null when a segment is empty or a dot segment.
function gitignoreRegex(body, anchored) {
  const segments = body.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) return null;
  let source = "";
  segments.forEach((segment, index) => {
    const last = index === segments.length - 1;
    if (segment === "**") source += last ? ".*" : "(?:.*/)?";
    else source += `${segmentRegex(segment)}${last ? "" : "/"}`;
  });
  return new RegExp(`^${anchored ? "" : "(?:.*/)?"}${source}$`);
}

// One path segment: `*` is any run of characters inside it, `?` is one character.
function segmentRegex(segment) {
  return segment
    .split("")
    .map((char) => (char === "*" ? "[^/]*" : char === "?" ? "[^/]" : escapeRegex(char)))
    .join("");
}

// Whether a pattern covers the path or one of its folders, as gitignore does: a folder matched by the pattern
// covers everything under it. Null when the pattern is not usable.
function patternCovers(body, anchored, path) {
  const regex = gitignoreRegex(body, anchored);
  if (regex === null) return null;
  const parts = path.split("/");
  for (let end = 1; end <= parts.length; end += 1) {
    if (regex.test(parts.slice(0, end).join("/"))) return true;
  }
  return false;
}

// A relative pattern with no `/` before its end matches at any depth. A pattern with a `/` in the middle is anchored
// at the project root. The exception from the docs: a single folder glob such as `src/**` is anchored in allow rules
// and matches at any depth in deny and ask rules.
function relativeAnchored(list, spec) {
  const trimmed = spec.replace(/\/+$/, "");
  if (!trimmed.includes("/")) return false;
  return list === "allow" || !/^[^/]+\/\*\*$/.test(trimmed);
}

// The folder of a settings file, relative to the project root, as a POSIX path ("" for the root). Null when it is
// not inside the project (docs: Read and Edit, the /path row of the anchor table).
function anchorDirectory(anchor) {
  if (typeof anchor !== "string") return null;
  const dir = anchor.replace(/\/+$/, "");
  if (dir === "") return "";
  const unsafe = dir.startsWith("/") || dir.startsWith("~") || /^[A-Za-z]:/.test(dir);
  if (unsafe || dir.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) return null;
  return dir;
}

// The state of a pattern that is usable as it is, with its anchoring decided by the caller.
function covered(body, anchored, path) {
  const cover = patternCovers(body.replace(/\/+$/, ""), anchored, path);
  if (cover === null) return unknown("unsupported-pattern");
  return cover ? MATCH : NONE;
}

// A `!` pattern carves paths out of the rules before it. It is not simulated. If it covers the path, or cannot be
// read, the whole list is undeterminable. The pattern is read relative to the project root, even with a prefix.
function negationState(list, inner, path) {
  if (list === "allow") return NONE;
  const body = inner.replace(/^\/+/, "");
  if (body.includes("[") || body.includes("\\")) return NEGATION_UNKNOWN;
  const cover = patternCovers(body.replace(/\/+$/, ""), relativeAnchored(list, body), path);
  return cover === false ? NONE : NEGATION_UNKNOWN;
}

// The state of one Read or Edit path rule for a path (docs: Read and Edit).
function pathRuleState(list, entry, path) {
  const spec = entry.parsed.specifier;
  if (spec === null) return MATCH;
  if (spec.startsWith("!")) return negationState(list, spec.slice(1), path);
  if (spec.includes("[") || spec.includes("\\")) return unknown("unsupported-pattern");
  // Absolute and home patterns are undeterminable, except the evident matches: `//**` covers the whole filesystem,
  // and `//**/<tail>` matches like `**/<tail>`. A literal tail proves nothing: a pattern can name an ancestor folder
  // of the project root.
  if (spec.startsWith("//")) {
    const rest = spec.slice(2);
    if (rest === "**") return MATCH;
    return rest.startsWith("**/") ? covered(rest, false, path) : unknown("absolute-path-rule");
  }
  if (spec.startsWith("~/")) return unknown("home-path-rule");
  if (spec.startsWith("/")) {
    if (entry.anchor === null) return unknown("anchor-unknown");
    const dir = anchorDirectory(entry.anchor);
    if (dir === null) return unknown("anchor-outside-project");
    return covered(dir === "" ? spec.slice(1) : `${dir}/${spec.slice(1)}`, true, path);
  }
  if (spec.startsWith("./")) return covered(spec.slice(2), true, path);
  return covered(spec, relativeAnchored(list, spec), path);
}

// WebFetch domain rules (docs: WebFetch). Case-insensitive, a trailing dot is ignored, `*.x` matches any subdomain
// depth but not x itself, and any other `*` matches within one label.
function webfetchState(rule, domain) {
  if (rule.specifier === null) return MATCH;
  if (!rule.specifier.startsWith("domain:")) return unknown("unsupported-pattern");
  const pattern = normalizeHost(rule.specifier.slice("domain:".length));
  const host = normalizeHost(domain);
  if (pattern === "" || host === "") return unknown("empty-domain");
  if (pattern === "*") return MATCH;
  // A leading `*.` is one or more labels, at any depth, and it never matches the apex. Any other `*` is within one label.
  const subdomains = pattern.startsWith("*.") ? "(?:[^.]+\\.)+" : "";
  const rest = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
  const regex = new RegExp(`^${subdomains}${rest.split("*").map(escapeRegex).join("[^.]*")}$`);
  return regex.test(host) ? MATCH : NONE;
}

function normalizeHost(text) {
  return text.trim().toLowerCase().replace(/\.$/, "");
}

// An MCP rule without a tool part covers every tool of the server. A rule with a tool part names one tool. A server
// name that contains "__" is read as that one tool, as the docs say for allow rules.
function mcpRuleMatches(ruleName, toolName) {
  const rest = ruleName.slice("mcp__".length);
  if (rest === "") return false;
  return rest.includes("__") ? toolName === ruleName : toolName.startsWith(`mcp__${rest}__`);
}

// A tool-name glob matches the whole tool name. In an allow list it counts only after a literal `mcp__<server>__`
// prefix, and otherwise approves nothing (docs: tool name wildcards).
function toolGlobState(list, glob, toolName) {
  if (list === "allow" && !/^mcp__.+?__/.test(glob.slice(0, glob.indexOf("*")))) return NONE;
  return toolGlobRegex(glob).test(toolName) ? MATCH : NONE;
}

function toolGlobRegex(glob) {
  return new RegExp(`^${glob.split("*").map(escapeRegex).join("[\\s\\S]*")}$`);
}

// The first word of a command, as written.
function leadWord(unit) {
  return unit.trim().split(/\s+/)[0];
}

// The command name for the read-only and removal checks: its last path segment, lowercase in PowerShell.
function commandName(unit, powershell) {
  const name = leadWord(unit).split(/[\\/]/).pop();
  return powershell ? name.toLowerCase() : name;
}

// A Bash command that starts with a wrapper or a leading NAME=value assignment (docs: wrappers).
function hasWrapperOrEnv(unit) {
  const word = leadWord(unit);
  return WRAPPERS.has(word) || ENV_ASSIGNMENT.test(word);
}

// One Bash or PowerShell rule against one simple command. `unit` is that command. A rule with a specifier that
// cannot be matched to a command, or whose command is wrapped or aliased, is undeterminable.
function shellUnitState(rule, unit, tool) {
  if (COMPOUND_CHARS.test(unit)) return unknown("compound-command");
  const powershell = tool === "PowerShell";
  if (powershell) {
    const ruleWord = rule.specifier.trim().split(/\s+/)[0].toLowerCase();
    if (POWERSHELL_ALIASES.has(leadWord(unit).toLowerCase()) || POWERSHELL_ALIASES.has(ruleWord)) {
      return unknown("powershell-alias");
    }
  } else if (hasWrapperOrEnv(unit)) {
    return unknown("wrapper-or-env-prefix");
  }
  return matchBash(rule.specifier, unit, { caseInsensitive: powershell }) ? MATCH : NONE;
}

// A Bash or PowerShell rule against a call. `unit` is one simple command, or null for a compound command that the
// caller gave no parts for. Bare rules (`Bash`, `Bash(*)`) match every command, compound or not.
function shellEntryState(list, rule, call, unit) {
  if (rule.tool !== call.tool) return NONE;
  if (rule.kind === "parameter") return list === "allow" ? NONE : unknown("parameter-rule");
  if (rule.kind !== KIND_OF_TOOL.get(call.tool)) return NONE;
  if (rule.specifier === null || rule.specifier === "*") return MATCH;
  if (unit === null) return unknown("compound-command");
  return shellUnitState(rule, unit, call.tool);
}

// A Read or Edit rule against a path. A Read deny rule also blocks Edit (docs: Read and Edit). A Read ask rule has
// no documented effect on Edit: for an Edit call it is undeterminable where it covers the path, and a non-match elsewhere.
function pathEntryState(list, entry, call) {
  const rule = entry.parsed;
  if (rule.kind !== "path") return NONE;
  if (rule.tool !== call.tool) {
    if (rule.tool !== "Read" || list === "allow") return NONE;
    if (list === "ask") {
      const state = pathRuleState(list, entry, call.path);
      return state.state === "match" ? unknown("read-ask-for-edit") : state;
    }
  }
  return pathRuleState(list, entry, call.path);
}

// The state of one rule for one call, or for one part of a call. Its list (deny, ask or allow) matters only for
// the tool-name globs and for the list-specific rules above.
function entryState(list, entry, call, unit) {
  const rule = entry.parsed;
  if (!rule.ok) return unknown("malformed-rule");
  if (rule.kind === "tool-glob") return toolGlobState(list, rule.tool, call.tool);
  if (rule.kind === "unsupported") {
    return toolGlobRegex(rule.tool).test(call.tool) ? unknown("unsupported-pattern") : NONE;
  }
  if (rule.kind === "mcp") {
    return !rule.skipped && call.tool.startsWith("mcp__") && mcpRuleMatches(rule.tool, call.tool) ? MATCH : NONE;
  }
  // Claude Code ignores command: rules (docs: match by input parameter), so they match nothing.
  if (rule.kind === "ignored-parameter") return NONE;
  if (SHELL_TOOLS.has(call.tool)) return shellEntryState(list, rule, call, unit);
  if (call.tool === "Read" || call.tool === "Edit") return pathEntryState(list, entry, call);
  if (call.tool === "WebFetch") return rule.kind === "webfetch" ? webfetchState(rule, call.domain) : NONE;
  return NONE;
}

function unknown(reason) {
  return { state: "unknown", reason };
}

// The state of one list for one call or one part. A rule that matches decides. A `!` rule that covers the path makes
// the whole list undeterminable. Otherwise an undeterminable rule makes the list undeterminable.
function scanList(list, entries, call, unit) {
  let match = null;
  let unresolved = null;
  for (const entry of entries) {
    const state = entryState(list, entry, call, unit);
    if (state.neg === true) return { state: "unknown", rule: entry.rule, source: entry.source, reason: state.reason };
    if (state.state === "match" && match === null) match = { state: "match", rule: entry.rule, source: entry.source };
    if (state.state === "unknown" && unresolved === null) {
      unresolved = { state: "unknown", rule: entry.rule, source: entry.source, reason: state.reason };
    }
  }
  return match ?? unresolved ?? NONE;
}

// An allow rule approves a compound command only when every part is approved by some allow rule.
function allowAllParts(results) {
  if (results.some((result) => result.state === "none")) return NONE;
  if (results.every((result) => result.state === "match")) {
    return { state: "match", rule: results.map((result) => result.rule).join(" && "), source: results[0].source };
  }
  return results.find((result) => result.state === "unknown");
}

// The state of one list for a call. With parts, deny and ask match when any part matches, and allow needs every part.
function listResult(list, entries, call, units) {
  if (units === null || units.length === 1) return scanList(list, entries, call, units === null ? null : units[0]);
  const results = units.map((unit) => scanList(list, entries, call, unit));
  if (list === "allow") return allowAllParts(results);
  return results.find((result) => result.state === "match") ?? results.find((result) => result.state === "unknown") ?? NONE;
}

// Normalizes a list of rules: plain strings, or objects with rule, source and anchor. A missing anchor is the project
// root (""); a null anchor means the folder is unknown.
function entriesOf(list) {
  if (!Array.isArray(list)) return [];
  return list.map((item) => {
    const entry =
      typeof item === "string"
        ? { rule: item, source: null, anchor: "" }
        : { rule: item?.rule, source: item?.source ?? null, anchor: item?.anchor === undefined ? "" : item.anchor };
    return { ...entry, parsed: parseRule(entry.rule) };
  });
}

// The simple commands to match: the caller's parts when given, else the command itself when it has no operator.
// Null for a compound command without parts. A non-shell call has one unit, which is not used.
function unitsOf(call) {
  if (!SHELL_TOOLS.has(call.tool)) return [null];
  if (Array.isArray(call.parts) && call.parts.length > 0 && call.parts.every(isNonBlank)) return call.parts;
  return COMPOUND_CHARS.test(call.command) ? null : [call.command];
}

function isNonBlank(text) {
  return typeof text === "string" && text.trim() !== "";
}

// A call the module cannot simulate is undeterminable, with the reason. Paths must already be relative to the project
// root, in POSIX form and without `.`, `..` or empty segments.
function invalidCall(call) {
  if (call === null || typeof call !== "object") return "invalid-call";
  if (SHELL_TOOLS.has(call.tool)) return isNonBlank(call.command) ? null : "empty-command";
  if (call.tool === "Read" || call.tool === "Edit") return validPath(call.path) ? null : "unsupported-path";
  if (call.tool === "WebFetch") return isNonBlank(call.domain) ? null : "empty-domain";
  if (typeof call.tool === "string" && call.tool.startsWith("mcp__")) return null;
  return "unsupported-call";
}

function validPath(path) {
  if (typeof path !== "string" || path === "" || path.includes("\\") || path.startsWith("/")) return false;
  return !path.split("/").some((segment) => segment === "" || segment === "." || segment === "..");
}

/**
 * Decides one call against the rules, in the order deny, ask, allow (docs: manage permissions). The first list that
 * has a definite match decides. An undeterminable rule in a list stops the decision, because no later list can then
 * be trusted. The result names the rule that decided, or the undeterminable rule.
 * @param {{ allow?: Array<string | { rule: string, source?: string, anchor?: string | null }>, ask?: Array<string | object>, deny?: Array<string | object> }} rules
 * @param {{ tool: string, command?: string, parts?: string[], path?: string, domain?: string }} call
 * @returns {{ decision: "deny" | "ask" | "allow" | "default" | "undeterminable", rule: string | null, source: string | null, reason: string, list: "deny" | "ask" | "allow" | null }}
 */
export function decide(rules, call) {
  const invalid = invalidCall(call);
  if (invalid !== null) return { decision: "undeterminable", rule: null, source: null, reason: invalid, list: null };
  const lists = { deny: entriesOf(rules?.deny), ask: entriesOf(rules?.ask), allow: entriesOf(rules?.allow) };
  const units = unitsOf(call);
  for (const list of ["deny", "ask", "allow"]) {
    const result = listResult(list, lists[list], call, units);
    if (result.state === "match") {
      return { decision: list, rule: result.rule, source: result.source, reason: LIST_REASON[list], list };
    }
    if (result.state === "unknown") {
      return { decision: "undeterminable", rule: result.rule, source: result.source, reason: result.reason, list };
    }
  }
  return { decision: "default", rule: null, source: null, reason: "no-rule-matched", list: null };
}

/**
 * The outcome of one call with the defaultMode applied (docs: permission modes). Only Bash and PowerShell calls
 * are simulated. A deny rule blocks, an ask rule asks (blocked in dontAsk), and an allow rule passes. A critical-path
 * removal asks even when an allow rule matches. Without a rule, the mode decides. A value that a project settings
 * file cannot set (auto, bypassPermissions) is ignored and recorded as ignoredMode.
 * @param {object} rules The same rules as decide.
 * @param {{ tool: string, command?: string, parts?: string[] }} call
 * @param {{ mode?: string | null, insideProject?: boolean, criticalPath?: boolean }} [options]
 *   mode: the defaultMode of the project settings. insideProject: whether every path the command writes is inside
 *   the project. criticalPath: whether the removal target is a critical path. It is needed only when a removal would pass.
 * @returns {{ outcome: "blocked" | "asks" | "passes" | "undeterminable", decidedBy: object | null, reason: string, decision: string }}
 */
export function evaluate(rules, call, options) {
  const opts = options ?? {};
  const mode = opts.mode ?? null;
  if (!SHELL_TOOLS.has(call?.tool)) return verdict("undeterminable", null, "not-a-shell-call", "undeterminable");
  const decided = decide(rules, call);
  if (decided.decision === "deny") return verdict("blocked", ruleBy(decided), decided.reason, decided.decision);
  if (decided.decision === "ask") {
    return verdict(mode === "dontAsk" ? "blocked" : "asks", ruleBy(decided), decided.reason, decided.decision);
  }
  if (decided.decision === "undeterminable") return verdict("undeterminable", ruleBy(decided), decided.reason, decided.decision);
  const units = unitsOf(call);
  const outcome =
    decided.decision === "allow"
      ? verdict("passes", ruleBy(decided), decided.reason, decided.decision)
      : defaultOutcome(call, units, mode, opts, decided);
  if (outcome.outcome !== "passes" || !removesFiles(call, units)) return outcome;
  return criticalGate(mode, opts, decided, outcome);
}

/**
 * The outcome of one call in a session started in one permission mode (docs: permission modes), one of MATRIX_MODES.
 * Unlike evaluate, the mode is the session's own, so auto and bypassPermissions are not ignored. A deny rule blocks in
 * every mode, as the cited docs state. An ask rule asks, and an allow rule passes (with the critical-path gate of
 * evaluate), in every mode too; for auto and bypassPermissions that is NOT VERIFIED against the docs. Without a rule, a
 * compound command without parts or a read-only command is undeterminable. Otherwise default asks, acceptEdits follows
 * acceptEditsOutcome, auto gives classifier (a model decides, so no result is invented), and bypassPermissions passes
 * unless the command removes files and its criticalPath is true or unknown. Hooks are not used.
 * @param {object} rules The same rules as decide.
 * @param {{ tool: string, command?: string, parts?: string[] }} call
 * @param {{ mode: string, insideProject?: boolean, criticalPath?: boolean }} options mode is the session mode. The other
 *   fields mean what they mean in evaluate.
 * @returns {{ outcome: "blocked" | "asks" | "passes" | "classifier" | "undeterminable", decidedBy: object | null, reason: string, decision: string }}
 */
export function evaluateInSessionMode(rules, call, options) {
  const opts = options ?? {};
  const mode = opts.mode;
  if (!SHELL_TOOLS.has(call?.tool)) return verdict("undeterminable", null, "not-a-shell-call", "undeterminable");
  if (!MATRIX_MODES.includes(mode)) return verdict("undeterminable", null, "unknown-mode", "undeterminable");
  const decided = decide(rules, call);
  if (decided.decision === "deny") return verdict("blocked", ruleBy(decided), decided.reason, decided.decision);
  // NOT VERIFIED for auto and bypassPermissions: the cited docs state only that deny applies in every mode. The ask
  // outcome here, and the allow outcome below, apply in every mode as a repo choice.
  if (decided.decision === "ask") return verdict("asks", ruleBy(decided), decided.reason, decided.decision);
  if (decided.decision === "undeterminable") {
    return verdict("undeterminable", ruleBy(decided), decided.reason, decided.decision);
  }
  const units = unitsOf(call);
  // NOT VERIFIED for auto and bypassPermissions, as the ask outcome above is.
  const outcome =
    decided.decision === "allow"
      ? verdict("passes", ruleBy(decided), decided.reason, decided.decision)
      : sessionDefaultOutcome(call, units, mode, opts, decided);
  if (outcome.outcome !== "passes" || !removesFiles(call, units)) return outcome;
  return criticalGate(mode, opts, decided, outcome);
}

// A removal of a critical path never passes on its own (docs: critical paths). Only a removal that would pass needs
// the criticalPath answer: true asks (blocked in dontAsk), unknown is undeterminable, and false lets it pass.
function criticalGate(mode, options, decided, passed) {
  if (options.criticalPath === false) return passed;
  if (options.criticalPath !== true) return verdict("undeterminable", null, "critical-path-unknown", decided.decision);
  return verdict(mode === "dontAsk" ? "blocked" : "asks", { kind: "critical-path" }, "critical-path-removal", decided.decision);
}

// The outcome when no rule decided. A compound command without parts is undeterminable, and so is a read-only
// command, which runs without a prompt (docs: read-only commands). Otherwise the mode decides.
function defaultOutcome(call, units, mode, options, decided) {
  if (units === null) return verdict("undeterminable", null, "compound-command", decided.decision);
  if (isReadOnly(call, units)) return verdict("undeterminable", null, "read-only-command", decided.decision);
  if (mode === null || mode === "default" || mode === "manual") {
    return verdict("asks", modeBy("default"), "default-mode", decided.decision);
  }
  if (IGNORED_MODES.has(mode)) return verdict("asks", modeBy("default", mode), "ignored-project-mode", decided.decision);
  if (mode === "dontAsk") return verdict("blocked", modeBy(mode), "dont-ask-mode", decided.decision);
  if (mode === "acceptEdits") return acceptEditsOutcome(call, units, options, decided);
  if (mode === "plan") return verdict("undeterminable", modeBy(mode), "plan-mode-depends-on-session", decided.decision);
  return verdict("undeterminable", modeBy(mode), "unknown-mode", decided.decision);
}

// Whether every simple command of the call is a built-in read-only command (docs: read-only commands).
function isReadOnly(call, units) {
  const powershell = call.tool === "PowerShell";
  return units.every((unit) => READ_ONLY.has(commandName(unit, powershell)));
}

// The outcome of a session mode when no rule decided. It has the same compound and read-only checks as defaultOutcome.
// bypassPermissions passes a command, except a removal (rm or rmdir) whose criticalPath is true or unknown, which is
// undeterminable. The cited docs say nothing about how bypassPermissions treats critical paths, so that gate is a repo
// choice, not note content.
function sessionDefaultOutcome(call, units, mode, options, decided) {
  if (units === null) return verdict("undeterminable", null, "compound-command", decided.decision);
  if (isReadOnly(call, units)) return verdict("undeterminable", null, "read-only-command", decided.decision);
  if (mode === "default") return verdict("asks", modeBy("default"), "default-mode", decided.decision);
  if (mode === "acceptEdits") return acceptEditsOutcome(call, units, options, decided);
  if (mode === "auto") return verdict("classifier", modeBy("auto"), "classifier-decides", decided.decision);
  // Only a removal is gated. A command that removes no file passes whatever its criticalPath is.
  if (!removesFiles(call, units) || options.criticalPath === false) {
    return verdict("passes", modeBy(mode), "bypass-mode", decided.decision);
  }
  const reason = options.criticalPath === true ? "bypass-critical-path" : "critical-path-unknown";
  return verdict("undeterminable", modeBy(mode), reason, decided.decision);
}

// acceptEdits approves the common file commands inside the project (docs: acceptEdits mode). A command that could be
// one of them, but cannot be settled here, is undeterminable: a wrapper or assignment prefix, a PowerShell alias, or
// a PowerShell command with a quote character.
function acceptEditsOutcome(call, units, options, decided) {
  const powershell = call.tool === "PowerShell";
  const candidates = units.filter((unit) => maybeAcceptEdits(unit, powershell));
  if (candidates.length === 0) return verdict("asks", modeBy("acceptEdits"), "accept-edits-other-command", decided.decision);
  if (units.length > 1) return verdict("undeterminable", modeBy("acceptEdits"), "accept-edits-compound", decided.decision);
  const unit = units[0];
  if (powershell) {
    if (POWERSHELL_ALIASES.has(leadWord(unit).toLowerCase())) {
      return verdict("undeterminable", modeBy("acceptEdits"), "powershell-alias", decided.decision);
    }
    if (/["']/.test(unit)) return verdict("undeterminable", modeBy("acceptEdits"), "quote-character", decided.decision);
  } else if (hasWrapperOrEnv(unit)) {
    return verdict("undeterminable", modeBy("acceptEdits"), "wrapper-or-env-prefix", decided.decision);
  }
  if (options.insideProject === true) {
    return verdict("passes", modeBy("acceptEdits"), "accept-edits-inside-project", decided.decision);
  }
  if (options.insideProject === false) {
    return verdict("asks", modeBy("acceptEdits"), "accept-edits-outside-project", decided.decision);
  }
  return verdict("undeterminable", modeBy("acceptEdits"), "inside-project-unknown", decided.decision);
}

// Whether a command might be one that acceptEdits approves: a listed command, or one that this module cannot read
// (a wrapper or assignment prefix, a PowerShell alias, or a PowerShell quote character).
function maybeAcceptEdits(unit, powershell) {
  const word = leadWord(unit);
  if (powershell) {
    return /["']/.test(unit) || POWERSHELL_ALIASES.has(word.toLowerCase()) || ACCEPT_EDITS_POWERSHELL.has(word.toLowerCase());
  }
  return hasWrapperOrEnv(unit) || ACCEPT_EDITS_BASH.has(word);
}

// Whether the command may remove files: rm or rmdir as the first word of a part. A compound command without parts
// is checked by its text, which over-matches on purpose (the outcome is only asks or undeterminable).
function removesFiles(call, units) {
  if (units === null) return /\b(?:rm|rmdir)\b/i.test(call.command);
  return units.some((unit) => REMOVAL_COMMANDS.has(commandName(unit, call.tool === "PowerShell")));
}

function ruleBy(decided) {
  return decided.list === null ? null : { kind: "rule", list: decided.list, rule: decided.rule, source: decided.source };
}

function modeBy(mode, ignoredMode) {
  return ignoredMode === undefined ? { kind: "mode", mode } : { kind: "mode", mode, ignoredMode };
}

function verdict(outcome, decidedBy, reason, decision) {
  return { outcome, decidedBy, reason, decision };
}
