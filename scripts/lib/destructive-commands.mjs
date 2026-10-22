// Measure "destructive-commands": what the project's permission rules, defaultMode and PreToolUse hooks would do with each
// command of data/destructive-commands.json, and what a subagent with a shell tool would do with them. It simulates only:
// no command runs and no hook runs. The target is read through loadClaudeConfig, the parser of the claude-config measure,
// and through ctx, never directly.
//
// Output: security.destructiveCoverage = { mode, commands, preToolUseHooks, subagents, matrixModes }. The rules are applied
// by permissions.mjs (evaluate, and evaluateInSessionMode for each command's modes), so every outcome names the rule or
// the mode that decides it.
//
// The standard matrix (commands[].modes) shows each command at the location its data entry gives. The deep matrix
// (createDestructiveCommandsMeasure with deep) adds the three locations of LOCATIONS: each command also gets locations,
// and destructiveCoverage gets matrixLocations. Quick and standard write neither key.
//
// The two cmd commands of the data run as the PowerShell tool runs "cmd /c ...", the form that the docs show for them.
// Their shell is "cmd" and their tool is "PowerShell".
//
// Each entry has coverRule: a Bash or PowerShell rule that covers the command and the same prefix followed by any arguments.
// It does not cover a reordered or respelled form of the command. An entry may have coverNote, a short text that says what else
// the rule covers (for example every curl, not only a pipe into a shell). Both are read by scripts/lib/remediation.mjs, which
// turns them into a fragment, and neither is written to the measurements: commandResult leaves them out.

import fs from "node:fs";
import { loadClaudeConfig } from "./claude-config.mjs";
import { UNDETERMINABLE, coveredTools, hookRunState } from "./hook-matcher.mjs";
import { isPlainObject } from "./json-out.mjs";
import { MATRIX_MODES, decisionRules, evaluate, evaluateInSessionMode, matchBash, parseRule } from "./permissions.mjs";

export { hookFilterState } from "./hook-matcher.mjs";

export const MEASURE_ID = "destructive-commands";

// The data file of the harness, not of the target.
const DATA_URL = new URL("../../data/destructive-commands.json", import.meta.url);
const SHELL_TOOLS = ["Bash", "PowerShell"];
const SHELLS = new Set(["bash", "powershell", "cmd"]);
const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const REQUIRED_FIELDS = [
  "id",
  "shell",
  "tool",
  "command",
  "coverRule",
  "category",
  "insideProject",
  "criticalPath",
  "builtInProtection",
];
// The fields that remediation.mjs reads and that the measurements never carry.
const REMEDIATION_FIELDS = ["coverRule", "coverNote"];
const OPTIONAL_FIELDS = ["parts", "coverNote"];
const COVER_NOTE_MAX = 300;
// The effect of a project defaultMode that the project file applies (see claude-config).
const APPLIED_EFFECT = "applies";
// Main-conversation modes that a subagent runs in, whatever its own permissionMode says (docs: sub-agents).
const INHERITED_MODES = new Set(["acceptEdits", "bypassPermissions", "auto"]);
// The locations of the deep matrix, in the order they are written: the flags that evaluateInSessionMode takes for each.
const LOCATIONS = Object.freeze({
  inside: Object.freeze({ insideProject: true, criticalPath: false }),
  outside: Object.freeze({ insideProject: false, criticalPath: false }),
  critical: Object.freeze({ insideProject: false, criticalPath: true }),
});

let commandsCache = null;

export const destructiveCommandsMeasure = createDestructiveCommandsMeasure();

/**
 * Builds the destructive-commands measure. The standard one (the default) writes the matrix of each command at the
 * location its data entry gives. With deep, it also writes the three locations of LOCATIONS for each command, and
 * matrixLocations. The two levels differ only in those keys.
 * @param {object} [options]
 * @param {boolean} [options.deep] Also write the matrix at the three locations. Default false.
 * @returns {{ id: string, collect: (ctx: object) => object }}
 */
export function createDestructiveCommandsMeasure({ deep = false } = {}) {
  if (typeof deep !== "boolean") throw new TypeError("createDestructiveCommandsMeasure: deep must be a boolean");
  return Object.freeze({ id: MEASURE_ID, collect: (ctx) => collectDestructiveCoverage(ctx, deep) });
}

/**
 * The commands of data/destructive-commands.json, validated. The file is read and checked once per process.
 * The objects are shared: callers must not change them.
 * @returns {object[]}
 */
export function loadDestructiveCommands() {
  commandsCache ??= validateDestructiveData(JSON.parse(fs.readFileSync(DATA_URL, "utf8")));
  return commandsCache;
}

/**
 * Checks the shape of the data file and throws on the first problem, naming the entry.
 * @param {unknown} data The parsed file.
 * @returns {object[]} data.commands.
 */
export function validateDestructiveData(data) {
  if (!isPlainObject(data) || !Array.isArray(data.commands) || data.commands.length === 0) {
    throw new Error("destructive-commands: the data must be an object with a non-empty commands list");
  }
  const ids = new Set();
  data.commands.forEach((entry, index) => {
    const where = `destructive-commands: commands[${index}]`;
    validateEntry(entry, where);
    if (ids.has(entry.id)) throw new Error(`${where}: duplicate id "${entry.id}"`);
    ids.add(entry.id);
  });
  return data.commands;
}

function validateEntry(entry, where) {
  if (!isPlainObject(entry)) throw new Error(`${where} is not an object`);
  const known = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);
  for (const key of Object.keys(entry)) {
    if (!known.has(key)) throw new Error(`${where} has the unknown field "${key}"`);
  }
  for (const key of REQUIRED_FIELDS) {
    if (!Object.hasOwn(entry, key)) throw new Error(`${where} has no "${key}"`);
  }
  if (!isKebab(entry.id)) throw new Error(`${where}: id must be kebab-case`);
  if (!SHELLS.has(entry.shell)) throw new Error(`${where}: shell must be bash, powershell or cmd`);
  if (!SHELL_TOOLS.includes(entry.tool)) throw new Error(`${where}: tool must be Bash or PowerShell`);
  // bash runs in the Bash tool; powershell and cmd run in the PowerShell tool.
  if ((entry.shell === "bash") !== (entry.tool === "Bash")) {
    throw new Error(`${where}: shell "${entry.shell}" does not match tool "${entry.tool}"`);
  }
  if (!isNonBlank(entry.command)) throw new Error(`${where}: command must be a non-blank string`);
  if (entry.shell === "cmd" && !entry.command.startsWith("cmd /c ")) {
    throw new Error(`${where}: a cmd command must start with "cmd /c "`);
  }
  if (Object.hasOwn(entry, "parts")) {
    // Only a compound command has parts: at least two simple commands, each one not blank.
    if (!Array.isArray(entry.parts) || entry.parts.length < 2 || !entry.parts.every(isNonBlank)) {
      throw new Error(`${where}: parts must be two or more non-blank commands`);
    }
  }
  validateCoverRule(entry, where);
  if (!isNonBlank(entry.coverRule)) throw new Error(`${where}: coverRule must be a non-blank string`);
  if (Object.hasOwn(entry, "coverNote") && (!isNonBlank(entry.coverNote) || entry.coverNote.length > COVER_NOTE_MAX)) {
    throw new Error(`${where}: coverNote must be a non-blank string of at most ${COVER_NOTE_MAX} characters`);
  }
  if (!isKebab(entry.category)) throw new Error(`${where}: category must be kebab-case`);
  if (typeof entry.insideProject !== "boolean") throw new Error(`${where}: insideProject must be a boolean`);
  if (typeof entry.criticalPath !== "boolean") throw new Error(`${where}: criticalPath must be a boolean`);
  if (entry.builtInProtection !== null && !isKebab(entry.builtInProtection)) {
    throw new Error(`${where}: builtInProtection must be null or kebab-case`);
  }
}

// The rule must parse as a Bash or PowerShell rule of the command's tool, with a specifier, and it must match the command: its
// text, or one of its parts for a compound command. Only a rule that does not parse, or that names another tool, is refused.
function validateCoverRule(entry, where) {
  const rule = parseRule(entry.coverRule);
  if (!rule.ok || rule.skipped === true || rule.specifier === null) {
    throw new Error(`${where}: coverRule must be a Bash or PowerShell rule with a specifier`);
  }
  if (rule.tool !== entry.tool) throw new Error(`${where}: coverRule must name the tool "${entry.tool}"`);
  const caseInsensitive = entry.tool === "PowerShell";
  const subjects = Object.hasOwn(entry, "parts") ? entry.parts : [entry.command];
  if (!subjects.some((text) => matchBash(rule.specifier, text, { caseInsensitive }))) {
    throw new Error(`${where}: coverRule does not match the command`);
  }
}

function isKebab(value) {
  return typeof value === "string" && KEBAB_CASE.test(value);
}

function isNonBlank(value) {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * The shell tools (Bash, PowerShell) that a PreToolUse matcher covers (docs: hooks). See coveredTools in hook-matcher.mjs.
 * @param {string | null} matcher
 * @returns {string[] | "undeterminable"}
 */
export function toolsCoveredBy(matcher) {
  return coveredTools(matcher, SHELL_TOOLS);
}

// ---------------------------------------------------------------------------------------------------

// Reads the parsed configuration and the data, and simulates every command with the project's rules. The rules include the
// user layer's when it was read (decisionRules). The mode is the project's defaultMode only: the user's is not applied.
// deep adds the locations of the matrix (see createDestructiveCommandsMeasure).
function collectDestructiveCoverage(ctx, deep) {
  const config = loadClaudeConfig(ctx);
  const commands = loadDestructiveCommands();
  const rules = decisionRules(config.permissions, ctx.outside);
  const defaultMode = config.permissions.defaultMode;
  const mode = defaultMode === null ? null : defaultMode.value;
  // The main conversation runs in the project mode only when the project file may apply it; otherwise in default.
  const mainMode = defaultMode !== null && defaultMode.effect === APPLIED_EFFECT ? modeName(defaultMode.value) : "default";
  const hooks = preToolUseEntries(config.hooks);

  const destructiveCoverage = {
    mode: defaultMode === null ? null : { ...defaultMode },
    commands: commands.map((command) => commandResult(command, rules, mode, hooks, deep)),
    preToolUseHooks: hooks.map(hookOutput),
    subagents: subagentsOf(config.subagents, rules, commands, mainMode),
    matrixModes: [...MATRIX_MODES],
  };
  // Only the deep level names its locations, so a standard run writes the same keys as before.
  if (deep) destructiveCoverage.matrixLocations = Object.keys(LOCATIONS);
  return { security: { destructiveCoverage } };
}

// The outcome of one command with the project rules and mode, and whether a PreToolUse hook runs for it.
function commandResult(command, rules, mode, hooks, deep) {
  const call = callOf(command);
  const verdict = evaluate(rules, call, { mode, insideProject: command.insideProject, criticalPath: command.criticalPath });
  return {
    ...measuredFields(command),
    outcome: verdict.outcome,
    decidedBy: verdict.decidedBy,
    reason: verdict.reason,
    preToolUseHook: hookStateOf(hooks, call),
    modes: modeOutcomes(command, rules),
    ...(deep ? { locations: locationOutcomes(command, rules) } : {}),
  };
}

// The outcome of the command in a session started in each mode of the matrix (see evaluateInSessionMode), keyed by mode
// in the order of MATRIX_MODES. The session mode is not the project defaultMode, and no hook is taken into account.
// location gives the flags of the place where the command runs: by default, the command's own entry in the data.
function modeOutcomes(command, rules, location = command) {
  const call = callOf(command);
  const options = { insideProject: location.insideProject, criticalPath: location.criticalPath };
  return Object.fromEntries(
    MATRIX_MODES.map((mode) => [mode, evaluateInSessionMode(rules, call, { ...options, mode }).outcome]),
  );
}

// The deep matrix: the modes of the command at each location of LOCATIONS, keyed by location. The standard matrix shows
// the command at the location its data entry gives. dontAsk and plan stay out of both matrices for the reason given in
// permissions.mjs (MATRIX_MODES).
function locationOutcomes(command, rules) {
  return Object.fromEntries(Object.entries(LOCATIONS).map(([name, flags]) => [name, modeOutcomes(command, rules, flags)]));
}

// The fields of a command that the measurements write: every field of the data entry but the remediation ones.
function measuredFields(command) {
  return Object.fromEntries(Object.entries(command).filter(([key]) => !REMEDIATION_FIELDS.includes(key)));
}

// The call that permissions.mjs simulates. parts is given only for a compound command.
function callOf(command) {
  return command.parts === undefined
    ? { tool: command.tool, command: command.command }
    : { tool: command.tool, command: command.command, parts: command.parts };
}

// The PreToolUse hooks whose matcher can cover a shell tool, with the tools that they cover.
function preToolUseEntries(hooks) {
  return hooks
    .filter((hook) => hook.event === "PreToolUse")
    .map((hook) => ({ hook, tools: toolsCoveredBy(hook.matcher) }))
    .filter(({ tools }) => tools === UNDETERMINABLE || tools.length > 0);
}

function hookOutput({ hook, tools }) {
  return {
    source: hook.source,
    matcher: hook.matcher,
    if: hook.if,
    type: hook.type,
    command: hook.command,
    script: hook.script,
    onFailure: hook.onFailure,
    failsOpen: hook.failsOpen,
    tools,
  };
}

// Whether at least one PreToolUse hook runs for the call. It is undeterminable when no hook surely runs but one of them
// cannot be settled.
function hookStateOf(hooks, call) {
  const states = hooks.map(({ hook, tools }) => hookRunState(hook, tools, call));
  if (states.includes("runs")) return "runs";
  return states.includes(UNDETERMINABLE) ? UNDETERMINABLE : "none";
}

// The subagents that have a shell tool and a permissionMode, with the outcome of each command inside them. Claude Code
// skips a subagent without a name, so it is not listed.
function subagentsOf(subagents, rules, commands, mainMode) {
  const listed = [];
  for (const agent of subagents) {
    if (agent.name === null || agent.permissionMode === null) continue;
    const shellTools = shellToolsOf(agent);
    if (shellTools.length === 0) continue;
    const { effectiveMode, ignoredMode } = effectiveSubagentMode(mainMode, agent.permissionMode);
    const item = {
      path: agent.path,
      name: agent.name,
      permissionMode: agent.permissionMode,
      effectiveMode,
      shellTools,
      results: commands
        .filter((command) => shellTools.includes(command.tool))
        .map((command) => subagentResult(command, rules, effectiveMode)),
    };
    if (ignoredMode !== undefined) item.ignoredMode = ignoredMode;
    listed.push(item);
  }
  return listed;
}

function subagentResult(command, rules, mode) {
  const verdict = evaluate(rules, callOf(command), { mode, insideProject: command.insideProject, criticalPath: command.criticalPath });
  return { id: command.id, outcome: verdict.outcome, decidedBy: verdict.decidedBy, reason: verdict.reason };
}

// The shell tools that a subagent has (docs: sub-agents). Omitted tools means every tool. A tool in disallowedTools is
// removed whole, even when its entry has a specifier. A tools value that is neither a string nor a list reads as omitted.
function shellToolsOf(agent) {
  const listed = agent.tools === null ? SHELL_TOOLS : toolNames(agent.tools);
  const removed = agent.disallowedTools === null ? [] : toolNames(agent.disallowedTools);
  return SHELL_TOOLS.filter((tool) => listed.includes(tool) && !removed.includes(tool));
}

// The tool names of a tools value: a comma-separated string or a list. A specifier in parentheses is dropped.
function toolNames(value) {
  const entries = typeof value === "string" ? splitList(value) : value;
  return entries.map((entry) => entry.split("(")[0].trim()).filter((name) => name !== "");
}

// Splits a comma-separated list. A comma inside parentheses belongs to a specifier.
function splitList(text) {
  const parts = [];
  let depth = 0;
  let current = "";
  for (const char of text) {
    if (char === "(") depth += 1;
    if (char === ")") depth = Math.max(0, depth - 1);
    if (char === "," && depth === 0) {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

// The mode a subagent runs in, and the value of its own permissionMode that does not apply (docs: sub-agents). Under
// acceptEdits the main mode applies and the subagent's own mode is ignored. Under default, dontAsk or plan the subagent
// runs in its own mode, except bypassPermissions (the main mode applies) and auto. Whether auto is available is not
// known here, so that mode is undeterminable.
function effectiveSubagentMode(main, own) {
  const ownMode = modeName(own);
  if (INHERITED_MODES.has(main)) {
    return ownMode === main ? { effectiveMode: main } : { effectiveMode: main, ignoredMode: own };
  }
  if (own === "bypassPermissions") return { effectiveMode: main, ignoredMode: own };
  if (own === "auto") return { effectiveMode: UNDETERMINABLE };
  return { effectiveMode: ownMode };
}

// manual is the config value of default (docs: permission modes).
function modeName(mode) {
  return mode === "manual" ? "default" : mode;
}
