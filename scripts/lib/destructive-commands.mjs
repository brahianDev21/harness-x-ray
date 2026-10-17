// Measure "destructive-commands": what the project's permission rules, defaultMode and PreToolUse hooks would do with each
// command of data/destructive-commands.json, and what a subagent with a shell tool would do with them. It simulates only:
// no command runs and no hook runs. The target is read through loadClaudeConfig, the parser of the claude-config measure,
// and through ctx, never directly.
//
// Output: security.destructiveCoverage = { mode, commands, preToolUseHooks, subagents }. The rules are applied by
// permissions.mjs (evaluate), so every outcome names the rule or the mode that decides it.
//
// The two cmd commands of the data run as the PowerShell tool runs "cmd /c ...", the form that the docs show for them.
// Their shell is "cmd" and their tool is "PowerShell".

import fs from "node:fs";
import { loadClaudeConfig } from "./claude-config.mjs";
import { isPlainObject } from "./json-out.mjs";
import { decide, evaluate } from "./permissions.mjs";

export const MEASURE_ID = "destructive-commands";

// The data file of the harness, not of the target.
const DATA_URL = new URL("../../data/destructive-commands.json", import.meta.url);
const SHELL_TOOLS = ["Bash", "PowerShell"];
const SHELLS = new Set(["bash", "powershell", "cmd"]);
const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const REQUIRED_FIELDS = ["id", "shell", "tool", "command", "category", "insideProject", "criticalPath", "builtInProtection"];
const OPTIONAL_FIELDS = ["parts"];
const UNDETERMINABLE = "undeterminable";
// A hook matcher made only of these characters is an exact tool name or a list of exact names (docs: hooks).
const EXACT_MATCHER = /^[A-Za-z0-9_ ,|-]+$/;
// The effect of a project defaultMode that the project file applies (see claude-config).
const APPLIED_EFFECT = "applies";
// Main-conversation modes that a subagent runs in, whatever its own permissionMode says (docs: sub-agents).
const INHERITED_MODES = new Set(["acceptEdits", "bypassPermissions", "auto"]);

let commandsCache = null;

export const destructiveCommandsMeasure = Object.freeze({ id: MEASURE_ID, collect: collectDestructiveCoverage });

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
  if (!isKebab(entry.category)) throw new Error(`${where}: category must be kebab-case`);
  if (typeof entry.insideProject !== "boolean") throw new Error(`${where}: insideProject must be a boolean`);
  if (typeof entry.criticalPath !== "boolean") throw new Error(`${where}: criticalPath must be a boolean`);
  if (entry.builtInProtection !== null && !isKebab(entry.builtInProtection)) {
    throw new Error(`${where}: builtInProtection must be null or kebab-case`);
  }
}

function isKebab(value) {
  return typeof value === "string" && KEBAB_CASE.test(value);
}

function isNonBlank(value) {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * The shell tools (Bash, PowerShell) that a PreToolUse matcher covers (docs: hooks). "*", an empty matcher and an omitted
 * matcher cover both. A matcher made only of letters, digits, "_", "-", spaces, "," and "|" is a list of exact tool names.
 * Any other matcher is an unanchored JavaScript regular expression, and an invalid one is undeterminable.
 * @param {string | null} matcher
 * @returns {string[] | "undeterminable"}
 */
export function toolsCoveredBy(matcher) {
  if (matcher === null || matcher === "" || matcher === "*") return [...SHELL_TOOLS];
  if (EXACT_MATCHER.test(matcher)) {
    const names = new Set(matcher.split(/[|,]/).map((name) => name.trim()));
    return SHELL_TOOLS.filter((tool) => names.has(tool));
  }
  let pattern;
  try {
    pattern = new RegExp(matcher);
  } catch {
    return UNDETERMINABLE;
  }
  return SHELL_TOOLS.filter((tool) => pattern.test(tool));
}

/**
 * Whether a hook's filter (its if field, one permission rule) lets the hook run for a call. The rule is evaluated as a
 * single deny rule: a match runs the hook, no match does not, and a rule that cannot be settled is undeterminable.
 * A null filter lets every call through.
 * @param {string | null} rule
 * @param {{ tool: string, command: string, parts?: string[] }} call
 * @returns {"runs" | "none" | "undeterminable"}
 */
export function hookFilterState(rule, call) {
  if (rule === null) return "runs";
  const decided = decide({ allow: [], ask: [], deny: [rule] }, call);
  if (decided.decision === "deny") return "runs";
  return decided.decision === "undeterminable" ? UNDETERMINABLE : "none";
}

// ---------------------------------------------------------------------------------------------------

// Reads the parsed configuration and the data, and simulates every command with the project's rules.
function collectDestructiveCoverage(ctx) {
  const config = loadClaudeConfig(ctx);
  const commands = loadDestructiveCommands();
  const rules = { allow: config.permissions.allow, ask: config.permissions.ask, deny: config.permissions.deny };
  const defaultMode = config.permissions.defaultMode;
  const mode = defaultMode === null ? null : defaultMode.value;
  // The main conversation runs in the project mode only when the project file may apply it; otherwise in default.
  const mainMode = defaultMode !== null && defaultMode.effect === APPLIED_EFFECT ? modeName(defaultMode.value) : "default";
  const hooks = preToolUseEntries(config.hooks);

  return {
    security: {
      destructiveCoverage: {
        mode: defaultMode === null ? null : { ...defaultMode },
        commands: commands.map((command) => commandResult(command, rules, mode, hooks)),
        preToolUseHooks: hooks.map(hookOutput),
        subagents: subagentsOf(config.subagents, rules, commands, mainMode),
      },
    },
  };
}

// The outcome of one command with the project rules and mode, and whether a PreToolUse hook runs for it.
function commandResult(command, rules, mode, hooks) {
  const call = callOf(command);
  const verdict = evaluate(rules, call, { mode, insideProject: command.insideProject, criticalPath: command.criticalPath });
  return {
    ...command,
    outcome: verdict.outcome,
    decidedBy: verdict.decidedBy,
    reason: verdict.reason,
    preToolUseHook: hookStateOf(hooks, call),
  };
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

// One hook for one call: its matcher must cover the tool, and then its filter must let the call through.
function hookRunState(hook, tools, call) {
  const covered = tools === UNDETERMINABLE ? UNDETERMINABLE : tools.includes(call.tool);
  if (covered === false) return "none";
  const filter = hookFilterState(hook.if, call);
  if (filter === "none") return "none";
  return covered === true && filter === "runs" ? "runs" : UNDETERMINABLE;
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
