// Which tools a hook's matcher covers, and whether a hook's if filter lets one call through. The rules are the ones of the
// hooks documentation. Shared by the measures that read hooks (destructive-commands and secrets), so that they agree on what a
// matcher covers. Nothing here runs a hook.

import { decide } from "./permissions.mjs";

/** Returned when a matcher or a filter cannot be settled from the text alone. */
export const UNDETERMINABLE = "undeterminable";
// A matcher made only of these characters is an exact tool name or a list of exact names (docs: hooks).
const EXACT_MATCHER = /^[A-Za-z0-9_ ,|-]+$/;

/**
 * The tools of a list that a PreToolUse matcher covers (docs: hooks). "*", an empty matcher and an omitted matcher cover
 * every tool. A matcher made only of letters, digits, "_", "-", spaces, "," and "|" is a list of exact tool names. Any other
 * matcher is an unanchored JavaScript regular expression, and an invalid one is undeterminable.
 * @param {string | null} matcher
 * @param {string[]} tools The tool names to test, in the order to return them.
 * @returns {string[] | "undeterminable"}
 */
export function coveredTools(matcher, tools) {
  if (matcher === null || matcher === "" || matcher === "*") return [...tools];
  if (EXACT_MATCHER.test(matcher)) {
    const names = new Set(matcher.split(/[|,]/).map((name) => name.trim()));
    return tools.filter((tool) => names.has(tool));
  }
  let pattern;
  try {
    pattern = new RegExp(matcher);
  } catch {
    return UNDETERMINABLE;
  }
  return tools.filter((tool) => pattern.test(tool));
}

/**
 * Whether a hook's filter (its if field, one permission rule) lets the hook run for a call. The rule is evaluated as a
 * single deny rule: a match runs the hook, no match does not, and a rule that cannot be settled is undeterminable.
 * A null filter lets every call through.
 * @param {string | null} rule
 * @param {{ tool: string, command?: string, parts?: string[], path?: string }} call
 * @returns {"runs" | "none" | "undeterminable"}
 */
export function hookFilterState(rule, call) {
  if (rule === null) return "runs";
  const decided = decide({ allow: [], ask: [], deny: [rule] }, call);
  if (decided.decision === "deny") return "runs";
  return decided.decision === "undeterminable" ? UNDETERMINABLE : "none";
}

/**
 * Whether one hook runs for a call: its matcher must cover the tool, and then its filter must let the call through.
 * @param {{ if: string | null }} hook
 * @param {string[] | "undeterminable"} tools The tools that the matcher covers (see coveredTools).
 * @param {{ tool: string, command?: string, parts?: string[], path?: string }} call
 * @returns {"runs" | "none" | "undeterminable"}
 */
export function hookRunState(hook, tools, call) {
  const covered = tools === UNDETERMINABLE ? UNDETERMINABLE : tools.includes(call.tool);
  if (covered === false) return "none";
  const filter = hookFilterState(hook.if, call);
  if (filter === "none") return "none";
  return covered === true && filter === "runs" ? "runs" : UNDETERMINABLE;
}
