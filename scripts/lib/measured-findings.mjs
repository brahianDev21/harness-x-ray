// Measured findings and candidates. This is the derive step of the scan: it reads the merged measurements of one
// scan (never the target) and applies the triggers of the measured MVP rules. It returns three lists:
//
// - measuredFindings: one entry per finding of a measured rule. Its impact is the highest impact of its triggers, and
//   each trigger names the measurement that caused it. Ids mf-N follow the order of EMITTERS, then the order of the
//   measurements inside each emitter.
// - candidates: what the agent must read: duplication groups (COD-01, COD-04), hook scripts (SEC-02, SEC-04) and
//   memory files (judgment rules). They carry file paths and line numbers, never code text. Ids cand-N follow the
//   order of the three groups.
// - undeterminable: cases that a measured rule could not decide, with the reason. They are never findings.
//
// Every measurementRef is an RFC 6901 JSON pointer into measurements.json. Triggers are sorted by impact, high first,
// and keep their order inside one impact. The finding's measurementRef is the ref of its first trigger with the
// highest impact. CTX-01 and COD-01 are the exceptions: they point at their number, as their rules say.
//
// A section that a scan did not write (for example a scan with no measures) means no finding, never an error.
// Thresholds come from thresholds.mjs, and the category of a script name from verification.mjs.

import { categoriesOfScriptName } from "./verification.mjs";
import { THRESHOLDS } from "./thresholds.mjs";

export { THRESHOLDS, THRESHOLDS_STATUS } from "./thresholds.mjs";

const AXIS_BY_PREFIX = Object.freeze({
  RUL: "instructions",
  CTX: "context",
  SEC: "security",
  VER: "verification",
  STR: "structure",
  COD: "code",
});
const AXIS_ORDER = Object.freeze(["instructions", "context", "security", "verification", "structure", "code"]);
const IMPACT_RANK = Object.freeze({ high: 3, medium: 2, low: 1 });
const SHELL_TOOLS = Object.freeze(["Bash", "PowerShell"]);
const VERIFICATION_CATEGORIES = Object.freeze(["lint", "test", "typecheck", "verify"]);
// Bare shell allows: the tool with no specifier, or with the whole-tool wildcard.
const BARE_SHELL_RULES = new Set(["Bash", "Bash(*)", "PowerShell", "PowerShell(*)"]);
// A shell allow with a wildcard inside its parentheses, such as Bash(git *).
const WILDCARD_SHELL_RULE = /^(?:Bash|PowerShell)\([^)]*\*[^)]*\)$/;
// The files that Claude Code reads as CLAUDE memory, and as AGENTS memory, by their path from the target.
const CLAUDE_FILE_NAMES = Object.freeze(["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md"]);
const CLAUDE_BASE_NAMES = Object.freeze(["CLAUDE.md", "CLAUDE.local.md"]);
const AGENTS_FILE_NAMES = Object.freeze(["AGENTS.md", ".claude/AGENTS.md"]);
const TOTAL_POINTER = "/context/alwaysLoaded/estTokensTotal";
const DUPLICATION_POINTER = "/code/duplication/duplicatedLinesPct";
const DUPLICATION_RULES = Object.freeze(["COD-01", "COD-04"]);
const HOOK_RULES = Object.freeze(["SEC-02", "SEC-04"]);
const MEMORY_RULES = Object.freeze(["RUL-01", "RUL-02", "RUL-03", "VER-01", "SEC-04", "SEC-05", "STR-01", "COD-04"]);

/**
 * The emitters of the measured MVP rules, in axis order. Each takes the merged measurements and returns
 * { findings, undeterminable }. A finding has no id yet; deriveMeasuredOutput numbers them. check-catalog.mjs reads
 * the keys of this object to check that every measured MVP rule has an emitter.
 */
export const EMITTERS = Object.freeze({
  "RUL-04": emitBrokenReferences,
  "CTX-01": emitAlwaysLoadedBudget,
  "CTX-07": emitAgentsMdNotLoaded,
  "SEC-01": emitBroadPermissions,
  "SEC-02": emitDestructiveCommands,
  "SEC-03": emitSecrets,
  "STR-02": emitUnprotectedEntries,
  "COD-01": emitDuplication,
});

/**
 * Derives the measured findings, the candidates and the undeterminable cases from the merged measurements.
 * This is the function that scan() calls after the measures have merged (see scripts/lib/scanner.mjs).
 * @param {object} measurements The merged measurements. It is not changed.
 * @returns {{ measuredFindings: object[], candidates: object[], undeterminable: object[] }}
 */
export function deriveMeasuredOutput(measurements) {
  const measuredFindings = [];
  const undeterminable = [];
  for (const rule of Object.keys(EMITTERS)) {
    const emitted = EMITTERS[rule](measurements);
    measuredFindings.push(...emitted.findings);
    undeterminable.push(...emitted.undeterminable);
  }
  return {
    measuredFindings: measuredFindings.map((finding, index) => ({ id: `mf-${index + 1}`, ...finding })),
    candidates: buildCandidates(measurements).map((candidate, index) => ({ id: `cand-${index + 1}`, ...candidate })),
    undeterminable,
  };
}

/**
 * Counts the findings of each axis. The keys follow the axis order of EMITTERS.
 * @param {Array<{ axis: string }>} findings
 * @returns {Record<string, number>}
 */
export function countByAxis(findings) {
  const counts = Object.fromEntries(AXIS_ORDER.map((axis) => [axis, 0]));
  for (const finding of findings) counts[finding.axis] += 1;
  return counts;
}

// ---------------------------------------------------------------------------------------------------
// Building blocks

// One trigger. Extra fields are threshold ({ key, value }) and detail, when the trigger has them.
function trigger(name, impact, measurementRef, extra = {}) {
  return { trigger: name, impact, measurementRef, ...extra };
}

function thresholdOf(key) {
  return { key, value: THRESHOLDS[key] };
}

// A finding with its triggers, or null when there are no triggers. measurementRef overrides the default, which is the
// ref of the first trigger with the highest impact.
function measuredFinding(rule, triggers, evidence, measurementRef) {
  if (triggers.length === 0) return null;
  const ordered = [...triggers].sort((a, b) => IMPACT_RANK[b.impact] - IMPACT_RANK[a.impact]);
  return {
    rule,
    axis: AXIS_BY_PREFIX[rule.slice(0, 3)],
    impact: ordered[0].impact,
    measurementRef: measurementRef ?? ordered[0].measurementRef,
    evidence: uniqueEvidence(evidence),
    triggers: ordered,
  };
}

// The evidence of a file, with a line and an end line only when they are integers.
function evidenceOf(file, line, endLine) {
  const entry = { file };
  if (Number.isInteger(line)) entry.line = line;
  if (Number.isInteger(endLine)) entry.endLine = endLine;
  return entry;
}

function uniqueEvidence(list) {
  const seen = new Set();
  const unique = [];
  for (const entry of list) {
    const key = JSON.stringify(entry);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(entry);
  }
  return unique;
}

function undeterminableOf(rule, measurementRef, reason) {
  return { rule, measurementRef, reason };
}

// A list section, read with optional access: a missing or malformed section is an empty list.
function listAt(value) {
  return Array.isArray(value) ? value : [];
}

// ---------------------------------------------------------------------------------------------------
// RUL-04 Broken references: one finding per entry of instructions.brokenRefs.

function emitBrokenReferences(measurements) {
  const findings = listAt(measurements.instructions?.brokenRefs).map((ref, index) => {
    const verification = ref.kind === "script" && isVerificationScript(ref.script);
    const name = verification ? "verification-command-missing" : "reference-missing";
    const impact = verification ? "high" : "medium";
    const pointer = `/instructions/brokenRefs/${index}`;
    return measuredFinding("RUL-04", [trigger(name, impact, pointer)], [evidenceOf(ref.file, ref.line)]);
  });
  return { findings, undeterminable: [] };
}

// A script that a memory file names is a verification command when its name is a test, lint, typecheck or verify name
// (the categories of the verification measure).
function isVerificationScript(name) {
  if (typeof name !== "string") return false;
  return categoriesOfScriptName(name).some((category) => VERIFICATION_CATEGORIES.includes(category));
}

// ---------------------------------------------------------------------------------------------------
// CTX-01 Always-loaded budget: the memory files of the target and the repository total. Ancestor files are never
// counted: the scan has no lines or tokens for them, and they are not in the total (context.ancestors).

function emitAlwaysLoadedBudget(measurements) {
  const triggers = [];
  const evidence = [];
  listAt(measurements.inventory).forEach((item, index) => {
    if (item.kind !== "memory" || item.loadMode !== "always") return;
    if (!Number.isInteger(item.lines) || item.lines <= THRESHOLDS.memoryFileMaxLines) return;
    const threshold = thresholdOf("memoryFileMaxLines");
    triggers.push(trigger("memory-file-over-limit", "medium", `/inventory/${index}/lines`, { threshold }));
    evidence.push(evidenceOf(item.path));
  });
  const total = measurements.context?.alwaysLoaded?.estTokensTotal;
  if (typeof total === "number") {
    if (total > THRESHOLDS.alwaysLoadedTokensHigh) {
      const threshold = thresholdOf("alwaysLoadedTokensHigh");
      triggers.push(trigger("always-loaded-total-high", "high", TOTAL_POINTER, { threshold }));
    } else if (total > THRESHOLDS.alwaysLoadedTokensMedium) {
      const threshold = thresholdOf("alwaysLoadedTokensMedium");
      triggers.push(trigger("always-loaded-total-medium", "medium", TOTAL_POINTER, { threshold }));
    }
  }
  const finding = measuredFinding("CTX-01", triggers, evidence, TOTAL_POINTER);
  return { findings: compact([finding]), undeterminable: [] };
}

// ---------------------------------------------------------------------------------------------------
// CTX-07 AGENTS.md not loaded: one finding per AGENTS entry that the scan marks not-loaded. The cause is a CLAUDE file
// in the target when the inventory has one that loads, otherwise a CLAUDE file in an ancestor folder.

function emitAgentsMdNotLoaded(measurements) {
  const inventory = listAt(measurements.inventory);
  const inTarget = inventory.find(
    (item) => item.kind === "memory" && item.loadMode === "always" && CLAUDE_FILE_NAMES.includes(item.path),
  );
  const ancestor = listAt(measurements.context?.ancestors).find((item) => CLAUDE_BASE_NAMES.includes(baseName(item.path)));
  let cause = { causedBy: null };
  if (inTarget !== undefined) cause = { causedBy: "target", file: inTarget.path };
  else if (ancestor !== undefined) cause = { causedBy: "ancestor", file: ancestor.path };

  const findings = inventory.map((item, index) => {
    if (item.kind !== "memory" || item.loadMode !== "not-loaded" || !AGENTS_FILE_NAMES.includes(item.path)) return null;
    const evidence = [evidenceOf(item.path)];
    if (cause.file !== undefined) evidence.push(evidenceOf(cause.file));
    const detail = { causedBy: cause.causedBy };
    const triggers = [trigger("agents-md-not-loaded", "medium", `/inventory/${index}`, { detail })];
    return measuredFinding("CTX-07", triggers, evidence);
  });
  return { findings: compact(findings), undeterminable: [] };
}

function baseName(relPath) {
  const parts = relPath.split("/");
  return parts[parts.length - 1];
}

// ---------------------------------------------------------------------------------------------------
// SEC-01 Broad project permissions.

function emitBroadPermissions(measurements) {
  const permissions = measurements.security?.permissions ?? {};
  const allow = listAt(permissions.allow);
  const passingByAllow = passingCommandsByAllowEntry(measurements, allow);
  const triggers = [];
  const evidence = [];

  allow.forEach((entry, index) => {
    const pointer = `/security/permissions/allow/${index}`;
    if (BARE_SHELL_RULES.has(entry.rule)) {
      triggers.push(trigger("bare-shell-allow", "high", pointer));
    } else if (WILDCARD_SHELL_RULE.test(entry.rule) && passingByAllow.has(index)) {
      const commands = [...passingByAllow.get(index)].sort(compareText);
      triggers.push(trigger("destructive-allow-passes", "high", pointer, { detail: { commands } }));
    } else if (WILDCARD_SHELL_RULE.test(entry.rule)) {
      triggers.push(trigger("wildcard-shell-allow", "medium", pointer));
    } else {
      return;
    }
    evidence.push(evidenceOf(entry.source));
  });

  const mode = permissions.defaultMode;
  if (mode?.value === "acceptEdits" && mode.effect === "applies") {
    triggers.push(trigger("accept-edits-in-project", "high", "/security/permissions/defaultMode"));
    evidence.push(evidenceOf(mode.source));
  }

  listAt(measurements.security?.destructiveCoverage?.subagents).forEach((agent, index) => {
    const shell = listAt(agent.shellTools).some((tool) => SHELL_TOOLS.includes(tool));
    if (!shell || agent.effectiveMode !== "acceptEdits") return;
    triggers.push(trigger("subagent-accept-edits-shell", "high", `/security/destructiveCoverage/subagents/${index}`));
    evidence.push(evidenceOf(agent.path));
  });

  listAt(permissions.additionalDirectories).forEach((dir, index) => {
    if (!isBroadDirectory(dir.path)) return;
    triggers.push(trigger("broad-additional-directory", "medium", `/security/permissions/additionalDirectories/${index}`));
    evidence.push(evidenceOf(dir.source));
  });

  const finding = measuredFinding("SEC-01", triggers, evidence);
  return { findings: compact([finding]), undeterminable: [] };
}

// The root of a drive, the filesystem root and the home folder, as written in additionalDirectories.
function isBroadDirectory(value) {
  if (typeof value !== "string") return false;
  return value === "/" || value === "~" || /^[A-Za-z]:[\\/]?$/.test(value);
}

// For each allow entry (by index), the ids of the destructive commands that pass through it. A compound command's
// decidedBy.rule joins several allow rules with " && ", and each part is looked up on its own.
function passingCommandsByAllowEntry(measurements, allow) {
  const coverage = measurements.security?.destructiveCoverage ?? {};
  const passing = [
    ...listAt(coverage.commands).map((command) => ({ id: command.id, outcome: command.outcome, decidedBy: command.decidedBy })),
    ...listAt(coverage.subagents).flatMap((agent) =>
      listAt(agent.results).map((result) => ({ id: result.id, outcome: result.outcome, decidedBy: result.decidedBy })),
    ),
  ];
  const byAllow = new Map();
  for (const item of passing) {
    if (item.outcome !== "passes" || item.decidedBy?.kind !== "rule" || item.decidedBy.list !== "allow") continue;
    for (const part of String(item.decidedBy.rule).split(" && ")) {
      const index = allowIndexOf(allow, part, item.decidedBy.source);
      if (index === -1) continue;
      if (!byAllow.has(index)) byAllow.set(index, new Set());
      byAllow.get(index).add(item.id);
    }
  }
  return byAllow;
}

// The index of the allow entry with this rule text, preferring the one from the same source file.
function allowIndexOf(allow, rule, source) {
  const same = allow.findIndex((entry) => entry.rule === rule && entry.source === source);
  if (same !== -1) return same;
  return allow.findIndex((entry) => entry.rule === rule);
}

// ---------------------------------------------------------------------------------------------------
// SEC-02 Destructive commands. A passing command is high. Otherwise, and only when nothing passes, the medium rows:
// a command that only the default-mode prompt stops, and a PreToolUse hook that fails open.

function emitDestructiveCommands(measurements) {
  const coverage = measurements.security?.destructiveCoverage ?? {};
  const commands = listAt(coverage.commands);
  const subagents = listAt(coverage.subagents);
  const hooks = listAt(coverage.preToolUseHooks);
  const base = "/security/destructiveCoverage";
  const undeterminable = [];
  const high = [];
  const medium = [];

  commands.forEach((command, index) => {
    const pointer = `${base}/commands/${index}`;
    if (command.outcome === "passes") {
      const evidence = passEvidence(command.decidedBy, coverage.mode);
      high.push({ trigger: trigger("destructive-command-passes", "high", pointer), evidence });
    } else if (command.outcome === "undeterminable") {
      undeterminable.push(undeterminableOf("SEC-02", `${pointer}/outcome`, `outcome undeterminable: ${command.reason}`));
    }
  });
  subagents.forEach((agent, agentIndex) => {
    listAt(agent.results).forEach((result, resultIndex) => {
      const pointer = `${base}/subagents/${agentIndex}/results/${resultIndex}`;
      if (result.outcome === "passes") {
        const evidence = [evidenceOf(agent.path), ...passEvidence(result.decidedBy, coverage.mode)];
        high.push({ trigger: trigger("destructive-command-passes", "high", pointer), evidence });
      } else if (result.outcome === "undeterminable") {
        undeterminable.push(undeterminableOf("SEC-02", `${pointer}/outcome`, `outcome undeterminable: ${result.reason}`));
      }
    });
  });

  if (high.length === 0) {
    commands.forEach((command, index) => {
      const asksByDefault = command.outcome === "asks" && command.decidedBy?.kind === "mode" && command.decidedBy.mode === "default";
      if (!asksByDefault) return;
      const pointer = `${base}/commands/${index}`;
      if (command.preToolUseHook === "none") {
        medium.push({ trigger: trigger("default-mode-without-hook", "medium", pointer), evidence: [] });
      } else if (command.preToolUseHook === "undeterminable") {
        undeterminable.push(undeterminableOf("SEC-02", `${pointer}/preToolUseHook`, "the PreToolUse hook state is undeterminable"));
      }
    });
    hooks.forEach((hook, index) => {
      if (hook.failsOpen !== true) return;
      const pointer = `${base}/preToolUseHooks/${index}`;
      if (listAt(hook.tools).some((tool) => SHELL_TOOLS.includes(tool))) {
        medium.push({ trigger: trigger("hook-fails-open", "medium", pointer), evidence: hookEvidence(hook) });
      } else if (hook.tools === "undeterminable") {
        undeterminable.push(undeterminableOf("SEC-02", `${pointer}/tools`, "the hook matcher does not settle which tools it covers"));
      }
    });
  }

  const rows = [...high, ...medium];
  const finding = measuredFinding(
    "SEC-02",
    rows.map((row) => row.trigger),
    rows.flatMap((row) => row.evidence),
  );
  return { findings: compact([finding]), undeterminable };
}

// The harness file that lets a command pass: the allow or ask rule, or the project mode.
function passEvidence(decidedBy, mode) {
  if (decidedBy?.kind === "rule" && typeof decidedBy.source === "string") return [evidenceOf(decidedBy.source)];
  if (decidedBy?.kind === "mode" && typeof mode?.source === "string") return [evidenceOf(mode.source)];
  return [];
}

// The settings file that holds the hook, and its script when the script is in the target.
function hookEvidence(hook) {
  const evidence = [];
  if (typeof hook.source === "string") evidence.push(evidenceOf(hook.source));
  if (hook.script && hook.script.external === false && hook.script.exists === true) {
    evidence.push(evidenceOf(hook.script.path));
  }
  return evidence;
}

// ---------------------------------------------------------------------------------------------------
// SEC-03 Secrets: one finding for the repository. The versioned and read triggers are per file; the literal
// triggers are per value; the .env row covers a local .env that the scan cannot list.

function emitSecrets(measurements) {
  const secrets = measurements.security?.secrets ?? {};
  const versioned = secrets.fileListSource === "git";
  const triggers = [];
  const evidence = [];
  const undeterminable = [];

  listAt(secrets.files).forEach((file, index) => {
    const pointer = `/security/secrets/files/${index}`;
    const decision = file.readDecision?.decision;
    if (versioned) {
      triggers.push(trigger("secret-file-versioned", "high", pointer));
      evidence.push(evidenceOf(file.path));
    }
    if (decision === "default" || decision === "allow") {
      triggers.push(trigger("secret-file-readable", "high", `${pointer}/readDecision`));
      evidence.push(evidenceOf(file.path));
    } else if (decision === "ask") {
      triggers.push(trigger("secret-file-read-with-prompt", "medium", `${pointer}/readDecision`));
      evidence.push(evidenceOf(file.path));
    } else if (decision === "undeterminable") {
      const reason = `read decision undeterminable: ${file.readDecision.reason}`;
      undeterminable.push(undeterminableOf("SEC-03", `${pointer}/readDecision`, reason));
    }
  });

  listAt(secrets.literals).forEach((literal, index) => {
    triggers.push(trigger("literal-secret", "high", `/security/secrets/literals/${index}`));
    evidence.push(evidenceOf(literal.file, literal.line));
  });

  const protection = secrets.readProtection ?? {};
  if (protection.envAtRoot !== undefined && protection.envAtRoot !== null) {
    const envTrigger = envAtRootTrigger(protection, undeterminable);
    if (envTrigger !== null) triggers.push(envTrigger);
  }

  const finding = measuredFinding("SEC-03", triggers, evidence);
  return { findings: compact([finding]), undeterminable };
}

// The .env row. A deny or an ask gives nothing. A read that needs no prompt is medium, unless a read hook runs for .env
// and fails closed. An undeterminable decision, or a hook whose coverage of .env cannot be settled when no hook fails
// closed, is listed as undeterminable, not as a trigger. Returns the trigger or null.
function envAtRootTrigger(protection, undeterminable) {
  const env = protection.envAtRoot;
  const pointer = "/security/secrets/readProtection/envAtRoot/decision";
  if (env.decision === "undeterminable") {
    undeterminable.push(undeterminableOf("SEC-03", pointer, `read decision for .env undeterminable: ${env.reason}`));
    return null;
  }
  if (env.decision !== "default" && env.decision !== "allow") return null;

  const hooks = listAt(protection.preToolUseReadHooks);
  if (hooks.some((hook) => hook.runsForEnv === "runs" && hook.failsOpen === false)) return null;
  const unknown = hooks.findIndex((hook) => hook.runsForEnv === "undeterminable");
  if (unknown !== -1) {
    const hookPointer = `/security/secrets/readProtection/preToolUseReadHooks/${unknown}/runsForEnv`;
    undeterminable.push(undeterminableOf("SEC-03", hookPointer, "a PreToolUse hook may cover a read of .env; it is undeterminable"));
    return null;
  }
  return trigger("env-at-root-readable", "medium", pointer);
}

// ---------------------------------------------------------------------------------------------------
// STR-02 Generated, large or vendored files that nothing protects: one finding per listed entry. An entry is covered
// by a Read or Edit deny, or by a memory line that marks it as not to touch. A decision that is mixed across a folder's
// files is not a deny, so the entry is not covered (the rule does not say; the report notes it).

function emitUnprotectedEntries(measurements) {
  const structure = measurements.structure ?? {};
  const rows = [
    ...listAt(structure.generatedFiles).map((entry, index) => ({
      entry,
      pointer: `/structure/generatedFiles/${index}`,
      impact: "medium",
      name: "generated-entry-unprotected",
    })),
    ...listAt(structure.largeFiles).map((entry, index) => ({
      entry,
      pointer: `/structure/largeFiles/${index}`,
      impact: "low",
      name: "large-file-unprotected",
    })),
  ];
  const findings = [];
  const undeterminable = [];
  for (const { entry, pointer, impact, name } of rows) {
    const read = entry.protection?.read;
    const edit = entry.protection?.edit;
    if (read?.decision === "deny" || edit?.decision === "deny" || entry.memory?.marked === true) continue;

    const unsettled = [["read", read], ["edit", edit]].filter(([, verdict]) => verdict?.decision === "undeterminable");
    if (unsettled.length > 0) {
      for (const [tool, verdict] of unsettled) {
        const reason = `${tool} decision undeterminable: ${verdict.reason}`;
        undeterminable.push(undeterminableOf("STR-02", `${pointer}/protection/${tool}`, reason));
      }
      continue;
    }
    const detail = { read: decisionOf(read), edit: decisionOf(edit) };
    findings.push(measuredFinding("STR-02", [trigger(name, impact, pointer, { detail })], [evidenceOf(entry.path)]));
  }
  return { findings: compact(findings), undeterminable };
}

// The decision of a verdict for the trigger detail. A mixed folder also shows how many files had each decision.
function decisionOf(verdict) {
  if (verdict?.decision === "mixed") return { decision: "mixed", counts: { ...verdict.counts } };
  return { decision: verdict?.decision ?? null };
}

// ---------------------------------------------------------------------------------------------------
// COD-01 Duplication: one finding for the repository, from the percentage alone. inTests is not read here.

function emitDuplication(measurements) {
  const duplication = measurements.code?.duplication;
  const pct = duplication?.duplicatedLinesPct;
  if (typeof pct !== "number") return { findings: [], undeterminable: [] };
  const triggers = [];
  if (pct > THRESHOLDS.duplicationPctHigh) {
    const threshold = thresholdOf("duplicationPctHigh");
    triggers.push(trigger("duplication-high", "high", DUPLICATION_POINTER, { threshold }));
  } else if (pct > THRESHOLDS.duplicationPctMedium) {
    const threshold = thresholdOf("duplicationPctMedium");
    triggers.push(trigger("duplication-medium", "medium", DUPLICATION_POINTER, { threshold }));
  }
  const evidence = listAt(duplication.groups).flatMap((group) =>
    listAt(group.copies).map((copy) => evidenceOf(copy.file, copy.line, copy.endLine)),
  );
  const finding = measuredFinding("COD-01", triggers, evidence, DUPLICATION_POINTER);
  return { findings: compact([finding]), undeterminable: [] };
}

// ---------------------------------------------------------------------------------------------------
// Candidates. They are not findings: the agent reads them and judges. Groups come first, then hook scripts sorted by
// path, then memory files in inventory order.

function buildCandidates(measurements) {
  const candidates = [];
  listAt(measurements.code?.duplication?.groups).forEach((group, index) => {
    candidates.push({
      kind: "duplication-group",
      rules: [...DUPLICATION_RULES],
      measurementRef: `/code/duplication/groups/${index}`,
      lines: group.lines,
      redundantLines: group.redundantLines,
      copies: listAt(group.copies).map((copy) => evidenceOf(copy.file, copy.line, copy.endLine)),
    });
  });

  // One candidate per script path, at the first hook that runs it. Only scripts inside the target are listed.
  const scripts = new Map();
  listAt(measurements.claudeConfig?.hooks).forEach((hook, index) => {
    const script = hook.script;
    if (!script || script.external !== false || script.exists !== true) return;
    if (!scripts.has(script.path)) scripts.set(script.path, `/claudeConfig/hooks/${index}/script`);
  });
  for (const file of [...scripts.keys()].sort(compareText)) {
    candidates.push({ kind: "hook-script", rules: [...HOOK_RULES], measurementRef: scripts.get(file), file });
  }

  listAt(measurements.inventory).forEach((item, index) => {
    if (item.kind !== "memory" && item.kind !== "rule") return;
    candidates.push({
      kind: "memory-file",
      rules: [...MEMORY_RULES],
      measurementRef: `/inventory/${index}`,
      file: item.path,
      loadMode: item.loadMode,
    });
  });
  return candidates;
}

// The non-null items of a list.
function compact(list) {
  return list.filter((item) => item !== null);
}

function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
