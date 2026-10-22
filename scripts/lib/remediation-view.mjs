// The blocks of a remediation (lib/remediation.mjs). remediate.mjs writes them as remediation.md, and render-report.mjs puts the
// same blocks in the report, in both views, so the two show the same content. The blocks are the report model's blocks (see
// report.mjs), and the report writes them in its own format. The texts come from the labels of the language, the ids and the
// rules are code, and an agent's text is a "data" run, which each view escapes for its own format. The agent's text is shown on
// one line: every run of whitespace, line breaks included, becomes one space, so that it cannot start an indented code block.
// The results in the modes of UNVERIFIED_MODES are marked as not verified. Nothing here reads the target.

import { MATRIX_MODES, UNVERIFIED_MODES } from "./permissions.mjs";
import { createLabelParts } from "./report-labels.mjs";

/**
 * The section of a remediation, as blocks: a title, the intro, the summary, the count of what was left out, the fragments, the
 * simulation of the destructive commands and of the secret reads, what is not simulated, and what the simulation does not cover.
 * The title is at `level`, and the parts below it one level down, and the fragments two levels down.
 * @param {object} remediation The content of remediation.json (see buildRemediation).
 * @param {{ labels: Readonly<Record<string, string>>, level?: number }} options labels of the language; level 1 to 2 (the fragments
 *   then reach 4, the deepest heading of the report page).
 * @returns {object[]} Blocks of the report model.
 */
export function buildRemediationBlocks(remediation, { labels, level = 2 }) {
  const parts = createLabelParts(labels);
  const t = (key, values = {}) => runsOf(parts(key, values));
  const heading = (depth, key) => ({ type: "heading", level: depth, runs: t(key) });
  const paragraph = (runs) => ({ type: "paragraph", runs });
  const { summary, omitted } = remediation;
  const blocks = [
    heading(level, "remediation.title"),
    paragraph(t("remediation.intro")),
    paragraph(
      t("remediation.summary", {
        fragments: textOf(summary.fragments),
        simulated: textOf(summary.simulatedFragments),
        notSimulated: textOf(summary.notSimulatedFragments),
        passing: textOf(summary.commandsPassingToday),
        moved: textOf(summary.commandsMoved),
        stillPassing: textOf(summary.commandsStillPassing),
        unsimulated: textOf(summary.commandsNotSimulated),
      }),
    ),
    paragraph(
      t("remediation.omitted", {
        cap: textOf(omitted.cap),
        fragments: textOf(omitted.fragments),
        commands: textOf(omitted.commands),
        reads: textOf(omitted.reads),
        notSimulated: textOf(omitted.notSimulated),
      }),
    ),
  ];

  blocks.push(heading(level + 1, "remediation.fragments.title"));
  if (remediation.fragments.length === 0) blocks.push(paragraph(t("remediation.fragments.none")));
  for (const fragment of remediation.fragments) blocks.push(...fragmentBlocks(fragment, level + 2, t));

  blocks.push(heading(level + 1, "remediation.commands.title"), paragraph(t("remediation.commands.legend")));
  blocks.push(commandsTable(remediation.commands, t));

  blocks.push(heading(level + 1, "remediation.reads.title"), paragraph(t("remediation.reads.legend")));
  blocks.push(readsTable(remediation.reads, t));

  blocks.push(heading(level + 1, "remediation.notSimulated.title"));
  blocks.push(notSimulatedList(remediation.notSimulated, t));

  blocks.push(heading(level + 1, "remediation.limits.title"));
  blocks.push({ type: "list", items: LIMIT_KEYS.map((key) => t(key)) });
  return blocks;
}

// The keys of the fixed notes on what the simulation does not cover, in the order they are written.
const LIMIT_KEYS = Object.freeze([
  "remediation.limit.apply",
  "remediation.limit.hooks",
  "remediation.limit.read",
  "remediation.limit.modes",
  "remediation.limit.userLayer",
]);

// The blocks of one fragment: its heading, its fields, its text, and its settings as a code block.
function fragmentBlocks(fragment, depth, t) {
  const blocks = [{ type: "heading", level: depth, runs: runsOf([code(fragment.id), glue(" · "), ...titleRuns(fragment, t)]) }];
  const items = [
    field(t("remediation.field.origin"), t(`remediation.origin.${fragment.origin}`)),
    field(t("remediation.field.finding"), fragment.measuredFindingId === null ? t("remediation.value.none") : [code(fragment.measuredFindingId)]),
    field(t("remediation.field.simulated"), t(fragment.simulated ? "remediation.value.yes" : "remediation.value.no")),
  ];
  if (fragment.reason !== null) items.push(field(t("remediation.field.reason"), t(`remediation.reason.${fragment.reason}`)));
  if (fragment.targets.length > 0) items.push(field(t("remediation.field.targets"), targetsRuns(fragment.targets)));
  if (fragment.coverNote !== null) items.push(field(t("remediation.field.scope"), runsOf([fragment.coverNote])));
  blocks.push({ type: "fields", items });
  if (fragment.origin === "agent") {
    blocks.push({ type: "paragraph", runs: [{ type: "data", text: oneLine(fragment.title) }] });
    blocks.push({ type: "paragraph", runs: [{ type: "data", text: oneLine(fragment.text) }] });
  } else {
    blocks.push({ type: "paragraph", runs: t(TEXT_KEYS[fragment.rule]) });
  }
  if (fragment.settings !== null) {
    blocks.push({ type: "paragraph", runs: t("remediation.field.settings") });
    blocks.push({ type: "code-block", text: JSON.stringify(fragment.settings, null, 2) });
  }
  return blocks;
}

// The explanation of a measured fragment, by its rule. The agent's fragments carry their own text.
const TEXT_KEYS = Object.freeze({
  "SEC-01": "remediation.text.sec01",
  "SEC-02": "remediation.text.sec02",
  "SEC-03": "remediation.text.sec03",
});

// The title of a fragment: the rule's title for a measured one, or the judgment label with its rule for an agent's.
function titleRuns(fragment, t) {
  if (fragment.origin === "agent") return runsOf([t("remediation.rule.judgment"), glue(" "), code(fragment.rule)]);
  return t(`remediation.rule.${fragment.rule}`);
}

function targetsRuns(targets) {
  const shown = targets.map((target) => code(target.kind === "command" ? target.id : target.path));
  return shown.flatMap((run, index) => (index === 0 ? [run] : [glue(", "), run]));
}

// One row per destructive command: its id, its measured outcome, the outcome before and after the patch for each mode, and the
// result. A command that is not simulated says why. The modes of UNVERIFIED_MODES are marked as not verified, in the header and
// in each cell of their columns.
function commandsTable(rows, t) {
  const headers = [
    t("remediation.table.command"),
    t("remediation.table.outcome"),
    ...MATRIX_MODES.map((mode) => modeRuns(mode, t)),
    t("remediation.table.result"),
  ];
  const body = rows.map((row) => {
    const measuredModes = row.measured.modes;
    const modes = MATRIX_MODES.map((mode) => {
      const before = measuredModes === null ? "-" : measuredModes[mode];
      const value = row.after === null ? before : `${before} → ${row.after.modes[mode]}`;
      return cellRuns(value, row.notVerified.includes(mode), t);
    });
    const outcome = row.after === null ? row.measured.outcome : `${row.measured.outcome} → ${row.after.outcome}`;
    return [[code(row.id)], [code(outcome)], ...modes, resultRuns(row, t)];
  });
  return { type: "table", headers, rows: body };
}

// A mode of the matrix as a header: its name, and the marker when its results are not verified.
function modeRuns(mode, t) {
  if (!UNVERIFIED_MODES.includes(mode)) return [code(mode)];
  return runsOf([code(mode), glue(" "), t("remediation.notVerified")]);
}

// A value of a mode as a cell, with the marker when the value is not verified.
function cellRuns(value, notVerified, t) {
  if (!notVerified) return [code(value)];
  return runsOf([code(value), glue(" "), t("remediation.notVerified")]);
}

function resultRuns(row, t) {
  const result = t(`remediation.result.${row.result}`);
  if (row.reason === null) return result;
  return runsOf([result, glue(" ("), t(`remediation.reason.${row.reason}`), glue(")")]);
}

// One row per secret read: its path, the measured decision, the decision after the patch, and the result.
function readsTable(rows, t) {
  const headers = [t("remediation.table.path"), t("remediation.table.measured"), t("remediation.table.after"), t("remediation.table.result")];
  const body = rows.map((row) => [
    [code(row.path)],
    [code(row.measured)],
    [code(row.after ?? "-")],
    row.reason === null ? t(`remediation.result.${row.result}`) : runsOf([t(`remediation.result.${row.result}`), glue(" ("), t(`remediation.reason.${row.reason}`), glue(")")]),
  ]);
  return { type: "table", headers, rows: body };
}

// The literal secrets (by file and line only, never the value) and the note that hooks are not simulated.
function notSimulatedList(items, t) {
  const lines = items.map((item) =>
    t("remediation.literal", {
      file: code(item.file),
      line: item.line === null ? t("remediation.value.noLine") : code(String(item.line)),
      kind: code(item.secretKind),
      reason: t(`remediation.reason.${item.reason}`),
    }),
  );
  lines.push(t("remediation.hooks"));
  return { type: "list", items: lines };
}

// Runs -------------------------------------------------------------------------------------------------

function field(label, runs) {
  return { label, runs };
}

// A label's pieces, as runs: fixed text is a label run, and a value that is a run (or a list of runs) is kept as it is.
function runsOf(pieces) {
  return pieces.flatMap((piece) => {
    if (typeof piece === "string") return [{ type: "label", text: piece }];
    if (Array.isArray(piece)) return piece;
    return [piece];
  });
}

const code = (text) => ({ type: "code", text: String(text) });
const glue = (text) => ({ type: "text", text });

// Agent text on one line: each run of whitespace, line breaks included, is one space, and the ends are trimmed.
function oneLine(text) {
  return String(text).replace(/\s+/g, " ").trim();
}

// A number of the summary, as text.
function textOf(value) {
  return glue(String(value));
}
