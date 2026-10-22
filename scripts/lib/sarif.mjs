// SARIF 2.1.0 log of a CI run: a minimal log built from measurements.json and the rule catalog. It is a pure function. It reads no
// file and writes none; the caller writes the result with writeStableJson. The log has one run of one tool (harness-x-ray), its
// measured rules, and one result per measured finding, in the order of measuredFindings.
//
// The $schema URL is written as a string only. This module never fetches it, and the URL is not verified against the published
// schema: the code was written without network access. The subset of the format that this module writes is described in
// schemas/sarif.schema.json.
//
// The judgment rules are not applied by a CI run, and the log says so: runs[0].properties holds judgmentRulesApplied (false) and
// judgmentRules (how many judgment rules the catalog has), and runs[0].invocations[0] holds a note notification with the same
// fact. Locations are files of the target only: a path relative to the target, each segment percent-encoded. Evidence with a
// layer lies outside the target, so it has no location, and a finding with no file evidence has no locations key. A region has a
// startLine when the evidence has a line, and an endLine only with that startLine.

export const SARIF_VERSION = "2.1.0";
// Written as a string only; see the header.
export const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME = "harness-x-ray";
const TOOL_PREFIX = `${TOOL_NAME}@`;
// The SARIF level of each impact: a high finding is an error, a medium one a warning and a low one a note.
const LEVEL_BY_IMPACT = Object.freeze({ high: "error", medium: "warning", low: "note" });
// The evidence entries that a message names in full; the others are counted.
const MESSAGE_EVIDENCE_LIMIT = 3;

/**
 * Builds the SARIF log of one scan. See the header of this module.
 * @param {{ measuredFindings: object[], meta: { tool: string } }} measurements The measurements of the scan (the fields of
 *   measurements.json that the log uses). It is not changed.
 * @param {Array<{ id: string, title: string, kind: string }>} rules The rule catalog, as loadRules returns it.
 * @returns {object} The SARIF log, ready for writeStableJson.
 * @throws {TypeError} If meta.tool is not harness-x-ray@<version>, a finding has an impact that is not high, medium or low, a
 *   finding names a rule that is not a measured rule of the catalog, or a file of the evidence is not a relative path.
 */
export function buildSarif(measurements, rules) {
  if (!Array.isArray(measurements.measuredFindings)) throw new TypeError("measurements.measuredFindings must be a list");
  const measured = rules.filter((rule) => rule.kind === "measured").sort((a, b) => compareText(a.id, b.id));
  const judgmentRules = rules.filter((rule) => rule.kind === "judgment").length;
  const indexOf = new Map(measured.map((rule, index) => [rule.id, index]));
  const results = measurements.measuredFindings.map((finding) => resultOf(finding, measured, indexOf));
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: versionOf(measurements),
            rules: measured.map((rule) => ({ id: rule.id, shortDescription: { text: rule.title } })),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            toolExecutionNotifications: [{ level: "note", message: { text: notAppliedText(judgmentRules) } }],
          },
        ],
        properties: { judgmentRulesApplied: false, judgmentRules },
        results,
      },
    ],
  };
}

// The version that the scanner records in meta.tool, which is name@version.
function versionOf(measurements) {
  const tool = measurements.meta?.tool;
  if (typeof tool !== "string" || !tool.startsWith(TOOL_PREFIX)) throw new TypeError(`meta.tool must be ${TOOL_PREFIX}<version>`);
  return tool.slice(TOOL_PREFIX.length);
}

function notAppliedText(judgmentRules) {
  return `The judgment rules were not applied: this run checks the measured rules only, and the catalog has ${judgmentRules} judgment rules.`;
}

function resultOf(finding, measured, indexOf) {
  const ruleIndex = indexOf.get(finding.rule);
  if (ruleIndex === undefined) throw new TypeError(`${finding.id}: ${finding.rule} is not a measured rule of the catalog`);
  const level = LEVEL_BY_IMPACT[finding.impact];
  if (level === undefined) throw new TypeError(`${finding.id}: the impact must be high, medium or low`);
  const rule = measured[ruleIndex];
  const result = { ruleId: rule.id, ruleIndex, level, message: { text: messageOf(finding, rule) } };
  const locations = finding.evidence.flatMap(locationOf);
  if (locations.length > 0) result.locations = locations;
  return result;
}

// The text of a result. It is built from the fields of measurements.json and the title of the rule only: the rule id and title,
// the impact, the triggers with their counts (in the order they first appear), and the first evidence entries.
function messageOf(finding, rule) {
  const counts = new Map();
  for (const item of finding.triggers) counts.set(item.trigger, (counts.get(item.trigger) ?? 0) + 1);
  const triggers = [...counts].map(([name, count]) => `${name} (${count})`).join(", ");
  let text = `${rule.id} ${rule.title}. Impact: ${finding.impact}. Triggers: ${triggers}.`;
  if (finding.evidence.length > 0) text += ` Evidence: ${evidenceListOf(finding.evidence)}.`;
  return text;
}

function evidenceListOf(evidence) {
  const shown = evidence
    .slice(0, MESSAGE_EVIDENCE_LIMIT)
    .map((entry) => (Number.isInteger(entry.line) ? `${entry.file}:${entry.line}` : entry.file));
  const more = evidence.length - shown.length;
  return more > 0 ? `${shown.join(", ")}, and ${more} more` : shown.join(", ");
}

// The locations of one evidence entry: none for a file outside the target (it has a layer), otherwise one location. The region
// is written only when the entry has a line that is at least 1, and its endLine only when that endLine is not before the line.
function locationOf(entry) {
  if (entry.layer !== undefined || typeof entry.file !== "string") return [];
  const location = { physicalLocation: { artifactLocation: { uri: uriOf(entry.file) } } };
  if (Number.isInteger(entry.line) && entry.line >= 1) {
    const region = { startLine: entry.line };
    if (Number.isInteger(entry.endLine) && entry.endLine >= entry.line) region.endLine = entry.endLine;
    location.physicalLocation.region = region;
  }
  return [location];
}

// The URI of a file of the target. The path is relative, and each segment is percent-encoded, so that no segment can read as a
// scheme, a drive letter or a backslash path. An empty segment or a parent folder is refused.
function uriOf(file) {
  if (file === ".") return ".";
  const segments = file.split("/");
  if (segments.some((segment) => segment === "" || segment === "..")) {
    throw new TypeError(`evidence file is not a relative path of the target: ${JSON.stringify(file)}`);
  }
  return segments.map((segment) => encodeURIComponent(segment)).join("/");
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
