// A checker for the minimal SARIF 2.1.0 log that lib/sarif.mjs writes. It is not a full SARIF validator and reads no schema file:
// it checks the parts that a code-scanning upload reads and the rules this repository states for them.
//
//   - version "2.1.0" and a $schema string; runs is a non-empty list.
//   - Each run: a tool driver with a name, and a rules list with unique ids and a shortDescription.text.
//   - Each result: a ruleId that is a rule of the run, a ruleIndex that names that same rule, a level of error, warning, note or
//     none, and a non-empty message.text.
//   - Each location: an artifact uri that is relative (no scheme, not absolute, no backslash, no parent folder segment), and a
//     region whose startLine is an integer of at least 1 and whose endLine, when given, is not before it.
//   - The judgment note: properties.judgmentRulesApplied is false, judgmentRules is a count, and an invocation notification of
//     level note says the judgment rules were not applied.

const LEVELS = Object.freeze(["error", "warning", "note", "none"]);
// A URI that starts with a scheme, such as "file:" or "https:", and a Windows drive ("C:") are both schemes for this check.
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;
const JUDGMENT_NOTE = /judgment rules were not applied/;

/**
 * Checks a SARIF log and returns its problems.
 * @param {unknown} log The parsed SARIF log.
 * @returns {string[]} One message per problem, each starting with the JSON pointer of the value. An empty list means the log passes.
 */
export function sarifProblems(log) {
  const problems = [];
  if (!isObject(log)) return ["/: the log must be an object"];
  if (log.version !== "2.1.0") problems.push('/version: must be "2.1.0"');
  if (typeof log.$schema !== "string" || log.$schema === "") problems.push("/$schema: must be a non-empty string");
  if (!Array.isArray(log.runs) || log.runs.length === 0) {
    problems.push("/runs: must be a non-empty list");
    return problems;
  }
  log.runs.forEach((run, index) => checkRun(run, `/runs/${index}`, problems));
  return problems;
}

function checkRun(run, pointer, problems) {
  if (!isObject(run)) {
    problems.push(`${pointer}: must be an object`);
    return;
  }
  const driver = run.tool?.driver;
  if (typeof driver?.name !== "string" || driver.name === "") problems.push(`${pointer}/tool/driver/name: must be a non-empty string`);
  if (!Array.isArray(driver?.rules)) {
    problems.push(`${pointer}/tool/driver/rules: must be a list`);
    return;
  }
  const ids = [];
  driver.rules.forEach((rule, index) => {
    const where = `${pointer}/tool/driver/rules/${index}`;
    if (typeof rule?.id !== "string" || rule.id === "") problems.push(`${where}/id: must be a non-empty string`);
    if (typeof rule?.shortDescription?.text !== "string") problems.push(`${where}/shortDescription/text: must be a string`);
    if (ids.includes(rule?.id)) problems.push(`${where}/id: ${rule.id} is listed twice`);
    ids.push(rule?.id);
  });
  if (!Array.isArray(run.results)) {
    problems.push(`${pointer}/results: must be a list`);
  } else {
    run.results.forEach((result, index) => checkResult(result, `${pointer}/results/${index}`, driver.rules, problems));
  }
  checkInvocations(run, pointer, problems);
  checkJudgmentNote(run, pointer, problems);
}

function checkResult(result, pointer, rules, problems) {
  if (!isObject(result)) {
    problems.push(`${pointer}: must be an object`);
    return;
  }
  const index = result.ruleIndex;
  if (typeof result.ruleId !== "string" || !rules.some((rule) => rule?.id === result.ruleId)) {
    problems.push(`${pointer}/ruleId: ${JSON.stringify(result.ruleId)} is not a rule of the run`);
  }
  if (!Number.isInteger(index) || index < 0 || index >= rules.length) {
    problems.push(`${pointer}/ruleIndex: must be an index of the rules list`);
  } else if (rules[index]?.id !== result.ruleId) {
    problems.push(`${pointer}/ruleIndex: names ${rules[index]?.id}, not ${JSON.stringify(result.ruleId)}`);
  }
  if (!LEVELS.includes(result.level)) problems.push(`${pointer}/level: must be one of ${LEVELS.join(", ")}`);
  if (typeof result.message?.text !== "string" || result.message.text === "") {
    problems.push(`${pointer}/message/text: must be a non-empty string`);
  }
  if (result.locations === undefined) return;
  if (!Array.isArray(result.locations) || result.locations.length === 0) {
    problems.push(`${pointer}/locations: must be a non-empty list when it is given`);
    return;
  }
  result.locations.forEach((location, index) => checkLocation(location, `${pointer}/locations/${index}`, problems));
}

function checkLocation(location, pointer, problems) {
  const physical = location?.physicalLocation;
  if (!isObject(physical)) {
    problems.push(`${pointer}/physicalLocation: must be an object`);
    return;
  }
  const uri = physical.artifactLocation?.uri;
  for (const reason of uriProblems(uri)) problems.push(`${pointer}/physicalLocation/artifactLocation/uri: ${reason}`);
  if (physical.region === undefined) return;
  const region = physical.region;
  if (!isObject(region) || !Number.isInteger(region.startLine) || region.startLine < 1) {
    problems.push(`${pointer}/physicalLocation/region/startLine: must be an integer of at least 1`);
    return;
  }
  if (region.endLine !== undefined && (!Number.isInteger(region.endLine) || region.endLine < region.startLine)) {
    problems.push(`${pointer}/physicalLocation/region/endLine: must be an integer that is not before startLine`);
  }
}

// The reasons why a uri of the target is not a relative reference. An empty list means it is one.
function uriProblems(uri) {
  if (typeof uri !== "string" || uri === "") return ["must be a non-empty string"];
  const reasons = [];
  if (SCHEME.test(uri)) reasons.push("has a scheme, so it is not relative");
  if (uri.startsWith("/")) reasons.push("is absolute");
  if (uri.includes("\\")) reasons.push("has a backslash");
  if (uri.split("/").includes("..")) reasons.push("has a parent folder segment");
  return reasons;
}

function checkInvocations(run, pointer, problems) {
  const first = Array.isArray(run.invocations) ? run.invocations[0] : undefined;
  if (typeof first?.executionSuccessful !== "boolean") {
    problems.push(`${pointer}/invocations/0/executionSuccessful: must be a boolean`);
  }
}

// The judgment note: the properties say the judgment rules were not applied, and a note notification says so in its text.
function checkJudgmentNote(run, pointer, problems) {
  const properties = run.properties;
  if (properties?.judgmentRulesApplied !== false) problems.push(`${pointer}/properties/judgmentRulesApplied: must be false`);
  if (!Number.isInteger(properties?.judgmentRules) || properties.judgmentRules < 0) {
    problems.push(`${pointer}/properties/judgmentRules: must be a count`);
  }
  const notifications = Array.isArray(run.invocations) ? run.invocations.flatMap((item) => item?.toolExecutionNotifications ?? []) : [];
  const noted = notifications.some((item) => item?.level === "note" && JUDGMENT_NOTE.test(item?.message?.text ?? ""));
  if (!noted) problems.push(`${pointer}/invocations: no note says the judgment rules were not applied`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
