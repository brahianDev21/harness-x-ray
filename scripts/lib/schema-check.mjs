// A checker for the subset of JSON Schema that the schemas of this repository use. The scripts use it to check the inputs that
// they read (remediation.json, agent-fragments.json), and the tests use it to check the values that the commands write.
// SUPPORTED_KEYWORDS are the keywords it checks: $ref into the schema's own $defs, type, const, enum, oneOf, anyOf, allOf, if,
// then, else, not, required, properties with additionalProperties false, items, minItems, maxItems, uniqueItems, pattern,
// minLength, maxLength, minimum and maximum. ANNOTATION_KEYWORDS do not constrain a value, so they are ignored on purpose. Any
// other keyword is an error: a constraint that is silently ignored would accept any value, so a schema that uses one must extend
// this file first. The problem messages name a JSON pointer and a fixed text, never a key or a value of the checked value: a key
// of an agent's file can hold a secret. It reads nothing but the values it is given.

export const SUPPORTED_KEYWORDS = Object.freeze([
  "$ref",
  "type",
  "const",
  "enum",
  "oneOf",
  "anyOf",
  "allOf",
  "if",
  "then",
  "else",
  "not",
  "required",
  "properties",
  "additionalProperties",
  "items",
  "minItems",
  "maxItems",
  "uniqueItems",
  "pattern",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
]);

// $defs holds the subschemas that $ref points to. format is an annotation in JSON Schema 2020-12: no value is checked against it.
export const ANNOTATION_KEYWORDS = Object.freeze([
  "$schema",
  "$id",
  "$comment",
  "$defs",
  "title",
  "description",
  "examples",
  "default",
  "format",
]);

const KNOWN = new Set([...SUPPORTED_KEYWORDS, ...ANNOTATION_KEYWORDS]);

/**
 * Checks a value against a schema, and returns the problems it finds.
 * @param {object} schema The schema. A $ref points into the root schema, for example "#/$defs/scopeAll". A keyword that is not in
 *   SUPPORTED_KEYWORDS or ANNOTATION_KEYWORDS throws, so a constraint is never ignored.
 * @param {unknown} value The value to check.
 * @param {string} [pointer=""] The JSON pointer of the value, used in the messages.
 * @param {object} [root=schema] The root schema, which the $ref entries resolve against.
 * @returns {string[]} The problems, each with its JSON pointer. An empty list means the value passes.
 * @throws {Error} If the schema uses a keyword that the checker neither supports nor ignores on purpose.
 */
export function schemaProblems(schema, value, pointer = "", root = schema) {
  assertKnownKeywords(schema);
  if (schema.$ref !== undefined) return schemaProblems(resolveRef(root, schema.$ref), value, pointer, root);
  const where = pointer === "" ? "/" : pointer;
  const problems = [];
  if (schema.const !== undefined && !sameValue(schema.const, value)) problems.push(`${where} must be ${JSON.stringify(schema.const)}`);
  if (schema.enum !== undefined && !schema.enum.some((item) => sameValue(item, value))) {
    problems.push(`${where} is not one of ${JSON.stringify(schema.enum)}`);
  }
  if (schema.type !== undefined && !typeMatches(schema.type, value)) problems.push(`${where} must be ${JSON.stringify(schema.type)}`);
  if (schema.oneOf !== undefined) {
    const matches = schema.oneOf.filter((branch) => schemaProblems(branch, value, pointer, root).length === 0).length;
    if (matches !== 1) problems.push(`${where} matches ${matches} of the oneOf branches, not exactly one`);
  }
  if (schema.anyOf !== undefined && !schema.anyOf.some((branch) => schemaProblems(branch, value, pointer, root).length === 0)) {
    problems.push(`${where} matches none of the anyOf branches`);
  }
  for (const branch of schema.allOf ?? []) problems.push(...schemaProblems(branch, value, pointer, root));
  if (schema.if !== undefined) {
    const branch = schemaProblems(schema.if, value, pointer, root).length === 0 ? schema.then : schema.else;
    if (branch !== undefined) problems.push(...schemaProblems(branch, value, pointer, root));
  }
  if (schema.not !== undefined && schemaProblems(schema.not, value, pointer, root).length === 0) {
    problems.push(`${where} matches the not branch`);
  }
  if (typeof value === "string") problems.push(...stringProblems(schema, value, where));
  if (typeof value === "number") problems.push(...numberProblems(schema, value, where));
  if (Array.isArray(value)) problems.push(...arrayProblems(schema, value, pointer, where, root));
  if (isObject(value)) problems.push(...objectProblems(schema, value, pointer, where, root));
  return problems;
}

function assertKnownKeywords(schema) {
  if (!isObject(schema)) return;
  for (const key of Object.keys(schema)) {
    if (!KNOWN.has(key)) throw new Error(`schema-check: the schema keyword "${key}" is not supported`);
  }
}

function stringProblems(schema, value, where) {
  const problems = [];
  const length = [...value].length;
  if (schema.minLength !== undefined && length < schema.minLength) problems.push(`${where} is shorter than ${schema.minLength}`);
  if (schema.maxLength !== undefined && length > schema.maxLength) problems.push(`${where} is longer than ${schema.maxLength}`);
  if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) {
    problems.push(`${where} does not match ${schema.pattern}`);
  }
  return problems;
}

function numberProblems(schema, value, where) {
  const problems = [];
  if (schema.minimum !== undefined && value < schema.minimum) problems.push(`${where} is less than ${schema.minimum}`);
  if (schema.maximum !== undefined && value > schema.maximum) problems.push(`${where} is more than ${schema.maximum}`);
  return problems;
}

function arrayProblems(schema, value, pointer, where, root) {
  const problems = [];
  if (schema.minItems !== undefined && value.length < schema.minItems) problems.push(`${where} has fewer than ${schema.minItems} items`);
  if (schema.maxItems !== undefined && value.length > schema.maxItems) problems.push(`${where} has more than ${schema.maxItems} items`);
  if (schema.uniqueItems === true && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
    problems.push(`${where} repeats an item`);
  }
  if (schema.items !== undefined) {
    value.forEach((item, index) => problems.push(...schemaProblems(schema.items, item, `${pointer}/${index}`, root)));
  }
  return problems;
}

function objectProblems(schema, value, pointer, where, root) {
  const problems = [];
  const properties = schema.properties ?? {};
  let unlisted = 0;
  for (const key of Object.keys(value)) {
    if (Object.hasOwn(properties, key)) {
      problems.push(...schemaProblems(properties[key], value[key], `${pointer}/${key}`, root));
    } else if (schema.additionalProperties === false) {
      unlisted += 1;
    }
  }
  // The key names are not in the message: a key of an agent's file may be a secret. The count and the pointer of the object are.
  if (unlisted > 0) problems.push(`${where} has ${unlisted} key(s) that are not in the schema`);
  for (const key of schema.required ?? []) {
    if (!Object.hasOwn(value, key)) problems.push(`${where === "/" ? "" : where}/${key} is required`);
  }
  return problems;
}

function resolveRef(root, ref) {
  if (!ref.startsWith("#/")) throw new Error(`only local references are supported: ${ref}`);
  return ref
    .slice(2)
    .split("/")
    .reduce((node, part) => node[part], root);
}

function typeMatches(type, value) {
  const types = Array.isArray(type) ? type : [type];
  return types.some((name) => {
    if (name === "object") return isObject(value);
    if (name === "array") return Array.isArray(value);
    if (name === "string") return typeof value === "string";
    if (name === "boolean") return typeof value === "boolean";
    if (name === "integer") return Number.isSafeInteger(value);
    if (name === "number") return typeof value === "number" && Number.isFinite(value);
    if (name === "null") return value === null;
    return false;
  });
}

function sameValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
