// A checker for the subset of JSON Schema that the schemas of this repository use, for the tests that check the values they
// write (not their text). It covers $ref into the schema's own $defs, oneOf, anyOf, const, enum, type, required, properties
// with additionalProperties false, items, minItems, uniqueItems, pattern, minLength and maxLength. A keyword that is not in
// this list is ignored, so a schema that uses another keyword must extend this file first.

/**
 * Checks a value against a schema, and returns the problems it finds.
 * @param {object} schema The schema. A $ref points into the root schema, for example "#/$defs/scopeAll".
 * @param {unknown} value The value to check.
 * @param {string} [pointer=""] The JSON pointer of the value, used in the messages.
 * @param {object} [root=schema] The root schema, which the $ref entries resolve against.
 * @returns {string[]} The problems, each with its JSON pointer. An empty list means the value passes.
 */
export function schemaProblems(schema, value, pointer = "", root = schema) {
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
  if (typeof value === "string") problems.push(...stringProblems(schema, value, where));
  if (Array.isArray(value)) problems.push(...arrayProblems(schema, value, pointer, where, root));
  if (isObject(value)) problems.push(...objectProblems(schema, value, pointer, where, root));
  return problems;
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

function arrayProblems(schema, value, pointer, where, root) {
  const problems = [];
  if (schema.minItems !== undefined && value.length < schema.minItems) problems.push(`${where} has fewer than ${schema.minItems} items`);
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
  for (const key of Object.keys(value)) {
    if (Object.hasOwn(properties, key)) {
      problems.push(...schemaProblems(properties[key], value[key], `${pointer}/${key}`, root));
    } else if (schema.additionalProperties === false) {
      problems.push(`${pointer}/${key} is not in the schema`);
    }
  }
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
