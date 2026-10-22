// Tests of lib/schema-check.mjs: the keywords it checks, the messages (which never print a key of the checked value), the refusal of
// a keyword that it neither checks nor ignores on purpose, and a walk over every schema of schemas/ that fails on any other keyword.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { ANNOTATION_KEYWORDS, SUPPORTED_KEYWORDS, schemaProblems } from "../scripts/lib/schema-check.mjs";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = path.join(TEST_DIR, "..", "schemas");
// A secret-shaped key name, built at test time, so that this file holds no token-shaped text.
const SECRET_KEY = ["gh", "p_"].join("") + ["A1b2C3d4E5", "f6G7h8I9j0", "K1l2M3n4O5", "p6Q7r8"].join("");

// The subschemas of a schema node by the keyword that holds them. The keywords that hold values (const, enum, default, examples,
// required) are not schemas, so they are not walked.
const MAP_KEYWORDS = ["properties", "$defs", "patternProperties", "dependentSchemas"];
const SUBSCHEMA_KEYWORDS = ["items", "additionalProperties", "not", "if", "then", "else", "contains", "propertyNames"];
const LIST_KEYWORDS = ["allOf", "anyOf", "oneOf", "prefixItems"];

// Every keyword of a schema, with the place where it is written.
function keywordsOf(schema, where = "", found = []) {
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) return found;
  for (const [keyword, value] of Object.entries(schema)) {
    found.push({ keyword, where });
    if (MAP_KEYWORDS.includes(keyword)) {
      for (const [name, sub] of Object.entries(value)) keywordsOf(sub, `${where}/${keyword}/${name}`, found);
    } else if (SUBSCHEMA_KEYWORDS.includes(keyword)) {
      keywordsOf(value, `${where}/${keyword}`, found);
    } else if (LIST_KEYWORDS.includes(keyword)) {
      value.forEach((sub, index) => keywordsOf(sub, `${where}/${keyword}/${index}`, found));
    }
  }
  return found;
}

describe("schemaProblems: the keywords it checks", () => {
  test("type, const and enum give one problem each, and values that match give none (positive control)", () => {
    assert.deepEqual(schemaProblems({ type: "integer" }, 3), []);
    assert.deepEqual(schemaProblems({ type: "integer" }, 3.5), ['/ must be "integer"']);
    assert.deepEqual(schemaProblems({ type: ["string", "null"] }, null), []);
    assert.deepEqual(schemaProblems({ const: 1 }, 2), ["/ must be 1"]);
    assert.deepEqual(schemaProblems({ enum: ["a", "b"] }, "c"), ['/ is not one of ["a","b"]']);
  });

  test("minimum and maximum bound a number, both inclusive", () => {
    const schema = { type: "integer", minimum: 1, maximum: 100 };
    assert.deepEqual(schemaProblems(schema, 1), []);
    assert.deepEqual(schemaProblems(schema, 100), []);
    assert.deepEqual(schemaProblems(schema, 0), ["/ is less than 1"]);
    assert.deepEqual(schemaProblems(schema, 101), ["/ is more than 100"]);
  });

  test("minLength, maxLength and pattern bound a string, and length counts code points", () => {
    assert.deepEqual(schemaProblems({ maxLength: 2 }, "😀😀"), [], "two code points, four code units");
    assert.deepEqual(schemaProblems({ maxLength: 2 }, "😀😀😀"), ["/ is longer than 2"]);
    assert.deepEqual(schemaProblems({ minLength: 1 }, ""), ["/ is shorter than 1"]);
    assert.deepEqual(schemaProblems({ pattern: "^a+$" }, "aa"), []);
    assert.deepEqual(schemaProblems({ pattern: "^a+$" }, "ab"), ["/ does not match ^a+$"]);
  });

  test("minItems, maxItems and uniqueItems bound a list", () => {
    assert.deepEqual(schemaProblems({ minItems: 1, maxItems: 2, uniqueItems: true }, [1, 2]), []);
    assert.deepEqual(schemaProblems({ maxItems: 2 }, [1, 2, 3]), ["/ has more than 2 items"]);
    assert.deepEqual(schemaProblems({ minItems: 1 }, []), ["/ has fewer than 1 items"]);
    assert.deepEqual(schemaProblems({ uniqueItems: true }, [{ a: 1 }, { a: 1 }]), ["/ repeats an item"]);
  });

  test("oneOf needs exactly one branch, anyOf one branch, and allOf every branch", () => {
    assert.deepEqual(schemaProblems({ oneOf: [{ type: "string" }, { minLength: 2 }] }, "ab"), ["/ matches 2 of the oneOf branches, not exactly one"]);
    assert.deepEqual(schemaProblems({ anyOf: [{ type: "number" }, { type: "boolean" }] }, "x"), ["/ matches none of the anyOf branches"]);
    assert.deepEqual(schemaProblems({ allOf: [{ type: "object" }, { required: ["a"] }] }, {}), ["/a is required"]);
    assert.deepEqual(schemaProblems({ allOf: [{ type: "object" }, { required: ["a"] }] }, { a: 1 }), []);
  });

  test("if and then check a value only when the if holds, and not refuses a value that matches its branch", () => {
    const schema = {
      if: { required: ["kind"], properties: { kind: { const: "measured" } } },
      then: { required: ["id"] },
      else: { required: ["note"] },
    };
    assert.deepEqual(schemaProblems(schema, { kind: "measured" }), ["/id is required"]);
    assert.deepEqual(schemaProblems(schema, { kind: "measured", id: "mf-1" }), []);
    assert.deepEqual(schemaProblems(schema, { kind: "judgment" }), ["/note is required"]);
    assert.deepEqual(schemaProblems({ not: { required: ["x"] } }, { x: 1 }), ["/ matches the not branch"]);
    assert.deepEqual(schemaProblems({ not: { required: ["x"] } }, {}), []);
  });

  test("$ref resolves into the root's $defs", () => {
    const schema = { $defs: { count: { type: "integer", minimum: 0 } }, type: "object", properties: { n: { $ref: "#/$defs/count" } } };
    assert.deepEqual(schemaProblems(schema, { n: 0 }), []);
    assert.deepEqual(schemaProblems(schema, { n: -1 }), ["/n is less than 0"]);
  });

  test("additionalProperties false refuses a key that the schema does not list, and the message never names the key", () => {
    const schema = { type: "object", properties: { a: { type: "string" } }, additionalProperties: false };
    assert.deepEqual(schemaProblems(schema, { a: "x" }, "/fragments/0"), [], "positive control: the listed key passes");
    const problems = schemaProblems(schema, { a: "x", [SECRET_KEY]: "y" }, "/fragments/0");
    assert.deepEqual(problems, ["/fragments/0 has 1 key(s) that are not in the schema"]);
    assert.ok(!problems.join("\n").includes(SECRET_KEY), "the key is not in the message");
    assert.deepEqual(schemaProblems(schema, { [SECRET_KEY]: 1 }), ["/ has 1 key(s) that are not in the schema"]);
  });

  test("a keyword that the checker neither checks nor ignores throws, and the message names the keyword", () => {
    assert.throws(() => schemaProblems({ contains: { type: "string" } }, ["a"]), /the schema keyword "contains" is not supported/);
    assert.deepEqual(schemaProblems({ type: "array" }, ["a"]), [], "positive control: a supported keyword checks and passes");
  });

  test("a keyword that is nested in a schema that the value reaches is refused too", () => {
    const schema = { type: "object", properties: { a: { type: "array", dependentRequired: {} } } };
    assert.throws(() => schemaProblems(schema, { a: [] }), /"dependentRequired" is not supported/);
  });

  test("the annotations check nothing: format, title, description, examples and default are ignored on purpose", () => {
    const schema = { format: "date-time", title: "t", description: "d", $comment: "c", examples: [1], default: 2 };
    assert.deepEqual(schemaProblems(schema, "not a date"), []);
  });
});

describe("the schemas of schemas/", () => {
  const files = fs.readdirSync(SCHEMAS_DIR).filter((name) => name.endsWith(".json")).sort();

  test("the walk finds the keywords of the schemas, and the walk itself finds an unsupported one (positive and negative control)", () => {
    const found = files.flatMap((file) => keywordsOf(JSON.parse(fs.readFileSync(path.join(SCHEMAS_DIR, file), "utf8")), file));
    assert.ok(found.some((item) => item.keyword === "$ref" && item.where.startsWith("remediation.schema.json")), "a $ref is found");
    assert.deepEqual(keywordsOf({ properties: { contains: { contains: {} } } }).map((item) => item.keyword), ["properties", "contains"]);
  });

  test("every keyword of every schema is supported by the checker or ignored on purpose", () => {
    const allowed = new Set([...SUPPORTED_KEYWORDS, ...ANNOTATION_KEYWORDS]);
    const unknown = [];
    for (const file of files) {
      for (const { keyword, where } of keywordsOf(JSON.parse(fs.readFileSync(path.join(SCHEMAS_DIR, file), "utf8")), file)) {
        if (!allowed.has(keyword)) unknown.push(`${where}: ${keyword}`);
      }
    }
    assert.deepEqual(unknown, [], "a keyword that the checker would ignore: support it in scripts/lib/schema-check.mjs first");
  });

  test("the supported and the ignored lists do not overlap", () => {
    const overlap = SUPPORTED_KEYWORDS.filter((keyword) => ANNOTATION_KEYWORDS.includes(keyword));
    assert.deepEqual(overlap, []);
  });
});
