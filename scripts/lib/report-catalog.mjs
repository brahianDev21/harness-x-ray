// What the report reads from the rule catalog: for each rule, its sources and its evidence level, the titles, URLs and
// levels of the sources, and the catalog version. The rule list is the one loadRules returns, so the report and the
// validator see the same rules. Only the harness folder is read; nothing from a target.
//
// Catalog version. The catalog has no version field. The version is the number of rule files and the first 12 hex
// digits of a SHA-256 over the rule files, sorted by file name, each written as its name, a line feed, its text with
// line endings normalized to LF, and a line feed. rules/sources.json is not part of it.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseFrontmatter } from "./frontmatter.mjs";

const VERSION_HEX_DIGITS = 12;

/**
 * Reads the catalog for the report.
 * @param {string} harnessRoot The folder that contains rules/.
 * @param {Array<{ id: string, title: string, axis: string, kind: string, file: string }>} rules As loadRules returns them.
 * @returns {{
 *   rules: Map<string, { id: string, title: string, axis: string, kind: string, evidence: string, sources: string[] }>,
 *   sources: Map<string, { id: string, title: string, url: string, type: string }>,
 *   version: { count: number, sha256: string },
 * }}
 * @throws {Error} If a rule has no evidence level or no source list, or sources.json is not in the expected shape.
 */
export function readCatalog(harnessRoot, rules) {
  const hash = createHash("sha256");
  const ruleMap = new Map();
  const byName = [...rules].sort((a, b) => compareText(a.file, b.file));
  for (const rule of byName) {
    const text = fs.readFileSync(path.join(harnessRoot, rule.file), "utf8");
    hash.update(`${rule.file}\n${text.replace(/\r\n?/g, "\n")}\n`);
    const { data } = parseFrontmatter(text);
    if (data === null || typeof data.evidence !== "string" || !Array.isArray(data.sources)) {
      throw new Error(`${rule.file}: the frontmatter needs evidence as text and sources as a list`);
    }
    ruleMap.set(rule.id, {
      id: rule.id,
      title: rule.title,
      axis: rule.axis,
      kind: rule.kind,
      evidence: data.evidence,
      sources: data.sources.map((id) => String(id)),
    });
  }
  return {
    rules: ruleMap,
    sources: readSources(harnessRoot),
    version: { count: rules.length, sha256: hash.digest("hex").slice(0, VERSION_HEX_DIGITS) },
  };
}

// The sources of rules/sources.json, by id. Each entry needs text for every field.
function readSources(harnessRoot) {
  const file = path.join(harnessRoot, "rules", "sources.json");
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(parsed?.sources)) throw new Error("rules/sources.json needs a sources list");
  const byId = new Map();
  for (const item of parsed.sources) {
    for (const field of ["id", "title", "url", "type"]) {
      if (typeof item?.[field] !== "string") throw new Error(`rules/sources.json: a source has no text ${field}`);
    }
    byId.set(item.id, { id: item.id, title: item.title, url: item.url, type: item.type });
  }
  return byId;
}

// Plain code-unit comparison, so the order does not depend on the locale.
function compareText(a, b) {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}
