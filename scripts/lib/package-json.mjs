// The root package.json, read as data. The file is parsed with JSON.parse and never run or required.
// Every measure that needs its scripts or fields reads it through this module, so a file that is missing,
// unreadable or invalid is seen the same way everywhere. The warnings are the caller's to record.

/**
 * Reads and parses a package.json of the target through ctx.readText.
 * @param {{ readText: (rel: string) => object }} ctx
 * @param {string} [rel] The file, relative to the target. The root package.json by default.
 * @returns {{ status: "absent" } | { status: "unreadable" } | { status: "invalid", detail: string } | { status: "ok", data: object }}
 *   "absent": no file. "unreadable": the file exists but cannot be read (a skipped read of any reason but
 *   not-found). "invalid": not JSON ("not-json") or not a JSON object ("not-object").
 */
export function readPackageJson(ctx, rel = "package.json") {
  const read = ctx.readText(rel);
  if (!read.ok) return read.reason === "not-found" ? { status: "absent" } : { status: "unreadable" };
  let data;
  try {
    data = JSON.parse(read.text);
  } catch {
    return { status: "invalid", detail: "not-json" };
  }
  if (!isObject(data)) return { status: "invalid", detail: "not-object" };
  return { status: "ok", data };
}

/**
 * The scripts of a parsed package.json. A missing "scripts" key is an empty map. A "scripts" value that is
 * not an object is not usable. A script whose value is not a string has no command text, so it gets "".
 * @param {object} data A parsed package.json object.
 * @returns {{ ok: true, scripts: Map<string, string> } | { ok: false, detail: "scripts-not-object" }}
 */
export function packageScripts(data) {
  if (data.scripts === undefined) return { ok: true, scripts: new Map() };
  if (!isObject(data.scripts)) return { ok: false, detail: "scripts-not-object" };
  const scripts = new Map(
    Object.entries(data.scripts).map(([name, command]) => [name, typeof command === "string" ? command : ""]),
  );
  return { ok: true, scripts };
}

export function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
