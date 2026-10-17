import assert from "node:assert/strict";
import { test } from "node:test";
import { parseFrontmatter } from "../scripts/lib/frontmatter.mjs";

// Joins lines of a document with LF, so that each test reads like the file it describes.
function doc(...lines) {
  return lines.join("\n");
}

// Every value that is an object (not an array) must be exactly { error } with a line-numbered
// message. The parser produces no other kind of object value, so callers can tell them apart.
function assertOnlyErrorObjects(data) {
  for (const [key, value] of Object.entries(data)) {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      assert.deepEqual(Object.keys(value), ["error"], `value of ${key} is not an error object`);
      assert.match(value.error, /^line \d+: /, `error of ${key} has no line number`);
    }
  }
}

// Skill frontmatter, copied from the code blocks of https://code.claude.com/docs/en/skills
// (sections "Task content", "Frontmatter reference", "Pre-approve tools for a skill",
// "Run skills in a subagent", "Use string substitutions" and "Generate visual output").
test("skill frontmatter examples from the documentation parse to the documented values", () => {
  const cases = [
    [
      doc("---", "name: deploy", "description: Deploy the application to production", "context: fork",
        "disable-model-invocation: true", "---", "Deploy $ARGUMENTS"),
      { name: "deploy", description: "Deploy the application to production", context: "fork",
        "disable-model-invocation": true },
    ],
    [
      doc("---", "name: my-skill", "description: What this skill does", "disable-model-invocation: true",
        "allowed-tools: Read Grep", "---", "Body"),
      { name: "my-skill", description: "What this skill does", "disable-model-invocation": true,
        "allowed-tools": "Read Grep" },
    ],
    [
      doc("---", "name: commit", "description: Stage and commit the current changes",
        "disable-model-invocation: true", "allowed-tools: Bash(git add *) Bash(git commit *) Bash(git status *)",
        "---"),
      { name: "commit", description: "Stage and commit the current changes", "disable-model-invocation": true,
        "allowed-tools": "Bash(git add *) Bash(git commit *) Bash(git status *)" },
    ],
    [
      doc("---", "name: pr-summary", "description: Summarize changes in a pull request", "context: fork",
        "agent: Explore", "allowed-tools: Bash(gh *)", "---"),
      { name: "pr-summary", description: "Summarize changes in a pull request", context: "fork",
        agent: "Explore", "allowed-tools": "Bash(gh *)" },
    ],
    [
      // The "${CLAUDE_SKILL_DIR}" braces are inside a plain scalar, which YAML allows.
      doc("---", "name: render-chart", "description: Render a chart from a CSV file",
        "allowed-tools: Bash(${CLAUDE_SKILL_DIR}/scripts/render.sh *)", "---"),
      { name: "render-chart", description: "Render a chart from a CSV file",
        "allowed-tools": "Bash(${CLAUDE_SKILL_DIR}/scripts/render.sh *)" },
    ],
    [
      doc("---", "name: codebase-visualizer",
        "description: Generate an interactive collapsible tree visualization of your codebase. Use when exploring a new repo, understanding project structure, or identifying large files.",
        "allowed-tools: Bash(python3 *)", "---"),
      { name: "codebase-visualizer",
        description: "Generate an interactive collapsible tree visualization of your codebase. Use when exploring a new repo, understanding project structure, or identifying large files.",
        "allowed-tools": "Bash(python3 *)" },
    ],
  ];
  for (const [text, expected] of cases) {
    const result = parseFrontmatter(text);
    assert.deepEqual(result.data, expected);
    assert.equal("error" in result, false);
  }
});

// Subagent frontmatter, copied from the code blocks of https://code.claude.com/docs/en/sub-agents
// (sections "Minimal subagent", "Allowlist of tools", "Denylist of tools", "Quickstart subagent").
test("subagent frontmatter examples from the documentation parse to the documented values", () => {
  const minimal = parseFrontmatter(doc(
    "---",
    "name: code-reviewer",
    "description: Reviews code for quality and best practices",
    "tools: Read, Glob, Grep",
    "model: sonnet",
    "---",
  ));
  assert.deepEqual(minimal.data, {
    name: "code-reviewer",
    description: "Reviews code for quality and best practices",
    tools: "Read, Glob, Grep",
    model: "sonnet",
  });

  const quickstart = parseFrontmatter(doc(
    "---",
    "name: code-improver",
    "description: Scans files and suggests improvements for readability, performance, and best practices. Use after writing or modifying code.",
    "tools: Read, Grep, Glob",
    "model: sonnet",
    "---",
  ));
  assert.equal(quickstart.data.description.endsWith("Use after writing or modifying code."), true);

  const denylist = parseFrontmatter(doc(
    "---",
    "name: no-writes",
    "description: Inherits the available tools except file writes",
    "disallowedTools: Write, Edit",
    "---",
  ));
  assert.deepEqual(denylist.data, {
    name: "no-writes",
    description: "Inherits the available tools except file writes",
    disallowedTools: "Write, Edit",
  });

  // The parentheses and the comma inside "Agent(worker, researcher)" are part of a plain scalar.
  const coordinator = parseFrontmatter(doc(
    "---",
    "name: coordinator",
    "description: Coordinates work across specialized agents",
    "tools: Agent(worker, researcher), Read, Bash",
    "---",
  ));
  assert.equal(coordinator.data.tools, "Agent(worker, researcher), Read, Bash");

  const localOnly = parseFrontmatter(doc(
    "---",
    "name: local-only",
    "description: Inherits every tool except those from the github MCP server",
    "disallowedTools: mcp__github",
    "---",
  ));
  assert.equal(localOnly.data.disallowedTools, "mcp__github");
});

// The documentation has no example of a multi-line description or of a list-valued field, so this
// one is written with the documented field names (see the same page for the field table).
test("a multi-line description with > and a multi-line when_to_use with | parse as folded and literal text", () => {
  const result = parseFrontmatter(doc(
    "---",
    "name: api-reviewer",
    "description: >",
    "  Reviews API changes for breaking",
    "  contract changes. Use after editing routes.",
    "when_to_use: |",
    "  Use when the diff touches routes.",
    "  Not for internal helpers.",
    "---",
    "# Body",
  ));
  assert.deepEqual(result.data, {
    name: "api-reviewer",
    description: "Reviews API changes for breaking contract changes. Use after editing routes.\n",
    when_to_use: "Use when the diff touches routes.\nNot for internal helpers.\n",
  });
  assert.equal(result.body, "# Body");
});

// Subagent with a nested hooks block, copied from "Hooks in frontmatter (nested)" in the sub-agents
// documentation. The nested block cannot be read, so hooks is { error }; the other keys still parse.
test("a subagent with a nested hooks block: the other keys parse and hooks is an error with its line", () => {
  const result = parseFrontmatter(doc(
    "---",
    "name: db-reader",
    "description: Execute read-only database queries",
    "tools: Bash",
    "hooks:",
    "  PreToolUse:",
    "    - matcher: \"Bash\"",
    "      hooks:",
    "        - type: command",
    "          command: \"./scripts/validate-readonly-query.sh\"",
    "---",
    "Body",
  ));
  assert.deepEqual(result.data, {
    name: "db-reader",
    description: "Execute read-only database queries",
    tools: "Bash",
    hooks: { error: "line 6: nested mappings are not supported" },
  });
  assert.equal(result.body, "Body");
});

test("a subagent with several nested hook events and a nested mcpServers list keeps its scalar keys", () => {
  const hooks = parseFrontmatter(doc(
    "---",
    "name: code-reviewer",
    "description: Review code changes with automatic linting",
    "hooks:",
    "  PreToolUse:",
    "    - matcher: \"Bash\"",
    "      hooks:",
    "        - type: command",
    "          command: \"./scripts/validate-command.sh\"",
    "  PostToolUse:",
    "    - matcher: \"Edit|Write\"",
    "---",
  ));
  assert.equal(hooks.data.name, "code-reviewer");
  assert.equal(hooks.data.hooks.error, "line 5: nested mappings are not supported");

  // The docs example puts a comment before the list. The list items are mappings, so it is an error.
  const servers = parseFrontmatter(doc(
    "---",
    "name: browser-tester",
    "description: Tests features in a real browser using Playwright",
    "mcpServers:",
    "  # Inline definition: scoped to this subagent only",
    "  - playwright:",
    "      type: stdio",
    "      command: npx",
    "      args: [\"-y\", \"@playwright/mcp@latest\"]",
    "  # Reference by name: reuses an already-configured server",
    "  - github",
    "---",
  ));
  assert.deepEqual(servers.data, {
    name: "browser-tester",
    description: "Tests features in a real browser using Playwright",
    mcpServers: { error: "line 6: list items that are mappings are not supported" },
  });
});

test("the subagent fields that are scalars, lists or nested blocks keep their documented types", () => {
  const result = parseFrontmatter(doc(
    "---",
    "name: api-developer",
    "description: Implement API endpoints following team conventions",
    "skills:",
    "  - api-conventions",
    "  - error-handling-patterns",
    "autoCompactWindow: 200000",
    "maxTurns: 12",
    "permissionMode: acceptEdits",
    "memory: user",
    "experimental:",
    "  cacheTtl: 1h",
    "---",
  ));
  assert.deepEqual(result.data.skills, ["api-conventions", "error-handling-patterns"]);
  assert.equal(result.data.autoCompactWindow, 200000);
  assert.equal(result.data.maxTurns, 12);
  assert.equal(result.data.permissionMode, "acceptEdits");
  assert.equal(result.data.memory, "user");
  assert.deepEqual(result.data.experimental, { error: "line 12: nested mappings are not supported" });
});

test("null, booleans, numbers and other plain scalars follow the YAML 1.2 core spellings", () => {
  const result = parseFrontmatter(doc(
    "---",
    "a: null",
    "b: ~",
    "c:",
    "d: Null",
    "e: NULL",
    "f: true",
    "g: True",
    "h: TRUE",
    "i: false",
    "j: False",
    "k: FALSE",
    "l: tRUE",
    "m: 42",
    "n: -3",
    "o: +7",
    "p: 1.5",
    "q: .5",
    "r: 1e3",
    "s: 0x1F",
    "t: 1_000",
    "u: .inf",
    "v: 2026-10-17",
    "---",
  ));
  assert.deepEqual(result.data, {
    a: null, b: null, c: null, d: null, e: null,
    f: true, g: true, h: true, i: false, j: false, k: false,
    l: "tRUE",
    m: 42, n: -3, o: 7, p: 1.5, q: 0.5, r: 1000,
    s: "0x1F", t: "1_000", u: ".inf", v: "2026-10-17",
  });
});

test("quoted scalars are always strings and follow the escape rules", () => {
  const result = parseFrontmatter(doc(
    "---",
    "a: 'true'",
    "b: \"42\"",
    "c: 'it''s'",
    "d: \"tab\\there \\u0041 \\x42\"",
    "e: \"x # not a comment\"",
    "f: 'quoted' # a comment",
    "g: \"back\\\\slash \\\"q\\\"\"",
    "h: 'single \\n stays'",
    "---",
  ));
  assert.deepEqual(result.data, {
    a: "true",
    b: "42",
    c: "it's",
    d: "tab\there A B",
    e: "x # not a comment",
    f: "quoted",
    g: 'back\\slash "q"',
    h: "single \\n stays",
  });
});

test("comments: full-line comments are ignored, a plain value ends at ' #', and '#' without a space is text", () => {
  const result = parseFrontmatter(doc(
    "---",
    "# a full-line comment",
    "model: sonnet # the default",
    "name: plain#hash",
    "empty-with-comment: # only a comment",
    "  # an indented comment under a key with no value",
    "---",
  ));
  assert.deepEqual(result.data, {
    model: "sonnet",
    name: "plain#hash",
    "empty-with-comment": null,
  });
});

test("inline lists of scalars and dash lists of scalars", () => {
  const result = parseFrontmatter(doc(
    "---",
    "tools: [Read, \"Grep\", 3, true, 'x y']",
    "none: []",
    "trailing: [a, b, ]",
    "paths: [\"src/**/*.ts\", \"lib/*.js\"]",
    "allowed-tools:",
    "  - Read",
    "  - \"Bash(git status *)\"",
    "  - 7",
    "skills:",
    "- api-conventions",
    "- error-handling-patterns",
    "---",
  ));
  assert.deepEqual(result.data, {
    tools: ["Read", "Grep", 3, true, "x y"],
    none: [],
    trailing: ["a", "b"],
    paths: ["src/**/*.ts", "lib/*.js"],
    "allowed-tools": ["Read", "Bash(git status *)", 7],
    skills: ["api-conventions", "error-handling-patterns"],
  });
});

test("block scalars: literal and folded, with the - + and indentation indicators", () => {
  const result = parseFrontmatter(doc(
    "---",
    "literal: |",
    "  line one",
    "    indented",
    "  line three",
    "keep: |+",
    "  kept",
    "",
    "strip: |-",
    "  stripped",
    "folded: >",
    "  folded one",
    "  folded two",
    "",
    "  new paragraph",
    "    more indented",
    "  back to normal",
    "explicit: |2",
    "    two extra",
    "---",
  ));
  assert.deepEqual(result.data, {
    literal: "line one\n  indented\nline three\n",
    keep: "kept\n\n",
    strip: "stripped",
    folded: "folded one folded two\nnew paragraph\n  more indented\nback to normal\n",
    explicit: "  two extra\n",
  });
});

test("an empty block scalar is an empty string", () => {
  const result = parseFrontmatter(doc("---", "description: >", "name: x", "---"));
  assert.deepEqual(result.data, { description: "", name: "x" });
});

test("a plain value that cannot be read, such as an alias or a flow mapping, is an error for that key only", () => {
  const cases = [
    ["meta: {a: 1}", "line 2: flow mappings ({ }) are not supported"],
    ["anchor: &x 1", 'line 2: a value that starts with "&" is read by YAML as an anchor, alias or tag; quote it'],
    ["alias: *x", 'line 2: a value that starts with "*" is read by YAML as an anchor, alias or tag; quote it'],
    ["mixed: Use this: that", 'line 2: a plain value cannot contain ": "; quote the value'],
    ["ref: @x", 'line 2: a value cannot start with "@"; quote it'],
    ["bullet: - x", 'line 2: a value cannot start with "- "; quote it'],
    ["block: |x", 'line 2: invalid block scalar header "|x"'],
    ["open: \"abc", "line 2: the double-quoted value does not end on this line; multi-line quoted values are not supported"],
    ["escape: \"bad \\q\"", 'line 2: unknown escape sequence "\\q"'],
    ["flow: [a, b", "line 2: inline list is not closed on this line; multi-line lists are not supported"],
    ["empty: [a,,b]", "line 2: inline list has an empty item"],
    ["nested: [[a]]", "line 2: nested collections are not supported in inline lists"],
    ["greeting: this is", "  continued", "line 3: a value continued on the next lines is not supported"],
    ["values:", "  just text", "line 3: a value on the lines below its key is not supported; put it on the key line"],
    ["hooks:", "  PreToolUse:", "    - matcher: x", "line 3: nested mappings are not supported"],
    ["items:", "  - name: x", "    other: y", "line 3: list items that are mappings are not supported"],
    ["nested:", "  - [a, b]", "line 3: nested lists are not supported"],
  ];
  for (const [first, ...rest] of cases) {
    const expected = rest.pop();
    const result = parseFrontmatter(doc("---", first, ...rest, "name: ok", "---", "Body"));
    assert.equal("error" in result, false, `${first}: unexpected whole-file error`);
    assert.equal(result.data.name, "ok", `${first}: the next key was not parsed`);
    const key = first.split(":")[0];
    assert.deepEqual(result.data[key], { error: expected }, first);
    assert.equal(result.body, "Body");
    assertOnlyErrorObjects(result.data);
  }
});

test("a value outside the subset keeps the other keys, in their order", () => {
  const result = parseFrontmatter(doc("---", "name: x", "meta: {a: 1}", "description: y", "---"));
  assert.deepEqual(result.data, {
    name: "x",
    meta: { error: "line 3: flow mappings ({ }) are not supported" },
    description: "y",
  });
});

test("an unclosed frontmatter is an error that points at line 1, and the body is the whole text", () => {
  const text = "---\nname: x\n";
  const result = parseFrontmatter(text);
  assert.match(result.error, /^line 1: /);
  assert.equal(result.body, text);
  assert.equal("data" in result, false);
});

test("broken structure is a whole-file error with the line number of the problem", () => {
  const cases = [
    ["---", "  name: x", "---", "line 2: unexpected indentation"],
    ["---", "name: x", "name: y", "---", 'line 3: duplicate key "name" (first on line 2)'],
    ["---", "allowed-tools:", "    - Read", "  - Grep", "---", "line 4: bad indentation"],
    ["---", "name: x", "\tdescription: y", "---", "line 3: tabs cannot be used for indentation"],
    ["---", "just text", "---", 'line 2: expected "key: value" at the top level'],
    ["---", "name:x", "---", 'line 2: expected "key: value" at the top level'],
    ["---", "- item", "---", 'line 2: expected "key: value" at the top level'],
    ["---", "hooks:", "    PreToolUse:", "  - x", "---", "line 4: bad indentation"],
  ];
  for (const [...lines] of cases) {
    const expected = lines.pop();
    const result = parseFrontmatter(doc(...lines, "Body"));
    assert.match(result.error, /^line \d+: /, lines.join("|"));
    assert.ok(result.error.startsWith(expected), `${result.error} does not start with ${expected}`);
    assert.equal(result.body, "Body");
    assert.equal("data" in result, false);
  }
});

test("a broken frontmatter never throws, and its body is the text after the closing line", () => {
  const result = parseFrontmatter("---\njust text\n---\n# Title\n");
  assert.equal(result.error, 'line 2: expected "key: value" at the top level');
  assert.equal(result.body, "# Title\n");
});

test("a text without frontmatter has data null and the whole text as body", () => {
  assert.deepEqual(parseFrontmatter("# Title\n"), { data: null, body: "# Title\n" });
  assert.deepEqual(parseFrontmatter(""), { data: null, body: "" });
  // Three dashes followed by text on the same line do not open a frontmatter.
  assert.deepEqual(parseFrontmatter("---x\nname: y\n"), { data: null, body: "---x\nname: y\n" });
});

test("an empty frontmatter gives an empty object, and the body is what follows it", () => {
  assert.deepEqual(parseFrontmatter("---\n---\nBody"), { data: {}, body: "Body" });
});

test("a leading BOM and CRLF line endings parse like LF, and the body has LF endings", () => {
  const result = parseFrontmatter("\uFEFF---\r\nname: x\r\ndescription: >\r\n  one\r\n  two\r\n---\r\nBody\r\n");
  assert.deepEqual(result, {
    data: { name: "x", description: "one two\n" },
    body: "Body\n",
  });
});

test("non-string input never throws and gives no frontmatter", () => {
  const inputs = [undefined, null, 42, {}, [], Symbol("x"), () => {}, Buffer.from("---\nname: x\n---")];
  for (const input of inputs) {
    assert.deepEqual(parseFrontmatter(input), { data: null, body: "" });
  }
});

test("random input never throws, and every error names its line", () => {
  // A xorshift32 generator with a fixed seed, so that the inputs (and any failure) are the same on every run.
  let seed = 0x20261017;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) / 4294967296;
  };
  const pieces = [
    "---", "\n", "\r\n", "\t", " ", "  ", "name", ":", ": ", "- ", "-", "#", "\"", "'", "|", ">", "+",
    "[", "]", ",", "{", "}", "&", "*", "!", "\\", "1", "x", "\uFEFF", "\uD83D", "~", "null", "true",
    "\n---\n", "key: |\n  ", "\n  - ",
  ];
  for (let round = 0; round < 3000; round += 1) {
    const length = Math.floor(next() * 40);
    let text = "";
    for (let piece = 0; piece < length; piece += 1) {
      text += pieces[Math.floor(next() * pieces.length)];
    }
    const result = parseFrontmatter(text);
    assert.equal(typeof result.body, "string");
    if ("error" in result) {
      assert.match(result.error, /^line \d+: /, JSON.stringify(text));
    } else if (result.data !== null) {
      assertOnlyErrorObjects(result.data);
    }
  }
});
