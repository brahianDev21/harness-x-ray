import assert from "node:assert/strict";
import { test } from "node:test";
import { decide, evaluate, matchBash, parseRule } from "../scripts/lib/permissions.mjs";

// Documentation URLs cited in test names. Each example is copied from the Claude Code permission docs.
const PERMISSIONS = "https://code.claude.com/docs/en/permissions";
const MODES = "https://code.claude.com/docs/en/permission-modes";

// Rule lists in the shape of security.permissions: plain strings.
const rules = (deny = [], ask = [], allow = []) => ({ deny, ask, allow });
const bash = (command) => ({ tool: "Bash", command });
const read = (path) => ({ tool: "Read", path });
const edit = (path) => ({ tool: "Edit", path });
const fetchDomain = (domain) => ({ tool: "WebFetch", domain });

test(`wildcard table: rows that match (${PERMISSIONS}#wildcard-patterns)`, () => {
  const rows = [
    ["npm run build", "npm run build"],
    ["npm run *", "npm run build"],
    ["npm run *", "npm run test --watch"],
    ["npm run *", "npm run"],
    ["git log * main", "git log --oneline main"],
    ["git log * main", "git log -5 main"],
    ["git log * main", "git log --output=<file> main"],
    ["git * main", "git merge main"],
    ["git * main", "git push origin main"],
    ["git * main", "git -c core.fsmonitor=<script> diff main"],
    ["* --version", "node --version"],
    ["* --version", "bash -c 'echo hi' --version"],
    ["ls *", "ls -la"],
    ["ls *", "ls"],
    ["ls*", "ls -la"],
    ["ls*", "lsof"],
    ["* --help *", "npm --help x"],
  ];
  for (const [pattern, command] of rows) assert.equal(matchBash(pattern, command), true, `${pattern} / ${command}`);
});

test(`wildcard table: rows that do not match (${PERMISSIONS}#wildcard-patterns)`, () => {
  const rows = [
    ["npm run build", "npm run build --watch"],
    ["npm run *", "npm install"],
    ["git log * main", "git log main"],
    ["git log * main", "git push origin main"],
    ["git * main", "git log"],
    ["* --version", "node -v"],
    ["ls *", "lsof"],
    ["* --help *", "npm --help"],
  ];
  for (const [pattern, command] of rows) assert.equal(matchBash(pattern, command), false, `${pattern} / ${command}`);
});

test(`wildcard table: a trailing ' *' that is not the only wildcard does not match the bare command (${PERMISSIONS}#wildcard-patterns)`, () => {
  assert.equal(matchBash("git log *", "git log"), true);
  assert.equal(matchBash("* --help *", "npm --help"), false);
});

test(`':*' suffix is the same as a trailing ' *' (${PERMISSIONS}#wildcard-patterns)`, () => {
  for (const command of ["ls", "ls -la", "lsof", "ls-la", "cat ls"]) {
    assert.equal(matchBash("ls:*", command), matchBash("ls *", command), command);
  }
});

test(`a colon before a wildcard in the middle is literal (${PERMISSIONS}#wildcard-patterns)`, () => {
  assert.equal(matchBash("git:* push", "git push"), false);
  assert.equal(matchBash("git:* push", "git:x push"), true);
});

test(`Bash and Bash(*) cover every command (${PERMISSIONS}#match-all-uses-of-a-tool)`, () => {
  for (const allow of [["Bash"], ["Bash(*)"]]) {
    assert.equal(decide(rules([], [], allow), bash("rm -rf build")).decision, "allow", allow[0]);
    assert.equal(decide(rules([], [], allow), bash("node -e 'x'")).decision, "allow", allow[0]);
  }
});

test("Bash matching is case-sensitive, PowerShell matching is not", () => {
  assert.equal(matchBash("npm test", "NPM test"), false);
  assert.equal(matchBash("Get-ChildItem *", "get-childitem -r", { caseInsensitive: true }), true);
});

test(`deny Bash(aws *) beats allow Bash(aws s3 ls) (${PERMISSIONS}#manage-permissions)`, () => {
  const result = decide(rules(["Bash(aws *)"], [], ["Bash(aws s3 ls)"]), bash("aws s3 ls"));
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "Bash(aws *)");
  assert.equal(result.reason, "deny-rule");
});

test(`ask beats a more specific allow (${PERMISSIONS}#manage-permissions)`, () => {
  const result = decide(rules([], ["Bash(git push *)"], ["Bash(git push origin main)"]), bash("git push origin main"));
  assert.equal(result.decision, "ask");
  assert.equal(result.rule, "Bash(git push *)");
});

test(`nothing matches gives default, and specificity does not change the order (${PERMISSIONS}#manage-permissions)`, () => {
  assert.equal(decide(rules(), bash("npm test")).decision, "default");
  assert.equal(decide(rules([], [], ["Bash(npm test)"]), bash("npm test")).decision, "allow");
});

test(`Read(./.env) matches only the .env in the project root (${PERMISSIONS}#use-specifiers-for-fine-grained-control)`, () => {
  const deny = rules(["Read(./.env)"]);
  assert.equal(decide(deny, read(".env")).decision, "deny");
  assert.equal(decide(deny, read("a/.env")).decision, "default");
});

test(`Read(.env) equals Read(**/.env) at depths 0, 1 and 3 (${PERMISSIONS}#read-and-edit)`, () => {
  for (const pattern of ["Read(.env)", "Read(**/.env)"]) {
    for (const path of [".env", "a/.env", "a/b/c/.env"]) {
      assert.equal(decide(rules([pattern]), read(path)).decision, "deny", `${pattern} / ${path}`);
    }
  }
});

test(`Read(//**/.env) is an evident match anywhere (${PERMISSIONS}#read-and-edit)`, () => {
  assert.equal(decide(rules(["Read(//**/.env)"]), read("x/y/.env")).decision, "deny");
});

test(`a ~/ or // rule is undeterminable, except //** and //**/<tail> (${PERMISSIONS}#read-and-edit)`, () => {
  const home = decide(rules(["Read(~/.zshrc)"]), read(".env"));
  assert.equal(home.decision, "undeterminable");
  assert.equal(home.reason, "home-path-rule");
  const absolute = decide(rules(["Read(//c/work/**)"]), read("src/app.ts"));
  assert.equal(absolute.decision, "undeterminable");
  assert.equal(absolute.reason, "absolute-path-rule");
  assert.equal(decide(rules(["Read(//**)"]), read("src/app.ts")).decision, "deny");
});

test(`src/** as an allow rule is anchored at the root (${PERMISSIONS}#read-and-edit)`, () => {
  assert.equal(decide(rules([], [], ["Edit(src/**)"]), edit("src/app.ts")).decision, "allow");
  assert.equal(decide(rules([], [], ["Edit(src/**)"]), edit("vendor/pkg/src/lib.js")).decision, "default");
});

test(`src/** as a deny rule matches at any depth (${PERMISSIONS}#read-and-edit)`, () => {
  assert.equal(decide(rules(["Edit(src/**)"]), edit("src/app.ts")).decision, "deny");
  assert.equal(decide(rules(["Edit(src/**)"]), edit("vendor/pkg/src/lib.js")).decision, "deny");
});

test(`/src/** is anchored in every rule type (${PERMISSIONS}#read-and-edit)`, () => {
  assert.equal(decide(rules(["Edit(/src/**)"]), edit("src/app.ts")).decision, "deny");
  assert.equal(decide(rules(["Edit(/src/**)"]), edit("vendor/pkg/src/lib.js")).decision, "default");
});

test(`**/src/** matches at any depth in every rule type (${PERMISSIONS}#read-and-edit)`, () => {
  assert.equal(decide(rules([], [], ["Edit(**/src/**)"]), edit("vendor/pkg/src/lib.js")).decision, "allow");
  assert.equal(decide(rules(["Edit(**/src/**)"]), edit("src/app.ts")).decision, "deny");
});

test(`Edit(/docs/**) is the project docs folder only (${PERMISSIONS}#read-and-edit)`, () => {
  const allow = rules([], [], ["Edit(/docs/**)"]);
  assert.equal(decide(allow, edit("docs/guide.md")).decision, "allow");
  assert.equal(decide(allow, edit(".claude/docs/guide.md")).decision, "default");
});

test(`a Read deny rule also blocks Edit on the same path (${PERMISSIONS}#read-and-edit)`, () => {
  const result = decide(rules(["Read(.env)"], [], ["Edit(.env)"]), edit(".env"));
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "Read(.env)");
});

test(`a Read ask rule makes an Edit call undeterminable only where it covers the path (${PERMISSIONS}#read-and-edit)`, () => {
  assert.equal(decide(rules([], ["Read(secrets/**)"], ["Edit(src/app.ts)"]), edit("src/app.ts")).decision, "allow");
  const covering = decide(rules([], ["Read(src/**)"], ["Edit(src/app.ts)"]), edit("src/app.ts"));
  assert.equal(covering.decision, "undeterminable");
  assert.equal(covering.reason, "read-ask-for-edit");
});

test(`a ! negation is not simulated (${PERMISSIONS}#read-and-edit)`, () => {
  const deny = rules(["Read(*.env)", "Read(!sample.env)"]);
  assert.equal(decide(deny, read("sample.env")).decision, "undeterminable");
  assert.equal(decide(deny, read("other.env")).decision, "deny");
});

test(`WebFetch domain examples (${PERMISSIONS}#webfetch)`, () => {
  assert.equal(decide(rules(["WebFetch(domain:example.com)"]), fetchDomain("example.com")).decision, "deny");
  assert.equal(decide(rules(["WebFetch(domain:example.com)"]), fetchDomain("api.example.com")).decision, "default");
  assert.equal(decide(rules(["WebFetch(domain:*.example.com)"]), fetchDomain("api.example.com")).decision, "deny");
  assert.equal(decide(rules(["WebFetch(domain:*.example.com)"]), fetchDomain("a.b.example.com")).decision, "deny");
  assert.equal(decide(rules(["WebFetch(domain:*.example.com)"]), fetchDomain("example.com")).decision, "default");
  assert.equal(decide(rules(["WebFetch(domain:*)"]), fetchDomain("anything.org")).decision, "deny");
  assert.equal(decide(rules(["WebFetch(domain:example.*)"]), fetchDomain("example.org")).decision, "deny");
  assert.equal(decide(rules(["WebFetch(domain:example.*)"]), fetchDomain("example.evil.com")).decision, "default");
});

test(`a leading *. matches any depth even when another * follows, and any other * stays in one label (${PERMISSIONS}#webfetch)`, () => {
  const deny = rules(["WebFetch(domain:*.example.*)"]);
  assert.equal(decide(deny, fetchDomain("a.b.example.org")).decision, "deny");
  assert.equal(decide(deny, fetchDomain("api.example.co")).decision, "deny");
  assert.equal(decide(deny, fetchDomain("example.org")).decision, "default");
  const inner = rules(["WebFetch(domain:example.*.org)"]);
  assert.equal(decide(inner, fetchDomain("example.evil.org")).decision, "deny");
  assert.equal(decide(inner, fetchDomain("example.a.b.org")).decision, "default");
});

test(`WebFetch domains are case-insensitive and ignore a trailing dot (${PERMISSIONS}#webfetch)`, () => {
  assert.equal(decide(rules(["WebFetch(domain:Example.COM.)"]), fetchDomain("example.com")).decision, "deny");
});

test(`a bare WebFetch deny matches every fetch (${PERMISSIONS}#allow-or-deny-every-fetch)`, () => {
  assert.equal(decide(rules(["WebFetch"]), fetchDomain("example.com")).decision, "deny");
});

test(`MCP examples (${PERMISSIONS}#mcp)`, () => {
  assert.equal(decide(rules([], [], ["mcp__puppeteer"]), { tool: "mcp__puppeteer__navigate" }).decision, "allow");
  assert.equal(decide(rules([], [], ["mcp__puppeteer__*"]), { tool: "mcp__puppeteer__navigate" }).decision, "allow");
  const exact = rules([], [], ["mcp__puppeteer__puppeteer_navigate"]);
  assert.equal(decide(exact, { tool: "mcp__puppeteer__puppeteer_navigate" }).decision, "allow");
  assert.equal(decide(exact, { tool: "mcp__puppeteer__puppeteer_click" }).decision, "default");
});

test(`an mcp__* deny blocks every MCP tool (${PERMISSIONS}#tool-name-wildcards)`, () => {
  assert.equal(decide(rules(["mcp__*"]), { tool: "mcp__github__get_repo" }).decision, "deny");
  assert.equal(decide(rules(["mcp__*"]), bash("ls")).decision, "default");
});

test(`an unanchored allow glob approves nothing (${PERMISSIONS}#tool-name-wildcards)`, () => {
  for (const glob of ["*", "B*", "mcp__*"]) {
    assert.equal(decide(rules([], [], [glob]), bash("ls")).decision, "default", glob);
    assert.equal(decide(rules([], [], [glob]), { tool: "mcp__github__get_repo" }).decision, "default", glob);
  }
});

test(`a literal server prefix makes an allow glob count (${PERMISSIONS}#tool-name-wildcards)`, () => {
  assert.equal(decide(rules([], [], ["mcp__github__get_*"]), { tool: "mcp__github__get_repo" }).decision, "allow");
  assert.equal(decide(rules([], [], ["mcp__github__get_*"]), { tool: "mcp__github__put_repo" }).decision, "default");
});

test(`an mcp__ rule with parentheses is skipped and never matches (${PERMISSIONS}#match-by-input-parameter)`, () => {
  const parsed = parseRule("mcp__github__get_repo(x)");
  assert.equal(parsed.ok, true);
  assert.equal(parsed.skipped, true);
  assert.equal(decide(rules(["mcp__github__get_repo(x)"]), { tool: "mcp__github__get_repo" }).decision, "default");
});

test(`parameter rules are undeterminable for deny and never allow (${PERMISSIONS}#match-by-input-parameter)`, () => {
  assert.equal(decide(rules(["Bash(run_in_background:true)"]), bash("npm test")).decision, "undeterminable");
  assert.equal(decide(rules([], [], ["Bash(run_in_background:true)"]), bash("npm test")).decision, "default");
});

test(`command: parameter rules never match, since Claude Code ignores them (${PERMISSIONS}#match-by-input-parameter)`, () => {
  assert.equal(decide(rules(["Bash(command:rm *)"]), bash("rm -rf x")).decision, "default");
  assert.equal(decide(rules([], ["PowerShell(command:Remove-Item *)"]), { tool: "PowerShell", command: "Remove-Item x" }).decision, "default");
  assert.equal(decide(rules([], [], ["Bash(command:npm test)"]), bash("npm test")).decision, "default");
  assert.equal(parseRule("Bash(command:rm *)").kind, "ignored-parameter");
});

test(`compound command without parts: specifier rules are undeterminable, bare rules still match (${PERMISSIONS}#compound-commands)`, () => {
  const result = decide(rules([], [], ["Bash(npm test)"]), bash("npm test && rm -rf x"));
  assert.equal(result.decision, "undeterminable");
  assert.equal(result.reason, "compound-command");
  assert.equal(decide(rules([], [], ["Bash"]), bash("npm test && rm -rf x")).decision, "allow");
  assert.equal(decide(rules(["Bash(rm *)"]), bash("npm test; rm -rf x")).decision, "undeterminable");
});

test(`compound command with parts: deny when any part matches, allow when every part matches (${PERMISSIONS}#compound-commands)`, () => {
  const parts = ["ls", "rm -rf x"];
  const command = "ls && rm -rf x";
  assert.equal(decide(rules(["Bash(rm *)"]), { tool: "Bash", command, parts }).decision, "deny");
  assert.equal(decide(rules([], [], ["Bash(ls *)", "Bash(rm *)"]), { tool: "Bash", command, parts }).decision, "allow");
  assert.equal(decide(rules([], [], ["Bash(ls *)"]), { tool: "Bash", command, parts }).decision, "default");
});

test(`a wrapper prefix makes specifier rules undeterminable (${PERMISSIONS}#process-wrappers)`, () => {
  const result = decide(rules([], [], ["Bash(npm test *)"]), bash("timeout 30 npm test"));
  assert.equal(result.decision, "undeterminable");
  assert.equal(result.reason, "wrapper-or-env-prefix");
  assert.equal(decide(rules(["Bash(rm *)"]), bash("FOO=bar rm -rf tmp/")).decision, "undeterminable");
});

test("a PowerShell alias makes the rule undeterminable, in either direction", () => {
  const rule = rules([], [], ["PowerShell(Get-ChildItem *)"]);
  assert.equal(decide(rule, { tool: "PowerShell", command: "ls -la" }).decision, "undeterminable");
  assert.equal(decide(rule, { tool: "PowerShell", command: "Get-ChildItem -Recurse" }).decision, "allow");
  assert.equal(decide(rules([], [], ["PowerShell(ls *)"]), { tool: "PowerShell", command: "ls -la" }).decision, "undeterminable");
});

test("a [ pattern makes the rule undeterminable", () => {
  assert.equal(decide(rules([], [], ["Read(src/[ab].ts)"]), read("src/a.ts")).decision, "undeterminable");
});

test(`acceptEdits passes rm -rf build inside the project (${MODES}#auto-approve-file-edits-with-acceptedits-mode)`, () => {
  const outcome = evaluate(rules(), bash("rm -rf build"), { mode: "acceptEdits", insideProject: true, criticalPath: false });
  assert.equal(outcome.outcome, "passes");
  assert.deepEqual(outcome.decidedBy, { kind: "mode", mode: "acceptEdits" });
});

test(`acceptEdits asks for a file command outside the project and for other commands (${MODES}#auto-approve-file-edits-with-acceptedits-mode)`, () => {
  const options = { mode: "acceptEdits", insideProject: false, criticalPath: false };
  assert.equal(evaluate(rules(), bash("mv a /tmp/a"), options).outcome, "asks");
  assert.equal(evaluate(rules(), bash("npm install"), { mode: "acceptEdits", insideProject: true }).outcome, "asks");
});

test(`acceptEdits needs insideProject to be known (${MODES}#auto-approve-file-edits-with-acceptedits-mode)`, () => {
  assert.equal(evaluate(rules(), bash("mkdir out"), { mode: "acceptEdits" }).outcome, "undeterminable");
});

test(`dontAsk blocks what would prompt (${MODES}#allow-only-pre-approved-tools-with-dontask-mode)`, () => {
  assert.equal(evaluate(rules(), bash("npm test"), { mode: "dontAsk" }).outcome, "blocked");
  assert.equal(evaluate(rules([], ["Bash(npm test)"]), bash("npm test"), { mode: "dontAsk" }).outcome, "blocked");
  assert.equal(evaluate(rules([], [], ["Bash(npm test)"]), bash("npm test"), { mode: "dontAsk" }).outcome, "passes");
});

test(`bypassPermissions and auto from the project are ignored (${MODES}#common-setups)`, () => {
  for (const mode of ["bypassPermissions", "auto"]) {
    const outcome = evaluate(rules(), bash("npm test"), { mode });
    assert.equal(outcome.outcome, "asks", mode);
    assert.deepEqual(outcome.decidedBy, { kind: "mode", mode: "default", ignoredMode: mode });
  }
});

test(`manual is the alias of default (${MODES}#available-modes)`, () => {
  assert.equal(evaluate(rules(), bash("npm test"), { mode: "manual" }).outcome, "asks");
  assert.equal(evaluate(rules(), bash("npm test"), { mode: null }).outcome, "asks");
});

test(`a critical-path rm asks even when an allow rule matches (${MODES}#critical-paths)`, () => {
  const outcome = evaluate(rules([], [], ["Bash(rm *)"]), bash("rm -rf /"), { mode: "default", criticalPath: true });
  assert.equal(outcome.outcome, "asks");
  assert.equal(outcome.reason, "critical-path-removal");
  const blocked = evaluate(rules([], [], ["Bash(rm *)"]), bash("rm -rf /"), { mode: "dontAsk", criticalPath: true });
  assert.equal(blocked.outcome, "blocked");
  assert.equal(evaluate(rules(), bash("rm -rf build"), { mode: "acceptEdits" }).outcome, "undeterminable");
});

test(`a removal with no rule asks in default mode and is blocked in dontAsk, without criticalPath (${MODES}#critical-paths)`, () => {
  assert.equal(evaluate(rules(), bash("rm -rf build"), { mode: null }).outcome, "asks");
  assert.equal(evaluate(rules(), bash("rm -rf build"), { mode: "dontAsk" }).outcome, "blocked");
});

test(`a removal that would pass needs criticalPath: unknown is undeterminable, true asks, false passes (${MODES}#critical-paths)`, () => {
  const allow = rules([], [], ["Bash(rm *)"]);
  assert.equal(evaluate(allow, bash("rm -rf build")).outcome, "undeterminable");
  assert.equal(evaluate(allow, bash("rm -rf build"), { criticalPath: true }).outcome, "asks");
  assert.equal(evaluate(allow, bash("rm -rf build"), { criticalPath: false }).outcome, "passes");
  const accept = { mode: "acceptEdits", insideProject: true };
  assert.equal(evaluate(rules(), bash("rm -rf build"), accept).outcome, "undeterminable");
  assert.equal(evaluate(rules(), bash("rm -rf build"), { ...accept, criticalPath: true }).outcome, "asks");
  assert.equal(evaluate(rules(), bash("rm -rf build"), { ...accept, criticalPath: false }).outcome, "passes");
});

test(`a deny rule blocks, an allow rule passes, and a read-only command is undeterminable (${PERMISSIONS}#read-only-commands)`, () => {
  assert.equal(evaluate(rules(["Bash(aws *)"]), bash("aws s3 ls")).outcome, "blocked");
  assert.equal(evaluate(rules([], [], ["Bash(npm test)"]), bash("npm test")).outcome, "passes");
  assert.equal(evaluate(rules(), bash("ls -la")).outcome, "undeterminable");
});

test("evaluate: undeterminable for a plan mode and an unknown mode, and for a parameter rule", () => {
  assert.equal(evaluate(rules(), bash("npm test"), { mode: "plan" }).outcome, "undeterminable");
  assert.equal(evaluate(rules(), bash("npm test"), { mode: "someMode" }).outcome, "undeterminable");
  assert.equal(evaluate(rules(["Bash(run_in_background:true)"]), bash("npm test")).outcome, "undeterminable");
});

test("malformed rules are reported, and a malformed deny is undeterminable", () => {
  assert.deepEqual(parseRule("Bash(ls"), { ok: false, reason: "missing-closing-parenthesis" });
  assert.equal(decide(rules(["Bash(ls"]), bash("npm test")).decision, "undeterminable");
});

test("parseRule classifies the rule kinds, and keeps parentheses inside the specifier", () => {
  assert.equal(parseRule("Bash(ls *)").kind, "bash");
  assert.equal(parseRule("PowerShell(Get-ChildItem *)").kind, "powershell");
  assert.equal(parseRule("Read(./.env)").kind, "path");
  assert.equal(parseRule("Edit(./Finance (2024)/**)").specifier, "./Finance (2024)/**");
  assert.equal(parseRule("WebFetch(domain:example.com)").kind, "webfetch");
  assert.equal(parseRule("mcp__github__get_repo").kind, "mcp");
  assert.equal(parseRule("mcp__*").kind, "tool-glob");
  assert.equal(parseRule("Write(docs/**)").kind, "other");
});

test("decide is deterministic and does not change its input", () => {
  const input = rules(["Read(.env)"], ["Bash(git push *)"], ["Bash(npm test)"]);
  const snapshot = JSON.stringify(input);
  assert.deepEqual(decide(input, bash("npm test")), decide(input, bash("npm test")));
  assert.equal(JSON.stringify(input), snapshot);
});
