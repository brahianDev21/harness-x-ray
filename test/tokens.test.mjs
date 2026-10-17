import assert from "node:assert/strict";
import { test } from "node:test";
import { ESTIMATE_METHOD, estimateTokens, stripHtmlComments } from "../scripts/lib/tokens.mjs";

test("the method name is chars/4", () => {
  assert.equal(ESTIMATE_METHOD, "chars/4");
});

test("a block comment on its own line is removed, and its line goes with it", () => {
  assert.equal(stripHtmlComments("<!-- maintainer notes -->\n# Title\n"), "# Title\n");
  assert.equal(stripHtmlComments("Before\n<!-- note -->\nAfter"), "Before\nAfter");
});

test("a block comment that spans several lines is removed in full", () => {
  assert.equal(stripHtmlComments("Before\n<!--\nhidden\nlines\n-->\nAfter"), "Before\nAfter");
  assert.equal(stripHtmlComments("<!--\n  indented, still hidden\n-->\n"), "");
});

test("a comment indented up to three spaces is removed, and four spaces make it code, which is kept", () => {
  assert.equal(stripHtmlComments("   <!-- three spaces -->\ny"), "y");
  assert.equal(stripHtmlComments("    <!-- four spaces -->\ny"), "    <!-- four spaces -->\ny");
});

test("a comment in the middle of a line is kept, because only block-level comments are documented as removed", () => {
  const text = "Run `npm test` <!-- before push --> first";
  assert.equal(stripHtmlComments(text), text);
  assert.equal(stripHtmlComments("text <!-- a -->\nmore"), "text <!-- a -->\nmore");
});

test("text after the closing --> on the same line is kept", () => {
  assert.equal(stripHtmlComments("<!-- a --> kept"), " kept");
});

test("a comment inside a backtick fence is kept, and the fence keeps the comment as written", () => {
  const text = "```md\n<!-- kept -->\n```\n";
  assert.equal(stripHtmlComments(text), text);
});

test("a comment inside a tilde fence is kept, including a comment that spans lines", () => {
  const text = "~~~\n<!--\nkept\n-->\n~~~";
  assert.equal(stripHtmlComments(text), text);
});

test("a fence closes only with the same character and at least the same length", () => {
  // The three-backtick line does not close the four-backtick fence, so the second comment is kept too.
  // The fence ends at the four-backtick line, and a comment after it is removed.
  const text = "````\n<!-- kept -->\n```\n<!-- still kept -->\n````\n<!-- gone -->\nend";
  assert.equal(stripHtmlComments(text), "````\n<!-- kept -->\n```\n<!-- still kept -->\n````\nend");
});

test("a fence that is never closed keeps everything below it", () => {
  const text = "```\n<!-- kept -->\nmore";
  assert.equal(stripHtmlComments(text), text);
});

test("a line that starts with a backtick run and has a backtick in its info string is not a fence", () => {
  assert.equal(stripHtmlComments("``` a`b\n<!-- x -->\n```"), "``` a`b\n```");
});

test("a comment that is never closed is kept as written", () => {
  const text = "text\n<!-- never closed\nmore";
  assert.equal(stripHtmlComments(text), text);
});

test("non-string input gives an empty text", () => {
  assert.equal(stripHtmlComments(undefined), "");
  assert.equal(stripHtmlComments(null), "");
  assert.equal(stripHtmlComments(42), "");
});

test("CRLF and a leading BOM are normalized, and the output uses LF", () => {
  assert.equal(stripHtmlComments("﻿<!-- a -->\r\nb\r\n"), "b\n");
  assert.equal(stripHtmlComments("one\r\ntwo\rthree"), "one\ntwo\nthree");
});

test("an empty string has zero tokens and the chars/4 method", () => {
  assert.deepEqual(estimateTokens(""), { estTokens: 0, method: "chars/4" });
});

test("non-string input estimates as empty, without throwing", () => {
  assert.deepEqual(estimateTokens(undefined), { estTokens: 0, method: "chars/4" });
  assert.deepEqual(estimateTokens(7), { estTokens: 0, method: "chars/4" });
});

test("tokens are the characters divided by four, rounded up", () => {
  assert.equal(estimateTokens("a").estTokens, 1);
  assert.equal(estimateTokens("abcd").estTokens, 1);
  assert.equal(estimateTokens("abcde").estTokens, 2);
  assert.equal(estimateTokens("abcdefgh").estTokens, 2);
});

test("HTML block comments are excluded from the count", () => {
  // The 400-character comment is gone; "abcd" remains.
  const text = `<!-- ${"x".repeat(400)} -->\nabcd`;
  assert.deepEqual(estimateTokens(text), { estTokens: 1, method: "chars/4" });
});

test("a multi-line HTML comment is excluded from the count", () => {
  assert.deepEqual(estimateTokens("<!--\nlong\nlong\nlong\n-->\nabcd"), { estTokens: 1, method: "chars/4" });
});

test("comments inside a fenced code block are counted", () => {
  // "```" (3) + LF + "<!-- abcd -->" (13) + LF + "```" (3) = 21 characters, so 6 tokens.
  assert.deepEqual(estimateTokens("```\n<!-- abcd -->\n```"), { estTokens: 6, method: "chars/4" });
});

test("CRLF text and LF text give the same estimate", () => {
  const lf = estimateTokens("one\ntwo\n");
  assert.deepEqual(estimateTokens("one\r\ntwo\r\n"), lf);
  assert.equal(lf.estTokens, 2);
});

test("a leading BOM is not counted", () => {
  assert.deepEqual(estimateTokens("﻿abcde"), estimateTokens("abcde"));
});

test("characters are code points: an emoji counts once, not as two UTF-16 units", () => {
  // Five code points give 2 tokens. Counting UTF-16 units (10) would give 3.
  assert.deepEqual(estimateTokens("😀".repeat(5)), { estTokens: 2, method: "chars/4" });
  // Four accented letters are four code points, so one token.
  assert.deepEqual(estimateTokens("é".repeat(4)), { estTokens: 1, method: "chars/4" });
});
