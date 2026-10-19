import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  codeSpan,
  escapePipes,
  formatNumber,
  inline,
  link,
  localeOf,
  table,
  utcDate,
} from "../scripts/lib/report-markdown.mjs";

describe("codeSpan", () => {
  test("uses one backtick when the text has none", () => {
    assert.equal(codeSpan("a|b"), "`a|b`");
  });

  test("fences with one backtick more than the longest run inside", () => {
    assert.equal(codeSpan("a``b"), "```a``b```");
    assert.equal(codeSpan("say `ok`"), "`` say `ok` ``");
  });

  test("pads a text that starts or ends with a backtick", () => {
    assert.equal(codeSpan("`x"), "`` `x ``");
    assert.equal(codeSpan("x`"), "`` x` ``");
  });

  test("rejects an empty text", () => {
    assert.throws(() => codeSpan(""), TypeError);
  });
});

describe("table cells", () => {
  test("escapes a pipe, also inside a code span", () => {
    assert.equal(escapePipes("a | b"), "a \\| b");
    assert.equal(table(["A"], [[codeSpan(escapePipes("x|y"))]]), "| A |\n| --- |\n| `x\\|y` |");
  });

  test("a line break in a cell becomes a space", () => {
    assert.equal(inline("first\r\nsecond\nthird"), "first second third");
  });

  test("a row with the wrong number of cells is an error", () => {
    assert.throws(() => table(["A", "B"], [["only one"]]), TypeError);
  });
});

describe("link", () => {
  test("escapes brackets in the label and encodes parentheses in the URL", () => {
    assert.equal(
      link("Piece [draft] (v2)", "https://example.com/a_(b)"),
      "[Piece \\[draft\\] (v2)](https://example.com/a_%28b%29)",
    );
  });

  test("writes a URL that is not http or https as code", () => {
    assert.equal(link("x", "javascript:alert(1)"), "`javascript:alert(1)`");
  });
});

describe("numbers and dates", () => {
  test("formats with the fixed locale of each language", () => {
    assert.equal(localeOf("en"), "en-US");
    assert.equal(localeOf("es"), "es-ES");
    assert.equal(formatNumber(12345.5, "en"), "12,345.5");
    assert.equal(formatNumber(12345.5, "es"), "12.345,5");
    assert.equal(formatNumber(0.125, "en"), "0.13");
  });

  test("rejects a language without a locale and a value that is not finite", () => {
    assert.throws(() => localeOf("fr"), Error);
    assert.throws(() => formatNumber(Number.NaN, "en"), TypeError);
  });

  test("the scan date is the UTC date, the same in both languages", () => {
    assert.equal(utcDate("2026-10-18T23:30:00.000Z"), "2026-10-18");
    assert.equal(utcDate("2026-10-18T23:30:00.000-05:00"), "2026-10-19");
    assert.throws(() => utcDate("yesterday"), TypeError);
  });
});
