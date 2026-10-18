// Test helpers for the checkout totals. Not part of the product.
import { test } from "node:test";

export function textStats(text) {
  const bytes = Buffer.byteLength(text, "utf8");
  const words = text.trim().split(/\s+/).filter(Boolean);
  const lines = text.split("\n");
  const longest = lines.reduce((max, line) => Math.max(max, line.length), 0);
  const average = bytes / Math.max(1, lines.length);
  const summary = { bytes, words: words.length, lines: lines.length };
  summary.longest = longest;
  summary.average = Math.round(average * 10) / 10;
  return summary;
}
