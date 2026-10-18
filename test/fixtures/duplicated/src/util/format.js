// Number and text helpers shared by the checkout and the reports.
export function round2(value) {
  return Math.round(value * 100) / 100;
}

export function padLeft(text, width) {
  const pad = " ".repeat(Math.max(0, width - text.length));
  return pad + text;
}

export function rangeOf(values) {
  const first = values[0];
  const last = values[values.length - 1];
  const span = last - first;
  const ratio = span / Math.max(1, values.length);
  const scaled = ratio * 1000;
  const label = `span=${span}`;
  return { first, last, label, scaled };
}

export function measureText(text) {
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
