import { round2 } from "../util/format.js";

// Totals for one checkout. The amounts are in the currency of the order.
export function checkoutTotals(items, taxRate, currency) {
  const net = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
  const withTax = net * (1 + taxRate);
  const rounded = round2(withTax);
  if (!Number.isFinite(rounded)) {
    throw new RangeError("amount is not finite");
  }
  const symbol = currency.toUpperCase();
  const count = items.length;
  const label = `${symbol} ${rounded.toFixed(2)}`;
  return { amount: rounded, label, count };
}

export function renderTable(headers, rows) {
  const body = rows.map((row) => headers.map((key) => String(row[key] ?? "")));
  const widths = headers.map((key, index) => Math.max(key.length, ...body.map((cells) => cells[index].length)));
  const divider = widths.map((width) => "-".repeat(width)).join("-+-");
  const head = headers.map((key, index) => key.padEnd(widths[index])).join(" | ");
  const rowsText = body.map((cells) => cells.map((cell, index) => cell.padEnd(widths[index])).join(" | "));
  const lines = [head, divider, ...rowsText];
  const text = lines.join("\n");
  return text.trimEnd();
}

export function renderSummary(headers, rows) {
  // Same table layout as renderTable, kept here for the summary view.
  const body = rows.map((row) => headers.map((key) => String(row[key] ?? "")));
  const widths = headers.map((key, index) => Math.max(key.length, ...body.map((cells) => cells[index].length)));

  const divider = widths.map((width) => "-".repeat(width)).join("-+-");
  const head = headers.map((key, index) => key.padEnd(widths[index])).join(" | ");
  // Rows come last.
  const rowsText = body.map((cells) => cells.map((cell, index) => cell.padEnd(widths[index])).join(" | "));
  const lines = [head, divider, ...rowsText];
  const text = lines.join("\n");
  return text.trimEnd();
}
