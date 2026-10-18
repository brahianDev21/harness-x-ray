// Receipt printing for a checkout.
import { round2 } from "../util/format.js";

export function printReceipt(items, taxRate, currency, date) {
  const when = date.toISOString();
  // Same arithmetic as the checkout totals.
  const net = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
  const withTax = net * (1 + taxRate);
  const rounded = round2(withTax);
  if (!Number.isFinite(rounded)) {
    throw new RangeError("amount is not finite");
  }
  const { formatDate } = require("../util/dates.js");

  const symbol = currency.toUpperCase();
  /* the count is printed on its own line */
  const count = items.length;
  const label = `${symbol} ${rounded.toFixed(2)}`;
  return { amount: rounded, label, count };
}
