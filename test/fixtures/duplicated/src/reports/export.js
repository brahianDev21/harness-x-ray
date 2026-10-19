import { round2 } from "../util/format.js";

export function exportInvoice(items, taxRate, currency) {
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
