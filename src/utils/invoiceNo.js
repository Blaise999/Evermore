// utils/invoiceNo.js
const Counter = require("../models/counter.model");

async function nextInvoiceNo(session) {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const key = `invoice:${y}${m}`;

  const doc = await Counter.findOneAndUpdate(
    { key },
    { $inc: { seq: 1 } },
    { new: true, upsert: true, session }
  );

  const n = String(doc.seq).padStart(6, "0");
  return `EVM-INV-${y}${m}-${n}`; // EVM-INV-202512-000001
}

module.exports = { nextInvoiceNo };
