// models/invoice.model.js
const mongoose = require("mongoose");

const InvoiceItemSchema = new mongoose.Schema(
  {
    code: { type: String, trim: true },
    description: { type: String, required: true, trim: true },
    qty: { type: Number, default: 1, min: 1 },
    unitPrice: { type: Number, required: true, min: 0 },
    amount: { type: Number, required: true, min: 0 },
  },
  { _id: false }
);

const InvoiceSchema = new mongoose.Schema(
  {
    invoiceNo: { type: String, required: true, unique: true, index: true },

    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    hospitalId: { type: String, required: true, index: true },

    appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: "Appointment", required: true, index: true },

    // Billing is EUR-only for CareFlex (Option A)
    currency: { type: String, default: "EUR" },

    status: {
      type: String,
      enum: ["issued", "paid", "void"],
      default: "issued",
      index: true,
    },

    issuedAt: { type: Date, default: Date.now },
    dueDate: { type: Date, required: true, index: true },
    paidAt: { type: Date, default: null },

    // ✅ Option A support: track how much of this invoice has been
    // covered by CareFlex repayments (oldest-first behind the scenes).
    // Invoice status remains "issued" until fully covered.
    coveredAmount: { type: Number, default: 0, min: 0 },

    items: { type: [InvoiceItemSchema], default: [] },

    subtotal: { type: Number, required: true, min: 0 },
    tax: { type: Number, required: true, min: 0, default: 0 },
    total: { type: Number, required: true, min: 0 },

    notes: { type: String, default: "" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Invoice", InvoiceSchema);
