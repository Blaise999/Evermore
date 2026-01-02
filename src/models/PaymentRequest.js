const mongoose = require("mongoose");

const AppliedInvoiceSchema = new mongoose.Schema(
  {
    invoiceId: { type: mongoose.Schema.Types.ObjectId, ref: "Invoice", required: true },
    invoiceNo: { type: String, required: false },
    amount: { type: Number, required: true, min: 0 },
  },
  { _id: false }
);

const PaymentRequestSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    invoiceId: { type: mongoose.Schema.Types.ObjectId, ref: "Invoice", default: null, index: true },

    reference: { type: String, required: true, unique: true, index: true },
    currency: { type: String, default: "EUR" },
    amount: { type: Number, required: true },

    // ✅ What kind of payment this is.
    // - invoice_payment: pay a single invoice (invoiceId is set)
    // - careflex_repayment: pay any amount to reduce CareFlex owed; applied oldest-first
    kind: {
      type: String,
      enum: ["invoice_payment", "careflex_repayment", "topup"],
      default: "invoice_payment",
      index: true,
    },

    // For careflex_repayment approvals, store how it was allocated across invoices.
    applied: { type: [AppliedInvoiceSchema], default: [] },

    // Extra metadata (optional)
    meta: { type: mongoose.Schema.Types.Mixed, default: {} },

    // Sponsor-demo: payment "pends" until admin approves/declines
    status: { type: String, enum: ["pending", "approved", "declined"], default: "pending", index: true },

    method: { type: String, enum: ["card", "bank", "cash", "other"], default: "card" },

    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    reviewedAt: { type: Date, default: null },
    adminNote: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PaymentRequest", PaymentRequestSchema);
