const mongoose = require("mongoose");

const PatientAccountSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", unique: true, required: true, index: true },

    currency: { type: String, default: "EUR" },

    // The "money stuff" admin can edit
    balance: { type: Number, default: 0 },          // available balance
    // CareFlex limit (Option A)
    creditLimit: { type: Number, default: 5000 },
    amountOwed: { type: Number, default: 0 },

    // Optional: allow "high credit score" access / sponsor demo logic
    creditScore: { type: Number, default: 600 },
    owedDueAt: { type: Date, default: null },       // when amount owed must be cleared

    notes: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PatientAccount", PatientAccountSchema);
