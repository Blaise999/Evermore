const mongoose = require("mongoose");

const LoginEventSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    at: { type: Date, default: () => new Date(), index: true },
    ip: { type: String, default: null },
    userAgent: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("LoginEvent", LoginEventSchema);
