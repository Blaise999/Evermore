const mongoose = require("mongoose");

const AdminMessageSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    // recipient email at send-time (historical)
    to: { type: String, required: true, trim: true, lowercase: true },

    subject: { type: String, required: true, trim: true },
    message: { type: String, required: true },

    templateId: { type: String, default: "general", trim: true },

    status: { type: String, enum: ["queued", "sent", "failed"], default: "sent", index: true },

    provider: { type: String, default: "resend" },
    providerId: { type: String, default: null },

    // optional CTA (stored for audit/history)
    ctaLabel: { type: String, default: "" },
    ctaUrl: { type: String, default: "" },

    // optional tags (stored for audit/history)
    tags: [
      {
        name: { type: String, trim: true },
        value: { type: String, trim: true },
      },
    ],

    error: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("AdminMessage", AdminMessageSchema);
