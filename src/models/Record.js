const mongoose = require("mongoose");

const RecordSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    type: {
      type: String,
      enum: ["consultation", "lab", "radiology", "prescription", "diagnosis", "discharge", "other"],
      default: "consultation",
      index: true
    },

    title: { type: String, required: true },
    summary: { type: String, default: null },

    // flexible "hospital report" payload
    data: { type: mongoose.Schema.Types.Mixed, default: {} },

    recordedAt: { type: Date, default: () => new Date(), index: true },
    clinician: { type: String, default: null },

    status: { type: String, enum: ["final", "draft"], default: "final", index: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Record", RecordSchema);
