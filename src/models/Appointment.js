const mongoose = require("mongoose");

const AppointmentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    department: { type: String, required: true },
    doctorName: { type: String, default: null },

    scheduledAt: { type: Date, required: true, index: true },
    status: { type: String, enum: ["scheduled", "completed", "cancelled"], default: "scheduled", index: true },

    reason: { type: String, default: null },
    notes: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Appointment", AppointmentSchema);
