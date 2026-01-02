const mongoose = require("mongoose");

// Extended patient profile fields used by the dashboard & admin editor.
// We keep auth credentials on User; everything "profile" lives here.

const PatientProfileSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", unique: true, required: true, index: true },

    patientId: { type: String, required: true, index: true }, // usually the User.hospitalId
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    phone: { type: String, default: null, trim: true },

    gender: { type: String, default: null },
    dob: { type: Date, default: null },
    address: { type: String, default: null },
    bloodType: { type: String, default: null },
    allergies: { type: [String], default: [] },
    notes: { type: String, default: null },
  },
  { timestamps: true }
);

module.exports = mongoose.model("PatientProfile", PatientProfileSchema);
