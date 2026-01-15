const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { makeHospitalId } = require("../utils/refs");

const UserSchema = new mongoose.Schema(
  {
    role: { type: String, enum: ["patient", "admin"], default: "patient", index: true },
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
    phone: { type: String, default: null, trim: true },

    hospitalId: { type: String, unique: true, index: true },

    passwordHash: { type: String, required: true },

    // OTP (password reset / login / step-up)
    otpHash: { type: String, default: null },
    otpPurpose: { type: String, enum: ["reset_password", "login", "portal_stepup", null], default: null },
    otpExpiresAt: { type: Date, default: null },
    otpAttempts: { type: Number, default: 0 }, // ✅ minimal brute-force protection

    // ✅ Email verification
    emailVerifiedAt: { type: Date, default: null, index: true },
    emailVerifyTokenHash: { type: String, default: null, index: true },
    emailVerifyTokenExpiresAt: { type: Date, default: null },
    emailVerifySentAt: { type: Date, default: null },

    // Admin visibility: last time the user successfully logged in
    lastLoginAt: { type: Date, default: null, index: true },

    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

UserSchema.pre("validate", function (next) {
  if (!this.hospitalId) this.hospitalId = makeHospitalId();
  next();
});

UserSchema.methods.setPassword = async function (plain) {
  const salt = await bcrypt.genSalt(10);
  this.passwordHash = await bcrypt.hash(String(plain), salt);
};

UserSchema.methods.verifyPassword = async function (plain) {
  return bcrypt.compare(String(plain), this.passwordHash);
};

UserSchema.methods.safe = function () {
  return {
    id: String(this._id),
    role: this.role,
    name: this.name,
    email: this.email,
    phone: this.phone,
    hospitalId: this.hospitalId,
    isActive: this.isActive,
    emailVerifiedAt: this.emailVerifiedAt || null,
    lastLoginAt: this.lastLoginAt,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt,
  };
};

module.exports = mongoose.model("User", UserSchema);
