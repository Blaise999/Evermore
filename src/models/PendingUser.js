// models/PendingUser.js
// Stores registration data temporarily until email is verified
// Auto-expires after 24 hours so users can re-register if they abandon

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const PendingUserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
    phone: { type: String, default: null, trim: true },
    passwordHash: { type: String, required: true },

    // Email verification token
    emailVerifyToken: { type: String, required: true, index: true },
    emailVerifyTokenExpiresAt: { type: Date, required: true },

    // When the verification email was last sent (for rate limiting)
    emailVerifySentAt: { type: Date, default: null },

    // Auto-expire pending registrations after 24 hours
    expiresAt: { 
      type: Date, 
      required: true, 
      default: () => new Date(Date.now() + 24 * 60 * 60 * 1000),
      index: { expires: 0 } // TTL index - MongoDB auto-deletes when expiresAt is reached
    },
  },
  { timestamps: true }
);

// Hash password before saving
PendingUserSchema.methods.setPassword = async function (plain) {
  const salt = await bcrypt.genSalt(10);
  this.passwordHash = await bcrypt.hash(String(plain), salt);
};

// Generate a new verification token
PendingUserSchema.methods.generateVerifyToken = function () {
  const token = crypto.randomBytes(32).toString("hex");
  this.emailVerifyToken = crypto.createHash("sha256").update(token).digest("hex");
  this.emailVerifyTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  this.emailVerifySentAt = new Date();
  return token; // Return raw token to send in email
};

// Check if token is valid
PendingUserSchema.methods.isTokenValid = function (rawToken) {
  if (!this.emailVerifyToken || !this.emailVerifyTokenExpiresAt) return false;
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const hashMatch = tokenHash === this.emailVerifyToken;
  const notExpired = new Date(this.emailVerifyTokenExpiresAt).getTime() > Date.now();
  return hashMatch && notExpired;
};

// Check if can resend (60s cooldown)
PendingUserSchema.methods.canResendEmail = function () {
  if (!this.emailVerifySentAt) return true;
  const lastSent = new Date(this.emailVerifySentAt).getTime();
  return Date.now() - lastSent >= 60 * 1000;
};

module.exports = mongoose.model("PendingUser", PendingUserSchema);
