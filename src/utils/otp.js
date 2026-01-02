const crypto = require("crypto");

function generateOtp() {
  // 6-digit numeric
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

function otpExpiresAt() {
  const ttlMin = Number(process.env.OTP_TTL_MINUTES || 10);
  return new Date(Date.now() + ttlMin * 60 * 1000);
}

function isOtpExpired(expiresAt) {
  if (!expiresAt) return true;
  return new Date(expiresAt).getTime() < Date.now();
}

module.exports = { generateOtp, hashOtp, otpExpiresAt, isOtpExpired };
