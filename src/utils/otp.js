// utils/otp.js
const crypto = require("crypto");

const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 10);
const OTP_SECRET = process.env.OTP_SECRET; // ✅ REQUIRED in prod (long random string)
const OTP_DIGITS = 6;

function generateOtp() {
  const max = 10 ** OTP_DIGITS;
  const n = crypto.randomInt(0, max); // ✅ secure
  return String(n).padStart(OTP_DIGITS, "0");
}

function otpExpiresAt() {
  return new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);
}

function isOtpExpired(expiresAt) {
  if (!expiresAt) return true;
  return new Date(expiresAt).getTime() <= Date.now();
}

// ✅ makes OTP unique to user + purpose (no "one OTP for all")
function hashOtp({ otp, userId, purpose }) {
  if (!OTP_SECRET) throw new Error("OTP_SECRET is not set");
  const msg = `${String(userId)}|${String(purpose)}|${String(otp)}`;
  return crypto.createHmac("sha256", OTP_SECRET).update(msg).digest("hex");
}

function safeEqualHex(a, b) {
  const aa = Buffer.from(String(a || ""), "hex");
  const bb = Buffer.from(String(b || ""), "hex");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

module.exports = { generateOtp, hashOtp, otpExpiresAt, isOtpExpired, safeEqualHex };
