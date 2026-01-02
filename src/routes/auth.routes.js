const express = require("express");
const rateLimit = require("express-rate-limit");

const User = require("../models/User");
const PatientAccount = require("../models/PatientAccount");
const PatientProfile = require("../models/PatientProfile");
const LoginEvent = require("../models/LoginEvent");

const { asyncHandler, AppError } = require("../middleware/error");
const auth = require("../middleware/auth");
const { signAccessToken } = require("../utils/tokens");
const { generateOtp, hashOtp, otpExpiresAt, isOtpExpired } = require("../utils/otp");
const { auditLog } = require("../utils/audit");

// ✅ email verify helpers
const {
  sendVerificationEmail,
  hashEmailVerifyToken,
  isEmailVerifyTokenValidForUser,
} = require("../utils/emailverification");

const router = express.Router();

// Tight limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

function issueToken(user) {
  return signAccessToken({
    sub: String(user._id),
    role: user.role,
    email: user.email,
    hospitalId: user.hospitalId,
  });
}

// Optional: seed admin on boot (safe for dev/demo)
async function seedAdminIfNeeded() {
  const enabled = String(process.env.SEED_ADMIN_ON_BOOT || "false") === "true";
  if (!enabled) return;

  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  const name = process.env.ADMIN_NAME || "Admin";

  if (!email || !password) return;

  const exists = await User.findOne({ email }).lean();
  if (exists) return;

  const admin = new User({ role: "admin", name, email, passwordHash: "x" });
  await admin.setPassword(password);
  admin.emailVerifiedAt = new Date(); // admins can be treated as verified
  await admin.save();

  console.log("✅ Seeded admin:", email);
}
seedAdminIfNeeded().catch(() => {});

router.post(
  "/signup",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { name, email, password, phone } = req.body || {};
    if (!name || !email || !password) throw new AppError("name, email, password are required", 400);

    const existing = await User.findOne({ email: String(email).toLowerCase() }).lean();
    if (existing) throw new AppError("Email already in use", 409, "DUPLICATE");

    const user = new User({
      role: "patient",
      name: String(name).trim(),
      email: String(email).toLowerCase().trim(),
      phone: phone ? String(phone).trim() : null,
      passwordHash: "x",
      emailVerifiedAt: null,
    });

    await user.setPassword(password);
    await user.save();

    await PatientAccount.create({ userId: user._id });
    await PatientProfile.create({
      userId: user._id,
      patientId: user.hospitalId,
      fullName: user.name,
      email: user.email,
      phone: user.phone,
      allergies: [],
    });

    await auditLog({
      actorId: user._id,
      actorRole: user.role,
      action: "AUTH_SIGNUP",
      targetModel: "User",
      targetId: String(user._id),
      after: user.safe(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // ✅ You said: send on login. So we DON'T auto-send here.
    // If you want to send on signup too, uncomment:
    // try { await sendVerificationEmail(user, { reason: "signup" }); } catch (e) {}

    const token = issueToken(user);

    res.json({
      ok: true,
      token,
      user: user.safe(),
    });
  })
);

router.post(
  "/login",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) throw new AppError("email and password are required", 400);

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user || !user.isActive) throw new AppError("Invalid credentials", 401, "UNAUTHORIZED");

    const ok = await user.verifyPassword(password);
    if (!ok) throw new AppError("Invalid credentials", 401, "UNAUTHORIZED");

    // ✅ If patient not verified: send email + block login
    if (user.role === "patient" && !user.emailVerifiedAt) {
      try {
        await sendVerificationEmail(user, { reason: "login" });
      } catch (e) {
        // if resend fails, still block login, but with clearer error
        throw new AppError("Email not verified and we could not send verification email. Try again.", 502, "EMAIL_SEND_FAILED");
      }

      throw new AppError(
        "Email not verified. We’ve sent you a verification link.",
        403,
        "EMAIL_NOT_VERIFIED"
      );
    }

    // Track successful logins for the admin panel.
    user.lastLoginAt = new Date();
    await user.save();
    await LoginEvent.create({
      userId: user._id,
      at: user.lastLoginAt,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    const token = issueToken(user);

    await auditLog({
      actorId: user._id,
      actorRole: user.role,
      action: "AUTH_LOGIN",
      targetModel: "User",
      targetId: String(user._id),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, token, user: user.safe() });
  })
);

// ✅ Verify email link
// GET /api/auth/verify-email?token=...
router.get(
  "/verify-email",
  asyncHandler(async (req, res) => {
    const token = String(req.query.token || "").trim();
    if (!token) throw new AppError("token is required", 400);

    const tokenHash = hashEmailVerifyToken(token);
    const user = await User.findOne({ emailVerifyTokenHash: tokenHash });
    if (!user) throw new AppError("Invalid or expired token", 400, "BAD_TOKEN");

    const ok = isEmailVerifyTokenValidForUser(user, token);
    if (!ok) throw new AppError("Invalid or expired token", 400, "BAD_TOKEN");

    user.emailVerifiedAt = new Date();
    user.emailVerifyTokenHash = null;
    user.emailVerifyTokenExpiresAt = null;
    await user.save();

    await auditLog({
      actorId: user._id,
      actorRole: user.role,
      action: "AUTH_EMAIL_VERIFIED",
      targetModel: "User",
      targetId: String(user._id),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // you can redirect to frontend success page
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    return res.redirect(`${appUrl}/verify-email/success`);
  })
);

// ✅ Optional: allow resending verification email (helpful for UI button)
// POST /api/auth/resend-verification  { email }
router.post(
  "/resend-verification",
  authLimiter,
  asyncHandler(async (req, res) => {
    const email = String(req.body?.email || "").toLowerCase().trim();
    if (!email) throw new AppError("email is required", 400);

    const user = await User.findOne({ email });
    // Always respond ok (don’t leak)
    if (!user) return res.json({ ok: true });

    if (user.emailVerifiedAt) return res.json({ ok: true });

    await sendVerificationEmail(user, { reason: "manual_resend" });
    res.json({ ok: true });
  })
);

router.get(
  "/me",
  auth,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.id);
    if (!user) throw new AppError("User not found", 404);

    const account = await PatientAccount.findOne({ userId: user._id }).lean();

    res.json({
      ok: true,
      user: user.safe(),
      account: account || null,
    });
  })
);

// Forgot password -> OTP
router.post(
  "/forgot-password",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body || {};
    if (!email) throw new AppError("email is required", 400);

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    // Always respond ok (don’t leak existence)
    if (!user) return res.json({ ok: true, message: "If the email exists, an OTP was sent." });

    const otp = generateOtp();
    user.otpHash = hashOtp(otp);
    user.otpPurpose = "reset_password";
    user.otpExpiresAt = otpExpiresAt();
    await user.save();

    await auditLog({
      actorId: user._id,
      actorRole: user.role,
      action: "AUTH_FORGOT_PASSWORD_OTP_ISSUED",
      targetModel: "User",
      targetId: String(user._id),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // Demo behavior: print OTP / optionally return it if OTP_DEBUG=true
    console.log(`🔐 OTP for ${user.email}:`, otp);

    const debug = String(process.env.OTP_DEBUG || "false") === "true";
    res.json({
      ok: true,
      message: "If the email exists, an OTP was sent.",
      ...(debug ? { debugOtp: otp } : {}),
    });
  })
);

// Reset password with OTP
router.post(
  "/reset-password",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, otp, newPassword } = req.body || {};
    if (!email || !otp || !newPassword) throw new AppError("email, otp, newPassword are required", 400);

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) throw new AppError("Invalid OTP", 400);

    if (user.otpPurpose !== "reset_password") throw new AppError("Invalid OTP", 400);
    if (isOtpExpired(user.otpExpiresAt)) throw new AppError("OTP expired", 400);

    const matches = user.otpHash === hashOtp(otp);
    if (!matches) throw new AppError("Invalid OTP", 400);

    const before = user.safe();

    await user.setPassword(newPassword);
    user.otpHash = null;
    user.otpPurpose = null;
    user.otpExpiresAt = null;
    await user.save();

    await auditLog({
      actorId: user._id,
      actorRole: user.role,
      action: "AUTH_PASSWORD_RESET",
      targetModel: "User",
      targetId: String(user._id),
      before,
      after: user.safe(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, message: "Password reset successful." });
  })
);

module.exports = router;
