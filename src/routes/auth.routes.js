const express = require("express");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const User = require("../models/User");
const PendingUser = require("../models/PendingUser");
const PatientAccount = require("../models/PatientAccount");
const PatientProfile = require("../models/PatientProfile");
const LoginEvent = require("../models/LoginEvent");

const { asyncHandler, AppError } = require("../middleware/error");
const auth = require("../middleware/auth");
const { signAccessToken } = require("../utils/tokens");
const { generateOtp, hashOtp, otpExpiresAt, isOtpExpired } = require("../utils/otp");
const { auditLog } = require("../utils/audit");
const { getResend } = require("../utils/resendClient");
const { renderBrandedEmail } = require("../utils/brand");

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

// Helper: send verification email to pending user
async function sendPendingVerificationEmail(pendingUser, rawToken) {
  const from = process.env.MAIL_FROM;
  if (!from) throw new Error("MAIL_FROM is not set");

  const replyTo = process.env.MAIL_REPLY_TO || undefined;
  const appUrl = process.env.APP_URL || "http://localhost:3000";

  const verifyUrl = `${appUrl}/api/auth/verify-email?token=${rawToken}`;

  const subject = "Verify your email address";
  const message =
    `Hi ${pendingUser.name ? String(pendingUser.name).trim() : "there"},\n\n` +
    `Please confirm your email address to complete your Evermore registration.\n\n` +
    `This link expires in 1 hour.\n\n` +
    `If you didn't request this, you can ignore this email.`;

  const { html, text } = renderBrandedEmail({
    subject,
    message,
    ctaLabel: "Verify email",
    ctaUrl: verifyUrl,
  });

  const resend = await getResend();

  const { data, error } = await resend.emails.send({
    from,
    to: [String(pendingUser.email).toLowerCase().trim()],
    subject,
    html,
    text,
    replyTo,
    tags: [
      { name: "type", value: "email_verification" },
      { name: "reason", value: "signup" },
    ],
  });

  if (error) throw new Error(error.message || "Failed to send email");
  return { id: data?.id || null };
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

// ============================================
// SIGNUP - Creates PendingUser, NOT User
// ============================================
router.post(
  "/signup",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { name, email, password, phone } = req.body || {};
    if (!name || !email || !password) throw new AppError("name, email, password are required", 400);

    const normalizedEmail = String(email).toLowerCase().trim();

    // Check if email already exists as a verified user
    const existingUser = await User.findOne({ email: normalizedEmail }).lean();
    if (existingUser) throw new AppError("Email already in use", 409, "DUPLICATE");

    // Check if there's already a pending registration for this email
    // If so, delete it (allow re-registration)
    await PendingUser.deleteOne({ email: normalizedEmail });

    // Create pending user
    const pendingUser = new PendingUser({
      name: String(name).trim(),
      email: normalizedEmail,
      phone: phone ? String(phone).trim() : null,
      passwordHash: "x", // temporary, will be set below
    });

    await pendingUser.setPassword(password);
    const rawToken = pendingUser.generateVerifyToken();
    await pendingUser.save();

    // Send verification email
    try {
      await sendPendingVerificationEmail(pendingUser, rawToken);
    } catch (e) {
      // If email fails, delete the pending user so they can retry
      await PendingUser.deleteOne({ _id: pendingUser._id });
      console.error("Failed to send verification email:", e);
      throw new AppError("Could not send verification email. Please try again.", 502, "EMAIL_SEND_FAILED");
    }

    console.log(`📧 Verification email sent to ${pendingUser.email}`);

    res.json({
      ok: true,
      message: "Verification email sent. Please check your inbox.",
      // DO NOT return token or user - they need to verify email first
    });
  })
);

// ============================================
// VERIFY EMAIL - Moves PendingUser → User
// ============================================
router.get(
  "/verify-email",
  asyncHandler(async (req, res) => {
    const token = String(req.query.token || "").trim();
    if (!token) throw new AppError("token is required", 400);

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    
    // First check PendingUser (new flow)
    const pendingUser = await PendingUser.findOne({ emailVerifyToken: tokenHash });
    
    if (pendingUser) {
      // Validate token
      if (!pendingUser.isTokenValid(token)) {
        const appUrl = process.env.APP_URL || "http://localhost:3000";
        return res.redirect(`${appUrl}/verify-email/error?reason=expired`);
      }

      // Double-check email isn't taken (race condition protection)
      const existingUser = await User.findOne({ email: pendingUser.email }).lean();
      if (existingUser) {
        await PendingUser.deleteOne({ _id: pendingUser._id });
        const appUrl = process.env.APP_URL || "http://localhost:3000";
        return res.redirect(`${appUrl}/verify-email/error?reason=duplicate`);
      }

      // Create the real user
      const user = new User({
        role: "patient",
        name: pendingUser.name,
        email: pendingUser.email,
        phone: pendingUser.phone,
        passwordHash: pendingUser.passwordHash, // Already hashed
        emailVerifiedAt: new Date(),
      });
      await user.save();

      // Create patient account and profile
      await PatientAccount.create({ userId: user._id });
      await PatientProfile.create({
        userId: user._id,
        patientId: user.hospitalId,
        fullName: user.name,
        email: user.email,
        phone: user.phone,
        allergies: [],
      });

      // Delete pending user
      await PendingUser.deleteOne({ _id: pendingUser._id });

      // Log the verification
      await auditLog({
        actorId: user._id,
        actorRole: user.role,
        action: "AUTH_SIGNUP_COMPLETED",
        targetModel: "User",
        targetId: String(user._id),
        after: user.safe(),
        ip: req.ip,
        userAgent: req.headers["user-agent"],
      });

      console.log(`✅ User verified and created: ${user.email}`);

      // Issue token and redirect to bank connect (next step in onboarding)
      const accessToken = issueToken(user);
      const appUrl = process.env.APP_URL || "http://localhost:3000";
      
      // Redirect to success page with token (frontend will store it and redirect to bank)
      return res.redirect(`${appUrl}/verify-email/success?token=${accessToken}`);
    }

    // Fallback: Check if it's an existing user re-verifying (old flow compatibility)
    const user = await User.findOne({ emailVerifyTokenHash: tokenHash });
    if (user) {
      const okHash = tokenHash === user.emailVerifyTokenHash;
      const okTime = user.emailVerifyTokenExpiresAt && new Date(user.emailVerifyTokenExpiresAt).getTime() > Date.now();
      
      if (!okHash || !okTime) {
        const appUrl = process.env.APP_URL || "http://localhost:3000";
        return res.redirect(`${appUrl}/verify-email/error?reason=expired`);
      }

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

      const accessToken = issueToken(user);
      const appUrl = process.env.APP_URL || "http://localhost:3000";
      return res.redirect(`${appUrl}/verify-email/success?token=${accessToken}`);
    }

    // Token not found
    const appUrl = process.env.APP_URL || "http://localhost:3000";
    return res.redirect(`${appUrl}/verify-email/error?reason=invalid`);
  })
);

// ============================================
// RESEND VERIFICATION - Works with PendingUser
// ============================================
router.post(
  "/resend-verification",
  authLimiter,
  asyncHandler(async (req, res) => {
    const email = String(req.body?.email || "").toLowerCase().trim();
    if (!email) throw new AppError("email is required", 400);

    // Check PendingUser first (new flow)
    const pendingUser = await PendingUser.findOne({ email });
    if (pendingUser) {
      // Check cooldown
      if (!pendingUser.canResendEmail()) {
        return res.json({ ok: true, message: "If an account exists, a verification email was sent." });
      }

      const rawToken = pendingUser.generateVerifyToken();
      await pendingUser.save();

      try {
        await sendPendingVerificationEmail(pendingUser, rawToken);
      } catch (e) {
        console.error("Failed to resend verification email:", e);
        // Don't throw - just return ok to prevent enumeration
      }

      return res.json({ ok: true, message: "Verification email resent." });
    }

    // Check existing User (old flow - for unverified existing users)
    const user = await User.findOne({ email });
    if (user && !user.emailVerifiedAt) {
      // Import the old sendVerificationEmail for backward compatibility
      const { sendVerificationEmail } = require("../utils/emailverification");
      try {
        await sendVerificationEmail(user, { reason: "manual_resend" });
      } catch (e) {
        // Silently fail to prevent enumeration
      }
    }

    // Always return ok (don't leak whether email exists)
    res.json({ ok: true, message: "If an account exists, a verification email was sent." });
  })
);

// ============================================
// LOGIN - Only works for verified users
// ============================================
router.post(
  "/login",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) throw new AppError("email and password are required", 400);

    const normalizedEmail = String(email).toLowerCase().trim();

    // Check if there's a pending registration
    const pendingUser = await PendingUser.findOne({ email: normalizedEmail }).lean();
    if (pendingUser) {
      throw new AppError(
        "Please verify your email first. Check your inbox for the verification link.",
        403,
        "EMAIL_NOT_VERIFIED"
      );
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user || !user.isActive) throw new AppError("Invalid credentials", 401, "UNAUTHORIZED");

    const ok = await user.verifyPassword(password);
    if (!ok) throw new AppError("Invalid credentials", 401, "UNAUTHORIZED");

    // If patient not verified (legacy users)
    if (user.role === "patient" && !user.emailVerifiedAt) {
      const { sendVerificationEmail } = require("../utils/emailverification");
      try {
        await sendVerificationEmail(user, { reason: "login" });
      } catch (e) {
        throw new AppError("Email not verified and we could not send verification email. Try again.", 502, "EMAIL_SEND_FAILED");
      }

      throw new AppError(
        "Email not verified. We've sent you a verification link.",
        403,
        "EMAIL_NOT_VERIFIED"
      );
    }

    // Track successful logins
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

// ============================================
// ME - Get current user
// ============================================
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

// ============================================
// FORGOT PASSWORD
// ============================================
router.post(
  "/forgot-password",
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email } = req.body || {};
    if (!email) throw new AppError("email is required", 400);

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    // Always respond ok (don't leak existence)
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

    console.log(`🔐 OTP for ${user.email}:`, otp);

    const debug = String(process.env.OTP_DEBUG || "false") === "true";
    res.json({
      ok: true,
      message: "If the email exists, an OTP was sent.",
      ...(debug ? { debugOtp: otp } : {}),
    });
  })
);

// ============================================
// RESET PASSWORD
// ============================================
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
