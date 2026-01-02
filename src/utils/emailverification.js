const crypto = require("crypto");
const { getResend } = require("./resendClient");
const { renderBrandedEmail } = require("./brand");

function sha256(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function sendVerificationEmail(user, { reason = "verify" } = {}) {
  const from = process.env.MAIL_FROM;
  if (!from) throw new Error("MAIL_FROM is not set");

  const replyTo = process.env.MAIL_REPLY_TO || undefined;
  const appUrl = process.env.APP_URL || "http://localhost:3000";

  // basic anti-spam: 60s cooldown
  const lastSent = user.emailVerifySentAt ? new Date(user.emailVerifySentAt).getTime() : 0;
  const now = Date.now();
  if (lastSent && now - lastSent < 60 * 1000) return { skipped: true };

  // reuse existing token if still valid
  let rawToken = null;
  const hasValidExisting =
    user.emailVerifyTokenHash &&
    user.emailVerifyTokenExpiresAt &&
    new Date(user.emailVerifyTokenExpiresAt).getTime() > now;

  if (!hasValidExisting) {
    rawToken = makeToken();
    user.emailVerifyTokenHash = sha256(rawToken);
    user.emailVerifyTokenExpiresAt = new Date(now + 60 * 60 * 1000); // 1 hour
  }

  // If we reused an old token, we cannot email it (we don't have raw token),
  // so force regenerate when we need to send.
  if (!rawToken) {
    rawToken = makeToken();
    user.emailVerifyTokenHash = sha256(rawToken);
    user.emailVerifyTokenExpiresAt = new Date(now + 60 * 60 * 1000);
  }

  user.emailVerifySentAt = new Date();
  await user.save();

  const verifyUrl = `${appUrl}/verify-email?token=${rawToken}`;

  const subject = "Verify your email address";
  const message =
    `Hi ${user.name ? String(user.name).trim() : "there"},\n\n` +
    `Please confirm your email address to activate your Evermore account.\n\n` +
    `If you didn’t request this, you can ignore this email.`;

  const { html, text } = renderBrandedEmail({
    subject,
    message,
    ctaLabel: "Verify email",
    ctaUrl: verifyUrl,
  });

  const resend = await getResend();

  const { data, error } = await resend.emails.send({
    from,
    to: [String(user.email).toLowerCase().trim()],
    subject,
    html,
    text,
    replyTo,
    tags: [
      { name: "type", value: "email_verification" },
      { name: "reason", value: String(reason) },
      { name: "user_id", value: String(user._id) },
    ],
  });

  if (error) throw new Error(error.message || "Resend failed");
  return { skipped: false, id: data?.id || null };
}

function verifyEmailToken(user, token) {
  if (!user?.emailVerifyTokenHash || !user?.emailVerifyTokenExpiresAt) return false;
  const okHash = sha256(token) === user.emailVerifyTokenHash;
  const okTime = new Date(user.emailVerifyTokenExpiresAt).getTime() > Date.now();
  return okHash && okTime;
}

module.exports = { sendVerificationEmail, verifyEmailToken };
