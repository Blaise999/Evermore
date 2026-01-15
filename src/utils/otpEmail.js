const { getResend } = require("./resendClient");
const { renderBrandedEmail } = require("./brand");

async function sendOtpEmail(to, otp, { minutes = 10, purpose = "OTP" } = {}) {
  const from = process.env.MAIL_FROM;
  if (!from) throw new Error("MAIL_FROM is not set");

  const replyTo = process.env.MAIL_REPLY_TO || undefined;

  const subject = `Your Evermore ${purpose} code`;
  const message =
    `Use this code to continue: ${otp}\n\n` +
    `It expires in ${minutes} minutes.\n\n` +
    `If you didn’t request this, ignore this email.`;

  const { html, text } = renderBrandedEmail({ subject, message });

  const resend = await getResend();
  const { error } = await resend.emails.send({
    from,
    to: [String(to).toLowerCase().trim()],
    subject,
    html,
    text,
    replyTo,
    tags: [{ name: "type", value: "otp" }],
  });

  if (error) throw new Error(error.message || "Resend failed");
}

module.exports = { sendOtpEmail };
