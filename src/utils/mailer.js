// utils/mailer.js
const nodemailer = require("nodemailer");

let _tx = null;

function getTransport() {
  if (_tx) return _tx;

  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error("SMTP env missing: SMTP_HOST, SMTP_USER, SMTP_PASS (and optionally SMTP_PORT)");
  }

  _tx = nodemailer.createTransport({
    host,
    port,
    secure: port === 465, // true for 465, false for 587 (STARTTLS)
    auth: { user, pass },
  });

  return _tx;
}

async function sendMail({ to, subject, html, text, replyTo }) {
  const from = process.env.MAIL_FROM;

  // ✅ in prod, force MAIL_FROM to be set (don’t silently use fallback)
  if (process.env.NODE_ENV === "production" && !from) {
    throw new Error("MAIL_FROM is not set");
  }

  const finalFrom = from || "Evermore Hospitals <no-reply@evermorehospitals.co.uk>";
  const transport = getTransport();

  return transport.sendMail({
    from: finalFrom,
    to: Array.isArray(to) ? to : String(to),
    subject: String(subject || "").trim(),
    html,
    text,
    ...(replyTo ? { replyTo } : {}),
  });
}

module.exports = { sendMail };
