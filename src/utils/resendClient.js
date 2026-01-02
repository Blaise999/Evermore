// utils/resend.js (CommonJS project-safe)
let clientPromise = null;

async function getResend() {
  const key = process.env.RESEND_API_KEY;
  if (!key) throw new Error("Missing RESEND_API_KEY");

  if (!clientPromise) {
    clientPromise = import("resend").then((mod) => new mod.Resend(key));
  }
  return clientPromise;
}

module.exports = { getResend };
