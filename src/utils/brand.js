// utils/emailBrand.js
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function textToHtmlParagraphs(text) {
  const safe = escapeHtml(text);
  // keep line breaks readable
  return safe.replace(/\n/g, "<br/>");
}

function renderBrandedEmail({ subject, message, ctaLabel, ctaUrl }) {
  const appName = "Evermore Hospitals";
  const helpUrl = process.env.APP_HELP_URL || "https://evermorehospitals.co.uk/help";

  const messageHtml = textToHtmlParagraphs(message);

  const buttonHtml =
    ctaLabel && ctaUrl
      ? `
      <div style="margin-top:18px;">
        <a href="${escapeHtml(ctaUrl)}"
           style="display:inline-block;background:#0ea5e9;color:#fff;text-decoration:none;
                  padding:12px 16px;border-radius:12px;font-weight:700;">
          ${escapeHtml(ctaLabel)}
        </a>
      </div>`
      : "";

  const html = `<!doctype html>
<html>
  <body style="margin:0;background:#F6FAFF;padding:24px;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;">
    <div style="max-width:640px;margin:0 auto;">
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:18px;overflow:hidden;">
        <div style="padding:18px 20px;background:linear-gradient(90deg,#0ea5e9,#2563eb);color:#fff;">
          <div style="font-weight:800;font-size:16px;letter-spacing:.2px;">${appName}</div>
          <div style="opacity:.95;margin-top:4px;font-size:13px;">${escapeHtml(subject)}</div>
        </div>

        <div style="padding:20px;color:#0f172a;line-height:1.55;">
          <div style="font-size:14px;">
            ${messageHtml}
          </div>
          ${buttonHtml}
          <div style="margin-top:18px;font-size:12px;color:#64748b;">
            For sensitive medical information, please use your patient portal.
          </div>
        </div>

        <div style="padding:16px 20px;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;">
          Need help? <a href="${helpUrl}" style="color:#2563eb;text-decoration:none;font-weight:700;">Visit support</a>
        </div>
      </div>
    </div>
  </body>
</html>`;

  // plain text fallback
  const text = `${subject}\n\n${message}\n\nNeed help? ${helpUrl}`;

  return { html, text };
}

module.exports = { renderBrandedEmail };
