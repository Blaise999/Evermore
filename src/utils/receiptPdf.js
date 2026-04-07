const PDFDocument = require("pdfkit");
const path = require("path");
const fs = require("fs");

function n2(num) {
  const n = Number(num);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n * 100) / 100;
}

function fmtMoney(amount, currency = "GBP") {
  const n = n2(amount);
  if (currency === "GBP") return `£${n.toFixed(2)}`;
  try {
    return new Intl.NumberFormat("en-GB", { style: "currency", currency }).format(n);
  } catch { return `£${n.toFixed(2)}`; }
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-GB", { year: "numeric", month: "long", day: "numeric" });
}

function generateReceiptPdf(invoice, patient = {}, hospital = {}) {
  const doc = new PDFDocument({ size: "A4", margin: 50, bufferPages: true });
  const buffers = [];
  doc.on("data", (chunk) => buffers.push(chunk));

  const blue = "#1E40AF";
  const darkBlue = "#0F172A";
  const lightBlue = "#EFF6FF";
  const gray = "#64748B";
  const lightGray = "#F8FAFC";
  const green = "#059669";

  const pw = doc.page.width - 100; // page width minus margins
  const lm = 50; // left margin

  // ===== HEADER =====
  doc.rect(0, 0, doc.page.width, 110).fill(blue);

  // Logo text
  doc.font("Helvetica-Bold").fontSize(24).fillColor("#FFFFFF");
  doc.text(hospital.name || "Evermore Hospitals", lm, 28);
  doc.font("Helvetica").fontSize(9).fillColor("rgba(255,255,255,0.7)");
  doc.text("Excellence in Patient Care", lm, 58);

  // Status badge
  const status = String(invoice.status || "issued").toUpperCase();
  const badgeColor = status === "PAID" ? "#10B981" : status === "OVERDUE" ? "#EF4444" : "#F59E0B";
  const badgeW = 75;
  const badgeX = doc.page.width - lm - badgeW;
  doc.roundedRect(badgeX, 32, badgeW, 24, 12).fill(badgeColor);
  doc.font("Helvetica-Bold").fontSize(9).fillColor("#FFFFFF");
  doc.text(status, badgeX, 38, { width: badgeW, align: "center" });

  // Invoice label
  doc.font("Helvetica").fontSize(8).fillColor("rgba(255,255,255,0.6)");
  doc.text("INVOICE", badgeX, 65, { width: badgeW, align: "center" });
  doc.font("Helvetica-Bold").fontSize(10).fillColor("#FFFFFF");
  doc.text(invoice.invoiceNo || "—", badgeX - 20, 78, { width: badgeW + 20, align: "center" });

  let y = 128;

  // ===== FROM / BILL TO =====
  const halfW = pw / 2;

  // FROM
  doc.font("Helvetica-Bold").fontSize(7).fillColor(gray);
  doc.text("FROM", lm, y);
  y += 12;
  doc.font("Helvetica-Bold").fontSize(10).fillColor(darkBlue);
  doc.text(hospital.name || "Evermore Hospitals", lm, y);
  y += 13;
  doc.font("Helvetica").fontSize(8.5).fillColor(gray);
  const addr = hospital.address || ["145 Harley Street", "London, W1G 6BJ", "United Kingdom"];
  (Array.isArray(addr) ? addr : [addr]).forEach(line => { doc.text(line, lm, y); y += 11; });
  if (hospital.phone) { doc.text(hospital.phone, lm, y); y += 11; }
  if (hospital.email) { doc.text(hospital.email, lm, y); y += 11; }

  // BILL TO (right side)
  let ry = 128;
  doc.font("Helvetica-Bold").fontSize(7).fillColor(gray);
  doc.text("BILL TO", lm + halfW, ry);
  ry += 12;
  doc.font("Helvetica-Bold").fontSize(10).fillColor(darkBlue);
  doc.text(patient.fullName || "Patient", lm + halfW, ry);
  ry += 13;
  doc.font("Helvetica").fontSize(8.5).fillColor(gray);
  if (patient.email) { doc.text(patient.email, lm + halfW, ry); ry += 11; }
  if (patient.phone) { doc.text(patient.phone, lm + halfW, ry); ry += 11; }
  if (patient.patientId) { doc.text(`Patient ID: ${patient.patientId}`, lm + halfW, ry); ry += 11; }

  y = Math.max(y, ry) + 12;

  // ===== DATE BAR =====
  doc.roundedRect(lm, y, pw, 32, 6).fill(lightBlue);
  const dateCols = [
    { label: "ISSUED", value: fmtDate(invoice.issuedAt) },
    { label: "DUE", value: fmtDate(invoice.dueDate) },
    { label: "PAID", value: invoice.paidAt ? fmtDate(invoice.paidAt) : "—" },
    { label: "CURRENCY", value: invoice.currency || "GBP" },
  ];
  const dateColW = pw / 4;
  dateCols.forEach((col, i) => {
    const dx = lm + i * dateColW + 8;
    doc.font("Helvetica-Bold").fontSize(6.5).fillColor(blue);
    doc.text(col.label, dx, y + 5);
    doc.font("Helvetica").fontSize(8.5).fillColor(darkBlue);
    doc.text(col.value, dx, y + 16);
  });
  y += 44;

  // ===== AILMENT =====
  if (invoice.ailment || invoice.diagnosis) {
    doc.roundedRect(lm, y, pw, 28, 6).fill("#FFFBEB");
    doc.font("Helvetica-Bold").fontSize(7).fillColor("#92400E");
    doc.text("DIAGNOSIS", lm + 10, y + 4);
    doc.font("Helvetica").fontSize(8.5).fillColor(darkBlue);
    doc.text([invoice.ailment, invoice.diagnosis].filter(Boolean).join(" — "), lm + 10, y + 15, { width: pw - 20 });
    y += 36;
  }

  // ===== LINE ITEMS =====
  // Header row
  doc.roundedRect(lm, y, pw, 22, 4).fill(blue);
  const cols = [
    { label: "DESCRIPTION", x: lm + 8, w: pw * 0.44 },
    { label: "QTY", x: lm + pw * 0.48, w: 35, align: "center" },
    { label: "UNIT PRICE", x: lm + pw * 0.58, w: 70, align: "right" },
    { label: "AMOUNT", x: lm + pw * 0.78, w: pw * 0.2, align: "right" },
  ];
  doc.font("Helvetica-Bold").fontSize(7).fillColor("#FFFFFF");
  cols.forEach(c => doc.text(c.label, c.x, y + 6, { width: c.w, align: c.align || "left" }));
  y += 22;

  // Item rows
  const items = invoice.items || [];
  items.forEach((item, idx) => {
    if (idx % 2 === 0) doc.rect(lm, y, pw, 22).fill(lightGray);
    doc.font("Helvetica").fontSize(8.5).fillColor(darkBlue);
    doc.text(item.description || "—", cols[0].x, y + 6, { width: cols[0].w });
    doc.text(String(item.qty || 1), cols[1].x, y + 6, { width: cols[1].w, align: "center" });
    doc.text(fmtMoney(item.unitPrice, invoice.currency), cols[2].x, y + 6, { width: cols[2].w, align: "right" });
    doc.font("Helvetica-Bold");
    doc.text(fmtMoney(item.amount, invoice.currency), cols[3].x, y + 6, { width: cols[3].w, align: "right" });
    y += 22;
  });

  y += 8;

  // ===== TOTALS =====
  const totX = lm + pw * 0.58;
  const totW = pw * 0.4;
  const totLW = totW * 0.55;
  const totVW = totW * 0.45;

  const rows = [
    { label: "Subtotal", value: fmtMoney(invoice.subtotal, invoice.currency) },
    { label: "Tax / VAT", value: fmtMoney(invoice.tax || 0, invoice.currency) },
  ];
  if (n2(invoice.coveredAmount) > 0) {
    rows.push({ label: "CareFlex Covered", value: `- ${fmtMoney(invoice.coveredAmount, invoice.currency)}`, color: green });
  }

  rows.forEach(row => {
    doc.font("Helvetica").fontSize(8.5).fillColor(row.color || gray);
    doc.text(row.label, totX, y, { width: totLW, align: "right" });
    doc.text(row.value, totX + totLW, y, { width: totVW, align: "right" });
    y += 14;
  });

  // Grand total bar
  y += 3;
  doc.roundedRect(totX, y, totW, 28, 4).fill(blue);
  doc.font("Helvetica-Bold").fontSize(8).fillColor("#FFFFFF");
  doc.text("TOTAL DUE", totX + 8, y + 8, { width: totLW - 16, align: "right" });
  const balDue = Math.max(0, n2(n2(invoice.total) - n2(invoice.coveredAmount)));
  doc.fontSize(12);
  doc.text(fmtMoney(balDue, invoice.currency), totX + totLW, y + 5, { width: totVW - 8, align: "right" });
  y += 40;

  // ===== CAREFLEX NOTE =====
  if (n2(invoice.coveredAmount) > 0) {
    doc.roundedRect(lm, y, pw, 32, 6).fill("#F0FDF4");
    doc.font("Helvetica-Bold").fontSize(7).fillColor(green);
    doc.text("CAREFLEX CREDIT", lm + 10, y + 4);
    doc.font("Helvetica").fontSize(8.5).fillColor(darkBlue);
    doc.text(`${fmtMoney(invoice.coveredAmount, invoice.currency)} was covered by your CareFlex credit line.`, lm + 10, y + 16, { width: pw - 20 });
    y += 40;
  }

  // ===== NOTES =====
  if (invoice.notes) {
    doc.font("Helvetica-Bold").fontSize(7).fillColor(gray);
    doc.text("NOTES", lm, y);
    y += 11;
    doc.font("Helvetica").fontSize(8.5).fillColor(darkBlue);
    doc.text(String(invoice.notes), lm, y, { width: pw });
    y += 18;
  }

  // ===== FOOTER =====
  const footY = doc.page.height - 70;
  doc.rect(0, footY, doc.page.width, 70).fill(lightGray);
  doc.font("Helvetica").fontSize(7).fillColor(gray);
  doc.text("Thank you for choosing Evermore Hospitals. This invoice is valid without signature.", lm, footY + 12, { width: pw, align: "center" });
  doc.text(`${hospital.name || "Evermore Hospitals"} • ${hospital.phone || "+44 20 7946 0958"} • ${hospital.email || "billing@evermore.health"}`, lm, footY + 25, { width: pw, align: "center" });
  doc.text(`Generated ${fmtDate(new Date().toISOString())} • ${invoice.invoiceNo || "—"}`, lm, footY + 38, { width: pw, align: "center" });

  doc.end();
  return new Promise((resolve, reject) => {
    doc.on("end", () => resolve(Buffer.concat(buffers)));
    doc.on("error", reject);
  });
}

module.exports = { generateReceiptPdf };
