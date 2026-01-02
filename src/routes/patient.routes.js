const express = require("express");

const auth = require("../middleware/auth");
const { asyncHandler, AppError } = require("../middleware/error");

const User = require("../models/User");
const PatientAccount = require("../models/PatientAccount");
const PatientProfile = require("../models/PatientProfile");
const Appointment = require("../models/Appointment");
const Record = require("../models/Record");
const Invoice = require("../models/Invoice");
const PaymentRequest = require("../models/PaymentRequest");

const { makeRequestRef } = require("../utils/refs");
const { auditLog } = require("../utils/audit");

const router = express.Router();
router.use(auth);

// ---------------------------
// CareFlex (Option A) helpers
// ---------------------------
function n2(num) {
  const n = Number(num);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n * 100) / 100;
}

function invoiceBalanceDue(inv) {
  const total = n2(inv?.total);
  const covered = n2(inv?.coveredAmount);
  return Math.max(0, n2(total - covered));
}

async function computeOutstandingOwedEUR(userId) {
  const docs = await Invoice.find({ userId, status: { $ne: "void" } }).select("total coveredAmount status").lean();
  let owed = 0;
  for (const inv of docs) {
    // If status is paid but coveredAmount is missing/0, treat as fully covered.
    const covered = n2(inv.coveredAmount);
    const total = n2(inv.total);
    const effectiveCovered = inv.status === "paid" ? Math.max(covered, total) : covered;
    owed += Math.max(0, n2(total - effectiveCovered));
  }
  return n2(owed);
}

async function applyCareflexRepaymentOldestFirst(userId, amountEUR) {
  let remaining = n2(amountEUR);
  if (remaining <= 0) return { applied: [], remaining: 0 };

  // Oldest invoices first (issuedAt asc)
  const invoices = await Invoice.find({ userId, status: { $ne: "void" } }).sort({ issuedAt: 1 });

  const applied = [];
  for (const inv of invoices) {
    if (remaining <= 0) break;

    // Ensure coveredAmount is initialized for older docs
    if (!Number.isFinite(Number(inv.coveredAmount))) inv.coveredAmount = 0;
    if (inv.status === "paid") {
      // Keep invariant: paid invoices are fully covered
      inv.coveredAmount = Math.max(n2(inv.coveredAmount), n2(inv.total));
      await inv.save();
      continue;
    }

    const due = invoiceBalanceDue(inv);
    if (due <= 0) {
      // If somehow fully covered, mark paid
      inv.status = "paid";
      inv.paidAt = inv.paidAt || new Date();
      inv.coveredAmount = Math.max(n2(inv.coveredAmount), n2(inv.total));
      await inv.save();
      continue;
    }

    const take = Math.min(due, remaining);
    inv.coveredAmount = n2(n2(inv.coveredAmount) + take);
    remaining = n2(remaining - take);

    if (invoiceBalanceDue(inv) <= 0) {
      inv.status = "paid";
      inv.paidAt = new Date();
      inv.coveredAmount = Math.max(n2(inv.coveredAmount), n2(inv.total));
    }

    await inv.save();
    applied.push({ invoiceId: inv._id, invoiceNo: inv.invoiceNo, amount: take });
  }

  return { applied, remaining };
}

async function ensureAccountForUser(userId) {
  let account = await PatientAccount.findOne({ userId });
  if (!account) {
    account = await PatientAccount.create({ userId, currency: "EUR", creditLimit: 5000, amountOwed: 0, balance: 0 });
  }
  return account;
}

async function syncAccountFromInvoices(userId) {
  const account = await ensureAccountForUser(userId);
  account.currency = "EUR";
  if (!Number.isFinite(Number(account.creditLimit)) || Number(account.creditLimit) <= 0) account.creditLimit = 5000;
  account.amountOwed = await computeOutstandingOwedEUR(userId);
  await account.save();
  return account;
}

// Profile
router.get(
  "/profile",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.id);
    if (!user) throw new AppError("User not found", 404);

    // Ensure profile exists (older users may not have it yet)
    let profile = await PatientProfile.findOne({ userId: user._id }).lean();
    if (!profile) {
      const created = await PatientProfile.create({
        userId: user._id,
        patientId: user.hospitalId,
        fullName: user.name,
        email: user.email,
        phone: user.phone,
        allergies: [],
      });
      profile = created.toObject();
    }

    res.json({ ok: true, user: user.safe(), profile });
  })
);

// Dashboard bundle (fast single call for frontend)
router.get(
  "/dashboard",
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const [user, profile, account, appointments, records, invoices, payments, owed] = await Promise.all([
      User.findById(userId),
      PatientProfile.findOne({ userId }).lean(),
      PatientAccount.findOne({ userId }).lean(),
      Appointment.find({ userId }).sort({ scheduledAt: 1 }).limit(20).lean(),
      Record.find({ userId }).sort({ recordedAt: -1 }).limit(30).lean(),
      Invoice.find({ userId }).sort({ issuedAt: -1 }).limit(30).lean(),
      PaymentRequest.find({ userId }).sort({ createdAt: -1 }).limit(30).lean(),
      computeOutstandingOwedEUR(userId),
    ]);

    if (!user) throw new AppError("User not found", 404);

    // Older accounts might miss a profile; create lazily.
    let prof = profile;
    if (!prof) {
      const created = await PatientProfile.create({
        userId: user._id,
        patientId: user.hospitalId,
        fullName: user.name,
        email: user.email,
        phone: user.phone,
        allergies: [],
      });
      prof = created.toObject();
    }

    res.json({
      ok: true,
      user: user.safe(),
      profile: prof,
      account: account || null,
      careflex: {
        currency: "EUR",
        limit: n2(account?.creditLimit ?? 5000),
        owed,
        available: n2((account?.creditLimit ?? 5000) - owed),
      },
      appointments,
      records,
      invoices,
      payments,
    });
  })
);

// Account (money panel)
router.get(
  "/account",
  asyncHandler(async (req, res) => {
    const account = await PatientAccount.findOne({ userId: req.user.id }).lean();
    if (!account) throw new AppError("Account not found", 404);
    res.json({ ok: true, account });
  })
);

/**
 * ✅ Book appointment
 * - Creates Appointment
 * - Creates Invoice IMMEDIATELY (so Billing shows it)
 * - No admin approval waiting
 */
router.post(
  "/appointments/book",
  asyncHandler(async (req, res) => {
    const userId = req.user.id;

    const { dept, clinician, facility, startISO, notes, estimatedCostEUR, estimatedCostGBP, paymentMethod } = req.body || {};

    const department = String(dept || "").trim();
    const doctorName = String(clinician || "").trim();
    const whenISO = String(startISO || "").trim();
    // Back-compat: accept estimatedCostGBP but treat as EUR in the new UI.
    const amt = Number(estimatedCostEUR ?? estimatedCostGBP ?? 0);

    if (!department) throw new AppError("Department required", 400);
    if (!whenISO || Number.isNaN(Date.parse(whenISO))) throw new AppError("Valid startISO required", 400);
    if (!Number.isFinite(amt) || amt <= 0) throw new AppError("Valid estimatedCostEUR required", 400);

    // Fetch user for hospitalId (required by Invoice schema)
    const user = await User.findById(userId).lean();
    if (!user) throw new AppError("User not found", 404);
    const hospitalId = String(user.hospitalId || "").trim();
    if (!hospitalId) throw new AppError("User hospitalId missing (required for invoice)", 400);

    // 1) Create appointment
    const appt = await Appointment.create({
      userId,
      department,
      doctorName: doctorName || null,
      scheduledAt: new Date(whenISO),
      status: "scheduled",
      reason: facility ? `Facility: ${String(facility).slice(0, 200)}` : null,
      notes: notes ? String(notes).slice(0, 1000) : null,
    });

    // 2) Create invoice immediately (match YOUR schema)
    const invoiceNo = makeRequestRef("INV");
    const dueDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    const items = [
      {
        code: "APPT",
        description: `${department} appointment`,
        qty: 1,
        unitPrice: amt,
        amount: amt,
      },
    ];

    const subtotal = amt;
    const tax = 0;
    const total = subtotal + tax;

    // If you truly want linked_account bookings to be instantly paid, set this true:
    const payNow = paymentMethod === "linked_account"; // toggle behavior here

    const inv = await Invoice.create({
      invoiceNo,
      userId,
      hospitalId,
      appointmentId: appt._id,
      currency: "EUR",
      status: payNow ? "paid" : "issued",
      issuedAt: new Date(),
      dueDate,
      paidAt: payNow ? new Date() : null,
      coveredAmount: payNow ? total : 0,
      items,
      subtotal,
      tax,
      total,
      notes: `APPT:${String(appt._id)}${facility ? ` | ${String(facility).slice(0, 80)}` : ""}`,
    });

    // OPTIONAL: If you still want a PaymentRequest record for audit/history (but NOT admin approval),
    // mark it as approved/paid immediately. (Change enum value if your schema differs.)
    // If your PaymentRequest schema DOES NOT allow "approved", delete this block.
    let paymentRef = null;
    let pr = null;
    if (payNow) {
      paymentRef = makeRequestRef("PMT");
      pr = await PaymentRequest.create({
        userId,
        invoiceId: inv._id,
        reference: paymentRef,
        currency: "EUR",
        amount: total,
        kind: "invoice_payment",
        status: "approved",
        method: paymentMethod === "linked_account" ? "bank" : "cash",
        createdBy: userId,
        reviewedBy: userId,
        reviewedAt: new Date(),
        adminNote: `AUTO_APPT:${String(appt._id)}`,
      });
    }

    await auditLog({
      actorId: userId,
      actorRole: req.user.role,
      action: "PATIENT_APPOINTMENT_BOOKED",
      targetModel: "Appointment",
      targetId: String(appt._id),
      after: { appointment: appt.toObject(), invoice: inv.toObject(), paymentRequest: pr ? pr.toObject() : null },
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // Keep canonical CareFlex totals in sync (so refresh/relogin shows the correct numbers)
    await syncAccountFromInvoices(userId);

    res.json({
      ok: true,
      appointment: appt,
      invoice: inv,
      requestRef: invoiceNo,
      paymentRef,
      message: payNow ? "Appointment booked. Invoice paid." : "Appointment booked. Invoice issued in Billing.",
    });
  })
);

/**
 * ✅ List invoices (optional — your /dashboard already returns invoices)
 */
router.get(
  "/invoices",
  asyncHandler(async (req, res) => {
    const docs = await Invoice.find({ userId: req.user.id }).sort({ issuedAt: -1 }).lean();
    res.json({ ok: true, invoices: docs });
  })
);

/**
 * ✅ Create payment (NO admin approval)
 * - If invoiceId provided: must be "issued" (unpaid)
 * - Marks invoice "paid" immediately
 */
router.post(
  "/payments",
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { amount, currency, method, invoiceId } = req.body || {};

    let inv = null;

    if (invoiceId) {
      inv = await Invoice.findOne({ _id: invoiceId, userId });
      if (!inv) throw new AppError("Invoice not found", 404);

      // Your schema uses issued/paid/void (NOT unpaid)
      if (inv.status !== "issued") throw new AppError("Invoice is not payable", 400);

      inv.status = "paid";
      inv.paidAt = new Date();
      inv.coveredAmount = Math.max(n2(inv.coveredAmount), n2(inv.total));
      await inv.save();
    }

    const amt = inv ? Number(inv.total) : Number(amount);
    if (!Number.isFinite(amt) || amt <= 0) throw new AppError("Invalid amount", 400);

    const reference = makeRequestRef("PMT");

    // Create a record (instant approval)
    const pr = await PaymentRequest.create({
      userId,
      invoiceId: inv ? inv._id : null,
      reference,
      currency: currency || (inv ? inv.currency : "EUR"),
      amount: amt,
      method: method || "card",
      status: "approved", // <-- change if your enum differs
      kind: inv ? "invoice_payment" : "topup",
      createdBy: userId,
      reviewedBy: userId,
      reviewedAt: new Date(),
    });

    await auditLog({
      actorId: userId,
      actorRole: req.user.role,
      action: "PATIENT_PAYMENT_REQUEST_CREATED",
      targetModel: "PaymentRequest",
      targetId: String(pr._id),
      after: pr.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // Keep canonical CareFlex totals in sync
    await syncAccountFromInvoices(userId);

    res.json({
      ok: true,
      paymentRequest: pr,
      invoice: inv || null,
      message: "Payment processed.",
    });
  })
);

/**
 * ✅ CareFlex repayment (Option A)
 * - Pay any amount (EUR)
 * - Reduces total owed by allocating to oldest invoices first
 * - Creates a PaymentRequest record with kind=careflex_repayment
 */
router.post(
  "/careflex/repayments",
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const amount = n2(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) throw new AppError("Invalid amount", 400);

    const account = await PatientAccount.findOne({ userId }).lean();
    const limit = n2(account?.creditLimit ?? 5000);

    const reference = makeRequestRef("CFX");

    const { applied, remaining } = await applyCareflexRepaymentOldestFirst(userId, amount);
    const owed = await computeOutstandingOwedEUR(userId);

    // Save payment record (approved immediately)
    const pr = await PaymentRequest.create({
      userId,
      invoiceId: null,
      reference,
      currency: "EUR",
      amount,
      kind: "careflex_repayment",
      applied,
      meta: { remaining, owedAfter: owed },
      status: "approved",
      method: String(req.body?.method || "bank"),
      createdBy: userId,
      reviewedBy: userId,
      reviewedAt: new Date(),
    });

    await auditLog({
      actorId: userId,
      actorRole: req.user.role,
      action: "PATIENT_CAREFLEX_REPAYMENT",
      targetModel: "PaymentRequest",
      targetId: String(pr._id),
      after: pr.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    const acc = await syncAccountFromInvoices(userId);
    const owedNow = n2(acc.amountOwed);
    const limitNow = n2(acc.creditLimit ?? limit);

    res.json({
      ok: true,
      paymentRequest: pr,
      applied,
      careflex: { currency: "EUR", owed: owedNow, limit: limitNow, available: n2(limitNow - owedNow) },
    });
  })
);

module.exports = router;
