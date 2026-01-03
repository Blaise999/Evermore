// routes/admin.js
const express = require("express");
const mongoose = require("mongoose");

const auth = require("../middleware/auth");
const requireRole = require("../middleware/requireRole");
const { asyncHandler, AppError } = require("../middleware/error");

const User = require("../models/User");
const PatientAccount = require("../models/PatientAccount");
const PatientProfile = require("../models/PatientProfile");
const Appointment = require("../models/Appointment");
const Record = require("../models/Record");
const Invoice = require("../models/Invoice");
const PaymentRequest = require("../models/PaymentRequest");
const AuditLog = require("../models/AuditLog");
const LoginEvent = require("../models/LoginEvent");
const AdminMessage = require("../models/AdminMessage");

const { getResend } = require("../utils/resendClient");
const { renderBrandedEmail } = require("../utils/brand");

const { makeRequestRef } = require("../utils/refs");
const { auditLog } = require("../utils/audit");

const router = express.Router();

// ✅ Admin-only middleware (ONLY ONCE)
router.use(auth);
router.use(requireRole("admin"));

/* ========================================================================== */
/*  EMAIL (ADMIN -> USER)                                                     */
/* ========================================================================== */
/**
 * NEW (preferred for your admin UI):
 * POST /api/admin/users/:id/messages/email
 * body: { templateId?: "general"|"appointment"|"billing", subject, message, cta?: {label,url}, tags?: [{name,value}] }
 *
 * LEGACY (keep to avoid breaking older frontend):
 * POST /api/admin/email
 * body: { userId, subject, message, cta?: {label,url}, tags?: [{name,value}], templateId? }
 */

function sanitizeTags(tags) {
  return Array.isArray(tags)
    ? tags
        .slice(0, 10)
        .map((t) => ({
          name: String(t?.name || "").trim().slice(0, 64),
          value: String(t?.value || "").trim().slice(0, 128),
        }))
        .filter((t) => t.name && t.value)
    : [];
}

async function sendBrandedEmailToUser({ req, res, userId, subject, message, cta, tags, templateId }) {
  if (!userId) throw new AppError("userId is required", 400);
  if (!subject || !String(subject).trim()) throw new AppError("subject is required", 400);
  if (!message || !String(message).trim()) throw new AppError("message is required", 400);

  // Always get recipient from DB (don’t trust client-provided "to")
  const user = await User.findById(userId).select("email name").lean();
  if (!user?.email) throw new AppError("User not found", 404);

  const from = process.env.MAIL_FROM;
  if (!from) throw new AppError("MAIL_FROM is not set", 500);

  const replyTo = process.env.MAIL_REPLY_TO || undefined;

  const ctaLabel = cta?.label ? String(cta.label).trim() : "";
  const ctaUrl = cta?.url ? String(cta.url).trim() : "";

  // ✅ admin sends plain text; backend wraps into branded HTML
  const { html, text } = renderBrandedEmail({
    templateId: templateId ? String(templateId).trim() : "general",
    subject: String(subject).trim(),
    message: String(message),
    ctaLabel: ctaLabel && ctaUrl ? ctaLabel : "",
    ctaUrl: ctaLabel && ctaUrl ? ctaUrl : "",
  });

  const extraTags = sanitizeTags(tags);

  const resend = await getResend();

  let data = null;
  try {
    const out = await resend.emails.send({
      from,
      to: [String(user.email).toLowerCase().trim()],
      subject: String(subject).trim(),
      html,
      text,
      replyTo,
      tags: [
        { name: "source", value: "admin" },
        { name: "user_id", value: String(userId) },
        { name: "template", value: String(templateId || "general") },
        ...extraTags,
      ],
    });
    data = out?.data || null;
    const error = out?.error;
    if (error) throw new AppError(error.message || "Resend failed", 502);
  } catch (err) {
    // log failure for admin history (do not block on logging errors)
    try {
      await AdminMessage.create({
        userId,
        to: String(user.email).toLowerCase().trim(),
        subject: String(subject).trim(),
        message: String(message),
        templateId: String(templateId || "general"),
        status: "failed",
        provider: "resend",
        providerId: null,
        ctaLabel: ctaLabel && ctaUrl ? ctaLabel : "",
        ctaUrl: ctaLabel && ctaUrl ? ctaUrl : "",
        tags: extraTags,
        error: err?.message ? String(err.message) : String(err),
      });
    } catch {}
    throw err;
  }

  // log success for admin history (do not block on logging errors)
  try {
    await AdminMessage.create({
      userId,
      to: String(user.email).toLowerCase().trim(),
      subject: String(subject).trim(),
      message: String(message),
      templateId: String(templateId || "general"),
      status: "sent",
      provider: "resend",
      providerId: data?.id || null,
      ctaLabel: ctaLabel && ctaUrl ? ctaLabel : "",
      ctaUrl: ctaLabel && ctaUrl ? ctaUrl : "",
      tags: extraTags,
      error: null,
    });
  } catch {}

  await auditLog({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "ADMIN_EMAIL_SEND",
    targetModel: "User",
    targetId: String(userId),
    after: {
      to: user.email,
      subject: String(subject).trim(),
      templateId: String(templateId || "general"),
      preview: String(message).slice(0, 160),
      resendId: data?.id || null,
    },
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  return res.json({ ok: true, id: data?.id || null });
}

// ✅ Message history (for admin UI)
// GET /api/admin/users/:id/messages
router.get(
  "/users/:id/messages",
  asyncHandler(async (req, res) => {
    const userId = req.params.id;

    // Make sure user exists (clean error for UI)
    const user = await User.findById(userId).select("_id email").lean();
    if (!user?._id) throw new AppError("User not found", 404);

    const items = await AdminMessage.find({ userId }).sort({ createdAt: -1 }).limit(50).lean();

    return res.json({
      ok: true,
      items: (items || []).map((m) => ({
        id: String(m._id),
        to: m.to,
        subject: m.subject,
        message: m.message,
        status: m.status,
        createdAt: m.createdAt ? new Date(m.createdAt).toISOString() : null,
        providerId: m.providerId || null,
        error: m.error || null,
      })),
    });
  })
);

router.post(
  "/users/:id/messages/email",
  asyncHandler(async (req, res) => {
    const userId = req.params.id;
    const { templateId, subject, message, cta, tags } = req.body || {};
    return sendBrandedEmailToUser({ req, res, userId, templateId, subject, message, cta, tags });
  })
);

// ✅ LEGACY route (keep existing callers working)
router.post(
  "/email",
  asyncHandler(async (req, res) => {
    const { userId, templateId, subject, message, cta, tags } = req.body || {};
    return sendBrandedEmailToUser({ req, res, userId, templateId, subject, message, cta, tags });
  })
);

/* ========================================================================== */
/*  CareFlex (Option A) helpers                                               */
/* ========================================================================== */
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

  const invoices = await Invoice.find({ userId, status: { $ne: "void" } }).sort({ issuedAt: 1 });
  const applied = [];

  for (const inv of invoices) {
    if (remaining <= 0) break;

    if (!Number.isFinite(Number(inv.coveredAmount))) inv.coveredAmount = 0;

    if (inv.status === "paid") {
      inv.coveredAmount = Math.max(n2(inv.coveredAmount), n2(inv.total));
      await inv.save();
      continue;
    }

    const due = invoiceBalanceDue(inv);
    if (due <= 0) {
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

async function ensureProfileForUser(userDocOrLean) {
  const user = userDocOrLean;
  if (!user) return null;

  const userId = user._id ? String(user._id) : String(user.id);
  let profile = await PatientProfile.findOne({ userId }).lean();

  if (!profile) {
    const created = await PatientProfile.create({
      userId,
      patientId: String(user.hospitalId || "").trim() || `EVR-${String(userId).slice(-8)}`,
      fullName: String(user.name || "Patient").trim(),
      email: String(user.email || "").toLowerCase().trim(),
      phone: user.phone ? String(user.phone).trim() : null,
      allergies: [],
    });
    profile = created.toObject();
  }

  return profile;
}

async function ensureAccountForUser(userId) {
  let account = await PatientAccount.findOne({ userId });
  if (!account) {
    account = await PatientAccount.create({
      userId,
      currency: "EUR",
      creditLimit: 5000,
      amountOwed: 0,
      balance: 0,
    });
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

function randomBetween(from, to) {
  const a = new Date(from).getTime();
  const b = new Date(to).getTime();
  const lo = Math.min(a, b);
  const hi = Math.max(a, b);
  const t = lo + Math.random() * (hi - lo);
  return new Date(t);
}

/* ========================================================================== */
/*  USERS                                                                     */
/* ========================================================================== */
/**
 * ADMIN: list users
 */
router.get(
  "/users",
  asyncHandler(async (req, res) => {
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(50, Math.max(1, Number(req.query.limit || 20)));
    const q = String(req.query.q || "").trim();

    const filter = q
      ? {
          $or: [
            { email: { $regex: q, $options: "i" } },
            { name: { $regex: q, $options: "i" } },
            { hospitalId: { $regex: q, $options: "i" } },
          ],
        }
      : {};

    const [userDocs, total] = await Promise.all([
      User.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
      User.countDocuments(filter),
    ]);

    const userIds = userDocs.map((u) => u._id);
    const profiles = await PatientProfile.find({ userId: { $in: userIds } }).select("userId patientId fullName email phone").lean();
    const pByUserId = new Map(profiles.map((p) => [String(p.userId), p]));

    const items = userDocs.map((u) => {
      const p = pByUserId.get(String(u._id));
      return {
        _id: String(u._id),
        role: u.role,
        email: u.email,
        fullName: p?.fullName || u.name,
        phone: p?.phone || u.phone || null,
        patientId: p?.patientId || u.hospitalId,
        createdAt: u.createdAt,
        lastLoginAt: u.lastLoginAt || null,
        isActive: u.isActive,
      };
    });

    res.json({ ok: true, page, limit, total, items, users: userDocs.map((u) => u.safe()) });
  })
);

/**
 * ADMIN: list recent successful logins
 */
router.get(
  "/logins",
  asyncHandler(async (req, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit || 200)));
    const userId = req.query.userId ? String(req.query.userId) : null;

    const filter = userId ? { userId } : {};
    const docs = await LoginEvent.find(filter)
      .sort({ at: -1 })
      .limit(limit)
      .populate("userId", "email role name hospitalId")
      .lean();

    const items = docs.map((d) => ({
      _id: String(d._id),
      at: d.at,
      ip: d.ip || null,
      userAgent: d.userAgent || null,
      user: d.userId
        ? {
            _id: String(d.userId._id),
            email: d.userId.email,
            role: d.userId.role,
            name: d.userId.name,
            hospitalId: d.userId.hospitalId,
          }
        : null,
    }));

    res.json({ ok: true, items });
  })
);

/**
 * ADMIN: get a user by id (full bundle)
 */
router.get(
  "/users/:id",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) throw new AppError("User not found", 404);

    const [account, appointments, records, invoices, payments] = await Promise.all([
      PatientAccount.findOne({ userId: user._id }).lean(),
      Appointment.find({ userId: user._id }).sort({ scheduledAt: 1 }).lean(),
      Record.find({ userId: user._id }).sort({ recordedAt: -1 }).lean(),
      Invoice.find({ userId: user._id }).sort({ issuedAt: -1 }).lean(),
      PaymentRequest.find({ userId: user._id }).sort({ createdAt: -1 }).lean(),
    ]);

    res.json({
      ok: true,
      user: user.safe(),
      account: account || null,
      appointments,
      records,
      invoices,
      payments,
    });
  })
);

/**
 * ADMIN: get/edit a user's extended profile (used by admin editor)
 */
router.get(
  "/users/:id/profile",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id).lean();
    if (!user) throw new AppError("User not found", 404);
    const profile = await ensureProfileForUser(user);
    res.json({ ok: true, profile });
  })
);

router.put(
  "/users/:id/profile",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) throw new AppError("User not found", 404);

    const existingProfile = await ensureProfileForUser(user);
    let profile = await PatientProfile.findOne({ userId: user._id });
    if (!profile) {
      profile = await PatientProfile.create({
        userId: user._id,
        patientId: user.hospitalId,
        fullName: user.name,
        email: user.email,
        phone: user.phone || null,
      });
    }

    const patch = req.body || {};
    const beforeUser = user.toObject();
    const beforeProfile = profile.toObject();

    if (patch.fullName !== undefined) user.name = String(patch.fullName).trim() || user.name;
    if (patch.phone !== undefined) user.phone = patch.phone ? String(patch.phone).trim() : null;

    if (patch.email !== undefined) {
      const nextEmail = String(patch.email).toLowerCase().trim();
      if (!nextEmail) throw new AppError("email is required", 400);
      if (nextEmail !== user.email) {
        const exists = await User.findOne({ email: nextEmail }).lean();
        if (exists) throw new AppError("Email already in use", 409, "DUPLICATE");
        user.email = nextEmail;
      }
    }

    await user.save();

    if (profile) {
      profile.patientId = String(patch.patientId || profile.patientId || user.hospitalId);
      profile.fullName = String(patch.fullName || profile.fullName || user.name);
      profile.email = String(patch.email || profile.email || user.email).toLowerCase().trim();
      profile.phone = patch.phone !== undefined ? (patch.phone ? String(patch.phone).trim() : null) : profile.phone;
      if (patch.gender !== undefined) profile.gender = patch.gender ? String(patch.gender) : null;
      if (patch.dob !== undefined) profile.dob = patch.dob ? new Date(patch.dob) : null;
      if (patch.address !== undefined) profile.address = patch.address ? String(patch.address) : null;
      if (patch.bloodType !== undefined) profile.bloodType = patch.bloodType ? String(patch.bloodType) : null;
      if (patch.allergies !== undefined) profile.allergies = Array.isArray(patch.allergies) ? patch.allergies : [];
      if (patch.notes !== undefined) profile.notes = patch.notes ? String(patch.notes) : null;
      await profile.save();
    }

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_PROFILE_UPDATE",
      targetModel: "PatientProfile",
      targetId: String(user._id),
      before: { user: beforeUser, profile: beforeProfile },
      after: { user: user.toObject(), profile: profile ? profile.toObject() : null },
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, profile: profile ? profile.toObject() : existingProfile });
  })
);

/**
 * ADMIN: edit money stuff (balances / credit limit / amount owed / credit score)
 */
router.patch(
  "/users/:id/account",
  asyncHandler(async (req, res) => {
    const userId = req.params.id;

    const account = await PatientAccount.findOne({ userId });
    if (!account) throw new AppError("Account not found", 404);

    const before = account.toObject();

    const { balance, creditLimit, amountOwed, creditScore, owedDueAt, currency, notes } = req.body || {};

    if (balance !== undefined) account.balance = Number(balance);
    if (creditLimit !== undefined) account.creditLimit = Number(creditLimit);
    if (amountOwed !== undefined) account.amountOwed = Number(amountOwed);
    if (creditScore !== undefined) account.creditScore = Number(creditScore);
    if (currency !== undefined) account.currency = String(currency);
    if (notes !== undefined) account.notes = notes ? String(notes) : null;

    if (owedDueAt !== undefined) {
      account.owedDueAt = owedDueAt ? new Date(owedDueAt) : null;
    }

    await account.save();

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_ACCOUNT_UPDATE",
      targetModel: "PatientAccount",
      targetId: String(account._id),
      before,
      after: account.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, account });
  })
);

/**
 * ADMIN: list a user's appointments (admin frontend expects /users/:id/appointments)
 */
router.get(
  "/users/:id/appointments",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id).lean();
    if (!user) throw new AppError("User not found", 404);
    const items = await Appointment.find({ userId: user._id }).sort({ scheduledAt: 1 }).lean();
    res.json({ ok: true, items });
  })
);

/**
 * ADMIN: create appointment for a user (manual)
 */
router.post(
  "/users/:id/appointments",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id).lean();
    if (!user) throw new AppError("User not found", 404);

    const body = req.body || {};
    const department = String(body.department || body.dept || "General Practice").trim();
    const doctorName = body.doctorName
      ? String(body.doctorName).trim()
      : body.clinician
      ? String(body.clinician).trim()
      : null;

    const scheduledAtRaw = body.scheduledAt || body.startISO || body.whenISO || new Date().toISOString();
    if (!department) throw new AppError("department is required", 400);
    if (!scheduledAtRaw || Number.isNaN(Date.parse(String(scheduledAtRaw))))
      throw new AppError("Valid scheduledAt required", 400);

    const appt = await Appointment.create({
      userId: user._id,
      department,
      doctorName,
      scheduledAt: new Date(scheduledAtRaw),
      status: body.status ? String(body.status) : "scheduled",
      reason: body.reason ? String(body.reason).slice(0, 200) : null,
      notes: body.notes ? String(body.notes).slice(0, 1000) : null,
    });

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_APPOINTMENT_CREATE",
      targetModel: "Appointment",
      targetId: String(appt._id),
      after: appt.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, appointment: appt });
  })
);

/**
 * ADMIN: delete appointment
 */
router.delete(
  "/appointments/:appointmentId",
  asyncHandler(async (req, res) => {
    const appt = await Appointment.findById(req.params.appointmentId);
    if (!appt) throw new AppError("Appointment not found", 404);
    const before = appt.toObject();
    await appt.deleteOne();

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_APPOINTMENT_DELETE",
      targetModel: "Appointment",
      targetId: String(req.params.appointmentId),
      before,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true });
  })
);

/**
 * ADMIN: list a user's records
 */
router.get(
  "/users/:id/records",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id).lean();
    if (!user) throw new AppError("User not found", 404);
    const items = await Record.find({ userId: user._id }).sort({ recordedAt: -1 }).lean();
    res.json({ ok: true, items });
  })
);

/**
 * ADMIN: create a record for a user
 */
router.post(
  "/users/:id/records",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id).lean();
    if (!user) throw new AppError("User not found", 404);

    const body = req.body || {};
    const title = String(body.title || "Hospital Record").trim();
    if (!title) throw new AppError("title is required", 400);

    const record = await Record.create({
      userId: user._id,
      type: body.type ? String(body.type) : "consultation",
      title,
      summary: body.summary ? String(body.summary) : null,
      data: body.data !== undefined ? body.data : {},
      recordedAt: body.recordedAt ? new Date(body.recordedAt) : new Date(),
      clinician: body.clinician ? String(body.clinician) : null,
      status: body.status ? String(body.status) : "final",
    });

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_RECORD_CREATE",
      targetModel: "Record",
      targetId: String(record._id),
      after: record.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, record });
  })
);

/**
 * ADMIN: delete record
 */
router.delete(
  "/records/:recordId",
  asyncHandler(async (req, res) => {
    const record = await Record.findById(req.params.recordId);
    if (!record) throw new AppError("Record not found", 404);
    const before = record.toObject();
    await record.deleteOne();

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_RECORD_DELETE",
      targetModel: "Record",
      targetId: String(req.params.recordId),
      before,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true });
  })
);

/**
 * ADMIN: list a user's invoices
 */
router.get(
  "/users/:id/invoices",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id).lean();
    if (!user) throw new AppError("User not found", 404);
    const items = await Invoice.find({ userId: user._id }).sort({ issuedAt: -1 }).lean();
    res.json({ ok: true, items });
  })
);

function normalizeInvoiceItems(items) {
  if (!Array.isArray(items)) return [];
  return items
    .map((it) => {
      const qty = Number(it.qty ?? 1);
      const unitPrice = Number(it.unitPrice ?? it.price ?? 0);
      const amount = Number(it.amount ?? qty * unitPrice);
      return {
        code: it.code ? String(it.code) : undefined,
        description: String(it.description || "Item").trim(),
        qty: Number.isFinite(qty) && qty > 0 ? qty : 1,
        unitPrice: Number.isFinite(unitPrice) && unitPrice >= 0 ? unitPrice : 0,
        amount: Number.isFinite(amount) && amount >= 0 ? amount : 0,
      };
    })
    .filter((x) => x.description);
}

/**
 * ADMIN: create an invoice for a user.
 */
router.post(
  "/users/:id/invoices",
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) throw new AppError("User not found", 404);

    const body = req.body || {};
    const currency = String(body.currency || "EUR").toUpperCase();
    if (currency !== "EUR") throw new AppError("Billing is EUR-only (CareFlex)", 400);

    let appointmentId = body.appointmentId || null;
    if (appointmentId) {
      const exists = await Appointment.findById(appointmentId).lean();
      if (!exists) appointmentId = null;
    }

    if (!appointmentId) {
      const dept = String(body.department || "Billing");
      const when = body.issuedAt || body.scheduledAt || new Date().toISOString();
      const appt = await Appointment.create({
        userId: user._id,
        department: dept,
        doctorName: body.doctorName ? String(body.doctorName) : null,
        scheduledAt: new Date(when),
        status: "completed",
        reason: body.reason ? String(body.reason).slice(0, 200) : "Billing",
        notes: body.notes ? String(body.notes).slice(0, 1000) : null,
      });
      appointmentId = appt._id;
    }

    const items = normalizeInvoiceItems(body.items);
    const subtotal = Number.isFinite(Number(body.subtotal))
      ? Number(body.subtotal)
      : items.reduce((s, it) => s + Number(it.amount || 0), 0);
    const tax = Number.isFinite(Number(body.tax)) ? Number(body.tax) : 0;
    const total = Number.isFinite(Number(body.total)) ? Number(body.total) : subtotal + tax;
    if (!Number.isFinite(total) || total <= 0) throw new AppError("Invoice total must be > 0", 400);

    const status = body.status ? String(body.status) : "issued";
    const issuedAt = body.issuedAt ? new Date(body.issuedAt) : new Date();
    const dueDate = body.dueDate ? new Date(body.dueDate) : new Date(issuedAt.getTime() + 30 * 24 * 60 * 60 * 1000);

    const invoiceNo = String(body.invoiceNo || "").trim() || makeRequestRef("INV");

    const inv = await Invoice.create({
      invoiceNo,
      userId: user._id,
      hospitalId: String(user.hospitalId || "EVM").trim(),
      appointmentId,
      currency: "EUR",
      status,
      issuedAt,
      dueDate,
      paidAt: status === "paid" ? (body.paidAt ? new Date(body.paidAt) : new Date()) : null,
      coveredAmount: status === "paid" ? total : Number(body.coveredAmount || 0),
      items,
      subtotal,
      tax,
      total,
      notes: body.notes ? String(body.notes) : "",
    });

    await syncAccountFromInvoices(user._id);

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_INVOICE_CREATE",
      targetModel: "Invoice",
      targetId: String(inv._id),
      after: inv.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, invoice: inv });
  })
);

/**
 * ADMIN: update an invoice
 */
async function updateInvoiceHandler(req, res) {
  const inv = await Invoice.findById(req.params.invoiceId);
  if (!inv) throw new AppError("Invoice not found", 404);
  const before = inv.toObject();

  const body = req.body || {};

  if (body.invoiceNo !== undefined) inv.invoiceNo = String(body.invoiceNo).trim() || inv.invoiceNo;
  if (body.status !== undefined) inv.status = String(body.status);
  if (body.issuedAt !== undefined) inv.issuedAt = new Date(body.issuedAt);
  if (body.dueDate !== undefined) inv.dueDate = new Date(body.dueDate);
  if (body.paidAt !== undefined) inv.paidAt = body.paidAt ? new Date(body.paidAt) : null;
  if (body.notes !== undefined) inv.notes = body.notes ? String(body.notes) : "";

  if (body.items !== undefined) inv.items = normalizeInvoiceItems(body.items);
  if (body.subtotal !== undefined) inv.subtotal = Number(body.subtotal);
  if (body.tax !== undefined) inv.tax = Number(body.tax);
  if (body.total !== undefined) inv.total = Number(body.total);
  if (body.coveredAmount !== undefined) inv.coveredAmount = Number(body.coveredAmount);

  inv.currency = "EUR";

  if (inv.status === "paid") {
    inv.paidAt = inv.paidAt || new Date();
    inv.coveredAmount = Math.max(n2(inv.coveredAmount), n2(inv.total));
  }

  await inv.save();
  await syncAccountFromInvoices(inv.userId);

  await auditLog({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "ADMIN_INVOICE_UPDATE",
    targetModel: "Invoice",
    targetId: String(inv._id),
    before,
    after: inv.toObject(),
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  res.json({ ok: true, invoice: inv });
}

router.patch("/invoices/:invoiceId", asyncHandler(updateInvoiceHandler));
router.put("/invoices/:invoiceId", asyncHandler(updateInvoiceHandler));

/**
 * ADMIN: delete invoice
 */
router.delete(
  "/invoices/:invoiceId",
  asyncHandler(async (req, res) => {
    const inv = await Invoice.findById(req.params.invoiceId);
    if (!inv) throw new AppError("Invoice not found", 404);
    const before = inv.toObject();
    const userId = inv.userId;

    await inv.deleteOne();
    await syncAccountFromInvoices(userId);

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_INVOICE_DELETE",
      targetModel: "Invoice",
      targetId: String(req.params.invoiceId),
      before,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true });
  })
);

/**
 * ADMIN: edit appointments
 */
async function updateAppointmentHandler(req, res) {
  const appt = await Appointment.findById(req.params.appointmentId);
  if (!appt) throw new AppError("Appointment not found", 404);

  const before = appt.toObject();

  const { department, doctorName, scheduledAt, status, reason, notes } = req.body || {};

  if (department !== undefined) appt.department = String(department);
  if (doctorName !== undefined) appt.doctorName = doctorName ? String(doctorName) : null;
  if (scheduledAt !== undefined) appt.scheduledAt = new Date(scheduledAt);
  if (status !== undefined) appt.status = String(status);
  if (reason !== undefined) appt.reason = reason ? String(reason) : null;
  if (notes !== undefined) appt.notes = notes ? String(notes) : null;

  await appt.save();

  await auditLog({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "ADMIN_APPOINTMENT_UPDATE",
    targetModel: "Appointment",
    targetId: String(appt._id),
    before,
    after: appt.toObject(),
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  res.json({ ok: true, appointment: appt });
}

router.patch("/appointments/:appointmentId", asyncHandler(updateAppointmentHandler));
router.put("/appointments/:appointmentId", asyncHandler(updateAppointmentHandler));

/**
 * ADMIN: edit hospital reports (records)
 */
async function updateRecordHandler(req, res) {
  const record = await Record.findById(req.params.recordId);
  if (!record) throw new AppError("Record not found", 404);

  const before = record.toObject();

  const { type, title, summary, data, recordedAt, clinician, status } = req.body || {};
  if (type !== undefined) record.type = String(type);
  if (title !== undefined) record.title = String(title);
  if (summary !== undefined) record.summary = summary ? String(summary) : null;
  if (data !== undefined) record.data = data;
  if (recordedAt !== undefined) record.recordedAt = new Date(recordedAt);
  if (clinician !== undefined) record.clinician = clinician ? String(clinician) : null;
  if (status !== undefined) record.status = String(status);

  await record.save();

  await auditLog({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "ADMIN_RECORD_UPDATE",
    targetModel: "Record",
    targetId: String(record._id),
    before,
    after: record.toObject(),
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  res.json({ ok: true, record });
}

router.patch("/records/:recordId", asyncHandler(updateRecordHandler));
router.put("/records/:recordId", asyncHandler(updateRecordHandler));

/**
 * ADMIN: list payment requests (default pending)
 */
router.get(
  "/payments",
  asyncHandler(async (req, res) => {
    const status = String(req.query.status || "pending");
    const items = await PaymentRequest.find({ status }).sort({ createdAt: -1 }).limit(200).lean();
    res.json({ ok: true, items, payments: items });
  })
);

/**
 * ADMIN: approve payment request
 */
router.post(
  "/payments/:paymentId/approve",
  asyncHandler(async (req, res) => {
    const pr = await PaymentRequest.findById(req.params.paymentId);
    if (!pr) throw new AppError("Payment request not found", 404);
    if (pr.status !== "pending") throw new AppError("Payment request is not pending", 400);

    const account = await PatientAccount.findOne({ userId: pr.userId });
    if (!account) throw new AppError("Patient account not found", 404);

    const beforePR = pr.toObject();

    pr.status = "approved";
    pr.reviewedBy = req.user.id;
    pr.reviewedAt = new Date();
    pr.adminNote = req.body?.adminNote ? String(req.body.adminNote) : null;
    await pr.save();

    let invoice = null;
    let allocation = null;

    if (pr.kind === "invoice_payment" && pr.invoiceId) {
      invoice = await Invoice.findById(pr.invoiceId);
      if (!invoice) throw new AppError("Invoice not found", 404);
      if (invoice.status !== "issued") throw new AppError("Invoice is not payable", 400);

      invoice.status = "paid";
      invoice.paidAt = new Date();
      invoice.coveredAmount = Math.max(n2(invoice.coveredAmount), n2(invoice.total));
      await invoice.save();
    }

    if (pr.kind === "careflex_repayment") {
      allocation = await applyCareflexRepaymentOldestFirst(pr.userId, pr.amount);
      pr.applied = allocation.applied;
      pr.meta = Object.assign({}, pr.meta || {}, {
        remaining: allocation.remaining,
        settledAt: new Date().toISOString(),
      });
      await pr.save();
    }

    const beforeAcc = account.toObject();
    const amt = n2(pr.amount);
    if (pr.kind === "topup") {
      account.balance = n2(n2(account.balance) + amt);
    }

    account.currency = "EUR";
    if (!Number.isFinite(Number(account.creditLimit)) || Number(account.creditLimit) <= 0) account.creditLimit = 5000;
    account.amountOwed = await computeOutstandingOwedEUR(pr.userId);

    await account.save();

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_PAYMENT_APPROVE",
      targetModel: "PaymentRequest",
      targetId: String(pr._id),
      before: beforePR,
      after: pr.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_ACCOUNT_AUTO_UPDATE_AFTER_PAYMENT_APPROVE",
      targetModel: "PatientAccount",
      targetId: String(account._id),
      before: beforeAcc,
      after: account.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({
      ok: true,
      payment: pr,
      invoice: invoice ? invoice.toObject() : null,
      account: account.toObject(),
      careflex: {
        currency: "EUR",
        limit: n2(account.creditLimit ?? 5000),
        owed: n2(account.amountOwed ?? 0),
        available: n2((account.creditLimit ?? 5000) - (account.amountOwed ?? 0)),
      },
      applied: allocation ? allocation.applied : [],
    });
  })
);

/**
 * ADMIN: decline payment request
 */
router.post(
  "/payments/:paymentId/decline",
  asyncHandler(async (req, res) => {
    const pr = await PaymentRequest.findById(req.params.paymentId);
    if (!pr) throw new AppError("Payment request not found", 404);
    if (pr.status !== "pending") throw new AppError("Payment request is not pending", 400);

    const before = pr.toObject();

    pr.status = "declined";
    pr.reviewedBy = req.user.id;
    pr.reviewedAt = new Date();
    pr.adminNote = req.body?.adminNote ? String(req.body.adminNote) : "Declined";
    await pr.save();

    await auditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: "ADMIN_PAYMENT_DECLINE",
      targetModel: "PaymentRequest",
      targetId: String(pr._id),
      before,
      after: pr.toObject(),
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.json({ ok: true, payment: pr });
  })
);

/* ========================================================================== */
/*  SEED / POPULATE USER DATA                                                 */
/* ========================================================================== */
/**
 * ADMIN: bulk-create user data
 * POST /api/admin/users/:id/populate
 *
 * NEW: supports reset
 *   - query: ?reset=1 or ?force=1
 *   - body:  { reset: true }
 *
 * "reset" deletes existing appointments/records/invoices/payments for that user first.
 */
async function bulkCreateUserDataHandler(req, res) {
  // Validate user id early so you don’t get CastErrors
  const id = String(req.params.id || "");
  if (!mongoose.Types.ObjectId.isValid(id)) throw new AppError("Invalid user id", 400);

  const user = await User.findById(id);
  if (!user) throw new AppError("User not found", 404);

  await ensureProfileForUser(user);
  await ensureAccountForUser(user._id);

  const body = req.body || {};

  const reset =
    body.reset === true ||
    String(req.query.reset || "") === "1" ||
    String(req.query.force || "") === "1";

  if (reset) {
    await Promise.all([
      Appointment.deleteMany({ userId: user._id }),
      Record.deleteMany({ userId: user._id }),
      Invoice.deleteMany({ userId: user._id }),
      PaymentRequest.deleteMany({ userId: user._id }),
    ]);
  }

  const legacyCount = Math.min(50, Math.max(1, Number(body.count || 3)));
  const counts = {
    appointments: Number(body?.counts?.appointments ?? body.appointmentsCount ?? (body.appointments !== false ? legacyCount : 0)),
    records: Number(body?.counts?.records ?? body.recordsCount ?? (body.records !== false ? legacyCount : 0)),
    invoices: Number(body?.counts?.invoices ?? body.invoicesCount ?? (body.invoices !== false ? legacyCount : 0)),
  };
  counts.appointments = Math.min(200, Math.max(0, Math.floor(counts.appointments)));
  counts.records = Math.min(400, Math.max(0, Math.floor(counts.records)));
  counts.invoices = Math.min(200, Math.max(0, Math.floor(counts.invoices)));

  const flags = {
    appointments: counts.appointments > 0,
    records: counts.records > 0,
    invoices: counts.invoices > 0,
  };

  const now = new Date();
  const fromDateRaw =
    body.fromDate ||
    body.startDate ||
    body.from ||
    new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000).toISOString();
  const toDateRaw =
    body.toDate ||
    body.endDate ||
    body.to ||
    new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

  if (Number.isNaN(Date.parse(String(fromDateRaw))) || Number.isNaN(Date.parse(String(toDateRaw)))) {
    throw new AppError("fromDate/toDate must be valid ISO date strings", 400);
  }

  const fromDate = new Date(fromDateRaw);
  const toDate = new Date(toDateRaw);

  const paidRatio = Math.max(0, Math.min(1, Number(body.paidRatio ?? 0.2)));
  const partialCoverageRatio = Math.max(0, Math.min(1, Number(body.partialCoverageRatio ?? 0.35)));

  const created = { appointments: 0, records: 0, invoices: 0 };

  const departments = ["Cardiology", "General Practice", "Radiology", "Dermatology", "Orthopedics", "Neurology"];
  const doctors = ["Dr. Adebayo", "Dr. Musa", "Dr. Okafor", "Dr. Smith", "Dr. Garcia", "Dr. Chen"];
  const recordTypes = ["consultation", "lab", "radiology", "prescription", "diagnosis", "discharge"];

  if (flags.appointments) {
    const appts = [];
    for (let i = 0; i < counts.appointments; i++) {
      const scheduledAt = randomBetween(fromDate, toDate);
      const r = Math.random();
      const status = r < 0.6 ? "scheduled" : r < 0.9 ? "completed" : "cancelled";
      appts.push({
        userId: user._id,
        department: departments[i % departments.length],
        doctorName: doctors[i % doctors.length],
        scheduledAt,
        status,
        reason: "Visit",
        notes: null,
      });
    }
    await Appointment.insertMany(appts);
    created.appointments = appts.length;
  }

  if (flags.records) {
    const recs = [];
    for (let i = 0; i < counts.records; i++) {
      const recordedAt = randomBetween(fromDate, toDate);
      const type = recordTypes[i % recordTypes.length];
      recs.push({
        userId: user._id,
        type,
        title: `${type[0].toUpperCase()}${type.slice(1)} Report`,
        summary: "Clinical note.",
        clinician: doctors[i % doctors.length],
        status: "final",
        data: {
          vitals: { bp: "120/80", temp: "36.7C", pulse: 72 },
          findings: "Normal",
          recommendation: "Hydrate, rest, follow-up if symptoms persist.",
        },
        recordedAt,
      });
    }
    await Record.insertMany(recs);
    created.records = recs.length;
  }

  if (flags.invoices) {
    for (let i = 0; i < counts.invoices; i++) {
      const issuedAt = randomBetween(fromDate, toDate);
      const dueDate = new Date(issuedAt.getTime() + (7 + Math.floor(Math.random() * 45)) * 24 * 60 * 60 * 1000);

      const appt = await Appointment.create({
        userId: user._id,
        department: departments[i % departments.length],
        doctorName: doctors[i % doctors.length],
        scheduledAt: issuedAt,
        status: "completed",
        reason: "Visit",
        notes: null,
      });

      const itemA = { code: "CONS", description: "Consultation", qty: 1, unitPrice: 120, amount: 120 };
      const itemB = { code: "LAB", description: "Lab work", qty: 1, unitPrice: 80, amount: 80 };
      const itemC = { code: "MED", description: "Medication", qty: 1, unitPrice: 40, amount: 40 };
      const chosen = i % 3 === 0 ? [itemA, itemB] : i % 3 === 1 ? [itemA, itemC] : [itemA, itemB, itemC];

      const subtotal = chosen.reduce((s, it) => s + Number(it.amount || 0), 0);
      const tax = 0;
      const total = subtotal + tax;

      const isPaid = Math.random() < paidRatio;
      const hasPartialCoverage = !isPaid && Math.random() < partialCoverageRatio;
      const coveredAmount = isPaid ? total : hasPartialCoverage ? n2(total * (0.1 + Math.random() * 0.75)) : 0;

      await Invoice.create({
        invoiceNo: makeRequestRef("INV"),
        userId: user._id,
        hospitalId: String(user.hospitalId || "EVM").trim(),
        appointmentId: appt._id,
        currency: "EUR",
        status: isPaid ? "paid" : "issued",
        issuedAt,
        dueDate,
        paidAt: isPaid ? new Date(issuedAt.getTime() + 2 * 60 * 60 * 1000) : null,
        coveredAmount,
        items: chosen,
        subtotal,
        tax,
        total,
        notes: "",
      });

      created.invoices += 1;
    }
  }

  await syncAccountFromInvoices(user._id);

  await auditLog({
    actorId: req.user.id,
    actorRole: req.user.role,
    action: "ADMIN_BULK_CREATE_USER_DATA",
    targetModel: "User",
    targetId: String(user._id),
    after: { created, flags, counts, fromDate, toDate, reset },
    ip: req.ip,
    userAgent: req.headers["user-agent"],
  });

  res.json({ ok: true, created, fromDate, toDate, reset });
}

/**
 * ✅ NEW: /seed (alias for populate)
 * Works with GET and POST because your error showed GET.
 *
 * GET  /api/admin/users/:id/seed
 * POST /api/admin/users/:id/seed
 *
 * Defaults: reset=true, count=3
 * You can override in POST body.
 */
router.get(
  "/users/:id/seed",
  asyncHandler(async (req, res) => {
    req.body = Object.assign({}, req.body || {}, { count: 3, reset: true });
    return bulkCreateUserDataHandler(req, res);
  })
);

router.post(
  "/users/:id/seed",
  asyncHandler(async (req, res) => {
    req.body = Object.assign({ count: 3 }, req.body || {});
    if (req.body.reset === undefined) req.body.reset = true;
    return bulkCreateUserDataHandler(req, res);
  })
);

router.post("/users/:id/populate", asyncHandler(bulkCreateUserDataHandler));

/**
 * ADMIN: audit logs
 */
router.get(
  "/audit",
  asyncHandler(async (req, res) => {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ ok: true, logs });
  })
);

module.exports = router;
