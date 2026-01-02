const AuditLog = require("../models/AuditLog");

async function auditLog({
  actorId,
  actorRole,
  action,
  targetModel,
  targetId,
  before,
  after,
  ip,
  userAgent,
}) {
  try {
    await AuditLog.create({
      actorId: actorId || null,
      actorRole: actorRole || "unknown",
      action,
      targetModel,
      targetId: targetId || null,
      before: before ?? null,
      after: after ?? null,
      ip: ip || null,
      userAgent: userAgent || null,
    });
  } catch (e) {
    // Don't block main operation if audit fails
    console.error("AuditLog write failed:", e.message);
  }
}

module.exports = { auditLog };
