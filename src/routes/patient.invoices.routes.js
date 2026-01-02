// routes/patient.invoices.routes.js (or inside patient.routes.js)
const Invoice = require("../models/Invoice");

router.get("/invoices", protectPatient, async (req, res) => {
  const docs = await Invoice.find({ userId: req.user._id })
    .sort({ issuedAt: -1 })
    .lean();

  res.json({ ok: true, invoices: docs });
});
