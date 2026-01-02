const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const connectDB = require("./config/db");
const authRoutes = require("./routes/auth.routes");
const patientRoutes = require("./routes/patient.routes");
const adminRoutes = require("./routes/admin.routes");

const { notFound, errorHandler } = require("./middleware/error");

dotenv.config();

async function boot() {
  await connectDB();

  const app = express();

  // Trust proxy if behind reverse proxy (Vercel/NGINX/etc.)
  app.set("trust proxy", 1);

  app.use(helmet());
  app.use(
    cors({
      origin: (origin, cb) => {
        // ✅ Safe defaults for local dev + Next.js same-origin proxying.
        // If CORS_ORIGIN is empty, fall back to localhost:3000.
        // Also allow requests with no Origin header (curl / server-to-server).
        const raw = String(process.env.CORS_ORIGIN || "");
        const allowed = raw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);

        if (allowed.length === 0) {
          allowed.push("http://localhost:3000");
        }

        if (!origin) return cb(null, true);
        if (allowed.includes(origin)) return cb(null, true);

        return cb(new Error(`CORS blocked for origin: ${origin}`));
      },
      credentials: true,
    })
  );
  app.use(express.json({ limit: "1mb" }));
  app.use(morgan("dev"));

  // Basic global rate limit
  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      max: 300,
      standardHeaders: true,
      legacyHeaders: false,
    })
  );

  app.get("/health", (req, res) => res.json({ ok: true, service: "evermore-backend" }));

  app.use("/api/auth", authRoutes);
  app.use("/api/patient", patientRoutes);
  app.use("/api/admin", adminRoutes);

  app.use(notFound);
  app.use(errorHandler);

  const port = Number(process.env.PORT || 8080);
  app.listen(port, () => {
    console.log(`✅ Evermore backend running on http://localhost:${port}`);
  });
}

boot().catch((err) => {
  console.error("❌ Boot failed:", err);
  process.exit(1);
});
