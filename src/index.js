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

  // Trust proxy if behind reverse proxy (Vercel/NGINX/Render/etc.)
  app.set("trust proxy", 1);

  app.use(helmet());

  // ✅ CORS configuration - more flexible
  app.use(
    cors({
      origin: (origin, cb) => {
        // Parse allowed origins from env
        const raw = String(process.env.CORS_ORIGIN || "");
        const allowed = raw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);

        // Default fallback for development
        if (allowed.length === 0) {
          allowed.push("http://localhost:3000");
        }

        // Allow requests with no Origin header (curl, server-to-server, mobile apps)
        if (!origin) return cb(null, true);

        // Check if origin is in allowed list
        if (allowed.includes(origin)) return cb(null, true);

        // Also allow any Vercel preview deployments (*.vercel.app)
        if (origin.endsWith(".vercel.app")) return cb(null, true);

        // Also allow localhost for development
        if (origin.startsWith("http://localhost:")) return cb(null, true);

        // Log rejected origins for debugging
        console.warn(`[CORS] Blocked origin: ${origin}. Allowed: ${allowed.join(", ")}`);
        return cb(new Error(`CORS blocked for origin: ${origin}`));
      },
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "Accept", "X-Requested-With"],
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

  // Health check endpoint
  app.get("/health", (req, res) => res.json({ ok: true, service: "evermore-backend" }));

  // API Routes
  app.use("/api/auth", authRoutes);
  app.use("/api/patient", patientRoutes);
  app.use("/api/admin", adminRoutes);

  // Error handling
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
