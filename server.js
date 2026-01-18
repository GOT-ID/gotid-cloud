import "dotenv/config";

import express from "express";
import path from "path";
import { fileURLToPath } from "url";

import healthRoute from "./routes/health.js";
import scansRoute from "./routes/v1/scans.js";
import authRoute from "./routes/v1/auth.js";
import anprRoute from "./routes/v1/anpr.js";
import aiRoute from "./routes/v1/ai.js";
import fusionRoute from "./routes/v1/fusion.js"; // ✅ ADD THIS

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.resolve(path.dirname(__filename));

const app = express();
app.set("trust proxy", 1);

// ---- basic CORS (safe for prototype; tighten later) ----
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Parse JSON bodies up to 1MB (for forensic scan payloads)
app.use(express.json({ limit: "1mb" }));

// Serve static admin dashboard files (if you have /public)
app.use(express.static(path.join(__dirname, "public")));

// ----------------------------------------------
// ROOT HOME ENDPOINT
// ----------------------------------------------
app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "GOT-ID Cloud API is running",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      scans: "/v1/scans",
      scans_recent: "/v1/scans/recent",
      auth_status: "/v1/auth/status",
      anpr: "/v1/anpr",
      ai: "/v1/ai",
      fusion: "/v1/fusion",                 // ✅ ADD THIS
      fusion_recent: "/v1/fusion/recent"    // ✅ ADD THIS
    }
  });
});

// ----------------------------------------------
// ROUTES
// ----------------------------------------------
app.use("/health", healthRoute);
app.use("/v1/scans", scansRoute);
app.use("/v1/auth", authRoute);
app.use("/v1/anpr", anprRoute);
app.use("/v1/ai", aiRoute);
app.use("/v1/fusion", fusionRoute); // ✅ ADD THIS

// ----------------------------------------------
// 404 FALLBACK
// ----------------------------------------------
app.use((req, res) => {
  res.status(404).json({ ok: false, error: "not_found" });
});

// ----------------------------------------------
// SERVER START
// ----------------------------------------------
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`GOT-ID Cloud running on http://localhost:${port}`);
});
