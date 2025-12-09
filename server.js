// server.js
import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

// Route modules
import healthRoute from "./routes/health.js";
import scansRoute from "./routes/v1/scans.js";
import authRoute from "./routes/v1/auth.js";
import anprRoute from "./routes/v1/anpr.js";

// ----------------------------------------------
// PATH SETUP (so we can serve /public, etc.)
// ----------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.resolve(path.dirname(__filename));

const app = express();

// ----------------------------------------------
// GLOBAL MIDDLEWARE
// ----------------------------------------------

// Parse JSON bodies up to 1MB (for forensic scan payloads)
app.use(express.json({ limit: "1mb" }));

// (Optional) allow URL-encoded forms if we ever need them
app.use(express.urlencoded({ extended: false }));

// Serve static admin dashboard files from /public
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
      auth_login: "/v1/auth/login", // once we add this route fully
      anpr_ingest: "/v1/anpr",
      test_scan: "/api/test-scan"   // DEV: scanner → cloud sanity check
    }
  });
});

// Simple extra health-check if you ever want it
app.get("/healthz", (req, res) => {
  res.json({ ok: true, service: "gotid-cloud", ts: new Date().toISOString() });
});

// ----------------------------------------------
// MAIN ROUTES
// ----------------------------------------------
app.use("/health", healthRoute);
app.use("/v1/scans", scansRoute);
app.use("/v1/auth", authRoute);
app.use("/v1/anpr", anprRoute);

// ----------------------------------------------
// DEV / DIAGNOSTIC ENDPOINT (KEEP FOR NOW)
// ----------------------------------------------
// This is your direct scanner → cloud sanity-check endpoint.
// We’ll remove it later once /v1/scans is 100% production-ready.
app.post("/api/test-scan", (req, res) => {
  console.log("TEST SCAN PAYLOAD:", req.body);

  // In future we’ll insert into Postgres here (or call scansRoute logic).
  res.json({
    ok: true,
    message: "Test scan received on GOT-ID Cloud",
    received: req.body
  });
});

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

// (Optional export, in case we ever want to import app in tests)
export default app;

