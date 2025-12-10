// server.js
import "dotenv/config";
import express from "express";
import cors from "cors";               // ✅ NEW: CORS
import path from "path";
import { fileURLToPath } from "url";

// Route modules
import healthRoute from "./routes/health.js";
import scansRoute from "./routes/v1/scans.js";
import authRoute from "./routes/v1/auth.js";
import anprRoute from "./routes/v1/anpr.js";

// DB helper (same query() you already use in routes/v1/scans.js)
import { query } from "./db/index.js";

// ----------------------------------------------
// PATH SETUP (so we can serve /public, etc.)
// ----------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.resolve(path.dirname(__filename));

// ----------------------------------------------
// DB SCHEMA INITIALISATION (RUNS ON STARTUP)
// ----------------------------------------------
async function ensureSchema() {
  const sql = `
    CREATE TABLE IF NOT EXISTS scan_events (
      id SERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ver INTEGER NOT NULL,
      flags INTEGER NOT NULL,
      uuid TEXT,
      counter INTEGER,
      sig_valid BOOLEAN,
      chal_valid BOOLEAN,
      tamper_flag BOOLEAN,
      result TEXT,
      plate TEXT,
      vin TEXT,
      make TEXT,
      model TEXT,
      colour TEXT,
      rssi INTEGER,
      est_distance_m NUMERIC,
      gps_lat NUMERIC,
      gps_lon NUMERIC,
      scanner_id TEXT,
      officer_id TEXT,
      raw_json JSONB
    );

    CREATE TABLE IF NOT EXISTS fusion_events (
      id SERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      plate TEXT,
      scan_id INTEGER REFERENCES scan_events(id) ON DELETE CASCADE,
      fusion_verdict TEXT,
      final_label TEXT,
      visual_confidence NUMERIC,
      has_gotid BOOLEAN,
      registry_status TEXT,
      reasons JSONB,
      raw_json JSONB
    );

    CREATE TABLE IF NOT EXISTS anpr_events (
      id SERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      plate TEXT NOT NULL,
      camera_id TEXT,
      confidence NUMERIC,
      raw_json JSONB
    );

    CREATE TABLE IF NOT EXISTS vehicles (
      id SERIAL PRIMARY KEY,
      plate TEXT UNIQUE NOT NULL,
      vin TEXT,
      make TEXT,
      model TEXT,
      colour TEXT,
      gotid_uuid TEXT,
      public_key TEXT,
      status TEXT,
      raw_json JSONB
    );
  `;

  try {
    await query(sql);
    console.log("✅ GOT-ID DB schema is ready.");
  } catch (err) {
    console.error("❌ GOT-ID DB schema init failed:", err);
  }
}

const app = express();

// kick off DB schema init (safe to run every deploy)
ensureSchema();

// ----------------------------------------------
// GLOBAL MIDDLEWARE
// ----------------------------------------------

// ✅ Allow cross-origin requests (browser / tools)
app.use(cors());

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
      auth_login: "/v1/auth/login",
      anpr_ingest: "/v1/anpr",
      test_scan: "/api/test-scan" // DEV: scanner → cloud sanity check
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
app.post("/api/test-scan", (req, res) => {
  console.log("TEST SCAN PAYLOAD:", req.body);

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
