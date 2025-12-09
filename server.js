// server.js — GOT-ID Cloud API

import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

import healthRoute from "./routes/health.js";
import scansRoute from "./routes/v1/scans.js";
import authRoute from "./routes/v1/auth.js";
import anprRoute from "./routes/v1/anpr.js";

// ----------------------------------------------
// PATH / APP SETUP
// ----------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.resolve(path.dirname(__filename));

const app = express();

// Parse JSON bodies up to 1MB (for forensic scan payloads)
app.use(express.json({ limit: "1mb" }));

// Serve static admin dashboard files
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
      auth_login: "/v1/auth/login", // once we add this route
      anpr: "/v1/anpr",
      test_scan: "/api/test-scan"
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

// ----------------------------------------------
// TEST SCAN ENDPOINT (for Daniel's sanity check)
// ----------------------------------------------
app.post("/api/test-scan", (req, res) => {
  console.log("TEST SCAN PAYLOAD:", req.body);

  // In future we'll insert into Postgres here.
  res.json({
    ok: true,
    message: "Test scan received on GOT-ID Cloud",
    received: req.body
  });
});

// ----------------------------------------------
// 404 FALLBACK  (KEEP THIS LAST)
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

