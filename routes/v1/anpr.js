// routes/v1/anpr.js
// Simple ANPR event intake for GOT-ID cloud.

import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

const router = Router();

/*
  POST /v1/anpr

  Example body:

  {
    "plate": "BT55WMO",
    "timestamp": 1701429000,      // optional, seconds since epoch
    "camera_id": "C920_TEST",
    "confidence": 0.92,           // 0.0 - 1.0
    "raw": { "extra": "anything" }
  }
*/

router.post("/", requireAuth, async (req, res) => {
  try {
    const { plate, timestamp, camera_id, confidence, raw } = req.body || {};

    if (!plate) {
      return res.status(400).json({ ok: false, error: "missing_plate" });
    }

    // If no timestamp provided, use "now" in seconds
    const tsSeconds =
      typeof timestamp === "number"
        ? timestamp
        : Math.floor(Date.now() / 1000);

    const sql = `
      INSERT INTO anpr_events (
        plate,
        ts,
        camera_id,
        confidence,
        raw_json
      )
      VALUES ($1, to_timestamp($2), $3, $4, $5)
      RETURNING id, ts;
    `;

    const params = [
      plate,
      tsSeconds,
      camera_id || "C920_CAM",
      confidence ?? 0.9,
      raw || req.body
    ];

    const result = await query(sql, params);
    const row = result.rows[0];

    console.log("[ANPR] inserted:", row);

    res.status(201).json({
      ok: true,
      anpr_id: row.id,
      ts: row.ts
    });
  } catch (err) {
    console.error("Error in POST /v1/anpr:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;