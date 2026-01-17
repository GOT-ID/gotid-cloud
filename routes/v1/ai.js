// routes/v1/ai.js
// AI camera event intake for GOT-ID cloud (separate from ANPR).

import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

const router = Router();

/*
POST /v1/ai

Example body:

{
  "plate": "BT55WMO",             // optional (AI can run even if plate unreadable)
  "timestamp": 1701429000,        // optional, seconds since epoch
  "camera_id": "C920_TEST",
  "vehicle_conf": 0.88,           // optional
  "make": "AUDI",                 // optional
  "model": "A3",
  "colour": "BLUE",
  "raw": { ... anything ... }
}
*/

router.post("/", requireAuth, async (req, res) => {
  try {
    const { plate, timestamp, camera_id, vehicle_conf, make, model, colour, raw } =
      req.body || {};

    const tsSeconds =
      typeof timestamp === "number" ? timestamp : Math.floor(Date.now() / 1000);

    const sql = `
      INSERT INTO ai_events (
        plate,
        ts,
        camera_id,
        vehicle_conf,
        make,
        model,
        colour,
        raw_json
      )
      VALUES ($1, to_timestamp($2), $3, $4, $5, $6, $7, $8)
      RETURNING id, ts;
    `;

    const params = [
      plate || null,
      tsSeconds,
      camera_id || "C920_CAM",
      vehicle_conf ?? null,
      make || null,
      model || null,
      colour || null,
      raw || req.body
    ];

    const r = await query(sql, params);
    const row = r.rows[0];

    console.log("[AI] inserted:", row);

    res.status(201).json({
      ok: true,
      ai_id: row.id,
      ts: row.ts
    });
  } catch (err) {
    console.error("Error in POST /v1/ai:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
