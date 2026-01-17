// routes/v1/anpr.js
import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

const router = Router();

// How long after ANPR we wait for a GOT-ID scan before declaring UUID_MISSING
const SIGN_WINDOW_SEC = 10;

function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}

router.post("/", requireAuth, async (req, res) => {
  try {
    const { plate, timestamp, camera_id, confidence, raw } = req.body || {};
    const p = normPlate(plate);

    if (!p) return res.status(400).json({ ok: false, error: "missing_plate" });

    const tsSeconds =
      typeof timestamp === "number" ? timestamp : Math.floor(Date.now() / 1000);

    // 1) Insert ANPR event
    const sql = `
      INSERT INTO anpr_events (
        plate, ts, camera_id, confidence, raw_json
      )
      VALUES ($1, to_timestamp($2), $3, $4, $5)
      RETURNING id, ts;
    `;

    const params = [
      p,
      tsSeconds,
      camera_id || "C920_CAM",
      confidence ?? 0.9,
      raw || req.body
    ];

    const r = await query(sql, params);
    const row = r.rows[0];

    // 2) UUID_MISSING creation logic (police-grade):
    // If NO scan_event arrives for this plate within ±SIGN_WINDOW_SEC,
    // we create a fusion_events record with verdict UUID_MISSING.
    //
    // IMPORTANT: This is the only way “missing tag” becomes real-world evidence:
    // car seen (ANPR) + no crypto identity observed in time window.

    const scanRes = await query(
      `
      SELECT id
      FROM scan_events
      WHERE plate = $1
        AND created_at > (to_timestamp($2) - interval '${SIGN_WINDOW_SEC} seconds')
        AND created_at < (to_timestamp($2) + interval '${SIGN_WINDOW_SEC} seconds')
      ORDER BY created_at DESC
      LIMIT 1;
      `,
      [p, tsSeconds]
    );

    if (scanRes.rows.length === 0) {
      // de-dupe: don’t spam UUID_MISSING if ANPR posts repeatedly
      const existsRes = await query(
        `
        SELECT id
        FROM fusion_events
        WHERE plate = $1
          AND scan_id IS NULL
          AND fusion_verdict = 'UUID_MISSING'
          AND created_at > (to_timestamp($2) - interval '${SIGN_WINDOW_SEC} seconds')
          AND created_at < (to_timestamp($2) + interval '${SIGN_WINDOW_SEC} seconds')
        ORDER BY created_at DESC
        LIMIT 1;
        `,
        [p, tsSeconds]
      );

      if (existsRes.rows.length === 0) {
        await query(
          `
          INSERT INTO fusion_events (
            plate,
            scan_id,
            fusion_verdict,
            final_label,
            visual_confidence,
            has_gotid,
            registry_status,
            reasons,
            raw_json
          )
          VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8);
          `,
          [
            p,
            "UUID_MISSING",
            "NO_GOTID_TAG",
            confidence ?? null,
            false,
            "UNKNOWN",
            ["ANPR saw vehicle but no GOT-ID scan arrived within window."],
            {
              anpr_id: row.id,
              plate: p,
              ts: row.ts,
              camera_id: camera_id || "C920_CAM",
              confidence: confidence ?? null
            }
          ]
        );
      }
    }

    res.status(201).json({ ok: true, anpr_id: row.id, ts: row.ts });
  } catch (err) {
    console.error("Error in POST /v1/anpr:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
