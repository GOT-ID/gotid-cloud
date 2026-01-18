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

/**
 * NEW (added): GET /v1/anpr/recent?limit=10
 * Lets you confirm the cloud is receiving ANPR events from your laptop script.
 */
router.get("/recent", requireAuth, async (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query.limit ?? "20"), 10);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(200, limitRaw)) : 20;

    const r = await query(
      `
      SELECT id, plate, ts, camera_id, confidence, raw_json
      FROM anpr_events
      ORDER BY ts DESC
      LIMIT $1;
      `,
      [limit]
    );

    res.json({ ok: true, count: r.rows.length, rows: r.rows });
  } catch (err) {
    console.error("Error in GET /v1/anpr/recent:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

router.post("/", requireAuth, async (req, res) => {
  try {
    const { plate, timestamp, camera_id, confidence, raw } = req.body || {};
    const p = normPlate(plate);

    if (!p) return res.status(400).json({ ok: false, error: "missing_plate" });

    const tsSeconds =
      typeof timestamp === "number" ? timestamp : Math.floor(Date.now() / 1000);

    // 0) REGISTRY GATE (ADDED)
    // Only enrolled vehicles that actually have GOT-ID should create UUID_MISSING.
    // This prevents "random plates" from spamming UUID_MISSING rows.
    const regRes = await query(
      `
      SELECT plate, status, gotid_uuid, raw_json
      FROM vehicles
      WHERE plate = $1
      LIMIT 1;
      `,
      [p]
    );

    const reg = regRes.rows[0] || null;

    // Determine "has_gotid" from either gotid_uuid OR raw_json.has_gotid (if you store it there)
    const hasGotId =
      !!(reg && reg.gotid_uuid && String(reg.gotid_uuid).trim().length > 0) ||
      !!(reg && reg.raw_json && reg.raw_json.has_gotid === true);

    const registryStatus = reg?.status || "UNKNOWN";

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
    // Only if:
    //  - plate is ENROLLED (exists in vehicles)
    //  - has_gotid === true (tag expected)
    //  - no scan_event arrives within ±SIGN_WINDOW_SEC
    if (reg && hasGotId === true) {
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
              // IMPORTANT: this label means "tag expected but missing"
              "CLONE_MISSING_TAG_STRONG",
              confidence ?? null,
              true,
              registryStatus,
              ["Enrolled vehicle seen by ANPR but no GOT-ID scan arrived within window."],
              {
                anpr_id: row.id,
                plate: p,
                ts: row.ts,
                camera_id: camera_id || "C920_CAM",
                confidence: confidence ?? null,
                registry_status: registryStatus,
                has_gotid: true
              }
            ]
          );
        }
      }
    }

    // Always return success for ANPR ingestion
    res.status(201).json({
      ok: true,
      anpr_id: row.id,
      ts: row.ts,
      // Helpful debug fields (doesn't break anything)
      enrolled: !!reg,
      has_gotid: hasGotId === true,
      registry_status: registryStatus
    });
  } catch (err) {
    console.error("Error in POST /v1/anpr:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
