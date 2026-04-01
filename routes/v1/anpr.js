// routes/v1/anpr.js
import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

const router = Router();

// Keep these for now as shared policy values / future use.
// UUID_MISSING will be handled by the pass adjudicator later, not here.
const SIGN_WINDOW_SEC = 20;
const PASS_DEDUP_SEC = 12;
const RECENT_MATCH_SUPPRESS_SEC = 25;

function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function getAiConfidence(ai) {
  if (!ai) return null;
  const c1 = num(ai.vehicle_conf);
  if (c1 !== null) return c1;
  const c2 = num(ai.raw_json?.vehicle_type_conf);
  if (c2 !== null) return c2;
  const c3 = num(ai.raw_json?.confidence);
  if (c3 !== null) return c3;
  return null;
}

/**
 * GET /v1/anpr/recent?limit=10
 * Lets you confirm the cloud is receiving ANPR events from your laptop script.
 */
router.get("/recent", requireAuth, async (req, res) => {
  try {
    const limitRaw = parseInt(String(req.query.limit ?? "20"), 10);
    const limit = Number.isFinite(limitRaw)
      ? Math.max(1, Math.min(200, limitRaw))
      : 20;

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

    if (!p) {
      return res.status(400).json({ ok: false, error: "missing_plate" });
    }

    const tsSeconds =
      typeof timestamp === "number" ? timestamp : Math.floor(Date.now() / 1000);

    const camId = camera_id || "C920_CAM";

    // 0) REGISTRY GATE
    // Keep this here because the ANPR anchor should still know whether
    // the vehicle is enrolled / expected to have GOT-ID.
    const regRes = await query(
      `
      SELECT plate, status, gotid_uuid, public_key, raw_json, make, model, colour, vin
      FROM vehicles
      WHERE plate = $1
      LIMIT 1;
      `,
      [p]
    );

    const reg = regRes.rows[0] || null;

    const hasGotId =
      !!(reg && reg.public_key && String(reg.public_key).trim().length > 0) ||
      !!(reg && reg.gotid_uuid && String(reg.gotid_uuid).trim().length > 0) ||
      !!(reg && reg.raw_json && reg.raw_json.has_gotid === true);

    const registryStatus = reg?.status || "UNKNOWN";

    // 1) Insert ANPR event
    const insertAnprSql = `
      INSERT INTO anpr_events (
        plate, ts, camera_id, confidence, raw_json
      )
      VALUES ($1, to_timestamp($2), $3, $4, $5)
      RETURNING id, ts;
    `;

    const insertAnprParams = [
      p,
      tsSeconds,
      camId,
      confidence ?? 0.9,
      raw || req.body
    ];

    const anprInsertRes = await query(insertAnprSql, insertAnprParams);
    const row = anprInsertRes.rows[0];

    // 2) Find nearest AI event within ±10 seconds
    const aiRes = await query(
      `
      SELECT *
      FROM ai_events
      WHERE ts BETWEEN (to_timestamp($1) - interval '10 seconds')
                   AND (to_timestamp($1) + interval '10 seconds')
        AND camera_id = $2
        AND (
          plate = $3
          OR plate IS NULL
          OR plate = ''
        )
      ORDER BY
        CASE WHEN plate = $3 THEN 0 ELSE 1 END,
        ABS(EXTRACT(EPOCH FROM (ts - to_timestamp($1)))) ASC
      LIMIT 1;
      `,
      [tsSeconds, camId, p]
    );

    const aiEvent = aiRes.rows[0] || null;
    const aiConfidence = getAiConfidence(aiEvent);

    // IMPORTANT:
    // Do NOT create UUID_MISSING here.
    // This route is now ANPR ingestion + anchor creation only.
    // Final absence adjudication must happen later, after the full
    // allowed window has actually expired.

    // Always return success for ANPR ingestion
    res.status(201).json({
      ok: true,
      anpr_id: row.id,
      ts: row.ts,
      enrolled: !!reg,
      has_gotid: hasGotId === true,
      registry_status: registryStatus,
      ai_linked: !!aiEvent,
      ai_id: aiEvent?.id ?? null,

      // Helpful debug / audit fields for now
      ai_confidence: aiConfidence,
      policy: {
        sign_window_sec: SIGN_WINDOW_SEC,
        pass_dedup_sec: PASS_DEDUP_SEC,
        recent_match_suppress_sec: RECENT_MATCH_SUPPRESS_SEC
      }
    });
  } catch (err) {
    console.error("Error in POST /v1/anpr:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
