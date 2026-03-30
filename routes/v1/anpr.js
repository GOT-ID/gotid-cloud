// routes/v1/anpr.js
import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

const router = Router();

// How long after ANPR we wait for a GOT-ID scan before declaring UUID_MISSING
const SIGN_WINDOW_SEC = 20;
// Suppress duplicate contradictory ANPR-led alerts for the same plate/pass
const PASS_DEDUP_SEC = 12;

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

    // 0) REGISTRY GATE
    // Only enrolled vehicles that actually have GOT-ID should create UUID_MISSING.
    const regRes = await query(
      `
      SELECT plate, status, gotid_uuid, raw_json, make, model, colour, vin
      FROM vehicles
      WHERE plate = $1
      LIMIT 1;
      `,
      [p]
    );

    const reg = regRes.rows[0] || null;

    const hasGotId =
      !!(reg && reg.gotid_uuid && String(reg.gotid_uuid).trim().length > 0) ||
      !!(reg && reg.raw_json && reg.raw_json.has_gotid === true);

    const registryStatus = reg?.status || "UNKNOWN";
    const camId = camera_id || "C920_CAM";

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

    // 3) UUID_MISSING creation logic (police-grade)
    // Only if:
    //  - plate is ENROLLED
    //  - has_gotid === true
    //  - no scan_event arrives within ±SIGN_WINDOW_SEC
    if (reg && hasGotId === true) {
      const scanRes = await query(
        `
        SELECT id, created_at, result, plate
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
        // Suppress UUID_MISSING if the same plate already got a recent MATCH
        const recentMatchRes = await query(
          `
          SELECT id
          FROM fusion_events
          WHERE plate = $1
            AND fusion_verdict = 'MATCH'
            AND created_at > (to_timestamp($2) - interval '${PASS_DEDUP_SEC} seconds')
            AND created_at < (to_timestamp($2) + interval '${PASS_DEDUP_SEC} seconds')
          ORDER BY created_at DESC
          LIMIT 1;
          `,
          [p, tsSeconds]
        );

        if (recentMatchRes.rows.length === 0) {
          // De-dupe repeated ANPR alerts
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
            let visualConfidence = "WEAK";
            if ((confidence ?? 0) >= 0.9 || (aiConfidence ?? 0) >= 0.9) {
              visualConfidence = "STRONG";
            } else if ((confidence ?? 0) >= 0.7 || (aiConfidence ?? 0) >= 0.7) {
              visualConfidence = "MEDIUM";
            }

            const reasons = [
              "Enrolled vehicle seen by ANPR but no GOT-ID scan arrived within window."
            ];

            if (aiEvent) {
              reasons.push("AI camera evidence also present near the same timestamp.");
            }

            await query(
              `
              INSERT INTO fusion_events (
                plate,
                scan_id,
                scan_event_id,
                anpr_id,
                ai_id,
                match_delta_ms,
                fusion_verdict,
                final_label,
                visual_confidence,
                has_gotid,
                registry_status,
                reasons,
                raw_json
              )
              VALUES ($1, NULL, NULL, $2, $3, NULL, $4, $5, $6, $7, $8, $9, $10);
              `,
              [
                p,
                row.id,
                aiEvent?.id ?? null,
                "UUID_MISSING",
                visualConfidence === "STRONG" || visualConfidence === "MEDIUM"
                  ? "CLONE_MISSING_TAG_STRONG"
                  : "CLONE_MISSING_TAG_WEAK",
                visualConfidence,
                true,
                registryStatus,
                reasons,
                {
                  evidence_type: "ANPR_LED_UUID_MISSING",
                  anpr_id: row.id,
                  ai_id: aiEvent?.id ?? null,
                  plate: p,
                  ts: row.ts,
                  camera_id: camId,
                  anpr_confidence: confidence ?? null,
                  ai_vehicle_conf: aiConfidence,
                  ai_vehicle_type:
                    aiEvent?.vehicle_type ||
                    aiEvent?.raw_json?.vehicle_type ||
                    aiEvent?.raw_json?.yolo_class_name ||
                    null,
                  ai_colour:
                    aiEvent?.colour ||
                    aiEvent?.raw_json?.colour_estimate ||
                    null,
                  registry_status: registryStatus,
                  has_gotid: true,
                  vehicle: reg
                    ? {
                        plate: reg.plate,
                        vin: reg.vin,
                        make: reg.make,
                        model: reg.model,
                        colour: reg.colour
                      }
                    : null
                }
              ]
            );
          }
        }
      }
    }

    // Always return success for ANPR ingestion
    res.status(201).json({
      ok: true,
      anpr_id: row.id,
      ts: row.ts,
      enrolled: !!reg,
      has_gotid: hasGotId === true,
      registry_status: registryStatus,
      ai_linked: !!aiEvent,
      ai_id: aiEvent?.id ?? null
    });
  } catch (err) {
    console.error("Error in POST /v1/anpr:", err);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
