import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";
import { decideFusion } from "../../fusion.js";

const router = Router();

/*
POST /v1/scans

Body example (scanner -> cloud):

{
  "uuid": "TEST-UUID-123",
  "plate": "AB12CDE",
  "vin": "VIN123456789",
  "make": "Ford",
  "model": "Fiesta",
  "colour": "Blue",
  "counter": 412,
  "sig_valid": true,
  "chal_valid": true,
  "pubkey_match": true,
  "tamper": false,
  "rssi": -55,
  "est_distance_m": 3.2,
  "gps_lat": 51.5,
  "gps_lon": -0.1,
  "scanner_id": "SCN-001",
  "officer_id": "OFF-001",
  "result": "MATCH",
  "raw_json": { "source": "cloud-test" }
}
*/

router.post("/", requireAuth, async (req, res) => {
  const body = req.body || {};

  try {
    // 1) Insert into your existing scan_events table (same as before)
    const sql = `
      INSERT INTO scan_events (
        ver,
        flags,
        uuid,
        counter,
        sig_valid,
        chal_valid,
        tamper_flag,
        result,
        plate,
        vin,
        make,
        model,
        colour,
        rssi,
        est_distance_m,
        gps_lat,
        gps_lon,
        scanner_id,
        officer_id,
        raw_json
      )
      VALUES (
        1,                           -- ver
        0,                           -- flags
        $1,                          -- uuid
        COALESCE($2, 0),             -- counter
        COALESCE($3, true),          -- sig_valid
        COALESCE($4, true),          -- chal_valid
        COALESCE($5, false),         -- tamper_flag
        $6,                          -- result
        $7,                          -- plate
        $8,                          -- vin
        $9,                          -- make
        $10,                         -- model
        $11,                         -- colour
        $12,                         -- rssi
        $13,                         -- est_distance_m
        $14,                         -- gps_lat
        $15,                         -- gps_lon
        $16,                         -- scanner_id
        $17,                         -- officer_id
        $18                          -- raw_json
      )
      RETURNING id, created_at;
    `;

    const params = [
      body.uuid,
      body.counter ?? 0,
      body.sig_valid ?? true,
      body.chal_valid ?? true,
      body.tamper ?? body.tamper_flag ?? false,
      body.result || "UNKNOWN",
      body.plate || null,
      body.vin || null,
      body.make || null,
      body.model || null,
      body.colour || null,
      body.rssi ?? null,
      body.est_distance_m ?? null,
      body.gps_lat ?? null,
      body.gps_lon ?? null,
      body.scanner_id || null,
      body.officer_id || null,
      body.raw_json || {}
    ];

    const result = await query(sql, params);
    const row = result.rows[0];

    console.log("scan inserted:", row);

    // --------- NEW: fusion logic ---------

    // 2) Look up vehicle in registry (if plate known)
    let registryVehicle = null;
    if (body.plate) {
      const vRes = await query(
        "SELECT * FROM vehicles WHERE plate = $1 LIMIT 1;",
        [body.plate]
      );
      registryVehicle = vRes.rows[0] || null;
    }

    // 3) Find ANPR event within ±10 seconds of this scan
    let anprEvent = null;
    if (body.plate) {
      const scanTsSec = Math.floor(new Date(row.created_at).getTime() / 1000);

      const anprRes = await query(
        `
        SELECT *
        FROM anpr_events
        WHERE plate = $1
          AND ts > (to_timestamp($2) - interval '10 seconds')
          AND ts < (to_timestamp($2) + interval '10 seconds')
        ORDER BY ts DESC
        LIMIT 1;
        `,
        [body.plate, scanTsSec]
      );
      anprEvent = anprRes.rows[0] || null;
    }

    // 4) Previous counter for this UUID (replay detection)
    let lastCounter = null;
    if (body.uuid) {
      const cRes = await query(
        `
        SELECT counter
        FROM scan_events
        WHERE uuid = $1 AND id <> $2
        ORDER BY created_at DESC
        LIMIT 1;
        `,
        [body.uuid, row.id]
      );
      lastCounter = cRes.rows[0]?.counter ?? null;
    }

    // 5) Run fusion brain
    const fusion = decideFusion({
      registryVehicle,
      scanEvent: {
        plate: body.plate || null,
        uuid: body.uuid,
        counter: body.counter ?? 0,
        sig_valid: body.sig_valid ?? true,
        chal_valid: body.chal_valid ?? true,
        pubkey_match: body.pubkey_match ?? true,   // not stored, but we can pass from body
        tamper: body.tamper ?? body.tamper_flag ?? false,
        rssi: body.rssi ?? null,
        est_distance_m: body.est_distance_m ?? null
      },
      anprEvent,
      aiEvent: null,        // we’ll add AI later
      lastCounter
    });

    // 6) Store fusion result into fusion_events
    const fusionSql = `
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
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING id, created_at;
    `;

    const fusionRes = await query(fusionSql, [
      fusion.plate,
      row.id,
      fusion.fusion_verdict,
      fusion.final_label,
      fusion.visual_confidence,
      fusion.has_gotid,
      fusion.registry_status,
      fusion.reasons,
      fusion
    ]);

    const fusionId = fusionRes.rows[0].id;

    // 7) Response back to caller (scanner, tools, etc.)
    res.json({
      ok: true,
      id: row.id,
      created_at: row.created_at,
      fusion_id: fusionId,
      fusion_verdict: fusion.fusion_verdict,
      final_label: fusion.final_label,
      visual_confidence: fusion.visual_confidence,
      reasons: fusion.reasons
    });
  } catch (err) {
    console.error("scan insert / fusion error:", err);
    res.status(500).json({
      ok: false,
      error: "DB insert or fusion error"
    });
  }
});

/**
 * GET /v1/scans/recent
 * Returns the most recent 100 scans for the admin dashboard.
 */
router.get("/recent", requireAuth, async (req, res) => {
  try {
    const sql = `
      SELECT
        id,
        created_at,
        ver,
        flags,
        uuid,
        counter,
        sig_valid,
        chal_valid,
        tamper_flag,
        result,
        plate,
        vin,
        make,
        model,
        colour,
        rssi,
        est_distance_m,
        gps_lat,
        gps_lon,
        scanner_id,
        officer_id
      FROM scan_events
      ORDER BY created_at DESC
      LIMIT 100;
    `;
    const result = await query(sql);
    res.json({
      ok: true,
      scans: result.rows
    });
  } catch (err) {
    console.error("scan recent error:", err);
    res.status(500).json({
      ok: false,
      error: "DB query error"
    });
  }
});

export default router;