// routes/v1/scanner_windows.js
import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}

function clampInt(n, min, max, fallback) {
  const v = Number(n);
  const x = Number.isFinite(v) ? Math.trunc(v) : fallback;
  return Math.min(max, Math.max(min, x));
}

function asBool(v, fallback = false) {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true" || s === "1" || s === "yes") return true;
    if (s === "false" || s === "0" || s === "no") return false;
  }
  return fallback;
}

function asStr(v, maxLen, fallback = null) {
  if (v === undefined || v === null) return fallback;
  const s = String(v);
  if (!s) return fallback;
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

function asObj(v) {
  return v && typeof v === "object" && !Array.isArray(v) ? v : {};
}

function asNullablePlate(v) {
  const p = normPlate(asStr(v, 16, "") || "");
  return p || null;
}

const router = Router();

router.post("/", requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    const rawIn = asObj(body.raw_json);

    const scanner_id = asStr(body.scanner_id, 64, "SCN-001");
    const camera_id = asStr(body.camera_id, 64, null);
    const plate = asNullablePlate(body.plate);

    const window_start = body.window_start || null;
    const window_end = body.window_end || null;

    if (!window_start || !window_end) {
      return res.status(400).json({
        ok: false,
        error: "window_start and window_end are required"
      });
    }

    const ble_packets_seen = clampInt(body.ble_packets_seen, 0, 1_000_000, 0);
    const ble_devices_seen = clampInt(body.ble_devices_seen, 0, 1_000_000, 0);
    const companyid_hits_seen = clampInt(body.companyid_hits_seen, 0, 1_000_000, 0);
    const gotid_candidates_seen = clampInt(body.gotid_candidates_seen, 0, 1_000_000, 0);

    const strongest_rssi =
      body.strongest_rssi === undefined || body.strongest_rssi === null
        ? null
        : clampInt(body.strongest_rssi, -120, 20, -80);

    const nearest_est_distance_m =
      body.nearest_est_distance_m === undefined || body.nearest_est_distance_m === null
        ? null
        : Math.max(0, Math.min(5000, Number(body.nearest_est_distance_m)));

    const valid_uuid_seen = asBool(body.valid_uuid_seen, false);
    const valid_sig_seen = asBool(body.valid_sig_seen, false);
    const valid_chal_seen = asBool(body.valid_chal_seen, false);
    const pk_match_seen = asBool(body.pk_match_seen, false);

    // New police-grade plate association fields
    const plate_association = asStr(body.plate_association, 32, null);
    const plate_hint_age_ms =
      body.plate_hint_age_ms === undefined || body.plate_hint_age_ms === null
        ? null
        : clampInt(body.plate_hint_age_ms, 0, 86_400_000, 0);

    const anpr_plate_hint = asNullablePlate(
      body.anpr_plate_hint ?? rawIn.anpr_plate_hint
    );

    const anpr_plate_fresh =
      body.anpr_plate_fresh === undefined || body.anpr_plate_fresh === null
        ? (
            rawIn.anpr_plate_fresh === undefined || rawIn.anpr_plate_fresh === null
              ? null
              : asBool(rawIn.anpr_plate_fresh, false)
          )
        : asBool(body.anpr_plate_fresh, false);

    const raw_json = {
      ...rawIn,
      source: "routes/v1/scanner_windows.js",
      scanner_id,
      camera_id,
      observed_plate: plate,
      plate_association,
      plate_hint_age_ms,
      anpr_plate_hint,
      anpr_plate_fresh,
      ble_packets_seen,
      ble_devices_seen,
      companyid_hits_seen,
      gotid_candidates_seen,
      strongest_rssi,
      nearest_est_distance_m,
      valid_uuid_seen,
      valid_sig_seen,
      valid_chal_seen,
      pk_match_seen
    };

    const sql = `
      INSERT INTO scanner_window_events (
        scanner_id,
        window_start,
        window_end,
        ble_packets_seen,
        ble_devices_seen,
        companyid_hits_seen,
        gotid_candidates_seen,
        strongest_rssi,
        nearest_est_distance_m,
        raw_json,
        plate,
        camera_id,
        valid_uuid_seen,
        valid_sig_seen,
        valid_chal_seen,
        pk_match_seen,
        plate_association,
        plate_hint_age_ms,
        anpr_plate_hint,
        anpr_plate_fresh
      )
      VALUES (
        $1,$2::timestamptz,$3::timestamptz,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
      )
      RETURNING id, created_at
    `;

    const params = [
      scanner_id,
      window_start,
      window_end,
      ble_packets_seen,
      ble_devices_seen,
      companyid_hits_seen,
      gotid_candidates_seen,
      strongest_rssi,
      nearest_est_distance_m,
      JSON.stringify(raw_json),
      plate,
      camera_id,
      valid_uuid_seen,
      valid_sig_seen,
      valid_chal_seen,
      pk_match_seen,
      plate_association,
      plate_hint_age_ms,
      anpr_plate_hint,
      anpr_plate_fresh
    ];

    const result = await query(sql, params);

    return res.json({
      ok: true,
      id: result.rows[0].id,
      created_at: result.rows[0].created_at
    });
  } catch (err) {
    console.error("scanner_window insert error:", err);
    return res.status(500).json({
      ok: false,
      error: "DB insert error"
    });
  }
});

export default router;
