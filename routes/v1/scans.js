import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

/* ---------- helpers (strict + safe) ---------- */
function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}
function normHex(h) {
  return (h || "").toUpperCase().replace(/\s+/g, "");
}
function isHexOrEmpty(s) {
  return s === "" || /^[0-9A-F]+$/.test(s);
}
function clampInt(n, min, max, fallback) {
  const v = Number(n);
  const x = Number.isFinite(v) ? Math.trunc(v) : fallback;
  return Math.min(max, Math.max(min, x));
}
function asBool(v, fallback) {
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
function jsonSizeBytes(obj) {
  try {
    return Buffer.byteLength(JSON.stringify(obj), "utf8");
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

/* ---------- production limits ---------- */
const MAX_RAW_JSON_BYTES = 8192;
const MAX_UUID_LEN = 128;
const MAX_PLATE_LEN = 16;
const MAX_SCANNER_ID_LEN = 64;
const MAX_OFFICER_ID_LEN = 64;

/* ---------- scanner window config ---------- */
const SCANNER_WINDOW_SEC = 10;

const router = Router();

router.post("/", requireAuth, async (req, res) => {
  const body = req.body || {};

  try {
    // ---- 0) Validate + normalise payload (production hygiene) ----
    const rawIn = asObj(body.raw_json);

    const observedPlate = normPlate(asStr(body.plate, MAX_PLATE_LEN, "") || "");
    const uuid = asStr(body.uuid, MAX_UUID_LEN, null);
    const counter = clampInt(body.counter ?? 0, 0, 2_000_000_000, 0);

    const sig_valid = asBool(body.sig_valid, false);
    const chal_valid = asBool(body.chal_valid, false);
    const tamper_flag = asBool(body.tamper ?? body.tamper_flag, false);

    const scanner_result_in =
      (asStr(body.result ?? body.verdict, 32, "") || "").toUpperCase().trim();

    let scanner_result = scanner_result_in;

    if (!scanner_result || scanner_result === "UNKNOWN") {
      if (tamper_flag) {
        scanner_result = "TAMPERED";
      } else if (!sig_valid) {
        scanner_result = "INVALID_TAG";
      } else if (sig_valid && !chal_valid) {
        scanner_result = "RELAY_SUSPECT";
      } else if (sig_valid && chal_valid) {
        scanner_result = "MATCH";
      } else {
        scanner_result = "UNKNOWN";
      }
    }

    const rssi =
      body.rssi === undefined || body.rssi === null
        ? null
        : clampInt(Number(body.rssi), -120, 20, -60);

    const est_distance_m =
      body.est_distance_m === undefined || body.est_distance_m === null
        ? null
        : Math.max(0, Math.min(5000, Number(body.est_distance_m)));

    const gps_lat =
      body.gps_lat === undefined || body.gps_lat === null
        ? null
        : Math.max(-90, Math.min(90, Number(body.gps_lat)));

    const gps_lon =
      body.gps_lon === undefined || body.gps_lon === null
        ? null
        : Math.max(-180, Math.min(180, Number(body.gps_lon)));

    const scanner_id = asStr(body.scanner_id, MAX_SCANNER_ID_LEN, null);
    const officer_id = asStr(body.officer_id, MAX_OFFICER_ID_LEN, null);

    const vin = asStr(body.vin, 32, null);
    const make = asStr(body.make, 64, null);
    const model = asStr(body.model, 128, null);
    const colour = asStr(body.colour, 32, null);
    const camera_id = asStr(body.camera_id, 64, null);

    const observedPubkeyHex = normHex(
      asStr(rawIn.pubkey_hex ?? body.pubkey_hex, 300, "") || ""
    );

    if (!isHexOrEmpty(observedPubkeyHex)) {
      return res.status(400).json({ ok: false, error: "pubkey_hex malformed (non-hex)" });
    }

    // ---- radio evidence preserved in raw_json and also used for scanner_window_events ----
    const ble_packets_seen =
      body.ble_packets_seen === undefined || body.ble_packets_seen === null
        ? null
        : clampInt(body.ble_packets_seen, 0, 1_000_000, 0);

    const ble_devices_seen =
      body.ble_devices_seen === undefined || body.ble_devices_seen === null
        ? null
        : clampInt(body.ble_devices_seen, 0, 1_000_000, 0);

    const companyid_hits_seen =
      body.companyid_hits_seen === undefined || body.companyid_hits_seen === null
        ? null
        : clampInt(body.companyid_hits_seen, 0, 1_000_000, 0);

    const gotid_candidates_seen =
      body.gotid_candidates_seen === undefined || body.gotid_candidates_seen === null
        ? null
        : clampInt(body.gotid_candidates_seen, 0, 1_000_000, 0);

    const valid_uuid_seen =
      body.valid_uuid_seen === undefined || body.valid_uuid_seen === null
        ? !!uuid
        : asBool(body.valid_uuid_seen, false);

    const valid_sig_seen =
      body.valid_sig_seen === undefined || body.valid_sig_seen === null
        ? sig_valid === true
        : asBool(body.valid_sig_seen, false);

    const valid_chal_seen =
      body.valid_chal_seen === undefined || body.valid_chal_seen === null
        ? chal_valid === true
        : asBool(body.valid_chal_seen, false);

    const pk_match_seen =
      body.pk_match_seen === undefined || body.pk_match_seen === null
        ? false
        : asBool(body.pk_match_seen, false);

    const raw = {
      ...rawIn,
      ble_packets_seen,
      ble_devices_seen,
      companyid_hits_seen,
      gotid_candidates_seen,
      valid_uuid_seen,
      valid_sig_seen,
      valid_chal_seen,
      pk_match_seen,
      scanner_result,
      scanner_id,
      officer_id,
      camera_id,
      observed_plate: observedPlate || null,
      rssi,
      est_distance_m
    };

    if (jsonSizeBytes(raw) > MAX_RAW_JSON_BYTES) {
      return res.status(413).json({ ok: false, error: "raw_json too large" });
    }

    const has_identity = !!observedPubkeyHex && sig_valid === true;

    // ---- 1) Insert scan_events (forensic record) ----
    const insertSql = `
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
        1,
        0,
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10,
        $11,
        $12,
        $13,
        $14,
        $15,
        $16,
        $17,
        $18
      )
      RETURNING id, created_at;
    `;

    const insertParams = [
      uuid,
      counter,
      sig_valid,
      chal_valid,
      tamper_flag,
      scanner_result,
      observedPlate || null,
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
      raw
    ];

    const insertRes = await query(insertSql, insertParams);
    const scanRow = insertRes.rows[0];

    // ---- 2) Insert live scanner_window_events fallback evidence ----
    // This is the immediate professional bridge so the fusion worker has real,
    // time-local scanner environment evidence for UUID_MISSING decisions.
    const scannerWindowSql = `
      INSERT INTO scanner_window_events (
        plate,
        camera_id,
        scanner_id,
        window_start,
        window_end,
        ble_packets_seen,
        ble_devices_seen,
        companyid_hits_seen,
        gotid_candidates_seen,
        strongest_rssi,
        nearest_est_distance_m,
        valid_uuid_seen,
        valid_sig_seen,
        valid_chal_seen,
        pk_match_seen,
        raw_json
      )
      VALUES (
        $1,
        $2,
        $3,
        $4::timestamptz,
        $5::timestamptz,
        $6,
        $7,
        $8,
        $9,
        $10,
        $11,
        $12,
        $13,
        $14,
        $15,
        $16::jsonb
      )
      RETURNING id;
    `;

    const scannerWindowParams = [
      observedPlate || null,
      camera_id,
      scanner_id,
      new Date(new Date(scanRow.created_at).getTime() - (SCANNER_WINDOW_SEC / 2) * 1000).toISOString(),
      new Date(new Date(scanRow.created_at).getTime() + (SCANNER_WINDOW_SEC / 2) * 1000).toISOString(),
      ble_packets_seen,
      ble_devices_seen,
      companyid_hits_seen,
      gotid_candidates_seen,
      rssi,
      est_distance_m,
      valid_uuid_seen,
      valid_sig_seen,
      valid_chal_seen,
      pk_match_seen,
      JSON.stringify({
        source: "routes/v1/scans.js",
        scan_event_id: scanRow.id,
        scanner_result,
        has_identity,
        observed_plate: observedPlate || null,
        uuid: uuid || null,
        counter,
        scanner_id,
        camera_id,
        ble_packets_seen,
        ble_devices_seen,
        companyid_hits_seen,
        gotid_candidates_seen,
        strongest_rssi: rssi,
        nearest_est_distance_m: est_distance_m,
        valid_uuid_seen,
        valid_sig_seen,
        valid_chal_seen,
        pk_match_seen
      })
    ];

    try {
      await query(scannerWindowSql, scannerWindowParams);
    } catch (windowErr) {
      console.error("scanner_window_events insert error:", windowErr);
      // Do not fail the scan ingest if the fallback evidence insert fails.
      // scan_events is still the primary forensic record.
    }

    res.json({
      ok: true,
      id: scanRow.id,
      created_at: scanRow.created_at,
      accepted: true,
      plate: observedPlate || null,
      has_identity,
      scanner_result
    });
  } catch (err) {
    console.error("scan insert error:", err);
    res.status(500).json({ ok: false, error: "DB insert error" });
  }
});

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
    res.json({ ok: true, scans: result.rows });
  } catch (err) {
    console.error("scan recent error:", err);
    res.status(500).json({ ok: false, error: "DB query error" });
  }
});

export default router;
