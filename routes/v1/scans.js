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

const router = Router();

router.post("/", requireAuth, async (req, res) => {
  const body = req.body || {};

  try {
    // ---- 0) Validate + normalise payload (production hygiene) ----
    const raw = asObj(body.raw_json);
    if (jsonSizeBytes(raw) > MAX_RAW_JSON_BYTES) {
      return res.status(413).json({ ok: false, error: "raw_json too large" });
    }

    const observedPlate = normPlate(asStr(body.plate, MAX_PLATE_LEN, "") || "");
    const uuid = asStr(body.uuid, MAX_UUID_LEN, null);
    const counter = clampInt(body.counter ?? 0, 0, 2_000_000_000, 0);

    const sig_valid = asBool(body.sig_valid, false);
    const chal_valid = asBool(body.chal_valid, false);
    const tamper_flag = asBool(body.tamper ?? body.tamper_flag, false);

    const scanner_result_in =
      (asStr(body.result ?? body.verdict, 32, "") || "").toUpperCase().trim();

    let scanner_result = scanner_result_in;

    // If scanner did not provide a trustworthy final result, infer a safe local intake label.
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

    // pubkey_hex can come from raw_json or top-level
    const observedPubkeyHex = normHex(
      asStr(raw.pubkey_hex ?? body.pubkey_hex, 300, "") || ""
    );

    if (!isHexOrEmpty(observedPubkeyHex)) {
      return res.status(400).json({ ok: false, error: "pubkey_hex malformed (non-hex)" });
    }

    // Identity is only truly present if we captured public-key identity proof
    // AND the base signature was valid.
    const has_identity = !!observedPubkeyHex && sig_valid === true;

    // ---- 1) Insert scan_events (forensic record only) ----
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

    // Intake acknowledgement only.
    // Final adjudication is performed later by the fusion adjudicator worker.
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
