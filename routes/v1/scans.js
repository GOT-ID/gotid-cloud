import crypto from "crypto";
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
function sha256Hex(value) {
  const json = typeof value === "string" ? value : JSON.stringify(value);
  return crypto.createHash("sha256").update(json).digest("hex");
}

/* ---------- production limits ---------- */
const MAX_RAW_JSON_BYTES = 8192;
const MAX_UUID_LEN = 128;
const MAX_PLATE_LEN = 16;
const MAX_SCANNER_ID_LEN = 64;
const MAX_OFFICER_ID_LEN = 64;
const MAX_TAMPER_HEX_LEN = 4096;
const MAX_TAMPER_SIG_HEX_LEN = 4096;
const MAX_PUBKEY_HEX_LEN = 300;

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

    const tamper_live =
      body.tamper_live === undefined || body.tamper_live === null
        ? tamper_flag
        : asBool(body.tamper_live, false);

    const tamper_latched =
      body.tamper_latched === undefined || body.tamper_latched === null
        ? tamper_flag
        : asBool(body.tamper_latched, false);

    const tamper_count =
      body.tamper_count === undefined || body.tamper_count === null
        ? 0
        : clampInt(body.tamper_count, 0, 1_000_000, 0);

    const tamper_event_sig_valid =
      body.tamper_event_sig_valid === undefined || body.tamper_event_sig_valid === null
        ? null
        : asBool(body.tamper_event_sig_valid, false);

    const tamper_event_hex = asStr(
      rawIn.tamper_event_hex ?? body.tamper_event_hex,
      MAX_TAMPER_HEX_LEN,
      null
    );

    const tamper_event_sig_hex = asStr(
      rawIn.tamper_event_sig_hex ?? body.tamper_event_sig_hex,
      MAX_TAMPER_SIG_HEX_LEN,
      null
    );

    let tamper_state_observed = "NONE";
    if (tamper_live) tamper_state_observed = "TAMPER_ACTIVE";
    else if (tamper_latched) tamper_state_observed = "TAMPER_LATCHED";

    const scanner_result_in =
      (asStr(body.result ?? body.verdict, 32, "") || "").toUpperCase().trim();

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
      asStr(rawIn.pubkey_hex ?? body.pubkey_hex, MAX_PUBKEY_HEX_LEN, "") || ""
    );

    if (!isHexOrEmpty(observedPubkeyHex)) {
      return res.status(400).json({ ok: false, error: "pubkey_hex malformed (non-hex)" });
    }

    // ---- radio evidence preserved inside raw_json too ----
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

    const challenge_hash = asStr(
      body.challenge_hash ?? rawIn.challenge_hash,
      128,
      null
    );

    // ---- 1) Read existing device state before deciding truth ----
    let existingState = null;
    if (observedPubkeyHex) {
      const stateLookup = await query(
        `
        SELECT *
        FROM device_security_state
        WHERE pubkey_hex = $1
        LIMIT 1
        `,
        [observedPubkeyHex]
      );
      existingState = stateLookup.rows[0] || null;
    }

    // ---- 2) Backend decides truth. Incoming device claim is evidence only ----
    let scanner_result = "UNKNOWN";

    if (tamper_live === true) {
      scanner_result = "TAMPER_LATCHED";
    } else if (existingState?.current_state === "REMEDIATED_PENDING_REVERIFY") {
      scanner_result = "REMEDIATED_PENDING_REVERIFY";
    } else if (existingState?.current_state === "ESCALATED_HOLD") {
      scanner_result = existingState?.escalation_reason || "ESCALATED_HOLD";
    } else if (!sig_valid) {
      scanner_result = "INVALID_TAG";
    } else if (sig_valid && !chal_valid) {
      scanner_result = "RELAY_SUSPECT";
    } else if (sig_valid && chal_valid) {
      scanner_result = "MATCH";
    } else if (tamper_latched === true && existingState?.current_state !== "SECURE") {
      scanner_result = "TAMPER_LATCHED";
    }

    const raw = {
      ...rawIn,
      pubkey_hex: observedPubkeyHex || null,
      ble_packets_seen,
      ble_devices_seen,
      companyid_hits_seen,
      gotid_candidates_seen,
      valid_uuid_seen,
      valid_sig_seen,
      valid_chal_seen,
      pk_match_seen,
      scanner_result_in: scanner_result_in || null,
      scanner_result,
      scanner_id,
      officer_id,
      camera_id,
      observed_plate: observedPlate || null,
      rssi,
      est_distance_m,
      tamper_live,
      tamper_latched,
      tamper_count,
      tamper_event_sig_valid,
      tamper_event_hex,
      tamper_event_sig_hex,
      tamper_state_observed,
      challenge_hash
    };

    if (jsonSizeBytes(raw) > MAX_RAW_JSON_BYTES) {
      return res.status(413).json({ ok: false, error: "raw_json too large" });
    }

    const evidence_hash = sha256Hex(raw);
    const has_identity = !!observedPubkeyHex && sig_valid === true;

    // ---- 3) Insert scan_events (forensic identity-hit record) ----
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
        raw_json,
        pubkey_hex,
        tamper_state_observed,
        tamper_live,
        tamper_latched,
        tamper_count,
        tamper_event_sig_valid,
        tamper_event_hex,
        tamper_event_sig_hex,
        challenge_hash,
        evidence_hash
      )
      VALUES (
        1,
        0,
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
        $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29
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
      raw,
      observedPubkeyHex || null,
      tamper_state_observed,
      tamper_live,
      tamper_latched,
      tamper_count,
      tamper_event_sig_valid,
      tamper_event_hex,
      tamper_event_sig_hex,
      challenge_hash,
      evidence_hash
    ];

    const insertRes = await query(insertSql, insertParams);
    const scanRow = insertRes.rows[0];

    // ---- 4) Append immutable tamper event history (if relevant) ----
    if (
      observedPubkeyHex ||
      tamper_live ||
      tamper_latched ||
      tamper_count > 0 ||
      tamper_event_hex ||
      tamper_event_sig_hex
    ) {
      await query(
        `
        INSERT INTO tamper_events (
          pubkey_hex,
          scan_event_id,
          tamper_live,
          tamper_latched,
          tamper_count,
          tamper_event_sig_valid,
          tamper_event_hex,
          tamper_event_sig_hex,
          observed_at,
          evidence_hash
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),$9)
        `,
        [
          observedPubkeyHex || null,
          scanRow.id,
          tamper_live,
          tamper_latched,
          tamper_count,
          tamper_event_sig_valid,
          tamper_event_hex,
          tamper_event_sig_hex,
          evidence_hash
        ]
      );
    }

    // ---- 5) Upsert persistent device security state ----
    if (observedPubkeyHex) {
      let nextState = existingState?.current_state || "SECURE";
      let holdFlag = existingState?.hold_flag === true;
      let escalationReason = existingState?.escalation_reason || null;

      // Only live tamper forces current tamper state.
      if (tamper_live === true) {
        nextState = "TAMPER_LATCHED";
        holdFlag = false;
        escalationReason = null;
      } else if (sig_valid === true && chal_valid === true) {
        nextState = "SECURE";
        holdFlag = false;
        escalationReason = null;
      }

      // Replay/clone-style events still escalate and hold.
      if (
        scanner_result === "REPLAY_SUSPECT" ||
        scanner_result === "CLONE_SUSPECT" ||
        scanner_result === "MISMATCH_PUBKEY"
      ) {
        nextState = "ESCALATED_HOLD";
        holdFlag = true;
        escalationReason = scanner_result;
      }

      await query(
        `
        INSERT INTO device_security_state (
          pubkey_hex,
          current_state,
          tamper_count,
          last_seen_at,
          last_tamper_at,
          last_scan_event_id,
          hold_flag,
          escalation_reason,
          updated_at
        )
        VALUES (
          $1,$2,$3,NOW(),
          CASE WHEN $4 THEN NOW() ELSE NULL END,
          $5,$6,$7,NOW()
        )
        ON CONFLICT (pubkey_hex)
        DO UPDATE SET
          current_state = CASE
            WHEN device_security_state.current_state = 'ESCALATED_HOLD'
              AND COALESCE(device_security_state.hold_flag, false) = true
              THEN device_security_state.current_state
            ELSE EXCLUDED.current_state
          END,
          tamper_count = GREATEST(
            COALESCE(device_security_state.tamper_count, 0),
            COALESCE(EXCLUDED.tamper_count, 0)
          ),
          last_seen_at = NOW(),
          last_tamper_at = CASE
            WHEN $4 THEN NOW()
            ELSE device_security_state.last_tamper_at
          END,
          last_scan_event_id = EXCLUDED.last_scan_event_id,
          hold_flag = CASE
            WHEN device_security_state.current_state = 'ESCALATED_HOLD'
              AND COALESCE(device_security_state.hold_flag, false) = true
              THEN true
            ELSE EXCLUDED.hold_flag
          END,
          escalation_reason = CASE
            WHEN device_security_state.current_state = 'ESCALATED_HOLD'
              AND COALESCE(device_security_state.hold_flag, false) = true
              THEN COALESCE(device_security_state.escalation_reason, EXCLUDED.escalation_reason)
            ELSE EXCLUDED.escalation_reason
          END,
          updated_at = NOW()
        `,
        [
          observedPubkeyHex,
          nextState,
          tamper_count,
          tamper_live === true,
          scanRow.id,
          holdFlag,
          escalationReason
        ]
      );
    }

    res.json({
      ok: true,
      id: scanRow.id,
      created_at: scanRow.created_at,
      accepted: true,
      plate: observedPlate || null,
      has_identity,
      scanner_result,
      scanner_result_in: scanner_result_in || null,
      tamper_state_observed,
      tamper_live,
      tamper_latched,
      tamper_count
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
        officer_id,
        pubkey_hex,
        tamper_state_observed,
        tamper_live,
        tamper_latched,
        tamper_count,
        tamper_event_sig_valid,
        challenge_hash,
        evidence_hash
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
