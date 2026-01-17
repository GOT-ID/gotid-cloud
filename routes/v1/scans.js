import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";
import { decideFusion } from "../../fusion.js";

/* ---------- helpers (strict + safe) ---------- */
function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}
function normHex(h) {
  return (h || "").toUpperCase().replace(/\s+/g, "");
}
function isHex(s) {
  return /^[0-9A-F]+$/.test(s);
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
// Accept pubkeys with or without "04" prefix.
function pubkeyCandidates(pubkeyHex) {
  const k = normHex(pubkeyHex);
  if (!k) return [];
  if (!isHex(k)) return [];
  if (k.startsWith("04")) return [k, k.slice(2)];
  return [k, "04" + k];
}
function normStatus(s) {
  return (s || "").toUpperCase().trim();
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

    const sig_valid_in = asBool(body.sig_valid, true);
    const chal_valid_in = asBool(body.chal_valid, true);
    const tamper_flag = asBool(body.tamper ?? body.tamper_flag, false);

    const rssi =
      body.rssi === undefined || body.rssi === null
        ? null
        : clampInt(body.rssi, -120, 20, -60);

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

    // If provided, must be hex
    if (!isHexOrEmpty(observedPubkeyHex)) {
      return res.status(400).json({ ok: false, error: "pubkey_hex malformed (non-hex)" });
    }

    // Police-grade truth: if no identity captured, crypto cannot be "passed"
    const has_identity = !!observedPubkeyHex;
    const sig_valid = has_identity ? sig_valid_in : false;
    const chal_valid = has_identity ? chal_valid_in : false;

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
      asStr(body.result, 32, "UNKNOWN") || "UNKNOWN",
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

    // Use scan time as fusion anchor
    const scanTsSec = Math.floor(new Date(scanRow.created_at).getTime() / 1000);

    // ---- 2) Cloud Master Authority lookup (pubkey-first + UUID_MISSING + KEY_MISMATCH) ----
    const reasonsCloud = [];
    let registryVehicle = null;
    let cloud_verdict = "UUID_MISSING";
    let cloud_action = "INVESTIGATE";

    // 2A) If NO pubkey captured: check if plate is enrolled (UUID_MISSING vs UNREGISTERED_VEHICLE)
    if (!observedPubkeyHex) {
      reasonsCloud.push("No pubkey_hex provided by scanner (tag missing / not captured).");

      if (observedPlate) {
        const pRes = await query(
          "SELECT * FROM vehicles WHERE plate = $1 LIMIT 1;",
          [observedPlate]
        );

        if (pRes.rows.length) {
          registryVehicle = pRes.rows[0];
          cloud_verdict = "UUID_MISSING";
          cloud_action = "INVESTIGATE";
          reasonsCloud.push("Plate is enrolled but no GOT-ID identity was captured within scan window.");
        } else {
          cloud_verdict = "UNREGISTERED_VEHICLE";
          cloud_action = "INVESTIGATE";
          reasonsCloud.push("Plate not found in registry (not enrolled / unknown vehicle).");
        }
      } else {
        cloud_verdict = "UUID_MISSING";
        cloud_action = "INVESTIGATE";
      }
    } else {
      // 2B) Pubkey present -> validate + look up identity
      const keys = pubkeyCandidates(observedPubkeyHex);

      if (!keys.length) {
        cloud_verdict = "INVALID_IDENTITY";
        cloud_action = "STOP_INVESTIGATE";
        reasonsCloud.push("pubkey_hex invalid (no usable candidates).");
      } else {
        let v = null;

        for (const k of keys) {
          const vRes = await query(
            "SELECT * FROM vehicles WHERE public_key = $1 LIMIT 1;",
            [k]
          );
          if (vRes.rows.length) {
            v = vRes.rows[0];
            break;
          }
        }

        if (!v) {
          // If plate exists in registry but pubkey doesn't -> KEY_MISMATCH (clone suspected)
          if (observedPlate) {
            const pRes = await query(
              "SELECT * FROM vehicles WHERE plate = $1 LIMIT 1;",
              [observedPlate]
            );

            if (pRes.rows.length) {
              registryVehicle = pRes.rows[0];
              cloud_verdict = "KEY_MISMATCH";
              cloud_action = "STOP";
              reasonsCloud.push(
                `Plate ${observedPlate} is enrolled, but pubkey_hex is not enrolled/matching. Possible clone.`
              );
            } else {
              cloud_verdict = "UNREGISTERED_IDENTITY";
              cloud_action = "INVESTIGATE";
              reasonsCloud.push("Identity not enrolled in cloud registry.");
            }
          } else {
            cloud_verdict = "UNREGISTERED_IDENTITY";
            cloud_action = "INVESTIGATE";
            reasonsCloud.push("Identity not enrolled in cloud registry.");
          }
        } else {
          registryVehicle = v;

          const st = normStatus(v.status);
          if (st && st !== "ACTIVE") {
            cloud_verdict = "REVOKED_VEHICLE";
            cloud_action = "STOP";
            reasonsCloud.push(`Registry status=${st}`);
          } else {
            const assignedPlate = normPlate(v.plate);
            if (observedPlate && assignedPlate && observedPlate !== assignedPlate) {
              cloud_verdict = "MISMATCH";
              cloud_action = "STOP";
              reasonsCloud.push(`Plate mismatch observed=${observedPlate} assigned=${assignedPlate}`);
            } else {
              cloud_verdict = "AUTHENTIC";
              cloud_action = "NONE";
              reasonsCloud.push("Identity enrolled + ACTIVE; plate consistent.");
            }
          }
        }
      }
    }

    // ---- 3) Find nearest ANPR event within ±10 seconds ----
    let anprEvent = null;
    if (observedPlate) {
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
        [observedPlate, scanTsSec]
      );
      anprEvent = anprRes.rows[0] || null;
    }

    // ---- 4) Find nearest AI event within ±10 seconds ----
    let aiEvent = null;
    if (observedPlate) {
      const aiRes = await query(
        `
        SELECT *
        FROM ai_events
        WHERE plate = $1
          AND ts > (to_timestamp($2) - interval '10 seconds')
          AND ts < (to_timestamp($2) + interval '10 seconds')
        ORDER BY ts DESC
        LIMIT 1;
        `,
        [observedPlate, scanTsSec]
      );
      aiEvent = aiRes.rows[0] || null;
    }

    // ---- 5) Previous counter for this UUID (replay input) ----
    let lastCounter = null;
    if (uuid) {
      const cRes = await query(
        `
        SELECT counter
        FROM scan_events
        WHERE uuid = $1 AND id <> $2
        ORDER BY created_at DESC
        LIMIT 1;
        `,
        [uuid, scanRow.id]
      );
      lastCounter = cRes.rows[0]?.counter ?? null;
    }

    // ---- 6) Run fusion brain (police-grade inputs) ----
    const fusion = decideFusion({
      registryVehicle,
      scanEvent: {
        plate: observedPlate || null,
        uuid: uuid || null,
        counter,
        sig_valid,
        chal_valid,
        pubkey_match: body.pubkey_match ?? null,
        tamper: tamper_flag,
        rssi,
        est_distance_m,
        cloud_verdict,
        has_identity
      },
      anprEvent,
      aiEvent,
      lastCounter
    });

    // ---- 7) Store fusion result ----
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

    const fusionPayload = {
      ...fusion,
      cloud: {
        cloud_verdict,
        cloud_action,
        reasonsCloud,
        registryVehicle: registryVehicle
          ? {
              plate: registryVehicle.plate,
              vin: registryVehicle.vin,
              make: registryVehicle.make,
              model: registryVehicle.model,
              colour: registryVehicle.colour,
              status: registryVehicle.status,
              public_key: registryVehicle.public_key
            }
          : null
      },
      linked: {
        anpr_id: anprEvent?.id ?? null,
        ai_id: aiEvent?.id ?? null,
        scan_id: scanRow.id
      }
    };

    const fusionRes = await query(fusionSql, [
      fusion.plate,
      scanRow.id,
      fusion.fusion_verdict,
      fusion.final_label,
      fusion.visual_confidence,
      fusion.has_gotid,
      fusion.registry_status,
      fusion.reasons,
      fusionPayload
    ]);

    const fusionId = fusionRes.rows[0].id;

    // ---- 8) Respond ----
    res.json({
      ok: true,
      id: scanRow.id,
      created_at: scanRow.created_at,
      fusion_id: fusionId,
      fusion_verdict: fusion.fusion_verdict,
      final_label: fusion.final_label,
      visual_confidence: fusion.visual_confidence,
      reasons: fusion.reasons,

      cloud_verdict,
      cloud_action,
      cloud_reasons: reasonsCloud,
      cloud_vehicle: registryVehicle
        ? {
            plate: registryVehicle.plate,
            vin: registryVehicle.vin,
            make: registryVehicle.make,
            model: registryVehicle.model,
            colour: registryVehicle.colour,
            status: registryVehicle.status
          }
        : null,

      anpr_id: anprEvent?.id ?? null,
      ai_id: aiEvent?.id ?? null
    });
  } catch (err) {
    console.error("scan insert / fusion error:", err);
    res.status(500).json({
      ok: false,
      error: "DB insert or fusion error"
    });
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
