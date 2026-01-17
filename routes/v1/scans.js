import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";
import { decideFusion } from "../../fusion.js";

/* ---------- helpers ---------- */
function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}
function normHex(h) {
  return (h || "").toUpperCase().replace(/\s+/g, "");
}
function isHex(s) {
  return /^[0-9A-F]*$/.test(s);
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

const router = Router();

router.post("/", requireAuth, async (req, res) => {
  const body = req.body || {};

  try {
    // 1) Insert scan_events (this is the forensic record)
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
        1,
        0,
        $1,
        COALESCE($2, 0),
        COALESCE($3, true),
        COALESCE($4, true),
        COALESCE($5, false),
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

    const params = [
      body.uuid || null,
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

    const insertRes = await query(sql, params);
    const row = insertRes.rows[0];

    // Use scan time as fusion anchor
    const scanTsSec = Math.floor(new Date(row.created_at).getTime() / 1000);

    // --------- Cloud Master Authority lookup (by pubkey, not plate) ---------
    const reasonsCloud = [];
    const observedPlate = normPlate(body.plate || "");
    const observedPubkeyHex = normHex(body.raw_json?.pubkey_hex || body.pubkey_hex || "");

    let registryVehicle = null; // authoritative registry record
    let cloud_verdict = "UUID_MISSING";
    let cloud_action = "INVESTIGATE";

    if (!observedPubkeyHex) {
      reasonsCloud.push("No pubkey_hex provided by scanner (tag missing / not captured).");
    } else {
      const keys = pubkeyCandidates(observedPubkeyHex);

      if (!keys.length) {
        cloud_verdict = "INVALID_IDENTITY";
        cloud_action = "STOP_INVESTIGATE";
        reasonsCloud.push("pubkey_hex malformed (non-hex).");
      } else {
        let v = null;

        // Try both forms (with/without 04 prefix)
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
          cloud_verdict = "UNREGISTERED_IDENTITY";
          cloud_action = "INVESTIGATE";
          reasonsCloud.push("Identity not enrolled in cloud registry.");
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

    // 3) Find nearest ANPR event within ±10 seconds
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

    // 4) Find nearest AI event within ±10 seconds
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

    // 5) Previous counter for this UUID (replay detection)
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

    // 6) Run fusion brain (your decideFusion() already knows MATCH/MISMATCH/MISSING logic)
    const fusion = decideFusion({
      registryVehicle,
      scanEvent: {
        plate: observedPlate || null,
        uuid: body.uuid || null,
        counter: body.counter ?? 0,
        sig_valid: body.sig_valid ?? true,
        chal_valid: body.chal_valid ?? true,
        pubkey_match: body.pubkey_match ?? null,
        tamper: body.tamper ?? body.tamper_flag ?? false,
        rssi: body.rssi ?? null,
        est_distance_m: body.est_distance_m ?? null
      },
      anprEvent,
      aiEvent,
      lastCounter
    });

    // 7) Store fusion result into fusion_events (include cloud authority in raw_json)
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
        scan_id: row.id
      }
    };

    const fusionRes = await query(fusionSql, [
      fusion.plate,
      row.id,
      fusion.fusion_verdict,
      fusion.final_label,
      fusion.visual_confidence,
      fusion.has_gotid,
      fusion.registry_status,
      fusion.reasons,
      fusionPayload
    ]);

    const fusionId = fusionRes.rows[0].id;

    // 8) Respond
    res.json({
      ok: true,
      id: row.id,
      created_at: row.created_at,
      fusion_id: fusionId,
      fusion_verdict: fusion.fusion_verdict,
      final_label: fusion.final_label,
      visual_confidence: fusion.visual_confidence,
      reasons: fusion.reasons,

      // cloud authority result
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

      // evidence links
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
