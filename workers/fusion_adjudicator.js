import { query } from "../db/index.js";
import { decideFusion } from "../fusion.js";


const SIGN_WINDOW_SEC = 20;
const LOOP_INTERVAL_MS = 2000;

console.log("🚔 GOT-ID Fusion Worker Started...");

function normPlate(p) {
  return (p || "").toUpperCase().replace(/\s+/g, "");
}

function normHex(h) {
  return (h || "").toUpperCase().replace(/\s+/g, "");
}

function isHex(s) {
  return /^[0-9A-F]+$/.test(s);
}

function pubkeyCandidates(pubkeyHex) {
  const k = normHex(pubkeyHex);
  if (!k) return [];
  if (!isHex(k)) return [];
  if (k.startsWith("04")) return [k, k.slice(2)];
  return [k, "04" + k];
}

function asBool(v, fallback = null) {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true" || s === "1" || s === "yes") return true;
    if (s === "false" || s === "0" || s === "no") return false;
  }
  return fallback;
}

async function processJobs() {
  try {
    const jobs = await query(`
      SELECT *
      FROM fusion_jobs
      WHERE status = 'PENDING'
        AND due_at <= NOW()
      ORDER BY due_at ASC
      LIMIT 10
    `);

    for (const job of jobs.rows) {
      await processSingleJob(job);
    }
  } catch (err) {
    console.error("❌ Worker loop error:", err);
  }
}

async function processSingleJob(job) {
  const { id, anpr_id } = job;

  try {
    console.log(`🔍 Processing ANPR job ${anpr_id}`);

    // 1) Load ANPR event
    const anprRes = await query(
      `SELECT * FROM anpr_events WHERE id = $1 LIMIT 1`,
      [anpr_id]
    );

    if (!anprRes.rows.length) {
      await failJob(id, "ANPR event missing");
      return;
    }

    const anpr = anprRes.rows[0];

    // 2) Load earliest matching scan within ANPR window
    const scanRes = await query(
      `
      SELECT *
      FROM scan_events
      WHERE plate = $1
        AND created_at BETWEEN $2 AND ($2 + interval '${SIGN_WINDOW_SEC} seconds')
      ORDER BY created_at ASC
      LIMIT 1
      `,
      [anpr.plate, anpr.ts]
    );

    const scan = scanRes.rows[0] || null;

    // 3) Load nearest AI event
    const aiRes = await query(
      `
      SELECT *
      FROM ai_events
      WHERE ts BETWEEN ($1 - interval '10 seconds') AND ($1 + interval '10 seconds')
        AND (
          plate = $2
          OR plate IS NULL
          OR plate = ''
        )
      ORDER BY
        CASE WHEN plate = $2 THEN 0 ELSE 1 END,
        ABS(EXTRACT(EPOCH FROM (ts - $1))) ASC
      LIMIT 1
      `,
      [anpr.ts, anpr.plate]
    );

    const ai = aiRes.rows[0] || null;

    // 4) Load registry vehicle (pubkey first if scan exists, else plate)
    let registryVehicle = null;
    let observedPubkeyHex = "";

    if (scan?.raw_json?.pubkey_hex) {
      observedPubkeyHex = normHex(scan.raw_json.pubkey_hex);
    }

    const keys = pubkeyCandidates(observedPubkeyHex);

    for (const k of keys) {
      const regRes = await query(
        `SELECT * FROM vehicles WHERE public_key = $1 LIMIT 1`,
        [k]
      );
      if (regRes.rows.length) {
        registryVehicle = regRes.rows[0];
        break;
      }
    }

    if (!registryVehicle) {
      const regRes = await query(
        `SELECT * FROM vehicles WHERE plate = $1 LIMIT 1`,
        [anpr.plate]
      );
      registryVehicle = regRes.rows[0] || null;
    }

    // 5) Previous counter lookup
    let lastCounter = null;

    if (scan) {
      if (keys.length) {
        const cRes = await query(
          `
          SELECT counter, created_at
          FROM scan_events
          WHERE id <> $1
            AND UPPER(raw_json->>'pubkey_hex') = ANY($2::text[])
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [scan.id, keys]
        );

        lastCounter = cRes.rows[0]
          ? {
              counter: cRes.rows[0].counter ?? null,
              created_at: cRes.rows[0].created_at ?? null
            }
          : null;
      }

      if (lastCounter === null && scan.uuid) {
        const cRes = await query(
          `
          SELECT counter, created_at
          FROM scan_events
          WHERE uuid = $1
            AND id <> $2
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [scan.uuid, scan.id]
        );

        lastCounter = cRes.rows[0]
          ? {
              counter: cRes.rows[0].counter ?? null,
              created_at: cRes.rows[0].created_at ?? null
            }
          : null;
      }
    }

    // 6) Build scan event for fusion brain
    let scanEventForFusion = null;

    if (scan) {
      const has_identity = !!observedPubkeyHex;

      let scanner_result = (scan.result || "").toUpperCase().trim();
      const sig_valid = asBool(scan.sig_valid, false);
      const chal_valid = asBool(scan.chal_valid, false);
      const tamper_flag = asBool(scan.tamper_flag, false);

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

      let cloud_verdict = "UUID_MISSING";

      if (!has_identity) {
        cloud_verdict = registryVehicle ? "UUID_MISSING" : "UNREGISTERED_VEHICLE";
      } else if (!registryVehicle) {
        cloud_verdict = "UNREGISTERED_IDENTITY";
      } else {
        const assignedPlate = normPlate(registryVehicle.plate);
        const observedPlate = normPlate(scan.plate);

        if (observedPlate && assignedPlate && observedPlate !== assignedPlate) {
          cloud_verdict = "MISMATCH";
        } else if (scanner_result === "REPLAY_SUSPECT") {
          cloud_verdict = "REPLAY_SUSPECT";
        } else if (scanner_result === "INVALID_TAG") {
          cloud_verdict = "INVALID_TAG";
        } else if (scanner_result === "CLONE_SUSPECT") {
          cloud_verdict = "KEY_MISMATCH";
        } else if (scanner_result === "RELAY_SUSPECT") {
          cloud_verdict = "RELAY_SUSPECT";
        } else if (scanner_result === "TAMPERED") {
          cloud_verdict = "TAMPERED";
        } else {
          cloud_verdict = "AUTHENTIC";
        }
      }

      scanEventForFusion = {
        plate: scan.plate || null,
        uuid: scan.uuid || null,
        counter: scan.counter ?? null,
        sig_valid,
        chal_valid,
        pubkey_match: null,
        tamper: tamper_flag,
        rssi: scan.rssi ?? null,
        est_distance_m: scan.est_distance_m ?? null,
        cloud_verdict,
        scanner_result,
        has_identity,
        created_at: scan.created_at
      };
    }

    // 7) Use the ONE true fusion brain
    const fusion = decideFusion({
      registryVehicle,
      scanEvent: scanEventForFusion,
      anprEvent: anpr,
      aiEvent: ai,
      lastCounter,
      allowMissingDecision: true
    });

    // 8) Store final fusion result
    await query(
      `
      INSERT INTO fusion_events (
        plate,
        scan_event_id,
        anpr_id,
        ai_id,
        fusion_verdict,
        final_label,
        visual_confidence,
        has_gotid,
        registry_status,
        reasons,
        raw_json,
        created_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
      `,
      [
        fusion.plate,
        scan?.id ?? null,
        anpr.id,
        ai?.id ?? null,
        fusion.fusion_verdict,
        fusion.final_label,
        fusion.visual_confidence,
        fusion.has_gotid,
        fusion.registry_status,
        fusion.reasons,
        fusion
      ]
    );

    // 9) Mark job complete
    await query(
      `UPDATE fusion_jobs SET status='DONE', processed_at=NOW() WHERE id=$1`,
      [id]
    );

    console.log(`✅ Job ${id} complete → ${fusion.final_label}`);
  } catch (err) {
    console.error(`❌ Job ${id} failed:`, err);
    await failJob(id, err.message);
  }
}

async function failJob(id, error) {
  await query(
    `
    UPDATE fusion_jobs
    SET status='FAILED',
        attempts = attempts + 1,
        last_error = $2
    WHERE id=$1
    `,
    [id, error]
  );
}

// Run once immediately, then repeat
processJobs();
setInterval(processJobs, LOOP_INTERVAL_MS);
