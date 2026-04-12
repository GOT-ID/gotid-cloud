import { query } from "../db/index.js";
import { decideFusion } from "../fusion.js";

const SIGN_WINDOW_SEC = 20;
const LOOP_INTERVAL_MS = 1000;

// Pass/session timing
const PASS_OPEN_WINDOW_SEC = 45;       // same plate within this window = same pass
const PASS_IDLE_FINALISE_SEC = 8;     // if no new ANPR for this long, pass can finalise
const MATCH_STABILISE_SEC = 5;         // valid match can finalise early after stabilising
const SUSPICION_STABILISE_SEC = 8;     // replay/relay/invalid/tamper stabilisation
const MISSING_OBSERVATION_SEC = 5;     // must wait this long before UUID_MISSING finalises

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

function toMs(ts) {
  if (!ts) return null;
  const t = new Date(ts).getTime();
  return Number.isFinite(t) ? t : null;
}

function ageSec(fromTs, toTs = new Date()) {
  const a = toMs(fromTs);
  const b = toMs(toTs);
  if (a === null || b === null) return null;
  return Math.max(0, Math.round((b - a) / 1000));
}

function isStrongSuspicion(v) {
  return [
    "MISMATCH",
    "MISMATCH_PUBKEY",
    "INVALID_TAG",
    "RELAY_SUSPECT",
    "REPLAY_SUSPECT",
    "COUNTER_ROLLBACK",
    "TAMPER"
  ].includes(v);
}

function isStrongMatch(scanEvent) {
  if (!scanEvent) return false;

  return (
    scanEvent.has_identity === true &&
    scanEvent.sig_valid === true &&
    scanEvent.chal_valid === true &&
    scanEvent.pubkey_match === true &&
    scanEvent.tamper !== true &&
    scanEvent.scanner_result !== "REPLAY_SUSPECT" &&
    scanEvent.scanner_result !== "INVALID_TAG" &&
    scanEvent.scanner_result !== "RELAY_SUSPECT" &&
    scanEvent.scanner_result !== "TAMPERED" &&
    scanEvent.cloud_verdict !== "MISMATCH" &&
    scanEvent.cloud_verdict !== "KEY_MISMATCH" &&
    scanEvent.cloud_verdict !== "REPLAY_SUSPECT" &&
    scanEvent.cloud_verdict !== "INVALID_TAG" &&
    scanEvent.cloud_verdict !== "RELAY_SUSPECT" &&
    scanEvent.cloud_verdict !== "TAMPERED"
  );
}

function bestOf(existing, incoming) {
  const rank = {
    MISMATCH_PUBKEY: 100,
    MISMATCH: 95,
    INVALID_TAG: 90,
    RELAY_SUSPECT: 85,
    REPLAY_SUSPECT: 80,
    COUNTER_ROLLBACK: 80,
    TAMPER: 75,
    MATCH: 60,
    UUID_MISSING: 30,
    NOT_ENROLLED: 20,
    UNKNOWN_TAG: 18,
    PENDING: 5,
    UNKNOWN: 0,
    null: -1
  };

  const a = existing || null;
  const b = incoming || null;
  return (rank[b] ?? -1) > (rank[a] ?? -1) ? b : a;
}

function deriveScannerResult(scan) {
  let scanner_result = (scan?.result || "").toUpperCase().trim();
  const sig_valid = asBool(scan?.sig_valid, false);
  const chal_valid = asBool(scan?.chal_valid, false);
  const tamper_flag = asBool(scan?.tamper_flag, false);

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

  return scanner_result;
}

function derivePubkeyMatch({ observedPubkeyHex, registryVehicle }) {
  if (!observedPubkeyHex) return null;
  if (!registryVehicle) return false;

  const regPubkey = normHex(registryVehicle.public_key || "");
  if (!regPubkey) return false;

  const candidates = pubkeyCandidates(observedPubkeyHex);
  return candidates.includes(regPubkey);
}

function buildCloudVerdict({
  has_identity,
  registryVehicle,
  scan,
  scanner_result
}) {
  if (!has_identity) {
    return registryVehicle ? null : "UNREGISTERED_VEHICLE";
  }

  if (!registryVehicle) {
    return "UNREGISTERED_IDENTITY";
  }

  const assignedPlate = normPlate(registryVehicle.plate);
  const observedPlate = normPlate(scan?.plate);

  if (observedPlate && assignedPlate && observedPlate !== assignedPlate) {
    return "MISMATCH";
  } else if (scanner_result === "REPLAY_SUSPECT") {
    return "REPLAY_SUSPECT";
  } else if (scanner_result === "INVALID_TAG") {
    return "INVALID_TAG";
  } else if (scanner_result === "CLONE_SUSPECT") {
    return "KEY_MISMATCH";
  } else if (scanner_result === "RELAY_SUSPECT") {
    return "RELAY_SUSPECT";
  } else if (scanner_result === "TAMPERED") {
    return "TAMPERED";
  } else if (scanner_result === "MATCH") {
    return "AUTHENTIC";
  }

  return null;
}

function buildScanEventForFusion(scan, registryVehicle) {
  if (!scan) return null;

  const observedPubkeyHex = normHex(scan.raw_json?.pubkey_hex || "");
  const sig_valid = asBool(scan.sig_valid, false);
  const chal_valid = asBool(scan.chal_valid, false);
  const tamper_flag = asBool(scan.tamper_flag, false);
  const scanner_result = deriveScannerResult(scan);
  const has_identity = !!observedPubkeyHex && sig_valid === true;
  const pubkey_match = derivePubkeyMatch({ observedPubkeyHex, registryVehicle });
  const cloud_verdict = buildCloudVerdict({
    has_identity,
    registryVehicle,
    scan,
    scanner_result
  });

  return {
    id: scan.id,
    plate: scan.plate || null,
    uuid: scan.uuid || null,
    counter: scan.counter ?? null,
    sig_valid,
    chal_valid,
    pubkey_match,
    tamper: tamper_flag,
    rssi: scan.rssi ?? null,
    est_distance_m: scan.est_distance_m ?? null,
    cloud_verdict,
    scanner_result,
    has_identity,
    created_at: scan.created_at
  };
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

    await finaliseMatureOpenPasses();
  } catch (err) {
    console.error("❌ Worker loop error:", err);
  }
}

async function processSingleJob(job) {
  const { id, anpr_id } = job;

  try {
    console.log(`🔍 Processing ANPR job ${anpr_id}`);

    const anprRes = await query(
      `SELECT * FROM anpr_events WHERE id = $1 LIMIT 1`,
      [anpr_id]
    );

    if (!anprRes.rows.length) {
      await failJob(id, "ANPR event missing");
      return;
    }

    const anpr = anprRes.rows[0];
    const plate = normPlate(anpr.plate);

    const scanRes = await query(
      `
      SELECT *
      FROM scan_events
      WHERE plate = $1
        AND created_at BETWEEN $2::timestamptz
                          AND ($2::timestamptz + ($3 * INTERVAL '1 second'))
      ORDER BY created_at ASC
      LIMIT 1
      `,
      [plate, anpr.ts, SIGN_WINDOW_SEC]
    );

    const scan = scanRes.rows[0] || null;

    const aiRes = await query(
      `
      SELECT *
      FROM ai_events
      WHERE ts BETWEEN ($1::timestamptz - INTERVAL '10 seconds')
                   AND ($1::timestamptz + INTERVAL '10 seconds')
        AND (
          plate = $2
          OR plate IS NULL
          OR plate = ''
        )
      ORDER BY
        CASE WHEN plate = $2 THEN 0 ELSE 1 END,
        ABS(EXTRACT(EPOCH FROM (ts - $1::timestamptz))) ASC
      LIMIT 1
      `,
      [anpr.ts, plate]
    );

    const ai = aiRes.rows[0] || null;

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
        [plate]
      );
      registryVehicle = regRes.rows[0] || null;
    }

    let lastCounter = null;

    if (scan) {
      if (keys.length) {
        const cRes = await query(
          `
          SELECT counter, created_at
          FROM scan_events
          WHERE id <> $1
            AND created_at < $3::timestamptz
            AND UPPER(raw_json->>'pubkey_hex') = ANY($2::text[])
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [scan.id, keys, scan.created_at]
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
            AND created_at < $3::timestamptz
          ORDER BY created_at DESC
          LIMIT 1
          `,
          [scan.uuid, scan.id, scan.created_at]
        );

        lastCounter = cRes.rows[0]
          ? {
              counter: cRes.rows[0].counter ?? null,
              created_at: cRes.rows[0].created_at ?? null
            }
          : null;
      }
    }

    const scanEventForFusion = buildScanEventForFusion(scan, registryVehicle);

    const pass = await getOrCreateOpenPass({
      plate,
      anpr,
      ai,
      scan,
      registryVehicle
    });

    const provisional = decideFusion({
      registryVehicle,
      scanEvent: scanEventForFusion,
      anprEvent: anpr,
      aiEvent: ai,
      lastCounter,
      allowMissingDecision: false
    });

    await updatePassWithEvidence({
      pass,
      anpr,
      ai,
      scan,
      registryVehicle,
      provisional
    });

    let finalised = null;

    if (isStrongMatch(scanEventForFusion) && provisional.fusion_verdict === "MATCH") {
      finalised = await tryFinalisePass({
        passId: pass.id,
        latestAnpr: anpr,
        latestAi: ai,
        latestScan: scan,
        registryVehicle,
        scanEventForFusion,
        provisional: {
          fusion_verdict: "MATCH",
          visual_confidence: provisional.visual_confidence || "NONE",
          reasons: Array.isArray(provisional.reasons) ? provisional.reasons : []
        }
      });
    }

    await query(
      `UPDATE fusion_jobs SET status='DONE', processed_at=NOW() WHERE id=$1`,
      [id]
    );

    if (finalised) {
      console.log(`✅ Job ${id} complete → ${finalised.final_label}`);
    } else {
      console.log(`⏳ Job ${id} absorbed into open pass for ${plate}`);
    }
  } catch (err) {
    console.error(`❌ Job ${id} failed:`, err);
    await failJob(id, err.message);
  }
}

async function getOrCreateOpenPass({ plate, anpr, ai, scan, registryVehicle }) {
  const openRes = await query(
    `
    SELECT *
    FROM fusion_passes
    WHERE plate = $1
      AND pass_status = 'OPEN'
      AND last_seen_at >= ($2::timestamptz - ($3 * INTERVAL '1 second'))
    ORDER BY last_seen_at DESC
    LIMIT 1
    `,
    [plate, anpr.ts, PASS_OPEN_WINDOW_SEC]
  );

  if (openRes.rows.length) {
    return openRes.rows[0];
  }

  const insertRes = await query(
    `
    INSERT INTO fusion_passes (
      plate,
      camera_id,
      lane_id,
      registry_vehicle_id,
      has_gotid_expected,
      registry_status,
      first_seen_at,
      last_seen_at,
      pass_status,
      best_scan_event_id,
      best_anpr_event_id,
      best_ai_event_id,
      created_at,
      updated_at
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'OPEN',$9,$10,$11,NOW(),NOW())
    RETURNING *
    `,
    [
      plate,
      anpr.camera_id || anpr.source_id || null,
      anpr.lane_id || null,
      registryVehicle?.id ?? null,
      registryVehicle ? (registryVehicle.has_gotid === true) : false,
      registryVehicle?.status || "unknown",
      anpr.ts,
      anpr.ts,
      scan?.id ?? null,
      anpr.id,
      ai?.id ?? null
    ]
  );

  return insertRes.rows[0];
}

async function updatePassWithEvidence({ pass, anpr, ai, scan, registryVehicle, provisional }) {
  const current = await query(
    `SELECT * FROM fusion_passes WHERE id = $1 LIMIT 1`,
    [pass.id]
  );
  const p = current.rows[0];

  const bestFusionVerdict = bestOf(p.final_fusion_verdict, provisional.fusion_verdict);

  const bestScanEventId = scan?.id ?? p.best_scan_event_id;
  const bestAnprEventId = anpr?.id ?? p.best_anpr_event_id;
  const bestAiEventId = ai?.id ?? p.best_ai_event_id;

  const strongestCryptoState = bestOf(
    p.strongest_crypto_state,
    provisional.fusion_verdict === "MATCH"
      ? "MATCH"
      : isStrongSuspicion(provisional.fusion_verdict)
        ? provisional.fusion_verdict
        : null
  );

  const strongestCounterState =
    provisional.fusion_verdict === "COUNTER_ROLLBACK" ||
    provisional.fusion_verdict === "REPLAY_SUSPECT"
      ? provisional.fusion_verdict
      : p.strongest_counter_state;

  const strongestVisualState =
    provisional.visual_confidence || p.strongest_visual_state;

  const mergedReasons = Array.from(
    new Set([
      ...(Array.isArray(p.reasons) ? p.reasons : []),
      ...(Array.isArray(provisional.reasons) ? provisional.reasons : [])
    ])
  );

  const rawSummary = {
    latest_anpr_id: anpr?.id ?? null,
    latest_ai_id: ai?.id ?? null,
    latest_scan_id: scan?.id ?? null,
    registry_vehicle_id: registryVehicle?.id ?? null
  };

  await query(
    `
    UPDATE fusion_passes
    SET
      last_seen_at = GREATEST(last_seen_at, $2::timestamptz),
      registry_vehicle_id = COALESCE($3, registry_vehicle_id),
      has_gotid_expected = COALESCE($4, has_gotid_expected),
      registry_status = COALESCE($5, registry_status),
      best_scan_event_id = COALESCE($6, best_scan_event_id),
      best_anpr_event_id = COALESCE($7, best_anpr_event_id),
      best_ai_event_id = COALESCE($8, best_ai_event_id),
      final_fusion_verdict = $9,
      visual_confidence = COALESCE($10, visual_confidence),
      reasons = $11::jsonb,
      strongest_crypto_state = COALESCE($12, strongest_crypto_state),
      strongest_counter_state = COALESCE($13, strongest_counter_state),
      strongest_visual_state = COALESCE($14, strongest_visual_state),
      raw_summary = $15::jsonb,
      updated_at = NOW()
    WHERE id = $1
    `,
    [
      p.id,
      anpr.ts,
      registryVehicle?.id ?? null,
      registryVehicle ? (registryVehicle.has_gotid === true) : null,
      registryVehicle?.status || null,
      bestScanEventId,
      bestAnprEventId,
      bestAiEventId,
      bestFusionVerdict,
      provisional.visual_confidence || null,
      JSON.stringify(mergedReasons),
      strongestCryptoState,
      strongestCounterState,
      strongestVisualState,
      JSON.stringify(rawSummary)
    ]
  );
}

async function tryFinalisePass({
  passId,
  latestAnpr,
  latestAi,
  latestScan,
  registryVehicle,
  scanEventForFusion,
  provisional
}) {
  const res = await query(`SELECT * FROM fusion_passes WHERE id = $1 LIMIT 1`, [passId]);
  const pass = res.rows[0];
  if (!pass || pass.pass_status !== "OPEN") return null;

  const now = new Date();
  const passAge = ageSec(pass.first_seen_at, now);
  const idleAge = ageSec(pass.last_seen_at, now);

  const strongest = pass.final_fusion_verdict || provisional.fusion_verdict || "PENDING";
  const hasValidMatch = strongest === "MATCH";
  const hasStrongSuspicion = isStrongSuspicion(strongest);
  const isMissingCandidate =
    (strongest === "PENDING" || strongest === "UUID_MISSING" || !strongest) &&
    pass.has_gotid_expected === true;

  let finalFusion = null;

  const canEarlyMatch =
    hasValidMatch &&
    scanEventForFusion &&
    isStrongMatch(scanEventForFusion);

  if (
    (canEarlyMatch && passAge !== null && passAge >= 1) ||
    (hasValidMatch && passAge !== null && passAge >= MATCH_STABILISE_SEC)
  ) {
    finalFusion = decideFusion({
      registryVehicle,
      scanEvent: scanEventForFusion,
      anprEvent: latestAnpr,
      aiEvent: latestAi,
      lastCounter: null,
      allowMissingDecision: false
    });
  } else if (
    hasStrongSuspicion &&
    passAge !== null &&
    passAge >= SUSPICION_STABILISE_SEC &&
    idleAge !== null &&
    idleAge >= PASS_IDLE_FINALISE_SEC
  ) {
    finalFusion = {
      fusion_verdict: strongest,
      final_label: strongest,
      visual_confidence: pass.visual_confidence || "NONE",
      reasons: Array.isArray(pass.reasons) ? pass.reasons : [],
      plate: pass.plate,
      has_gotid: pass.has_gotid_expected,
      registry_status: pass.registry_status
    };
  } else if (
    isMissingCandidate &&
    passAge !== null &&
    passAge >= MISSING_OBSERVATION_SEC &&
    idleAge !== null &&
    idleAge >= PASS_IDLE_FINALISE_SEC
  ) {
    finalFusion = decideFusion({
      registryVehicle,
      scanEvent: null,
      anprEvent: latestAnpr,
      aiEvent: latestAi,
      lastCounter: null,
      allowMissingDecision: true
    });
  } else if (
    idleAge !== null &&
    idleAge >= PASS_IDLE_FINALISE_SEC &&
    !pass.has_gotid_expected
  ) {
    finalFusion = decideFusion({
      registryVehicle,
      scanEvent: scanEventForFusion,
      anprEvent: latestAnpr,
      aiEvent: latestAi,
      lastCounter: null,
      allowMissingDecision: false
    });
  }

  if (!finalFusion) return null;

  if (
    finalFusion.fusion_verdict === "COUNTER_ROLLBACK" ||
    finalFusion.fusion_verdict === "REPLAY_SUSPECT"
  ) {
    finalFusion.final_label = "REPLAY_SUSPECT";
  } else if (
    finalFusion.fusion_verdict === "MISMATCH" ||
    finalFusion.fusion_verdict === "MISMATCH_PUBKEY"
  ) {
    finalFusion.final_label = "CLONE_SUSPECT";
  } else if (finalFusion.fusion_verdict === "INVALID_TAG") {
    finalFusion.final_label = "INVALID_TAG";
  } else if (finalFusion.fusion_verdict === "RELAY_SUSPECT") {
    finalFusion.final_label = "RELAY_SUSPECT";
  } else if (finalFusion.fusion_verdict === "TAMPER") {
    finalFusion.final_label =
      pass.visual_confidence === "STRONG" || pass.visual_confidence === "MEDIUM"
        ? "TAMPER_STRONG"
        : "TAMPER_WEAK";
  } else if (finalFusion.fusion_verdict === "NOT_ENROLLED") {
    finalFusion.final_label = "NOT_ENROLLED";
  } else if (finalFusion.fusion_verdict === "UNKNOWN_TAG") {
    finalFusion.final_label = "UNREGISTERED_IDENTITY";
  }

  // Police-grade alert suppression:
  // same plate + same final label within 30s = same continuing incident
  const recentRes = await query(
    `
    SELECT 1
    FROM fusion_events
    WHERE plate = $1
      AND final_label = $2
      AND created_at > NOW() - INTERVAL '30 seconds'
    LIMIT 1
    `,
    [pass.plate, finalFusion.final_label]
  );

  if (recentRes.rows.length) {
    console.log(`🔕 Suppressed duplicate alert for ${pass.plate} (${finalFusion.final_label})`);
  } else {
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
        pass.plate,
        pass.best_scan_event_id ?? null,
        pass.best_anpr_event_id ?? null,
        pass.best_ai_event_id ?? null,
        finalFusion.fusion_verdict,
        finalFusion.final_label,
        finalFusion.visual_confidence || pass.visual_confidence || "NONE",
        pass.has_gotid_expected,
        pass.registry_status,
        finalFusion.reasons || pass.reasons || [],
        finalFusion
      ]
    );
  }

  await query(
    `
    UPDATE fusion_passes
    SET
      pass_status = 'FINALISED',
      finalised_at = NOW(),
      final_fusion_verdict = $2,
      final_label = $3,
      visual_confidence = COALESCE($4, visual_confidence),
      reasons = $5::jsonb,
      updated_at = NOW()
    WHERE id = $1
    `,
    [
      pass.id,
      finalFusion.fusion_verdict,
      finalFusion.final_label,
      finalFusion.visual_confidence || pass.visual_confidence || "NONE",
      JSON.stringify(finalFusion.reasons || pass.reasons || [])
    ]
  );

  return finalFusion;
}

async function finaliseMatureOpenPasses() {
  const openRes = await query(
    `
    SELECT *
    FROM fusion_passes
    WHERE pass_status = 'OPEN'
      AND last_seen_at <= (NOW() - ($1 * INTERVAL '1 second'))
    ORDER BY last_seen_at ASC
    LIMIT 20
    `,
    [PASS_IDLE_FINALISE_SEC]
  );

  for (const pass of openRes.rows) {
    try {
      const anprRes = pass.best_anpr_event_id
        ? await query(`SELECT * FROM anpr_events WHERE id = $1 LIMIT 1`, [pass.best_anpr_event_id])
        : { rows: [] };

      const aiRes = pass.best_ai_event_id
        ? await query(`SELECT * FROM ai_events WHERE id = $1 LIMIT 1`, [pass.best_ai_event_id])
        : { rows: [] };

      const scanRes = pass.best_scan_event_id
        ? await query(`SELECT * FROM scan_events WHERE id = $1 LIMIT 1`, [pass.best_scan_event_id])
        : { rows: [] };

      const regRes = pass.registry_vehicle_id
        ? await query(`SELECT * FROM vehicles WHERE id = $1 LIMIT 1`, [pass.registry_vehicle_id])
        : { rows: [] };

      const scan = scanRes.rows[0] || null;
      const anpr = anprRes.rows[0] || null;
      const ai = aiRes.rows[0] || null;
      const registryVehicle = regRes.rows[0] || null;

      const scanEventForFusion = buildScanEventForFusion(scan, registryVehicle);

      await tryFinalisePass({
        passId: pass.id,
        latestAnpr: anpr,
        latestAi: ai,
        latestScan: scan,
        registryVehicle,
        scanEventForFusion,
        provisional: {
          fusion_verdict: pass.final_fusion_verdict || "PENDING",
          visual_confidence: pass.visual_confidence || "NONE",
          reasons: Array.isArray(pass.reasons) ? pass.reasons : []
        }
      });
    } catch (err) {
      console.error(`❌ Failed to finalise pass ${pass.id}:`, err);
    }
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

processJobs();
setInterval(processJobs, LOOP_INTERVAL_MS);
