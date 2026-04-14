import { query } from "../db/index.js";
import { decideFusion } from "../fusion.js";

const SIGN_WINDOW_SEC = 10;
const LOOP_INTERVAL_MS = 1000;

// Pass/session timing
const PASS_OPEN_WINDOW_SEC = 45;
const PASS_IDLE_FINALISE_SEC = 8;
const MATCH_STABILISE_SEC = 5;
const SUSPICION_STABILISE_SEC = 8;
const MISSING_OBSERVATION_SEC = 5;

console.log("🚔 GOT-ID Fusion Worker Started...");
console.log("🚨 WORKER VERSION: encounter-classifier + evidence-policy build loaded");

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
    NO_SCANNER_EVIDENCE: 25,
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
  } else if (scanner_result === "MATCH" || scanner_result === "AUTHENTIC") {
    return "MATCH";
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
    created_at: scan.created_at,
    scanner_id: scan.scanner_id || null
  };
}

function extractTrackAgeSeconds(ev) {
  const candidates = [
    ev?.raw_json?.raw_json?.track_age_s,
    ev?.raw_json?.track_age_s
  ];

  for (const c of candidates) {
    const n = Number(c);
    if (Number.isFinite(n)) return n;
  }

  return null;
}

function extractFramesSeen(ev) {
  const candidates = [
    ev?.raw_json?.raw_json?.frames_seen,
    ev?.raw_json?.frames_seen
  ];

  for (const c of candidates) {
    const n = Number(c);
    if (Number.isFinite(n)) return n;
  }

  return null;
}

function scannerResultFromWindow(row) {
  const s = row?.raw_json?.scanner_result;
  return typeof s === "string" ? s.toUpperCase().trim() : "";
}

function hasScannerCoverage(row) {
  if (!row) return false;

  return (
    Number(row.ble_packets_seen || 0) > 0 ||
    Number(row.ble_devices_seen || 0) > 0 ||
    Number(row.companyid_hits_seen || 0) > 0 ||
    Number(row.gotid_candidates_seen || 0) > 0 ||
    row.strongest_rssi !== null
  );
}

function windowShowsIdentity(row) {
  if (!row) return false;

  return (
    row.valid_uuid_seen === true ||
    row.valid_sig_seen === true ||
    row.valid_chal_seen === true ||
    row.pk_match_seen === true
  );
}

function windowShowsRelay(row) {
  if (!row) return false;

  const scannerResult = scannerResultFromWindow(row);

  return (
    scannerResult === "RELAY_SUSPECT" ||
    (
      row.valid_uuid_seen === true &&
      row.valid_sig_seen === true &&
      row.valid_chal_seen === false
    )
  );
}

function isCleanAbsenceWindow(row) {
  if (!row) return false;
  if (!hasScannerCoverage(row)) return false;
  if (windowShowsIdentity(row)) return false;
  if (windowShowsRelay(row)) return false;
  return true;
}

async function getEncounterWindows({ plate, anchorTs }) {
  const p = normPlate(plate);
  if (!p || !anchorTs) return [];

  const res = await query(
    `
    SELECT *
    FROM scanner_window_events
    WHERE plate = $1
      AND created_at BETWEEN ($2::timestamptz - INTERVAL '20 seconds')
                         AND ($2::timestamptz + INTERVAL '20 seconds')
    ORDER BY created_at ASC
    `,
    [p, anchorTs]
  );

  return res.rows;
}

async function getEncounterScans({ plate, anchorTs }) {
  const p = normPlate(plate);
  if (!p || !anchorTs) return [];

  const res = await query(
    `
    SELECT *
    FROM scan_events
    WHERE plate = $1
      AND created_at BETWEEN ($2::timestamptz - INTERVAL '20 seconds')
                         AND ($2::timestamptz + INTERVAL '20 seconds')
    ORDER BY created_at ASC
    `,
    [p, anchorTs]
  );

  return res.rows;
}

function classifyEncounterProfile({ anprEvent, aiEvent }) {
  const trackAge = Math.max(
    Number.isFinite(extractTrackAgeSeconds(anprEvent)) ? extractTrackAgeSeconds(anprEvent) : -1,
    Number.isFinite(extractTrackAgeSeconds(aiEvent)) ? extractTrackAgeSeconds(aiEvent) : -1
  );

  const framesSeen = Math.max(
    Number.isFinite(extractFramesSeen(anprEvent)) ? extractFramesSeen(anprEvent) : -1,
    Number.isFinite(extractFramesSeen(aiEvent)) ? extractFramesSeen(aiEvent) : -1
  );

  if (
    (Number.isFinite(trackAge) && trackAge >= 10) ||
    (Number.isFinite(framesSeen) && framesSeen >= 10)
  ) {
    return "SUSTAINED";
  }

  return "BRIEF";
}

function buildFallbackWindowForFusion(row, consecutiveCleanAbsenceWindows = 0) {
  if (!row) return null;

  return {
    id: row.id,
    plate: row.plate || null,
    camera_id: row.camera_id || null,
    scanner_id: row.scanner_id || null,
    window_start: row.window_start || null,
    window_end: row.window_end || null,
    ble_packets_seen: Number(row.ble_packets_seen || 0),
    ble_devices_seen: Number(row.ble_devices_seen || 0),
    companyid_hits_seen: Number(row.companyid_hits_seen || 0),
    gotid_candidates_seen: Number(row.gotid_candidates_seen || 0),
    strongest_rssi: row.strongest_rssi ?? null,
    nearest_est_distance_m: row.nearest_est_distance_m ?? null,
    valid_uuid_seen: row.valid_uuid_seen === true,
    valid_sig_seen: row.valid_sig_seen === true,
    valid_chal_seen: row.valid_chal_seen === true,
    pk_match_seen: row.pk_match_seen === true,
    consecutive_missing_windows: consecutiveCleanAbsenceWindows
  };
}

function summariseEncounter({
  windows,
  scans,
  anprEvent,
  aiEvent
}) {
  const encounterProfile = classifyEncounterProfile({ anprEvent, aiEvent });

  const scannerCoveragePresent = windows.some(hasScannerCoverage);

  const identitySeenInWindows = windows.some(windowShowsIdentity);
  const relaySeenInWindows = windows.some(windowShowsRelay);

  const identitySeenInScans = scans.some((s) => {
    const sig = asBool(s.sig_valid, false);
    const pub = normHex(s.raw_json?.pubkey_hex || "");
    return sig === true && !!pub;
  });

  const validMatchSeenInScans = scans.some((s) => {
    return asBool(s.sig_valid, false) === true && asBool(s.chal_valid, false) === true;
  });

  const relaySeenInScans = scans.some((s) => {
    return asBool(s.sig_valid, false) === true && asBool(s.chal_valid, false) === false;
  });

  let consecutiveCleanAbsenceWindows = 0;
  let contaminatedWindows = 0;
  let latestRelevantWindow = windows.length ? windows[windows.length - 1] : null;
  let latestCleanAbsenceWindow = null;

  for (let i = windows.length - 1; i >= 0; i--) {
    const row = windows[i];

    if (isCleanAbsenceWindow(row)) {
      consecutiveCleanAbsenceWindows += 1;
      if (!latestCleanAbsenceWindow) {
        latestCleanAbsenceWindow = row;
      }
    } else {
      if (hasScannerCoverage(row)) contaminatedWindows += 1;
      break;
    }
  }

  if (!latestRelevantWindow && latestCleanAbsenceWindow) {
    latestRelevantWindow = latestCleanAbsenceWindow;
  }

  return {
    encounter_profile: encounterProfile,
    scanner_coverage_present: scannerCoveragePresent,
    identity_present_any:
      identitySeenInWindows || identitySeenInScans,
    valid_match_present_any: validMatchSeenInScans,
    relay_present_any:
      relaySeenInWindows || relaySeenInScans,
    consecutive_clean_absence_windows: consecutiveCleanAbsenceWindows,
    contaminated_windows: contaminatedWindows,
    window_count: windows.length,
    scan_count: scans.length,
    latest_relevant_window: latestRelevantWindow,
    latest_clean_absence_window: latestCleanAbsenceWindow
  };
}

function shouldCreateEvidenceWindow(decisionType) {
  return [
    "UUID_MISSING",
    "NO_SCANNER_EVIDENCE",
    "NOT_ENROLLED",
    "REPLAY_SUSPECT",
    "COUNTER_ROLLBACK",
    "INVALID_TAG",
    "RELAY_SUSPECT",
    "MISMATCH_PUBKEY",
    "MISMATCH",
    "TAMPER"
  ].includes(decisionType);
}

async function resolveEvidenceAnchors({ pass, latestAnpr }) {
  const plate = normPlate(pass?.plate);
  const anchorTs = latestAnpr?.ts || pass?.last_seen_at || pass?.first_seen_at || null;

  if (!plate || !anchorTs) {
    return {
      lastValidScan: null,
      firstReturnScan: null
    };
  }

  const lastValidRes = await query(
    `
    SELECT id, created_at
    FROM scan_events
    WHERE plate = $1
      AND sig_valid = true
      AND chal_valid = true
      AND COALESCE(tamper_flag, false) = false
      AND created_at < $2::timestamptz
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [plate, anchorTs]
  );

  const firstReturnRes = await query(
    `
    SELECT id, created_at
    FROM scan_events
    WHERE plate = $1
      AND sig_valid = true
      AND chal_valid = true
      AND COALESCE(tamper_flag, false) = false
      AND created_at > $2::timestamptz
    ORDER BY created_at ASC
    LIMIT 1
    `,
    [plate, anchorTs]
  );

  return {
    lastValidScan: lastValidRes.rows[0] || null,
    firstReturnScan: firstReturnRes.rows[0] || null
  };
}

async function createEvidenceWindow({
  fusionEventId,
  finalFusion,
  pass,
  latestAnpr,
  latestAi,
  latestScan
}) {
  try {
    if (!shouldCreateEvidenceWindow(finalFusion?.fusion_verdict)) return;
    if (!fusionEventId || !pass) return;

    const { lastValidScan, firstReturnScan } = await resolveEvidenceAnchors({
      pass,
      latestAnpr
    });

    const rawJson = {
      decision_basis: {
        summary: Array.isArray(finalFusion.reasons) && finalFusion.reasons.length
          ? finalFusion.reasons[0]
          : "Auto-generated evidence window",
        verdict: finalFusion.fusion_verdict
      },
      encounter_summary: finalFusion?.raw_json?.encounter_summary || null,
      window_summary: {
        window_start: pass.first_seen_at || null,
        window_end: pass.last_seen_at || null
      },
      scanner_health: {
        scanner_id: latestScan?.scanner_id || "SCN-001",
        scanner_active: true,
        uploader_active: true,
        worker_status: "DONE"
      },
      radio_environment: {
        ble_packets_seen: latestScan?.raw_json?.ble_packets_seen ?? null,
        ble_devices_seen: latestScan?.raw_json?.ble_devices_seen ?? null,
        companyid_hits_seen: latestScan?.raw_json?.companyid_hits_seen ?? null,
        gotid_candidates_seen: latestScan?.raw_json?.gotid_candidates_seen ?? null,
        strongest_rssi: latestScan?.rssi ?? latestScan?.raw_json?.rssi ?? null,
        nearest_est_distance_m: latestScan?.est_distance_m ?? latestScan?.raw_json?.est_distance_m ?? null
      },
      scanner_window_evidence: finalFusion?.raw_json?.fallback_scanner_window || null,
      transition: {
        last_valid_scan_id: lastValidScan?.id ?? null,
        last_valid_scan_ts: lastValidScan?.created_at ?? null,
        first_return_scan_id: firstReturnScan?.id ?? null,
        first_return_scan_ts: firstReturnScan?.created_at ?? null
      },
      linked_records: {
        fusion_event_id: fusionEventId,
        fusion_pass_id: pass.id,
        anpr_event_id: pass.best_anpr_event_id ?? null,
        scan_event_id: pass.best_scan_event_id ?? null,
        ai_event_id: pass.best_ai_event_id ?? null
      }
    };

    await query(
      `
      INSERT INTO evidence_windows (
        decision_type,
        plate,
        fusion_event_id,
        fusion_pass_id,
        anpr_event_id,
        scan_event_id,
        ai_event_id,
        window_start,
        window_end,
        has_gotid_expected,
        registry_status,
        scanner_id,
        camera_id,
        scanner_active,
        uploader_active,
        worker_status,
        strongest_rssi,
        nearest_est_distance_m,
        last_valid_scan_id,
        last_valid_scan_ts,
        first_return_scan_id,
        first_return_scan_ts,
        notes,
        raw_json
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24::jsonb
      )
      `,
      [
        finalFusion.fusion_verdict,
        pass.plate,
        fusionEventId,
        pass.id,
        pass.best_anpr_event_id ?? null,
        pass.best_scan_event_id ?? null,
        pass.best_ai_event_id ?? null,
        pass.first_seen_at ?? latestAnpr?.ts ?? null,
        pass.last_seen_at ?? latestAnpr?.ts ?? null,
        pass.has_gotid_expected,
        pass.registry_status,
        latestScan?.scanner_id || "SCN-001",
        latestAnpr?.camera_id || pass.camera_id || null,
        true,
        true,
        "DONE",
        latestScan?.rssi ?? null,
        latestScan?.est_distance_m ?? null,
        lastValidScan?.id ?? null,
        lastValidScan?.created_at ?? null,
        firstReturnScan?.id ?? null,
        firstReturnScan?.created_at ?? null,
        "AUTO evidence window generated by fusion worker.",
        JSON.stringify(rawJson)
      ]
    );
  } catch (err) {
    console.error("❌ Failed to create evidence window:", err);
  }
}

async function enrichOpenEvidenceWindows() {
  try {
    console.log("🧪 enrichment loop running");

    const pendingRes = await query(
      `
      SELECT *
      FROM evidence_windows
      WHERE decision_type IN ('UUID_MISSING', 'RELAY_SUSPECT')
        AND first_return_scan_id IS NULL
      ORDER BY created_at ASC
      LIMIT 20
      `
    );

    console.log(`🧪 evidence windows awaiting enrichment: ${pendingRes.rows.length}`);

    for (const ew of pendingRes.rows) {
      await enrichSingleEvidenceWindow(ew);
    }
  } catch (err) {
    console.error("❌ Evidence enrichment loop error:", err);
  }
}

async function enrichSingleEvidenceWindow(ew) {
  try {
    console.log(`🧪 checking evidence window ${ew.id}`);

    const plate = normPlate(ew?.plate);
    const anchorTs = ew?.window_end || ew?.created_at || null;

    if (!plate || !anchorTs) {
      console.log(`⏭️ skipping evidence window ${ew?.id} (missing plate or anchorTs)`);
      return;
    }

    const returnRes = await query(
      `
      SELECT id, created_at, rssi, est_distance_m, scanner_id
      FROM scan_events
      WHERE plate = $1
        AND sig_valid = true
        AND chal_valid = true
        AND COALESCE(tamper_flag, false) = false
        AND created_at > $2::timestamptz
      ORDER BY created_at ASC
      LIMIT 1
      `,
      [plate, anchorTs]
    );

    const firstReturn = returnRes.rows[0] || null;

    let gapSeconds = null;
    let returnClassification = null;
    let decisionConfidence = "MEDIUM";

    if (ew.last_valid_scan_ts && firstReturn?.created_at) {
      const last = new Date(ew.last_valid_scan_ts).getTime();
      const ret = new Date(firstReturn.created_at).getTime();

      if (Number.isFinite(last) && Number.isFinite(ret)) {
        gapSeconds = (ret - last) / 1000;

        if (gapSeconds < 10) {
          returnClassification = "NORMAL_RETURN";
        } else if (gapSeconds < 30) {
          returnClassification = "DELAYED_RETURN";
        } else {
          returnClassification = "SUSPICIOUS_RETURN";
        }
      }
    }

    if (
      ew.decision_type === "RELAY_SUSPECT" ||
      ew.decision_type === "REPLAY_SUSPECT" ||
      ew.decision_type === "INVALID_TAG"
    ) {
      decisionConfidence = "HIGH";
    } else if (ew.decision_type === "UUID_MISSING") {
      decisionConfidence = "MEDIUM";
    } else {
      decisionConfidence = "LOW";
    }

    if (!firstReturn) {
      console.log(`⏭️ no return scan found yet for evidence window ${ew.id}`);
      return;
    }

    console.log(`🧪 found return scan ${firstReturn.id} for evidence window ${ew.id}`);

    await query(
      `
      UPDATE evidence_windows
      SET
        first_return_scan_id = $2::bigint,
        first_return_scan_ts = $3::timestamptz,
        strongest_rssi = COALESCE(strongest_rssi, $4::integer),
        nearest_est_distance_m = COALESCE(nearest_est_distance_m, $5::numeric),
        scanner_id = COALESCE(scanner_id, $6::text),
        gap_seconds = COALESCE(gap_seconds, $7),
        return_classification = COALESCE(return_classification, $8),
        decision_confidence = COALESCE(decision_confidence, $9),
        raw_json = jsonb_set(
          jsonb_set(
            COALESCE(raw_json, '{}'::jsonb),
            '{transition}',
            COALESCE(raw_json->'transition', '{}'::jsonb) || jsonb_build_object(
              'first_return_scan_id', $2::bigint,
              'first_return_scan_ts', $3::timestamptz
            ),
            true
          ),
          '{scanner_health}',
          COALESCE(raw_json->'scanner_health', '{}'::jsonb) || jsonb_build_object(
            'scanner_id', COALESCE(scanner_id, $6::text)
          ),
          true
        )
      WHERE id = $1::bigint
        AND first_return_scan_id IS NULL
      `,
      [
        ew.id,
        firstReturn.id,
        firstReturn.created_at,
        firstReturn.rssi ?? null,
        firstReturn.est_distance_m ?? null,
        firstReturn.scanner_id || "SCN-001",
        gapSeconds,
        returnClassification,
        decisionConfidence
      ]
    );

    console.log(`🧾 Evidence window ${ew.id} enriched with return scan ${firstReturn.id}`);
  } catch (err) {
    console.error(`❌ Failed to enrich evidence window ${ew?.id}:`, err);
  }
}

async function buildEncounterPolicyContext({ plate, anchorTs, anprEvent, aiEvent }) {
  const windows = await getEncounterWindows({ plate, anchorTs });
  const scans = await getEncounterScans({ plate, anchorTs });

  return summariseEncounter({
    windows,
    scans,
    anprEvent,
    aiEvent
  });
}

function attachEncounterSummary(finalFusion, encounterSummary) {
  finalFusion.raw_json = {
    ...(finalFusion.raw_json || {}),
    encounter_summary: encounterSummary
  };
  return finalFusion;
}

function makePolicyVerdict({
  fusion_verdict,
  reasons,
  pass,
  encounterSummary
}) {
  return attachEncounterSummary({
    fusion_verdict,
    final_label: fusion_verdict,
    visual_confidence: pass.visual_confidence || "NONE",
    reasons,
    plate: pass.plate,
    has_gotid: pass.has_gotid_expected,
    registry_status: pass.registry_status,
    raw_json: {}
  }, encounterSummary);
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

    await enrichOpenEvidenceWindows();
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
        AND created_at BETWEEN ($2::timestamptz - ($3 * INTERVAL '1 second'))
                          AND ($2::timestamptz + ($3 * INTERVAL '1 second'))
      ORDER BY ABS(EXTRACT(EPOCH FROM (created_at - $2::timestamptz))) ASC,
               created_at ASC
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
    const encounterSummary = await buildEncounterPolicyContext({
      plate,
      anchorTs: anpr.ts,
      anprEvent: anpr,
      aiEvent: ai
    });

    const scannerWindowEvidence = encounterSummary.latest_relevant_window
      ? buildFallbackWindowForFusion(
          encounterSummary.latest_relevant_window,
          encounterSummary.consecutive_clean_absence_windows
        )
      : null;

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
      allowMissingDecision: false,
      scannerWindowEvidence
    });

    provisional.raw_json = {
      ...(provisional.raw_json || {}),
      encounter_summary: encounterSummary
    };

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
        encounterSummary,
        scannerWindowEvidence,
        provisional: {
          fusion_verdict: "MATCH",
          visual_confidence: provisional.visual_confidence || "NONE",
          reasons: Array.isArray(provisional.reasons) ? provisional.reasons : [],
          raw_json: {
            encounter_summary: encounterSummary
          }
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
      registryVehicle?.has_gotid === true,
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
    registry_vehicle_id: registryVehicle?.id ?? null,
    encounter_summary: provisional?.raw_json?.encounter_summary || null
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
  provisional,
  scannerWindowEvidence = null,
  encounterSummary = null
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
      allowMissingDecision: false,
      scannerWindowEvidence
    });
    attachEncounterSummary(finalFusion, encounterSummary);
  } else if (
    hasStrongSuspicion &&
    passAge !== null &&
    passAge >= SUSPICION_STABILISE_SEC &&
    idleAge !== null &&
    idleAge >= PASS_IDLE_FINALISE_SEC
  ) {
    finalFusion = makePolicyVerdict({
      fusion_verdict: strongest,
      reasons: Array.isArray(pass.reasons) ? pass.reasons : [],
      pass,
      encounterSummary
    });
  } else if (
    isMissingCandidate &&
    passAge !== null &&
    passAge >= MISSING_OBSERVATION_SEC &&
    idleAge !== null &&
    idleAge >= PASS_IDLE_FINALISE_SEC
  ) {
    if (encounterSummary?.identity_present_any === true) {
      if (encounterSummary?.relay_present_any === true) {
        finalFusion = makePolicyVerdict({
          fusion_verdict: "RELAY_SUSPECT",
          reasons: [
            "Identity was seen during the encounter and at least one relay-style failure occurred, so true missing cannot be claimed."
          ],
          pass,
          encounterSummary
        });
      } else {
        finalFusion = makePolicyVerdict({
          fusion_verdict: "NO_SCANNER_EVIDENCE",
          reasons: [
            "Identity was seen during the encounter, so true missing cannot be claimed from this encounter summary."
          ],
          pass,
          encounterSummary
        });
      }
    } else if (encounterSummary?.scanner_coverage_present !== true) {
      finalFusion = makePolicyVerdict({
        fusion_verdict: "NO_SCANNER_EVIDENCE",
        reasons: [
          "Scanner coverage was not proven strongly enough to support a missing-tag conclusion."
        ],
        pass,
        encounterSummary
      });
    } else {
      const fallbackScannerWindowEvidence =
        scannerWindowEvidence ||
        (encounterSummary?.latest_clean_absence_window
          ? buildFallbackWindowForFusion(
              encounterSummary.latest_clean_absence_window,
              encounterSummary.consecutive_clean_absence_windows
            )
          : null);

      finalFusion = decideFusion({
        registryVehicle,
        scanEvent: null,
        anprEvent: latestAnpr,
        aiEvent: latestAi,
        lastCounter: null,
        allowMissingDecision: true,
        scannerWindowEvidence: fallbackScannerWindowEvidence
      });

      attachEncounterSummary(finalFusion, encounterSummary);
    }
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
      allowMissingDecision: false,
      scannerWindowEvidence
    });
    attachEncounterSummary(finalFusion, encounterSummary);
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
  } else if (finalFusion.fusion_verdict === "NO_SCANNER_EVIDENCE") {
    finalFusion.final_label = "NO_SCANNER_EVIDENCE";
  }

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
    const fusionInsertRes = await query(
      `
      INSERT INTO fusion_events (
        plate,
        scan_event_id,
        anpr_event_id,
        ai_event_id,
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
      RETURNING id
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

    const fusionEventId = fusionInsertRes.rows[0]?.id ?? null;

    await createEvidenceWindow({
      fusionEventId,
      finalFusion,
      pass,
      latestAnpr,
      latestAi,
      latestScan
    });
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

      const encounterSummary = await buildEncounterPolicyContext({
        plate: pass.plate,
        anchorTs: anpr?.ts || pass.last_seen_at || pass.first_seen_at,
        anprEvent: anpr,
        aiEvent: ai
      });

      const scannerWindowEvidence = encounterSummary.latest_relevant_window
        ? buildFallbackWindowForFusion(
            encounterSummary.latest_relevant_window,
            encounterSummary.consecutive_clean_absence_windows
          )
        : null;

      await tryFinalisePass({
        passId: pass.id,
        latestAnpr: anpr,
        latestAi: ai,
        latestScan: scan,
        registryVehicle,
        scanEventForFusion,
        scannerWindowEvidence,
        encounterSummary,
        provisional: {
          fusion_verdict: pass.final_fusion_verdict || "PENDING",
          visual_confidence: pass.visual_confidence || "NONE",
          reasons: Array.isArray(pass.reasons) ? pass.reasons : [],
          raw_json: {
            encounter_summary: encounterSummary
          }
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
