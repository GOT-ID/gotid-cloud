// fusion.js
// GOT-ID fusion engine
// Police-grade principle:
// - Crypto is the truth.
// - Cameras support identity context, never override valid crypto.
// - Clean absence windows can prove UUID_MISSING.
// - If identity disappears and later returns, preserve that as a recovery-after-absence story.

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function toMs(ts) {
  if (!ts) return null;
  const t = new Date(ts).getTime();
  return Number.isFinite(t) ? t : null;
}

function boolish(v) {
  return v === true || v === "true" || v === 1 || v === "1";
}

function toInt(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function normStr(s) {
  return (s || "").toString().trim().toUpperCase();
}

function pushReason(arr, msg) {
  if (!Array.isArray(arr)) return;
  if (!arr.includes(msg)) arr.push(msg);
}

// confidence may be stored as a column OR inside raw_json.confidence
function getConfidence(ev) {
  if (!ev) return null;

  const c1 = num(ev.confidence);
  if (c1 !== null) return c1;

  const c2 = num(ev.raw_json?.confidence);
  if (c2 !== null) return c2;

  return null;
}

function getAiVehicleType(aiEvent) {
  return normStr(
    aiEvent?.vehicle_type ||
    aiEvent?.raw_json?.vehicle_type ||
    aiEvent?.raw_json?.yolo_class_name ||
    null
  );
}

function deriveRegistryVehicleType(registryVehicle) {
  const model = normStr(registryVehicle?.model);
  const make = normStr(registryVehicle?.make);
  const text = `${make} ${model}`.trim();

  if (!text) return "";

  if (
    text.includes("MOTORBIKE") ||
    text.includes("MOTORCYCLE") ||
    text.includes("BIKE")
  ) return "MOTORCYCLE";

  if (
    text.includes("TRUCK") ||
    text.includes("HGV") ||
    text.includes("LORRY")
  ) return "TRUCK";

  if (text.includes("BUS") || text.includes("COACH")) return "BUS";

  if (text.includes("VAN") || text.includes("TRANSIT")) return "VAN";

  if (
    text.includes("HATCHBACK") ||
    text.includes("SALOON") ||
    text.includes("SEDAN") ||
    text.includes("ESTATE") ||
    text.includes("COUPE") ||
    text.includes("CABRIOLET") ||
    text.includes("CONVERTIBLE") ||
    text.includes("SUV") ||
    text.includes("CROSSOVER") ||
    text.includes("AUDI") ||
    text.includes("BMW") ||
    text.includes("FORD") ||
    text.includes("VOLKSWAGEN") ||
    text.includes("VW") ||
    text.includes("MERCEDES") ||
    text.includes("TOYOTA") ||
    text.includes("HONDA") ||
    text.includes("NISSAN") ||
    text.includes("PEUGEOT") ||
    text.includes("RENAULT") ||
    text.includes("KIA") ||
    text.includes("HYUNDAI")
  ) return "CAR";

  return "";
}

function vehicleTypeMatches(aiType, regType) {
  const a = normStr(aiType);
  const r = normStr(regType);

  if (!a || !r) return false;
  if (a === r) return true;

  return false;
}

function buildFallbackScannerWindow(scannerWindowEvidence) {
  if (!scannerWindowEvidence) return null;

  return {
    id: scannerWindowEvidence.id,
    plate: scannerWindowEvidence.plate || null,
    camera_id: scannerWindowEvidence.camera_id || null,
    scanner_id: scannerWindowEvidence.scanner_id || null,
    window_start: scannerWindowEvidence.window_start || null,
    window_end: scannerWindowEvidence.window_end || null,
    ble_packets_seen: toInt(scannerWindowEvidence.ble_packets_seen, 0),
    ble_devices_seen: toInt(scannerWindowEvidence.ble_devices_seen, 0),
    companyid_hits_seen: toInt(scannerWindowEvidence.companyid_hits_seen, 0),
    gotid_candidates_seen: toInt(scannerWindowEvidence.gotid_candidates_seen, 0),
    strongest_rssi: scannerWindowEvidence.strongest_rssi,
    nearest_est_distance_m: scannerWindowEvidence.nearest_est_distance_m,
    valid_uuid_seen: boolish(scannerWindowEvidence.valid_uuid_seen),
    valid_sig_seen: boolish(scannerWindowEvidence.valid_sig_seen),
    valid_chal_seen: boolish(scannerWindowEvidence.valid_chal_seen),
    pk_match_seen: boolish(scannerWindowEvidence.pk_match_seen),
    consecutive_missing_windows: toInt(scannerWindowEvidence.consecutive_missing_windows, 0)
  };
}

function evaluateScannerWindowEvidence(ev) {
  if (!ev) {
    return {
      usable: false,
      cleanAbsence: false,
      strong: false,
      veryStrong: false,
      consecutiveMissingWindows: 0,
      scannerAlive: false,
      noValidIdentity: false,
      reasons: ["No fallback scanner evidence window found."]
    };
  }

  const blePacketsSeen = toInt(ev.ble_packets_seen, 0);
  const bleDevicesSeen = toInt(ev.ble_devices_seen, 0);
  const companyIdHits = toInt(ev.companyid_hits_seen, 0);
  const gotidCandidates = toInt(ev.gotid_candidates_seen, 0);
  const strongestRssi =
    ev.strongest_rssi == null ? null : toInt(ev.strongest_rssi, null);

  const validUuidSeen = boolish(ev.valid_uuid_seen);
  const validSigSeen = boolish(ev.valid_sig_seen);
  const validChalSeen = boolish(ev.valid_chal_seen);
  const pkMatchSeen = boolish(ev.pk_match_seen);

  const consecutiveMissingWindows = toInt(ev.consecutive_missing_windows, 0);

  const scannerAlive =
    blePacketsSeen > 0 ||
    bleDevicesSeen > 0 ||
    companyIdHits > 0 ||
    gotidCandidates > 0 ||
    strongestRssi !== null;

  const noValidIdentity =
    !validUuidSeen &&
    !validSigSeen &&
    !validChalSeen &&
    !pkMatchSeen;

  const cleanAbsence = scannerAlive && noValidIdentity;
  const usable = scannerAlive;

  const strong =
    cleanAbsence &&
    consecutiveMissingWindows >= 2;

  const veryStrong =
    cleanAbsence &&
    consecutiveMissingWindows >= 3;

  const reasons = [];

  if (scannerAlive) {
    reasons.push(
      `Scanner evidence window active: ble_packets_seen=${blePacketsSeen}, ble_devices_seen=${bleDevicesSeen}, companyid_hits_seen=${companyIdHits}, gotid_candidates_seen=${gotidCandidates}, strongest_rssi=${strongestRssi ?? "null"}`
    );
  } else {
    reasons.push("Fallback scanner evidence window exists but does not prove scanner activity strongly enough.");
  }

  if (noValidIdentity) {
    reasons.push("No valid GOT-ID UUID, signature, challenge result, or pubkey match was observed in the scanner evidence window.");
  } else {
    reasons.push("A valid UUID/signature/challenge/pubkey match was observed, so UUID_MISSING is not valid.");
  }

  reasons.push(`Consecutive clean missing windows observed: ${consecutiveMissingWindows}`);

  return {
    usable,
    cleanAbsence,
    strong,
    veryStrong,
    consecutiveMissingWindows,
    scannerAlive,
    noValidIdentity,
    reasons
  };
}

function detectRecentIdentityLossRecovery(scanEvent, scannerWindowEvidence) {
  if (!scanEvent || !scannerWindowEvidence) {
    return {
      recoveredAfterAbsence: false,
      secondsGap: null
    };
  }

  const evEval = evaluateScannerWindowEvidence(scannerWindowEvidence);

  if (!evEval.cleanAbsence) {
    return {
      recoveredAfterAbsence: false,
      secondsGap: null
    };
  }

  const scanTs = toMs(scanEvent.created_at || scanEvent.ts);
  const winEndTs = toMs(scannerWindowEvidence.window_end);

  if (scanTs === null || winEndTs === null) {
    return {
      recoveredAfterAbsence: false,
      secondsGap: null
    };
  }

  const gapS = Math.round((scanTs - winEndTs) / 1000);

  // Police-grade rule:
  // if a clean absence window ends shortly before a valid crypto return,
  // preserve that as a recovered-after-absence encounter.
  const recoveredAfterAbsence =
    gapS >= 0 &&
    gapS <= 30 &&
    evEval.consecutiveMissingWindows >= 1;

  return {
    recoveredAfterAbsence,
    secondsGap: gapS
  };
}

function isEnrolledMissingTagState(fused) {
  const rs = normStr(fused?.registry_status);

  return (
    fused?.has_gotid === true &&
    (
      rs === "ENROLLED_NO_VALID_TAG_SEEN" ||
      rs === "ENROLLED" ||
      rs === "ACTIVE"
    )
  );
}

export function decideFusion({
  registryVehicle,
  scanEvent,
  anprEvent,
  aiEvent,
  lastCounter,
  allowMissingDecision = false,
  scannerWindowEvidence = null
}) {
  const cloudVerdict = scanEvent?.cloud_verdict || null;
  const scannerResult = scanEvent?.scanner_result || null;

  const hasIdentity =
    scanEvent?.has_identity === true ||
    scanEvent?.pubkey_match === true;

  const fused = {
    fusion_verdict: null,
    final_label: null,
    visual_confidence: "NONE",
    reasons: [],
    plate: anprEvent?.plate || scanEvent?.plate || registryVehicle?.plate || null,

    has_gotid: registryVehicle ? (registryVehicle.has_gotid === true) : false,
    registry_status: registryVehicle?.status || "unknown",

    crypto: {
      sig_valid: scanEvent?.sig_valid ?? null,
      chal_valid: scanEvent?.chal_valid ?? null,
      pubkey_match: scanEvent?.pubkey_match ?? null,
      tamper: scanEvent?.tamper ?? null,
      counter: scanEvent?.counter ?? null,
      last_counter: lastCounter?.counter ?? lastCounter ?? null,
      last_seen_at: lastCounter?.created_at ?? null,
      cloud_verdict: cloudVerdict,
      scanner_result: scannerResult,
      has_identity: scanEvent?.has_identity ?? null
    },

    anpr: anprEvent || null,
    ai: aiEvent || null,
    scan: scanEvent || null,
    raw_json: {}
  };

  const windowEval = evaluateScannerWindowEvidence(scannerWindowEvidence);
  const fallbackScannerWindow = buildFallbackScannerWindow(scannerWindowEvidence);
  const recoveryEval = detectRecentIdentityLossRecovery(scanEvent, scannerWindowEvidence);

  fused.raw_json = {
    ...(fused.raw_json || {}),
    fallback_scanner_window_event_id: scannerWindowEvidence?.id || null,
    fallback_scanner_window: fallbackScannerWindow,
    scanner_window_summary: {
      usable: windowEval.usable,
      clean_absence: windowEval.cleanAbsence,
      strong: windowEval.strong,
      very_strong: windowEval.veryStrong,
      consecutive_missing_windows: windowEval.consecutiveMissingWindows
    },
    recovery_summary: {
      recovered_after_absence: recoveryEval.recoveredAfterAbsence,
      gap_seconds_from_absence_window_end: recoveryEval.secondsGap
    }
  };

  // ---------------------------------------------------------------------------
  // 1) Preserve strongest scanner/cloud truth first
  // ---------------------------------------------------------------------------
  if (scannerResult === "CLONE_SUSPECT" || cloudVerdict === "KEY_MISMATCH") {
    fused.fusion_verdict = "MISMATCH_PUBKEY";
    pushReason(fused.reasons, "Scanner/cloud detected pubkey mismatch or clone suspicion.");
  } else if (scannerResult === "REPLAY_SUSPECT") {
    fused.fusion_verdict = "REPLAY_SUSPECT";
    pushReason(fused.reasons, "Scanner detected replay or counter rollback suspicion.");
  } else if (scannerResult === "INVALID_TAG") {
    fused.fusion_verdict = "INVALID_TAG";
    pushReason(fused.reasons, "Scanner detected invalid base signature.");
  } else if (scannerResult === "RELAY_SUSPECT") {
    fused.fusion_verdict = "RELAY_SUSPECT";
    pushReason(fused.reasons, "Scanner challenge-response failed; relay suspected.");
  } else if (scannerResult === "TAMPERED") {
    fused.fusion_verdict = "TAMPER";
    pushReason(fused.reasons, "Scanner detected active tamper condition.");
  } else if (cloudVerdict === "MISMATCH") {
    fused.fusion_verdict = "MISMATCH";
    pushReason(fused.reasons, "Cloud detected plate mismatch.");
  } else if (cloudVerdict === "REPLAY_SUSPECT") {
    fused.fusion_verdict = "REPLAY_SUSPECT";
    pushReason(fused.reasons, "Cloud classified scan as replay suspicion.");
  } else if (cloudVerdict === "INVALID_TAG") {
    fused.fusion_verdict = "INVALID_TAG";
    pushReason(fused.reasons, "Cloud classified scan as invalid tag.");
  } else if (cloudVerdict === "RELAY_SUSPECT") {
    fused.fusion_verdict = "RELAY_SUSPECT";
    pushReason(fused.reasons, "Cloud classified scan as relay suspicion.");
  } else if (cloudVerdict === "TAMPERED") {
    fused.fusion_verdict = "TAMPER";
    pushReason(fused.reasons, "Cloud classified scan as tampered.");
  }

  // ---------------------------------------------------------------------------
  // 2) Core verdict if not already locked by scanner/cloud truth
  // ---------------------------------------------------------------------------
  if (!fused.fusion_verdict) {
    if (!registryVehicle) {
      fused.fusion_verdict = "NOT_ENROLLED";
      pushReason(fused.reasons, "Vehicle not found in registry for this scan context.");
    } else if (fused.has_gotid === false) {
      if (!scanEvent) {
        fused.fusion_verdict = "NOT_ENROLLED";
        pushReason(fused.reasons, "Vehicle does not have GOT-ID assigned.");
      } else {
        fused.fusion_verdict = "UNKNOWN_TAG";
        pushReason(fused.reasons, "GOT-ID tag detected but vehicle is not enrolled for GOT-ID.");
      }
    } else {
      // -----------------------------------------------------------------------
      // TRUE UUID_MISSING path
      // -----------------------------------------------------------------------
      if (!scanEvent || !hasIdentity) {
        if (allowMissingDecision === true) {
          pushReason(fused.reasons, "Enrolled vehicle but no GOT-ID identity was captured within scan window.");

          for (const r of windowEval.reasons) {
            pushReason(fused.reasons, r);
          }

          if (windowEval.veryStrong) {
            fused.fusion_verdict = "UUID_MISSING";
            fused.registry_status = "ENROLLED_NO_VALID_TAG_SEEN";
            fused.raw_json.missing_evidence_grade = "VERY_STRONG";
          } else if (windowEval.strong) {
            fused.fusion_verdict = "UUID_MISSING";
            fused.registry_status = "ENROLLED_NO_VALID_TAG_SEEN";
            fused.raw_json.missing_evidence_grade = "STRONG";
          } else if (windowEval.usable && windowEval.cleanAbsence) {
            fused.fusion_verdict = "UUID_MISSING";
            fused.registry_status = "ENROLLED_NO_VALID_TAG_SEEN";
            fused.raw_json.missing_evidence_grade = "USABLE";
          } else {
            fused.fusion_verdict = "NO_SCANNER_EVIDENCE";
            fused.registry_status = "INSUFFICIENT_SCANNER_EVIDENCE";
            fused.raw_json.missing_evidence_grade = "NONE";
          }
        } else {
          fused.fusion_verdict = "PENDING";
          pushReason(fused.reasons, "Enrolled vehicle pass is still awaiting identity evidence before deadline.");
        }
      } else {
        // ---------------------------------------------------------------------
        // Counter / replay policy
        // ---------------------------------------------------------------------
        const DUP_WINDOW_S = 35;
        const REPLAY_WINDOW_S = 120;

        const prevCounter =
          typeof lastCounter === "object" ? lastCounter?.counter : lastCounter;
        const prevTs =
          typeof lastCounter === "object" ? lastCounter?.created_at : null;

        if (typeof prevCounter === "number" && typeof scanEvent.counter === "number") {
          if (scanEvent.counter < prevCounter) {
            fused.fusion_verdict = "COUNTER_ROLLBACK";
            pushReason(fused.reasons, "Counter rolled back vs previous scan (strong clone/reset signal).");
          } else if (scanEvent.counter === prevCounter) {
            const currentTs = toMs(scanEvent.created_at) || toMs(scanEvent.ts) || null;
            const previousTs = toMs(prevTs);
            const gapS =
              currentTs !== null && previousTs !== null
                ? Math.abs(currentTs - previousTs) / 1000
                : null;

            if (gapS !== null && gapS <= DUP_WINDOW_S) {
              pushReason(fused.reasons, `Same counter re-seen after ${Math.round(gapS)}s (benign duplicate live sighting).`);
            } else if (gapS !== null && gapS > REPLAY_WINDOW_S) {
              fused.fusion_verdict = "REPLAY_SUSPECT";
              pushReason(fused.reasons, `Counter repeated after ${Math.round(gapS)}s since previous scan (possible replay).`);
            } else {
              pushReason(fused.reasons, `Same counter repeated after ${Math.round(gapS)}s (still treated as live duplicate, broadcaster rotates every ~30s).`);
            }
          }
        }

        // ---------------------------------------------------------------------
        // Core crypto truth
        // ---------------------------------------------------------------------
        if (!fused.fusion_verdict) {
          if (scanEvent.sig_valid === false) {
            fused.fusion_verdict = "INVALID_TAG";
            pushReason(fused.reasons, "Base signature verification failed.");
          } else if (scanEvent.chal_valid === false) {
            fused.fusion_verdict = "RELAY_SUSPECT";
            pushReason(fused.reasons, "Challenge-response failed.");
          } else if (scanEvent.pubkey_match === false) {
            fused.fusion_verdict = "MISMATCH_PUBKEY";
            pushReason(fused.reasons, "GOT-ID tag pubkey does not match registry.");
          } else if (scanEvent.tamper === true) {
            fused.fusion_verdict = "TAMPER";
            pushReason(fused.reasons, "GOT-ID tag tamper input is active.");
          } else if (
            scanEvent.sig_valid === true &&
            scanEvent.pubkey_match === true &&
            scanEvent.chal_valid === true
          ) {
            fused.fusion_verdict = "MATCH";
            pushReason(fused.reasons, "All cryptographic checks passed, pubkey matches registry, and live challenge-response succeeded.");

            // Police-grade truth preservation:
            // if clean absence was seen shortly before a later clean return,
            // preserve that story explicitly instead of hiding it.
            if (recoveryEval.recoveredAfterAbsence) {
              pushReason(
                fused.reasons,
                `Valid identity returned ${recoveryEval.secondsGap}s after a clean no-identity interval.`
              );
              fused.raw_json.identity_recovery_after_absence = true;
              fused.raw_json.identity_recovery_gap_seconds = recoveryEval.secondsGap;
            }
          } else if (
            scanEvent.sig_valid === true &&
            scanEvent.pubkey_match === true &&
            scanEvent.chal_valid !== false
          ) {
            fused.fusion_verdict = "MATCH_CRYPTO_ONLY";
            pushReason(fused.reasons, "Cryptographic identity passed and pubkey matches registry, but live challenge was not confirmed.");
          } else {
            fused.fusion_verdict = "UNKNOWN_TAG";
            pushReason(fused.reasons, "Identity evidence was present but insufficient to classify as a trusted match.");
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // 3) Visual confidence
  // ---------------------------------------------------------------------------
  let visualScore = 0;

  if (anprEvent) {
    const c = getConfidence(anprEvent);
    if (c === null) visualScore += 1;
    else if (c >= 0.9) visualScore += 2;
    else if (c >= 0.7) visualScore += 1;
  }

  if (aiEvent) {
    const c = getConfidence(aiEvent);
    if (c === null) visualScore += 1;
    else if (c >= 0.9) visualScore += 2;
    else if (c >= 0.7) visualScore += 1;

    if (registryVehicle) {
      const aiMake = normStr(aiEvent.make || aiEvent.raw_json?.make);
      const aiColour = normStr(aiEvent.colour || aiEvent.raw_json?.colour_estimate || aiEvent.raw_json?.vehicle_colour);
      const aiType = getAiVehicleType(aiEvent);

      const regMake = normStr(registryVehicle.make);
      const regColour = normStr(registryVehicle.colour);
      const regType = deriveRegistryVehicleType(registryVehicle);

      const makeMatches = aiMake && regMake && aiMake === regMake;
      const colourMatches = aiColour && regColour && aiColour === regColour;
      const typeMatches = vehicleTypeMatches(aiType, regType);

      if (makeMatches || colourMatches || typeMatches) {
        visualScore += 1;
      }

      if (typeMatches) {
        pushReason(fused.reasons, `AI vehicle type matches registry (${aiType}).`);
      }

      if (
        (aiMake && regMake && aiMake !== regMake) ||
        (aiColour && regColour && aiColour !== regColour) ||
        (aiType && regType && !typeMatches)
      ) {
        pushReason(fused.reasons, "AI appearance does not fully match registry (type/make/colour).");
      }
    }
  }

  if (visualScore >= 4) fused.visual_confidence = "STRONG";
  else if (visualScore >= 2) fused.visual_confidence = "MEDIUM";
  else if (visualScore >= 1) fused.visual_confidence = "WEAK";
  else fused.visual_confidence = "NONE";

  // ---------------------------------------------------------------------------
  // 4) Officer label mapping
  // ---------------------------------------------------------------------------
  const v = fused.fusion_verdict;

  if (v === "MATCH") {
    if (fused.raw_json?.identity_recovery_after_absence === true) {
      fused.final_label = "MATCH_AFTER_IDENTITY_RECOVERY";
    } else {
      fused.final_label =
        fused.visual_confidence === "STRONG" || fused.visual_confidence === "MEDIUM"
          ? "MATCH_STRONG"
          : "MATCH_WEAK_VISUAL";
    }
  } else if (v === "PENDING") {
    fused.final_label = "PENDING";
  } else if (v === "MATCH_CRYPTO_ONLY") {
    fused.final_label = "MATCH_CRYPTO_ONLY";
  } else if (v === "UUID_MISSING" && isEnrolledMissingTagState(fused)) {
    const missingGrade = fused.raw_json?.missing_evidence_grade || "NONE";

    if (missingGrade === "VERY_STRONG") {
      fused.final_label = "UUID_MISSING_SUSPECT_CLONE_VERY_STRONG";
    } else if (missingGrade === "STRONG") {
      fused.final_label = "UUID_MISSING_SUSPECT_CLONE_STRONG";
    } else if (missingGrade === "USABLE") {
      fused.final_label = "UUID_MISSING_SUSPECT_CLONE";
    } else {
      fused.final_label = "UUID_MISSING_SUSPECT_CLONE";
    }
  } else if (v === "UUID_MISSING" && fused.has_gotid === true) {
    const missingGrade = fused.raw_json?.missing_evidence_grade || "NONE";

    if (missingGrade === "VERY_STRONG") {
      fused.final_label = "UUID_MISSING_VERY_STRONG";
    } else if (missingGrade === "STRONG") {
      fused.final_label = "UUID_MISSING_STRONG";
    } else if (missingGrade === "USABLE") {
      fused.final_label = "CLONE_SUSPECT_MISSING_TAG";
    } else {
      fused.final_label = "UUID_MISSING";
    }
  } else if (v === "NO_SCANNER_EVIDENCE") {
    fused.final_label = "NO_SCANNER_EVIDENCE";
  } else if (v === "MISMATCH" || v === "MISMATCH_PUBKEY") {
    fused.final_label = "CLONE_SUSPECT";
  } else if (v === "REPLAY_SUSPECT" || v === "COUNTER_ROLLBACK") {
    fused.final_label = "REPLAY_SUSPECT";
  } else if (v === "INVALID_TAG") {
    fused.final_label = "INVALID_TAG";
  } else if (v === "RELAY_SUSPECT") {
    fused.final_label = "RELAY_SUSPECT";
  } else if (v === "TAMPER") {
    fused.final_label =
      fused.visual_confidence === "STRONG" || fused.visual_confidence === "MEDIUM"
        ? "TAMPER_STRONG"
        : "TAMPER_WEAK";
  } else if (v === "NOT_ENROLLED") {
    fused.final_label = "NOT_ENROLLED";
  } else if (v === "UNKNOWN_TAG") {
    fused.final_label = "UNKNOWN_TAG";
  } else {
    fused.final_label = v || "UNKNOWN";
  }

  return fused;
}
