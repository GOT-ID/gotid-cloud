// fusion.js
// GOT-ID fusion engine: crypto is the truth, cameras support it (never override crypto).

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
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

function normStr(s) {
  return (s || "").toString().trim().toUpperCase();
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

  if (
    text.includes("BUS") ||
    text.includes("COACH")
  ) return "BUS";

  if (
    text.includes("VAN") ||
    text.includes("TRANSIT")
  ) return "VAN";

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

// Helper: parse event timestamps safely (ms since epoch)
function toMs(ts) {
  if (!ts) return null;
  const t = new Date(ts).getTime();
  return Number.isFinite(t) ? t : null;
}

export function decideFusion({ registryVehicle, scanEvent, anprEvent, aiEvent, lastCounter }) {
  const cloudVerdict = scanEvent?.cloud_verdict || null;
  const scannerResult = scanEvent?.scanner_result || null;

  // Strict identity presence:
  // Only trust actual scan evidence, not a downstream label alone.
  const hasIdentity =
    scanEvent?.has_identity === true ||
    (scanEvent?.uuid && String(scanEvent.uuid).trim().length > 0) ||
    scanEvent?.pubkey_match === true ||
    scanEvent?.sig_valid === true ||
    scanEvent?.chal_valid === true;

  const fused = {
    fusion_verdict: null,       // raw verdict
    final_label: null,          // officer label
    visual_confidence: "NONE",  // NONE | WEAK | MEDIUM | STRONG
    reasons: [],
    plate: anprEvent?.plate || scanEvent?.plate || registryVehicle?.plate || null,

    // If has_gotid is missing in DB rows, treat "vehicle exists in registry" as enrolled
    // unless explicitly false.
    has_gotid: registryVehicle ? (registryVehicle.has_gotid ?? true) : false,
    registry_status: registryVehicle?.status || "unknown",

    crypto: {
      sig_valid: scanEvent?.sig_valid ?? null,
      chal_valid: scanEvent?.chal_valid ?? null,
      pubkey_match: scanEvent?.pubkey_match ?? null,
      tamper: scanEvent?.tamper ?? null,
      counter: scanEvent?.counter ?? null,
      last_counter: lastCounter ?? null,
      cloud_verdict: cloudVerdict,
      scanner_result: scannerResult,
      has_identity: scanEvent?.has_identity ?? null
    },

    anpr: anprEvent || null,
    ai: aiEvent || null,
    scan: scanEvent || null
  };

  // ---------------------------------------------------------------------------
  // 1) Preserve strongest scanner/cloud truth first
  // ---------------------------------------------------------------------------
  if (scannerResult === "CLONE_SUSPECT" || cloudVerdict === "KEY_MISMATCH") {
    fused.fusion_verdict = "MISMATCH_PUBKEY";
    fused.reasons.push("Scanner/cloud detected pubkey mismatch or clone suspicion.");
  } else if (scannerResult === "REPLAY_SUSPECT") {
    fused.fusion_verdict = "REPLAY_SUSPECT";
    fused.reasons.push("Scanner detected replay or counter rollback suspicion.");
  } else if (scannerResult === "INVALID_TAG") {
    fused.fusion_verdict = "INVALID_TAG";
    fused.reasons.push("Scanner detected invalid base signature.");
  } else if (scannerResult === "RELAY_SUSPECT") {
    fused.fusion_verdict = "RELAY_SUSPECT";
    fused.reasons.push("Scanner challenge-response failed; relay suspected.");
  } else if (scannerResult === "TAMPERED") {
    fused.fusion_verdict = "TAMPER";
    fused.reasons.push("Scanner detected active tamper condition.");
  } else if (cloudVerdict === "MISMATCH") {
    fused.fusion_verdict = "MISMATCH";
    fused.reasons.push("Cloud detected plate mismatch.");
  } else if (cloudVerdict === "REPLAY_SUSPECT") {
    fused.fusion_verdict = "REPLAY_SUSPECT";
    fused.reasons.push("Cloud classified scan as replay suspicion.");
  } else if (cloudVerdict === "INVALID_TAG") {
    fused.fusion_verdict = "INVALID_TAG";
    fused.reasons.push("Cloud classified scan as invalid tag.");
  } else if (cloudVerdict === "RELAY_SUSPECT") {
    fused.fusion_verdict = "RELAY_SUSPECT";
    fused.reasons.push("Cloud classified scan as relay suspicion.");
  } else if (cloudVerdict === "TAMPERED") {
    fused.fusion_verdict = "TAMPER";
    fused.reasons.push("Cloud classified scan as tampered.");
  }

  // ---------------------------------------------------------------------------
  // 2) Core verdict if not already locked by scanner/cloud truth
  // ---------------------------------------------------------------------------
  if (!fused.fusion_verdict) {
    if (!registryVehicle) {
      fused.fusion_verdict = "NOT_ENROLLED";
      fused.reasons.push("Vehicle not found in registry for this scan context.");
    } else if (fused.has_gotid === false) {
      if (!scanEvent) {
        fused.fusion_verdict = "NOT_ENROLLED";
        fused.reasons.push("Vehicle does not have GOT-ID assigned.");
      } else {
        fused.fusion_verdict = "UNKNOWN_TAG";
        fused.reasons.push("GOT-ID tag detected but vehicle is not enrolled for GOT-ID.");
      }
    } else {
      // Vehicle is enrolled
      if (!scanEvent || !hasIdentity) {
        fused.fusion_verdict = "UUID_MISSING";
        fused.reasons.push("Enrolled vehicle but no GOT-ID identity was captured within scan window.");
      } else {
        const DUP_WINDOW_S = 20;     // benign repeated observation
        const REPLAY_WINDOW_S = 60;  // repetition beyond this becomes suspicious

        if (typeof lastCounter === "number" && typeof scanEvent.counter === "number") {
          if (scanEvent.counter < lastCounter) {
            fused.fusion_verdict = "COUNTER_ROLLBACK";
            fused.reasons.push("Counter rolled back vs previous scan (strong clone/reset signal).");
          } else if (scanEvent.counter === lastCounter) {
            const scanTs = toMs(scanEvent.created_at) || toMs(scanEvent.ts) || null;
            const nowTs = Date.now();
            const dtS = scanTs ? Math.abs(nowTs - scanTs) / 1000 : null;

            if (dtS !== null && dtS <= DUP_WINDOW_S) {
              // benign duplicate re-observation
            } else if (dtS !== null && dtS >= REPLAY_WINDOW_S) {
              fused.fusion_verdict = "REPLAY_SUSPECT";
              fused.reasons.push(`Counter repeated after ${Math.round(dtS)}s (possible replay).`);
            }
          }
        }

        // If still undecided, evaluate crypto flags
        if (!fused.fusion_verdict) {
          if (scanEvent.sig_valid === false) {
            fused.fusion_verdict = "INVALID_TAG";
            fused.reasons.push("Base signature verification failed.");
          } else if (scanEvent.chal_valid === false) {
            fused.fusion_verdict = "RELAY_SUSPECT";
            fused.reasons.push("Challenge-response failed.");
          } else if (scanEvent.pubkey_match === false) {
            fused.fusion_verdict = "MISMATCH_PUBKEY";
            fused.reasons.push("GOT-ID tag pubkey does not match registry.");
          } else if (scanEvent.tamper === true) {
            fused.fusion_verdict = "TAMPER";
            fused.reasons.push("GOT-ID tag tamper input is active.");
          } else {
            fused.fusion_verdict = "MATCH";
            fused.reasons.push("All cryptographic checks passed and pubkey matches registry.");
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // 3) Visual confidence (ANPR + AI only supports, never overrides crypto)
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
      const aiColour = normStr(aiEvent.colour || aiEvent.raw_json?.colour_estimate);
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
        fused.reasons.push(`AI vehicle type matches registry (${aiType}).`);
      }

      if (
        (aiMake && regMake && aiMake !== regMake) ||
        (aiColour && regColour && aiColour !== regColour) ||
        (aiType && regType && !typeMatches)
      ) {
        fused.reasons.push("AI appearance does not fully match registry (type/make/colour).");
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
    fused.final_label =
      fused.visual_confidence === "STRONG" || fused.visual_confidence === "MEDIUM"
        ? "MATCH_STRONG"
        : "MATCH_WEAK_VISUAL";
  } else if (v === "UUID_MISSING" && fused.has_gotid === true) {
    fused.final_label =
      fused.visual_confidence === "STRONG" || fused.visual_confidence === "MEDIUM"
        ? "CLONE_MISSING_TAG_STRONG"
        : "CLONE_MISSING_TAG_WEAK";
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
  } else {
    fused.final_label = v || "UNKNOWN";
  }

  return fused;
}
