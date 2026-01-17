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

export function decideFusion({ registryVehicle, scanEvent, anprEvent, aiEvent, lastCounter }) {
  const fused = {
    fusion_verdict: null,       // raw verdict
    final_label: null,          // officer label
    visual_confidence: "NONE",  // NONE | WEAK | MEDIUM | STRONG
    reasons: [],
    plate: anprEvent?.plate || scanEvent?.plate || registryVehicle?.plate || null,

    // If has_gotid is missing in DB rows, treat "vehicle exists in registry" as enrolled for GOT-ID unless explicitly false.
    has_gotid: registryVehicle ? (registryVehicle.has_gotid ?? true) : false,
    registry_status: registryVehicle?.status || "unknown",

    crypto: {
      sig_valid: scanEvent?.sig_valid ?? null,
      chal_valid: scanEvent?.chal_valid ?? null,
      pubkey_match: scanEvent?.pubkey_match ?? null,
      tamper: scanEvent?.tamper ?? null,
      counter: scanEvent?.counter ?? null,
      last_counter: lastCounter ?? null,
      cloud_verdict: scanEvent?.cloud_verdict ?? null,
      has_identity: scanEvent?.has_identity ?? null
    },

    anpr: anprEvent || null,
    ai: aiEvent || null,
    scan: scanEvent || null
  };

  // Pull through cloud authority classification (from scans.js)
  const cloudVerdict = scanEvent?.cloud_verdict || null;

  // Determine whether we truly captured a GOT-ID identity in this scan
  // (uuid alone can be null; the key proof is typically pubkey/identity captured)
  const hasIdentity =
    scanEvent?.has_identity === true ||
    (scanEvent?.uuid && String(scanEvent.uuid).trim().length > 0) ||
    scanEvent?.pubkey_match === true || // if scanner computed this, identity was present
    cloudVerdict === "AUTHENTIC" ||
    cloudVerdict === "KEY_MISMATCH";

  // ---------- 1) Core verdict ----------
  // Police-grade rule: if the cloud already determined KEY_MISMATCH, treat as a clone-suspect mismatch.
  if (cloudVerdict === "KEY_MISMATCH") {
    fused.fusion_verdict = "MISMATCH";
    fused.reasons.push(
      "Plate is enrolled but presented pubkey is not enrolled/matching (clone suspected)."
    );
  }

  // If not already decided by cloudVerdict, proceed with original logic (with missing-identity fix)
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
      // Vehicle IS enrolled
      if (!scanEvent || !hasIdentity) {
        fused.fusion_verdict = "UUID_MISSING";
        fused.reasons.push("Enrolled vehicle but no GOT-ID identity was captured within scan window.");
      } else {
        // Counter checks (replay / rollback)
        if (typeof lastCounter === "number" && typeof scanEvent.counter === "number") {
          if (scanEvent.counter < lastCounter) {
            fused.fusion_verdict = "COUNTER_ROLLBACK";
            fused.reasons.push("Counter rolled back compared to previous scan (possible replay/clone).");
          } else if (scanEvent.counter === lastCounter) {
            fused.reasons.push("Counter did not advance since previous scan (possible replay).");
          }
        }

        // If not already decided by rollback, check crypto flags
        if (!fused.fusion_verdict) {
          if (scanEvent.sig_valid === false || scanEvent.chal_valid === false) {
            fused.fusion_verdict = "CRYPTO_FAIL";
            fused.reasons.push("Signature or challenge-response failed.");
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

  // ---------- 2) Visual confidence (ANPR + AI, never overrides crypto) ----------
  let visualScore = 0;

  // ANPR presence boosts confidence
  if (anprEvent) {
    const c = getConfidence(anprEvent);
    if (c === null) visualScore += 1;
    else if (c >= 0.9) visualScore += 2;
    else if (c >= 0.7) visualScore += 1;
  }

  // AI presence boosts confidence; if make/colour exist, compare with registry and score accordingly
  if (aiEvent) {
    const c = getConfidence(aiEvent);
    if (c === null) visualScore += 1;
    else if (c >= 0.9) visualScore += 2;
    else if (c >= 0.7) visualScore += 1;

    if (registryVehicle) {
      const aiMake = normStr(aiEvent.make);
      const aiColour = normStr(aiEvent.colour);
      const regMake = normStr(registryVehicle.make);
      const regColour = normStr(registryVehicle.colour);

      const makeMatches = aiMake && regMake && aiMake === regMake;
      const colourMatches = aiColour && regColour && aiColour === regColour;

      // If AI provided appearance and it matches, add support; if it conflicts, note it.
      if (makeMatches || colourMatches) visualScore += 1;
      else if ((aiMake && regMake && aiMake !== regMake) || (aiColour && regColour && aiColour !== regColour)) {
        fused.reasons.push("AI appearance does not fully match registry (make/colour).");
      }
    }
  }

  if (visualScore >= 4) fused.visual_confidence = "STRONG";
  else if (visualScore >= 2) fused.visual_confidence = "MEDIUM";
  else if (visualScore >= 1) fused.visual_confidence = "WEAK";
  else fused.visual_confidence = "NONE";

  // ---------- 3) Officer label mapping ----------
  const v = fused.fusion_verdict;

  if (v === "MATCH") {
    fused.final_label =
      fused.visual_confidence === "STRONG" || fused.visual_confidence === "MEDIUM"
        ? "MATCH_STRONG"
        : "MATCH_WEAK_VISUAL";
  } else if (v === "UUID_MISSING" && fused.has_gotid === true) {
    // Police-grade: missing tag is stronger if ANPR/AI saw the car
    fused.final_label =
      fused.visual_confidence === "STRONG" || fused.visual_confidence === "MEDIUM"
        ? "CLONE_MISSING_TAG_STRONG"
        : "CLONE_MISSING_TAG_WEAK";
  } else if (v === "MISMATCH" || v === "MISMATCH_PUBKEY") {
    fused.final_label = "CLONE_SUSPECT";
  } else if (v === "CRYPTO_FAIL" || v === "COUNTER_ROLLBACK") {
    fused.final_label = "CLONE_CRYPTO";
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
