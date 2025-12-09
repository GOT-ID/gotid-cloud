// fusion.js
// GOT-ID fusion engine: crypto is the truth, cameras support it.

export function decideFusion({
  registryVehicle,
  scanEvent,
  anprEvent,
  aiEvent,
  lastCounter
}) {
  const fused = {
    fusion_verdict: null,       // raw crypto-based verdict
    final_label: null,          // human-readable label
    visual_confidence: "NONE",  // NONE | WEAK | MEDIUM | STRONG
    reasons: [],
    plate: anprEvent?.plate || scanEvent?.plate || registryVehicle?.plate || null,
    has_gotid: registryVehicle?.has_gotid ?? false,
    registry_status: registryVehicle?.status || "unknown",
    crypto: {
      sig_valid: scanEvent?.sig_valid ?? null,
      chal_valid: scanEvent?.chal_valid ?? null,
      pubkey_match: scanEvent?.pubkey_match ?? null,
      tamper: scanEvent?.tamper ?? null,
      counter: scanEvent?.counter ?? null,
      last_counter: lastCounter ?? null
    },
    anpr: anprEvent || null,
    ai: aiEvent || null,
    scan: scanEvent || null
  };

  // ---------- 1) Crypto-based core verdict ----------

  if (!registryVehicle) {
    fused.fusion_verdict = "NOT_ENROLLED";
    fused.reasons.push("Plate not found in GOT-ID registry.");
  } else if (registryVehicle.has_gotid === false) {
    if (!scanEvent) {
      fused.fusion_verdict = "NOT_ENROLLED";
      fused.reasons.push("Vehicle does not have GOT-ID assigned.");
    } else {
      fused.fusion_verdict = "UNKNOWN_TAG";
      fused.reasons.push("GOT-ID tag detected but vehicle is not enrolled.");
    }
  } else {
    // Vehicle IS enrolled (has_gotid = true)
    if (!scanEvent) {
      fused.fusion_verdict = "UUID_MISSING";
      fused.reasons.push("Enrolled vehicle but no GOT-ID scan detected.");
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

  // ---------- 2) Visual confidence (ANPR + AI, never overrides crypto) ----------

  let visualScore = 0;

  // ANPR confidence
  if (anprEvent && typeof anprEvent.confidence === "number") {
    if (anprEvent.confidence >= 0.9) visualScore += 2;
    else if (anprEvent.confidence >= 0.7) visualScore += 1;
  }

  // Future AI (make/colour) – currently aiEvent will be null
  if (aiEvent && typeof aiEvent.confidence === "number" && aiEvent.confidence >= 0.7 && registryVehicle) {
    const makeMatches =
      aiEvent.make &&
      registryVehicle.make &&
      aiEvent.make.toUpperCase() === registryVehicle.make.toUpperCase();

    const colourMatches =
      aiEvent.colour &&
      registryVehicle.colour &&
      aiEvent.colour.toUpperCase() === registryVehicle.colour.toUpperCase();

    if (makeMatches || colourMatches) {
      visualScore += 1;
    } else {
      fused.reasons.push("AI appearance does not fully match registry (make/colour).");
    }
  }

  if (visualScore >= 3) fused.visual_confidence = "STRONG";
  else if (visualScore === 2) fused.visual_confidence = "MEDIUM";
  else if (visualScore === 1) fused.visual_confidence = "WEAK";
  else fused.visual_confidence = "NONE";

  // ---------- 3) Map crypto verdict + visual_confidence → final_label ----------

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
  } else if (v === "MISMATCH_PUBKEY" || v === "CRYPTO_FAIL" || v === "COUNTER_ROLLBACK") {
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