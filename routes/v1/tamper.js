import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

function normHex(h) {
  return (h || "").toUpperCase().replace(/\s+/g, "");
}

function asStr(v, maxLen, fallback = null) {
  if (v === undefined || v === null) return fallback;
  const s = String(v).trim();
  if (!s) return fallback;
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

const router = Router();

/**
 * POST /v1/tamper/remediate
 * Body:
 * {
 *   "pubkey_hex": "...",
 *   "workshop_id": "WS-001",
 *   "technician_id": "TECH-001",
 *   "notes": "Seal replaced and enclosure inspected"
 * }
 */
router.post("/remediate", requireAuth, async (req, res) => {
  try {
    const body = req.body || {};

    const pubkey_hex = normHex(asStr(body.pubkey_hex, 300, "") || "");
    const workshop_id = asStr(body.workshop_id, 128, null);
    const technician_id = asStr(body.technician_id, 128, null);
    const notes = asStr(body.notes, 4000, null);

    if (!pubkey_hex) {
      return res.status(400).json({ ok: false, error: "missing_pubkey_hex" });
    }

    // record immutable remediation action
    await query(
      `
      INSERT INTO tamper_remediations (
        pubkey_hex,
        workshop_id,
        technician_id,
        notes,
        created_at
      )
      VALUES ($1,$2,$3,$4,NOW())
      `,
      [pubkey_hex, workshop_id, technician_id, notes]
    );

    // update persistent security state
    await query(
      `
      INSERT INTO device_security_state (
        pubkey_hex,
        current_state,
        tamper_count,
        last_remediation_at,
        hold_flag,
        escalation_reason,
        remediation_notes,
        remediation_workshop_id,
        remediation_technician_id,
        updated_at
      )
      VALUES (
        $1,
        'REMEDIATED_PENDING_REVERIFY',
        0,
        NOW(),
        FALSE,
        NULL,
        $2,
        $3,
        $4,
        NOW()
      )
      ON CONFLICT (pubkey_hex)
      DO UPDATE SET
        current_state = CASE
          WHEN device_security_state.current_state = 'ESCALATED_HOLD'
            THEN device_security_state.current_state
          ELSE 'REMEDIATED_PENDING_REVERIFY'
        END,
        last_remediation_at = NOW(),
        remediation_notes = EXCLUDED.remediation_notes,
        remediation_workshop_id = EXCLUDED.remediation_workshop_id,
        remediation_technician_id = EXCLUDED.remediation_technician_id,
        updated_at = NOW()
      `,
      [pubkey_hex, notes, workshop_id, technician_id]
    );

    const stateRes = await query(
      `
      SELECT
        pubkey_hex,
        current_state,
        tamper_count,
        hold_flag,
        escalation_reason,
        last_remediation_at,
        updated_at
      FROM device_security_state
      WHERE pubkey_hex = $1
      LIMIT 1
      `,
      [pubkey_hex]
    );

    return res.json({
      ok: true,
      remediation_recorded: true,
      state: stateRes.rows[0] || null
    });
  } catch (err) {
    console.error("tamper remediate error:", err);
    return res.status(500).json({ ok: false, error: "tamper_remediation_failed" });
  }
});

export default router;
