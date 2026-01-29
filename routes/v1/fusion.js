// routes/v1/fusion.js
import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";
import { query } from "../../db/index.js";

const router = Router();

/**
 * GET /v1/fusion/recent?limit=10
 * Returns recent fusion_events rows so you can verify UUID_MISSING / MATCH / etc are being created.
 */
router.get("/recent", requireAuth, async (req, res) => {
  try {
    const limitRaw = req.query?.limit;
    let limit = parseInt(limitRaw, 10);
    if (!Number.isFinite(limit) || limit <= 0) limit = 10;
    if (limit > 100) limit = 100; // keep API safe

    const r = await query(
      `
      SELECT
        id,
        plate,
        scan_id,
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
      FROM fusion_events
      ORDER BY id DESC
      LIMIT $1;
      `,
      [limit]
    );

    // Build "linked" from the real DB IDs (source of truth)
    const rowsOut = r.rows.map(row => ({
      ...row,
      linked: {
        scan_id: row.scan_id ?? null,
        anpr_id: row.anpr_id ?? null,
        ai_id: row.ai_id ?? null
      }
    }));

    return res.json({
      ok: true,
      count: rowsOut.length,
      rows: rowsOut
    });

  } catch (err) {
    console.error("Error in GET /v1/fusion/recent:", err);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

export default router;
