// routes/v1/auth.js
import { Router } from "express";
import { requireAuth } from "../../middleware/auth.js";

const router = Router();

/**
 * GET /v1/auth/status
 *
 * - Protected by requireAuth (must send correct Bearer token)
 * - Lets you test that API_TOKEN + middleware are working
 *   without involving the scanner.
 */
router.get("/status", requireAuth, (req, res) => {
  res.json({
    ok: true,
    message: "GOT-ID auth is working",
    scanner: req.scanner || null,  // set in middleware
  });
});

export default router;
