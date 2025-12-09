import { Router } from "express";
const router = Router();

// sanity check endpoint
router.get("/", (req, res) => {
  res.json({
    ok: true,
    service: process.env.JWT_ISSUER || "gotid-cloud",
    time: new Date().toISOString(),
  });
});

export default router;