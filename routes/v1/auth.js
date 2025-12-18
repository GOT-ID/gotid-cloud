// routes/v1/auth.js
import express from "express";
import jwt from "jsonwebtoken";

const router = express.Router();

// DEV login endpoint to mint JWTs for scanners/officers.
// Later we’ll replace this with real officer accounts + hashed passwords.
router.post("/login", (req, res) => {
  const { officer_id, scanner_id } = req.body;

  if (!officer_id && !scanner_id) {
    return res.status(400).json({
      ok: false,
      error: "missing_identity",
      help: "send officer_id or scanner_id"
    });
  }

  if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET missing in .env");
    return res.status(500).json({ ok: false, error: "server_misconfigured" });
  }

  const token = jwt.sign(
    {
      officer_id: officer_id || null,
      scanner_id: scanner_id || null,
      role: officer_id ? "officer" : "scanner",
    },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );

  res.json({ ok: true, token });
});

export default router;
