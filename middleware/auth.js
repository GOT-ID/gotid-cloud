// middleware/auth.js
import jwt from "jsonwebtoken";

// Simple bearer-token auth.
// In dev you can bypass with DEV_ALLOW_NO_TOKEN=true
export function requireAuth(req, res, next) {
  if (process.env.DEV_ALLOW_NO_TOKEN === "true") return next();

  if (!process.env.JWT_SECRET) {
    console.error("JWT_SECRET missing in environment");
    return res.status(500).json({ ok: false, error: "server_misconfigured" });
  }

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ ok: false, error: "missing_token" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    // more explicit errors help real-world debugging
    const code = e?.name === "TokenExpiredError" ? "token_expired" : "invalid_token";
    return res.status(401).json({ ok: false, error: code });
  }
}