// middleware/auth.js

// Simple bearer-token auth for machine clients (scanner, ANPR, etc.).
// In dev you can bypass with DEV_ALLOW_NO_TOKEN=true

export function requireAuth(req, res, next) {
  // Optional dev bypass
  if (process.env.DEV_ALLOW_NO_TOKEN === "true") {
    return next();
  }

  const expected = process.env.API_TOKEN;
  if (!expected) {
    console.error("API_TOKEN missing in environment");
    return res
      .status(500)
      .json({ ok: false, error: "server_misconfigured_no_api_token" });
  }

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ ok: false, error: "missing_token" });
  }

  if (token !== expected) {
    return res.status(401).json({ ok: false, error: "invalid_token" });
  }

  // You can attach a simple "user" if you want for logging
  req.user = { role: "scanner", auth: "api_token" };
  next();
}
