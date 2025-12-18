// db/index.js
import pkg from "pg";
const { Pool } = pkg;

// Create PG pool using your .env settings
const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  ssl: { rejectUnauthorized: false }
});

/**
 * Full result helper (used by routes/v1/scans.js)
 * Returns the full pg.Result object with rows, rowCount, etc.
 */
export async function query(text, params = []) {
  return pool.query(text, params);
}

/**
 * Rows-only helper (used by routes/v1/anpr.js)
 * Returns just result.rows for convenience.
 */
export async function runQuery(text, params = []) {
  const result = await pool.query(text, params);
  return result.rows;
}

// Optional: export pool if you ever need it directly
export { pool };

// Optional default export in case some code does `import db from ...`
const db = { query, runQuery, pool };
export default db;
