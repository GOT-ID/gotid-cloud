// db/index.js
// GOT-ID Cloud — Postgres helper

import pool from "./pool.js";

// Simple wrapper for running SQL queries
export async function query(text, params = []) {
  const result = await pool.query(text, params);
  return result.rows;  // Always return only rows
}

// Export pool in case we ever need raw access
export { pool };
