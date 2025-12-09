// db/index.js
// GOT-ID Cloud – Postgres connection

import pg from 'pg';

const { Pool } = pg;

// Use the DATABASE_URL from your .env file
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Simple helper for running queries
export async function query(text, params) {
  return pool.query(text, params);
}

// Export the pool itself if we ever need it directly
export { pool };