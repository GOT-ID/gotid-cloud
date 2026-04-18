-- 002_scans_table.sql
-- Create table to store GOT-ID scanner events

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  uuid TEXT NOT NULL,
  counter INTEGER,
  signature_valid BOOLEAN,
  match_result TEXT,
  plate TEXT,
  vin TEXT,
  make TEXT,
  model TEXT,
  raw_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
