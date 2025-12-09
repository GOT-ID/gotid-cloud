-- 001_anpr_fusion.sql
-- Create table to store ANPR camera events
CREATE TABLE IF NOT EXISTS anpr_events (
  id SERIAL PRIMARY KEY,
  plate TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  camera_id TEXT,
  confidence REAL,
  raw_json JSONB
);

-- Create table to store fused GOT-ID + ANPR verdicts
CREATE TABLE IF NOT EXISTS fusion_events (
  id SERIAL PRIMARY KEY,
  plate TEXT,
  scan_id INTEGER,
  fusion_verdict TEXT,
  final_label TEXT,
  visual_confidence TEXT,
  has_gotid BOOLEAN,
  registry_status TEXT,
  reasons TEXT[],
  raw_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);