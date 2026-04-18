-- 003_police_grade_tamper.sql
-- Police-grade upgrade: tamper evidence + device state + forensic integrity
-- SAFE: does NOT break existing system

-- =========================================================
-- 1) Ensure scan_events table exists (for current backend)
-- =========================================================
CREATE TABLE IF NOT EXISTS scan_events (
  id SERIAL PRIMARY KEY,

  uuid TEXT,
  counter BIGINT,

  sig_valid BOOLEAN,
  chal_valid BOOLEAN,
  tamper_flag BOOLEAN,
  result TEXT,

  plate TEXT,
  vin TEXT,
  make TEXT,
  model TEXT,
  colour TEXT,

  rssi INTEGER,
  est_distance_m NUMERIC,

  scanner_id TEXT,
  officer_id TEXT,

  raw_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================================================
-- 2) Add police-grade tamper + identity fields
-- =========================================================
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS pubkey_hex TEXT;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_live BOOLEAN;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_latched BOOLEAN;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_count INTEGER;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_event_sig_valid BOOLEAN;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_event_hex TEXT;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_event_sig_hex TEXT;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS tamper_state_observed TEXT;
ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS evidence_hash TEXT;

-- Indexes for performance (millions of vehicles scale)
CREATE INDEX IF NOT EXISTS idx_scan_events_time
  ON scan_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_events_pubkey
  ON scan_events(pubkey_hex);

CREATE INDEX IF NOT EXISTS idx_scan_events_plate
  ON scan_events(plate);

CREATE INDEX IF NOT EXISTS idx_scan_events_tamper
  ON scan_events(tamper_state_observed);

-- =========================================================
-- 3) Persistent device security state (CRITICAL)
-- =========================================================
CREATE TABLE IF NOT EXISTS device_security_state (
  pubkey_hex TEXT PRIMARY KEY,

  current_state TEXT NOT NULL DEFAULT 'SECURE',
  tamper_count INTEGER NOT NULL DEFAULT 0,

  last_seen_at TIMESTAMPTZ,
  last_tamper_at TIMESTAMPTZ,
  last_scan_event_id BIGINT,

  hold_flag BOOLEAN NOT NULL DEFAULT FALSE,
  escalation_reason TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_state_status
  ON device_security_state(current_state);

-- =========================================================
-- 4) Immutable tamper event history (court evidence)
-- =========================================================
CREATE TABLE IF NOT EXISTS tamper_events (
  id SERIAL PRIMARY KEY,

  pubkey_hex TEXT,
  scan_event_id BIGINT,

  tamper_live BOOLEAN,
  tamper_latched BOOLEAN,
  tamper_count INTEGER,

  tamper_event_sig_valid BOOLEAN,
  tamper_event_hex TEXT,
  tamper_event_sig_hex TEXT,

  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  evidence_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_tamper_events_pubkey
  ON tamper_events(pubkey_hex);

CREATE INDEX IF NOT EXISTS idx_tamper_events_time
  ON tamper_events(observed_at DESC);

-- =========================================================
-- 5) Workshop remediation (garage reset tracking)
-- =========================================================
CREATE TABLE IF NOT EXISTS tamper_remediations (
  id SERIAL PRIMARY KEY,

  pubkey_hex TEXT NOT NULL,
  workshop_id TEXT,
  technician_id TEXT,
  notes TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================================================
-- 6) Officer clearance actions (legal audit)
-- =========================================================
CREATE TABLE IF NOT EXISTS tamper_clear_actions (
  id SERIAL PRIMARY KEY,

  pubkey_hex TEXT NOT NULL,
  officer_id TEXT,
  notes TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
