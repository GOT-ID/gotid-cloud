-- 002_scans_table.sql
-- Table to store GOT-ID scanner BLE scan events

CREATE TABLE IF NOT EXISTS scans (
    id              SERIAL PRIMARY KEY,
    scanner_id      TEXT,           -- e.g. "COM5" or scanner UUID
    uuid            TEXT,           -- GOT-ID broadcaster UUID
    plate           TEXT,           -- licence plate recognised / expected
    vin             TEXT,           -- optional VIN
    result          TEXT,           -- MATCH / MISMATCH / MISSING / ERROR
    rssi            INTEGER,        -- signal strength if we capture it
    raw_json        JSONB,          -- full payload from scanner (for forensics)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
