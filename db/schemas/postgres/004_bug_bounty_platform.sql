-- ============================================================
-- ReconX Migration 004 — Bug Bounty Platform Extensions
-- Safe: all statements wrapped in exception handlers
-- ============================================================

-- Add policy fields to programs (safe, idempotent)
DO $$ BEGIN
    ALTER TABLE programs ADD COLUMN allowed_tests JSONB DEFAULT '["xss","sqli","lfi","ssrf","csrf","cors","idor","open_redirect","ssti","misconfig","graphql","jwt"]';
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE programs ADD COLUMN rate_limit_rps INTEGER DEFAULT 2;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE programs ADD COLUMN notes TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE programs ADD COLUMN platform_program_id TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Add priority to scopes
DO $$ BEGIN
    ALTER TABLE scopes ADD COLUMN priority INTEGER DEFAULT 5;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Extend findings with bug bounty fields
DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN parameter TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN cvss_score REAL DEFAULT 0.0;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN cvss_vector TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN cwe TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN owasp TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN remediation TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN steps_to_reproduce TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN raw_request TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD COLUMN raw_response TEXT;
EXCEPTION WHEN duplicate_column THEN NULL; END $$;

-- Live scan events table
CREATE TABLE IF NOT EXISTS scan_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID,
    session_id TEXT,
    event_type TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    detail TEXT,
    severity TEXT,
    data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

DO $$ BEGIN
    CREATE INDEX idx_scan_events_session ON scan_events(session_id);
EXCEPTION WHEN duplicate_table THEN NULL; END $$;

DO $$ BEGIN
    CREATE INDEX idx_scan_events_type ON scan_events(event_type);
EXCEPTION WHEN duplicate_table THEN NULL; END $$;

DO $$ BEGIN
    CREATE INDEX idx_scan_events_created ON scan_events(created_at DESC);
EXCEPTION WHEN duplicate_table THEN NULL; END $$;

-- Default standalone program (safe insert)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM programs WHERE name = 'Standalone Scans') THEN
        INSERT INTO programs(name, platform, description)
        VALUES ('Standalone Scans', 'custom', 'Default program for scans not linked to a bug bounty program');
    END IF;
END $$;
