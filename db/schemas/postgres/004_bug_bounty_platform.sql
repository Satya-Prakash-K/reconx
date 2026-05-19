-- ============================================================
-- ReconX Migration 004 — Bug Bounty Platform Extensions
-- ============================================================

-- Add policy + rate limiting to programs table
ALTER TABLE programs
    ADD COLUMN IF NOT EXISTS allowed_tests JSONB DEFAULT '["xss","sqli","lfi","ssrf","csrf","cors","idor","open_redirect","ssti","xxe","cmdi","misconfig","graphql","jwt"]',
    ADD COLUMN IF NOT EXISTS rate_limit_rps INTEGER DEFAULT 2,
    ADD COLUMN IF NOT EXISTS notes TEXT,
    ADD COLUMN IF NOT EXISTS platform_program_id TEXT;

-- Extend scopes with priority
ALTER TABLE scopes
    ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 5;

-- Add full fields to findings
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS parameter TEXT,
    ADD COLUMN IF NOT EXISTS cvss_score REAL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS cvss_vector TEXT,
    ADD COLUMN IF NOT EXISTS cwe TEXT,
    ADD COLUMN IF NOT EXISTS owasp TEXT,
    ADD COLUMN IF NOT EXISTS remediation TEXT,
    ADD COLUMN IF NOT EXISTS steps_to_reproduce TEXT,
    ADD COLUMN IF NOT EXISTS raw_request TEXT,
    ADD COLUMN IF NOT EXISTS raw_response TEXT;

-- Live scan events table (for live feed)
CREATE TABLE IF NOT EXISTS scan_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID,
    session_id TEXT,
    event_type TEXT NOT NULL
        CHECK (event_type IN ('finding','endpoint','change','asset','tech','error','info')),
    title TEXT NOT NULL,
    detail TEXT,
    severity TEXT,
    data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_events_session ON scan_events(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_type ON scan_events(event_type);
CREATE INDEX IF NOT EXISTS idx_scan_events_created ON scan_events(created_at DESC);

-- Create a default workspace + program for standalone scans
INSERT INTO programs(name, platform, description)
    VALUES ('Standalone Scans', 'custom', 'Default program for scans not linked to a bug bounty program')
    ON CONFLICT DO NOTHING;
