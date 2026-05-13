-- ============================================
-- ReconX Vulnerability Engine Schema Extension
-- ============================================
-- Run after 001_initial_schema.sql

-- ── Vulnerability Scans ────────────────────
CREATE TABLE IF NOT EXISTS vuln_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    scan_type       VARCHAR(50) NOT NULL DEFAULT 'full',
    status          VARCHAR(30) NOT NULL DEFAULT 'pending',
    current_phase   VARCHAR(50),
    progress        REAL DEFAULT 0.0,
    config          JSONB DEFAULT '{}',
    target_urls     TEXT[] DEFAULT '{}',
    categories      TEXT[] DEFAULT '{}',
    endpoints_total INT DEFAULT 0,
    endpoints_tested INT DEFAULT 0,
    vulns_found     INT DEFAULT 0,
    critical_count  INT DEFAULT 0,
    high_count      INT DEFAULT 0,
    medium_count    INT DEFAULT 0,
    low_count       INT DEFAULT 0,
    info_count      INT DEFAULT 0,
    ai_reasoning    TEXT[] DEFAULT '{}',
    phase_results   JSONB DEFAULT '{}',
    report          JSONB,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vuln_scans_workspace ON vuln_scans(workspace_id);
CREATE INDEX idx_vuln_scans_status ON vuln_scans(status);

-- ── Vulnerability Findings ─────────────────
CREATE TABLE IF NOT EXISTS vuln_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES vuln_scans(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'info',
    category        VARCHAR(50) NOT NULL,
    affected_url    TEXT,
    param           VARCHAR(255),
    payload         TEXT,
    confidence      REAL DEFAULT 0.5,
    fp_probability  REAL DEFAULT 0.0,
    risk_score      REAL DEFAULT 0.0,
    status          VARCHAR(30) DEFAULT 'new',  -- new, confirmed, false_positive, fixed, accepted
    evidence        JSONB DEFAULT '{}',
    reproduction_steps TEXT,
    ai_summary      TEXT,
    source_tool     VARCHAR(100),
    screenshot_path TEXT,
    request_dump    TEXT,
    response_dump   TEXT,
    validated_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vuln_findings_scan ON vuln_findings(scan_id);
CREATE INDEX idx_vuln_findings_workspace ON vuln_findings(workspace_id);
CREATE INDEX idx_vuln_findings_severity ON vuln_findings(severity);
CREATE INDEX idx_vuln_findings_category ON vuln_findings(category);
CREATE INDEX idx_vuln_findings_status ON vuln_findings(status);
CREATE INDEX idx_vuln_findings_confidence ON vuln_findings(confidence DESC);

-- ── Endpoints (attack surface) ─────────────
CREATE TABLE IF NOT EXISTS endpoints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    url             TEXT NOT NULL,
    method          VARCHAR(10) DEFAULT 'GET',
    params          JSONB DEFAULT '{}',
    headers         JSONB DEFAULT '{}',
    body            JSONB,
    content_type    VARCHAR(100),
    auth_required   BOOLEAN DEFAULT FALSE,
    technologies    TEXT[] DEFAULT '{}',
    risk_indicators TEXT[] DEFAULT '{}',
    priority_score  REAL DEFAULT 0.0,
    category        VARCHAR(50),
    last_tested     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(workspace_id, url, method)
);

CREATE INDEX idx_endpoints_workspace ON endpoints(workspace_id);
CREATE INDEX idx_endpoints_priority ON endpoints(priority_score DESC);
CREATE INDEX idx_endpoints_category ON endpoints(category);

-- ── AI Hypotheses ──────────────────────────
CREATE TABLE IF NOT EXISTS vuln_hypotheses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    scan_id         UUID REFERENCES vuln_scans(id) ON DELETE CASCADE,
    endpoint_url    TEXT,
    param           VARCHAR(255),
    category        VARCHAR(50) NOT NULL,
    reasoning       TEXT,
    confidence      REAL DEFAULT 0.5,
    severity_estimate VARCHAR(20),
    test_strategy   TEXT,
    payloads        TEXT[] DEFAULT '{}',
    result          VARCHAR(30) DEFAULT 'pending',  -- pending, confirmed, rejected
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_hypotheses_workspace ON vuln_hypotheses(workspace_id);
CREATE INDEX idx_hypotheses_category ON vuln_hypotheses(category);

-- ── Fuzzing Sessions ───────────────────────
CREATE TABLE IF NOT EXISTS fuzz_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES vuln_scans(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL,
    target_url      TEXT NOT NULL,
    target_param    VARCHAR(255),
    payloads_sent   INT DEFAULT 0,
    findings_count  INT DEFAULT 0,
    anomalies       INT DEFAULT 0,
    waf_detected    BOOLEAN DEFAULT FALSE,
    waf_bypassed    BOOLEAN DEFAULT FALSE,
    status          VARCHAR(30) DEFAULT 'running',
    config          JSONB DEFAULT '{}',
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

-- ── Vulnerability Chains ───────────────────
CREATE TABLE IF NOT EXISTS vuln_chains (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    finding_ids     UUID[] NOT NULL,
    combined_severity VARCHAR(20),
    combined_risk   REAL DEFAULT 0.0,
    attack_path     JSONB DEFAULT '[]',
    ai_analysis     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_vuln_chains_workspace ON vuln_chains(workspace_id);

-- ── Tool Execution Log ─────────────────────
CREATE TABLE IF NOT EXISTS tool_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES vuln_scans(id) ON DELETE SET NULL,
    workspace_id    UUID NOT NULL,
    tool_name       VARCHAR(100) NOT NULL,
    target          TEXT,
    command         TEXT,
    exit_code       INT,
    output_size     INT DEFAULT 0,
    findings_count  INT DEFAULT 0,
    duration_ms     INT DEFAULT 0,
    error           TEXT,
    executed_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_tool_exec_scan ON tool_executions(scan_id);
CREATE INDEX idx_tool_exec_tool ON tool_executions(tool_name);

-- ── Trigger: auto-update updated_at ────────
CREATE OR REPLACE FUNCTION update_vuln_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_vuln_scans_updated
    BEFORE UPDATE ON vuln_scans
    FOR EACH ROW EXECUTE FUNCTION update_vuln_timestamp();

CREATE TRIGGER trg_vuln_findings_updated
    BEFORE UPDATE ON vuln_findings
    FOR EACH ROW EXECUTE FUNCTION update_vuln_timestamp();
