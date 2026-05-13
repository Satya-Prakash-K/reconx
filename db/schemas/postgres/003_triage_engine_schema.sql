-- ============================================
-- ReconX Triage Engine Schema Extension
-- ============================================
-- Run after 002_vuln_engine_schema.sql

-- ── Triaged Findings ───────────────────────
CREATE TABLE IF NOT EXISTS triaged_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_id     UUID,
    workspace_id    UUID NOT NULL,
    scan_id         UUID,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'info',
    category        VARCHAR(50) NOT NULL,
    affected_url    TEXT,
    param           VARCHAR(255),
    confidence      REAL DEFAULT 0.5,
    -- Triage enrichments
    cwe_id          VARCHAR(20),
    cwe_name        TEXT,
    cvss_score      REAL DEFAULT 0.0,
    cvss_vector     VARCHAR(100),
    owasp_category  VARCHAR(100),
    exploitability_score REAL DEFAULT 0.0,
    impact_score    REAL DEFAULT 0.0,
    priority_rank   INT DEFAULT 0,
    is_duplicate    BOOLEAN DEFAULT FALSE,
    duplicate_of    UUID,
    cluster_id      VARCHAR(20),
    root_cause      TEXT,
    suggested_fix   TEXT,
    ai_summary      TEXT,
    evidence        JSONB DEFAULT '{}',
    source_tool     VARCHAR(100),
    status          VARCHAR(30) DEFAULT 'triaged',
    triaged_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_triaged_workspace ON triaged_findings(workspace_id);
CREATE INDEX idx_triaged_severity ON triaged_findings(severity);
CREATE INDEX idx_triaged_category ON triaged_findings(category);
CREATE INDEX idx_triaged_priority ON triaged_findings(priority_rank);
CREATE INDEX idx_triaged_cvss ON triaged_findings(cvss_score DESC);
CREATE INDEX idx_triaged_duplicate ON triaged_findings(is_duplicate);

-- ── Generated Reports ──────────────────────
CREATE TABLE IF NOT EXISTS generated_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    finding_id      UUID,
    format          VARCHAR(30) NOT NULL,
    title           TEXT,
    content         TEXT NOT NULL,
    ai_enrichments  JSONB DEFAULT '{}',
    metadata        JSONB DEFAULT '{}',
    status          VARCHAR(30) DEFAULT 'draft',
    submitted_to    VARCHAR(50),
    submission_id   VARCHAR(100),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_reports_workspace ON generated_reports(workspace_id);
CREATE INDEX idx_reports_format ON generated_reports(format);
CREATE INDEX idx_reports_finding ON generated_reports(finding_id);

-- ── Exploit Intelligence ───────────────────
CREATE TABLE IF NOT EXISTS exploit_intelligence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category        VARCHAR(50) NOT NULL,
    payload         TEXT,
    payload_hash    VARCHAR(64),
    effectiveness   REAL DEFAULT 0.0,
    success_count   INT DEFAULT 0,
    fail_count      INT DEFAULT 0,
    waf_bypasses    TEXT[] DEFAULT '{}',
    technologies    TEXT[] DEFAULT '{}',
    last_used       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_exploit_intel_category ON exploit_intelligence(category);
CREATE INDEX idx_exploit_intel_effectiveness ON exploit_intelligence(effectiveness DESC);

-- ── Audit Trail ────────────────────────────
CREATE TABLE IF NOT EXISTS audit_trail (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    user_id         VARCHAR(100),
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50),
    resource_id     UUID,
    details         JSONB DEFAULT '{}',
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_workspace ON audit_trail(workspace_id);
CREATE INDEX idx_audit_action ON audit_trail(action);
CREATE INDEX idx_audit_created ON audit_trail(created_at DESC);

-- ── Trigger: auto-update ───────────────────
CREATE TRIGGER trg_triaged_updated
    BEFORE UPDATE ON triaged_findings
    FOR EACH ROW EXECUTE FUNCTION update_vuln_timestamp();

CREATE TRIGGER trg_reports_updated
    BEFORE UPDATE ON generated_reports
    FOR EACH ROW EXECUTE FUNCTION update_vuln_timestamp();
