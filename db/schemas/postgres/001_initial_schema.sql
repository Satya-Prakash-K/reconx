-- ============================================
-- ReconX PostgreSQL Schema
-- Version: 1.0.0
-- ============================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users & Auth ────────────────────────────

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('admin', 'operator', 'viewer', 'api_key')),
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- ── Bug Bounty Programs ─────────────────────

CREATE TABLE programs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
    platform VARCHAR(20) NOT NULL
        CHECK (platform IN ('hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'custom')),
    platform_url TEXT,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_programs_platform ON programs(platform);
CREATE INDEX idx_programs_active ON programs(is_active);

-- ── Scope Definitions ───────────────────────

CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scope_type VARCHAR(20) NOT NULL
        CHECK (scope_type IN ('domain', 'wildcard', 'ip', 'ip_range', 'url', 'api')),
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    is_in_scope BOOLEAN DEFAULT true,
    is_wildcard BOOLEAN DEFAULT false,
    parent_domain VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scopes_program ON scopes(program_id);
CREATE INDEX idx_scopes_value ON scopes(normalized_value);
CREATE INDEX idx_scopes_in_scope ON scopes(is_in_scope);

-- ── Workspaces ──────────────────────────────

CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    scan_count INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    asset_count INTEGER DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_workspaces_program ON workspaces(program_id);

-- ── Scans ───────────────────────────────────

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(200),
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
    config JSONB DEFAULT '{}',
    current_phase VARCHAR(50),
    phase_results JSONB DEFAULT '[]',
    total_assets_found INTEGER DEFAULT 0,
    total_findings_found INTEGER DEFAULT 0,
    progress_percent REAL DEFAULT 0.0,
    temporal_workflow_id VARCHAR(255),
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    scheduled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scans_workspace ON scans(workspace_id);
CREATE INDEX idx_scans_status ON scans(status);

-- ── Assets ──────────────────────────────────

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    asset_type VARCHAR(30) NOT NULL
        CHECK (asset_type IN (
            'domain', 'subdomain', 'ip', 'port', 'url', 'api_endpoint',
            'js_file', 's3_bucket', 'azure_blob', 'gcp_bucket', 'firebase',
            'graphql', 'swagger'
        )),
    value TEXT NOT NULL,
    hostname VARCHAR(255),
    ip_address INET,
    port INTEGER CHECK (port >= 1 AND port <= 65535),
    protocol VARCHAR(10),
    technology TEXT[] DEFAULT '{}',
    http_status INTEGER,
    http_title TEXT,
    content_length BIGINT,
    tls_info JSONB,
    waf_detected VARCHAR(100),
    cdn_detected VARCHAR(100),
    risk_score REAL DEFAULT 0.0,
    is_alive BOOLEAN DEFAULT true,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_assets_workspace ON assets(workspace_id);
CREATE INDEX idx_assets_type ON assets(asset_type);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_ip ON assets(ip_address);
CREATE INDEX idx_assets_risk ON assets(risk_score DESC);
CREATE UNIQUE INDEX idx_assets_unique_value ON assets(workspace_id, asset_type, value);

-- ── Subdomains ──────────────────────────────

CREATE TABLE subdomains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    subdomain VARCHAR(255) NOT NULL,
    parent_domain VARCHAR(255) NOT NULL,
    source VARCHAR(50) NOT NULL,
    ip_addresses INET[] DEFAULT '{}',
    cname_records TEXT[] DEFAULT '{}',
    is_alive BOOLEAN,
    http_status INTEGER,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_subdomains_workspace ON subdomains(workspace_id);
CREATE INDEX idx_subdomains_parent ON subdomains(parent_domain);
CREATE UNIQUE INDEX idx_subdomains_unique ON subdomains(workspace_id, subdomain);

-- ── DNS Records ─────────────────────────────

CREATE TABLE dns_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    record_type VARCHAR(10) NOT NULL,
    record_value TEXT NOT NULL,
    ttl INTEGER,
    is_takeover_candidate BOOLEAN DEFAULT false,
    takeover_provider VARCHAR(100),
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_dns_workspace ON dns_records(workspace_id);
CREATE INDEX idx_dns_hostname ON dns_records(hostname);
CREATE INDEX idx_dns_takeover ON dns_records(is_takeover_candidate) WHERE is_takeover_candidate = true;

-- ── HTTP Probes ─────────────────────────────

CREATE TABLE http_probes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    url TEXT NOT NULL,
    hostname VARCHAR(255),
    status_code INTEGER,
    content_type VARCHAR(100),
    content_length BIGINT,
    title TEXT,
    server_header VARCHAR(200),
    technologies TEXT[] DEFAULT '{}',
    tls_version VARCHAR(20),
    tls_cipher VARCHAR(100),
    tls_certificate JSONB,
    waf_detected VARCHAR(100),
    cdn_detected VARCHAR(100),
    response_time_ms INTEGER,
    redirect_url TEXT,
    headers JSONB,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_http_workspace ON http_probes(workspace_id);
CREATE INDEX idx_http_hostname ON http_probes(hostname);
CREATE INDEX idx_http_status ON http_probes(status_code);

-- ── Ports ───────────────────────────────────

CREATE TABLE ports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    ip_address INET NOT NULL,
    port INTEGER NOT NULL CHECK (port >= 1 AND port <= 65535),
    protocol VARCHAR(10) DEFAULT 'tcp',
    state VARCHAR(20) DEFAULT 'open',
    service VARCHAR(100),
    version VARCHAR(200),
    banner TEXT,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ports_workspace ON ports(workspace_id);
CREATE INDEX idx_ports_ip ON ports(ip_address);
CREATE UNIQUE INDEX idx_ports_unique ON ports(workspace_id, ip_address, port, protocol);

-- ── URLs ────────────────────────────────────

CREATE TABLE urls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    url TEXT NOT NULL,
    domain VARCHAR(255),
    path TEXT,
    parameters TEXT[] DEFAULT '{}',
    source VARCHAR(50) NOT NULL,
    status_code INTEGER,
    content_type VARCHAR(100),
    content_length BIGINT,
    is_interesting BOOLEAN DEFAULT false,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_urls_workspace ON urls(workspace_id);
CREATE INDEX idx_urls_domain ON urls(domain);
CREATE INDEX idx_urls_interesting ON urls(is_interesting) WHERE is_interesting = true;

-- ── JS Findings ─────────────────────────────

CREATE TABLE js_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    js_url TEXT NOT NULL,
    finding_type VARCHAR(50) NOT NULL
        CHECK (finding_type IN ('secret', 'endpoint', 'token', 'api_key', 'link', 'sourcemap')),
    value TEXT NOT NULL,
    context TEXT,
    confidence REAL DEFAULT 0.5,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_js_workspace ON js_findings(workspace_id);
CREATE INDEX idx_js_type ON js_findings(finding_type);

-- ── Screenshots ─────────────────────────────

CREATE TABLE screenshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    url TEXT NOT NULL,
    hostname VARCHAR(255),
    file_path TEXT NOT NULL,
    file_size BIGINT,
    http_status INTEGER,
    title TEXT,
    favicon_hash VARCHAR(64),
    similar_to UUID REFERENCES screenshots(id),
    captured_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_screenshots_workspace ON screenshots(workspace_id);

-- ── Findings ────────────────────────────────

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    asset_id UUID REFERENCES assets(id),
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(10) NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status VARCHAR(20) NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'confirmed', 'false_positive', 'duplicate', 'reported', 'resolved')),
    finding_type VARCHAR(100) NOT NULL,
    risk_score REAL DEFAULT 0.0,
    confidence REAL DEFAULT 0.0,
    evidence JSONB DEFAULT '{}',
    reproduction_steps TEXT,
    affected_url TEXT,
    source_tool VARCHAR(50),
    ai_summary TEXT,
    ai_attack_path TEXT,
    is_duplicate BOOLEAN DEFAULT false,
    duplicate_of UUID REFERENCES findings(id),
    tags TEXT[] DEFAULT '{}',
    embedding_id VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_workspace ON findings(workspace_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_risk ON findings(risk_score DESC);
CREATE INDEX idx_findings_type ON findings(finding_type);

-- ── Attack Paths (AI-Generated) ─────────────

CREATE TABLE attack_paths (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(10) NOT NULL,
    path_nodes JSONB NOT NULL DEFAULT '[]',
    related_findings UUID[] DEFAULT '{}',
    confidence REAL DEFAULT 0.0,
    ai_reasoning TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_attack_paths_workspace ON attack_paths(workspace_id);

-- ── Recon Summaries (AI-Generated) ──────────

CREATE TABLE recon_summaries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id),
    summary_type VARCHAR(20) NOT NULL DEFAULT 'full',
    content TEXT NOT NULL,
    key_findings JSONB DEFAULT '[]',
    risk_overview JSONB DEFAULT '{}',
    recommendations JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Audit Logs ──────────────────────────────

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_time ON audit_logs(created_at DESC);

-- ── Rate Limit State ────────────────────────

CREATE TABLE rate_limit_state (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier VARCHAR(255) NOT NULL,
    limit_type VARCHAR(20) NOT NULL
        CHECK (limit_type IN ('global', 'per_target', 'per_tool')),
    request_count INTEGER DEFAULT 0,
    window_start TIMESTAMPTZ DEFAULT NOW(),
    window_seconds INTEGER DEFAULT 60
);

CREATE UNIQUE INDEX idx_rate_limit_id ON rate_limit_state(identifier, limit_type);

-- ── Updated At Trigger ──────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_programs_updated_at BEFORE UPDATE ON programs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_workspaces_updated_at BEFORE UPDATE ON workspaces
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
