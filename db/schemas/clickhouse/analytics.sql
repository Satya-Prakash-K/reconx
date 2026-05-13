-- ============================================
-- ReconX ClickHouse Analytics Schema
-- ============================================
-- High-performance analytics for scan metrics, events, and time-series data

CREATE DATABASE IF NOT EXISTS reconx;

-- ── Scan Events (time-series) ──────────────
CREATE TABLE IF NOT EXISTS reconx.scan_events (
    event_id        UUID DEFAULT generateUUIDv4(),
    workspace_id    String,
    scan_id         String,
    event_type      LowCardinality(String),
    phase           LowCardinality(String),
    category        LowCardinality(String),
    severity        LowCardinality(String),
    target_url      String,
    tool            LowCardinality(String),
    duration_ms     UInt32 DEFAULT 0,
    payload_size    UInt32 DEFAULT 0,
    status_code     UInt16 DEFAULT 0,
    is_finding      Bool DEFAULT false,
    metadata        String DEFAULT '{}',
    created_at      DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, created_at, event_type)
TTL created_at + INTERVAL 365 DAY;

-- ── Finding Analytics ──────────────────────
CREATE TABLE IF NOT EXISTS reconx.finding_analytics (
    finding_id      String,
    workspace_id    String,
    scan_id         String,
    category        LowCardinality(String),
    severity        LowCardinality(String),
    cvss_score      Float32 DEFAULT 0,
    exploitability  Float32 DEFAULT 0,
    impact          Float32 DEFAULT 0,
    confidence      Float32 DEFAULT 0,
    is_duplicate    Bool DEFAULT false,
    source_tool     LowCardinality(String),
    triaged_at      DateTime DEFAULT now(),
    created_at      DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, category, severity);

-- ── Request Metrics ────────────────────────
CREATE TABLE IF NOT EXISTS reconx.request_metrics (
    request_id      UUID DEFAULT generateUUIDv4(),
    workspace_id    String,
    target_url      String,
    method          LowCardinality(String),
    status_code     UInt16,
    response_time_ms UInt32,
    response_size   UInt32,
    is_blocked      Bool DEFAULT false,
    waf_detected    LowCardinality(String) DEFAULT '',
    created_at      DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (workspace_id, created_at)
TTL created_at + INTERVAL 90 DAY;

-- ── Materialized Views ─────────────────────

-- Severity distribution per workspace
CREATE MATERIALIZED VIEW IF NOT EXISTS reconx.mv_severity_distribution
ENGINE = SummingMergeTree()
ORDER BY (workspace_id, category, severity)
AS SELECT
    workspace_id,
    category,
    severity,
    count() AS finding_count,
    avg(cvss_score) AS avg_cvss,
    max(cvss_score) AS max_cvss
FROM reconx.finding_analytics
GROUP BY workspace_id, category, severity;

-- Hourly scan activity
CREATE MATERIALIZED VIEW IF NOT EXISTS reconx.mv_hourly_activity
ENGINE = SummingMergeTree()
ORDER BY (workspace_id, hour)
AS SELECT
    workspace_id,
    toStartOfHour(created_at) AS hour,
    count() AS event_count,
    countIf(is_finding) AS finding_count,
    avg(duration_ms) AS avg_duration
FROM reconx.scan_events
GROUP BY workspace_id, hour;
