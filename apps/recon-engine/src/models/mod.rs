//! Data models for the recon engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub plugin_name: String,
    pub phase: String,
    pub target: String,
    pub result_type: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub scan_id: Uuid,
    pub workspace_id: Uuid,
    pub targets: Vec<String>,
    pub phases: Vec<String>,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub parent_domain: String,
    pub source: String,
    pub ip_addresses: Vec<String>,
    pub is_alive: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub tls_version: Option<String>,
    pub waf: Option<String>,
    pub cdn: Option<String>,
    pub response_time_ms: u64,
}
