use serde::{Deserialize, Serialize};
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditFinding {
    pub section: String,
    pub item: String,
    pub status: FindingStatus,
    pub severity: Severity,
    pub description: String,
    pub fix_available: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum FindingStatus {
    Secure,
    Warning,
    Vulnerable,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[async_trait]
pub trait PlatformCollectors {
    async fn audit_defender(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_firewall(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_rdp(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_smbv1(&self) -> Result<Vec<AuditFinding>>;
    async fn get_network_connections(&self) -> Result<Vec<NetworkConnection>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_address: String,
    pub remote_address: String,
    pub protocol: String,
    pub state: String,
    pub process_id: u32,
    pub process_name: String,
}
