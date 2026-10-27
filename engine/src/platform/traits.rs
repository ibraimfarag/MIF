use serde::{Deserialize, Serialize};
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditFinding {
    pub section: String,
    pub item: String,
    pub status: FindingStatus,
    pub severity: Severity,
    pub description: String,
    pub fix_available: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum FindingStatus {
    Secure,
    Warning,
    Vulnerable,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Score penalty when the finding is insecure (spec: critical 25 / high 15 / medium 8 / low 3).
    pub fn penalty(&self) -> u32 {
        match self {
            Severity::Low => 3,
            Severity::Medium => 8,
            Severity::High => 15,
            Severity::Critical => 25,
        }
    }
}

impl FindingStatus {
    pub fn is_insecure(&self) -> bool {
        matches!(self, FindingStatus::Vulnerable | FindingStatus::Warning)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConnection {
    pub local_address: String,
    pub remote_address: String,
    pub protocol: String,
    pub state: String,
    pub process_id: u32,
    pub process_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StartupEntry {
    pub name: String,
    pub command: String,
    pub location: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScheduledTaskEntry {
    pub name: String,
    pub path: String,
}

/// OS-specific collectors. Every OS (Windows now, Linux/macOS later) implements
/// this trait; the dispatcher and CLI call only through it.
#[async_trait]
pub trait PlatformCollectors: Send + Sync {
    async fn audit_defender(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_firewall(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_rdp(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_smbv1(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_uac(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_admins(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_startup(&self) -> Result<Vec<StartupEntry>>;
    async fn audit_scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>>;
    async fn audit_hosts_file(&self) -> Result<Vec<AuditFinding>>;
    async fn audit_remote_tools(&self) -> Result<Vec<AuditFinding>>;
    async fn get_network_connections(&self) -> Result<Vec<NetworkConnection>>;
    async fn get_software_inventory(&self) -> Result<Vec<SoftwareEntry>>;
}

/// Runs every audit section and reduces the findings into a 0–100 security
/// score plus the flat findings list. Shared by the CLI, the dispatcher and
/// (later) the dashboard — one definition so the score is always consistent.
pub async fn run_full_audit(collectors: &dyn PlatformCollectors) -> Result<serde_json::Value> {
    let mut findings: Vec<AuditFinding> = Vec::new();

    let sections = [
        ("defender", collectors.audit_defender()),
        ("firewall", collectors.audit_firewall()),
        ("rdp", collectors.audit_rdp()),
        ("smbv1", collectors.audit_smbv1()),
        ("uac", collectors.audit_uac()),
        ("admins", collectors.audit_admins()),
        ("hosts", collectors.audit_hosts_file()),
        ("remote_tools", collectors.audit_remote_tools()),
    ];
    for (name, section) in sections {
        match section.await {
            Ok(v) => findings.extend(v),
            Err(e) => tracing::warn!("{name} audit failed: {e:#}"),
        }
    }

    let startup = collectors.audit_startup().await.unwrap_or_default();
    let tasks = collectors.audit_scheduled_tasks().await.unwrap_or_default();

    let mut penalty = 0u32;
    for f in &findings {
        if f.status.is_insecure() {
            penalty += f.severity.penalty();
        }
    }
    let score = 100u32.saturating_sub(penalty.min(100));

    Ok(serde_json::json!({
        "score": score,
        "findings": findings,
        "startup_entries": startup,
        "scheduled_tasks": tasks,
    }))
}
