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
    #[serde(default)]
    pub country: String,
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

/// The check sections `audit.run` can be asked for by name. Order is the order
/// they run in, and the order a full audit reports them in.
pub const AUDIT_SECTIONS: [&str; 8] = [
    "defender",
    "firewall",
    "rdp",
    "smbv1",
    "uac",
    "admins",
    "hosts",
    "remote_tools",
];

/// Inventory lists rather than checks: part of a full audit, and requestable by
/// name on their own (`uac` fixed → only `defender` needs re-reading).
pub const AUDIT_INVENTORY: [&str; 2] = ["startup", "scheduled_tasks"];

/// Parses `params.sections` for `audit.run`.
///
/// `None` means "run everything" (the default the UI uses). An empty array is
/// also "everything": a request that names nothing is not a request for a score
/// of 100 over zero checks. Unknown names are an error, never silently ignored —
/// a typo would otherwise return a perfect score.
pub fn requested_sections(params: Option<&serde_json::Value>) -> Result<Option<Vec<String>>> {
    let Some(value) = params.and_then(|p| p.get("sections")) else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        anyhow::bail!("\"sections\" must be an array of section names");
    };
    if items.is_empty() {
        return Ok(None);
    }
    let mut wanted = Vec::with_capacity(items.len());
    for item in items {
        let Some(name) = item.as_str() else {
            anyhow::bail!("\"sections\" must contain section names, not {item}");
        };
        if !AUDIT_SECTIONS.contains(&name) && !AUDIT_INVENTORY.contains(&name) {
            anyhow::bail!(
                "unknown section \"{name}\" — known sections: {}",
                AUDIT_SECTIONS
                    .iter()
                    .chain(AUDIT_INVENTORY.iter())
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !wanted.iter().any(|w| w == name) {
            wanted.push(name.to_string());
        }
    }
    Ok(Some(wanted))
}

/// Runs the requested audit sections and reduces the findings into a 0–100
/// security score plus the flat findings list.
///
/// `sections` is what [`requested_sections`] returned: `None` is the full audit
/// the dashboard shows, `Some` is a subset (the report then carries
/// `"partial": true`, because a score over part of the checks is not comparable
/// with the full one). One definition so the score is always consistent.
pub async fn run_audit(
    collectors: &dyn PlatformCollectors,
    sections: Option<&[String]>,
) -> Result<serde_json::Value> {
    let wants = |name: &str| match sections {
        None => true,
        Some(list) => list.iter().any(|s| s == name),
    };
    let all = [
        ("defender", collectors.audit_defender()),
        ("firewall", collectors.audit_firewall()),
        ("rdp", collectors.audit_rdp()),
        ("smbv1", collectors.audit_smbv1()),
        ("uac", collectors.audit_uac()),
        ("admins", collectors.audit_admins()),
        ("hosts", collectors.audit_hosts_file()),
        ("remote_tools", collectors.audit_remote_tools()),
    ];
    let mut findings: Vec<AuditFinding> = Vec::new();
    let mut ran: Vec<&str> = Vec::new();
    for (name, section) in all {
        if !wants(name) {
            continue;
        }
        ran.push(name);
        match section.await {
            Ok(v) => findings.extend(v),
            // A section that fails is reported by omission from `ran`, not by a
            // silent zero penalty that would flatter the score.
            Err(e) => {
                tracing::warn!("{name} audit failed: {e:#}");
                ran.retain(|r| *r != name);
            }
        }
    }

    let startup = if wants("startup") {
        ran.push("startup");
        collectors.audit_startup().await.unwrap_or_default()
    } else {
        Vec::new()
    };
    let tasks = if wants("scheduled_tasks") {
        ran.push("scheduled_tasks");
        collectors.audit_scheduled_tasks().await.unwrap_or_default()
    } else {
        Vec::new()
    };

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
        "sections": ran,
        "partial": sections.is_some(),
    }))
}

/// Runs every audit section (the CLI and the default `audit.run` behaviour).
pub async fn run_full_audit(collectors: &dyn PlatformCollectors) -> Result<serde_json::Value> {
    run_audit(collectors, None).await
}
