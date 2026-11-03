use serde::{Deserialize, Serialize};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::{LazyLock, Mutex};

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

/// Parses `params.merge` for `audit.run`.
///
/// `true` means "re-read the named sections and merge them into the last full
/// audit", so the caller gets a *complete* report whose score is comparable with
/// the one the dashboard already showed. A partial report cannot be a base, and a
/// merge with nothing to re-read would be a full audit, so both are refused
/// rather than guessed.
pub fn merge_requested(
    params: Option<&serde_json::Value>,
    sections: Option<&[String]>,
) -> Result<bool> {
    let Some(value) = params.and_then(|p| p.get("merge")) else {
        return Ok(false);
    };
    let Some(merge) = value.as_bool() else {
        anyhow::bail!("\"merge\" must be true or false, not {value}");
    };
    if merge && sections.is_none() {
        anyhow::bail!(
            "\"merge\" needs \"sections\": re-reading nothing is a full audit, not a merge"
        );
    }
    Ok(merge)
}

/// The position of a section in the report: `AUDIT_SECTIONS` order, then the
/// inventory lists (which are not in that list).
fn section_rank(id: &str) -> usize {
    AUDIT_SECTIONS
        .iter()
        .position(|s| *s == id)
        .unwrap_or(AUDIT_SECTIONS.len())
}

/// One audit pass, grouped by the section id that produced each finding.
///
/// Grouping by id — not by the finding's display `section` — is what makes a
/// merge correct: `rdp` and `remote_tools` both report under "Remote Access", so
/// re-reading one must not erase the other's findings.
#[derive(Debug, Clone, Default)]
pub struct AuditPass {
    /// Check findings per section id, in `AUDIT_SECTIONS` order.
    pub checks: Vec<(String, Vec<AuditFinding>)>,
    /// Inventory lists: `None` when that section did not run in this pass.
    pub startup: Option<Vec<StartupEntry>>,
    pub scheduled_tasks: Option<Vec<ScheduledTaskEntry>>,
    /// Unix seconds at which each section was collected, by section id.
    ///
    /// A merge only re-reads the sections the caller named, so the rest of the
    /// report is as old as the full audit it came from. Carrying the timestamp
    /// with the section is what lets the UI show that age instead of presenting
    /// an old check as a fresh one (`و4`): the alternative - one timestamp for
    /// the whole report - would be right only for sections that were re-read.
    pub stamps: std::collections::BTreeMap<String, i64>,
}

impl AuditPass {
    /// Replaces (or inserts, in report order) one section's findings.
    fn set(&mut self, id: &str, findings: Vec<AuditFinding>) {
        match self.checks.iter_mut().find(|(existing, _)| existing == id) {
            Some(slot) => slot.1 = findings,
            None => {
                self.checks.push((id.to_string(), findings));
                self.checks.sort_by_key(|(id, _)| section_rank(id));
            }
        }
    }

    /// Drops a section entirely: a collector that failed on a re-read must not
    /// leave its previous finding behind, pretending to be fresh.
    fn drop_section(&mut self, id: &str) {
        self.checks.retain(|(existing, _)| existing != id);
    }

    /// Reduces the pass to the report shape the UI and the CLI read.
    ///
    /// `partial` is true when only a subset of the checks ran. `refreshed` names
    /// the sections a merge re-read just now, which is what makes a complete
    /// report explainable rather than suspiciously identical.
    pub fn report(&self, partial: bool, refreshed: &[String]) -> serde_json::Value {
        let findings: Vec<&AuditFinding> = self
            .checks
            .iter()
            .flat_map(|(_, section)| section.iter())
            .collect();
        let mut penalty = 0u32;
        for f in &findings {
            if f.status.is_insecure() {
                penalty += f.severity.penalty();
            }
        }
        let score = 100u32.saturating_sub(penalty.min(100));
        let ran: Vec<&str> = self
            .checks
            .iter()
            .map(|(id, _)| id.as_str())
            .chain(self.startup.is_some().then_some("startup"))
            .chain(self.scheduled_tasks.is_some().then_some("scheduled_tasks"))
            .collect();
        // A finding carries the id of the section that produced it: the display
        // name is not unique (`rdp` and `remote_tools` both report under "Remote
        // Access"), and the UI has to look up that section's age.
        let findings: Vec<serde_json::Value> = self
            .checks
            .iter()
            .flat_map(|(id, section)| {
                section.iter().map(move |f| {
                    serde_json::json!({
                        "id": id,
                        "section": f.section,
                        "item": f.item,
                        "status": f.status,
                        "severity": f.severity,
                        "description": f.description,
                        "fix_available": f.fix_available,
                    })
                })
            })
            .collect();
        serde_json::json!({
            "score": score,
            "findings": findings,
            "startup_entries": self.startup.clone().unwrap_or_default(),
            "scheduled_tasks": self.scheduled_tasks.clone().unwrap_or_default(),
            "sections": ran,
            // What each section cost in wall-clock time: `{id: unix seconds}`,
            // exactly for the sections that ran in *this* pass. A merge keeps the
            // base's stamp for everything it did not re-read.
            "section_times": self.stamps,
            "partial": partial,
            "merged": !refreshed.is_empty(),
            "refreshed": refreshed,
        })
    }
}

/// Runs the requested audit sections and groups what ran by section id.
///
/// Never fails: a broken collector is logged and its section is omitted from the
/// report (the score must never silently count a check that did not run).
pub async fn collect_audit(
    collectors: &dyn PlatformCollectors,
    sections: Option<&[String]>,
) -> AuditPass {
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
    let mut pass = AuditPass::default();
    for (name, section) in all {
        if !wants(name) {
            continue;
        }
        match section.await {
            Ok(findings) => {
                pass.checks.push((name.to_string(), findings));
                pass.stamps.insert(name.to_string(), collected_at());
            }
            Err(e) => {
                tracing::warn!("{name} audit failed: {e:#}");
            }
        }
    }
    pass.checks.sort_by_key(|(id, _)| section_rank(id));

    if wants("startup") {
        pass.startup = Some(collectors.audit_startup().await.unwrap_or_default());
        pass.stamps.insert("startup".to_string(), collected_at());
    }
    if wants("scheduled_tasks") {
        pass.scheduled_tasks = Some(collectors.audit_scheduled_tasks().await.unwrap_or_default());
        pass.stamps
            .insert("scheduled_tasks".to_string(), collected_at());
    }
    pass
}

/// When a section finished, in unix seconds. A clock that is set back after the
/// fact only makes a section look older than it is, which is the safe direction
/// for a "not re-checked since" line.
fn collected_at() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The last full audit, so a section re-check can be merged into a complete
/// report instead of replacing it with an uncomparable partial one.
#[derive(Debug, Default)]
pub struct AuditCache {
    last_full: Option<AuditPass>,
}

impl AuditCache {
    /// Remembers a full audit as the base for later merges.
    pub fn remember(&mut self, pass: AuditPass) {
        self.last_full = Some(pass);
    }

    /// Re-reads `fresh`'s sections on top of the remembered full audit and
    /// returns the complete report. One definition of the score, over every
    /// section, so a fix cannot flatter or spoil it.
    pub fn merge(&mut self, fresh: AuditPass, refreshed: &[String]) -> Result<serde_json::Value> {
        let Some(base) = self.last_full.as_mut() else {
            anyhow::bail!(
                "no full audit to merge into — run the full audit first (a partial \
                 report is not a base)"
            );
        };
        for id in refreshed {
            // A refreshed section is as new as its re-read; a section the merge
            // could not re-read (its collector failed) has no stamp any more, so
            // it cannot be presented as fresh either.
            match fresh.stamps.get(id) {
                Some(ts) => {
                    base.stamps.insert(id.clone(), *ts);
                }
                None => {
                    base.stamps.remove(id);
                }
            }
            match id.as_str() {
                "startup" => {
                    if fresh.startup.is_some() {
                        base.startup = fresh.startup.clone();
                    }
                }
                "scheduled_tasks" => {
                    if fresh.scheduled_tasks.is_some() {
                        base.scheduled_tasks = fresh.scheduled_tasks.clone();
                    }
                }
                _ => match fresh.checks.iter().find(|(fid, _)| fid == id) {
                    Some((_, findings)) => base.set(id, findings.clone()),
                    None => base.drop_section(id),
                },
            }
        }
        Ok(base.report(false, refreshed))
    }
}

/// The engine serves one UI session, so one process-wide cache is enough.
static AUDIT_CACHE: LazyLock<Mutex<AuditCache>> =
    LazyLock::new(|| Mutex::new(AuditCache::default()));

/// Runs `f` with the engine's audit cache. A poisoned lock (a panic elsewhere)
/// must not take the audit down with it, so the guard is recovered instead of
/// unwrapped — and the lock is never held across an await: callers collect the
/// sections first, then merge.
pub fn with_audit_cache<T>(f: impl FnOnce(&mut AuditCache) -> T) -> T {
    let mut guard = AUDIT_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
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
    let pass = collect_audit(collectors, sections).await;
    Ok(pass.report(sections.is_some(), &[]))
}

/// Runs every audit section (the CLI and the default `audit.run` behaviour).
pub async fn run_full_audit(collectors: &dyn PlatformCollectors) -> Result<serde_json::Value> {
    run_audit(collectors, None).await
}
