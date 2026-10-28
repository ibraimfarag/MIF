//! IDS minimal mode (L2, blocklist-based): enforces a domain blocklist on DNS
//! by managing a marked section of the system hosts file. Domains in the list
//! resolve to 0.0.0.0 — every app on the machine is blocked from them, no
//! driver needed. Full Suricata integration stays a later upgrade.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;

pub mod geoip;

use crate::storage::sqlite::Storage;

const MARK_BEGIN: &str = "# BEGIN MICS-IDS (managed — do not edit)";
const MARK_END: &str = "# END MICS-IDS";

fn hosts_path() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
}

#[derive(Debug, Serialize)]
pub struct IdsStatus {
    pub blocked_domains: Vec<String>,
    pub hosts_managed: bool,
}

pub fn status() -> Result<IdsStatus> {
    let content = std::fs::read_to_string(hosts_path()).unwrap_or_default();
    let blocked = managed_section(&content)
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(String::from)
        .collect();
    Ok(IdsStatus {
        blocked_domains: blocked,
        hosts_managed: content.contains(MARK_BEGIN),
    })
}

fn managed_section(content: &str) -> String {
    let Some(start) = content.find(MARK_BEGIN) else {
        return String::new();
    };
    let body = &content[start + MARK_BEGIN.len()..];
    let end = body.find(MARK_END).unwrap_or(body.len());
    body[..end].to_string()
}

fn rewrite_hosts(_content: &str, new_section: &str) -> Result<()> {
    let path = hosts_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Snapshot before any change (rollback-friendly, like hardening).
    let storage = Storage::open()?;
    storage.save_hardening_snapshot("ids_hosts", &existing)?;

    let mut out = String::new();
    match existing.find(MARK_BEGIN) {
        Some(start) => {
            out.push_str(&existing[..start]);
            let tail = &existing[start..];
            let after_end = tail
                .find(MARK_END)
                .map(|i| tail[i + MARK_END.len()..].to_string())
                .unwrap_or_default();
            if !new_section.trim().is_empty() {
                out.push_str(MARK_BEGIN);
                out.push('\n');
                out.push_str(new_section);
                if !new_section.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(MARK_END);
            }
            out.push_str(&after_end);
        }
        None => {
            out.push_str(existing.trim_end());
            out.push_str("\n\n");
            if !new_section.trim().is_empty() {
                out.push_str(MARK_BEGIN);
                out.push('\n');
                out.push_str(new_section);
                if !new_section.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(MARK_END);
                out.push('\n');
            }
        }
    }

    // hosts is admin-owned; write via elevated PowerShell.
    let tmp = std::env::temp_dir().join("mics_hosts_new");
    std::fs::write(&tmp, &out).context("write temp hosts")?;
    let ps_arg = format!(
        "Start-Process -FilePath cmd -ArgumentList @('/c','copy /Y \\'{}\\' \\'{}\\'') -Verb RunAs -Wait -WindowStyle Hidden",
        tmp.display(),
        path.display()
    );
    let out2 = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_arg])
        .output()
        .context("elevated hosts copy")?;
    if !out2.status.success() {
        anyhow::bail!(
            "hosts update failed: {}",
            String::from_utf8_lossy(&out2.stderr).trim()
        );
    }
    Ok(())
}

/// Adds domains to the DNS blocklist (idempotent).
pub fn add_domains(domains: &[String]) -> Result<usize> {
    let content = std::fs::read_to_string(hosts_path()).unwrap_or_default();
    let mut existing: Vec<String> = managed_section(&content)
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1).map(String::from))
        .collect();
    let mut added = 0;
    let mut lines = String::new();
    for d in domains {
        let d = d.trim().to_lowercase();
        if d.is_empty() || existing.iter().any(|e| e == &d) {
            continue;
        }
        lines.push_str(&format!("0.0.0.0 {d}\n"));
        existing.push(d);
        added += 1;
    }
    if added > 0 {
        let mut section = managed_section(&content);
        section.push_str(&lines);
        rewrite_hosts(&content, &section)?;
        let storage = Storage::open()?;
        for d in domains {
            let _ = storage.add_ioc_domain(&d.trim().to_lowercase(), "ids_manual");
        }
    }
    Ok(added)
}

/// Removes one domain from the blocklist.
pub fn remove_domain(domain: &str) -> Result<()> {
    let content = std::fs::read_to_string(hosts_path()).unwrap_or_default();
    let section = managed_section(&content);
    let new_section: String = section
        .lines()
        .filter(|l| {
            !l.split_whitespace()
                .nth(1)
                .map(|d| d.eq_ignore_ascii_case(domain))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>()
        .join("\n");
    rewrite_hosts(&content, &new_section)?;
    Ok(())
}

/// Imports a blocklist file (one domain per line, # comments).
pub fn import_blocklist(path: &str) -> Result<usize> {
    let text = std::fs::read_to_string(path).context("read blocklist")?;
    let domains: Vec<String> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().last().unwrap_or(l).to_string())
        .collect();
    add_domains(&domains)
}
