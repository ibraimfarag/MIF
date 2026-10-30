//! Reports: export the full security picture as a Markdown report.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub async fn export_markdown() -> Result<PathBuf> {
    let collectors = crate::platform::windows::collectors::WindowsCollectors;
    let report = crate::platform::traits::run_full_audit(&collectors).await?;
    let incidents = crate::smart::correlator::list_incidents(20)?;

    let mut md = String::new();
    md.push_str("# MIF Security Report\n\n");
    md.push_str(&format!(
        "_Generated: {}_\n\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M")
    ));
    md.push_str(&format!(
        "## Security Score: {}/100\n\n",
        report["score"].as_i64().unwrap_or(0)
    ));

    md.push_str("## Audit Findings\n\n| Section | Item | Status | Severity | Details |\n|---|---|---|---|---|\n");
    if let Some(findings) = report["findings"].as_array() {
        for f in findings {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                f["section"].as_str().unwrap_or(""),
                f["item"].as_str().unwrap_or(""),
                f["status"].as_str().unwrap_or(""),
                f["severity"].as_str().unwrap_or(""),
                f["description"].as_str().unwrap_or("").replace('|', "/")
            ));
        }
    }

    md.push_str("\n## Startup Entries\n\n");
    if let Some(items) = report["startup_entries"].as_array() {
        for s in items {
            md.push_str(&format!(
                "- **{}** [{}] — `{}`\n",
                s["name"].as_str().unwrap_or(""),
                s["location"].as_str().unwrap_or(""),
                s["command"].as_str().unwrap_or("")
            ));
        }
    }

    md.push_str("\n## Incidents (kill-chain timelines)\n\n");
    if incidents.is_empty() {
        md.push_str("_No incidents recorded._\n");
    }
    for inc in incidents {
        md.push_str(&format!(
            "### #{} — {} ({}{})\n\n",
            inc.incident_id,
            inc.title,
            inc.severity,
            if inc.closed { ", closed" } else { ", open" }
        ));
        for ev in &inc.timeline {
            let t = chrono::DateTime::from_timestamp(ev.at, 0)
                .map(|d| d.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
                .unwrap_or_default();
            md.push_str(&format!(
                "- `{}` {} — {} ({})\n",
                t,
                ev.rule_id,
                ev.detail,
                ev.severity
            ));
        }
        md.push('\n');
    }

    let dir = export_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "mics-report-{}.md",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(&path, md).context("write report")?;
    Ok(path)
}

pub fn export_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(|u| PathBuf::from(u).join("Documents").join("MICS-Reports"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\reports"))
}
