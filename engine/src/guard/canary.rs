//! Canaries (decoy files): nobody but the user should ever open these.
//! A touch (open/rename/delete) on a decoy is a CRITICAL event.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

use crate::guard::GuardEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryConfig {
    pub paths: Vec<String>,
}

fn config_path() -> PathBuf {
    crate::settings::Settings::base_dir().join("canaries.json")
}

pub fn load_config() -> CanaryConfig {
    let p = config_path();
    if let Ok(text) = std::fs::read_to_string(&p)
        && let Ok(c) = serde_json::from_str(&text) {
            return c;
        }
    // Default decoys: user documents/desktop.
    let mut paths = Vec::new();
    if let Ok(user) = std::env::var("USERPROFILE") {
        paths.push(format!("{user}\\Documents\\invoice_2026_q4.xlsx.canary"));
        paths.push(format!("{user}\\Documents\\wallet_backup.txt.canary"));
        paths.push(format!("{user}\\Desktop\\~important.lnk.canary"));
    }
    CanaryConfig { paths }
}

pub fn save_config(cfg: &CanaryConfig) -> Result<()> {
    let p = config_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).context("create MICS dir")?;
    }
    std::fs::write(&p, serde_json::to_string_pretty(cfg)?).context("write canaries.json")?;
    Ok(())
}

/// Creates any missing decoy files on disk.
pub fn deploy_decoys() -> Result<usize> {
    let cfg = load_config();
    let mut created = 0;
    for path in &cfg.paths {
        let p = PathBuf::from(path);
        if !p.exists() {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(
                &p,
                "MIF canary decoy file. If any program reads this file, something is wrong.\n",
            )
            .with_context(|| format!("create decoy {path}"))?;
            created += 1;
        }
    }
    Ok(created)
}

pub fn list_decoys() -> Vec<(String, bool)> {
    load_config()
        .paths
        .iter()
        .map(|p| (p.clone(), PathBuf::from(p).exists()))
        .collect()
}

type Snapshot = HashMap<String, (i64, u64)>;
static BASELINE: Mutex<Option<Snapshot>> = Mutex::new(None);

fn snapshot_now(cfg: &CanaryConfig) -> Snapshot {
    let mut map = HashMap::new();
    for p in &cfg.paths {
        let (mtime, size) = std::fs::metadata(p)
            .and_then(|m| {
                m.modified().map(|t| {
                    (
                        t.duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0),
                        m.len(),
                    )
                })
            })
            .unwrap_or((0, 0));
        map.insert(p.clone(), (mtime, size));
    }
    map
}

/// Captures the pristine state of every decoy. Called once by the guard loop.
pub fn arm_watchers() -> Result<()> {
    let _ = deploy_decoys();
    let cfg = load_config();
    let snap = snapshot_now(&cfg);
    let stored_len = snap.len();
    *BASELINE.lock().unwrap() = Some(snap);
    info!("Canary watchers armed over {} decoy file(s)", stored_len);
    Ok(())
}

/// Called every guard poll: any decoy whose mtime/size changed was touched.
pub fn check_touches() {
    let Some(baseline) = BASELINE.lock().unwrap().clone() else {
        return;
    };
    let cfg = load_config();
    let now = snapshot_now(&cfg);
    for (path, current) in &now {
        match baseline.get(path) {
            Some(baseline_state) if baseline_state == current => continue,
            _ => {}
        }
        emit(GuardEvent {
            r#type: "canary_triggered".into(),
            severity: "critical".into(),
            rule_id: "CANARY".into(),
            rule_name: "Decoy file touched".into(),
            pid: 0,
            process: String::new(),
            parent: String::new(),
            detail: format!("{path} was accessed/modified — something opened your decoy!"),
            at: chrono::Utc::now().timestamp(),
        });
        warn!("CANARY TRIGGERED: {path}");
    }
    *BASELINE.lock().unwrap() = Some(now);
}

fn emit(ev: GuardEvent) {
    crate::guard::emit_public(ev);
}
