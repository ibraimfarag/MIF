//! Scanner v1: triage-ordered directory scan.
//! Order: SHA-256 vs local IOC cache first (cheap), then YARA. Files are
//! scored by the triage engine so the riskiest are examined first.

pub mod vt;
pub mod yara_engine;
pub mod quarantine;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use walkdir::WalkDir;

use crate::scanner::quarantine::QuarantineManager;
use crate::scanner::yara_engine::YaraEngine;
use crate::storage::sqlite::Storage;

#[derive(Debug, Serialize, Clone)]
pub struct ScanFinding {
    pub path: String,
    pub sha256: String,
    pub reason: String,   // ioc_hash:<source> | yara:<rule>
    pub severity: String, // critical | high
    pub triage_score: u32,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub path: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub findings: Vec<ScanFinding>,
    pub duration_ms: u128,
    pub stopped: bool,
}

pub struct ScanStop(AtomicBool);

impl ScanStop {
    fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

static SCAN_STOP: std::sync::OnceLock<ScanStop> = std::sync::OnceLock::new();

pub fn stop_active_scan() -> bool {
    SCAN_STOP.get().map(|s| s.stop()).is_some()
}

const MAX_FILE_BYTES: u64 = 200 * 1024 * 1024; // 200 MB
const MAX_FILES: usize = 50_000;

pub fn starter_rules_source() -> String {
    // Prefer rules/ next to the exe (packaged layout), then the dev repo.
    for base in [
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.to_path_buf())),
        std::env::var("MICS_RULES_DIR").ok().map(PathBuf::from),
        std::env::current_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        let p = base.join("rules").join("yara").join("starter.yar");
        if p.exists() {
            if let Ok(s) = std::fs::read_to_string(&p) {
                return s;
            }
        }
    }
    include_str!("../../rules/yara/starter.yar").to_string()
}

/// Triage priority: location × extension × size × age. Higher = scan first.
pub fn triage_score(path: &Path) -> u32 {
    let mut score = 0u32;
    let lowered = path.to_string_lossy().to_lowercase();
    if lowered.contains("\\temp\\") || lowered.contains("\\appdata\\") {
        score += 50;
    }
    if lowered.contains("\\downloads\\") {
        score += 30;
    }
    if lowered.starts_with("\\\\") {
        score += 20;
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
    {
        Some(ext) => match ext.as_str() {
            "exe" | "dll" | "scr" | "com" | "pif" => score += 30,
            "vbs" | "js" | "ps1" | "bat" | "cmd" | "hta" => score += 25,
            "lnk" | "iso" | "img" => score += 15,
            "zip" | "rar" | "7z" => score += 8,
            _ => {}
        },
        None => score += 5,
    }
    if let Ok(meta) = std::fs::metadata(path) {
        let size = meta.len();
        if size < 4096 && lowered.ends_with(".exe") {
            score += 20; // tiny executables are classic droppers
        }
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = std::time::SystemTime::now().duration_since(modified) {
                if age.as_secs() < 86_400 {
                    score += 10; // created/modified in the last 24h
                }
            }
        }
    }
    score
}

pub async fn run_scan(root: &Path, quarantine: bool) -> Result<ScanReport> {
    let start = std::time::Instant::now();
    // Reset / register the stop flag for this scan.
    let stop_cell = SCAN_STOP.get_or_init(ScanStop::new);
    stop_cell.0.store(false, Ordering::SeqCst);

    // YARA's Rules is !Send, so the whole CPU-bound scan loop runs inside a
    // blocking task; findings come back and quarantine happens async after.
    let root_owned = root.to_path_buf();
    let storage = Storage::open()?;
    let ioc_hashes = storage.dump_ioc_hashes()?;
    let (findings, files_scanned, files_skipped, stopped) =
        tokio::task::spawn_blocking(move || -> Result<_> {
            let rules_src = starter_rules_source();
            let yara = YaraEngine::new(&rules_src)
                .context("compile starter YARA rules")?;
            let stop = SCAN_STOP.get_or_init(ScanStop::new);

            let mut queue: Vec<(u32, PathBuf)> = Vec::new();
            let mut files_skipped = 0usize;
            for entry in WalkDir::new(&root_owned)
                .follow_links(false)
                .max_open(64)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if stop.stopped() {
                    break;
                }
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path().to_path_buf();
                let big = entry
                    .metadata()
                    .map(|m| m.len() > MAX_FILE_BYTES)
                    .unwrap_or(true);
                if big {
                    files_skipped += 1;
                    continue;
                }
                queue.push((triage_score(&path), path));
                if queue.len() >= MAX_FILES {
                    break;
                }
            }
            queue.sort_by(|a, b| b.0.cmp(&a.0));

            let mut findings: Vec<ScanFinding> = Vec::new();
            let mut files_scanned = 0usize;
            for (score, path) in &queue {
                if stop.stopped() {
                    break;
                }
                let Ok(data) = std::fs::read(path) else {
                    files_skipped += 1;
                    continue;
                };
                files_scanned += 1;
                let hash = hex::encode(Sha256::digest(&data));

                // 1) IOC hash cache (works fully offline).
                if let Some(source) = ioc_hashes.get(&hash) {
                    findings.push(ScanFinding {
                        path: path.to_string_lossy().to_string(),
                        sha256: hash,
                        reason: format!("ioc_hash:{source}"),
                        severity: "critical".into(),
                        triage_score: *score,
                    });
                    continue;
                }

                // 2) YARA rules.
                if let Ok(matches) = yara.scan_bytes(&data) {
                    if !matches.is_empty() {
                        let severity = if matches
                            .iter()
                            .any(|m| m.contains("EICAR") || m.contains("TestMalware"))
                        {
                            "critical"
                        } else {
                            "high"
                        };
                        findings.push(ScanFinding {
                            path: path.to_string_lossy().to_string(),
                            sha256: hash,
                            reason: format!("yara:{}", matches.join(",")),
                            severity: severity.into(),
                            triage_score: *score,
                        });
                    }
                }
            }
            let stopped = stop.stopped();
            Ok((findings, files_scanned, files_skipped, stopped))
        })
        .await
        .context("scan task panicked")??;

    // Quarantine phase (async IO) — only when requested.
    if quarantine {
        if let Ok(qm) = QuarantineManager::new() {
            for f in &findings {
                let _ = qm.quarantine_file(Path::new(&f.path), &f.reason).await;
            }
        }
    } else {
        // Offer a one-tap quarantine from the toast for critical findings.
        for f in findings.iter().filter(|f| f.severity == "critical").take(3) {
            let _ = crate::notify::toast::show_toast_for_file(
                "🛡️ MI CS — Threat found",
                &format!("{} — {}", f.path, f.reason),
                &["Quarantine", "Open MI CS"],
                Some(f.path.clone()),
            );
        }
    }

    Ok(ScanReport {
        path: root.to_string_lossy().to_string(),
        files_scanned,
        files_skipped,
        findings,
        duration_ms: start.elapsed().as_millis(),
        stopped,
    })
}
