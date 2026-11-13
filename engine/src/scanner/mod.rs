//! Scanner v1: triage-ordered directory scan, run as a resumable job.
//!
//! Order: SHA-256 vs local IOC cache first (cheap), then YARA. Files are
//! scored by the triage engine so the riskiest are examined first.
//!
//! Persistence contract (see `docs/DECISIONS.md` D-006):
//!  * the triage-ordered queue is written to `job_files` once per job;
//!  * `jobs.processed` is the last queue position that was examined, updated
//!    in small batches, so a crash/restart resumes at the exact file;
//!  * findings are appended to `job_findings` as they are discovered.
//!
//! Nothing about a job lives only in memory, which is what makes
//! "engine restarted mid-scan" a resume instead of a lost scan.

pub mod quarantine;
pub mod yara_engine;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::storage::sqlite::{JobRow, Storage};
use crate::scanner::quarantine::QuarantineManager;
use crate::scanner::yara_engine::YaraEngine;

#[derive(Debug, Serialize, Deserialize, Clone)]
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

const MAX_FILE_BYTES: u64 = 200 * 1024 * 1024; // 200 MB
const MAX_FILES: usize = 50_000;
/// How many queue entries are read per SQLite round-trip / checkpoint.
const BATCH: usize = 64;
/// Enumerate at most this many entries before writing the queue transaction.
const ENUM_CHUNK: usize = 2048;
/// How many individual files may get their own desktop card per scan; the rest
/// are folded into one summary card so a folder of samples cannot bury the
/// desktop in notifications.
const LIVE_ALERTS: usize = 3;

/// Where the schedule remembers its last start (`meta` table, not settings).
const META_LAST_SCHEDULED: &str = "scan.last_scheduled";

/// How often the schedule looks at the clock. A scan interval is measured in
/// hours, so a few minutes of jitter costs nothing and saves a timer per second.
const SCHEDULE_TICK: std::time::Duration = std::time::Duration::from_secs(300);

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
        if p.exists()
            && let Ok(s) = std::fs::read_to_string(&p) {
                // Which file a scan used is evidence about the install, not noise:
                // a package is only complete when this is the shipped `rules\`.
                tracing::info!("YARA rules from {}", p.display());
                return s;
            }
    }
    tracing::info!("YARA rules from the built-in starter pack (no rules\\yara\\starter.yar found)");
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
        if let Ok(modified) = meta.modified()
            && let Ok(age) = std::time::SystemTime::now().duration_since(modified)
                && age.as_secs() < 86_400 {
                    score += 10; // created/modified in the last 24h
                }
    }
    score
}

/// Starts a scan job and returns immediately with its id.
///
/// The heavy loop (YARA compilation + file IO) runs on its own thread because
/// YARA's compiled rules are `!Send`; the returned id is what the UI polls and
/// what the progress notifications carry.
pub fn start_scan(
    root: PathBuf,
    quarantine: bool,
    rt: tokio::runtime::Handle,
) -> Result<String> {
    if crate::jobs::active_count() > 0 {
        anyhow::bail!("a scan job is already running");
    }
    if !root.exists() {
        anyhow::bail!("path does not exist: {}", root.display());
    }
    let job_id = crate::jobs::new_job_id("scan");
    let storage = Storage::open()?;
    storage.create_job(&job_id, "scan", &root.to_string_lossy(), quarantine)?;

    spawn_job_thread(job_id.clone(), root, quarantine, rt);
    Ok(job_id)
}

// ---- the scan schedule (D-027) ----
//
// A scan that runs whether or not the scan screen is open. It is the user's
// switch (`scan_interval_hours`, 0 = off), the engine has to be running for it -
// the logon entry's `--service`, or the app - and it never quarantines: nobody
// chose a file while it was running, so findings are reported and left where
// they are for the user to act on.

/// What the schedule looks like right now, for `scan.schedule` and the UI.
#[derive(Debug, Serialize)]
pub struct ScheduleStatus {
    /// `scan_interval_hours > 0`.
    pub enabled: bool,
    pub interval_hours: u32,
    /// The folder it would walk; `None` when the profile folder cannot be found
    /// either (an engine run without a user profile, e.g. a service account).
    pub target: Option<String>,
    /// Unix seconds of the last scheduled start, `None` = never.
    pub last_started: Option<i64>,
    /// Unix seconds the next one is due; `None` when the schedule is off.
    pub next_due: Option<i64>,
}

/// Whether one is due. Pure so the rule is testable without a clock or a disk:
/// an interval of 0 is off, "never ran" is due, a recorded start in the future
/// (a clock that moved backwards) is due, and otherwise the interval decides.
fn is_due(last: Option<i64>, now: i64, hours: u32) -> bool {
    if hours == 0 {
        return false;
    }
    match last {
        None => true,
        Some(t) if t > now => true,
        Some(t) => now.saturating_sub(t) >= i64::from(hours) * 3_600,
    }
}

/// The folder a scheduled scan walks: the configured one, else the profile.
fn schedule_target(configured: &str) -> Option<PathBuf> {
    let trimmed = configured.trim();
    if !trimmed.is_empty() {
        return Some(PathBuf::from(trimmed));
    }
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn schedule_status() -> ScheduleStatus {
    let settings = crate::settings::current();
    let hours = settings.scan_interval_hours;
    let last = Storage::open()
        .ok()
        .and_then(|s| s.meta_get(META_LAST_SCHEDULED).ok().flatten())
        .and_then(|v| v.parse::<i64>().ok());
    let next_due = if hours == 0 {
        None
    } else {
        Some(match last {
            Some(t) => t + i64::from(hours) * 3_600,
            None => now_unix(),
        })
    };
    ScheduleStatus {
        enabled: hours > 0,
        interval_hours: hours,
        target: schedule_target(&settings.scan_target).map(|p| p.to_string_lossy().into_owned()),
        last_started: last,
        next_due,
    }
}

/// Starts the timer that runs the scan when it falls due.
///
/// Every tick either starts one scan or does nothing: a job already running
/// means "try again next tick" (not a failure to record), and an attempt that
/// could not start - a path that is gone, a scan already running elsewhere -
/// still records the attempt, so a broken target is one log line per interval
/// instead of one every five minutes.
pub fn start_schedule(rt: tokio::runtime::Handle) {
    if std::env::var("MICS_NO_SCAN_SCHEDULE").is_ok() {
        return;
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SCHEDULE_TICK);
        loop {
            ticker.tick().await;
            tick_once(&rt);
        }
    });
}

/// One look at the clock. Returns the job id when it started a scan, which is
/// what the tests assert on.
pub(crate) fn tick_once(rt: &tokio::runtime::Handle) -> Option<String> {
    let settings = crate::settings::current();
    let hours = settings.scan_interval_hours;
    if hours == 0 {
        return None;
    }
    let storage = match Storage::open() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("scheduled scan: cannot open the state database: {e:#}");
            return None;
        }
    };
    let last = storage
        .meta_get(META_LAST_SCHEDULED)
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok());
    let now = now_unix();
    if !is_due(last, now, hours) {
        return None;
    }
    if crate::jobs::active_count() > 0 {
        // A scan is already running (the user's, or a previous scheduled one):
        // not due yet as far as the record is concerned, and not an error.
        return None;
    }
    let target = match schedule_target(&settings.scan_target) {
        Some(p) => p,
        None => {
            tracing::warn!("scheduled scan: no profile folder to scan; set scan_target");
            let _ = storage.meta_set(META_LAST_SCHEDULED, &now.to_string());
            return None;
        }
    };
    let _ = storage.meta_set(META_LAST_SCHEDULED, &now.to_string());
    match start_scan(target.clone(), false, rt.clone()) {
        Ok(job_id) => {
            tracing::info!(
                "scheduled scan started: job {job_id} over {} (every {hours} h, report only)",
                target.display()
            );
            Some(job_id)
        }
        Err(e) => {
            tracing::warn!(
                "scheduled scan over {} did not start: {e:#}",
                target.display()
            );
            None
        }
    }
}

fn run_job(
    job_id: &str,
    root: PathBuf,
    quarantine: bool,
    cancel: Arc<AtomicBool>,
    rt: tokio::runtime::Handle,
) -> Result<()> {
    let storage = Storage::open()?;
    let mut job = storage
        .get_job(job_id)?
        .with_context(|| format!("job {job_id} disappeared"))?;

    // 1) Enumerate once. On resume the persisted queue is reused as-is, so the
    //    order (and therefore `processed`) stays meaningful.
    if job.total == 0 {
        enumerate(&storage, job_id, &root)?;
        job = storage.get_job(job_id)?.context("job vanished after enumerate")?;
    }
    storage.set_job_state(job_id, "running", None)?;

    let rules_src = starter_rules_source();
    let yara = YaraEngine::new(&rules_src).context("compile starter YARA rules")?;
    let ioc_hashes = storage.dump_ioc_hashes()?;

    let mut processed = job.processed;
    let mut scanned = job.scanned;
    let mut skipped = job.skipped;
    let mut findings = job.findings_count;
    let mut state = "done";
    // Paths already announced on the desktop during this run, so a finding is
    // never carded twice (once live, once in the summary).
    let mut alerted: Vec<String> = Vec::new();

    crate::jobs::progress(
        job_id, "running", pct(processed, job.total), "scanning", scanned, skipped,
        job.total, findings,
    );

    loop {
        if cancel.load(Ordering::SeqCst) {
            state = "cancelled";
            break;
        }
        let batch = storage.job_files_after(job_id, processed, BATCH)?;
        if batch.is_empty() {
            break;
        }
        for (seq, path, score) in batch {
            if cancel.load(Ordering::SeqCst) {
                state = "cancelled";
                break;
            }
            let p = PathBuf::from(&path);
            match std::fs::read(&p) {
                Ok(data) => {
                    scanned += 1;
                    let hash = hex::encode(Sha256::digest(&data));
                    let mut hit: Option<ScanFinding> = None;

                    if let Some(source) = ioc_hashes.get(&hash) {
                        hit = Some(ScanFinding {
                            path: path.clone(),
                            sha256: hash.clone(),
                            reason: format!("ioc_hash:{source}"),
                            severity: "critical".into(),
                            triage_score: score as u32,
                        });
                    } else if let Ok(matches) = yara.scan_bytes(&data)
                        && !matches.is_empty() {
                            let severity = if matches
                                .iter()
                                .any(|m| m.contains("EICAR") || m.contains("TestMalware"))
                            {
                                "critical"
                            } else {
                                "high"
                            };
                            hit = Some(ScanFinding {
                                path: path.clone(),
                                sha256: hash.clone(),
                                reason: format!("yara:{}", matches.join(",")),
                                severity: severity.into(),
                                triage_score: score as u32,
                            });
                        }

                    if let Some(f) = hit {
                        findings += 1;
                        storage.add_job_finding(job_id, seq, &serde_json::to_string(&f)?)?;
                        // Tell the user as it happens, not minutes later when
                        // the whole tree has been walked. Auto-quarantine runs
                        // silently: the card would only name a file the user
                        // then cannot find.
                        if !quarantine && alerted.len() < LIVE_ALERTS {
                            crate::notify::alert::threat(&f.severity, &f.path, &f.reason);
                            alerted.push(f.path.clone());
                        }
                    }
                }
                Err(_) => skipped += 1,
            }
            processed = seq;
        }

        storage.set_job_progress(job_id, processed, scanned, skipped, findings)?;
        crate::jobs::progress(
            job_id,
            "running",
            pct(processed, job.total),
            "scanning",
            scanned,
            skipped,
            job.total,
            findings,
        );
        if state == "cancelled" {
            break;
        }
    }

    storage.set_job_progress(job_id, processed, scanned, skipped, findings)?;
    storage.set_job_state(job_id, state, None)?;

    // 2) Quarantine / notify only for a completed run.
    let found: Vec<ScanFinding> = storage
        .job_findings(job_id)?
        .iter()
        .filter_map(|t| serde_json::from_str(t).ok())
        .collect();

    if state == "done" {
        if quarantine {
            let mut stored = 0usize;
            if let Ok(qm) = QuarantineManager::new() {
                for f in &found {
                    let path = Path::new(&f.path);
                    // The product is never quarantined, and neither is a copy of
                    // it: the rules match our engine because it contains the
                    // strings they look for, and it carries the same certificate
                    // that signed this engine.
                    if is_product_file(path) || signed_by_us(path) {
                        tracing::warn!("keeping own file out of quarantine: {}", f.path);
                        continue;
                    }
                    if rt.block_on(qm.quarantine_file(path, &f.reason)).is_ok() {
                        stored += 1;
                    }
                }
            }
            if stored > 0 {
                crate::notify::alert::quarantined(stored);
            }
        } else {
            // Findings that appeared after the live-alert budget (or that were
            // not worth their own card) still deserve one summary.
            let remaining: Vec<(String, String, String)> = found
                .iter()
                .filter(|f| f.severity == "critical" || f.severity == "high")
                .filter(|f| !alerted.iter().any(|p| p == &f.path))
                .take(LIVE_ALERTS)
                .map(|f| (f.severity.clone(), f.path.clone(), f.reason.clone()))
                .collect();
            for (severity, path, reason) in remaining {
                crate::notify::alert::threat(&severity, &path, &reason);
                alerted.push(path);
            }
            if found.len() > alerted.len() {
                crate::notify::alert::threats_summary(found.len());
            }
        }
    }

    crate::jobs::progress(
        job_id,
        state,
        if state == "done" { 100 } else { pct(processed, job.total) },
        state,
        scanned,
        skipped,
        job.total,
        findings,
    );
    crate::jobs::finished(job_id, state, findings);
    Ok(())
}

fn pct(processed: i64, total: i64) -> u32 {
    if total <= 0 {
        return 0;
    }
    ((processed as f64 / total as f64) * 100.0).clamp(0.0, 100.0) as u32
}

/// Files the scanner must never judge: the YARA rules themselves, the `rules\`
/// tree we ship, and this engine's own image.
///
/// A rules file *is* the patterns it matches, and the engine carries the command
/// strings those patterns look for (`certutil -urlcache`, `DownloadString`,
/// `mshta`), so the two match each other by construction. Scanning them reported
/// the product as a threat and - because findings are quarantined without asking
/// - moved its own engine and rules out of the package they were run from.
///
/// A *copy* of the package is settled at the quarantine itself, by
/// [`signed_by_us`]: its path is not ours, but its certificate is.
fn is_product_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if ext == "yar" || ext == "yara" {
            return true;
        }
    }
    // Our own package: the layout the release is unpacked into, where `rules\`
    // sits beside the exe. A user's own `rules\` folder is not ours to skip, so
    // this is anchored on where this engine is running from.
    if let Ok(own) = std::env::current_exe() {
        if let Some(dir) = own.parent() {
            if path.starts_with(dir.join("rules")) || path == own {
                return true;
            }
        }
    }
    false
}

/// Whether `path` carries the signer this engine is signed with.
///
/// Our binaries are signed with the release certificate, so a package the user
/// copied elsewhere and pointed a scan at is still the product - not something
/// the product should quarantine out from under them.
fn signed_by_us(path: &Path) -> bool {
    use crate::platform::windows::signature::embedded_signer_thumbprint;
    let Ok(own) = std::env::current_exe() else {
        return false;
    };
    let Some(ours) = embedded_signer_thumbprint(&own) else {
        return false;
    };
    matches!(
        embedded_signer_thumbprint(path),
        Some(theirs) if theirs.eq_ignore_ascii_case(&ours)
    )
}

/// Walks the root, scores every file, and persists the queue in one batch.
fn enumerate(storage: &Storage, job_id: &str, root: &Path) -> Result<()> {
    let mut queue: Vec<(i64, String, i64)> = Vec::new();
    let mut skipped = 0i64;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_open(64)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        // The product is not a suspect; see `is_product_file`.
        if is_product_file(path) {
            skipped += 1;
            continue;
        }
        let too_big = entry
            .metadata()
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(true);
        if too_big {
            skipped += 1;
            continue;
        }
        queue.push((
            0,
            path.to_string_lossy().to_string(),
            triage_score(path) as i64,
        ));
        if queue.len() >= MAX_FILES {
            break;
        }
    }
    // Riskiest first; ties broken by path so the order is stable across runs.
    queue.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
    for (i, item) in queue.iter_mut().enumerate() {
        item.0 = i as i64 + 1; // seq is 1-based so `processed = 0` means "nothing yet"
    }
    let total = queue.len() as i64;
    for chunk in queue.chunks(ENUM_CHUNK) {
        storage.set_job_files(job_id, chunk)?;
    }
    storage.set_job_total(job_id, total)?;
    storage.set_job_progress(job_id, 0, 0, skipped, 0)?;
    tracing::info!("job {job_id}: enumerated {total} file(s), skipped {skipped}");
    Ok(())
}

/// Resumes every job that was in flight when the engine stopped.
pub fn resume_interrupted(rt: tokio::runtime::Handle) -> usize {
    let storage = match Storage::open() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("resume: cannot open storage: {e:#}");
            return 0;
        }
    };
    let jobs: Vec<JobRow> = storage.resumable_jobs().unwrap_or_default();
    let mut resumed = 0;
    for job in jobs {
        if job.kind != "scan" {
            continue;
        }
        let root = PathBuf::from(&job.root);
        if !root.exists() {
            let _ = storage.set_job_state(
                &job.job_id,
                "failed",
                Some("scan root no longer exists"),
            );
            continue;
        }
        spawn_job_thread(job.job_id.clone(), root, job.quarantine, rt.clone());
        resumed += 1;
    }
    resumed
}

/// Resumes one specific job (used by `job.resume`). Returns false when the job
/// is unknown or already finished.
pub fn resume_job(job_id: &str, rt: tokio::runtime::Handle) -> Result<bool> {
    if crate::jobs::active_count() > 0 {
        anyhow::bail!("another job is running");
    }
    let storage = Storage::open()?;
    let Some(job) = storage.get_job(job_id)? else {
        return Ok(false);
    };
    if !matches!(
        job.state.as_str(),
        "interrupted" | "queued" | "running" | "cancelled"
    ) {
        return Ok(false);
    }
    let root = PathBuf::from(&job.root);
    if !root.exists() {
        anyhow::bail!("scan root no longer exists: {}", job.root);
    }
    spawn_job_thread(job.job_id.clone(), root, job.quarantine, rt);
    Ok(true)
}

fn spawn_job_thread(job_id: String, root: PathBuf, quarantine: bool, rt: tokio::runtime::Handle) {
    let flag = crate::jobs::register(&job_id);
    std::thread::spawn(move || {
        tracing::info!("running job {job_id}");
        if let Err(e) = run_job(&job_id, root, quarantine, flag, rt) {
            tracing::error!("job {job_id} failed: {e:#}");
            if let Ok(s) = Storage::open() {
                let _ = s.set_job_state(&job_id, "failed", Some(&format!("{e:#}")));
            }
            crate::jobs::finished(&job_id, "failed", 0);
        }
        crate::jobs::unregister(&job_id);
    });
}

/// Cancels the running scan(s). Returns true if anything was running.
pub fn stop_active_scan() -> bool {
    crate::jobs::cancel_all() > 0
}

/// Blocking helper for the CLI: waits for a job and returns its report.
pub fn await_report(job_id: &str) -> Result<ScanReport> {
    let storage = Storage::open()?;
    let started = std::time::Instant::now();
    loop {
        let job = storage
            .get_job(job_id)?
            .with_context(|| format!("job {job_id} not found"))?;
        if !matches!(job.state.as_str(), "queued" | "running" | "interrupted") {
            let findings = storage
                .job_findings(job_id)?
                .iter()
                .filter_map(|t| serde_json::from_str::<ScanFinding>(t).ok())
                .collect::<Vec<_>>();
            return Ok(ScanReport {
                path: job.root,
                files_scanned: job.scanned.max(0) as usize,
                files_skipped: job.skipped.max(0) as usize,
                findings,
                duration_ms: ((job.updated_at - job.created_at).max(0) as u128) * 1000,
                stopped: job.state == "cancelled",
            });
        }
        if started.elapsed().as_secs() > 60 * 60 * 6 {
            anyhow::bail!("scan job {job_id} did not finish");
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// CLI entry point: start a job and wait for it.
pub fn run_scan(root: &Path, quarantine: bool) -> Result<ScanReport> {
    let rt = tokio::runtime::Handle::try_current()
        .context("run_scan needs a tokio runtime")?;
    let id = start_scan(root.to_path_buf(), quarantine, rt)?;
    await_report(&id)
}

#[cfg(test)]
mod product_file_tests {
    use super::*;

    #[test]
    fn the_rules_are_never_scanned_as_content() {
        // A rules file *is* the patterns it matches, so matching it is
        // meaningless - wherever the copy of the package happens to live.
        assert!(is_product_file(Path::new("/x/rules/yara/starter.yar")));
        assert!(is_product_file(Path::new(r"C:\pkg\rules\yara\Starter.YARA")));
        assert!(is_product_file(Path::new(r"C:\somewhere\notes.yar")));
    }

    #[test]
    fn this_engines_own_image_and_rules_are_skipped() {
        let own = std::env::current_exe().expect("the test binary runs from somewhere");
        assert!(is_product_file(&own));
        let shipped = own
            .parent()
            .expect("a file has a parent")
            .join("rules")
            .join("yara")
            .join("starter.yar");
        assert!(is_product_file(&shipped));
    }

    #[test]
    fn a_users_files_are_still_judged() {
        assert!(!is_product_file(Path::new("/home/u/invoice.pdf")));
        assert!(!is_product_file(Path::new("/home/u/rulebook.doc")));
        // A user's own folder called `rules` is not ours to skip.
        assert!(!is_product_file(Path::new("/home/u/rules/notes.txt")));
    }
}

#[cfg(test)]
mod schedule_tests {
    use super::*;

    #[test]
    fn an_interval_of_zero_is_off() {
        assert!(!is_due(None, 1_000, 0));
        assert!(!is_due(Some(0), 1_000_000, 0));
    }

    #[test]
    fn a_scan_that_never_ran_is_due() {
        assert!(is_due(None, 1_000, 1));
        assert!(is_due(None, 1_000, 168));
    }

    #[test]
    fn the_interval_decides_after_that() {
        let hour = 3_600;
        // 6 h interval, last run 5 h 59 min ago: not yet.
        assert!(!is_due(Some(0), 6 * hour - 60, 6));
        // Exactly the interval, and past it: due.
        assert!(is_due(Some(0), 6 * hour, 6));
        assert!(is_due(Some(0), 30 * hour, 6));
        // One hour is the shortest interval the settings allow.
        assert!(!is_due(Some(0), hour - 1, 1));
        assert!(is_due(Some(0), hour, 1));
    }

    #[test]
    fn a_clock_that_went_backwards_runs_instead_of_waiting() {
        // The recorded start is in the future (a timezone jump, a restored
        // image): waiting would mean never running again, so it runs.
        assert!(is_due(Some(9_999), 1_000, 6));
    }

    #[test]
    fn the_target_is_the_configured_folder_then_the_profile() {
        let explicit = schedule_target(r"C:\Windows");
        assert_eq!(explicit, Some(PathBuf::from(r"C:\Windows")));
        // Whitespace is not a path.
        let blank = schedule_target("   ");
        assert_eq!(blank, schedule_target(""));
    }

    #[test]
    fn the_status_serializes_the_shapes_the_ui_reads() {
        let status = schedule_status();
        let json = serde_json::to_value(&status).expect("serializes");
        for key in ["enabled", "interval_hours", "target", "last_started", "next_due"] {
            assert!(json.get(key).is_some(), "{key} must be present");
        }
        // The default is off, so the UI can say so without a special case.
        assert!(!status.enabled);
        assert!(status.next_due.is_none());
    }
}