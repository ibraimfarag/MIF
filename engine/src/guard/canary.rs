//! Canaries (decoy files): nobody but the user should ever open these.
//!
//! A write, rename or delete — anything that moves mtime or size — is a CRITICAL
//! event. A read-only open moves neither, so for a long time it was invisible
//! here. It does move the file's **last-access time**, and that time is part of
//! the snapshot now, so a read-only open is an event of its own (HIGH, its own
//! rule id, so a user can quiet reads without quieting writes).
//!
//! Only a volume that keeps a last-access time can show a read, and that is
//! *measured* rather than assumed: `read_detection()` probes the decoys' own
//! volume at guard start and `guard.status` carries the verdict, so a machine
//! that keeps none is named with the switch that turns it on instead of being
//! silently implied to be covered.
//!
//! Measured on this machine (2026-11-05, `fsutil behavior query
//! disablelastaccess` = `2 (System Managed, Last Access Time Updates
//! ENABLED)`): four reads in a row moved the atime, a read from a *different*
//! process moved it, and fifty metadata queries in a row moved nothing — which
//! is why the poll below can stat without tripping its own trap.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::guard::GuardEvent;

/// How long a decoy **this process just wrote** is left alone. The first program
/// to open a brand-new file on a normal Windows machine is Defender doing its
/// job or the indexer looking it over, and neither is the user. Only decoys
/// created by `deploy_decoys_detailed` get this window, so a decoy that was
/// already on disk is never blind.
pub const READ_SETTLE: Duration = Duration::from_secs(90);

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

/// Creates any missing decoy files on disk, and names the ones it created.
/// The caller needs that list: a file this process just wrote is the one case
/// where the first read is expected to be a scanner.
pub fn deploy_decoys_detailed() -> Result<Vec<String>> {
    let cfg = load_config();
    let mut created = Vec::new();
    for path in &cfg.paths {
        let p = PathBuf::from(path);
        if !p.exists() {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(
                &p,
                "MI CS canary decoy file. If any program reads this file, something is wrong.\n",
            )
            .with_context(|| format!("create decoy {path}"))?;
            created.push(path.clone());
        }
    }
    Ok(created)
}

/// Creates any missing decoy files on disk.
pub fn list_decoys() -> Vec<(String, bool)> {
    load_config()
        .paths
        .iter()
        .map(|p| (p.clone(), PathBuf::from(p).exists()))
        .collect()
}

// ---------- state ----------

/// Everything about one decoy that a read or a write can change. Atime is
/// `None` when the file is not there *and* when the volume keeps no
/// last-access time, which is why `classify` never guesses from it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryState {
    pub exists: bool,
    pub mtime_ns: i64,
    pub size: u64,
    /// Nanoseconds since the epoch. `None` when the volume does not keep one.
    pub atime_ns: Option<i64>,
}

impl CanaryState {
    /// A metadata query is not a read — measured, fifty of them in a row moved
    /// no last-access time — so the watcher can look at its own decoys.
    fn of(path: &str) -> Self {
        match std::fs::metadata(path) {
            Ok(m) => CanaryState {
                exists: true,
                mtime_ns: m.modified().ok().and_then(epoch_ns).unwrap_or(0),
                size: m.len(),
                atime_ns: m.accessed().ok().and_then(epoch_ns),
            },
            Err(_) => CanaryState {
                exists: false,
                mtime_ns: 0,
                size: 0,
                atime_ns: None,
            },
        }
    }
}

fn epoch_ns(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_nanos() as i64)
}

/// What happened to one decoy between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryChange {
    None,
    /// Opened for reading: the last-access time moved and nothing else did.
    Read,
    /// Written, truncated, renamed, deleted or re-created.
    Written,
}

/// The whole detection rule, in one pure function so it can be tested without a
/// filesystem. Order matters: a program that reads *and* writes is a writer, so
/// the write answers first.
pub fn classify(before: &CanaryState, after: &CanaryState) -> CanaryChange {
    if before == after {
        return CanaryChange::None;
    }
    if !after.exists || !before.exists {
        return CanaryChange::Written;
    }
    if after.size != before.size || after.mtime_ns != before.mtime_ns {
        return CanaryChange::Written;
    }
    match (before.atime_ns, after.atime_ns) {
        (Some(b), Some(a)) if a != b => CanaryChange::Read,
        _ => CanaryChange::None,
    }
}

#[derive(Clone)]
struct Armed {
    state: CanaryState,
    /// When this decoy started being watched. Reads inside `READ_SETTLE` of it
    /// are settled silently — see the constant's own note.
    since: Instant,
}

type Snapshot = HashMap<String, Armed>;
static BASELINE: Mutex<Option<Snapshot>> = Mutex::new(None);

/// The moment far enough in the past that a decoy is treated as long-watched.
fn settled_instant() -> Instant {
    let now = Instant::now();
    now.checked_sub(READ_SETTLE).unwrap_or(now)
}

fn snapshot_now(cfg: &CanaryConfig) -> HashMap<String, CanaryState> {
    cfg.paths
        .iter()
        .map(|p| (p.clone(), CanaryState::of(p)))
        .collect()
}

fn snapshot_fresh(cfg: &CanaryConfig, fresh: &HashSet<String>) -> Snapshot {
    let now = Instant::now();
    let settled = settled_instant();
    cfg.paths
        .iter()
        .map(|p| {
            (
                p.clone(),
                Armed {
                    state: CanaryState::of(p),
                    since: if fresh.contains(p) { now } else { settled },
                },
            )
        })
        .collect()
}

/// Captures the pristine state of every decoy. Called once by the guard loop,
/// and again whenever the set of decoys changes (so a decoy added at runtime is
/// adopted in one place, not two).
pub fn arm_watchers() -> Result<()> {
    arm_watchers_detailed().map(|_| ())
}

/// `arm_watchers`, but it also says how many decoy files it had to create.
pub fn arm_watchers_detailed() -> Result<usize> {
    let deployed = deploy_decoys_detailed()?;
    let created: HashSet<String> = deployed.iter().cloned().collect();
    let cfg = load_config();
    let snap = snapshot_fresh(&cfg, &created);
    let stored_len = snap.len();
    *BASELINE.lock().unwrap() = Some(snap);
    // Whether a read can be seen at all is a property of the volume, so it is
    // measured here — once, on the decoys' own volume — and never assumed.
    measure_read_detection(&cfg);
    info!(
        "Canary watchers armed over {} decoy file(s), {} of them just written",
        stored_len,
        created.len()
    );
    Ok(deployed.len())
}

/// Called every guard poll: a decoy whose mtime/size moved was written to, and
/// a decoy whose *last-access* time moved was read.
pub fn check_touches() {
    let Some(baseline) = BASELINE.lock().unwrap().clone() else {
        return;
    };
    let cfg = load_config();
    let now = snapshot_now(&cfg);
    let mut next: Snapshot = HashMap::new();
    for (path, current) in &now {
        let Some(prev) = baseline.get(path) else {
            // Configured since the last poll. A decoy that was just *added* is
            // not a decoy that was just touched, so it is adopted in silence —
            // and with no settle window, because the window belongs to files
            // this process wrote (`canary.configure` re-arms for exactly that).
            next.insert(
                path.clone(),
                Armed {
                    state: *current,
                    since: settled_instant(),
                },
            );
            continue;
        };
        match classify(&prev.state, current) {
            CanaryChange::None => {}
            CanaryChange::Read if prev.since.elapsed() < READ_SETTLE => {
                info!("canary settling: {path} was read inside the settle window");
            }
            CanaryChange::Read => report_read(path),
            CanaryChange::Written => report_written(path),
        }
        next.insert(
            path.clone(),
            Armed {
                state: *current,
                // The window is anchored when the decoy started being watched,
                // never extended by an event: a second read is not quieted by
                // the first one having been reported.
                since: prev.since,
            },
        );
    }
    *BASELINE.lock().unwrap() = Some(next);
}

fn report_written(path: &str) {
    emit(GuardEvent {
        r#type: "canary_triggered".into(),
        severity: "critical".into(),
        rule_id: "CANARY".into(),
        rule_name: "Decoy file modified".into(),
        pid: 0,
        process: String::new(),
        parent: String::new(),
        detail: format!(
            "{path} was modified — a program wrote to, renamed or deleted your decoy."
        ),
        at: chrono::Utc::now().timestamp(),
    });
    warn!("CANARY TRIGGERED: {path}");
}

fn report_read(path: &str) {
    emit(GuardEvent {
        r#type: "canary_read".into(),
        // Above the noise floor on purpose: what a decoy is for is being read by
        // something that should not, and that is worth a card. It is not
        // `critical` because nothing on disk changed.
        severity: "high".into(),
        // Its own id, so a user can quiet read alerts without losing the ones
        // that mean their decoy was overwritten.
        rule_id: "CANARY_READ".into(),
        rule_name: "Decoy file opened for read".into(),
        pid: 0,
        process: String::new(),
        parent: String::new(),
        detail: format!(
            "{path} was opened for reading — nothing was written to it. A stealer, a preview \
             handler and a scanner all look like this, and the unelevated guard cannot name the \
             reader."
        ),
        at: chrono::Utc::now().timestamp(),
    });
    warn!("CANARY READ: {path}");
}

// ---------- can a read be seen here at all? ----------

/// The measured answer to "can this machine show a decoy read?", kept for the
/// life of the process because the volume's policy does not change under us.
#[derive(Debug, Clone, Serialize)]
pub struct ReadDetection {
    /// `true` = a read-only open moves the last-access time here.
    pub available: bool,
    /// The folder the probe actually ran in (the decoys' own volume where one
    /// exists), so "unavailable" names the volume it is about.
    pub probed_on: String,
    pub detail: String,
}

static READ_DETECTION: Mutex<Option<ReadDetection>> = Mutex::new(None);

pub fn read_detection() -> Option<ReadDetection> {
    READ_DETECTION.lock().unwrap().clone()
}

/// The folder to probe: beside the decoys when one of them has a directory that
/// exists (the point is to measure *their* volume), otherwise the data folder.
fn probe_dir(cfg: &CanaryConfig) -> PathBuf {
    for p in &cfg.paths {
        if let Some(parent) = PathBuf::from(p).parent()
            && parent.is_dir() {
                return parent.to_path_buf();
            }
    }
    crate::settings::Settings::base_dir()
}

fn measure_read_detection(cfg: &CanaryConfig) {
    let dir = probe_dir(cfg);
    let probed_on = dir.display().to_string();
    {
        let cached = READ_DETECTION.lock().unwrap();
        // Measured once per folder, not once per process: the verdict is about
        // the volume the decoys are on, and a verdict about the *previous*
        // folder is worse than no verdict — it would name the wrong disk while
        // the answer came from another one. (Found by the probe, which asserts
        // that `probed_on` is the decoys' own folder.)
        if let Some(existing) = cached.as_ref()
            && existing.probed_on == probed_on
        {
            return;
        }
    }
    let available = probe_atime(&dir);
    let detail = if available {
        "a read-only open moves the last-access time on this volume, so a decoy read is detected"
            .to_string()
    } else {
        "this volume keeps no last-access time, so a read-only open of a decoy cannot be seen; \
         `fsutil behavior set disablelastaccess 0` in an elevated prompt turns it on"
            .to_string()
    };
    *READ_DETECTION.lock().unwrap() = Some(ReadDetection {
        available,
        probed_on,
        detail,
    });
}

/// Writes a scratch file, reads it back, and says whether that moved its
/// last-access time. `false` also covers "could not write here", which is the
/// honest answer for a folder we cannot measure in.
///
/// It reads a scratch file and never a decoy, so arming cannot trip the trap it
/// is arming.
pub(crate) fn probe_atime(dir: &Path) -> bool {
    probe_atime_in(dir).unwrap_or_else(|| {
        probe_atime_in(&crate::settings::Settings::base_dir()).unwrap_or(false)
    })
}

fn probe_atime_in(dir: &Path) -> Option<bool> {
    let probe = dir.join(format!(".mics-atime-probe-{}", std::process::id()));
    std::fs::write(&probe, b"MI CS last-access probe\n").ok()?;
    let before = std::fs::metadata(&probe).ok().and_then(|m| m.accessed().ok());
    // The read that must move the clock.
    let _ = std::fs::read(&probe);
    // NTFS updates the last-access time lazily. Measured lag on this machine was
    // 0.4–1.3 s across four reads, so 1.3 s is the smallest honest wait.
    std::thread::sleep(Duration::from_millis(1300));
    let after = std::fs::metadata(&probe).ok().and_then(|m| m.accessed().ok());
    let _ = std::fs::remove_file(&probe);
    match (before, after) {
        (Some(b), Some(a)) => Some(a > b),
        _ => Some(false),
    }
}

/// The canary half of `guard.status`: what is deployed, and whether a read
/// would be seen here.
pub fn status_json() -> serde_json::Value {
    let cfg = load_config();
    let deployed = cfg
        .paths
        .iter()
        .filter(|p| PathBuf::from(p).exists())
        .count();
    json!({
        "configured": cfg.paths.len(),
        "deployed": deployed,
        "read_settle_seconds": READ_SETTLE.as_secs(),
        "read_detection": read_detection(),
    })
}

fn emit(ev: GuardEvent) {
    crate::guard::emit_public(ev);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(mtime_ns: i64, size: u64, atime_ns: Option<i64>) -> CanaryState {
        CanaryState {
            exists: true,
            mtime_ns,
            size,
            atime_ns,
        }
    }

    #[test]
    fn an_untouched_decoy_is_no_event() {
        let s = state(1_000, 42, Some(500));
        assert_eq!(classify(&s, &s), CanaryChange::None);
    }

    #[test]
    fn a_read_only_open_is_a_read() {
        let before = state(1_000, 42, Some(500));
        let after = state(1_000, 42, Some(900));
        assert_eq!(classify(&before, &after), CanaryChange::Read);
    }

    #[test]
    fn a_read_that_also_writes_is_a_write() {
        let before = state(1_000, 42, Some(500));
        let after = state(2_000, 42, Some(900));
        assert_eq!(classify(&before, &after), CanaryChange::Written);
        let grown = state(1_000, 43, Some(900));
        assert_eq!(classify(&before, &grown), CanaryChange::Written);
    }

    #[test]
    fn a_deleted_decoy_is_a_write() {
        let before = state(1_000, 42, Some(500));
        let gone = CanaryState {
            exists: false,
            ..before
        };
        assert_eq!(classify(&before, &gone), CanaryChange::Written);
    }

    #[test]
    fn a_volume_without_atime_never_invents_a_read() {
        let before = state(1_000, 42, None);
        let after = state(1_000, 42, None);
        assert_eq!(classify(&before, &after), CanaryChange::None);
    }

    #[test]
    fn the_atime_probe_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("mics-canary-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let _ = probe_atime(&dir);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("read scratch dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(leftovers.is_empty(), "probe left {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
