//! Application settings — the single source of truth (D-008).
//!
//! One JSON file, `%PROGRAMDATA%\MICS\settings.json`, read by the engine at
//! startup and updated through the `settings.set` JSON-RPC method. The UI has
//! no private settings store: it reads and patches the same document, so the
//! engine and the screens can never disagree.
//!
//! Environment variables remain as a **test/portability override**: if a
//! variable is present it wins for that run, which is how the isolated test
//! engines are configured. Production behaviour comes from this file.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

/// How many hours between automatic intel syncs (clamped on save).
pub const MIN_SYNC_HOURS: u32 = 1;
pub const MAX_SYNC_HOURS: u32 = 168;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// UI language: `ar` | `en`.
    pub lang: String,
    /// `dark` | `light` | `system`.
    pub theme: String,
    /// Start the real-time guard as soon as the engine starts.
    pub guard_autostart: bool,
    /// Resume scans that were interrupted by a crash/reboot.
    pub auto_resume_scans: bool,
    /// Do-not-disturb: silence everything below CRITICAL.
    pub dnd: bool,
    /// Automatic intel refresh cadence (hours).
    pub sync_interval_hours: u32,
    /// VirusTotal API key (optional; feature is offline-first).
    pub vt_api_key: String,
    /// NVD API key (optional; raises the public rate limit).
    pub nvd_api_key: String,
    /// Custom sha256 hash-feed URL for `ioc_hashes`; empty = not configured
    /// (abuse.ch's public exports now need an Auth-Key). Env
    /// `MICS_IOC_FEED_URL` still overrides it.
    pub ioc_feed_url: String,
    /// Auth-Key sent to that feed (abuse.ch style header); env
    /// `MICS_IOC_FEED_KEY` overrides it.
    pub ioc_feed_key: String,
    /// LM Studio base URL (OpenAI-compatible), e.g. http://127.0.0.1:1234.
    pub lm_url: String,
    pub lm_model: String,
    /// Self-update manifest URL; empty = updates disabled.
    pub update_manifest_url: String,
    /// `stable` | `beta`.
    pub update_channel: String,
    /// Show the natural-language command bar in the title bar.
    pub nl_bar_enabled: bool,
    /// Notification sounds.
    pub sound_enabled: bool,
    /// 0..100.
    pub sound_volume: u8,
    /// Desktop notification cards (Windows toasts) for protection events.
    pub toast_enabled: bool,
    /// Auto-quarantine detections by default on the scan screen.
    pub scan_quarantine_default: bool,
    /// Extra canary paths; empty = engine defaults.
    pub canary_paths: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: "ar".into(),
            theme: "dark".into(),
            guard_autostart: true,
            auto_resume_scans: true,
            dnd: false,
            sync_interval_hours: 6,
            vt_api_key: String::new(),
            nvd_api_key: String::new(),
            ioc_feed_url: String::new(),
            ioc_feed_key: String::new(),
            lm_url: "http://127.0.0.1:1234".into(),
            lm_model: "local-model".into(),
            update_manifest_url: String::new(),
            update_channel: "stable".into(),
            nl_bar_enabled: true,
            sound_enabled: true,
            sound_volume: 70,
            toast_enabled: true,
            scan_quarantine_default: true,
            canary_paths: Vec::new(),
        }
    }
}

impl Settings {
    /// Applies a partial JSON object on top of `self`, validating as it goes.
    ///
    /// Unknown keys are rejected so a typo in the UI never silently does
    /// nothing (and a hand-edited file fails loudly instead of drifting).
    pub fn apply_patch(&mut self, patch: &Value) -> Result<()> {
        let obj = patch
            .as_object()
            .context("settings.set expects a JSON object")?;
        for (key, value) in obj {
            match key.as_str() {
                "lang" => {
                    let v = string(value, key)?;
                    if v != "ar" && v != "en" {
                        bail!("lang must be \"ar\" or \"en\"");
                    }
                    self.lang = v;
                }
                "theme" => {
                    let v = string(value, key)?;
                    if !["dark", "light", "system"].contains(&v.as_str()) {
                        bail!("theme must be dark, light or system");
                    }
                    self.theme = v;
                }
                "guard_autostart" => self.guard_autostart = boolean(value, key)?,
                "auto_resume_scans" => self.auto_resume_scans = boolean(value, key)?,
                "dnd" => self.dnd = boolean(value, key)?,
                "sync_interval_hours" => {
                    let v = value
                        .as_u64()
                        .with_context(|| format!("{key} must be a number"))?;
                    if v < MIN_SYNC_HOURS as u64 || v > MAX_SYNC_HOURS as u64 {
                        bail!(
                            "sync_interval_hours must be between {MIN_SYNC_HOURS} and {MAX_SYNC_HOURS}"
                        );
                    }
                    self.sync_interval_hours = v as u32;
                }
                "vt_api_key" => self.vt_api_key = string(value, key)?,
                "nvd_api_key" => self.nvd_api_key = string(value, key)?,
                "ioc_feed_url" => {
                    let v = string(value, key)?;
                    if !v.is_empty() && !(v.starts_with("http://") || v.starts_with("https://")) {
                        bail!("ioc_feed_url must start with http:// or https:// (or be empty)");
                    }
                    self.ioc_feed_url = v;
                }
                "ioc_feed_key" => self.ioc_feed_key = string(value, key)?,
                "lm_url" => {
                    let v = string(value, key)?;
                    if !v.is_empty() && !(v.starts_with("http://") || v.starts_with("https://")) {
                        bail!("lm_url must start with http:// or https:// (or be empty)");
                    }
                    self.lm_url = v;
                }
                "lm_model" => self.lm_model = string(value, key)?,
                "update_manifest_url" => {
                    let v = string(value, key)?;
                    if !v.is_empty() && !(v.starts_with("http://") || v.starts_with("https://")) {
                        bail!("update_manifest_url must start with http:// or https:// (or be empty)");
                    }
                    self.update_manifest_url = v;
                }
                "update_channel" => {
                    let v = string(value, key)?;
                    if v != "stable" && v != "beta" {
                        bail!("update_channel must be \"stable\" or \"beta\"");
                    }
                    self.update_channel = v;
                }
                "nl_bar_enabled" => self.nl_bar_enabled = boolean(value, key)?,
                "sound_enabled" => self.sound_enabled = boolean(value, key)?,
                "sound_volume" => {
                    let v = value
                        .as_u64()
                        .with_context(|| format!("{key} must be a number"))?;
                    if v > 100 {
                        bail!("sound_volume must be 0..100");
                    }
                    self.sound_volume = v as u8;
                }
                "scan_quarantine_default" => {
                    self.scan_quarantine_default = boolean(value, key)?
                }
                "toast_enabled" => self.toast_enabled = boolean(value, key)?,
                "canary_paths" => {
                    let arr = value
                        .as_array()
                        .with_context(|| format!("{key} must be an array of strings"))?;
                    let mut paths = Vec::with_capacity(arr.len());
                    for p in arr {
                        let s = p
                            .as_str()
                            .with_context(|| format!("{key} entries must be strings"))?;
                        if !s.trim().is_empty() {
                            paths.push(s.trim().to_string());
                        }
                    }
                    self.canary_paths = paths;
                }
                other => bail!("unknown setting: {other}"),
            }
        }
        Ok(())
    }

    /// Effective NVD key: environment (tests) wins over the stored value.
    pub fn nvd_key(&self) -> String {
        std::env::var("NVD_API_KEY").unwrap_or_else(|_| self.nvd_api_key.clone())
    }

    pub fn vt_key(&self) -> String {
        std::env::var("MICS_VT_API_KEY").unwrap_or_else(|_| self.vt_api_key.clone())
    }

    /// Effective custom hash-feed URL (environment wins, as with every other
    /// test hook).
    pub fn ioc_feed_url(&self) -> String {
        std::env::var("MICS_IOC_FEED_URL").unwrap_or_else(|_| self.ioc_feed_url.clone())
    }

    /// Auth-Key for that feed, sent as `Auth-Key:` when non-empty.
    pub fn ioc_feed_key(&self) -> String {
        std::env::var("MICS_IOC_FEED_KEY").unwrap_or_else(|_| self.ioc_feed_key.clone())
    }

    pub fn lm_base(&self) -> String {
        std::env::var("MICS_LM_URL").unwrap_or_else(|_| self.lm_url.clone())
    }

    pub fn lm_name(&self) -> String {
        std::env::var("MICS_LM_MODEL").unwrap_or_else(|_| self.lm_model.clone())
    }

    pub fn update_url(&self) -> String {
        std::env::var("MICS_UPDATE_MANIFEST_URL").unwrap_or_else(|_| self.update_manifest_url.clone())
    }

    pub fn sync_hours(&self) -> u32 {
        std::env::var("MICS_SYNC_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(self.sync_interval_hours)
    }

    pub fn quiet(&self) -> bool {
        std::env::var("MICS_DND")
            .map(|v| v == "1")
            .unwrap_or(self.dnd)
    }

    /// Where MI CS keeps its state. Resolved once per process:
    ///
    /// 1. `MICS_DATA_DIR` — explicit override (portable mode, tests, isolated runs);
    /// 2. `%PROGRAMDATA%\MICS` — the documented machine-wide layout;
    /// 3. `%LOCALAPPDATA%\MICS` — per-user fallback when (2) is not writable by
    ///    this user (an unelevated engine must never die on "readonly database").
    pub fn base_dir() -> PathBuf {
        BASE_DIR.get_or_init(resolve_base_dir).clone()
    }

    pub fn path() -> PathBuf {
        Self::base_dir().join("settings.json")
    }

    /// Reads the file; a missing or corrupt file falls back to defaults (and
    /// never blocks the engine from starting).
    pub fn load() -> Self {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Settings>(&text) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("settings.json is invalid ({e}) — using defaults");
                    Settings::default()
                }
            },
            Err(_) => Settings::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::base_dir();
        std::fs::create_dir_all(&dir).context("create MICS data dir")?;
        let path = Self::path();
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?).context("write settings")?;
        // Atomic replace: a crash mid-write must never leave a truncated file.
        std::fs::rename(&tmp, &path).context("replace settings.json")?;
        Ok(())
    }
}

// ---------- process-wide cache ----------

static CURRENT: OnceLock<RwLock<Settings>> = OnceLock::new();

fn cache() -> &'static RwLock<Settings> {
    CURRENT.get_or_init(|| RwLock::new(Settings::load()))
}

/// Loads the settings once (called at engine startup).
pub fn init() -> Settings {
    ensure_data_dir();
    let loaded = Settings::load();
    *cache().write().unwrap_or_else(|e| e.into_inner()) = loaded.clone();
    loaded
}

/// Creates the data directory and makes sure the signed-in user can write it.
///
/// `%PROGRAMDATA%\MICS` is usually created by the elevated app, so its ACL
/// gives Administrators full control and the interactive user read-only. The
/// engine started by the autostart entry is **not** elevated, and would then
/// fail with "attempt to write a readonly database" on every state change.
/// Granting the current user modify rights once fixes that without weakening
/// anything the usermode product already relies on.
pub fn ensure_data_dir() -> PathBuf {
    let dir = Settings::base_dir();
    let _ = std::fs::create_dir_all(&dir);
    // A writable *directory* is not enough: files created by an earlier
    // elevated run (database, log, quarantine blobs) can still be read-only for
    // this user. The marker records that the recursive grant already ran.
    let marker = dir.join(".acl-granted");
    let files_ok = !dir.join("mics.db").exists() || can_write(&dir.join("mics.db"));
    if can_write(&dir) && files_ok {
        return dir;
    }
    if !crate::platform::windows::elevation::is_elevated() {
        tracing::warn!(
            "data dir {} is not fully writable by this user — start MI CS once as \
             administrator to repair permissions",
            dir.display()
        );
        return dir;
    }
    if marker.exists() && can_write(&dir) {
        return dir;
    }
    if let Ok(user) = std::env::var("USERNAME") {
        match data_dir_acl_call(&dir, &user).run() {
            Ok(out) if out.success => {
                tracing::info!("granted {user} modify rights on {}", dir.display())
            }
            Ok(out) => tracing::warn!("icacls failed: {}", out.text.trim()),
            Err(e) => tracing::warn!("icacls: {e:#}"),
        }
        let _ = std::fs::write(&marker, b"1");
    }
    dir
}

/// How long the one-time ACL grant may take: `/T` walks the quarantine folder,
/// which can hold thousands of blobs, but a stalled `icacls` must not hold the
/// engine's startup open.
const ICACLS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// The recursive `icacls` grant for the data directory, with a deadline.
pub(crate) fn data_dir_acl_call(
    dir: &std::path::Path,
    user: &str,
) -> crate::platform::windows::process::ToolCall {
    crate::platform::windows::process::ToolCall::new(
        "icacls (data dir permissions)",
        "icacls",
        ICACLS_TIMEOUT,
    )
    .arg(dir)
    // /T so existing files (database, logs, quarantine blobs) created by an
    // earlier elevated run become writable too.
    .arg(format!("{user}:(OI)(CI)M"))
    .args(["/T", "/C", "/Q"])
}

/// Writable check that also covers an existing *file* (not just the folder).
fn can_write(path: &std::path::Path) -> bool {
    if path.is_dir() {
        let probe = path.join(".write-probe");
        let ok = std::fs::write(&probe, b"1").is_ok();
        let _ = std::fs::remove_file(&probe);
        return ok;
    }
    // Existing file: opening for append is the real test.
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

/// True when this process could actually persist state in `dir`: the folder is
/// writable *and* SQLite can take a write lock on the database. A folder
/// created by an earlier elevated run can be writable while the database (or
/// its WAL sidecars) is read-only for this user — exactly the "readonly
/// database" trap that makes scans and settings fail silently.
fn state_writable(dir: &std::path::Path) -> bool {
    if !can_write(dir) {
        return false;
    }
    for name in ["mics.db", "mics.db-wal", "mics.db-shm", "settings.json"] {
        let file = dir.join(name);
        if file.exists() && !can_write(&file) {
            return false;
        }
    }
    // The definitive test: an immediate transaction actually takes write locks.
    let db = dir.join("mics.db");
    match rusqlite::Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
    ) {
        Ok(conn) => conn
            .execute_batch("BEGIN IMMEDIATE; COMMIT;")
            .is_ok(),
        Err(_) => false,
    }
}

static BASE_DIR: OnceLock<PathBuf> = OnceLock::new();

fn machine_dir() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| PathBuf::from(p).join("MICS"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS"))
}

fn resolve_base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("MICS_DATA_DIR")
        && !dir.trim().is_empty()
    {
        return PathBuf::from(dir);
    }

    // Sticky choice: the first successful resolution is recorded per user, so an
    // elevated run and an autostart (unelevated) run never disagree about where
    // state lives — that would silently show different settings and scans.
    let pointer = data_dir_pointer();
    if let Some(text) = pointer
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
    {
        let dir = PathBuf::from(text.trim());
        if state_writable(&dir) {
            return dir;
        }
    }

    let machine = machine_dir();
    // The probe needs the directory to exist; creating it is itself part of the
    // writability test (a user without rights cannot create it).
    let _ = std::fs::create_dir_all(&machine);
    // An elevated engine can repair the machine-wide directory (see
    // `ensure_data_dir`), so keep it even when the probe fails.
    let chosen = if state_writable(&machine) || crate::platform::windows::elevation::is_elevated() {
        machine
    } else {
        per_user_dir().unwrap_or(machine)
    };

    if !state_writable(&chosen) {
        tracing::warn!(
            "data dir {} is not fully writable — state changes may fail",
            chosen.display()
        );
    }
    if let Some(p) = pointer {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(p, chosen.display().to_string());
    }
    chosen
}

/// Per-user state directory (`%LOCALAPPDATA%\MICS`).
fn per_user_dir() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA")
        .ok()
        .map(|local| PathBuf::from(local).join("MICS"))
}

/// Where the chosen data directory is remembered (`%LOCALAPPDATA%\MICS\.data-dir`).
fn data_dir_pointer() -> Option<PathBuf> {
    per_user_dir().map(|dir| dir.join(".data-dir"))
}

/// Current settings (cheap clone of a small struct).
pub fn current() -> Settings {
    cache()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Applies a partial update, persists it, and refreshes the cache.
pub fn patch(patch: &Value) -> Result<Settings> {
    let mut next = current();
    next.apply_patch(patch)?;
    next.save()?;
    *cache().write().unwrap_or_else(|e| e.into_inner()) = next.clone();
    Ok(next)
}

fn string(value: &Value, key: &str) -> Result<String> {
    value
        .as_str()
        .map(|s| s.to_string())
        .with_context(|| format!("{key} must be a string"))
}

fn boolean(value: &Value, key: &str) -> Result<bool> {
    value
        .as_bool()
        .with_context(|| format!("{key} must be true or false"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_are_sane() {
        let s = Settings::default();
        assert_eq!(s.lang, "ar");
        assert_eq!(s.theme, "dark");
        assert!(s.guard_autostart);
        assert!(s.auto_resume_scans);
        assert_eq!(s.sync_interval_hours, 6);
        assert!(!s.dnd);
        assert_eq!(s.update_channel, "stable");
        assert_eq!(s.sound_volume, 70);
        assert!(s.toast_enabled, "desktop cards are on unless the user says no");
    }

    #[test]
    fn patch_changes_only_named_fields() {
        let mut s = Settings::default();
        s.apply_patch(&json!({"dnd": true, "lang": "en"})).unwrap();
        assert!(s.dnd);
        assert_eq!(s.lang, "en");
        // untouched fields keep their defaults
        assert_eq!(s.theme, "dark");
        assert_eq!(s.sync_interval_hours, 6);
        assert!(s.guard_autostart);
    }

    #[test]
    fn patch_rejects_invalid_values() {
        let mut s = Settings::default();
        assert!(s.apply_patch(&json!({"sync_interval_hours": 0})).is_err());
        assert!(s.apply_patch(&json!({"sync_interval_hours": 999})).is_err());
        assert!(s.apply_patch(&json!({"theme": "neon"})).is_err());
        assert!(s.apply_patch(&json!({"lm_url": "127.0.0.1:1234"})).is_err());
        assert!(s.apply_patch(&json!({"sound_volume": 101})).is_err());
        assert!(s.apply_patch(&json!({"unknown_key": 1})).is_err());
        assert!(s.apply_patch(&json!({"dnd": "yes"})).is_err());
        assert!(s.apply_patch(&json!({"toast_enabled": "no"})).is_err());
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let mut s = Settings::default();
        s.apply_patch(&json!({
            "lang": "en",
            "theme": "light",
            "dnd": true,
            "sync_interval_hours": 24,
            "vt_api_key": "abc",
            "lm_url": "http://localhost:1234",
            "canary_paths": ["C:\\a", "C:\\b"],
            "sound_volume": 10,
            "toast_enabled": false
        }))
        .unwrap();
        let text = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&text).unwrap();
        assert_eq!(back.lang, "en");
        assert_eq!(back.theme, "light");
        assert_eq!(back.sync_interval_hours, 24);
        assert_eq!(back.vt_api_key, "abc");
        assert_eq!(back.canary_paths.len(), 2);
        assert_eq!(back.sound_volume, 10);
        assert!(!back.toast_enabled);
    }
}
