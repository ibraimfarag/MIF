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
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

/// How many hours between automatic intel syncs (clamped on save).
pub const MIN_SYNC_HOURS: u32 = 1;
pub const MAX_SYNC_HOURS: u32 = 168;

/// A scheduled scan that asks for the shortest interval this allows: the tick is
/// a few minutes long, so anything below an hour would just re-run immediately.
pub const MIN_SCAN_HOURS: u32 = 1;
/// A week. Past that the schedule is indistinguishable from "off".
pub const MAX_SCAN_HOURS: u32 = 168;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// UI language as a BCP-47 tag (`ar`, `en`, `de`, `pt-br`).
    ///
    /// The engine does not keep a list of languages: the UI owns the packs, so
    /// a language that ships next month must not need an engine change. It does
    /// refuse anything that is not a tag, so a typo is an error instead of a
    /// silently stored string.
    pub lang: String,
    /// `dark` | `light` | `system`.
    pub theme: String,
    /// Start the real-time guard as soon as the engine starts.
    pub guard_autostart: bool,
    /// Closing the window hides MI CS to the tray and leaves the engine running
    /// (D-039). **Off by default**: closing the window quits the app, and the
    /// engine it started stops with it — an engine that outlives the window is
    /// now a choice, not the only behaviour.
    pub close_to_tray: bool,
    /// Resume scans that were interrupted by a crash/reboot.
    pub auto_resume_scans: bool,
    /// Do-not-disturb: silence everything below CRITICAL.
    pub dnd: bool,
    /// Automatic intel refresh cadence (hours).
    pub sync_interval_hours: u32,
    /// NVD API key (optional; raises the public rate limit).
    ///
    /// **Never written to `settings.json`**: [`crate::secrets`] keeps it in the
    /// DPAPI-protected `secrets.dat` beside the document (و4). The field is here
    /// because `settings.get` returns it to the UI that owns the input.
    pub nvd_api_key: String,
    /// Custom sha256 hash-feed URL for `ioc_hashes`; empty = not configured
    /// (abuse.ch's public exports now need an Auth-Key). Env
    /// `MICS_IOC_FEED_URL` still overrides it.
    pub ioc_feed_url: String,
    /// Auth-Key sent to that feed (abuse.ch style header); env
    /// `MICS_IOC_FEED_KEY` overrides it. Protected on disk like `nvd_api_key`.
    pub ioc_feed_key: String,
    /// LM Studio base URL (OpenAI-compatible), e.g. http://127.0.0.1:1234.
    pub lm_url: String,
    pub lm_model: String,
    /// Self-update manifest URL the user typed; empty = read the channel's
    /// compiled-in default ([`default_update_manifest_url`], D-046).
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
    /// Hours between automatic scans; **0 disables them** (the default: a scan
    /// that starts by itself is something the user turns on, D-027).
    ///
    /// The engine has to be running: MI CS starts it and, by default, ends it
    /// when the window closes (D-039), so a schedule only fires while the app
    /// (or an engine the user started, e.g. the autostart entry) is up. The
    /// scan is report-only: a scheduled run never quarantines, because nobody
    /// chose a file while it was running.
    pub scan_interval_hours: u32,
    /// Folder that scan walks; empty = the current user's profile folder.
    pub scan_target: String,
    /// Extra canary paths; empty = engine defaults.
    pub canary_paths: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: "ar".into(),
            theme: "dark".into(),
            guard_autostart: true,
            close_to_tray: false,
            auto_resume_scans: true,
            dnd: false,
            sync_interval_hours: 6,
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
            scan_interval_hours: 0,
            scan_target: String::new(),
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
                    if !is_language_tag(&v) {
                        bail!("lang must be a language tag like \"ar\" or \"en-gb\"");
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
                "close_to_tray" => self.close_to_tray = boolean(value, key)?,
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
                "nvd_api_key" => self.nvd_api_key = string(value, key)?,
                "ioc_feed_url" => {
                    let v = string(value, key)?;
                    check_url(key, &v)?;
                    self.ioc_feed_url = v;
                }
                "ioc_feed_key" => self.ioc_feed_key = string(value, key)?,
                "lm_url" => {
                    let v = string(value, key)?;
                    check_url(key, &v)?;
                    self.lm_url = v;
                }
                "lm_model" => self.lm_model = string(value, key)?,
                "update_manifest_url" => {
                    let v = string(value, key)?;
                    check_url(key, &v)?;
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
                "scan_interval_hours" => {
                    let v = value
                        .as_u64()
                        .with_context(|| format!("{key} must be a number"))?;
                    if v > MAX_SCAN_HOURS as u64 {
                        bail!("scan_interval_hours must be 0 (off) or {MIN_SCAN_HOURS}..{MAX_SCAN_HOURS}");
                    }
                    if v != 0 && v < MIN_SCAN_HOURS as u64 {
                        bail!("scan_interval_hours must be 0 (off) or {MIN_SCAN_HOURS}..{MAX_SCAN_HOURS}");
                    }
                    self.scan_interval_hours = v as u32;
                }
                "scan_target" => {
                    let v = string(value, key)?;
                    let v = v.trim().to_string();
                    if !v.is_empty() && !std::path::Path::new(&v).is_absolute() {
                        bail!("scan_target must be an absolute path, or empty for the profile folder");
                    }
                    self.scan_target = v;
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
        resolve_update_url(
            std::env::var("MICS_UPDATE_MANIFEST_URL").ok().as_deref(),
            &self.update_manifest_url,
            &self.update_channel,
        )
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

    /// Reads the file; a missing or corrupt file falls back to defaults (and
    /// never blocks the engine from starting). A URL that the RPC patch would
    /// refuse is cleared here too, so a hand-edited `http://` feed cannot be used
    /// just because it arrived through the file instead of the UI (F-3).
    ///
    /// The API keys are not in this document any more: they come from the
    /// DPAPI-protected `secrets.dat` ([`crate::secrets`]), and a file written by
    /// an older build — with `nvd_api_key`/`ioc_feed_key` in it — is migrated on
    /// the way through and rewritten without them. That is the one write a *read*
    /// may perform, and it happens once.
    pub fn load() -> Self {
        Self::read_from(&Self::base_dir())
    }

    /// [`Settings::load`] for an explicit directory (tests, and the migration's
    /// own proof, which must not touch the machine's real data directory).
    pub(crate) fn read_from(dir: &Path) -> Self {
        let path = dir.join("settings.json");
        let mut s = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Settings>(&text) {
                Ok(mut s) => {
                    for (key, value) in [
                        ("ioc_feed_url", &mut s.ioc_feed_url),
                        ("lm_url", &mut s.lm_url),
                        ("update_manifest_url", &mut s.update_manifest_url),
                    ] {
                        if let Err(e) = check_url(key, value.as_str()) {
                            tracing::warn!("{e} — clearing {key}");
                            value.clear();
                        }
                    }
                    s
                }
                Err(e) => {
                    tracing::warn!("settings.json is invalid ({e}) — using defaults");
                    Settings::default()
                }
            },
            Err(_) => Settings::default(),
        };

        // Credentials never live in this document. `had_plaintext` is separate
        // from what moved: if an earlier migration saved the secrets and then
        // failed to rewrite the document, the keys are already safe on disk and
        // nothing "moves" this time - but the plaintext copy still has to go.
        let mut secrets = crate::secrets::load_from(dir);
        let had_plaintext = !s.nvd_api_key.is_empty() || !s.ioc_feed_key.is_empty();
        let moved = secrets.absorb_legacy(&mut s);
        s.nvd_api_key = secrets.nvd_api_key.clone();
        s.ioc_feed_key = secrets.ioc_feed_key.clone();
        if had_plaintext {
            tracing::info!(
                "moving {moved} API key(s) out of settings.json into the DPAPI-protected {}",
                crate::secrets::FILE_NAME
            );
            if let Err(e) = s.write_to(dir) {
                tracing::warn!(
                    "settings.json still holds the API keys ({e:#}) — this run uses them, \
                     and the next start retries the migration"
                );
            }
        }
        s
    }

    pub fn save(&self) -> Result<()> {
        self.write_to(&Self::base_dir())
    }

    /// Writes `dir\settings.json` (and the protected secrets that belong with it).
    ///
    /// Order matters: the secrets file is written and flushed **first**, so a
    /// crash between the two writes can lose the document's other fields but
    /// never a credential. The two key fields are stripped from the JSON.
    pub(crate) fn write_to(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).context("create MICS data dir")?;
        crate::secrets::save_to(
            dir,
            &crate::secrets::Secrets {
                nvd_api_key: self.nvd_api_key.clone(),
                ioc_feed_key: self.ioc_feed_key.clone(),
            },
        )?;
        let path = dir.join("settings.json");
        let tmp = path.with_extension("json.tmp");
        let mut doc = serde_json::to_value(self)?;
        if let Some(obj) = doc.as_object_mut() {
            obj.remove("nvd_api_key");
            obj.remove("ioc_feed_key");
        }
        std::fs::write(&tmp, serde_json::to_string_pretty(&doc)?).context("write settings")?;
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
    if crate::platform::windows::integrity::below_medium() {
        // Not a permissions bug in the folder: Windows runs a process from a
        // Low-labelled folder at Low, and a Low process cannot write a Medium
        // directory no matter what the ACL says. Saying "start as administrator"
        // here sent the user to a prompt that does not help.
        tracing::warn!(
            "data dir {} is not writable by this Low-integrity process — Windows runs a program \
             from a Low-labelled folder at Low; the installed copy in %LOCALAPPDATA%\\MI CS does \
             not have that problem, so run MI CS from there instead of a web root or a sandbox \
             output folder",
            dir.display()
        );
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

/// A language tag the UI can have a pack for: `xx` or `xx-YY`, lower-case
/// primary subtag (BCP-47 shape, not a closed list — see the `lang` field).
fn is_language_tag(tag: &str) -> bool {
    let (primary, region) = match tag.split_once('-') {
        Some((primary, region)) => (primary, Some(region)),
        None => (tag, None),
    };
    let primary_ok =
        (2..=3).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_lowercase());
    if !primary_ok {
        return false;
    }
    match region {
        None => true,
        Some(region) => {
            (2..=8).contains(&region.len()) && region.bytes().all(|b| b.is_ascii_alphanumeric())
        }
    }
}

/// The update feed MI CS ships, pointing at its own releases (D-046).
///
/// `scripts\make-release.ps1` writes the same `update.json` beside the archive it
/// publishes and the Release workflow uploads it with the rest of the assets, so
/// `releases/latest/download/update.json` resolves as soon as a release is
/// *published*. A draft serves its assets to nobody, so until the v0.1.0 draft is
/// published this URL answers 404 and the Updates screen says that rather than
/// pretending to be up to date (§0.6 row 1 is that click).
pub const DEFAULT_UPDATE_MANIFEST_URL_STABLE: &str =
    "https://github.com/ibraimfarag/MIF/releases/latest/download/update.json";

/// The `beta` channel's feed: the release behind the rolling `beta` tag, which is
/// where a build newer than stable can live without becoming "latest" (D-046).
pub const DEFAULT_UPDATE_MANIFEST_URL_BETA: &str =
    "https://github.com/ibraimfarag/MIF/releases/download/beta/update.json";

/// The feed a channel reads when the user named none. Anything but `beta` is
/// `stable`, the same rule `settings.set` applies to the channel itself.
pub fn default_update_manifest_url(channel: &str) -> &'static str {
    if channel.eq_ignore_ascii_case("beta") {
        DEFAULT_UPDATE_MANIFEST_URL_BETA
    } else {
        DEFAULT_UPDATE_MANIFEST_URL_STABLE
    }
}

/// Where `update.check` looks, from the three inputs that can decide it (D-046).
///
/// 1. `MICS_UPDATE_MANIFEST_URL` when the environment sets it — see
///    [`update_checks_disabled`] for the one value that means "do not check";
/// 2. the URL the user saved in Settings, when it is not blank;
/// 3. the channel's compiled-in default.
///
/// Nothing follows the result on its own: `update.check` — the UI's *Check now* —
/// is its only caller, so the compiled-in default costs no traffic until the user
/// asks (`docs/THREAT-MODEL.md` §B6).
pub fn resolve_update_url(env: Option<&str>, setting: &str, channel: &str) -> String {
    if let Some(from_env) = env {
        return from_env.trim().to_string();
    }
    let saved = setting.trim();
    if !saved.is_empty() {
        return saved.to_string();
    }
    default_update_manifest_url(channel).to_string()
}

/// True for the one value that means "do not check at all".
///
/// Nothing in normal use needs it: no timer calls `update.check`, so a machine
/// whose owner never presses *Check now* contacts no feed at all. It exists so a
/// probe, a test or an offline packager can ask for the disabled answer on purpose
/// — `MICS_UPDATE_MANIFEST_URL=off`, any case, or an explicitly empty environment
/// value where the platform can carry one (Windows deletes a variable set to "").
pub fn update_checks_disabled(url: &str) -> bool {
    url.is_empty() || url.eq_ignore_ascii_case("off")
}

/// Refuses a cleartext URL that is not loopback.
///
/// `http://127.0.0.1:1234` is the LM Studio default and never leaves the machine,
/// so it stays accepted. `http://feeds.example.com` is a cleartext downgrade an
/// on-path attacker can rewrite into whatever feed or update manifest it likes,
/// and the engine would trust it (`docs/THREAT-MODEL.md`, F-3), so it is refused
/// outright rather than warned about. An empty value means "not configured".
fn check_url(key: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    let url = reqwest::Url::parse(value).with_context(|| format!("{key} is not a URL"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if host_is_loopback(&url) => Ok(()),
        "http" => bail!(
            "{key} must use https:// (http:// is only accepted for loopback: 127.0.0.1, ::1 or localhost)"
        ),
        other => bail!("{key} must use http:// or https://, not {other}://"),
    }
}

/// True for `127.0.0.0/8`, `::1` and the literal name `localhost`.
///
/// The host comes from the parser (so `http://0x7f000001/` is seen as `127.0.0.1`),
/// but the decision is a numeric one: a domain that merely ends in `localhost`
/// (`localhost.evil.test`) is not loopback and is refused.
fn host_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
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
    fn the_scan_schedule_is_off_until_the_user_turns_it_on() {
        let mut s = Settings::default();
        assert_eq!(s.scan_interval_hours, 0, "a scan that starts itself is opt-in");
        assert_eq!(s.scan_target, "", "empty means the profile folder");

        // 0 is the off switch, not a rejection; a week is the ceiling.
        s.apply_patch(&json!({ "scan_interval_hours": 24 })).unwrap();
        assert_eq!(s.scan_interval_hours, 24);
        s.apply_patch(&json!({ "scan_interval_hours": 0 })).unwrap();
        assert_eq!(s.scan_interval_hours, 0);
        assert!(s.apply_patch(&json!({ "scan_interval_hours": 169 })).is_err());
        assert!(s.apply_patch(&json!({ "scan_interval_hours": -1 })).is_err());
        assert!(s.apply_patch(&json!({ "scan_interval_hours": "24" })).is_err());
    }

    #[test]
    fn the_scan_target_must_be_absolute_or_empty() {
        let mut s = Settings::default();
        s.apply_patch(&json!({ "scan_target": r"C:\Users" })).unwrap();
        assert_eq!(s.scan_target, r"C:\Users");
        // Optimistic about paths that do not exist yet (a stick comes back), but
        // not about relative ones: the engine's working directory is not the
        // user's idea of "here".
        s.apply_patch(&json!({ "scan_target": "D:\\backup\\" })).unwrap();
        assert!(s.apply_patch(&json!({ "scan_target": "backup" })).is_err());
        s.apply_patch(&json!({ "scan_target": "   " })).unwrap();
        assert_eq!(s.scan_target, "");
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
    fn lang_accepts_any_language_tag_and_refuses_the_rest() {
        let mut s = Settings::default();
        // The two packs that exist today, plus two the UI could ship tomorrow:
        // adding a language must not need an engine change.
        for ok in ["ar", "en", "de", "pt-br", "zh-hant"] {
            s.apply_patch(&json!({ "lang": ok }))
                .unwrap_or_else(|e| panic!("{ok} rejected: {e}"));
            assert_eq!(s.lang, ok);
        }
        for bad in ["", "a", "english", "EN", "en-", "en--gb", "en_gb", "ar1"] {
            assert!(
                s.apply_patch(&json!({ "lang": bad })).is_err(),
                "{bad:?} should not be a language tag"
            );
        }
        // A refused patch leaves the stored language alone.
        assert_eq!(s.lang, "zh-hant");
    }

    #[test]
    fn cleartext_urls_are_only_accepted_for_loopback() {
        let mut s = Settings::default();
        // The LM Studio default and every honest way to spell loopback.
        for ok in [
            "",
            "http://127.0.0.1:1234",
            "http://127.0.0.2:8080/v1",
            "http://[::1]:1234",
            "http://localhost:1234",
            "https://feeds.example.com/hashes.txt",
        ] {
            for key in ["ioc_feed_url", "lm_url", "update_manifest_url"] {
                s.apply_patch(&json!({ key: ok }))
                    .unwrap_or_else(|e| panic!("{key} rejected {ok}: {e}"));
            }
        }

        // Cleartext to anywhere else is refused — including a domain that merely
        // starts with "localhost" and a scheme other than http(s).
        for bad in [
            "http://feeds.example.com/hashes.txt",
            "http://localhost.evil.test:80/",
            "http://192.168.1.10:1234",
            "ftp://feeds.example.com/",
            "feeds.example.com",
        ] {
            for key in ["ioc_feed_url", "lm_url", "update_manifest_url"] {
                assert!(
                    s.apply_patch(&json!({ key: bad })).is_err(),
                    "{key} accepted {bad}"
                );
            }
        }

        // A refused patch changes nothing: the last accepted values survive.
        assert_eq!(s.ioc_feed_url, "https://feeds.example.com/hashes.txt");
        assert_eq!(s.lm_url, "https://feeds.example.com/hashes.txt");
        assert_eq!(s.update_manifest_url, "https://feeds.example.com/hashes.txt");
    }

    #[test]
    fn the_compiled_in_update_feed_passes_the_same_gate_as_a_typed_one() {
        for url in [
            DEFAULT_UPDATE_MANIFEST_URL_STABLE,
            DEFAULT_UPDATE_MANIFEST_URL_BETA,
        ] {
            let parsed = reqwest::Url::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(parsed.scheme(), "https", "{url} must not be reachable in cleartext");
            assert!(!host_is_loopback(&parsed), "{url} must not be loopback");
            check_url("update_manifest_url", url)
                .unwrap_or_else(|e| panic!("the default {url} fails the settings gate: {e}"));
        }
        assert_eq!(default_update_manifest_url("stable"), DEFAULT_UPDATE_MANIFEST_URL_STABLE);
        assert_eq!(default_update_manifest_url("beta"), DEFAULT_UPDATE_MANIFEST_URL_BETA);
        assert_eq!(default_update_manifest_url("BETA"), DEFAULT_UPDATE_MANIFEST_URL_BETA);
        assert_eq!(default_update_manifest_url(""), DEFAULT_UPDATE_MANIFEST_URL_STABLE);
        assert_ne!(
            DEFAULT_UPDATE_MANIFEST_URL_STABLE, DEFAULT_UPDATE_MANIFEST_URL_BETA,
            "the two channels must not read the same file"
        );
        // The sentinel is a word nobody can type into the URL field by accident:
        // `check_url` refuses anything that is not a URL, so only the environment
        // can carry it.
        assert!(update_checks_disabled(""));
        assert!(update_checks_disabled("off"));
        assert!(update_checks_disabled("OFF"));
        assert!(!update_checks_disabled("https://github.com/ibraimfarag/MIF"));
        assert!(check_url("update_manifest_url", "off").is_err());
    }

    #[test]
    fn the_update_url_resolves_in_order_and_an_empty_env_switches_it_off() {
        let own = "https://feeds.example.com/mics-manifest.json";
        // A URL the user saved wins over the default — on either channel.
        assert_eq!(resolve_update_url(None, own, "beta"), own);
        // Blank means "nothing saved", so the channel's default is read.
        assert_eq!(resolve_update_url(None, "", "stable"), DEFAULT_UPDATE_MANIFEST_URL_STABLE);
        assert_eq!(resolve_update_url(None, "   ", "beta"), DEFAULT_UPDATE_MANIFEST_URL_BETA);
        // The environment wins over both, and is trimmed.
        assert_eq!(resolve_update_url(Some(""), own, "stable"), "");
        assert_eq!(resolve_update_url(Some("  https://mirror.test/u.json  "), "", "beta"),
                   "https://mirror.test/u.json");
        // The settings object asks the same question — unless this machine has the
        // environment variable set, which would decide it instead.
        if std::env::var_os("MICS_UPDATE_MANIFEST_URL").is_none() {
            let mut s = Settings::default();
            assert_eq!(s.update_url(), DEFAULT_UPDATE_MANIFEST_URL_STABLE);
            s.apply_patch(&json!({"update_channel": "beta"}))
                .expect("beta is a valid channel");
            assert_eq!(s.update_url(), DEFAULT_UPDATE_MANIFEST_URL_BETA);
        }
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let mut s = Settings::default();
        s.apply_patch(&json!({
            "lang": "en",
            "theme": "light",
            "dnd": true,
            "sync_interval_hours": 24,
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
        assert_eq!(back.canary_paths.len(), 2);
        assert_eq!(back.sound_volume, 10);
        assert!(!back.toast_enabled);
    }
}
