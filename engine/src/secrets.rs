//! The two API keys, at rest — never in `settings.json`.
//!
//! `nvd_api_key` and `ioc_feed_key` used to be stored as plaintext in the
//! settings document, so any file copy of it (a backup, a synced folder, a
//! screenshot, a bug report) carried a working credential. They now live in
//! `<data dir>\secrets.dat`, protected with DPAPI at **machine scope** — the
//! same primitive the quarantine master key uses (`scanner\quarantine.rs`) — and
//! `settings.json` no longer holds them at all.
//!
//! The format is a magic header plus the DPAPI blob, so a file that is not ours
//! is refused instead of being fed to `CryptUnprotectData`:
//!
//! ```text
//! 4 bytes  magic "MS1\0"
//! n bytes  CryptProtectData(blob) of the UTF-8 JSON {"nvd_api_key":..., "ioc_feed_key":...}
//! ```
//!
//! `Settings` still *returns* the values over `settings.get`, because the UI
//! prefills the fields that own them and both are the same interactive user;
//! what changed is what is written where.
//!
//! # The honest limit
//!
//! DPAPI machine scope means "anyone on this computer can ask Windows to
//! decrypt it": it binds the blob to the machine, not to a user. What it
//! removes is the *plaintext copy* — the file is no longer a credential that
//! leaves with a backup or a shared folder, and it is no longer readable by
//! anything that does not call DPAPI on this machine. It is not a vault against
//! a local administrator, and the register says so
//! (`docs/TODO.md` §7, `docs/THREAT-MODEL.md` F-5).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Identifies our document, so a foreign file is refused rather than decrypted.
const MAGIC: &[u8; 4] = b"MS1\0";

/// The file name inside the data directory.
pub const FILE_NAME: &str = "secrets.dat";

/// The secrets the engine keeps out of `settings.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Secrets {
    /// NVD API key (optional; raises the public rate limit).
    pub nvd_api_key: String,
    /// Auth-Key for the user's own hash feed (abuse.ch style header).
    pub ioc_feed_key: String,
}

impl Secrets {
    /// Takes any plaintext key out of `settings` (the legacy layout) and puts it
    /// here, **only** into a slot this file does not already fill: a migrated
    /// value must never overwrite a newer protected one.
    ///
    /// Returns how many values moved, so the caller can say so once.
    pub fn absorb_legacy(&mut self, settings: &mut crate::settings::Settings) -> usize {
        let mut moved = 0;
        if !settings.nvd_api_key.is_empty() {
            if self.nvd_api_key.is_empty() {
                self.nvd_api_key = std::mem::take(&mut settings.nvd_api_key);
                moved += 1;
            } else {
                settings.nvd_api_key.clear();
            }
        }
        if !settings.ioc_feed_key.is_empty() {
            if self.ioc_feed_key.is_empty() {
                self.ioc_feed_key = std::mem::take(&mut settings.ioc_feed_key);
                moved += 1;
            } else {
                settings.ioc_feed_key.clear();
            }
        }
        moved
    }
}

/// `<dir>\secrets.dat`.
pub fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILE_NAME)
}

/// Reads `dir\secrets.dat`.
///
/// A missing file is "no keys yet". A file that is ours but cannot be decrypted
/// (a different machine, a wiped DPAPI master key, a truncated write) is logged
/// and treated as empty rather than blocking the engine: the user can paste the
/// key again, and the UI shows the field empty. A corrupt file is *not* deleted —
/// it may be the only copy of something, and the next save replaces it atomically.
pub fn load_from(dir: &Path) -> Secrets {
    let file = path_in(dir);
    let raw = match std::fs::read(&file) {
        Ok(raw) => raw,
        Err(_) => return Secrets::default(),
    };
    match decode(&raw) {
        Ok(secrets) => secrets,
        Err(e) => {
            tracing::warn!(
                "{} is unreadable ({e:#}) — the stored API keys are not available; \
                 paste them again in Settings",
                file.display()
            );
            Secrets::default()
        }
    }
}

/// Writes `dir\secrets.dat` atomically (temp file + rename), so a crash mid-write
/// never leaves a truncated credential file behind.
pub fn save_to(dir: &Path, secrets: &Secrets) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let file = path_in(dir);
    let tmp = file.with_extension("dat.tmp");
    let bytes = encode(secrets)?;
    std::fs::write(&tmp, &bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &file).with_context(|| format!("replace {}", file.display()))?;
    Ok(())
}

/// DPAPI-protects the document. An all-empty document is still written: the file
/// exists so "the keys are gone" is a fact on disk rather than an absence.
fn encode(secrets: &Secrets) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(secrets).context("serialize secrets")?;
    let protected = windows_dpapi::encrypt_data(&json, windows_dpapi::Scope::Machine, None)
        .map_err(|e| anyhow::anyhow!("DPAPI protect failed: {e}"))?;
    let mut out = Vec::with_capacity(MAGIC.len() + protected.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&protected);
    Ok(out)
}

/// Reverses [`encode`], refusing anything that is not our document.
fn decode(raw: &[u8]) -> Result<Secrets> {
    if raw.len() <= MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
        bail!("not an MI CS secrets document (bad header)");
    }
    let plain = windows_dpapi::decrypt_data(&raw[MAGIC.len()..], windows_dpapi::Scope::Machine, None)
        .map_err(|e| anyhow::anyhow!("DPAPI unprotect failed: {e}"))?;
    serde_json::from_slice(&plain).context("secrets document is not the expected JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mics-secrets-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_saved_key_is_not_what_is_on_disk() {
        let dir = scratch("roundtrip");
        let secret = "nvd-SECRET-0123456789abcdef";
        let feed = "feed-SECRET-abcdef0123456789";
        let secrets = Secrets {
            nvd_api_key: secret.into(),
            ioc_feed_key: feed.into(),
        };
        save_to(&dir, &secrets).unwrap();

        let raw = std::fs::read(path_in(&dir)).unwrap();
        assert_eq!(&raw[..4], MAGIC, "the file starts with our header");
        for needle in [secret, feed] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle} is readable in secrets.dat"
            );
        }
        assert_eq!(load_from(&dir), secrets, "the roundtrip keeps both values");

        // And the protected bytes really are DPAPI's, not our own cipher: a
        // blob written for another scope fails to decode.
        let mut foreign = raw.clone();
        foreign[4] ^= 0xff;
        assert!(decode(&foreign).is_err(), "a damaged blob must not decode");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_settings_file_is_written_without_the_keys_and_reads_them_back() {
        let dir = scratch("settings");
        let mut s = Settings::default();
        let key = "nvd-KEY-123456";
        let feed = "ioc-KEY-abcdef";
        s.nvd_api_key = key.into();
        s.ioc_feed_key = feed.into();
        s.write_to(&dir).unwrap();

        // The JSON document on disk names neither key...
        let settings_json = std::fs::read_to_string(dir.join("settings.json")).unwrap();
        assert!(!settings_json.contains("nvd-KEY-123456"), "{settings_json}");
        assert!(!settings_json.contains("ioc-KEY-abcdef"), "{settings_json}");
        assert!(!settings_json.contains("nvd_api_key"), "{settings_json}");
        assert!(!settings_json.contains("ioc_feed_key"), "{settings_json}");
        // ...and the secrets file does not hold them in the clear either.
        let secrets_raw = std::fs::read(path_in(&dir)).unwrap();
        for needle in ["nvd-KEY-123456", "ioc-KEY-abcdef"] {
            assert!(
                !secrets_raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle} is readable in secrets.dat"
            );
        }

        // A fresh read (a new engine process) gets both values back.
        let back = Settings::read_from(&dir);
        assert_eq!(back.nvd_api_key, "nvd-KEY-123456");
        assert_eq!(back.ioc_feed_key, "ioc-KEY-abcdef");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_plaintext_file_is_migrated_once_and_the_settings_document_is_cleaned() {
        let dir = scratch("migrate");
        // The pre-change layout: both keys in the settings document itself.
        let legacy_key = "nvd-LEGACY-999";
        let legacy_feed = "ioc-LEGACY-888";
        let legacy = serde_json::json!({
            "lang": "en",
            "nvd_api_key": legacy_key,
            "ioc_feed_key": legacy_feed
        });
        std::fs::write(
            dir.join("settings.json"),
            serde_json::to_string_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let first = Settings::read_from(&dir);
        assert_eq!(first.nvd_api_key, "nvd-LEGACY-999", "no key is lost by the migration");
        assert_eq!(first.ioc_feed_key, "ioc-LEGACY-888");
        assert_eq!(first.lang, "en", "the rest of the document survives");

        // The file was rewritten without them, and the secrets file now has them.
        let rewritten = std::fs::read_to_string(dir.join("settings.json")).unwrap();
        assert!(!rewritten.contains("LEGACY"), "{rewritten}");
        assert!(!rewritten.contains("nvd_api_key"), "{rewritten}");
        assert_eq!(load_from(&dir).nvd_api_key, "nvd-LEGACY-999");

        // A second read is the same answer (the migration is idempotent).
        let second = Settings::read_from(&dir);
        assert_eq!(second.nvd_api_key, "nvd-LEGACY-999");
        assert_eq!(second.ioc_feed_key, "ioc-LEGACY-888");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_legacy_value_never_overwrites_a_protected_one() {
        let dir = scratch("no-overwrite");
        let mut settings = Settings::default();
        let stale = "nvd-LEGACY";
        let protected = "nvd-PROTECTED";
        settings.nvd_api_key = stale.into();
        let mut stored = Secrets {
            nvd_api_key: protected.into(),
            ioc_feed_key: String::new(),
        };
        assert_eq!(stored.absorb_legacy(&mut settings), 0);
        assert_eq!(stored.nvd_api_key, "nvd-PROTECTED");
        assert!(settings.nvd_api_key.is_empty(), "the stale plaintext is dropped");
        let _ = &dir;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_foreign_file_is_refused_instead_of_decrypted() {
        let dir = scratch("foreign");
        std::fs::write(path_in(&dir), b"PK\x03\x04 not our document").unwrap();
        assert_eq!(load_from(&dir), Secrets::default(), "a stranger's file is not a key store");
        std::fs::remove_dir_all(&dir).ok();
    }
}