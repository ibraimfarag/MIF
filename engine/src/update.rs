//! Self-update apply: download the release ZIP, verify SHA256, then stage it
//! under %PROGRAMDATA%\MICS\update. Applying replaces the engine + app binaries
//! via the rename trick (current exe -> .old) and relaunches the UI.
//!
//! The manifest shape is the section-6 contract:
//! {version, url, sha256, size, notes_en, notes_ar}

use anyhow::{bail, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::platform::windows::process::ToolCall;
use crate::sync::SyncManager;

/// How long the staged archive may take to unpack. A ~24 MB zip takes seconds; a
/// PowerShell that never returns must not hold the update request open.
const UPDATE_EXTRACT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The `Expand-Archive` call, with its deadline. Zipping and unzipping through
/// PowerShell is the engine's supported path because the alternative is a zip
/// dependency in the shipped binary; the deadline is what makes shelling out
/// safe.
pub(crate) fn extract_call(zip_path: &str, out_dir: &str) -> ToolCall {
    ToolCall::new(
        "powershell Expand-Archive (update: extract)",
        "powershell",
        UPDATE_EXTRACT_TIMEOUT,
    )
    .args(["-NoProfile", "-Command"])
    .arg(format!(
        "Expand-Archive -Path '{zip_path}' -DestinationPath '{out_dir}' -Force"
    ))
}

fn staging_dir() -> PathBuf {
    crate::settings::Settings::base_dir().join("update")
}

/// Downloads the manifest and returns its parsed fields (update.check).
pub async fn check() -> Result<serde_json::Value> {
    let url = crate::settings::current().update_url();
    if url.is_empty() {
        return Ok(json!({"status": "disabled",
            "detail": "no update manifest URL configured (Settings → Updates)"}));
    }
    let sm = SyncManager::new()?;
    let manifest = sm.fetch_manifest(&url).await?;
    let current = env!("CARGO_PKG_VERSION");
    let latest = manifest["version"].as_str().unwrap_or(current);
    Ok(json!({
        "status": if latest != current { "available" } else { "up_to_date" },
        "current": current,
        "latest": latest,
        "download_url": manifest["url"].as_str(),
        "sha256": manifest["sha256"].as_str(),
        "notes_en": manifest["notes_en"].as_str(),
        "notes_ar": manifest["notes_ar"].as_str(),
    }))
}

/// Downloads + verifies + stages the update. Returns the staged path.
pub async fn download_and_verify() -> Result<PathBuf> {
    let info = check().await?;
    if info["status"] != "available" {
        bail!("no update available");
    }
    let url = info["download_url"]
        .as_str()
        .context("manifest missing url")?;
    let expected = info["sha256"]
        .as_str()
        .context("manifest missing sha256")?
        .to_lowercase();

    let sm = SyncManager::new()?;
    let bytes = sm.download(url).await?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != expected {
        bail!("SHA256 mismatch: expected {expected}, got {actual}");
    }

    let dir = staging_dir();
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join("update.zip");
    std::fs::write(&dest, &bytes).context("stage update.zip")?;
    Ok(dest)
}

/// Applies a staged update: extracts over the app dir with the rename trick
/// for the two running binaries, then relaunches the UI. Best-effort on files
/// the extractor can't replace (they keep the .old rename).
pub fn apply(staged_zip: &std::path::Path) -> Result<String> {
    let app_exe = std::env::current_exe().context("resolve engine exe")?;
    let engine_dir = app_exe.parent().context("engine dir")?;
    let app_dir = engine_dir.join("mics_app.exe");
    let target_dir = if app_dir.exists() {
        engine_dir.to_path_buf()
    } else {
        // UI lives next to the engine in the packaged layout; in dev the app
        // is elsewhere — extract next to the engine and let the user move it.
        engine_dir.to_path_buf()
    };

    let extract_dir = staging_dir().join("extracted");
    let _ = std::fs::remove_dir_all(&extract_dir);
    std::fs::create_dir_all(&extract_dir)?;

    let zip_path = staged_zip.to_string_lossy().replace('\\', "/");
    let out_dir = extract_dir.to_string_lossy().replace('\\', "/");
    let extracted = extract_call(&zip_path, &out_dir)
        .run()
        .context("extract update")?;
    if !extracted.success {
        bail!("extract failed: {}", extracted.text.trim());
    }

    // The zip root may be MICS-portable/ or flat — find mics-engine.exe.
    let src_root = find_root(&extract_dir).context("update zip missing mics-engine.exe")?;

    // Copy everything over, renaming locked binaries to .old first.
    copy_over(&src_root, &target_dir)?;

    // Relaunch the UI.
    let ui = target_dir.join("mics_app.exe");
    if ui.exists() {
        let _ = std::process::Command::new(&ui).spawn();
    }
    Ok(format!("applied to {}", target_dir.display()))
}

fn find_root(dir: &PathBuf) -> Option<PathBuf> {
    if dir.join("mics-engine.exe").exists() {
        return Some(dir.clone());
    }
    for sub in std::fs::read_dir(dir).ok()?.flatten() {
        if sub.path().is_dir()
            && let Some(found) = find_root(&sub.path()) {
                return Some(found);
            }
    }
    None
}

fn copy_over(src: &PathBuf, dst: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_over(&from, &to)?;
            continue;
        }
        if to.exists() {
            // Rename trick: a running exe can be renamed but not deleted.
            let old = to.with_extension("old");
            let _ = std::fs::remove_file(&old);
            if std::fs::rename(&to, &old).is_err() {
                continue; // locked and not renamable — skip
            }
        }
        std::fs::copy(&from, &to).with_context(|| format!("copy {}", to.display()))?;
    }
    Ok(())
}
