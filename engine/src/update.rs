//! Self-update apply: download the release ZIP, verify SHA256, then stage it
//! under %PROGRAMDATA%\MICS\update. Applying replaces the engine + app binaries
//! via the rename trick (current exe -> .old) and relaunches the UI.
//!
//! The manifest shape is the section-6 contract:
//! {version, url, sha256, size, notes_en, notes_ar}
//!
//! The manifest is only read after the detached signature published beside it
//! verifies against the certificate that signed this engine (D-047,
//! `docs/THREAT-MODEL.md` F-3). The `sha256` field catches a transfer that went
//! wrong; the signature is the part that says the feed is ours to trust.

use anyhow::{bail, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::platform::windows::process::ToolCall;
use crate::platform::windows::signature::{
    require_signed_by_pin, update_pin, verify_detached, Pin, VerifiedSigner,
};
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
///
/// The URL is `Settings::update_url()`: the user's own when they typed one, and
/// otherwise the channel's compiled-in default (D-046). `manifest_url` is echoed
/// back so the screen that asked can show which feed answered — an update answer
/// has to be checkable by the person reading it, not just plausible.
pub async fn check() -> Result<serde_json::Value> {
    let url = crate::settings::current().update_url();
    if crate::settings::update_checks_disabled(&url) {
        return Ok(json!({"status": "disabled",
            "detail": "update checks are switched off (MICS_UPDATE_MANIFEST_URL=off)"}));
    }
    let sm = SyncManager::new()?;
    // The bytes first, and the signature over exactly those bytes, before anything
    // parses them: a manifest that is not signed by the key this engine pins is
    // refused whatever its fields say (D-047).
    let raw = sm.fetch_bytes(&url, "the update manifest").await?;
    let verified = verify_manifest(&sm, &url, &raw).await?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&raw).with_context(|| format!("{url} is not manifest json"))?;
    let current = env!("CARGO_PKG_VERSION");
    let latest = manifest["version"].as_str().unwrap_or(current);
    Ok(json!({
        "status": if latest != current { "available" } else { "up_to_date" },
        "current": current,
        "latest": latest,
        "manifest_url": url,
        "download_url": manifest["url"].as_str(),
        "sha256": manifest["sha256"].as_str(),
        "notes_en": manifest["notes_en"].as_str(),
        "notes_ar": manifest["notes_ar"].as_str(),
        // Who signed the feed, and whether that was checked against a pin. The
        // screen prints the same fields it already prints; a probe reads them to
        // tell "verified against the pin" from "verified by name only".
        "signature": "verified",
        "signer": verified.signer.name,
        "signer_thumbprint": verified.signer.thumbprint,
        "pinned": verified.pinned,
    }))
}

/// The detached signature a feed publishes beside its manifest (D-047).
///
/// `<manifest>.sig`, the way a checksum names the file it describes, so the
/// manifest format does not change and a feed that publishes `update.json` says
/// nothing about its own signature. A query string or a fragment stays where it
/// is, so a feed served as `.../update.json?channel=beta` is described as
/// `.../update.json.sig?channel=beta` rather than guessed at.
pub fn signature_url(manifest_url: &str) -> String {
    let cut = manifest_url.find(['?', '#']).unwrap_or(manifest_url.len());
    format!("{}.sig{}", &manifest_url[..cut], &manifest_url[cut..])
}

/// A manifest whose signature verified, and the pin it was judged by.
struct Verified {
    signer: VerifiedSigner,
    /// True when the signer's thumbprint was compared against a pin this engine
    /// has; false when the engine carries no certificate of its own and only the
    /// release name could be checked.
    pinned: bool,
}

/// Fetches the signature beside `manifest_url` and verifies it over `raw`.
///
/// The pin is [`update_pin`]: the environment's test hook, or the certificate over
/// this executable, or — for a build with neither — the release name. A build with
/// no pin of its own still verifies the signature and still has to recognise that
/// name; an update feed that cannot be checked is refused with that reason, not read
/// anyway.
async fn verify_manifest(sm: &SyncManager, manifest_url: &str, raw: &[u8]) -> Result<Verified> {
    let sig_url = signature_url(manifest_url);
    let signature = sm
        .fetch_bytes(&sig_url, "the update manifest signature")
        .await
        .with_context(|| {
            format!(
                "the feed at {manifest_url} publishes no signature at {sig_url}: \
                 refusing an update manifest nothing signed"
            )
        })?;
    let signer = verify_detached(raw, &signature)
        .with_context(|| format!("the manifest at {manifest_url} was refused"))?;
    let pinned = judge(&update_pin()?, &signer, manifest_url)?;
    Ok(Verified { signer, pinned })
}

/// Whether a verified signer is the one this engine trusts, and which pin decided
/// it: `Ok(true)` when the thumbprint was compared, `Ok(false)` when this engine
/// has no certificate of its own and the release name had to stand in.
///
/// Pure on purpose: the refusals below are the whole policy of F-3's feed half,
/// and they are checked in unit tests rather than only against a live feed.
fn judge(pin: &Pin, signer: &VerifiedSigner, manifest_url: &str) -> Result<bool> {
    if pin.accepts(signer.name.as_deref(), Some(&signer.thumbprint)) {
        return Ok(matches!(pin, Pin::Thumbprint(_)));
    }
    match pin {
        Pin::Thumbprint(_) => bail!(
            "the manifest at {manifest_url} was refused: it is signed by {}, and this engine pins {}",
            describe(signer),
            pin.describe()
        ),
        Pin::Name(cn) => bail!(
            "the manifest at {manifest_url} was refused: it is signed by {}, and this engine \
             carries no signature of its own to pin, so the signer must be {cn}",
            describe(signer)
        ),
    }
}

/// A signer as a refusal has to name it: the name a person can read first, then
/// the thumbprint, so two certificates that share a subject stay tellable apart.
fn describe(signer: &VerifiedSigner) -> String {
    match signer.name.as_deref() {
        Some(name) => format!("{name:?} (thumbprint {})", signer.thumbprint),
        None => format!("a certificate with thumbprint {}", signer.thumbprint),
    }
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

    // F-3: the extracted binaries must be signed by the certificate this engine
    // pins *and* pass Windows' own chain check before they may replace the running
    // ones. The manifest's SHA-256 only proves the archive is the one the manifest
    // described; this proves who produced the binaries inside. The pin is the same
    // one the manifest's signature was judged by (D-051): with a real certificate in
    // use the *thumbprint* is what is compared, because the release name can no
    // longer be `MI CS Code Signing` at all.
    let pin = update_pin()?;
    for name in ["mics-engine.exe", "mics_app.exe"] {
        let candidate = src_root.join(name);
        if candidate.exists() {
            require_signed_by_pin(&candidate, &pin)
                .with_context(|| format!("update payload refused: {name}"))?;
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::windows::signature::EXPECTED_SIGNER_CN;

    fn signer(name: &str, thumbprint: &str) -> VerifiedSigner {
        VerifiedSigner {
            name: Some(name.to_string()),
            thumbprint: thumbprint.to_string(),
        }
    }

    const OURS: &str = "abcdef0123456789abcdef0123456789abcdef01";

    #[test]
    fn the_signature_sits_where_the_manifest_does() {
        // Plain, with a query, with a fragment, and with both: the signature is
        // the manifest's own name plus `.sig`, so a feed cannot ask for one file
        // and sign another (D-047).
        assert_eq!(
            signature_url("https://host/u/update.json"),
            "https://host/u/update.json.sig"
        );
        assert_eq!(
            signature_url("http://127.0.0.1:9/good.json?x=1"),
            "http://127.0.0.1:9/good.json.sig?x=1"
        );
        assert_eq!(
            signature_url("https://host/update.json#top"),
            "https://host/update.json.sig#top"
        );
        assert_eq!(
            signature_url("https://host/update.json?a=1#b"),
            "https://host/update.json.sig?a=1#b"
        );
    }

    #[test]
    fn a_manifest_is_judged_by_the_thumbprint_pin() {
        // The pin decides, and a signature by another key is refused with both
        // thumbprints named so the refusal can be checked.
        let ours = signer(EXPECTED_SIGNER_CN, OURS);
        let pin = Pin::Thumbprint(OURS.to_string());
        assert!(
            judge(&pin, &ours, "u").unwrap(),
            "the pinned certificate must be accepted"
        );

        let other = signer(EXPECTED_SIGNER_CN, &"b".repeat(40));
        let refused = judge(&pin, &other, "https://host/u.json")
            .expect_err("a signature by another key must be refused");
        let message = format!("{refused:#}");
        assert!(message.contains(OURS), "names the pin: {message}");
        assert!(message.contains(&"b".repeat(40)), "names the signer: {message}");
    }

    #[test]
    fn the_right_release_name_does_not_save_the_wrong_thumbprint() {
        // D-016's residual, now refused: a certificate that a CA issued with the
        // release CN in it is not the certificate this engine pins. The name is
        // identical, so only the thumbprint can tell them apart — which is the
        // whole reason decision (c) moved the pin (D-051).
        let impostor = signer(EXPECTED_SIGNER_CN, &"e".repeat(40));
        let refused = judge(
            &Pin::Thumbprint(OURS.to_string()),
            &impostor,
            "https://host/u.json",
        )
        .expect_err("the same CN from another key is not the pinned certificate");
        let message = format!("{refused:#}");
        assert!(
            message.contains(EXPECTED_SIGNER_CN) && message.contains(OURS),
            "the refusal names the name it did not accept and the pin it wanted: {message}"
        );
    }

    #[test]
    fn a_development_engine_falls_back_to_the_name_and_says_so() {
        // No pin: a dev engine has no signature of its own. The name still has to
        // be the release name, and the answer reports the weaker check as weaker.
        let pin = Pin::Name(EXPECTED_SIGNER_CN);
        let ours = signer(EXPECTED_SIGNER_CN, OURS);
        assert!(
            !judge(&pin, &ours, "u").unwrap(),
            "a name-only check must report itself as the weaker one"
        );

        let impostor = signer("Some Other Signer", &"c".repeat(40));
        let refused = judge(&pin, &impostor, "https://host/u.json")
            .expect_err("a different name must be refused when there is no pin");
        let message = format!("{refused:#}");
        assert!(
            message.contains("Some Other Signer") && message.contains(EXPECTED_SIGNER_CN),
            "the refusal names both the signer and the expected name: {message}"
        );

        // A certificate with no readable name is never ours.
        let nameless = VerifiedSigner {
            name: None,
            thumbprint: "d".repeat(40),
        };
        assert!(judge(&pin, &nameless, "u").is_err());
    }
}
