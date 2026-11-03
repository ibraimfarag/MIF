//! The package's own integrity: the answer `status.integrity` reports (ج2, D-025).
//!
//! `scripts\make-release.ps1` injects a JSON document — every shipped file with
//! its size and SHA-256 — into this executable as the `RT_RCDATA` resource
//! `MICS_MANIFEST`, and signs the result. So the document's authenticity is not a
//! separate signature to keep in step: it is *this file's* Authenticode signature,
//! and the pin that makes that mean anything (`EXPECTED_SIGNER_CN`) already exists
//! in `platform::windows::signature`.
//!
//! The engine is not in its own manifest. Its integrity is exactly the signature
//! over the bytes that carry the manifest, so listing it would be circular; every
//! other file in the folder is listed and hashed from the folder this engine runs
//! in. A copy whose files were swapped, renamed, truncated or edited therefore
//! cannot answer `ok` — the engine says so itself, before the user trusts a screen
//! that is maybe not the one we shipped.
//!
//! Three states, because two would be dishonest (D-025):
//!
//! * [`Integrity::Ok`] — signed by us, trusted by this Windows, every listed file
//!   hashes as published;
//! * [`Integrity::UntrustedCertificate`] — the same, except this Windows has not
//!   trusted the release certificate yet (the self-signed situation D-002
//!   records). Showing the "unofficial build" warning here would fire on every
//!   honest install, and a signal that always fires says nothing;
//! * [`Integrity::Unverified`] — not provable: no manifest, a broken one, another
//!   signer, or a listed file that is missing or changed.
//!
//! What it cannot do is written down in `docs/THREAT-MODEL.md` F-11: a repackager
//! who rebuilds from source and re-signs with their own key is indistinguishable
//! from us to any local check. This makes a *silent* edit of a published copy
//! impossible, which is the half that can be proved locally.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::FreeLibrary;
use windows::Win32::System::LibraryLoader::{
    FindResourceW, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
    LOAD_LIBRARY_AS_DATAFILE,
};

use crate::platform::windows::signature::{self, Trust};

/// The resource name `scripts\manifest-resource.ps1` writes (D-025).
const RESOURCE_NAME: &str = "MICS_MANIFEST";
/// `RT_RCDATA` (10), in the `MAKEINTRESOURCE` form `FindResource` wants.
const RCDATA: usize = 10;
/// The only document format this build understands.
const FORMAT: u32 = 1;
/// How many failing paths one detail line names; the rest are counted.
const DETAIL_LIMIT: usize = 3;

/// One shipped file, as the document lists it.
#[derive(Debug, Clone, Deserialize)]
struct Entry {
    path: String,
    bytes: u64,
    sha256: String,
}

/// The document as it is injected, and the only shape we accept.
#[derive(Debug, Deserialize)]
struct Document {
    format: u32,
    version: String,
    files: Vec<Entry>,
}

/// The three answers `status.integrity` reports (D-025).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// Signed by us, trusted here, and every listed file hashes as published.
    Ok,
    /// Signed by us and every file matches, but this Windows does not trust the
    /// release certificate yet. Nothing is wrong with the copy.
    UntrustedCertificate,
    /// Not provable: no manifest, a broken one, another signer, or a file that
    /// is missing or changed.
    Unverified,
}

impl Integrity {
    /// The wire word `status.integrity` carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::UntrustedCertificate => "untrusted-certificate",
            Self::Unverified => "unverified",
        }
    }
}

/// The verdict, plus what a support case needs to read.
#[derive(Debug, Clone)]
pub struct Report {
    pub state: Integrity,
    /// The document was there and parsed: this copy claims to be a release.
    ///
    /// A developer build has none, and that is the difference between "somebody
    /// edited the released files" and "this was never a release" — the first
    /// earns a card, the second only a line in the log.
    pub manifest: bool,
    /// How many files the document lists (0 when there is none).
    pub files: usize,
    pub version: Option<String>,
    /// What went wrong, in one line, when `state` is not `ok`.
    pub detail: Option<String>,
}

/// The verdict for this process, computed once.
///
/// Hashing a package is tens of megabytes and `status` answers the UI's 15 s
/// heartbeat: the first caller pays, every later one reads the cache.
pub fn state() -> &'static Report {
    static REPORT: OnceLock<Report> = OnceLock::new();
    REPORT.get_or_init(|| check(&own_exe()))
}

/// Computes the verdict once and says it: in the log always, and on the user's
/// desktop when this copy claims to be a release and cannot prove it.
///
/// `announce` is false for the one-shot CLI modes (`audit`, `scan`, ...): they
/// answer a question and exit, and a card raised there would interrupt somebody
/// who is already looking at the cause.
pub fn start(announce: bool) {
    let report = state();
    let version = report.version.as_deref().unwrap_or("unknown");
    match report.state {
        Integrity::Ok => tracing::info!(
            "package integrity: ok - {} file(s) hash as the manifest says (package {version})",
            report.files
        ),
        Integrity::UntrustedCertificate => tracing::info!(
            "package integrity: {version}, {} listed file(s) match and the engine is signed by \
             \"{}\", but this Windows does not trust that certificate yet (self-signed build); \
             nothing is wrong with this copy",
            report.files,
            signature::EXPECTED_SIGNER_CN
        ),
        Integrity::Unverified => {
            let detail = report
                .detail
                .as_deref()
                .unwrap_or("the package does not describe itself");
            tracing::warn!("package integrity: unverified - {detail}");
            if announce && report.manifest {
                crate::notify::alert::package_changed(detail);
            }
        }
    }
}

/// The whole check for one executable: read its manifest, verify the files beside
/// it, and classify its signature.
///
/// Takes the path instead of reading the process image so a test can point it at
/// a real release package.
pub fn check(exe: &Path) -> Report {
    // The package root is the folder the engine runs from: the document's paths
    // are relative to it, which is what makes the ZIP relocatable.
    let root = exe.parent().unwrap_or(Path::new("."));
    let document = match read_document(exe) {
        Ok(Some(document)) => document,
        Ok(None) => {
            return unverified(
                false,
                0,
                None,
                "the engine carries no MICS_MANIFEST resource",
            );
        }
        Err(e) => return unverified(false, 0, None, &format!("{e:#}")),
    };

    let failures = verify_files(root, &document.files);
    // A file we cannot read at all is not "somebody else's": both end up
    // unverified, and `trust` is the only thing that can make it quiet.
    let trust = signature::trust(exe).unwrap_or(Trust::NotOurs);
    let mut detail = if failures.is_empty() {
        None
    } else {
        Some(summarise(&failures))
    };
    let state = classify(failures.is_empty(), trust);
    if state == Integrity::Unverified && detail.is_none() {
        detail = Some(format!(
            "the engine is not signed by \"{}\"",
            signature::EXPECTED_SIGNER_CN
        ));
    }

    Report {
        state,
        manifest: true,
        files: document.files.len(),
        version: Some(document.version),
        detail,
    }
}

/// D-025's table, as a pure function: a real mismatch is never the quiet state,
/// whatever the certificate says.
fn classify(files_match: bool, trust: Trust) -> Integrity {
    match (files_match, trust) {
        (false, _) => Integrity::Unverified,
        (true, Trust::Ours) => Integrity::Ok,
        (true, Trust::UntrustedRoot) => Integrity::UntrustedCertificate,
        (true, Trust::NotOurs) => Integrity::Unverified,
    }
}

/// A report for a copy that cannot be proved, with its one-line reason.
fn unverified(manifest: bool, files: usize, version: Option<String>, detail: &str) -> Report {
    Report {
        state: Integrity::Unverified,
        manifest,
        files,
        version,
        detail: Some(detail.to_string()),
    }
}

/// One line naming the first failures; a card is a nudge, not a log file.
fn summarise(failures: &[String]) -> String {
    let named = failures
        .iter()
        .take(DETAIL_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    match failures.len().checked_sub(DETAIL_LIMIT) {
        Some(more) if more > 0 => format!("{named}; and {more} more"),
        _ => named,
    }
}

/// This process's image: the package's root is the folder it sits in.
fn own_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mics-engine.exe"))
}

/// The document injected into `exe`, or `None` when the resource is not there.
fn read_document(exe: &Path) -> Result<Option<Document>> {
    let Some(bytes) = resource_bytes(exe)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).context("the MICS_MANIFEST resource is not UTF-8")?;
    parse(&text).map(Some)
}

/// Parses and validates a document.
///
/// The order of the entries is deliberately *not* checked: ordinal sorting is the
/// producer's contract (`scripts\verify-manifest.ps1` enforces it), and refusing a
/// package the release gate accepted over a collation difference would be a worse
/// failure than the thing the order was there for.
fn parse(json: &str) -> Result<Document> {
    let document: Document =
        serde_json::from_str(json).context("the MICS_MANIFEST document does not parse")?;
    if document.format != FORMAT {
        bail!(
            "the MICS_MANIFEST format is {}, this build reads {FORMAT}",
            document.format
        );
    }
    if document.version.trim().is_empty() {
        bail!("the MICS_MANIFEST document names no version");
    }
    if document.files.is_empty() {
        bail!("the MICS_MANIFEST document lists no files");
    }
    for (index, entry) in document.files.iter().enumerate() {
        if document.files[..index]
            .iter()
            .any(|earlier| earlier.path == entry.path)
        {
            bail!("the MICS_MANIFEST lists {} twice", entry.path);
        }
        if safe_join(Path::new("."), &entry.path).is_err() {
            bail!(
                "the MICS_MANIFEST names a path outside the package: {}",
                entry.path
            );
        }
        if entry.sha256.len() != 64 || !entry.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("the MICS_MANIFEST has no sha256 for {}", entry.path);
        }
    }
    Ok(document)
}

/// Hashes every listed file under `root` and names the ones that do not match.
///
/// Empty means "this folder is the one the document describes".
fn verify_files(root: &Path, entries: &[Entry]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in entries {
        let Ok(path) = safe_join(root, &entry.path) else {
            failures.push(format!("{}: not a path inside the package", entry.path));
            continue;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            failures.push(format!("{}: missing", entry.path));
            continue;
        };
        if meta.len() != entry.bytes {
            failures.push(format!(
                "{}: {} bytes, published {}",
                entry.path,
                meta.len(),
                entry.bytes
            ));
            continue;
        }
        match sha256_file(&path) {
            Ok(digest) if digest.eq_ignore_ascii_case(&entry.sha256) => {}
            Ok(_) => failures.push(format!("{}: changed", entry.path)),
            Err(e) => failures.push(format!("{}: unreadable ({e:#})", entry.path)),
        }
    }
    failures
}

/// Joins a document path to the package root, refusing anything that is not a
/// plain relative path.
///
/// The document travels inside our own signature, but a repackager's does not:
/// `..\..\Windows\System32\...` must never be readable through it, and neither
/// must a driver-absolute or UNC path.
fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() {
        bail!("an empty path");
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        bail!("an absolute path");
    }
    if !path
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
    {
        bail!("a path with a parent, a root or a prefix");
    }
    Ok(root.join(path))
}

/// SHA-256 of a file, streamed so a large file cannot be held in memory.
fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// The bytes of the `MICS_MANIFEST` resource in `exe`, or `None` when it has none.
///
/// `LOAD_LIBRARY_AS_DATAFILE` maps the image as data: no code runs, no
/// dependencies load, and the resource is addressable without parsing the PE by
/// hand. The mapping is released before returning.
fn resource_bytes(exe: &Path) -> Result<Option<Vec<u8>>> {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = std::ffi::OsStr::new(exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; the returned handle
    // is released by the `FreeLibrary` at the end of this function.
    let module = unsafe { LoadLibraryExW(PCWSTR(wide.as_ptr()), None, LOAD_LIBRARY_AS_DATAFILE) }
        .map_err(|e| {
        anyhow::anyhow!(
            "cannot map {} to read its manifest: {e}",
            exe.display()
        )
    })?;

    let name: Vec<u16> = RESOURCE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `module` is the handle taken above, `name` is NUL-terminated, and
    // `RCDATA` is passed in `MAKEINTRESOURCE` form, which is what `FindResource`
    // documents for a predefined type.
    let found = unsafe {
        FindResourceW(
            Some(module),
            PCWSTR(name.as_ptr()),
            PCWSTR(RCDATA as *const u16),
        )
    };
    if found.is_invalid() {
        // SAFETY: the handle came from `LoadLibraryExW` above and is not used again.
        let _ = unsafe { FreeLibrary(module) };
        return Ok(None);
    }

    // SAFETY: `found` is a resource handle from this module; both calls take it
    // by value and neither invalidates it.
    let size = unsafe { SizeofResource(Some(module), found) };
    let loaded = unsafe { LoadResource(Some(module), found) };
    let bytes = match loaded {
        Ok(handle) if size > 0 => {
            // SAFETY: the resource is `size` bytes, locked for the life of the
            // module handle, and copied out before it is released.
            let pointer = unsafe { LockResource(handle) };
            if pointer.is_null() {
                None
            } else {
                // SAFETY: `pointer` addresses `size` initialised bytes of the
                // mapped image; the slice does not outlive this block.
                Some(unsafe {
                    std::slice::from_raw_parts(pointer as *const u8, size as usize).to_vec()
                })
            }
        }
        _ => None,
    };
    // SAFETY: the handle came from `LoadLibraryExW` above, the bytes are copied,
    // and it is not used afterwards.
    let _ = unsafe { FreeLibrary(module) };

    match bytes {
        Some(bytes) => Ok(Some(bytes)),
        None => bail!("the MICS_MANIFEST resource is empty or unreadable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document with the given entries, written the way the release script
    /// writes it. Built through `serde_json` so a hostile path reaches `parse`
    /// as the string a real document would carry, not as a JSON escape mistake.
    fn document(paths: &[(&str, u64, &str)]) -> String {
        let files = paths
            .iter()
            .map(|(path, bytes, sha)| {
                serde_json::json!({"path": path, "bytes": bytes, "sha256": sha})
            })
            .collect::<Vec<_>>();
        serde_json::json!({"format": 1, "version": "MI CS 0.1.0", "files": files}).to_string()
    }

    const DIGEST: &str = "1ef47f669c7fca8f99950efba3acbe06133338217393ccd42792038c8652d376";

    #[test]
    fn a_document_parses_and_keeps_its_files() {
        let parsed = parse(&document(&[
            ("THIRD-PARTY-NOTICES", 3, DIGEST),
            ("rules\\guard\\x.rule", 9, DIGEST),
        ]))
        .expect("a document the release script writes must parse");
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.version, "MI CS 0.1.0");
        assert_eq!(parsed.files[1].path, "rules\\guard\\x.rule");
    }

    #[test]
    fn a_format_this_build_does_not_read_is_refused() {
        let other = document(&[("a.txt", 1, DIGEST)]).replace(r#""format":1"#, r#""format":2"#);
        let err = format!("{:#}", parse(&other).expect_err("format 2 is not ours"));
        assert!(err.contains("format is 2"), "{err}");
    }

    #[test]
    fn an_empty_document_is_refused() {
        let empty = r#"{"format":1,"version":"MI CS 0.1.0","files":[]}"#;
        let err = format!("{:#}", parse(empty).expect_err("no files is not a package"));
        assert!(err.contains("lists no files"), "{err}");
    }

    #[test]
    fn a_path_that_walks_out_of_the_package_is_refused() {
        for hostile in [
            "..\\..\\Windows\\System32\\cmd.exe",
            "rules\\..\\..\\escape.txt",
            "C:\\Windows\\notepad.exe",
            "\\\\server\\share\\x.txt",
            "\\rooted.txt",
        ] {
            let json = document(&[(hostile, 1, DIGEST)]);
            // The *reason* matters as much as the refusal: a document that fails
            // to parse for some other reason would hide the case being tested.
            let err = format!(
                "{:#}",
                parse(&json).expect_err(&format!("{hostile} must not be readable"))
            );
            assert!(
                err.contains("outside the package"),
                "{hostile} was refused for the wrong reason: {err}"
            );
        }
    }

    #[test]
    fn a_duplicate_or_unhashed_entry_is_refused() {
        let twice = document(&[("a.txt", 1, DIGEST), ("a.txt", 1, DIGEST)]);
        let err = format!("{:#}", parse(&twice).expect_err("a list twice is ambiguous"));
        assert!(err.contains("twice"), "{err}");

        let short = document(&[("a.txt", 1, "deadbeef")]);
        let err = format!("{:#}", parse(&short).expect_err("a short hash is not a hash"));
        assert!(err.contains("no sha256"), "{err}");
    }

    #[test]
    fn the_state_is_the_table_in_d025() {
        // The quiet state is only reachable when the files match *and* the
        // signer settles it; anything else is the alarm.
        assert_eq!(classify(true, Trust::Ours), Integrity::Ok);
        assert_eq!(
            classify(true, Trust::UntrustedRoot),
            Integrity::UntrustedCertificate
        );
        assert_eq!(classify(true, Trust::NotOurs), Integrity::Unverified);
        assert_eq!(classify(false, Trust::Ours), Integrity::Unverified);
        assert_eq!(classify(false, Trust::UntrustedRoot), Integrity::Unverified);
        assert_eq!(
            Integrity::UntrustedCertificate.as_str(),
            "untrusted-certificate",
            "the wire words are what the UI switches on"
        );
    }

    #[test]
    fn matching_files_verify_and_a_changed_one_is_named() {
        let root = std::env::temp_dir().join(format!(
            "mics-selfcheck-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(root.join("data")).expect("create the fake package root");
        let app = root.join("data").join("app.so");
        std::fs::write(&app, b"the shipped bytes").expect("write a file the document lists");
        let digest = sha256_file(&app).expect("hash it the way the check does");
        let entries = vec![Entry {
            path: "data\\app.so".to_string(),
            bytes: 17,
            sha256: digest,
        }];

        assert!(
            verify_files(&root, &entries).is_empty(),
            "matching bytes must verify"
        );

        std::fs::write(&app, b"the shipped bytez").expect("change one byte");
        let changed = verify_files(&root, &entries);
        assert_eq!(changed.len(), 1, "{changed:?}");
        assert!(changed[0].contains("data\\app.so"), "{changed:?}");
        assert!(changed[0].contains("changed"), "{changed:?}");

        std::fs::remove_file(&app).expect("remove it");
        let missing = verify_files(&root, &entries);
        assert!(
            missing.iter().any(|line| line.contains("missing")),
            "{missing:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_size_change_is_named_before_any_hashing() {
        let root = std::env::temp_dir().join(format!(
            "mics-selfcheck-size-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&root).expect("create the fake package root");
        std::fs::write(root.join("rules.txt"), b"short").expect("write the file");
        let entries = vec![Entry {
            path: "rules.txt".to_string(),
            bytes: 4096,
            sha256: DIGEST.to_string(),
        }];
        let failures = verify_files(&root, &entries);
        let _ = std::fs::remove_dir_all(&root);

        // Cutting the hash is the point: a truncated or padded file is caught by
        // its size, and saying so beats "changed".
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("5 bytes, published 4096"), "{failures:?}");
    }

    #[test]
    fn a_binary_without_a_manifest_is_unverified_and_says_why() {
        let report = check(&own_exe());
        assert_eq!(report.state, Integrity::Unverified);
        assert!(!report.manifest, "a test binary is not a release package");
        let detail = report.detail.unwrap_or_default();
        assert!(
            detail.contains("no MICS_MANIFEST"),
            "the reason must name the missing document: {detail}"
        );
    }

    #[test]
    fn the_cached_state_is_what_status_reports() {
        // `status` must not re-hash the package: it reads this cache, and the two
        // cannot disagree about what the UI is told.
        assert_eq!(state().state.as_str(), "unverified");
        let request = crate::rpc::JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "status".to_string(),
            params: None,
            id: Some(serde_json::json!(7)),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime for one call");
        let response = runtime.block_on(crate::dispatcher::Dispatcher::handle_request(request));
        let result = response.result.expect("status answers");
        assert_eq!(result["integrity"], serde_json::json!("unverified"));
        assert_eq!(result["state"], serde_json::json!("running"));
    }
}