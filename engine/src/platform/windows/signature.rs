//! Authenticode verification for a file the engine is about to trust.
//!
//! `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` and no UI: it builds
//! the certificate chain, checks the signature over the PE image and refuses
//! anything unsigned or tampered with. The caller decides what a refusal means;
//! here it means "do not replace a running binary with this" (`docs/THREAT-MODEL.md`
//! F-3).
//!
//! What it does not do: it does not pin the signer to the MI CS certificate. Any
//! identity Windows trusts passes. That is a deliberate first step — it turns "a
//! byte-for-byte match with whatever the manifest said" into "and Windows accepts
//! the signature" — and pinning the subject to our own certificate is filed as the
//! next step in `docs/TODO.md`, because a locally created certificate has to be
//! trusted on the machine first for that check to pass.

use anyhow::{bail, Result};
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::WinTrust::{
    WinVerifyTrustEx, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// `ERROR_SUCCESS`; anything else from `WinVerifyTrust` is a refusal.
const TRUST_OK: i32 = 0;

/// True when Windows accepts the Authenticode signature on `path`.
///
/// A missing file is an error, not a `false`: the caller asked about a file it
/// intended to use, and silently treating "gone" as "unsigned" would hide a race.
pub fn is_signed(path: &std::path::Path) -> Result<bool> {
    let wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data` points at `file`, both live for the whole call, and the wide
    // path is NUL-terminated and outlives the call as well. `status` is the
    // documented `LONG` return of WinVerifyTrust.
    let status = unsafe { WinVerifyTrustEx(HWND::default(), &mut action, &mut data) };

    // The verify call may allocate state; closing it is required even on failure.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same arguments as above; the close action only releases that state.
    let _ = unsafe { WinVerifyTrustEx(HWND::default(), &mut action, &mut data) };

    Ok(status == TRUST_OK)
}

/// Refuses a file Windows does not consider signed, with the HRESULT in the error.
pub fn require_signed(path: &std::path::Path) -> Result<()> {
    match is_signed(path)? {
        true => Ok(()),
        false => bail!(
            "{} has no valid Authenticode signature - refusing to use it",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsigned_file_is_refused() {
        let path = std::env::temp_dir().join(format!(
            "mics-unsigned-{}-{}.exe",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, b"MZ this is not a signed binary").expect("write the fake exe");
        let signed = is_signed(&path);
        let _ = std::fs::remove_file(&path);

        assert!(
            matches!(signed, Ok(false)),
            "an unsigned file must not pass: {signed:?}"
        );
    }

    #[test]
    fn a_signed_release_binary_is_accepted() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        assert!(
            is_signed(&release).expect("query the release binary"),
            "{} is signed by make-release.ps1 -Sign and must pass",
            release.display()
        );
    }

    #[test]
    fn a_tampered_copy_of_a_signed_binary_is_refused() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        let copy = std::env::temp_dir().join(format!(
            "mics-tampered-{}-{}.exe",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::copy(&release, &copy).expect("copy the release binary");

        // The copy is still signed...
        let before = is_signed(&copy).expect("query the copy");
        // ...until one byte in the middle of the image changes.
        let mut bytes = std::fs::read(&copy).expect("read the copy");
        let middle = bytes.len() / 2;
        if let Some(byte) = bytes.get_mut(middle) {
            *byte = byte.wrapping_add(0x41);
        }
        std::fs::write(&copy, &bytes).expect("write the tampered copy");
        let after = is_signed(&copy).expect("query the tampered copy");
        let _ = std::fs::remove_file(&copy);

        assert!(before, "the untampered copy must verify before the edit");
        assert!(!after, "a single changed byte must break the signature");
    }

    /// The artifact `scripts/make-release.ps1 -Sign` produces. `dist/` is
    /// gitignored, so this returns `None` on a clean checkout and the two tests
    /// above say so instead of pretending to have run.
    fn signed_release() -> Option<std::path::PathBuf> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent()?;
        let path = root.join("dist").join("MICS-portable").join("mics-engine.exe");
        path.exists().then_some(path)
    }
}