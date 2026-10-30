//! Authenticode verification for a file the engine is about to trust.
//!
//! `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` and no UI: it builds
//! the certificate chain and checks the signature over the PE image. Then the
//! signer's name is read back from the same provider state, so "signed by anyone
//! Windows trusts" is not the answer — the caller passes the name it expects and a
//! different certificate is refused (`docs/THREAT-MODEL.md` F-3, D-016).
//!
//! The name is compared, not the thumbprint: the release certificate is created
//! locally and can be re-issued, and the certificate's subject is the part a
//! buyer/user can read in Explorer. The trade-off is written down in D-016 — a
//! thumbprint pin would also have to be updated by the release script.

use anyhow::{bail, Result};
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrustEx, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// `ERROR_SUCCESS`; anything else from `WinVerifyTrust` is a refusal.
const TRUST_OK: i32 = 0;

/// The subject common name of the certificate the release is signed with. It is a
/// release contract: `scripts/make-release.ps1 -Sign` uses this name, and an update
/// signed with anything else is refused.
pub const EXPECTED_SIGNER_CN: &str = "MI CS Code Signing";

/// The signer's display name when Windows accepts the signature, `None` when it
/// does not.
///
/// A missing file is an error, not `None`: the caller asked about a file it
/// intended to use, and silently treating "gone" as "unsigned" would hide a race.
pub fn signer_name(path: &std::path::Path) -> Result<Option<String>> {
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

    // The state handle must be read *before* it is closed, which is why the name is
    // taken here and the close action happens after.
    let name = if status == TRUST_OK {
        // SAFETY: the handle belongs to this verify call and is only released
        // below, after the provider data has been read.
        unsafe { signer_from_state(data.hWVTStateData) }
    } else {
        None
    };

    // The verify call may allocate state; closing it is required even on failure.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: same arguments as above; the close action only releases that state.
    let _ = unsafe { WinVerifyTrustEx(HWND::default(), &mut action, &mut data) };

    Ok(name)
}

/// Reads the signer certificate's display name out of a verify state handle.
///
/// # Safety
/// `state` must be the `hWVTStateData` of a successful verify call that has not been
/// closed yet.
unsafe fn signer_from_state(state: HANDLE) -> Option<String> {
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    if provider.is_null() {
        return None;
    }
    // Index 0 of the signer chain is the signer's own certificate; the rest are
    // the issuers Windows used to build the chain.
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, false, 0) };
    if signer.is_null() {
        return None;
    }
    let chain = unsafe { (*signer).pasCertChain };
    if chain.is_null() || unsafe { (*signer).csCertChain } == 0 {
        return None;
    }
    let cert = unsafe { (*chain).pCert };
    if cert.is_null() {
        return None;
    }
    let mut buffer = [0u16; 512];
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut buffer),
        )
    };
    // The count includes the terminating NUL; 1 means "empty name".
    if written == 0 || written == 1 {
        return None;
    }
    let len = (written as usize - 1).min(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

/// Refuses a file unless it carries a valid signature from `expected_cn`.
pub fn require_signed_by(path: &std::path::Path, expected_cn: &str) -> Result<()> {
    match signer_name(path)? {
        None => bail!(
            "{} has no valid Authenticode signature - refusing to use it",
            path.display()
        ),
        Some(name) if name.eq_ignore_ascii_case(expected_cn) => Ok(()),
        Some(name) => bail!(
            "{} is signed by \"{name}\", not \"{expected_cn}\" - refusing to use it",
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
        let signed = signer_name(&path);
        let _ = std::fs::remove_file(&path);

        assert!(
            matches!(signed, Ok(None)),
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
            signer_name(&release).expect("query the release binary").is_some(),
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
        let before = signer_name(&copy).expect("query the copy").is_some();
        // ...until one byte in the middle of the image changes.
        let mut bytes = std::fs::read(&copy).expect("read the copy");
        let middle = bytes.len() / 2;
        if let Some(byte) = bytes.get_mut(middle) {
            *byte = byte.wrapping_add(0x41);
        }
        std::fs::write(&copy, &bytes).expect("write the tampered copy");
        let after = signer_name(&copy).expect("query the tampered copy").is_some();
        let _ = std::fs::remove_file(&copy);

        assert!(before, "the untampered copy must verify before the edit");
        assert!(!after, "a single changed byte must break the signature");
    }

    #[test]
    fn the_identity_pin_accepts_our_certificate_and_refuses_another_name() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        // The name published with the release is what `update.rs` pins.
        let name = signer_name(&release)
            .expect("query the release binary")
            .expect("the release binary must be signed");
        assert_eq!(name, EXPECTED_SIGNER_CN, "the release certificate's CN moved");

        assert!(
            require_signed_by(&release, EXPECTED_SIGNER_CN).is_ok(),
            "our own signature must be accepted"
        );
        let other = require_signed_by(&release, "Some Other Signer");
        assert!(
            other.is_err(),
            "a certificate with a different CN must be refused"
        );
        let message = format!("{other:?}");
        assert!(
            message.contains("MI CS Code Signing"),
            "the refusal must name the actual signer: {message}"
        );
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