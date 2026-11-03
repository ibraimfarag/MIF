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
//!
//! [`Trust`] is the same question asked with the answer ج2 needs (D-025): a
//! package that is ours but signed with a certificate this Windows has not
//! trusted *yet* is not the same thing as a package somebody edited, and
//! [`embedded_signer_name`] is what tells the two apart.

use anyhow::{bail, Result};
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CERT_E_UNTRUSTEDROOT, HANDLE, HWND};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_INFO,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO,
    CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
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
    let (status, name) = verify(path)?;
    Ok(if status == TRUST_OK { name } else { None })
}

/// `WinVerifyTrust` and, on success, the signer's display name: the raw pair the
/// public answers are built from. The status is kept because a refusal has
/// several meanings and D-025 has to tell two of them apart.
fn verify(path: &std::path::Path) -> Result<(i32, Option<String>)> {
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

    Ok((status, name))
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

/// What ج2 needs to know about a shipped file, in D-025's terms.
///
/// `signer_name` answers "may I trust this?" with one bit, which is right for the
/// update path and wrong for the package's self-check: on a machine that has not
/// trusted the release certificate yet (the self-signed situation D-002 records),
/// the honest answer is *not* "this file is not ours" but "this file is ours and
/// this Windows does not know the certificate". The third state exists so that
/// distinction can be shown to the user instead of being flattened away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// A chain Windows trusts, ending at our own certificate.
    Ours,
    /// Our certificate is embedded and the signature verifies, but this Windows
    /// does not trust its root. Nothing is wrong with the file.
    UntrustedRoot,
    /// No signature, somebody else's, or one that does not verify (a changed
    /// byte, an expired certificate, a rewritten certificate table).
    NotOurs,
}

/// Classifies `path` against the release certificate named by
/// [`EXPECTED_SIGNER_CN`].
pub fn trust(path: &std::path::Path) -> Result<Trust> {
    let (status, name) = verify(path)?;
    if status == TRUST_OK {
        return Ok(match name {
            Some(n) if n.eq_ignore_ascii_case(EXPECTED_SIGNER_CN) => Trust::Ours,
            _ => Trust::NotOurs,
        });
    }
    // A refused chain is only "our certificate, not trusted here" when Windows
    // says exactly that *and* the certificate inside the file is ours. Anything
    // else — a changed byte is `TRUST_E_BAD_DIGEST`, not an untrusted root — is
    // a signature that no longer covers the file.
    if status as u32 == CERT_E_UNTRUSTEDROOT.0 as u32
        && embedded_signer_name(path)
            .is_some_and(|n| n.eq_ignore_ascii_case(EXPECTED_SIGNER_CN))
    {
        return Ok(Trust::UntrustedRoot);
    }
    Ok(Trust::NotOurs)
}

/// The subject display name of the certificate embedded in a file's signature,
/// read **without** building a chain.
///
/// `WinVerifyTrust` cannot answer this: when the chain does not build it returns
/// a negative status and no provider state, so "our certificate, not trusted
/// here" and "signed by somebody else" look identical. Reading the signer info
/// out of the PKCS#7 blob is one extra call and separates them (D-025).
///
/// `None` means "no readable signature at all" — an unsigned file, a truncated
/// certificate table, a file that is not a PE. A missing file is also `None`
/// here: the caller is classifying bytes it already has to read anyway, and the
/// hashes it checks are what report a missing file.
pub fn embedded_signer_name(path: &std::path::Path) -> Option<String> {
    let wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut store = HCERTSTORE::default();
    let mut msg: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: the path is NUL-terminated and outlives the call; `store` and `msg`
    // are out-parameters Windows fills in, and both are released below.
    let opened = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const core::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        )
    };
    if opened.is_err() || msg.is_null() {
        return None;
    }
    // SAFETY: both handles come from the successful query above and are still
    // open; the message is non-null.
    let name = unsafe { signer_name_from_message(store, msg) };
    // SAFETY: the two handles are released here, once, and are not used again.
    let _ = unsafe { CryptMsgClose(Some(msg)) };
    let _ = unsafe { CertCloseStore(Some(store), 0) };
    name
}

/// The signer certificate's display name out of a decoded signed message.
///
/// # Safety
/// `store` must be the certificate store and `msg` the signed message of a
/// successful `CryptQueryObject`, both still open.
unsafe fn signer_name_from_message(
    store: HCERTSTORE,
    msg: *mut core::ffi::c_void,
) -> Option<String> {
    // Ask for the size first: the signer info is variable-length (its attributes
    // are ASN.1 blobs), so it is read into a buffer of exactly that size.
    let mut size = 0u32;
    if unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut size) }.is_err()
        || size == 0
    {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: the buffer is `size` bytes, which is what the call above measured.
    let read = unsafe {
        CryptMsgGetParam(
            msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
        )
    };
    if read.is_err() {
        return None;
    }
    // SAFETY: `CMSG_SIGNER_INFO_PARAM` returns a `CMSG_SIGNER_INFO`, and the
    // buffer it was written into outlives this borrow.
    let signer = unsafe { &*(buffer.as_ptr() as *const CMSG_SIGNER_INFO) };
    // The find key is the issuer + serial pair, not the subject: that is what the
    // signer info carries, and it is also what makes the lookup work when two
    // certificates share a subject.
    let key = CERT_INFO {
        Issuer: signer.Issuer,
        SerialNumber: signer.SerialNumber,
        ..Default::default()
    };
    // SAFETY: `key` borrows its blobs from `buffer`, which outlives the call.
    let cert = unsafe {
        CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&key as *const CERT_INFO as *const core::ffi::c_void),
            None,
        )
    };
    if cert.is_null() {
        return None;
    }
    let mut name_buffer = [0u16; 512];
    // SAFETY: `cert` is a live context from the call above; the buffer is passed
    // with its length, as `CertGetNameStringW` documents.
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buffer),
        )
    };
    // SAFETY: the context was found above and is released once, after the name
    // has been copied out of it.
    let _ = unsafe { CertFreeCertificateContext(Some(cert)) };
    if written == 0 || written == 1 {
        return None;
    }
    let len = (written as usize - 1).min(name_buffer.len());
    Some(String::from_utf16_lossy(&name_buffer[..len]))
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

    #[test]
    fn an_unsigned_file_has_no_embedded_signer() {
        let path = temp_path("trust-unsigned");
        std::fs::write(&path, b"MZ this is not a signed binary").expect("write the fake exe");
        let name = embedded_signer_name(&path);
        let verdict = trust(&path).expect("classify the fake exe");
        let _ = std::fs::remove_file(&path);

        assert!(name.is_none(), "an unsigned file embeds no signer: {name:?}");
        assert_eq!(verdict, Trust::NotOurs);
    }

    #[test]
    fn the_release_binary_names_its_signer_and_is_one_of_the_two_ours() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        // The embedded certificate is ours whatever this Windows thinks of the
        // chain, which is what lets the package's self-check stay quiet on a
        // machine that has not trusted the root yet.
        assert_eq!(
            embedded_signer_name(&release).as_deref(),
            Some(EXPECTED_SIGNER_CN),
            "the certificate inside a signed release must be the release one"
        );
        let verdict = trust(&release).expect("classify the release binary");
        assert!(
            matches!(verdict, Trust::Ours | Trust::UntrustedRoot),
            "a genuine release is never \"not ours\": {verdict:?}"
        );
    }

    #[test]
    fn a_changed_byte_is_not_an_untrusted_certificate() {
        // The distinction D-025 rests on: a tampered file still carries *our*
        // certificate, so only the signature check tells it apart from a chain
        // this Windows has not trusted yet — and only the second may be quiet.
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        let copy = temp_path("trust-tampered");
        std::fs::copy(&release, &copy).expect("copy the release binary");
        let mut bytes = std::fs::read(&copy).expect("read the copy");
        let middle = bytes.len() / 2;
        if let Some(byte) = bytes.get_mut(middle) {
            *byte = byte.wrapping_add(0x41);
        }
        std::fs::write(&copy, &bytes).expect("write the tampered copy");

        let name = embedded_signer_name(&copy);
        let verdict = trust(&copy).expect("classify the tampered copy");
        let _ = std::fs::remove_file(&copy);

        assert_eq!(
            name.as_deref(),
            Some(EXPECTED_SIGNER_CN),
            "changing a byte does not touch the certificate table"
        );
        assert_eq!(
            verdict,
            Trust::NotOurs,
            "a changed byte breaks the signature, and that is never the quiet state"
        );
    }

    /// A unique path under `%TEMP%` for a copy a test writes and removes.
    fn temp_path(stem: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "mics-{stem}-{}-{}.exe",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ))
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