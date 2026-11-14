//! Authenticode verification for a file the engine is about to trust.
//!
//! `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` and no UI: it builds
//! the certificate chain and checks the signature over the PE image. Then the
//! signer's name is read back from the same provider state, so "signed by anyone
//! Windows trusts" is not the answer — the caller passes the name it expects and a
//! different certificate is refused (`docs/THREAT-MODEL.md` F-3, D-016).
//!
//! For a *binary*, the release certificate is created locally and can be
//! re-issued, and the certificate's subject is the part a buyer/user can read in
//! Explorer, so D-016's first answer was to compare the subject name. That answer
//! expired the moment a real certificate was priced: no CA may issue
//! `CN=MI CS Code Signing` at all (CA/B CSCBR §9.2.2 requires the verified legal
//! name), so the name pin would refuse our own release. D-051 settles it the way
//! `docs/OPEN-DECISIONS.md` item 3 recommended and decision (c) made binding —
//! [`Pin`]: the **thumbprint this copy knows** (the environment hook a probe sets,
//! or the certificate over the running engine) when there is one, and the release
//! CN only when there is none, which is a build that carries no signature at all.
//!
//! One pin, used by every step that decides whether a file is ours: the update
//! *feed*'s detached signature (D-047), the *payload*'s binaries before they may
//! replace the running ones, and the package self-check's [`Trust`] answer.
//!
//! [`Trust`] is the same question asked with the answer ج2 needs (D-025): a
//! package that is ours but signed with a certificate this Windows has not
//! trusted *yet* is not the same thing as a package somebody edited, and
//! [`embedded_signer_name`] is what tells the two apart.
//!
//! The update feed needs the same question answered about a *document* rather than
//! a PE ([`verify_detached`], D-047): `update.json` ships with a detached PKCS#7
//! beside it, and the certificate that must have made that signature is the one
//! over this executable ([`pinned_update_thumbprint`]). Verifying a document cannot
//! go through `WinVerifyTrust` — there is no PE, no page hashes and no chain to
//! build — so it is `CryptVerifyDetachedMessageSignature` plus the thumbprint,
//! which is also what makes the pin survive a machine that has never trusted the
//! release certificate (D-002).

use anyhow::{anyhow, bail, Context, Result};
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CERT_E_UNTRUSTEDROOT, HANDLE, HWND};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
    CryptQueryObject, CryptVerifyDetachedMessageSignature, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
    CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_SHA1_HASH_PROP_ID,
    CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CRYPT_VERIFY_MESSAGE_PARA, HCERTSTORE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrustEx, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// `ERROR_SUCCESS`; anything else from `WinVerifyTrust` is a refusal.
const TRUST_OK: i32 = 0;

/// The subject common name of the certificate a **development** release is signed
/// with, and the fallback half of [`Pin`]: `scripts/make-release.ps1 -Sign` uses
/// this name when it signs with the locally created certificate
/// (`scripts/codesign-cert.ps1`), and a copy that carries no signature of its own
/// accepts this name and nothing else (D-016).
///
/// It is no longer the whole contract, and it cannot be: a publicly trusted CA is
/// required to put the certificate holder's *verified legal name* in
/// `subject:commonName` (CA/B CSCBR §9.2.2), so no such certificate will ever read
/// `MI CS Code Signing` — a released copy pins the thumbprint instead (D-051).
pub const EXPECTED_SIGNER_CN: &str = "MI CS Code Signing";

/// The test hook that pins an update manifest to a thumbprint (D-047).
///
/// The probe and the tests sign a manifest with a certificate this machine minted
/// seconds ago, so they cannot re-sign the engine they are testing; this is the
/// environment-only way to say which certificate they signed with (AGENTS.md
/// rule 5). It is read by [`pinned_update_thumbprint`] and never by a shipped
/// configuration: a release engine pins its own signature.
pub const ENV_UPDATE_SIGNER_THUMBPRINT: &str = "MICS_UPDATE_SIGNER_THUMBPRINT";

/// A signature that verified, and who made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// The signer's display name, when the certificate carries one.
    pub name: Option<String>,
    /// The SHA-1 thumbprint of the signer's certificate, lowercase hex.
    pub thumbprint: String,
}

/// Verifies a detached PKCS#7 signature over `content` and says who signed it.
///
/// The certificate travels inside the signature, so this proves *a* key signed
/// these exact bytes — not that the key is ours. Pinning is the caller's job:
/// `update::check` is the caller, and [`pinned_update_thumbprint`] is the pin it
/// uses. A document that was edited after signing fails here with the provider's
/// own error, which is why the refusal can name the digest rather than a hash
/// mismatch in the manifest's own fields (D-047).
pub fn verify_detached(content: &[u8], signature: &[u8]) -> Result<VerifiedSigner> {
    let size = u32::try_from(content.len()).context("the signed content is larger than 4 GiB")?;
    let para = CRYPT_VERIFY_MESSAGE_PARA {
        cbSize: std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32,
        dwMsgAndCertEncodingType: X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0,
        ..Default::default()
    };
    // One blob, so the detached content cannot be split or reordered by a caller
    // that thinks it is passing more than it is.
    let contents = [content.as_ptr()];
    let lengths = [size];
    let mut signer: *mut CERT_CONTEXT = std::ptr::null_mut();
    // SAFETY: `para` is fully initialized, the blob pointer array and its lengths
    // describe `content`, `signature` is a live slice for the call, and `signer` is
    // an out-parameter Windows fills with a context this function releases below.
    let verified = unsafe {
        CryptVerifyDetachedMessageSignature(
            &para,
            0,
            signature,
            1,
            contents.as_ptr(),
            lengths.as_ptr(),
            Some(&mut signer),
        )
    };
    if let Err(e) = verified {
        bail!("the detached signature does not verify ({e})");
    }
    if signer.is_null() {
        bail!("the signature verified but named no signer certificate");
    }
    // SAFETY: `signer` is the context the call above returned: non-null, live until
    // the free below, and owned by this call.
    let identity = unsafe { signer_identity_from_context(signer) };
    // SAFETY: the context is released here, once, after the identity was copied out.
    let _ = unsafe { CertFreeCertificateContext(Some(signer)) };
    identity.ok_or_else(|| anyhow!("the signer certificate carries no readable thumbprint"))
}

/// The certificate's display name and SHA-1 thumbprint.
///
/// # Safety
/// `cert` must be a live certificate context for the duration of the call.
unsafe fn signer_identity_from_context(cert: *const CERT_CONTEXT) -> Option<VerifiedSigner> {
    Some(VerifiedSigner {
        name: unsafe { display_name(cert) },
        thumbprint: unsafe { thumbprint_of(cert) }?,
    })
}

/// The certificate's subject display name, `None` when it has none readable.
///
/// # Safety
/// `cert` must be a live certificate context for the duration of the call.
unsafe fn display_name(cert: *const CERT_CONTEXT) -> Option<String> {
    let mut buffer = [0u16; 512];
    // SAFETY: `cert` is live and the buffer is passed with its length, as
    // `CertGetNameStringW` documents.
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

/// The certificate's SHA-1 thumbprint, lowercase hex.
///
/// # Safety
/// `cert` must be a live certificate context for the duration of the call.
unsafe fn thumbprint_of(cert: *const CERT_CONTEXT) -> Option<String> {
    // Ask for the size first: the property is a 20-byte digest here, but reading
    // it the documented two-step way is what makes the buffer exactly right.
    let mut size = 0u32;
    // SAFETY: `cert` is live; a null buffer asks the property's size, as documented.
    unsafe { CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, None, &mut size) }
        .ok()?;
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    let mut written = size;
    // SAFETY: the buffer is `size` bytes, which is what the call above measured.
    unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA1_HASH_PROP_ID,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            &mut written,
        )
    }
    .ok()?;
    buffer.truncate(written as usize);
    Some(hex::encode(buffer))
}

/// The certificate an update path will accept, in the order decision (c) settled
/// (D-016, D-051).
///
/// `Thumbprint` is the one identity a certificate cannot be talked into: it is the
/// hash of the certificate's own bytes, so a CA that failed identity validation
/// cannot produce it. `Name` is what is left for a build that carries no signature
/// of its own — a `cargo build`, where the release CN is the only contract there is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// The SHA-1 thumbprint of the one certificate this copy signs and accepts,
    /// lowercase hex.
    Thumbprint(String),
    /// The subject common name of a development release, [`EXPECTED_SIGNER_CN`].
    Name(&'static str),
}

impl Pin {
    /// Whether this signer is the one the pin names.
    ///
    /// Both identities are compared case-insensitively, and either may be missing:
    /// a file whose signature Windows refuses has no name and no thumbprint to
    /// offer, and that is a refusal rather than a match.
    pub fn accepts(&self, name: Option<&str>, thumbprint: Option<&str>) -> bool {
        match self {
            Pin::Thumbprint(pinned) => thumbprint.is_some_and(|got| got.eq_ignore_ascii_case(pinned)),
            Pin::Name(cn) => name.is_some_and(|got| got.eq_ignore_ascii_case(cn)),
        }
    }

    /// The pin as a refusal has to name it: what was expected, in the terms the
    /// reader can check (`docs/THREAT-MODEL.md` F-3).
    pub fn describe(&self) -> String {
        match self {
            Pin::Thumbprint(pinned) => format!("the certificate with thumbprint {pinned}"),
            Pin::Name(cn) => format!("\"{cn}\""),
        }
    }
}

/// The pin every update decision uses: the thumbprint this copy knows, the release
/// CN only when it knows none (D-051).
///
/// This is deliberately the *same* value the feed has been pinned to since D-047 —
/// one function, so the manifest's signature, the payload's binaries and the
/// package self-check cannot drift into accepting different certificates.
pub fn update_pin() -> Result<Pin> {
    Ok(match pinned_update_thumbprint()? {
        Some(thumbprint) => Pin::Thumbprint(thumbprint),
        None => Pin::Name(EXPECTED_SIGNER_CN),
    })
}

/// The thumbprint the update path's signers must carry, or `None` when this engine
/// has nothing of its own to pin (D-047).
///
/// Order: [`ENV_UPDATE_SIGNER_THUMBPRINT`] when the environment sets one, then the
/// certificate that signed *this executable* — read out of its own Authenticode
/// blob by [`embedded_signer_thumbprint`], which builds no chain, so the
/// self-signed situation D-002 records still pins.
///
/// `None` means this engine carries no signature at all: a development build. The
/// caller keeps the signature check and the name check, and reports which of the
/// two pins it used rather than pretending they are the same — see [`update_pin`].
pub fn pinned_update_thumbprint() -> Result<Option<String>> {
    if let Some(value) = std::env::var_os(ENV_UPDATE_SIGNER_THUMBPRINT) {
        return normalise_thumbprint(&value.to_string_lossy()).map(Some);
    }
    let exe = std::env::current_exe().context("resolve this executable's own path")?;
    Ok(embedded_signer_thumbprint(&exe))
}

/// A SHA-1 thumbprint in the one spelling this module compares: lowercase hex,
/// no separators. Anything else is refused rather than guessed at — a pin that
/// silently matched nothing would refuse every honest release.
pub fn normalise_thumbprint(value: &str) -> Result<String> {
    let hex = value.trim().replace([' ', ':', '-'], "").to_lowercase();
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "{} is not a SHA-1 thumbprint (40 hex digits): {value:?}",
            ENV_UPDATE_SIGNER_THUMBPRINT
        );
    }
    Ok(hex)
}

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
    // SAFETY: `cert` is the signer's own certificate inside the provider state,
    // which is live until the caller closes it.
    unsafe { display_name(cert) }
}

/// Refuses a file unless it carries a valid signature from the certificate `pin`
/// names (D-051).
///
/// Windows still has to accept the signature — an expired, revoked or edited file
/// never gets this far — and then the identity is the pin's to decide: the
/// thumbprint of the certificate inside the file, or the release CN when this copy
/// has no certificate of its own. Both halves are needed: the chain check is what
/// rejects a changed byte, and the pin is what rejects a *valid* signature from
/// somebody else.
pub fn require_signed_by_pin(path: &std::path::Path, pin: &Pin) -> Result<()> {
    let Some(name) = signer_name(path)? else {
        bail!(
            "{} has no valid Authenticode signature - refusing to use it",
            path.display()
        );
    };
    // The thumbprint is read from the file's own certificate table rather than from
    // the verify state, so a pinned copy is decided by the bytes it was signed with
    // and not by the chain Windows happened to build.
    let thumbprint = embedded_signer_thumbprint(path);
    if pin.accepts(Some(&name), thumbprint.as_deref()) {
        return Ok(());
    }
    let ours = embedded_signer_name(path).unwrap_or(name.clone());
    bail!(
        "{} is signed by {ours:?}{}, and this {} pins {} - refusing to use it",
        path.display(),
        thumbprint
            .as_deref()
            .map(|t| format!(" (thumbprint {t})"))
            .unwrap_or_default(),
        match pin {
            Pin::Thumbprint(_) => "engine",
            Pin::Name(_) => "build",
        },
        pin.describe()
    )
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
    /// A chain Windows trusts, ending at the certificate this copy pins (D-051).
    Ours,
    /// That certificate is embedded and the signature verifies, but this Windows
    /// does not trust its root. Nothing is wrong with the file.
    UntrustedRoot,
    /// No signature, a signature that does not verify (a changed byte, an expired
    /// certificate, a rewritten certificate table), or one this copy does not pin.
    NotOurs,
}

/// Classifies `path` against the certificate this copy pins (D-025, D-051).
///
/// `Ours` is now "signed, and the chain Windows built ends somewhere it trusts, and
/// the signer is the pinned certificate" — the pin being [`update_pin`], so a
/// release signed by a real CA recognises itself by thumbprint where the old
/// release *name* could never match again (D-051). What this deliberately gives up
/// is written down in `docs/THREAT-MODEL.md` F-3: a copy re-signed by a third party
/// pins *its own* certificate and therefore reads as `Ours` here. An engine cannot
/// authenticate itself — the file under question is where the pin comes from — so
/// the teeth against a hand-delivered package stays what it always really was, the
/// hashes of the files beside it (still checked) and the publisher name Windows
/// shows; on the *update* path the same pin is a real comparison, because the
/// payload is a different file from the engine holding the pin.
pub fn trust(path: &std::path::Path) -> Result<Trust> {
    let (status, name) = verify(path)?;
    let pin = update_pin()?;
    // A refused chain is only "our certificate, not trusted here" when Windows says
    // exactly that *and* the certificate inside the file is one this copy pins.
    // Anything else — a changed byte is `TRUST_E_BAD_DIGEST`, not an untrusted root —
    // is a signature that no longer covers the file.
    let pinned = match status {
        TRUST_OK => Trust::Ours,
        s if s as u32 == CERT_E_UNTRUSTEDROOT.0 as u32 => Trust::UntrustedRoot,
        _ => return Ok(Trust::NotOurs),
    };
    let embedded = embedded_signer_identity(path);
    let (name, thumbprint) = match embedded {
        Some(signer) => (signer.name, Some(signer.thumbprint)),
        // No readable certificate table at all: an unsigned file, or a signature
        // this Windows accepted without a signer we can name.
        None => (name, None),
    };
    Ok(if pin.accepts(name.as_deref(), thumbprint.as_deref()) {
        pinned
    } else {
        Trust::NotOurs
    })
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
    embedded_identity(path).and_then(|signer| signer.name)
}

/// Both halves of the certificate embedded in a file's signature — the name
/// [`embedded_signer_name`] reads, and the thumbprint
/// [`embedded_signer_thumbprint`] reads — out of the same PKCS#7 walk, for callers
/// that decide with a [`Pin`] and need whichever half it names (D-051).
pub fn embedded_signer_identity(path: &std::path::Path) -> Option<VerifiedSigner> {
    embedded_identity(path)
}

/// The SHA-1 thumbprint of the certificate embedded in a file's signature, read
/// **without** building a chain — the pin the update feed is checked against
/// (D-047).
///
/// Same `None` contract as [`embedded_signer_name`], and for the same reason: an
/// unsigned engine is a development build, not a failure.
pub fn embedded_signer_thumbprint(path: &std::path::Path) -> Option<String> {
    embedded_identity(path).map(|signer| signer.thumbprint)
}

/// True when two thumbprints name the same certificate.
///
/// Kept apart from the two certificate reads so the rule is testable without a
/// signed binary: an absent signer is never a match - an unsigned file is not ours
/// by default.
pub fn same_signer(ours: Option<&str>, theirs: Option<&str>) -> bool {
    matches!((ours, theirs), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
}

/// The thumbprint this process's own image is signed with, read once.
///
/// Two callers ask "is this ours": the scan loop, per candidate file, and the
/// engine's caller gate, per connection. The answer cannot change while the
/// process lives, so it is read on the first ask and kept. `None` on an unsigned
/// build - which is what makes both checks false under `cargo test`, and true for
/// every copy of a signed release. Nothing is cached across processes, so a
/// re-signed engine never compares against a stale certificate.
pub fn own_thumbprint() -> Option<&'static str> {
    static OWN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    OWN.get_or_init(|| {
        let own = std::env::current_exe().ok()?;
        embedded_signer_thumbprint(&own)
    })
    .as_deref()
}

/// The signer's name and thumbprint out of the certificate embedded in a file's
/// Authenticode signature, read without building a chain.
fn embedded_identity(path: &std::path::Path) -> Option<VerifiedSigner> {
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
    let identity = unsafe { signer_identity_from_message(store, msg) };
    // SAFETY: the two handles are released here, once, and are not used again.
    let _ = unsafe { CryptMsgClose(Some(msg)) };
    let _ = unsafe { CertCloseStore(Some(store), 0) };
    identity
}

/// The signer certificate's display name and thumbprint out of a decoded signed
/// message.
///
/// # Safety
/// `store` must be the certificate store and `msg` the signed message of a
/// successful `CryptQueryObject`, both still open.
unsafe fn signer_identity_from_message(
    store: HCERTSTORE,
    msg: *mut core::ffi::c_void,
) -> Option<VerifiedSigner> {
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
    // SAFETY: `cert` is a live context found above; the identity is copied out of
    // it before the context is released, once.
    let identity = unsafe { signer_identity_from_context(cert) };
    let _ = unsafe { CertFreeCertificateContext(Some(cert)) };
    identity
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
    fn the_name_pin_accepts_our_certificate_and_refuses_another() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        // The name half of the pin is what an engine with nothing of its own has to
        // work with: the certificate over the release has to carry the release name,
        // and any other name is refused with the actual signer named.
        let ours = Pin::Name(EXPECTED_SIGNER_CN);
        assert!(
            require_signed_by_pin(&release, &ours).is_ok(),
            "our own signature must be accepted by the release name"
        );
        let other = require_signed_by_pin(&release, &Pin::Name("Some Other Signer"));
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
    fn a_pin_is_decided_by_the_half_it_names() {
        // The two pins are not interchangeable: the thumbprint half must not be
        // satisfied by a name, and the name half must not be satisfied by a
        // thumbprint (D-051).
        let thumbprint = Pin::Thumbprint("a".repeat(40));
        assert!(
            thumbprint.accepts(Some(EXPECTED_SIGNER_CN), Some(&"a".repeat(40))),
            "the pinned certificate is accepted"
        );
        assert!(
            !thumbprint.accepts(Some(EXPECTED_SIGNER_CN), Some(&"b".repeat(40))),
            "another certificate with the right name is not the pin"
        );
        assert!(
            !thumbprint.accepts(Some(EXPECTED_SIGNER_CN), None),
            "a pin nothing can offer is a refusal, not a match"
        );

        let name = Pin::Name(EXPECTED_SIGNER_CN);
        assert!(name.accepts(Some(EXPECTED_SIGNER_CN), None));
        assert!(!name.accepts(Some("Some Other Signer"), Some(&"a".repeat(40))));
        assert!(!name.accepts(None, Some(EXPECTED_SIGNER_CN)));
    }

    #[test]
    fn the_thumbprint_pin_accepts_our_binary_and_refuses_a_name_alike() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        // The pin the update path builds out of a real release is the thumbprint of
        // the certificate over the engine itself, which is what makes the payload
        // check survive a certificate whose CN a CA chose (D-051).
        let thumbprint = embedded_signer_thumbprint(&release)
            .expect("a signed release carries the certificate it is pinned to");
        let pin = Pin::Thumbprint(thumbprint.clone());
        assert!(
            require_signed_by_pin(&release, &pin).is_ok(),
            "the pinned certificate must be accepted"
        );

        // Same file, same *name*, one different thumbprint: refused, and the
        // refusal says which thumbprint it wanted.
        let other = Pin::Thumbprint("f".repeat(40));
        let refused = require_signed_by_pin(&release, &other)
            .expect_err("the pinned thumbprint is the whole check");
        let message = format!("{refused:#}");
        assert!(message.contains(&thumbprint), "names the signer: {message}");
        assert!(message.contains(&"f".repeat(40)), "names the pin: {message}");
    }

    #[test]
    fn an_unsigned_payload_is_refused_by_either_pin() {
        // The payload check's first question is unchanged: no signature, no
        // install. Both halves of the pin have to answer it the same way.
        let path = temp_path("pin-unsigned");
        std::fs::write(&path, b"MZ this is not a signed binary").expect("write the fake exe");
        let by_name = require_signed_by_pin(&path, &Pin::Name(EXPECTED_SIGNER_CN));
        let by_thumbprint = require_signed_by_pin(&path, &Pin::Thumbprint("a".repeat(40)));
        let _ = std::fs::remove_file(&path);

        for (which, refused) in [("name", by_name), ("thumbprint", by_thumbprint)] {
            let message = format!("{refused:?}");
            assert!(
                message.contains("no valid Authenticode signature"),
                "the {which} pin must refuse an unsigned file by its signature: {message}"
            );
        }
    }

    #[test]
    fn a_build_with_no_signature_of_its_own_falls_back_to_the_release_name() {
        // `cargo test` runs an unsigned test binary under the environment hook's
        // default, so this is exactly the development case: the pin is the CN, not
        // a thumbprint, and it is the *fallback* rather than the contract
        // (decision (c), D-016).
        if std::env::var_os(ENV_UPDATE_SIGNER_THUMBPRINT).is_some() {
            eprintln!("the environment pins a thumbprint - the fallback is not what runs");
            return;
        }
        assert_eq!(
            update_pin().expect("build the pin"),
            Pin::Name(EXPECTED_SIGNER_CN)
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
        assert!(
            embedded_signer_thumbprint(&path).is_none(),
            "an unsigned file pins no thumbprint either"
        );
        assert_eq!(verdict, Trust::NotOurs);
    }

    #[test]
    fn a_detached_signature_that_is_not_one_is_refused() {
        // The feed half of F-3: whatever arrives beside `update.json` has to be a
        // signature over those exact bytes. Bytes that are not a PKCS#7 message, an
        // empty sidecar, and a valid-looking header with nothing behind it all have
        // to come back refused rather than `Ok` (D-047).
        for (what, signature) in [
            ("plain text", b"this is not a signature".as_slice()),
            ("empty", b"".as_slice()),
            ("a PKCS#7 header and no message", [0x30u8, 0x82, 0x00, 0x0a].as_slice()),
        ] {
            let refused = verify_detached(b"{\"version\":\"9.9.9\"}", signature);
            assert!(
                refused.is_err(),
                "{what} must not verify as a signature: {refused:?}"
            );
        }
    }

    /// The manifest a committed fixture signature was made over, the detached
    /// PKCS#7 itself, and the thumbprint of the throwaway certificate inside it.
    /// See `engine/tests/data/README.md` - regenerating them is a deliberate act,
    /// because the pinned thumbprint is part of the test.
    const FIXTURE_MANIFEST: &[u8] = include_bytes!("../../../tests/data/update-manifest.json");
    const FIXTURE_SIGNATURE: &[u8] = include_bytes!("../../../tests/data/update-manifest.pkcs7");
    const FIXTURE_THUMBPRINT: &str = "f34c6d80ebaa3bf5110d343adeb37718f539da35";

    #[test]
    fn a_real_detached_signature_verifies_over_exactly_those_bytes() {
        // The happy path, without a store, a CA or a network: the fixture is a
        // detached PKCS#7 over `update-manifest.json`, made once with a throwaway
        // key whose private half was not kept (a signature stays verifiable, and
        // nothing here reads a certificate's dates). It is the same shape
        // `scripts/sign.ps1 -DataFile` writes, which is the point: the release lane
        // and this verifier have to agree about what a signed manifest is.
        let signer = verify_detached(FIXTURE_MANIFEST, FIXTURE_SIGNATURE)
            .expect("the committed fixture signature verifies");
        assert_eq!(signer.name.as_deref(), Some("MI CS Update Fixture"));
        assert_eq!(
            signer.thumbprint, FIXTURE_THUMBPRINT,
            "the signer's own thumbprint is what the pin decides on"
        );

        // One flipped byte is one refused manifest: the signature is over these
        // exact bytes, not over a re-encoded copy of the parsed document.
        let mut changed = FIXTURE_MANIFEST.to_vec();
        changed[0] ^= 0x01;
        let refused = verify_detached(&changed, FIXTURE_SIGNATURE);
        assert!(
            refused.is_err(),
            "a manifest changed after signing must not verify: {refused:?}"
        );
    }

    #[test]
    fn a_thumbprint_pin_is_normalised_or_refused() {
        assert_eq!(
            normalise_thumbprint("  ab:CD:ef 01 23 45 67 89 ab cd ef 01 23 45 67 89-ab-cd-ef-01  ").unwrap(),
            "abcdef0123456789abcdef0123456789abcdef01"
        );
        assert_eq!(
            normalise_thumbprint("ABCDEF0123456789ABCDEF0123456789ABCDEF01").unwrap(),
            "abcdef0123456789abcdef0123456789abcdef01"
        );
        for bad in ["", "off", "abcdef", &"a".repeat(39), &"a".repeat(41), &"z".repeat(40)] {
            assert!(
                normalise_thumbprint(bad).is_err(),
                "{bad:?} is not a SHA-1 thumbprint and must be refused"
            );
        }
    }

    #[test]
    fn the_release_binary_names_its_signer_and_is_one_of_the_two_ours() {
        let Some(release) = signed_release() else {
            eprintln!("no signed release artifact to test against - skipped");
            return;
        };
        // The embedded certificate is the one this copy pins whatever this Windows
        // thinks of the chain, which is what lets the package's self-check stay
        // quiet on a machine that has not trusted the root yet, and what a release
        // signed by a real CA still recognises as itself (D-051).
        let signer = embedded_signer_identity(&release)
            .expect("a signed release embeds the certificate it was signed with");
        assert!(
            update_pin()
                .expect("build the pin")
                .accepts(signer.name.as_deref(), Some(&signer.thumbprint)),
            "the certificate inside a signed release must be the release one: {signer:?}"
        );
        let verdict = trust(&release).expect("classify the release binary");
        assert!(
            matches!(verdict, Trust::Ours | Trust::UntrustedRoot),
            "a genuine release is never \"not ours\": {verdict:?}"
        );
        // The pin D-047 compares against comes out of this same blob: a signed
        // release always carries one, and it is the thumbprint Windows shows.
        let thumbprint = embedded_signer_thumbprint(&release)
            .expect("a signed release embeds the certificate the feed is pinned to");
        assert_eq!(thumbprint.len(), 40, "a SHA-1 thumbprint: {thumbprint}");
        assert!(
            thumbprint
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "the pin is compared in lowercase hex: {thumbprint}"
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