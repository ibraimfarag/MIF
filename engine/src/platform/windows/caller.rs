//! Who is on the other end of the privileged helper's pipe.
//!
//! The helper serves `%PROGRAMDATA%\MICS` and the firewall with a LocalSystem
//! token, and its pipe grants `INTERACTIVE` (D-007). That means every interactive
//! user can reach it, so the helper identifies the caller before it does anything
//! (`docs/THREAT-MODEL.md` F-2, D-017):
//!
//! 1. `GetNamedPipeClientProcessId` names the client process. A handle to that
//!    process is opened and kept until both answers below are read, so the pid
//!    cannot be recycled between the calls.
//! 2. The image path must be the engine Ã¢â‚¬â€ `mics-engine.exe` by name, or exactly the
//!    path in `MICS_ENGINE_PATH`, the hook the installer records.
//! 3. The caller's token must belong to the account MI CS was installed for. That
//!    account is read as the owner of `%PROGRAMDATA%\MICS`, a directory only the
//!    elevated installer creates, so a *different* local user cannot drive the
//!    helper even by copying the engine binary. The owner is not always an
//!    account: a server-class Windows (and any machine whose "default owner"
//!    security policy says so) gives a directory an administrator creates to
//!    **BUILTIN\Administrators**, so a record naming that group is satisfied by a
//!    caller whose token carries the group - measured on GitHub's Windows runner on
//!    2026-11-05, where the record was `S-1-5-32-544` and the installing account was
//!    `S-1-5-21-...-500` (D-030).
//!
//! When no data directory exists yet (portable run, a console helper in a fresh
//! checkout), step 3 has nothing to compare against: [`judge`] then lets the image
//! check stand alone, because refusing would break the documented development flows
//! for no security gain Ã¢â‚¬â€ a console helper already runs with the caller's own token.

use anyhow::{bail, Context, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree, HANDLE};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

/// The only image name the helper answers without `MICS_ENGINE_PATH` being set.
const ENGINE_IMAGE: &str = "mics-engine.exe";

/// BUILTIN\Administrators Ã¢â‚¬â€ the owner a server-class Windows records for a directory
/// an administrator creates, which is why the installer's account can be a group
/// rather than a user (see D-030).
const BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";

/// Everything the helper needs to decide about one connection.
#[derive(Debug, Clone)]
pub struct Caller {
    pub pid: u32,
    pub image: PathBuf,
    /// The token user SID, when it could be read. `None` means the query failed,
    /// which is not the same thing as "a different user".
    pub sid: Option<String>,
    /// True when the token carries an enabled BUILTIN\Administrators group. Needed
    /// only for the record that names that group instead of an account.
    pub is_administrator: bool,
}

/// Why a caller was refused, or that it was not.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    NotTheEngine,
    /// The SID that was found, for the log line.
    NotTheInstaller(String),
}

/// True when `path` names the engine, comparing only the file name.
pub fn is_engine_image(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(ENGINE_IMAGE))
}

/// True when `path` is a client this helper serves.
///
/// The engine image by name is always allowed. `allowed` (the `MICS_ENGINE_PATH`
/// the installer records) adds one more trusted client Ã¢â‚¬â€ which is how the
/// verification scripts speak the protocol themselves, and how a differently named
/// build can be named instead of loosening the check for everyone.
pub fn is_authorised(path: &Path, allowed: Option<&Path>) -> bool {
    if is_engine_image(path) {
        return true;
    }
    allowed.is_some_and(|expected| same_path(path, expected))
}

/// The engine path the installer recorded, if any. `MICS_ENGINE_PATH` is the same
/// hook the engine uses to find its own image on restart.
pub fn configured_engine_path() -> Option<PathBuf> {
    std::env::var_os("MICS_ENGINE_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// The only image name the engine hands the app's handover to.
const APP_IMAGE: &str = "mics_app.exe";

/// True when `path` names the app, comparing only the file name.
pub fn is_app_image(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(APP_IMAGE))
}

/// The app path a caller recorded, if any. `MICS_APP_PATH` mirrors what
/// `MICS_ENGINE_PATH` does for the helper: one named exception, so the
/// verification scripts can speak as the app instead of the check having to trust
/// every image it meets.
pub fn configured_app_path() -> Option<PathBuf> {
    std::env::var_os("MICS_APP_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Whether the image on the other end of the engine pipe may ask this engine to
/// hand a path to the app's window.
///
/// The pipe admits Low-integrity callers, so that a release unpacked into a folder
/// Windows labels Low can still drive its own engine (the mandatory label in
/// [`super::pipe`] says why). "A process of this user" is therefore no longer the
/// whole membership test - Low is exactly where Windows puts the sandboxes, and
/// any one of them reaches the pipe too. The handover is the one method whose
/// effect lands on the user's screen: it raises the window and puts the path it
/// was handed into the scan field. So it asks one thing more, and asks it of the
/// caller rather than of the transport: be this product. By name, or - the answer
/// that cannot simply be typed - by carrying the certificate this engine itself is
/// signed with. `allowed` is the script hook above.
pub fn may_hand_over(
    image: &Path,
    our_signer: Option<&str>,
    their_signer: Option<&str>,
    allowed: Option<&Path>,
) -> bool {
    is_app_image(image)
        || super::signature::same_signer(our_signer, their_signer)
        || allowed.is_some_and(|expected| same_path(image, expected))
}

/// [`may_hand_over`] with both certificates read from disk.
pub fn handover_allowed(image: &Path) -> bool {
    let their_signer = super::signature::embedded_signer_thumbprint(image);
    may_hand_over(
        image,
        super::signature::own_thumbprint(),
        their_signer.as_deref(),
        configured_app_path().as_deref(),
    )
}

/// Decides one connection. `installer_sid` is the account recorded at install time;
/// `None` means this machine has no record yet and the image check stands alone.
pub fn judge(caller: &Caller, allowed: Option<&Path>, installer_sid: Option<&str>) -> Verdict {
    if !is_authorised(&caller.image, allowed) {
        return Verdict::NotTheEngine;
    }
    match (installer_sid, caller.sid.as_deref()) {
        (Some(expected), Some(found)) => {
            let is_the_account = expected.eq_ignore_ascii_case(found);
            // A record that names BUILTIN\Administrators means the data directory was
            // created by an administrator on a machine that hands such objects to the
            // group (D-030). The installing account is then recognised by carrying
            // that group; refusing it would break a legitimate install and protect
            // nothing, because an administrator can take the directory over anyway.
            let is_the_group =
                expected.eq_ignore_ascii_case(BUILTIN_ADMINISTRATORS) && caller.is_administrator;
            if is_the_account || is_the_group {
                Verdict::Allowed
            } else {
                Verdict::NotTheInstaller(found.to_string())
            }
        }
        _ => Verdict::Allowed,
    }
}

/// Identifies the process on the client end of `pipe`.
pub fn identify(pipe: HANDLE) -> Result<Caller> {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out-pointer and `pipe` is the connected server end.
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }
        .context("read the caller's process id from the pipe")?;
    describe(pid)
}

/// The image path and token SID of `pid`, read through one process handle.
pub fn describe(pid: u32) -> Result<Caller> {
    if pid == 0 {
        bail!("the pipe has no client process id");
    }
    // SAFETY: nothing to keep alive; the call either returns a handle or an error.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .with_context(|| format!("open process {pid}"))?;

    let image = image_path(process);
    // The SID is best effort here: an unreadable SID is reported by `judge` as "no
    // SID", not as "a different user". The group membership is best effort too, and
    // its absence can only refuse a record that names a group.
    let (sid, is_administrator) = match token_facts(process) {
        Ok((sid, is_administrator)) => (Some(sid), is_administrator),
        Err(_) => (None, false),
    };
    // SAFETY: `process` came from `OpenProcess` above and is closed exactly once.
    let _ = unsafe { CloseHandle(process) };

    Ok(Caller {
        pid,
        image: image.with_context(|| format!("caller pid {pid}"))?,
        sid,
        is_administrator,
    })
}

fn image_path(process: HANDLE) -> Result<PathBuf> {
    let mut buffer = [0u16; 1024];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is `len` elements long and the call writes at most that
    // many UTF-16 units, updating `len` to the count written.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }
    .context("query the caller's image path")?;
    let len = (len as usize).min(buffer.len());
    if len == 0 {
        bail!("the caller's image path came back empty");
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
}

/// The token user SID of a process and whether its token carries
/// BUILTIN\Administrators.
fn token_facts(process: HANDLE) -> Result<(String, bool)> {
    with_token(process, |token| {
        let sid = token_sid(token)?;
        Ok((sid, token_is_administrator(token)))
    })
}

/// Runs `read` with a query token for `process`, closing the token exactly once.
fn with_token<T>(process: HANDLE, read: impl FnOnce(HANDLE) -> Result<T>) -> Result<T> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-handle and `process` is an open process handle.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .context("open the caller's token")?;
    let result = read(token);
    // SAFETY: `token` came from `OpenProcessToken` and is closed exactly once.
    let _ = unsafe { CloseHandle(token) };
    result
}

/// True when `token` carries BUILTIN\Administrators, whether the group is enabled or
/// deny-only.
///
/// The group list is read instead of asking `CheckTokenMembership`, because that call
/// answers "no" for a **UAC-filtered** token: GitHub's runner runs the job with a
/// filtered administrator token, and the measured answer was `administrator=false` for
/// token user `S-1-5-21-...-500` (2026-11-05). A deny-only group still means the account
/// *is* an administrator; the pipe ACL is what keeps an unelevated process out of an
/// actual privileged call, and a standard user carries neither form of the group.
fn token_is_administrator(token: HANDLE) -> bool {
    token_has_group(token, BUILTIN_ADMINISTRATORS)
}

/// True when `token`'s group list contains the SID in `group`.
fn token_has_group(token: HANDLE, group: &str) -> bool {
    let text: Vec<u16> = group.encode_utf16().chain(std::iter::once(0)).collect();
    let mut wanted = PSID::default();
    // SAFETY: `text` is NUL-terminated, `wanted` is a valid out-pointer, and the SID it
    // returns is freed with `LocalFree` below, which is the allocator it comes from.
    if unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut wanted) }.is_err() {
        return false;
    }
    let mut found = false;
    if let Ok(buffer) = token_information(token, TokenGroups) {
        // SAFETY: the API wrote a `TOKEN_GROUPS` at the start of the buffer, and its
        // `Groups` field is a flexible array of `GroupCount` entries inside that same
        // buffer, which outlives every SID read from it here.
        let groups = unsafe { &*(buffer.as_ptr() as *const TOKEN_GROUPS) };
        let count = groups.GroupCount as usize;
        let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
        found = entries.iter().any(|entry| {
            // SAFETY: both SIDs are valid for the duration of the comparison.
            unsafe { EqualSid(entry.Sid, wanted) }.is_ok()
        });
    }
    // SAFETY: `wanted` came from `ConvertStringSidToSidW` above.
    let _ = unsafe { LocalFree(Some(HLOCAL(wanted.0))) };
    found
}

/// One `GetTokenInformation` call, sized by the API itself.
fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>> {
    // Two calls: the first for the size, the second for the data.
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 asks only for the required size; the
    // returned error is expected and only the size matters.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if needed == 0 {
        bail!("the token has no readable {class:?}");
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is `needed` bytes long and the call writes at most that much.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
    }
    .with_context(|| format!("read the caller's token {class:?}"))?;
    Ok(buffer)
}

fn token_sid(token: HANDLE) -> Result<String> {
    let buffer = token_information(token, TokenUser)?;
    // SAFETY: the buffer holds a `TOKEN_USER` (guaranteed by the API contract) whose
    // first field is the user's `SID_AND_ATTRIBUTES`, and its SID points into it.
    let user: &TOKEN_USER = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    sid_to_string(user.User.Sid)
}

/// The owner of `path` as `S-1-5-...`, e.g. the account that created the data
/// directory.
pub fn owner_sid(path: &Path) -> Result<String> {
    let wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is NUL-terminated, the out-pointers are valid, and the returned
    // descriptor is owned by this call and freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    if status.is_err() {
        bail!("read the owner of {}: {status:?}", path.display());
    }
    let sid = sid_to_string(owner);
    // SAFETY: the descriptor came from `GetNamedSecurityInfoW` above.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    sid
}

/// The account MI CS was installed for: the owner of `%PROGRAMDATA%\MICS`.
///
/// `None` when that directory does not exist (a portable run) Ã¢â‚¬â€ `judge` then has no
/// record to compare against and says so in the threat model.
pub fn installer_account() -> Option<String> {
    let program_data = std::env::var_os("PROGRAMDATA")?;
    let directory = PathBuf::from(program_data).join("MICS");
    if !directory.exists() {
        return None;
    }
    owner_sid(&directory).ok()
}

fn sid_to_string(sid: PSID) -> Result<String> {
    let mut raw = PWSTR::null();
    // SAFETY: `sid` came from a token or a security descriptor and is only read.
    unsafe { ConvertSidToStringSidW(sid, &mut raw) }.context("convert the SID to text")?;
    // SAFETY: `raw` points at a NUL-terminated string owned by this call.
    let text = unsafe { raw.to_string() }.unwrap_or_default();
    // SAFETY: `raw` was allocated by `ConvertSidToStringSidW`.
    unsafe { LocalFree(Some(HLOCAL(raw.0 as *mut core::ffi::c_void))) };
    if text.is_empty() {
        bail!("the SID came back empty");
    }
    Ok(text)
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(image: &str, sid: Option<&str>) -> Caller {
        Caller {
            pid: 4242,
            image: PathBuf::from(image),
            sid: sid.map(str::to_string),
            is_administrator: false,
        }
    }

    fn admin_caller(image: &str, sid: &str) -> Caller {
        Caller {
            pid: 4242,
            image: PathBuf::from(image),
            sid: Some(sid.to_string()),
            is_administrator: true,
        }
    }

    #[test]
    fn the_engine_image_is_recognised_by_name() {
        assert!(is_engine_image(Path::new(
            r"C:\Users\x\AppData\Local\MI CS\mics-engine.exe"
        )));
        assert!(is_engine_image(Path::new(r"mics-engine.exe")));
        // Windows paths are case-insensitive, so the comparison is too.
        assert!(is_engine_image(Path::new(r"C:\MI CS\MICS-ENGINE.EXE")));
    }

    #[test]
    fn anything_that_is_not_the_engine_is_refused() {
        for path in [
            r"C:\Windows\System32\cmd.exe",
            r"C:\Tools\mics-engine.exe.bak",
            r"C:\Tools\mics-engine_old.exe",
            r"C:\Tools\mics_engine.exe",
            r"C:\Tools\mics-engine.dll",
            r"C:\Tools\",
        ] {
            assert!(!is_engine_image(Path::new(path)), "{path} must not pass");
        }
    }

    #[test]
    fn a_configured_engine_path_adds_one_trusted_client() {
        let engine = Path::new(r"C:\Users\x\AppData\Local\MI CS\mics-engine.exe");
        // The engine is allowed by name whether or not a path is configured.
        assert!(is_authorised(
            Path::new(r"c:\users\X\appdata\local\mi cs\MICS-ENGINE.EXE"),
            None
        ));
        assert!(is_authorised(engine, Some(engine)));

        // A tool that is not the engine is refused until it is named...
        let script_host = Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe");
        assert!(!is_authorised(script_host, None));
        // ...and a differently cased copy of that same path is accepted once it is.
        assert!(is_authorised(
            Path::new(r"c:\program files\powershell\7\PWSH.EXE"),
            Some(script_host)
        ));
        // Naming one client does not name another.
        assert!(!is_authorised(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            Some(script_host)
        ));
    }

    #[test]
    fn the_installer_account_is_what_decides_a_copied_engine() {
        let engine = r"C:\Users\x\AppData\Local\MI CS\mics-engine.exe";
        let installer = "S-1-5-21-1-2-3-1001";

        // The installing user: the engine image and the installer SID.
        assert_eq!(
            judge(&caller(engine, Some(installer)), None, Some(installer)),
            Verdict::Allowed
        );
        // A *different* user who copied the engine: the image passes, the SID does
        // not Ã¢â‚¬â€ exactly the case the image check alone could not stop.
        assert_eq!(
            judge(
                &caller(engine, Some("S-1-5-21-9-9-9-1002")),
                None,
                Some(installer)
            ),
            Verdict::NotTheInstaller("S-1-5-21-9-9-9-1002".into())
        );
        // SID strings are compared without case, like Windows does.
        assert_eq!(
            judge(
                &caller(engine, Some("s-1-5-21-1-2-3-1001")),
                None,
                Some(installer)
            ),
            Verdict::Allowed
        );
        // Not the engine is reported as that, whatever the SID says.
        assert_eq!(
            judge(
                &caller(r"C:\Tools\evil.exe", Some(installer)),
                None,
                Some(installer)
            ),
            Verdict::NotTheEngine
        );
        // No record yet (portable / console helper): the image check stands alone.
        assert_eq!(
            judge(&caller(engine, Some("S-1-5-21-9-9-9-1002")), None, None),
            Verdict::Allowed
        );
        // An unreadable SID is not treated as a different user.
        assert_eq!(
            judge(&caller(engine, None), None, Some(installer)),
            Verdict::Allowed
        );
    }

    #[test]
    fn a_record_that_names_administrators_is_satisfied_by_an_administrator() {
        // What GitHub's Windows runner measured on 2026-11-05: the data directory was
        // owned by BUILTIN\Administrators (S-1-5-32-544) while the installing account
        // was S-1-5-21-...-500, so an exact match refused the legitimate install
        // (D-030). Membership is what decides it instead.
        let engine = r"C:\ProgramData\MICS\mics-engine.exe";
        let installed_by_admin = "S-1-5-21-3077485881-3661871218-4154919024-500";

        assert_eq!(
            judge(
                &admin_caller(engine, installed_by_admin),
                None,
                Some(BUILTIN_ADMINISTRATORS)
            ),
            Verdict::Allowed
        );
        // The same account without the group is still refused: the rule is membership,
        // not "any caller once administrators own the directory".
        assert_eq!(
            judge(
                &caller(engine, Some(installed_by_admin)),
                None,
                Some(BUILTIN_ADMINISTRATORS)
            ),
            Verdict::NotTheInstaller(installed_by_admin.to_string())
        );
        // A standard user is not an administrator, whatever the record says.
        assert_eq!(
            judge(
                &caller(engine, Some("S-1-5-21-9-9-9-1002")),
                None,
                Some(BUILTIN_ADMINISTRATORS)
            ),
            Verdict::NotTheInstaller("S-1-5-21-9-9-9-1002".to_string())
        );
        // And a user record is never satisfied by an administrator token.
        assert_eq!(
            judge(
                &admin_caller(engine, installed_by_admin),
                None,
                Some("S-1-5-21-1-2-3-1001")
            ),
            Verdict::NotTheInstaller(installed_by_admin.to_string())
        );
    }

    #[test]
    fn a_process_id_with_no_process_is_an_error() {
        // 0 is never a valid client, and the call must say so instead of returning
        // a path that belongs to somebody else.
        assert!(describe(0).is_err());
    }

    #[test]
    fn the_owner_of_a_directory_is_the_sid_of_this_process() {
        let dir = std::env::temp_dir().join(format!("mics-sid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the temp directory");
        let owner = owner_sid(&dir);
        let me = describe(std::process::id())
            .expect("describe this process")
            .sid;
        let _ = std::fs::remove_dir_all(&dir);

        let owner = owner.expect("read the directory owner");
        let me = me.expect("read this process's token SID");
        // On a workstation an administrator's own objects are theirs; on a server-class
        // Windows the "default owner" policy hands them to BUILTIN\Administrators, which
        // is what GitHub's runner did on 2026-11-05 (D-030). Both are correct answers,
        // and the second one is why `judge` accepts a group record.
        assert!(
            owner == me || owner == BUILTIN_ADMINISTRATORS,
            "a directory this process created is owned by this process's user or by \
             BUILTIN\\Administrators; got {owner} for user {me}"
        );
        assert!(owner.starts_with("S-1-5-"), "not a SID: {owner}");
    }

    #[test]
    fn the_owner_of_a_missing_path_is_an_error() {
        let missing = std::env::temp_dir().join("mics-definitely-not-here-12345");
        assert!(owner_sid(&missing).is_err());
    }

    #[test]
    fn the_app_image_is_recognised_by_name() {
        assert!(is_app_image(Path::new(
            r"C:\Users\x\AppData\Local\MI CS\mics_app.exe"
        )));
        assert!(is_app_image(Path::new(r"mics_app.exe")));
        assert!(is_app_image(Path::new(r"C:\MI CS\MICS_APP.EXE")));
    }

    /// The handover reaches the user's screen, so "not this product" has to be the
    /// answer for everything that is not this product - including the neighbour of
    /// the real name, which is how a name check is usually defeated.
    #[test]
    fn only_this_product_may_drive_the_handover() {
        let app = Path::new(r"C:\Users\x\AppData\Local\MI CS\mics_app.exe");
        let ours = "6A1B0D9C4E77B3F2A5C8E10D3F6B92A4C7E018B5";
        let theirs = "1C4E9A2B7D0F3E8A5B1C6D2E9F4A7B3C8D0E5F19";

        // The app, by name, with or without a certificate read.
        assert!(may_hand_over(app, None, None, None));
        // A differently signed binary that is not the app: refused by every rule.
        assert!(!may_hand_over(
            Path::new(r"C:\Tools\evil.exe"),
            Some(ours),
            Some(theirs),
            None
        ));
        // Our own certificate is the answer a name cannot be: a copy under another
        // name is still ours.
        assert!(may_hand_over(
            Path::new(r"C:\Tools\renamed.exe"),
            Some(ours),
            Some(ours),
            None
        ));
        // Case, as Windows compares thumbprints.
        assert!(may_hand_over(
            Path::new(r"C:\Tools\renamed.exe"),
            Some(ours),
            Some(&ours.to_ascii_lowercase()),
            None
        ));
        // An unsigned caller is not ours by default, in either direction.
        assert!(!may_hand_over(Path::new(r"C:\Tools\raw.exe"), Some(ours), None, None));
        assert!(!may_hand_over(Path::new(r"C:\Tools\raw.exe"), None, Some(ours), None));
        assert!(!may_hand_over(Path::new(r"C:\Tools\raw.exe"), None, None, None));

        // The script hook names one client without widening anything else.
        let script_host = Path::new(r"C:\Program Files\PowerShell\7\pwsh.exe");
        assert!(may_hand_over(script_host, None, None, Some(script_host)));
        assert!(!may_hand_over(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            None,
            None,
            Some(script_host)
        ));

        // Names that must not pass a file-name comparison.
        for path in [
            r"C:\Tools\mics_app.exe.bak",
            r"C:\Tools\not_mics_app.exe",
            r"C:\Tools\mics_app.exe.dll",
            r"C:\Tools\mics-app.exe",
        ] {
            assert!(
                !may_hand_over(Path::new(path), None, None, None),
                "{path} must not pass"
            );
        }
    }

    /// The gate reads the caller's own certificate, which unit tests do not have:
    /// an unsigned binary is therefore outside the handover by every rule but the
    /// name, and `MICS_APP_PATH` is the one way in. Kept honest by asking for a path
    /// that is not actually named.
    #[test]
    fn an_unsigned_caller_is_refused_by_the_certificate_rule() {
        let ours = std::env::current_exe().expect("this test binary's path");
        assert!(
            !handover_allowed(&ours),
            "the test binary is not the app and carries no certificate"
        );
    }
}