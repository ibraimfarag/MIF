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
//! 2. The image path must be the engine â€” `mics-engine.exe` by name, or exactly the
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
//! for no security gain â€” a console helper already runs with the caller's own token.

use anyhow::{bail, Context, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree, HANDLE};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

/// The only image name the helper answers without `MICS_ENGINE_PATH` being set.
const ENGINE_IMAGE: &str = "mics-engine.exe";

/// BUILTIN\Administrators â€” the owner a server-class Windows records for a directory
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
/// the installer records) adds one more trusted client â€” which is how the
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

/// True when `token` carries an enabled BUILTIN\Administrators group.
///
/// `CheckTokenMembership` is asked about the group SID directly, so an unprivileged
/// caller answers "no" without any elevation attempt. A SID that cannot be built
/// answers "no" as well: the only thing this can do is refuse a record that names
/// the group.
fn token_is_administrator(token: HANDLE) -> bool {
    let text: Vec<u16> = BUILTIN_ADMINISTRATORS
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sid = PSID::default();
    // SAFETY: `text` is NUL-terminated, `sid` is a valid out-pointer, and the SID it
    // returns is freed with `LocalFree` below, which is the allocator it uses.
    if unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &mut sid) }.is_err() {
        return false;
    }
    let mut member = BOOL::default();
    // SAFETY: both handles are valid for the duration of the call and only read.
    let checked = unsafe { CheckTokenMembership(Some(token), sid, &mut member) }.is_ok();
    // SAFETY: `sid` came from `ConvertStringSidToSidW` above.
    let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
    checked && member.as_bool()
}

fn token_sid(token: HANDLE) -> Result<String> {
    // Two calls: the first for the size, the second for the data. `TOKEN_USER`
    // begins with a `SID_AND_ATTRIBUTES`, so the buffer is read as that struct.
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 asks only for the required size; the
    // returned error is expected and only the size matters.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 {
        bail!("the token has no readable user");
    }
    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: `buffer` is `needed` bytes long and the call writes at most that much.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
    }
    .context("read the caller's token user")?;
    // SAFETY: the buffer holds a `TOKEN_USER` (guaranteed by the API contract) whose
    // first field is the user's `SID_AND_ATTRIBUTES`.
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
/// `None` when that directory does not exist (a portable run) â€” `judge` then has no
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
        // not â€” exactly the case the image check alone could not stop.
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
}