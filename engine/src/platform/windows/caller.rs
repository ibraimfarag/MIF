//! Who is on the other end of the privileged helper's pipe.
//!
//! The helper serves `%PROGRAMDATA%\MICS` and the firewall with a LocalSystem
//! token, and its pipe grants `INTERACTIVE` (D-007). That means every interactive
//! user can reach it, so the helper has to ask who is calling before it does
//! anything: `GetNamedPipeClientProcessId` names the client process, and the image
//! path of that process is read back from a handle the helper holds — a handle keeps
//! the process object alive, so the pid cannot be recycled between the two calls
//! (`docs/THREAT-MODEL.md` F-2).
//!
//! The check is deliberately about the image *name* here: `mics-engine.exe`. A copy
//! of the engine still passes, which is why this is the first half — the second half
//! compares the caller's token SID against the account MI CS was installed for, and
//! that is what keeps a *different* user out.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The only image the helper answers.
const ENGINE_IMAGE: &str = "mics-engine.exe";

/// True when `path` names the engine, comparing only the file name.
pub fn is_engine_image(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(ENGINE_IMAGE))
}

/// True when `path` is a client this helper serves.
///
/// The engine image by name is always allowed. `allowed` (the `MICS_ENGINE_PATH`
/// the installer records) adds one more trusted client — which is how the
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

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

/// The image path of the process on the client end of `pipe`.
pub fn client_image_path(pipe: HANDLE) -> Result<PathBuf> {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out-pointer and `pipe` is the connected server end.
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }
        .context("read the caller's process id from the pipe")?;
    image_path(pid).with_context(|| format!("caller pid {pid}"))
}

/// The full image path of `pid`, read through a handle the caller keeps open while
/// the answer is built.
pub fn image_path(pid: u32) -> Result<PathBuf> {
    if pid == 0 {
        bail!("the pipe has no client process id");
    }
    // SAFETY: nothing to keep alive; the call either returns a handle or an error.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .with_context(|| format!("open process {pid}"))?;

    let mut buffer = [0u16; 1024];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is `len` elements long and the call writes at most that
    // many UTF-16 units, updating `len` to the count written.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    };
    // SAFETY: `process` came from `OpenProcess` above and is closed exactly once.
    let _ = unsafe { CloseHandle(process) };

    queried.context("query the caller's image path")?;
    let len = (len as usize).min(buffer.len());
    if len == 0 {
        bail!("the caller's image path came back empty");
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_engine_image_is_recognised_by_name() {
        assert!(is_engine_image(Path::new(r"C:\Users\x\AppData\Local\MI CS\mics-engine.exe")));
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
    fn a_process_id_with_no_process_is_an_error() {
        // 0 is never a valid client, and the call must say so instead of returning
        // a path that belongs to somebody else.
        assert!(image_path(0).is_err());
    }
}