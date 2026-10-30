//! Elevation helpers.
//!
//! The UI runs with `requireAdministrator` in its manifest (one prompt at
//! launch), so the engine it spawns inherits an elevated token. Anything that
//! shells out must still verify this, because the engine can also be started by
//! the autostart entry or from a terminal, where it is *not* elevated — and the
//! failure mode there must be a clear message, not a cryptic PowerShell error.

use anyhow::{Context, Result};
use std::os::windows::process::CommandExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `CREATE_NO_WINDOW`: a console app started from a GUI process must not flash
/// a console window at the user (this is what made PowerShell appear during an
/// audit fix).
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// True when the current process token is elevated.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Applies the hidden-console flag to a child process.
pub fn hide_console(command: &mut std::process::Command) -> &mut std::process::Command {
    command.creation_flags(CREATE_NO_WINDOW)
}

/// Runs `exe args` with the `runas` verb and waits for it, up to `timeout`.
///
/// This is the **one** UAC prompt in D-007: the consent dialog names our own
/// executable (not `Windows PowerShell` as `Start-Process -Verb RunAs` does),
/// and a refused or cancelled prompt comes back as an error the caller can show
/// instead of a hang.
pub fn run_elevated(exe: &std::path::Path, args: &[&str], timeout: std::time::Duration) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() };
    let verb = wide("runas");
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parameters = wide(&args.join(" "));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut info) }
        .context("elevation was refused or cancelled by the user")?;
    let process = info.hProcess;
    if process.is_invalid() {
        anyhow::bail!("elevation did not return a process handle");
    }
    let waited = unsafe { WaitForSingleObject(process, timeout.as_millis() as u32) };
    if waited == WAIT_TIMEOUT {
        unsafe {
            let _ = CloseHandle(process);
        }
        anyhow::bail!(
            "the elevated step did not finish within {}s",
            timeout.as_secs()
        );
    }
    let mut code = 1u32;
    let read = unsafe { GetExitCodeProcess(process, &mut code) };
    unsafe {
        let _ = CloseHandle(process);
    }
    if waited != WAIT_OBJECT_0 || read.is_err() {
        anyhow::bail!("the elevated step could not be waited for");
    }
    if code != 0 {
        anyhow::bail!("the elevated step failed (exit code {code})");
    }
    Ok(())
}
