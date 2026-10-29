//! Elevation helpers.
//!
//! The UI runs with `requireAdministrator` in its manifest (one prompt at
//! launch), so the engine it spawns inherits an elevated token. Anything that
//! shells out must still verify this, because the engine can also be started by
//! the autostart entry or from a terminal, where it is *not* elevated — and the
//! failure mode there must be a clear message, not a cryptic PowerShell error.

use std::os::windows::process::CommandExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
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
