//! The mandatory integrity label of *this* process, and why the engine cares.
//!
//! Windows starts a process with the integrity level of the **image file**, and
//! the default mandatory policy is "no write up": a Low process cannot modify a
//! Medium object. MI CS keeps its state at Medium (`%LOCALAPPDATA%`, or
//! `%PROGRAMDATA%`), so an engine started from a folder that carries a Low label
//! runs, answers, and then fails every write in two misleading ways
//! (`docs/TODO.md` traps 12 and 21):
//!
//! * SQLite reports `attempt to write a readonly database` (SQLITE_READONLY),
//!   which reads like a damaged database file and is a permission refusal;
//! * the helper's pipe is owned by LocalSystem, so the Low client's write is
//!   refused and `helper.status` says `reachable: false` for a service that is
//!   running perfectly — the UI shows that as "installed but not answering".
//!
//! The workspace root can acquire that label from host tooling (the sandbox
//! labels it Low and everything created under it inherits), so this is not
//! hypothetical: both messages were reported *together* by a user running a
//! build out of `dist\`. The engine therefore refuses to start below Medium and
//! names the folder it was started from; `MICS_ALLOW_LOW_INTEGRITY=1` is the
//! documented escape hatch for the diagnostic probes that deliberately run from
//! wherever a build landed.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// RIDs of the mandatory labels Windows assigns by default.
pub const LOW: u32 = 0x1000;
pub const MEDIUM: u32 = 0x2000;
pub const HIGH: u32 = 0x3000;
pub const SYSTEM: u32 = 0x4000;

/// The integrity level of the current process: the RID of its label's SID
/// (`0x1000` Low, `0x2000` Medium, ...). `None` when the token cannot be read,
/// which is never the same thing as "Low".
pub fn current() -> Option<u32> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is not closed.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let level = read_level(token);
        // SAFETY: `token` came from `OpenProcessToken` above and is closed once.
        let _ = CloseHandle(token);
        level
    }
}

/// True when this process is below Medium, i.e. cannot write MI CS state.
pub fn below_medium() -> bool {
    current().is_some_and(|level| level < MEDIUM)
}

/// Human name for a level, for the sentences a user reads.
pub fn name(level: u32) -> &'static str {
    if level < LOW {
        "Untrusted"
    } else if level < MEDIUM {
        "Low"
    } else if level < HIGH {
        "Medium"
    } else if level < SYSTEM {
        "High"
    } else if level < 0x5000 {
        "System"
    } else {
        "Protected"
    }
}

fn read_level(token: HANDLE) -> Option<u32> {
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 asks only for the required size; the
    // error it returns is expected and only `needed` matters.
    unsafe {
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buffer = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            needed,
            &mut needed,
        )
        .ok()?;
        // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL (the API contract)
        // whose SID lives inside that same allocation and is only read here.
        let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return None;
        }
        Some(*GetSidSubAuthority(label.Label.Sid, (count - 1) as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_labels_windows_uses_are_named() {
        assert_eq!(name(0x0000), "Untrusted");
        assert_eq!(name(LOW), "Low");
        assert_eq!(name(MEDIUM), "Medium");
        assert_eq!(name(HIGH), "High");
        assert_eq!(name(SYSTEM), "System");
        assert_eq!(name(0x5000), "Protected");
        // A custom label sits in the band above the level it extends.
        assert_eq!(name(LOW + 0x100), "Low");
    }

    #[test]
    fn this_process_has_a_readable_level_and_agrees_with_below_medium() {
        let level = current().expect("the token of this process has an integrity level");
        assert_eq!(
            below_medium(),
            level < MEDIUM,
            "level {level:#x} and below_medium() must agree"
        );
        assert!(
            level >= LOW,
            "no default label is below Low, got {level:#x}"
        );
    }
}