//! Single-instance guard (D-006).
//!
//! MI CS must have exactly one engine per machine: two engines would fight
//! over the firewall, the guard loop, and the quarantine database. A named
//! mutex is created at startup; the second process sees `ERROR_ALREADY_EXISTS`
//! and exits quietly so the UI connects to the running engine instead.

use windows::core::HSTRING;
use windows::Win32::Foundation::{GetLastError, CloseHandle, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

const MUTEX_NAME: &str = r"Local\MICS_Engine_Singleton";

/// Held for the lifetime of the process; dropping it releases the mutex.
/// `None` means "no real mutex was taken" (test isolation hook).
pub struct InstanceGuard(Option<HANDLE>);

// The handle is only ever closed on drop from the owning thread.
unsafe impl Send for InstanceGuard {}

/// Returns `Some` when this process owns the engine slot, `None` when another
/// engine is already running.
///
/// `MICS_NO_SINGLETON=1` is a test hook: together with `MICS_PIPE_NAME` it lets
/// an isolated engine run next to the real one.
pub fn acquire() -> Option<InstanceGuard> {
    if std::env::var("MICS_NO_SINGLETON").is_ok() {
        return Some(InstanceGuard(None));
    }
    unsafe {
        let name = HSTRING::from(MUTEX_NAME);
        let handle = CreateMutexW(None, true, &name).ok()?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = CloseHandle(handle);
            None
        } else {
            Some(InstanceGuard(Some(handle)))
        }
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0 {
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}
