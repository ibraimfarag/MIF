//! The engine's other end: the app that started it (D-039).
//!
//! `mics-engine service --parent <pid>` opens a handle to that process once and
//! waits on it. A handle rather than a pid check on a timer, because Windows
//! does not hand a pid to another process while a handle to the first one is
//! open — so "signaled" can only mean *that* process ended: the app was closed,
//! it crashed, or the user ended it from Task Manager. When it ends, the engine
//! asks itself to stop (`crate::lifecycle`) and the usual clean end runs.
//!
//! Nothing here fires when no parent was passed: an engine started by a logon
//! entry, a terminal or a verifier is not owned by an app and must not die with
//! one.

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
};

/// A handle to the app, held for as long as the engine runs.
pub struct ParentWatch(HANDLE);

// The handle is opened and waited on by the watcher thread and dropped there.
unsafe impl Send for ParentWatch {}

impl ParentWatch {
    /// `Some` when the process at `pid` can be waited on; `None` when it is
    /// already gone. "Already gone" is not an error: it is an app that ended
    /// before the engine attached, and the answer is to stop now, not to serve
    /// a machine whose owner is missing.
    pub fn attach(pid: u32) -> Option<ParentWatch> {
        // SAFETY: a synchronize-only handle on a pid we were given on the
        // command line. A failure here is the normal "no such process" case.
        unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }
            .ok()
            .map(ParentWatch)
    }

    /// Blocks until the app exits; `false` means `millis` elapsed first.
    pub fn wait(&self, millis: u32) -> bool {
        // SAFETY: `self.0` is a live handle for the life of this value, and the
        // wait only reads its signaled state.
        unsafe { WaitForSingleObject(self.0, millis) == WAIT_OBJECT_0 }
    }
}

impl Drop for ParentWatch {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `attach` and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Watches the app that started this engine and asks for a clean stop when it
/// ends. A plain thread, like the watchdog: it has to outlive whatever the
/// async runtime is doing, and it must never be the reason a client waits.
pub fn watch_parent(pid: u32) {
    let spawned = std::thread::Builder::new()
        .name("mics-parent-watch".to_string())
        .spawn(move || match ParentWatch::attach(pid) {
            Some(watch) => {
                if watch.wait(INFINITE) {
                    crate::lifecycle::request(&format!(
                        "the app that started this engine (pid {pid}) exited"
                    ));
                }
            }
            None => {
                crate::lifecycle::request(&format!(
                    "the app that started this engine (pid {pid}) was already gone"
                ));
            }
        });
    match spawned {
        Ok(_) => tracing::info!("watching the app that started this engine (pid {pid})"),
        Err(e) => tracing::warn!("could not start the parent watch for pid {pid}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pid_that_does_not_exist_is_already_gone() {
        // Far above any real pid, so `OpenProcess` refuses it: the answer the
        // engine acts on is "the app is not there", not an error to report.
        assert!(ParentWatch::attach(0xFFFF_FFF0).is_none());
    }

    #[test]
    fn the_process_asking_is_waitable_and_has_not_exited() {
        let watch = ParentWatch::attach(std::process::id())
            .expect("this test process must be waitable");
        assert!(
            !watch.wait(50),
            "the current process cannot have exited while it is asserting"
        );
    }
}
