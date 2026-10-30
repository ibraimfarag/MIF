//! How much CPU the engine process has actually burnt.
//!
//! `GetProcessTimes` on the current process returns kernel + user time that
//! Windows maintains for the process object itself. Reading it twice and dividing
//! the difference by wall time gives a percentage with **no measurement overhead**,
//! which is the whole point: `benchmark` used to sample `sysinfo` while refreshing
//! every process six times in three seconds, so it was measuring its own probe.
//!
//! The result is a share of *one* core (100 % = one thread busy), the same scale
//! `sysinfo` uses. Callers divide by `available_parallelism()` to get the Task
//! Manager number.

use anyhow::{Context, Result};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

/// Total CPU time (kernel + user) this process has used so far, in seconds.
pub fn own_cpu_seconds() -> Result<f64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: the four out-pointers are valid for the call and the handle is
    // `GetCurrentProcess`'s pseudo-handle, which must not be closed.
    unsafe { GetProcessTimes(GetCurrentProcess(), &mut creation, &mut exit, &mut kernel, &mut user) }
        .context("read this process's CPU times")?;
    Ok(filetime_seconds(kernel) + filetime_seconds(user))
}

/// `FILETIME` counts 100 ns intervals; convert to seconds.
fn filetime_seconds(time: FILETIME) -> f64 {
    let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    ticks as f64 / 10_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cpu_time_grows_when_this_thread_works() {
        let before = own_cpu_seconds().expect("read the first sample");
        // Burn CPU for a moment; the counter is process-wide and monotonic.
        let mut accumulator = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_millis(60);
        let mut i = 0u64;
        while std::time::Instant::now() < deadline {
            i = i.wrapping_mul(6364136223846793005).wrapping_add(1);
            accumulator ^= i >> 33;
        }
        let after = own_cpu_seconds().expect("read the second sample");
        assert!(accumulator != 0 || i > 0);
        assert!(
            after > before,
            "a busy loop must be visible in the process CPU time ({before} -> {after})"
        );
    }
}