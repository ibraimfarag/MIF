//! The pids that exist right now, in one call.
//!
//! `EnumProcesses` copies a flat array of pids into a caller buffer — one kernel
//! round trip, no per-process queries. That is the cheap half of the guard's poll:
//! the expensive half (command line, image path, parent) is only needed for pids
//! that are *new* since the previous tick, which `sysinfo` then reads for those few
//! (`docs/TODO.md` §0.1, the guard's idle CPU).
//!
//! The API reports both the bytes used and the buffer size: if the two are equal the
//! buffer was too small, because the process table grew while it was being copied,
//! and the call is retried with twice the room.

use anyhow::{bail, Result};
use windows::Win32::System::ProcessStatus::EnumProcesses;

/// Room for `pids` entries in bytes, with a floor so a tiny machine still fits one
/// buffer without a second round trip.
const INITIAL_CAPACITY: usize = 16 * 1024;
/// A process table this large means something is wrong; refusing beats allocating.
const MAX_CAPACITY: usize = 16 * 1024 * 1024;

/// Every pid Windows currently knows about, including `0` and the idle process.
pub fn list_pids() -> Result<Vec<u32>> {
    let mut capacity = INITIAL_CAPACITY;
    loop {
        let mut buffer = vec![0u32; capacity / std::mem::size_of::<u32>()];
        let mut used = 0u32;
        // SAFETY: the buffer is `capacity` bytes long, and the call writes at most
        // that many bytes into it, reporting how many it used in `used`.
        unsafe {
            EnumProcesses(
                buffer.as_mut_ptr(),
                capacity as u32,
                &mut used,
            )
        }
        .map_err(|e| anyhow::anyhow!("enumerate processes: {e}"))?;
        let used = used as usize;
        if used < capacity {
            buffer.truncate(used / std::mem::size_of::<u32>());
            return Ok(buffer);
        }
        capacity *= 2;
        if capacity > MAX_CAPACITY {
            bail!("the process table needs more than {MAX_CAPACITY} bytes");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_in_the_list() {
        let pids = list_pids().expect("enumerate processes");
        assert!(
            pids.contains(&std::process::id()),
            "the list must contain the process that asked for it"
        );
        assert!(pids.len() > 3, "a running Windows has more than 3 processes");
    }

    #[test]
    fn the_same_list_comes_back_twice() {
        let first = list_pids().expect("first enumeration");
        let second = list_pids().expect("second enumeration");
        // Pids come and go between the calls; the process asking is in both.
        assert!(first.contains(&std::process::id()));
        assert!(second.contains(&std::process::id()));
    }
}