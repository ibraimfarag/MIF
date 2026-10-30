//! --benchmark: measures the engine's own idle footprint (spec section 15).
//!
//! The CPU figure is a plain difference between two reads of this process's own
//! kernel+user time (`GetProcessTimes`), divided by the wall time between them, so
//! the measurement does not pay for itself. The previous version sampled `sysinfo`
//! while refreshing **every** process six times in three seconds: on this machine
//! that reported 9.94 % with the guard switched off, i.e. it was mostly measuring
//! its own probe. See `docs/TODO.md` §0.1 and `scripts/measure-guard-cpu.ps1`.
//!
//! Two numbers are reported on purpose, because "1 %" is meaningless without a
//! denominator:
//!
//! * `cpu_percent` — share of **one** core (100 % = one thread busy), the scale
//!   `sysinfo` and profilers use;
//! * `cpu_percent_of_machine` — the same work divided by the logical processor
//!   count, which is what Task Manager shows and what the budget means.

use serde::Serialize;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, ProcessRefreshKind, System};

/// The idle budget from the spec, as a share of the whole machine.
const IDLE_CPU_BUDGET: f32 = 1.0;
/// The idle RAM budget from the spec.
const IDLE_RAM_BUDGET_MB: f64 = 150.0;
/// How long the idle window is sampled for.
const WINDOW: Duration = Duration::from_secs(3);

#[derive(Debug, Serialize)]
pub struct Benchmark {
    pub duration_ms: u128,
    pub ram_mb: f64,
    /// Share of one core, the `sysinfo`/profiler scale.
    pub cpu_percent: f32,
    /// Share of every logical processor, the Task Manager scale the budget uses.
    pub cpu_percent_of_machine: f32,
    pub cores: usize,
    pub budget_ok: bool,
    pub budgets: serde_json::Value,
}

pub fn run() -> Benchmark {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let start = Instant::now();
    let before = crate::platform::windows::timing::own_cpu_seconds().unwrap_or(0.0);

    // One sleep, not six samples: the whole point is to measure the idle window
    // without doing work inside it.
    std::thread::sleep(WINDOW);

    let after = crate::platform::windows::timing::own_cpu_seconds().unwrap_or(before);
    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let cpu_one_core = ((after - before) / elapsed * 100.0) as f32;
    let cpu_of_machine = cpu_one_core / cores as f32;

    let ram_mb = own_ram_mb();
    let ok = ram_mb <= IDLE_RAM_BUDGET_MB && f64::from(cpu_of_machine) <= f64::from(IDLE_CPU_BUDGET);

    Benchmark {
        duration_ms: start.elapsed().as_millis(),
        ram_mb: (ram_mb * 10.0).round() / 10.0,
        cpu_percent: (cpu_one_core * 100.0).round() / 100.0,
        cpu_percent_of_machine: (cpu_of_machine * 100.0).round() / 100.0,
        cores,
        budget_ok: ok,
        budgets: serde_json::json!({
            "idle_cpu_percent_max": IDLE_CPU_BUDGET,
            "idle_cpu_basis": "percent of all logical processors (Task Manager), not of one core",
            "idle_ram_mb_max": IDLE_RAM_BUDGET_MB,
            "guard_measured_by": "scripts/measure-guard-cpu.ps1 (the guard loop lives in the long-running service process, not in this one)",
        }),
    }
}

/// This process's working set, refreshing only this process (the whole-table
/// refresh is what made the old number wrong).
fn own_ram_mb() -> f64 {
    let mut sys = System::new();
    let me = sysinfo::Pid::from_u32(std::process::id());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[me]),
        false,
        ProcessRefreshKind::nothing().with_memory(),
    );
    sys.process(me)
        .map(|p| p.memory() as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0)
}