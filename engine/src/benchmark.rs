//! --benchmark: measures the engine's own idle footprint (spec section 15).
//! Reports RAM (working set) and sampled CPU over a 3 s idle window.

use serde::Serialize;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, System};

#[derive(Debug, Serialize)]
pub struct Benchmark {
    pub duration_ms: u128,
    pub ram_mb: f64,
    pub cpu_percent_avg: f32,
    pub budget_ok: bool,
    pub budgets: serde_json::Value,
}

pub fn run() -> Benchmark {
    let me = std::process::id();
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let samples = 6u32;
    let mut cpu_sum = 0f32;
    let mut cpu_n = 0u32;
    let start = Instant::now();
    for _ in 0..samples {
        std::thread::sleep(Duration::from_millis(500));
        sys.refresh_processes(ProcessesToUpdate::All, true);
        if let Some(p) = sys.process(sysinfo::Pid::from_u32(me)) {
            cpu_sum += p.cpu_usage();
            cpu_n += 1;
        }
    }
    let ram_mb = sys
        .process(sysinfo::Pid::from_u32(me))
        .map(|p| p.memory() as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);
    let cpu = if cpu_n > 0 { cpu_sum / cpu_n as f32 } else { 0.0 };

    let budgets = serde_json::json!({
        "idle_cpu_percent_max": 1.0,
        "idle_ram_mb_max": 150.0,
    });
    let ok = ram_mb <= 150.0 && cpu <= 1.0;
    Benchmark {
        duration_ms: start.elapsed().as_millis(),
        ram_mb: (ram_mb * 10.0).round() / 10.0,
        cpu_percent_avg: (cpu * 100.0).round() / 100.0,
        budget_ok: ok,
        budgets,
    }
}
