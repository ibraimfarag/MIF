//! ETW kernel Process provider — instant process-start events (no 2 s poll).
//! Used automatically when the engine runs elevated; the poll loop remains
//! the unelevated fallback. Command lines are enriched from sysinfo at event
//! time (the kernel provider does not carry them).

use ferrisetw::parser::Parser;
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{emit_public, load_rules, rule_matches, GuardEvent};
use crate::storage::sqlite::Storage;

static ETW_ACTIVE: AtomicBool = AtomicBool::new(false);

/// True when the kernel ETW session is live (i.e. the guard is running with
/// instant process events instead of the 2 s poll fallback).
pub fn is_active() -> bool {
    ETW_ACTIVE.load(Ordering::SeqCst)
}

/// Returns true when the ETW session started (elevated), false to fall back
/// to the poll loop.
pub fn start() -> bool {
    ETW_ACTIVE.store(false, Ordering::SeqCst);

    let storage = Storage::open().ok();
    let ioc_hashes = storage.map(|s| s.dump_ioc_hashes().unwrap_or_default()).unwrap_or_default();

    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        // Kernel Process provider: opcode 1 = ProcessStart (3 = DCStart).
        let opcode = record.opcode();
        if opcode != 1 && opcode != 3 {
            return;
        }
        let parser = Parser::create(record, &schema);
        // Property names differ across Windows builds — try known variants.
        let name = ["ImageName", "NewProcessName", "ProcessName"]
            .iter()
            .find_map(|p| parser.try_parse::<String>(p).ok())
            .unwrap_or_default();
        let pid = ["NewProcessId", "ProcessId", "ProcessID"]
            .iter()
            .find_map(|p| parser.try_parse::<u32>(p).ok())
            .unwrap_or(0);
        if name.is_empty() || pid == 0 {
            return;
        }
        let name_l = name.to_lowercase();
        let file_name = name_l.rsplit('\\').next().unwrap_or(&name_l).to_string();

        // Enrich: parent + command line from a targeted sysinfo refresh.
        let (parent, cmd) = enrich(pid);

        let rules = load_rules().unwrap_or_default();
        for rule in &rules {
            if rule_matches(rule, &file_name, &parent, &cmd, &name_l) {
                emit_public(GuardEvent {
                    r#type: "process_suspicious".into(),
                    severity: rule.severity.clone(),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    pid,
                    process: file_name.clone(),
                    parent: parent.clone(),
                    detail: format!("cmd: {cmd}"),
                    at: chrono::Utc::now().timestamp(),
                });
                if rule.action == "kill" {
                    let _ = super::kill_tree(pid);
                }
            }
        }
        // IOC hash check happens on-demand later (hashing at every start is
        // too hot); the scanner + scheduled scans cover the hash dimension.
        let _ = ioc_hashes;
    };

    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(callback)
        .build();
    match KernelTrace::new()
        .named("MICS-Guard-ETW".to_string())
        .enable(provider)
        .start_and_process()
    {
        Ok(trace) => {
            // Run for the engine's lifetime.
            std::mem::forget(trace);
            ETW_ACTIVE.store(true, Ordering::SeqCst);
            tracing::info!("ETW kernel guard session started (instant events)");
            true
        }
        Err(e) => {
            tracing::warn!("ETW unavailable ({e:?}) — falling back to poll loop");
            false
        }
    }
}

/// Quick single-process enrichment (parent name + command line).
fn enrich(pid: u32) -> (String, String) {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[Pid::from_u32(pid)]), true);
    let Some(p) = sys.process(Pid::from_u32(pid)) else {
        return (String::new(), String::new());
    };
    let cmd = p
        .cmd()
        .iter()
        .map(|c| c.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let parent = p
        .parent()
        .and_then(|pp| sys.process(pp))
        .map(|pp| pp.name().to_string_lossy().to_lowercase())
        .unwrap_or_default();
    (parent, cmd)
}
