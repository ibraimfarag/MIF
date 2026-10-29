//! Real-time Process Guard (L3).
//!
//! v1 transport: a high-frequency process-diff loop over sysinfo (works
//! unelevated, zero kernel footprint) feeding a Sigma-like JSON rules engine.
//! ETW kernel sessions (ferrisetw) plug into the same rules engine when the
//! engine runs elevated — documented upgrade path in docs/DECISIONS.md.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub mod canary;
pub mod etw;


// ---------- rules (Sigma-like JSON) ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRule {
    pub id: String,
    pub name: String,
    pub severity: String, // high | critical
    #[serde(default)]
    pub parent_image: Option<String>,
    #[serde(default)]
    pub child_image: Option<String>,
    #[serde(default)]
    pub child_cmd_contains: Option<String>,
    #[serde(default)]
    pub child_path_contains: Option<String>,
    #[serde(default = "default_action")]
    pub action: String, // alert | kill
}

fn default_action() -> String {
    "alert".into()
}

pub fn rules_dir() -> PathBuf {
    for base in [
        std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())),
        std::env::var("MICS_RULES_DIR").ok().map(PathBuf::from),
        std::env::current_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        let p = base.join("rules").join("guard");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("rules/guard")
}

pub fn load_rules() -> Result<Vec<GuardRule>> {
    let mut rules = Vec::new();
    let dir = rules_dir();
    // The packaged layout ships `rules/` next to the binaries, but a dev or
    // partial copy may not have it. The starter pack is compiled into the
    // binary, so the guard is never left with zero rules.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().map(|x| x == "json").unwrap_or(false) {
                if let Ok(text) = std::fs::read_to_string(&path)
                    && let Ok(parsed) = serde_json::from_str::<Vec<GuardRule>>(&text)
                {
                    rules.extend(parsed);
                }
            }
        }
    }
    if rules.is_empty() {
        match serde_json::from_str::<Vec<GuardRule>>(starter_rules_source()) {
            Ok(embedded) => {
                tracing::info!(
                    "guard: using the built-in starter rules ({} rule(s)) — {} not found",
                    embedded.len(),
                    dir.display()
                );
                rules = embedded;
            }
            Err(e) => tracing::warn!("guard: starter rules unreadable: {e}"),
        }
    }
    Ok(rules)
}

pub fn starter_rules_source() -> &'static str {
    include_str!("../../rules/guard/starter.json")
}

// ---------- event bus ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvent {
    pub r#type: String, // process_suspicious | canary_triggered
    pub severity: String,
    pub rule_id: String,
    pub rule_name: String,
    pub pid: u32,
    pub process: String,
    pub parent: String,
    pub detail: String,
    pub at: i64,
}

static EVENT_TX: OnceLock<broadcast::Sender<GuardEvent>> = OnceLock::new();

fn event_tx() -> &'static broadcast::Sender<GuardEvent> {
    EVENT_TX.get_or_init(|| broadcast::channel(512).0)
}

/// Multiple consumers are supported (CLI prints, pipe forwards, tests).
pub fn subscribe_events() -> broadcast::Receiver<GuardEvent> {
    event_tx().subscribe()
}

/// Public emit for sibling modules (canary).
pub fn emit_public(ev: GuardEvent) {
    emit(ev);
}

fn emit(ev: GuardEvent) {
    // A send error only means nobody is listening (CLI mode / UI closed).
    let _ = event_tx().send(ev.clone());
    // Every guard event also lands in the correlator.
    if let Err(e) = crate::smart::correlator::record_event(&ev) {
        error!("correlator: {e:#}");
    }
}

// ---------- guard engine ----------

pub struct GuardState {
    running: AtomicBool,
    known: Mutex<HashSet<u32>>,
}

static GUARD: OnceLock<GuardState> = OnceLock::new();

fn guard() -> &'static GuardState {
    GUARD.get_or_init(|| GuardState {
        running: AtomicBool::new(false),
        known: Mutex::new(HashSet::new()),
    })
}

pub fn is_running() -> bool {
    guard().running.load(Ordering::SeqCst)
}

pub fn start_guard() {
    let g = guard();
    if g.running.swap(true, Ordering::SeqCst) {
        return; // already running
    }
    g.known.lock().unwrap().clear();

    std::thread::spawn(move || {
        info!("Guard loop started");
        let mut sys = System::new();
        let rules = Arc::new(Mutex::new(load_rules().unwrap_or_default()));
        // Rule hot-reload: rescan the rules dir every 30 s.
        let rules_for_reload = rules.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(30));
            match load_rules() {
                Ok(r) => *rules_for_reload.lock().unwrap() = r,
                Err(e) => warn!("rule reload: {e:#}"),
            }
        });

        // Canary watchers armed alongside the process loop.
        if let Err(e) = crate::guard::canary::arm_watchers() {
            error!("canary arm: {e:#}");
        }

        // Prefer instant ETW kernel events when elevated; the poll loop below
        // stays as the unelevated fallback (and still feeds canary checks).
        let etw_live = crate::guard::etw::start();

        let mut first = true;
        loop {
            if !guard().running.load(Ordering::SeqCst) {
                info!("Guard loop stopped");
                break;
            }
            sys.refresh_processes(ProcessesToUpdate::All, true);
            let mut current = HashSet::new();
            let mut new_procs: Vec<(u32, String, String, String, String)> = Vec::new();
            for (pid, proc) in sys.processes() {
                let pid_u32 = pid.as_u32();
                current.insert(pid_u32);
                let proc_name = proc.name().to_string_lossy().to_lowercase();
                let cmd = proc
                    .cmd()
                    .iter()
                    .map(|c| c.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                let parent_name = proc
                    .parent()
                    .and_then(|p: Pid| sys.process(p))
                    .map(|p| p.name().to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                let exe_path = proc
                    .exe()
                    .map(|p| p.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                new_procs.push((pid_u32, proc_name, parent_name, cmd, exe_path));
            }
            {
                let mut known = guard().known.lock().unwrap();
                let fresh: Vec<_> = new_procs
                    .into_iter()
                    .filter(|(pid, ..)| first || !known.contains(pid))
                    .collect();
                *known = current;
                                first = false;
                drop(known);


                let snapshot = rules.lock().unwrap().clone();
                for (pid, name, parent, cmd, exe_path) in fresh {
                    for rule in &snapshot {
                        if rule_matches(rule, &name, &parent, &cmd, &exe_path) {
                            let ev = GuardEvent {
                                r#type: "process_suspicious".into(),
                                severity: rule.severity.clone(),
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                pid,
                                process: name.clone(),
                                parent: parent.clone(),
                                detail: format!("cmd: {cmd}"),
                                at: chrono::Utc::now().timestamp(),
                            };
                            emit(ev);
                            if rule.action == "kill"
                                && let Err(e) = kill_tree(pid) {
                                    warn!("responder kill_tree({pid}): {e:#}");
                                }
                        }
                    }
                }
            }
            crate::guard::canary::check_touches();
            if etw_live {
                // ETW pushes instant events; the poll loop only services the
                // canary checker.
                std::thread::sleep(Duration::from_millis(1000));
                continue;
            }
            std::thread::sleep(Duration::from_millis(2000));
        }
    });
}

pub fn stop_guard() {
    guard().running.store(false, Ordering::SeqCst);
}

/// Field values may be pipe-separated alternates: "a.exe|b.exe".
fn field_matches(want: &str, got: &str) -> bool {
    want.to_lowercase()
        .split('|')
        .map(|w| w.trim())
        .filter(|w| !w.is_empty())
        .any(|w| got.contains(w))
}

fn rule_matches(
    rule: &GuardRule,
    child: &str,
    parent: &str,
    cmd: &str,
    exe_path: &str,
) -> bool {
    if let Some(want) = &rule.child_image
        && !field_matches(want, child) {
            return false;
        }
    if let Some(want) = &rule.parent_image
        && !field_matches(want, parent) {
            return false;
        }
    if let Some(want) = &rule.child_cmd_contains
        && !cmd.to_lowercase().contains(&want.to_lowercase()) {
            return false;
        }
    if let Some(want) = &rule.child_path_contains
        && !exe_path.contains(&want.to_lowercase()) {
            return false;
        }
    true
}

/// Optional tree-kill responder (usermode): taskkill /T /F.
pub fn kill_tree(pid: u32) -> Result<()> {
    let mut command = std::process::Command::new("taskkill");
    command.args(["/PID", &pid.to_string(), "/T", "/F"]);
    crate::platform::windows::elevation::hide_console(&mut command);
    let out = command.output().context("launch taskkill")?;
    if !out.status.success() {
        anyhow::bail!(
            "taskkill failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// JSON status for the UI.
pub fn status_json() -> serde_json::Value {
    json!({
        "running": is_running(),
        // True = instant kernel events; false = 2 s poll fallback (unelevated).
        "etw_active": etw::is_active(),
        "rules": load_rules().unwrap_or_default(),
    })
}
