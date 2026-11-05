//! Incident correlator: related guard events (same process / same rule family
//! within a window) collapse into ONE incident with a kill-chain timeline,
//! instead of spamming isolated alerts.

use anyhow::Result;
use serde::Serialize;
use std::sync::Mutex;
use std::sync::OnceLock;

use crate::guard::GuardEvent;
use crate::storage::sqlite::Storage;

const WINDOW_SECS: i64 = 600; // 10 minutes

#[derive(Debug, Serialize, Clone)]
pub struct Incident {
    pub incident_id: i64,
    pub title: String,
    pub severity: String,
    pub opened_at: i64,
    pub updated_at: i64,
    pub timeline: Vec<GuardEvent>,
    pub closed: bool,
}

struct CorrelatorState {
    // process name (+rule family) -> open incident id
    open: std::collections::HashMap<String, i64>,
}

static STATE: OnceLock<Mutex<CorrelatorState>> = OnceLock::new();

fn state() -> &'static Mutex<CorrelatorState> {
    STATE.get_or_init(|| {
        Mutex::new(CorrelatorState {
            open: std::collections::HashMap::new(),
        })
    })
}

fn incident_key(ev: &GuardEvent) -> String {
    // One incident per (process, rule family) — a kill chain usually repeats.
    format!("{}|{}", ev.process, ev.rule_id.split('-').next().unwrap_or(""))
}

pub fn record_event(ev: &GuardEvent) -> Result<()> {
    let storage = Storage::open()?;
    let key = incident_key(ev);
    let mut st = state().lock().unwrap();

    // Reuse an open incident for the same key within the window?
    if let Some(id) = st.open.get(&key) {
        if let Some(mut inc) = storage.get_incident(*id)? {
            let fresh = inc.timeline.last().map(|e| ev.at - e.at).unwrap_or(i64::MAX) <= WINDOW_SECS;
            if fresh && !inc.closed {
                inc.timeline.push(ev.clone());
                inc.severity = max_severity(&inc.severity, &ev.severity);
                inc.updated_at = ev.at;
                storage.update_incident(&inc)?;
                return Ok(());
            }
        }
        st.open.remove(&key);
    }

    let title = match ev.r#type.as_str() {
        "canary_triggered" => format!("Canary file modified: {}", ev.detail),
        "canary_read" => format!("Canary file opened for read: {}", ev.detail),
        _ => format!("{} → {} ({})", ev.parent, ev.process, ev.rule_name),
    };
    let id = storage.create_incident(&title, &ev.severity, ev.at)?;
    storage.append_incident_event(id, ev)?;
    st.open.insert(key, id);
    Ok(())
}

fn max_severity(a: &str, b: &str) -> String {
    let rank = |s: &str| match s {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    };
    if rank(b) > rank(a) {
        b.to_string()
    } else {
        a.to_string()
    }
}

pub fn list_incidents(limit: u32) -> Result<Vec<Incident>> {
    Storage::open()?.list_incidents(limit)
}

pub fn close_incident(id: i64) -> Result<()> {
    Storage::open()?.close_incident(id)
}
