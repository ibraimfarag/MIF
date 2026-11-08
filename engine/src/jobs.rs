//! Job plumbing shared by long-running engine work (currently scans).
//!
//! Two things live here so every caller behaves the same way:
//!  * a single progress/notification channel that the transports (pipe, stdio)
//!    forward to their clients, and
//!  * a cancellation registry keyed by job id, so `scan.stop` / `job.cancel`
//!    stop exactly one job instead of every worker in the process.
//!
//! Job *state* is persisted in SQLite (see `Storage::create_job` and friends);
//! this module only holds transient flags.

use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::broadcast;

static EVENTS: OnceLock<broadcast::Sender<String>> = OnceLock::new();

fn events() -> &'static broadcast::Sender<String> {
    EVENTS.get_or_init(|| broadcast::channel(1024).0)
}

/// Every transport subscribes here; a slow client cannot block the engine
/// (broadcast drops the oldest message for lagging receivers).
pub fn subscribe() -> broadcast::Receiver<String> {
    events().subscribe()
}

/// True while at least one transport is listening.
///
/// `notify` drops what nobody hears — which is fine for job progress — so a
/// producer whose message has to wait until someone is there (the in-app alert
/// cards) asks first and parks the message if the answer is no.
pub fn has_subscribers() -> bool {
    events().receiver_count() > 0
}

/// How many transports are listening right now: one per attached client, plus
/// one for a stdio caller. [`has_subscribers`] answers "anyone at all"; this
/// answers "anyone else", which is what a second launch has to know (D-041).
pub fn subscriber_count() -> usize {
    events().receiver_count()
}

/// The `event` payload an activation carries (D-041).
///
/// `path` is what Explorer handed over through `--scan`, or null for a plain
/// second launch: either way the window that is already open comes forward.
pub fn activation_payload(path: Option<&str>) -> serde_json::Value {
    json!({"type": "activate", "data": {"path": path}})
}

/// Whether a launch that found the app already up has somewhere to hand itself
/// over to.
///
/// The caller is a listener itself, so only a *second* one — the window that is
/// already open — counts. Pulled out of [`announce_activation`] because that
/// boundary (nobody in CLI mode, the caller alone, a window beside it) is the
/// whole rule, and it is worth a test of its own.
pub fn activation_is_delivered(listeners: usize) -> bool {
    listeners > 1
}

/// Announces a launch to every client and says whether anyone else heard it.
///
/// True means the app that is already running took the handover (and scans
/// `path` when there is one), so the process that asked ends; false means this
/// process *is* the window and has to scan the path itself. Nothing is raised
/// when nobody is listening: a notification nobody hears is dropped anyway, and
/// raising it would only be read back by the caller.
pub fn announce_activation(path: Option<&str>) -> bool {
    let delivered = activation_is_delivered(subscriber_count());
    if delivered {
        notify("event", activation_payload(path));
    }
    delivered
}

/// The JSON-RPC notification envelope [`notify`] sends.
///
/// A transport that has to replay a message it parked earlier builds exactly
/// the same line through here, so there is one shape and not two.
pub fn envelope(method: &str, params: serde_json::Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
    .to_string()
}

/// Sends one JSON-RPC notification (`method` + `params`) to every client.
pub fn notify(method: &str, params: serde_json::Value) {
    // No subscribers (CLI mode, or UI closed) is not an error.
    let _ = events().send(envelope(method, params));
}

/// Scan progress, per spec section 5 (`progress` notifications).
#[allow(clippy::too_many_arguments)]
pub fn progress(
    job_id: &str,
    state: &str,
    pct: u32,
    detail: &str,
    scanned: i64,
    skipped: i64,
    total: i64,
    findings: i64,
) {
    notify(
        "progress",
        json!({
            "job_id": job_id,
            "state": state,
            "pct": pct,
            "detail": detail,
            "scanned": scanned,
            "skipped": skipped,
            "total": total,
            "findings": findings,
        }),
    );
}

/// Terminal event for a job (the UI refreshes from `job.get` on receipt).
pub fn finished(job_id: &str, state: &str, findings: i64) {
    notify(
        "event",
        json!({
            "type": "job_finished",
            "data": { "job_id": job_id, "state": state, "findings": findings },
        }),
    );
}

/// Human-friendly, sortable, collision-resistant job id.
pub fn new_job_id(kind: &str) -> String {
    let now = chrono::Utc::now();
    format!(
        "{kind}-{}-{:03}",
        now.format("%Y%m%dT%H%M%S"),
        now.timestamp_subsec_millis()
    )
}

// ---------- cancellation ----------

static ACTIVE: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

fn active() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register(job_id: &str) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    active().lock().unwrap().insert(job_id.to_string(), flag.clone());
    flag
}

pub fn unregister(job_id: &str) {
    active().lock().unwrap().remove(job_id);
}

pub fn is_running(job_id: &str) -> bool {
    active().lock().unwrap().contains_key(job_id)
}

pub fn active_count() -> usize {
    active().lock().unwrap().len()
}

/// Cancels one job. Returns false when it is not running.
pub fn cancel(job_id: &str) -> bool {
    match active().lock().unwrap().get(job_id) {
        Some(flag) => {
            flag.store(true, Ordering::SeqCst);
            true
        }
        None => false,
    }
}

/// Cancels every running job (used by `scan.stop`); returns how many were hit.
pub fn cancel_all() -> usize {
    let map = active().lock().unwrap();
    for flag in map.values() {
        flag.store(true, Ordering::SeqCst);
    }
    map.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handover boundary (D-041). The caller of `app.activate` is a listener
    /// itself, so the interesting line is between one and two: alone, the launch
    /// has to scan the path in its own window; with the window that is already
    /// open beside it, it hands the path over and ends.
    #[test]
    fn only_a_second_listener_takes_the_handover() {
        assert!(!activation_is_delivered(0)); // CLI mode: no transport at all
        assert!(!activation_is_delivered(1)); // the launch itself
        assert!(activation_is_delivered(2)); // the window that is already open
        assert!(activation_is_delivered(3));
    }

    /// What the running window receives: an `event` (the only notification kind
    /// the app routes to its listeners) whose data carries Explorer's path.
    #[test]
    fn the_activation_notification_carries_the_path() {
        let line = envelope(
            "event",
            activation_payload(Some(r"C:\Users\me\Downloads\report.pdf")),
        );
        let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "event");
        assert_eq!(msg["params"]["type"], "activate");
        assert_eq!(
            msg["params"]["data"]["path"],
            r"C:\Users\me\Downloads\report.pdf"
        );
        assert!(msg.get("id").is_none(), "a notification carries no id");
    }

    /// A plain second launch (double-clicked shortcut, no `--scan`) is the same
    /// handover with nothing to scan: the window still comes forward.
    #[test]
    fn a_plain_second_launch_carries_no_path() {
        let payload = activation_payload(None);
        assert_eq!(payload["type"], "activate");
        assert!(payload["data"]["path"].is_null());
    }

    /// The activation is not a `progress` notification: the scanner screen
    /// filters those by job id and would drop it.
    #[test]
    fn the_activation_is_not_progress() {
        assert_ne!(activation_payload(None)["type"], "job_finished");
        assert_ne!(activation_payload(None)["type"], "progress");
    }
}
