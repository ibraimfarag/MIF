//! The hang detector (ز2-ب): a plain OS thread that watches the tokio runtime.
//!
//! The long-running modes (`serve`, `service`) start this module together with
//! the session. The runtime proves it is still alive by bumping a heartbeat: a
//! timer task of its own, plus every JSON-RPC request that enters the
//! dispatcher. A `std::thread` - deliberately **not** a tokio task, so it keeps
//! running when the runtime does not - watches that heartbeat and, once it has
//! been silent for the deadline, writes a `hang` report itself through
//! [`crate::crash`]: the same `MICS-<date>-<hash>` id, the same JSON + text
//! bundle under `<data dir>\crashes\` as a panic. Nothing is sent anywhere, and
//! nothing is written by the UI.
//!
//! What a "hang" means here - and what it does not:
//!
//! * It covers a runtime that **stopped scheduling tasks at all**: workers
//!   deadlocked, the timer driver wedged, the process starved long enough that
//!   nothing ran. The report says how long the heartbeat was silent and which
//!   request the dispatcher saw last.
//! * It does **not** cover one request that is merely slow, on purpose. A long
//!   `audit.run` or a Defender scan must never be filed as a hang, and on the
//!   multi-threaded runtime the timer task keeps beating while one worker sits
//!   inside a blocking Windows call - a single stuck request is invisible here
//!   by design.
//! * It does **not** cover a hang that takes the whole process with it (a
//!   deadlock inside the allocator, a driver call stuck before this thread
//!   starts, a killed process): the watchdog is a thread *of* that process, so
//!   it dies with it. That case is what the session marker and the next start's
//!   `unclean-exit` report are for (ز2-أ).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use crate::crash;

/// How often the runtime proves it is still scheduling tasks.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long the heartbeat may stay silent before the watchdog calls it a hang.
/// Four beats may be missed without a report, so a busy machine or one slow
/// tick is not a hang.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(20);

/// How often the watchdog thread looks at the heartbeat.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What the runtime and the watchdog thread share. Only atomics except one
/// short lock: it is held for a single string assignment, and the watchdog
/// *tries* it instead of waiting, so the watcher can never be blocked by the
/// runtime it is watching.
struct Shared {
    /// Milliseconds since `started` at the last heartbeat.
    last_beat_ms: AtomicU64,
    /// The last method the dispatcher began, if any. It is the only clue the
    /// report can give about *what* was running when progress stopped.
    last_request: Mutex<Option<String>>,
    /// Set by the watchdog once it filed a report, cleared by the next
    /// heartbeat: one stall is one report, and a later stall gets its own.
    reported: AtomicBool,
    /// Set when the handle is stopped or dropped, so the thread returns.
    stopped: AtomicBool,
}

/// The runtime's handle: bump it to say "still working".
pub struct Heartbeat {
    started: Instant,
    shared: Arc<Shared>,
    /// The watchdog thread, so stopping this handle is a join and not a hope
    /// (the session's handle lives for the process and is never dropped).
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Heartbeat {
    /// Record a sign of life. `method` names the request when the beat comes
    /// from the dispatcher, and is left alone for the timer's own beats.
    fn beat(&self, method: Option<&str>) {
        if let Some(method) = method
            && let Ok(mut last) = self.shared.last_request.lock()
        {
            *last = Some(method.to_string());
        }
        self.shared
            .last_beat_ms
            .store(self.elapsed_ms(), Ordering::SeqCst);
        // A beat ends the current stall: if it wedges again, that is a new one.
        self.shared.reported.store(false, Ordering::SeqCst);
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Ask the thread to return and wait for it: after this, nothing in this
    /// module runs on its behalf any more.
    fn stop(&self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
        let thread = self.thread.lock().ok().and_then(|mut held| held.take());
        if let Some(thread) = thread {
            let _ = thread.join();
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The watchdog of this process, once a session started one.
static ACTIVE: OnceLock<Heartbeat> = OnceLock::new();
/// `start_session` is idempotent: a second call must not start a second thread
/// (or a second heartbeat task) on the same process.
static SESSION: Once = Once::new();

/// Start the watchdog for a long-running session.
///
/// Called where the session marker is written (`crash::begin_session`), so a
/// process with no session has no watchdog either. The returned handle lives for
/// the rest of the process; the thread is detached and dies with it.
pub fn start_session() {
    SESSION.call_once(|| {
        let heartbeat = ACTIVE
            .get_or_init(|| start_with(crash::root(), DEFAULT_DEADLINE, POLL_INTERVAL));
        // The runtime's own proof of life. This task only runs when tokio is
        // still scheduling, so a runtime that has stopped shows up as a silent
        // heartbeat even while the process (and the watchdog thread) is alive.
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                tick.tick().await;
                heartbeat.beat(None);
            }
        });
    });
}

/// The dispatcher's sign of life: a request that reached it, and the method the
/// next hang report should name.
pub fn note_request(method: &str) {
    if let Some(heartbeat) = ACTIVE.get() {
        heartbeat.beat(Some(method));
    }
}

/// Start the thread. `root` is where the report is written (the settings data
/// dir in production, a temp dir in tests).
fn start_with(root: PathBuf, deadline: Duration, poll: Duration) -> Heartbeat {
    let started = Instant::now();
    let shared = Arc::new(Shared {
        last_beat_ms: AtomicU64::new(0),
        last_request: Mutex::new(None),
        reported: AtomicBool::new(false),
        stopped: AtomicBool::new(false),
    });
    let watching = shared.clone();
    let spawned = std::thread::Builder::new()
        .name("mics-watchdog".to_string())
        .spawn(move || watch(root, watching, started, deadline, poll));
    let thread = match spawned {
        Ok(thread) => Some(thread),
        Err(e) => {
            // The watchdog is the last line of defence, so it must not stop the
            // engine from starting - but a silent failure would hide the
            // detector itself, which is the one thing worse than no detector.
            tracing::error!("watchdog thread could not start: {e}");
            None
        }
    };
    Heartbeat {
        started,
        shared,
        thread: Mutex::new(thread),
    }
}

/// The watchdog thread: never wait on a lock the runtime may hold, never touch
/// the pipe, and report one stall exactly once.
fn watch(
    root: PathBuf,
    shared: Arc<Shared>,
    started: Instant,
    deadline: Duration,
    poll: Duration,
) {
    loop {
        std::thread::sleep(poll);
        if shared.stopped.load(Ordering::SeqCst) {
            return;
        }
        let stuck = Duration::from_millis(
            (started.elapsed().as_millis() as u64)
                .saturating_sub(shared.last_beat_ms.load(Ordering::SeqCst)),
        );
        if stuck < deadline {
            continue;
        }
        // `swap` is the whole "one report per stall" rule: the first poll past
        // the deadline files it, every later poll until a beat returns skips.
        if shared.reported.swap(true, Ordering::SeqCst) {
            continue;
        }
        let last_request = shared
            .last_request
            .try_lock()
            .ok()
            .and_then(|last| last.clone());
        match crash::note_hang_in(&root, stuck, deadline, last_request.as_deref()) {
            Some(bug_id) => tracing::error!(
                "watchdog: no heartbeat for {:.1}s (deadline {:.1}s) — hang report {bug_id} \
                 (last request: {})",
                stuck.as_secs_f64(),
                deadline.as_secs_f64(),
                last_request.as_deref().unwrap_or("none")
            ),
            // A read-only data dir must not turn the watchdog into a spinner.
            None => tracing::error!(
                "watchdog: no heartbeat for {:.1}s and no report could be written under {}",
                stuck.as_secs_f64(),
                root.display()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash::Report;

    /// A directory of its own per test, like the crash tests: the reports are
    /// never read from (or written to) the real data dir.
    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mics-watchdog-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Every report the watchdog filed under `root`, oldest id first.
    fn reports(root: &std::path::Path) -> Vec<Report> {
        let Ok(entries) = std::fs::read_dir(root.join("crashes")) else {
            return Vec::new();
        };
        let mut out: Vec<Report> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x.eq_ignore_ascii_case("json"))
                    .unwrap_or(false)
            })
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|text| serde_json::from_str::<Report>(&text).ok())
            .collect();
        out.sort_by(|a, b| a.bug_id.cmp(&b.bug_id));
        out
    }

    /// The seconds in "no heartbeat for 0.2 s", so the test reads the number
    /// the engine actually wrote instead of trusting the shape of the sentence.
    fn stuck_seconds(message: &str) -> Option<f64> {
        let rest = message.split("no heartbeat for ").nth(1)?;
        rest.split(' ').next()?.parse().ok()
    }

    fn wait_for_a_report(root: &std::path::Path, within: Duration) -> Option<Report> {
        let until = Instant::now() + within;
        while Instant::now() < until {
            if let Some(report) = reports(root).into_iter().next() {
                return Some(report);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    #[test]
    fn the_deadline_survives_several_missed_beats() {
        // A single missed beat (or one slow tick on a busy machine) must not be
        // a hang; the deadline has to be worth four of them.
        assert!(
            HEARTBEAT_INTERVAL * 4 <= DEFAULT_DEADLINE,
            "{} is not four beats of {}",
            DEFAULT_DEADLINE.as_secs_f64(),
            HEARTBEAT_INTERVAL.as_secs_f64()
        );
    }

    #[test]
    fn a_frozen_heartbeat_is_reported_once_with_how_long_it_was_stuck() {
        let root = temp_root("frozen");
        // 200 ms and not less: the report formats with one decimal, so a
        // smaller deadline could round down below itself in the message.
        let heartbeat = start_with(
            root.clone(),
            Duration::from_millis(200),
            Duration::from_millis(20),
        );
        heartbeat.beat(Some("scan.start"));

        // The runtime is now wedged as far as the watchdog can tell: nothing
        // beats the heartbeat again. The report must come from the thread.
        let report = wait_for_a_report(&root, Duration::from_secs(10))
            .expect("the watchdog must file a hang report on its own");

        assert_eq!(report.kind, crash::KIND_HANG);
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert!(
            report.message.contains("last request: scan.start"),
            "the report must name the last request: {}",
            report.message
        );
        let stuck = stuck_seconds(&report.message)
            .unwrap_or_else(|| panic!("no duration in {:?}", report.message));
        assert!(
            stuck >= 0.2,
            "reported {stuck}s, under the 0.2s deadline: {}",
            report.message
        );
        assert!(
            stuck < 10.0,
            "reported {stuck}s for a test that waited ~1s: {}",
            report.message
        );

        // Several more polls pass with the heartbeat still frozen: the same
        // stall is not filed again, so there is exactly one report and one
        // occurrence in it.
        std::thread::sleep(Duration::from_millis(300));
        let filed = reports(&root);
        assert_eq!(filed.len(), 1, "one stall is one report: {filed:?}");
        assert_eq!(filed[0].occurrences, 1, "the stall was written once");
        assert_eq!(filed[0].bug_id, report.bug_id);
    }

    #[test]
    fn a_runtime_that_keeps_beating_is_never_reported() {
        let root = temp_root("alive");
        let heartbeat = start_with(
            root.clone(),
            Duration::from_millis(120),
            Duration::from_millis(20),
        );
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            heartbeat.beat(None);
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            reports(&root).is_empty(),
            "a runtime that answers must never be filed as a hang"
        );
    }

    #[test]
    fn a_hang_with_no_request_yet_is_still_one_report() {
        let root = temp_root("norequest");
        let heartbeat = start_with(
            root.clone(),
            Duration::from_millis(100),
            Duration::from_millis(20),
        );
        heartbeat.beat(None);
        let report = wait_for_a_report(&root, Duration::from_secs(10))
            .expect("an idle runtime that stopped beating is a hang too");
        assert!(
            report.message.contains("last request: none"),
            "{}",
            report.message
        );
        // And the heartbeat method itself is not remembered as a request.
        assert_eq!(report.kind, crash::KIND_HANG);
    }

    #[test]
    fn a_stopped_watchdog_lets_its_thread_go_and_files_nothing() {
        let root = temp_root("stop");
        // A deadline this short would fire within a few polls if the thread
        // were still watching after `stop`.
        let heartbeat = start_with(
            root.clone(),
            Duration::from_millis(60),
            Duration::from_millis(10),
        );
        // `stop` joins, so the thread is provably gone before the sleep.
        heartbeat.stop();
        assert!(heartbeat.shared.stopped.load(Ordering::SeqCst));
        std::thread::sleep(Duration::from_millis(200));
        assert!(reports(&root).is_empty(), "a stopped watchdog must not report");
    }
}
