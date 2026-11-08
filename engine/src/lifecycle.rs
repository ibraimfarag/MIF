//! When the engine stops, and who is allowed to say so.
//!
//! The engine has exactly two deliberate ways to end, and both land here so the
//! loop that serves the pipe, the parent watch and the `shutdown` method cannot
//! disagree about whether a stop was asked for:
//!
//!  * the app that started this engine asks for it — the `shutdown` JSON-RPC
//!    method, which the UI calls when it is quitting;
//!  * the app that started this engine is gone — `mics-engine service --parent
//!    <pid>` holds a handle to it, so an app that was closed, crashed, or ended
//!    from Task Manager still takes its engine with it.
//!
//! A stop is a *clean* end: the caller still ends its crash session normally, so
//! an engine that exited because its app did is never filed as a crash. Nothing
//! else stops the engine — an engine started by a logon entry, a verifier or a
//! terminal has no parent to watch and runs until it is asked to stop (D-039).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tokio::sync::Notify;

/// The stop flag, as a value rather than a global, so the logic is testable
/// without one test's request being visible to the next one.
pub struct Stop {
    requested: AtomicBool,
    reason: OnceLock<String>,
    wake: Notify,
}

impl Default for Stop {
    fn default() -> Self {
        Self::new()
    }
}

impl Stop {
    pub fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            reason: OnceLock::new(),
            wake: Notify::new(),
        }
    }

    /// Asks for a stop. `true` only for the first caller, so the log line says
    /// what actually ended the process instead of the last thing to try.
    pub fn request(&self, reason: &str) -> bool {
        if self.requested.swap(true, Ordering::SeqCst) {
            return false;
        }
        tracing::info!("shutdown requested: {reason}");
        let _ = self.reason.set(reason.to_string());
        self.wake.notify_one();
        true
    }

    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// The reason the engine is stopping; empty until something asked.
    pub fn reason(&self) -> &str {
        self.reason.get().map(String::as_str).unwrap_or("")
    }

    /// Resolves as soon as a stop has been asked for, and immediately if it
    /// already was. `Notify` keeps the permit, so a request that lands between
    /// the check and the await is not lost.
    pub async fn wait(&self) {
        if self.requested() {
            return;
        }
        self.wake.notified().await;
    }
}

static STOP: OnceLock<Stop> = OnceLock::new();

fn stop() -> &'static Stop {
    STOP.get_or_init(Stop::new)
}

/// Asks this process to stop serving and end cleanly.
pub fn request(reason: &str) -> bool {
    stop().request(reason)
}

pub fn requested() -> bool {
    stop().requested()
}

/// Why this process is stopping (empty while it is not).
pub fn reason() -> &'static str {
    stop().reason()
}

/// Waits for a stop request; used by the pipe server so an idle engine with no
/// client attached still ends the moment it is asked to.
pub async fn wait() {
    stop().wait().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fresh_stop_is_not_requested() {
        let stop = Stop::new();
        assert!(!stop.requested());
        assert_eq!(stop.reason(), "");
    }

    #[tokio::test]
    async fn the_first_reason_is_the_one_that_is_kept() {
        let stop = Stop::new();
        assert!(stop.request("the app asked (shutdown)"));
        assert!(!stop.request("the parent watch noticed something else"));
        assert_eq!(stop.reason(), "the app asked (shutdown)");
    }

    #[tokio::test]
    async fn waiting_resolves_when_a_stop_is_requested() {
        let stop = std::sync::Arc::new(Stop::new());
        let waiter = {
            let stop = stop.clone();
            tokio::spawn(async move { stop.wait().await })
        };
        // The waiter is parked on `Notify` before the request, which is the
        // live case: the pipe server sleeps here while no client is attached.
        tokio::task::yield_now().await;
        assert!(stop.request("a test"));
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("wait() must resolve once a stop was requested")
            .expect("the waiter task must not panic");
    }

    #[tokio::test]
    async fn waiting_after_a_request_returns_at_once() {
        let stop = Stop::new();
        assert!(stop.request("a test"));
        tokio::time::timeout(std::time::Duration::from_millis(100), stop.wait())
            .await
            .expect("a stop that already happened must not park the caller");
    }
}
