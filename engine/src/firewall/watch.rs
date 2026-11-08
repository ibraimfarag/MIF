//! The tamper watch (D-044): our sublayer and our filters are **persistent**
//! objects in the filtering engine's own store.
//!
//! That persistence is the whole point of D-042 — a block outlives MI CS — and it
//! is also the opening: anything holding an administrator token can delete our
//! sublayer, one filter, or all of them, and the machine would go on reporting
//! "protected" while nothing was being enforced. This module is the part that
//! notices.
//!
//! The shape is deliberately small:
//!
//! * a **record** of what MI CS wrote (filter names, and whether the sublayer was
//!   created), kept in the database's `meta` table next to everything else;
//! * a **comparison** against what the filtering engine holds right now, which is
//!   pure and therefore testable without touching a machine;
//! * one **event** when something we recorded is gone — the same guard event path
//!   as the canaries and the rule engine, so it lands in the incidents list, in
//!   the desktop card and in the correlator without a surface of its own.
//!
//! What it does **not** claim:
//!
//! * It cannot see a delete-and-re-add that happens between two polls. The guard
//!   thread polls every 30 s, so that window is real and is written down rather
//!   than hidden.
//! * It cannot read the BFE from an unelevated engine: reading it is a
//!   privileged call too (measured in D-042). With no helper to ask, the answer
//!   is `unknown` — never "everything is fine" and never a false alarm.
//! * It does not restore anything. Noticing is the deliverable; the fix is the
//!   user's click on the block (or `fw.wfp.reset`, which clears the record too).
//!
//! Two test hooks make the detector measurable without an administrator
//! (docs/TODO.md section 8): [`SEED_ENV`] gives it a record to believe, and
//! [`LIVE_ENV`] gives it a status to compare that record against, so the compare
//! and the alert can be measured end to end on an unelevated machine while the
//! machine-reading half stays honestly marked.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::firewall::wfp::WfpStatus;
use crate::storage::sqlite::Storage;

/// Where the record lives, in the database's `meta` table.
pub const META_KEY: &str = "wfp_baseline";

/// Test hook: filter names to believe in when the record is empty, separated by
/// `;` (a leading `!sublayer` says "no sublayer was created"). Only read when
/// there is no record, so a real machine's own history is never overwritten.
pub const SEED_ENV: &str = "MICS_WFP_WATCH_SEED";

/// Test hook: a `WfpStatus` as JSON to compare the record against, instead of
/// reading the machine. The report says so in its `detail`, so an injected
/// answer can never be mistaken for a measured one.
pub const LIVE_ENV: &str = "MICS_WFP_WATCH_LIVE";

/// What MI CS wrote and expects to still be there.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// Whether MI CS' sublayer was created on this machine.
    #[serde(default)]
    pub sublayer: bool,
    /// The display names of the filters MI CS added, sorted and deduplicated.
    #[serde(default)]
    pub names: Vec<String>,
}

/// What the last look found. `unknown` is a first-class answer: it is what an
/// unelevated engine with no helper can honestly say, and it is not a tamper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchState {
    /// Nothing was ever recorded, so there is nothing to protect yet.
    Clear,
    /// The machine holds filters of ours with no record beside them (an older
    /// build, or a record that was lost). Worth a line, not an alarm.
    Unrecorded,
    /// Everything recorded is still there.
    Guarded,
    /// Something recorded is gone: the sublayer, a filter, or both.
    Tampered,
    /// The filtering engine refused this process and no helper answered, so
    /// what is on the machine is unknown.
    Unknown,
}

/// One look at the machine, judged against the record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReport {
    pub state: WatchState,
    /// How many filters the record claims.
    pub recorded: usize,
    /// How many the machine (or the injected status) listed.
    pub live: usize,
    /// Recorded filters the machine does not have.
    pub missing: Vec<String>,
    /// Filters the machine has that the record does not know about.
    pub extra: Vec<String>,
    /// Whether the machine's sublayer is there.
    pub sublayer: bool,
    pub needs_elevation: bool,
    /// The sentence a user reads: what is wrong, or why nothing can be said.
    pub detail: String,
    pub at: i64,
    /// When this process last raised the alert for this exact state, 0 if never.
    pub alerted_at: i64,
}

/// What the last alert said, so the same finding does not repeat every 30 s.
static LAST_ALERT: Mutex<Option<String>> = Mutex::new(None);
static LAST_ALERT_AT: AtomicI64 = AtomicI64::new(0);

/// The signature of a tamper: what is gone, so a *different* loss alerts again
/// while the same one stays quiet.
fn signature(report: &WatchReport) -> String {
    let mut parts = Vec::new();
    if !report.sublayer {
        parts.push("sublayer".to_string());
    }
    parts.extend(report.missing.iter().cloned());
    parts.join("|")
}

/// Whether this report should raise an alert, given what was last alerted.
///
/// Pure, so "one alert per change, never for `unknown`" is a unit test instead
/// of a promise.
pub fn should_alert(report: &WatchReport, last: Option<&str>) -> Option<String> {
    if report.state != WatchState::Tampered {
        return None;
    }
    let sig = signature(report);
    if sig.is_empty() || last == Some(sig.as_str()) {
        return None;
    }
    Some(sig)
}

/// Judges a record against a status. Pure: the machine is not involved, so every
/// branch below is measurable without an administrator.
pub fn verdict(baseline: &Baseline, live: &WfpStatus) -> WatchReport {
    let known: BTreeSet<&str> = baseline.names.iter().map(String::as_str).collect();
    let present: BTreeSet<&str> = live.names.iter().map(String::as_str).collect();
    let missing: Vec<String> = baseline
        .names
        .iter()
        .filter(|n| !present.contains(n.as_str()))
        .cloned()
        .collect();
    let extra: Vec<String> = live
        .names
        .iter()
        .filter(|n| !known.contains(n.as_str()))
        .cloned()
        .collect();
    let sublayer_gone = baseline.sublayer && !live.sublayer;
    let recorded = baseline.names.len();

    let (state, detail) = if live.needs_elevation {
        (
            WatchState::Unknown,
            format!(
                "the filtering engine refused this process and the helper could not read it \
                 either, so what the machine holds is unknown, not empty: {}",
                live.detail
            ),
        )
    } else if recorded == 0 && !baseline.sublayer {
        if live.filters == 0 {
            (
                WatchState::Clear,
                "MI CS has not written a filter on this machine yet, so there is nothing to watch"
                    .to_string(),
            )
        } else {
            (
                WatchState::Unrecorded,
                format!(
                    "{} filter(s) carry MI CS' provider and no record of them is kept — written by \
                     an older build, or the record was lost",
                    live.filters
                ),
            )
        }
    } else if missing.is_empty() && !sublayer_gone {
        (
            WatchState::Guarded,
            format!(
                "the MI CS sublayer and all {recorded} recorded filter(s) are still on the machine"
            ),
        )
    } else {
        (WatchState::Tampered, tamper_detail(sublayer_gone, &missing, recorded))
    };

    WatchReport {
        state,
        recorded,
        live: live.filters,
        missing,
        extra,
        sublayer: live.sublayer,
        needs_elevation: live.needs_elevation,
        detail,
        at: chrono::Utc::now().timestamp(),
        alerted_at: LAST_ALERT_AT.load(Ordering::SeqCst),
    }
}

/// The sentence for a tamper, in the order a reader needs it: what is gone.
fn tamper_detail(sublayer_gone: bool, missing: &[String], recorded: usize) -> String {
    let sublayer = if sublayer_gone {
        "the MI CS sublayer is gone"
    } else {
        ""
    };
    let filters = if missing.is_empty() {
        String::new()
    } else {
        format!(
            "{} of {recorded} recorded filter(s) are missing: {}",
            missing.len(),
            missing.join(", ")
        )
    };
    let both = match (sublayer.is_empty(), filters.is_empty()) {
        (false, false) => " and ",
        _ => "",
    };
    format!(
        "{sublayer}{both}{filters} — a block MI CS wrote is no longer enforced"
    )
}

/// Reads the record. The seed hook only ever fills an empty record, so a machine
/// that has written filters of its own is never overwritten by a test.
pub fn load() -> Result<Baseline> {
    let storage = Storage::open()?;
    let mut baseline = load_at(&storage)?;
    if baseline.names.is_empty()
        && !baseline.sublayer
        && let Some(seeded) = seeded_baseline(std::env::var(SEED_ENV).ok().as_deref())
    {
        info!(
            "{SEED_ENV} is set: the watch believes in {} filter(s) it did not write",
            seeded.names.len()
        );
        save_at(&storage, &seeded)?;
        baseline = seeded;
    }
    Ok(baseline)
}

pub fn load_at(storage: &Storage) -> Result<Baseline> {
    let raw = storage.meta_get(META_KEY)?;
    match raw {
        Some(text) if !text.trim().is_empty() => {
            serde_json::from_str(&text).context("the WFP record in the database is not readable")
        }
        _ => Ok(Baseline::default()),
    }
}

pub fn save_at(storage: &Storage, baseline: &Baseline) -> Result<()> {
    let text = serde_json::to_string(baseline).context("serialising the WFP record")?;
    storage.meta_set(META_KEY, &text)
}

/// The seed hook's parser, pure so it can be tested without setting an
/// environment variable in a parallel test run.
pub fn seeded_baseline(seed: Option<&str>) -> Option<Baseline> {
    let seed = seed?.trim();
    if seed.is_empty() {
        return None;
    }
    let mut baseline = Baseline {
        sublayer: true,
        names: Vec::new(),
    };
    for part in seed.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        if part == "!sublayer" {
            baseline.sublayer = false;
        } else {
            baseline.names.push(part.to_string());
        }
    }
    baseline.names.sort();
    baseline.names.dedup();
    Some(baseline)
}

/// Remembers one filter MI CS just wrote. Called after a successful block, so
/// the record and the machine move together.
pub fn remember(name: &str) -> Result<()> {
    let storage = Storage::open()?;
    let mut baseline = load_at(&storage)?;
    if !baseline.names.iter().any(|n| n == name) {
        baseline.names.push(name.to_string());
        baseline.names.sort();
    }
    baseline.sublayer = true;
    save_at(&storage, &baseline)
}

/// Forgets one filter MI CS removed on purpose.
pub fn forget(name: &str) -> Result<()> {
    let storage = Storage::open()?;
    let mut baseline = load_at(&storage)?;
    baseline.names.retain(|n| n != name);
    save_at(&storage, &baseline)
}

/// Forgets everything: what `fw.wfp.reset` means, and what stops the watch from
/// calling our own cleanup a tamper.
pub fn forget_all() -> Result<()> {
    let storage = Storage::open()?;
    save_at(&storage, &Baseline::default())
}

/// What the machine holds, or the injected status when the hook is set.
fn live_status() -> Result<(WfpStatus, bool)> {
    if let Ok(raw) = std::env::var(LIVE_ENV) {
        let mut status: WfpStatus = serde_json::from_str(&raw)
            .with_context(|| format!("{LIVE_ENV} is not a status MI CS can read"))?;
        status.detail = format!(
            "{} (status injected by {LIVE_ENV}: this is a test hook, not the machine)",
            status.detail
        );
        return Ok((status, true));
    }
    Ok((crate::firewall::wfp::status_blocking()?, false))
}

/// Looks once, and raises the alert when something recorded is gone.
pub fn poll() -> Result<WatchReport> {
    let baseline = load()?;
    let (live, injected) = live_status()?;
    let mut report = verdict(&baseline, &live);

    let last = LAST_ALERT.lock().ok().and_then(|l| l.clone());
    match should_alert(&report, last.as_deref()) {
        Some(sig) => {
            report.alerted_at = report.at;
            LAST_ALERT_AT.store(report.at, Ordering::SeqCst);
            if let Ok(mut l) = LAST_ALERT.lock() {
                *l = Some(sig);
            }
            warn!(
                "WFP tamper: {}{}",
                report.detail,
                if injected { " [injected status]" } else { "" }
            );
            crate::guard::emit_public(crate::guard::GuardEvent {
                r#type: "wfp_tamper".into(),
                severity: "high".into(),
                rule_id: "wfp.tamper".into(),
                rule_name: "MI CS filtering layer".into(),
                pid: 0,
                process: "MI CS".into(),
                parent: "MI CS".into(),
                detail: report.detail.clone(),
                at: report.at,
            });
        }
        None => {
            // A quiet look is not silence: the log keeps the state, so a session
            // that finds the layer intact can be told apart from one that never
            // looked.
            info!(
                "WFP watch: state={:?} recorded={} live={} missing={}",
                report.state,
                report.recorded,
                report.live,
                report.missing.len()
            );
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(sublayer: bool, names: &[&str]) -> WfpStatus {
        WfpStatus {
            sublayer,
            filters: names.len(),
            names: names.iter().map(|n| n.to_string()).collect(),
            needs_elevation: false,
            detail: String::new(),
        }
    }

    fn unknown() -> WfpStatus {
        WfpStatus {
            sublayer: false,
            filters: 0,
            names: Vec::new(),
            needs_elevation: true,
            detail: "adding the MI CS sublayer needs an administrator".into(),
        }
    }

    fn baseline(names: &[&str]) -> Baseline {
        Baseline {
            sublayer: true,
            names: names.iter().map(|n| n.to_string()).collect(),
        }
    }

    #[test]
    fn a_recorded_filter_that_vanished_is_a_tamper() {
        let report = verdict(
            &baseline(&["MICS-a", "MICS-b"]),
            &status(true, &["MICS-a", "MICS-elsewhere"]),
        );
        assert_eq!(report.state, WatchState::Tampered);
        assert_eq!(report.missing, vec!["MICS-b".to_string()]);
        assert_eq!(report.extra, vec!["MICS-elsewhere".to_string()]);
        assert!(
            report.detail.contains("MICS-b"),
            "the sentence must name what is gone: {}",
            report.detail
        );
    }

    #[test]
    fn a_sublayer_that_vanished_is_a_tamper_with_every_filter_still_there() {
        let report = verdict(&baseline(&["MICS-a"]), &status(false, &["MICS-a"]));
        assert_eq!(report.state, WatchState::Tampered);
        assert!(report.missing.is_empty());
        assert!(
            report.detail.contains("sublayer"),
            "the sublayer is the part that makes our block outrank the default: {}",
            report.detail
        );
    }

    #[test]
    fn everything_recorded_still_being_there_is_guarded() {
        let report = verdict(&baseline(&["MICS-a", "MICS-b"]), &status(true, &["MICS-b", "MICS-a"]));
        assert_eq!(report.state, WatchState::Guarded);
        assert_eq!(report.missing.len(), 0);
        assert!(report.detail.contains("2 recorded filter"));
    }

    #[test]
    fn an_unreadable_machine_is_unknown_and_never_a_tamper() {
        // The record claims two filters; an unelevated engine with no helper
        // cannot see any of them. That is not evidence of deletion.
        let report = verdict(&baseline(&["MICS-a", "MICS-b"]), &unknown());
        assert_eq!(report.state, WatchState::Unknown);
        assert!(report.needs_elevation);
        assert!(
            report.detail.contains("is unknown, not empty"),
            "an unknown state has to say why it is unknown: {}",
            report.detail
        );
        assert!(
            report.detail.contains("needs an administrator"),
            "the helper's own refusal is the reason, not a guess: {}",
            report.detail
        );
    }

    #[test]
    fn an_empty_record_is_clear_and_a_machine_with_filters_is_unrecorded() {
        let clear = verdict(&Baseline::default(), &status(false, &[]));
        assert_eq!(clear.state, WatchState::Clear);
        let unrecorded = verdict(&Baseline::default(), &status(true, &["MICS-old"]));
        assert_eq!(unrecorded.state, WatchState::Unrecorded);
        assert_eq!(unrecorded.extra, vec!["MICS-old".to_string()]);
    }

    #[test]
    fn a_filter_nobody_recorded_is_not_a_tamper() {
        let report = verdict(&baseline(&["MICS-a"]), &status(true, &["MICS-a", "MICS-other"]));
        assert_eq!(report.state, WatchState::Guarded);
        assert_eq!(report.extra, vec!["MICS-other".to_string()]);
    }

    #[test]
    fn the_alert_fires_once_per_change_and_never_for_unknown() {
        let tamper = verdict(&baseline(&["MICS-a", "MICS-b"]), &status(true, &[]));
        let sig = should_alert(&tamper, None).expect("a fresh tamper alerts");
        assert!(
            should_alert(&tamper, Some(&sig)).is_none(),
            "the same loss must not alert again on the next poll"
        );
        let other = verdict(&baseline(&["MICS-a", "MICS-b"]), &status(true, &["MICS-b"]));
        assert!(
            should_alert(&other, Some(&sig)).is_some(),
            "a different loss is news"
        );
        let blind = verdict(&baseline(&["MICS-a"]), &unknown());
        assert!(should_alert(&blind, None).is_none());
    }

    #[test]
    fn the_seed_hook_parses_a_record_it_was_given() {
        let seeded = seeded_baseline(Some("MICS-b; MICS-a ;MICS-a")).expect("a seed");
        assert_eq!(seeded.names, vec!["MICS-a".to_string(), "MICS-b".to_string()]);
        assert!(seeded.sublayer);
        let no_sublayer = seeded_baseline(Some("!sublayer;MICS-x")).expect("a seed");
        assert!(!no_sublayer.sublayer);
        assert!(seeded_baseline(Some("   ")).is_none());
        assert!(seeded_baseline(None).is_none());
    }

    #[test]
    fn the_record_round_trips_through_the_database() {
        let dir = std::env::temp_dir().join(format!("mics-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let storage = Storage::open_at(&dir.join("mics.db")).expect("throwaway database");

        assert_eq!(load_at(&storage).expect("empty"), Baseline::default());

        let written = Baseline {
            sublayer: true,
            names: vec!["MICS-a".into(), "MICS-b".into()],
        };
        save_at(&storage, &written).expect("save");
        assert_eq!(load_at(&storage).expect("load"), written);

        // Forgetting one leaves the other, and forgetting everything empties the
        // record the way `fw.wfp.reset` has to.
        save_at(
            &storage,
            &Baseline {
                sublayer: true,
                names: vec!["MICS-b".into()],
            },
        )
        .expect("save");
        assert_eq!(load_at(&storage).expect("load").names, vec!["MICS-b".to_string()]);
        save_at(&storage, &Baseline::default()).expect("clear");
        assert!(load_at(&storage).expect("load").names.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_tamper_sentence_names_both_losses_when_both_happened() {
        let report = verdict(&baseline(&["MICS-a"]), &status(false, &[]));
        assert_eq!(report.state, WatchState::Tampered);
        assert!(
            report.detail.contains("sublayer") && report.detail.contains("MICS-a"),
            "one sentence has to carry both: {}",
            report.detail
        );
    }
}
