//! The one gate every alert goes through (D-013, D-024).
//!
//! Producers (the guard, the scanner, the firewall/IDS actions, the crash
//! reporter) do not talk to the toast layer directly: they call the helpers
//! below, so "does this reach the user, and where?" is answered in exactly one
//! place — the `toast_enabled` setting, do-not-disturb, and the event severity.
//! That also means the answer is a pure function and can be tested without a
//! desktop.
//!
//! Two destinations leave this module:
//!  * the **desktop card** (a Windows toast), gated by `toast_enabled`, DND and
//!    the severity class — unchanged since D-013; and
//!  * the **in-app card** the UI paints in the window's bottom corner (D-024),
//!    gated by DND alone. Every severity reaches it, `low` included: the desktop
//!    never shows `low`, and the app window is exactly where it belongs. Turning
//!    desktop notifications off leaves the in-app surface alone, so a user who
//!    silences Windows still sees that something happened.
//!
//! Copy is chosen by `settings.lang`, because the card is user-facing: the
//! engine writes it, but the reader is the person in front of the screen.

use crate::notify::toast;
use crate::settings;
use serde_json::{json, Value};
use std::sync::Mutex;

/// The JSON-RPC notification that carries one in-app card (D-024).
pub const CARD_METHOD: &str = "alert";

/// Severities the gate understands, worst first (used by the policy tests to
/// prove that no severity slips through an off switch).
#[cfg(test)]
pub const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// The desktop half of the policy, as a pure function.
///
/// * `toast_enabled` off = nothing ever reaches the desktop;
/// * do-not-disturb silences everything below CRITICAL;
/// * only CRITICAL/HIGH/MEDIUM are worth a desktop card — LOW stays in-app,
///   otherwise the desktop becomes the log file.
pub fn decide(severity: &str, toast_enabled: bool, dnd: bool) -> bool {
    if !toast_enabled {
        return false;
    }
    if dnd && severity != "critical" {
        return false;
    }
    matches!(severity, "critical" | "high" | "medium")
}

/// The in-app half of the policy, as a pure function (D-024).
///
/// Do-not-disturb means silent, and it means silent on both surfaces, so it is
/// the only switch that can hold a card back here. Everything else reaches the
/// app: a low-severity event has nowhere else to go, and `toast_enabled` is
/// about the desktop, not about the app. An event with no severity at all is a
/// producer bug, not a card.
pub fn decide_in_app(severity: &str, dnd: bool) -> bool {
    if severity.trim().is_empty() {
        return false;
    }
    !dnd || severity == "critical"
}

/// `decide` against the live settings document.
pub fn allowed(severity: &str) -> bool {
    let s = settings::current();
    decide(severity, s.toast_enabled, s.quiet())
}

/// True when desktop cards are switched on at all (Settings → Notifications).
pub fn enabled() -> bool {
    settings::current().toast_enabled
}

/// Shows a card when the policy allows it, on either destination.
///
/// The desktop answer is the return value; the in-app card is handed to the
/// connected surface (or parked until one connects). Returns `true` when a card
/// was handed to Windows, `false` when the desktop half was silenced. A platform
/// failure is logged with the real reason and is **not** reported as success — a
/// silent alert is the failure mode this module exists to prevent.
fn show(
    kind: &str,
    severity: &str,
    title: &str,
    body: &str,
    actions: &[&str],
    quarantine: Option<String>,
) -> bool {
    if decide_in_app(severity, settings::current().quiet()) {
        push(card(kind, severity, title, body));
    }
    if !allowed(severity) {
        tracing::debug!("alert suppressed ({severity}): {title}");
        return false;
    }
    match toast::show_toast_for_file(title, body, actions, quarantine) {
        Ok(()) => {
            tracing::info!("alert shown ({severity}): {title}");
            true
        }
        Err(e) => {
            tracing::warn!("alert FAILED ({severity}): {title}: {e:#}");
            false
        }
    }
}

// ---------- in-app cards (D-024) ----------

/// Cards that had nowhere to go yet.
///
/// An alert can be raised before a UI is attached: the `unclean-exit` report is
/// filed while the engine is still starting, and the UI connects to the pipe a
/// moment later. A card with no subscriber waits here instead of vanishing, and
/// is handed to the first transport that connects.
static PENDING: Mutex<Waiting> = Mutex::new(Waiting::new());

/// How many cards may wait. A card is a nudge, not a record — the event stream,
/// the incident list and the report files are the record — so a pile nobody
/// collected is dropped rather than replayed an hour later.
const PENDING_CAP: usize = 5;

/// The waiting list, small enough to be a plain vector.
struct Waiting {
    cards: Vec<Value>,
}

impl Waiting {
    const fn new() -> Self {
        Self { cards: Vec::new() }
    }

    /// Parks one card, dropping the oldest when the list is full.
    fn park(&mut self, card: Value) {
        if self.cards.len() >= PENDING_CAP {
            self.cards.remove(0);
        }
        self.cards.push(card);
    }

    /// Hands the whole list over; a card is delivered once.
    fn take(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.cards)
    }
}

/// One card, in the shape the UI renders (`lib/models/alert_card.dart`).
///
/// `kind` is the producer class (`guard`, `canary`, `scan`, `quarantine`,
/// `protection`, `crash`) and it is also how the UI knows where a tap goes.
fn card(kind: &str, severity: &str, title: &str, body: &str) -> Value {
    json!({
        "kind": kind,
        "severity": severity,
        "title": title,
        "body": body,
    })
}

/// Hands a card to the connected transports, or parks it for the first one.
fn push(card: Value) {
    if crate::jobs::has_subscribers() {
        crate::jobs::notify(CARD_METHOD, card);
        return;
    }
    match PENDING.lock() {
        Ok(mut waiting) => waiting.park(card),
        // A poisoned lock must not turn "the UI missed a card" into a panic in
        // the middle of an alert.
        Err(_) => tracing::warn!("in-app alert queue is poisoned: card dropped"),
    }
}

/// The cards a transport that has just connected has not seen yet.
pub fn take_pending() -> Vec<Value> {
    PENDING
        .lock()
        .map(|mut waiting| waiting.take())
        .unwrap_or_default()
}

/// A card that names one detected file and really quarantines it on tap.
/// `severity` is the finding's own severity, so DND still decides correctly.
pub fn threat(severity: &str, path: &str, reason: &str) -> bool {
    show(
        "scan",
        severity,
        text("scan.threat.title"),
        &format!("{path} — {reason}"),
        &[text("scan.threat.action"), text("guard.action.open")],
        Some(path.to_string()),
    )
}

/// One card for a scan that found more than it alerted on individually.
pub fn threats_summary(count: usize) -> bool {
    show(
        "scan",
        "high",
        &fill(text("scan.summary.title"), "{n}", &count.to_string()),
        text("scan.summary.body"),
        &[text("guard.action.open")],
        None,
    )
}

/// Confirmation that a batch was really put in quarantine.
pub fn quarantined(count: usize) -> bool {
    show(
        "quarantine",
        "high",
        &fill(text("scan.quarantined.title"), "{n}", &count.to_string()),
        text("scan.quarantined.body"),
        &[text("guard.action.open")],
        None,
    )
}

/// A protection action the product performed (firewall rule, default deny,
/// hosts blocklist). `detail` is technical data, not copy.
pub fn protection(action: &str, detail: &str) -> bool {
    show(
        "protection",
        "medium",
        text("protect.blocked.title"),
        &format!("{action} — {detail}"),
        &[text("guard.action.open")],
        None,
    )
}

/// The package's files are not the ones this build shipped with (ج2, D-025).
///
/// Raised once at startup, and only for a copy that *carries* a manifest: a
/// developer build has none, and telling every developer that their own build is
/// unofficial would be noise rather than a warning. `detail` names what failed,
/// so the card says which file moved instead of only that something did.
pub fn package_changed(detail: &str) -> bool {
    show(
        "integrity",
        "high",
        text("integrity.title"),
        &format!("{detail} — {}", text("integrity.body")),
        &[text("guard.action.open")],
        None,
    )
}

/// Routes a guard event: CRITICAL/HIGH/MEDIUM become desktop cards, LOW does
/// not — and every one of them becomes an in-app card unless DND is on.
pub fn guard_event(ev: &crate::guard::GuardEvent) {
    let canary = ev.r#type == "canary_triggered";
    let title = if canary {
        text("guard.canary.title")
    } else {
        text("guard.suspicious.title")
    };
    let body = if canary {
        ev.detail.clone()
    } else {
        format!("{} — {}", ev.process, ev.rule_name)
    };
    let actions = [text("guard.action.open")];
    show(
        if canary { "canary" } else { "guard" },
        &ev.severity,
        title,
        &body,
        &actions,
        None,
    );
}

/// A report was filed: the one alert that is not a security event (D-024).
///
/// The bug id travels as its own field, because it is the point of the card —
/// it is what a user reads out to whoever supports the build. Nothing here says
/// the report *was delivered*: no report has a delivery state until ز2-د, and
/// the UI's own line says delivery is off. `report_kind` is the engine's own
/// (`panic`, `unclean-exit`, `hang`) and only picks the icon.
///
/// Best effort by nature: the engine is already failing when it writes one, so
/// a card raised by the panic hook may not outlive the abort. The reliable
/// record stays the bundle on disk, which `crash.list` reads back.
pub fn report_filed(bug_id: &str, report_kind: &str, message: &str) {
    if !decide_in_app("critical", settings::current().quiet()) {
        return;
    }
    let mut card = card("crash", "critical", text("crash.card.title"), message);
    card["bug_id"] = json!(bug_id);
    card["report_kind"] = json!(report_kind);
    push(card);
}

// ---------- copy (ar/en) ----------

/// (Arabic, English) for every string the engine puts on a card, so the alert
/// follows the language the user picked instead of always shouting in English.
const COPY: &[(&str, &str, &str)] = &[
    ("guard.suspicious.title", "🛡️ MI CS — نشاط مشبوه", "🛡️ MI CS — Suspicious activity"),
    ("guard.canary.title", "🥚 MI CS — ملف الطُعم اتغيّر!", "🥚 MI CS — Canary file modified!"),
    ("guard.action.open", "افتح MI CS", "Open MI CS"),
    ("scan.threat.title", "🛡️ MI CS — لقينا تهديد", "🛡️ MI CS — Threat found"),
    ("scan.threat.action", "اعزل الملف", "Quarantine"),
    (
        "scan.summary.title",
        "🛡️ MI CS — {n} ملفات مشبوهة",
        "🛡️ MI CS — {n} suspicious files",
    ),
    (
        "scan.summary.body",
        "افتح MI CS عشان تشوف التفاصيل وتتعامل معاها.",
        "Open MI CS to review them and act.",
    ),
    (
        "scan.quarantined.title",
        "🔒 MI CS — اتعزل {n} ملف",
        "🔒 MI CS — {n} files quarantined",
    ),
    (
        "scan.quarantined.body",
        "الملفات محفوظة في الحجر وممكن ترجّعها في أي وقت.",
        "The files are in quarantine and can be restored at any time.",
    ),
    (
        "protect.blocked.title",
        "🚫 MI CS — الحماية اتحركت",
        "🚫 MI CS — Protection applied",
    ),
    (
        "crash.card.title",
        "🧯 MI CS — المحرك سجّل تقرير انهيار",
        "🧯 MI CS — the engine filed a crash report",
    ),
    (
        "integrity.title",
        "🚨 MI CS — الملفات دي مش النسخة اللي اتنشرت",
        "🚨 MI CS — these files are not the published build",
    ),
    (
        "integrity.body",
        "المحرك قرا المانيفست الموقّع بتاعه ولقى فرق. نزّل النسخة من المصدر الرسمي تاني.",
        "The engine read its own signed manifest and found a difference. Download the build again from the official source.",
    ),
    (
        "test.title",
        "🛡️ MI CS — إشعار تجريبي",
        "🛡️ MI CS — test notification",
    ),
    (
        "test.body",
        "الإشعارات شغالة. ده شكل كارت تنبيه HIGH.",
        "Notifications are working. This is what a HIGH alert looks like.",
    ),
];

/// The card text for the current language (a static fallback when the key is
/// unknown — [`tests::every_copy_key_exists_in_both_languages`] pins the keys
/// the producers actually use, so the fallback is a safety net, not a path).
pub fn text(key: &str) -> &'static str {
    let lang = settings::current().lang;
    COPY.iter()
        .find(|(k, ..)| *k == key)
        .map(|(_, ar, en)| if lang == "ar" { *ar } else { *en })
        .unwrap_or("MI CS")
}

fn fill(template: &str, placeholder: &str, value: &str) -> String {
    template.replace(placeholder, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnd_only_lets_critical_through() {
        assert!(decide("critical", true, true));
        assert!(!decide("high", true, true));
        assert!(!decide("medium", true, true));
        assert!(!decide("low", true, true));
    }

    #[test]
    fn disabled_cards_silence_everything() {
        for severity in SEVERITIES {
            assert!(!decide(severity, false, false), "{severity} leaked through");
            assert!(!decide(severity, false, true));
        }
    }

    #[test]
    fn low_severity_stays_in_app() {
        assert!(decide("critical", true, false));
        assert!(decide("high", true, false));
        assert!(decide("medium", true, false));
        assert!(!decide("low", true, false));
        assert!(!decide("unknown", true, false));
        assert!(!decide("", true, false));
    }

    #[test]
    fn every_copy_key_exists_in_both_languages() {
        for (key, ar, en) in COPY {
            assert!(!ar.trim().is_empty(), "{key} has no Arabic");
            assert!(!en.trim().is_empty(), "{key} has no English");
        }
        // The producers reference these keys; a typo would silently ship the
        // raw key to the desktop.
        for key in [
            "guard.suspicious.title",
            "guard.canary.title",
            "guard.action.open",
            "scan.threat.title",
            "scan.threat.action",
            "scan.summary.title",
            "scan.summary.body",
            "scan.quarantined.title",
            "scan.quarantined.body",
            "protect.blocked.title",
            "crash.card.title",
            "integrity.title",
            "integrity.body",
            "test.title",
            "test.body",
        ] {
            assert!(COPY.iter().any(|(k, ..)| *k == key), "missing copy: {key}");
        }
    }

    #[test]
    fn the_app_shows_every_severity_the_desktop_refuses() {
        // D-024: the app is the surface a silenced desktop falls back to, and it
        // is the only surface a LOW event has. `toast_enabled` is not consulted
        // here at all - it is the desktop's switch.
        for severity in SEVERITIES {
            assert!(
                decide_in_app(severity, false),
                "{severity} has nowhere to go"
            );
        }
        assert!(decide_in_app("low", false));
        assert!(decide_in_app("medium", false));
    }

    #[test]
    fn dnd_silences_the_app_below_critical() {
        // "Do not disturb" promises silence; that promise is not desktop-only.
        assert!(decide_in_app("critical", true));
        assert!(!decide_in_app("high", true));
        assert!(!decide_in_app("medium", true));
        assert!(!decide_in_app("low", true));
    }

    #[test]
    fn a_severityless_event_is_not_a_card() {
        assert!(!decide_in_app("", false));
        assert!(!decide_in_app("   ", false));
    }

    #[test]
    fn a_card_with_no_transport_waits_and_is_handed_over_once() {
        // Pure: this never touches the process-wide waiting list, which the
        // crash tests also file into.
        let mut waiting = Waiting::new();
        for n in 0..PENDING_CAP + 2 {
            waiting.park(json!({"n": n}));
        }
        let taken = waiting.take();
        assert_eq!(taken.len(), PENDING_CAP, "the list grew past its cap");
        assert_eq!(
            taken[0]["n"],
            json!(2),
            "the oldest card is the one dropped"
        );
        assert!(waiting.take().is_empty(), "a card is delivered once");
    }

    #[test]
    fn a_crash_card_carries_the_bug_id_as_data() {
        let card = card("crash", "critical", "title", "body");
        assert_eq!(card["kind"], json!("crash"));
        assert_eq!(card["severity"], json!("critical"));
        assert!(
            card.get("bug_id").is_none(),
            "only a filed report has a bug id"
        );
        // The id reaches the JSON as its own field, never inside a sentence.
        let mut filed = card;
        filed["bug_id"] = json!("MICS-20261102-0d9743");
        filed["report_kind"] = json!("hang");
        assert_eq!(filed["bug_id"], json!("MICS-20261102-0d9743"));
        assert_eq!(filed["report_kind"], json!("hang"));
    }

    #[test]
    fn placeholders_are_filled() {
        assert_eq!(fill("🛡️ {n} files", "{n}", "3"), "🛡️ 3 files");
    }
}
