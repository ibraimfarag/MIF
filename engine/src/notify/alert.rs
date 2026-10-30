//! The one gate every desktop alert goes through (D-013).
//!
//! Producers (the guard, the scanner, the firewall/IDS actions) do not talk to
//! the toast layer directly: they call the helpers below, so "does this reach
//! the desktop?" is answered in exactly one place — the `toast_enabled`
//! setting, do-not-disturb, and the event severity. That also means the answer
//! is a pure function and can be tested without a desktop.
//!
//! Copy is chosen by `settings.lang`, because the card is user-facing: the
//! engine writes it, but the reader is the person in front of the screen.

use crate::notify::toast;
use crate::settings;

/// Severities the gate understands, worst first (used by the policy tests to
/// prove that no severity slips through an off switch).
#[cfg(test)]
pub const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// The whole policy, as a pure function.
///
/// * `toast_enabled` off = nothing ever reaches the desktop;
/// * do-not-disturb silences everything below CRITICAL;
/// * only CRITICAL/HIGH/MEDIUM are worth a card — LOW stays in-app, otherwise
///   the desktop becomes the log file.
pub fn decide(severity: &str, toast_enabled: bool, dnd: bool) -> bool {
    if !toast_enabled {
        return false;
    }
    if dnd && severity != "critical" {
        return false;
    }
    matches!(severity, "critical" | "high" | "medium")
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

/// Shows a card when the policy allows it.
///
/// Returns `true` when a card was handed to Windows, `false` when the policy
/// silenced it. A platform failure is logged with the real reason and is
/// **not** reported as success — a silent alert is the failure mode this module
/// exists to prevent.
pub fn show(
    severity: &str,
    title: &str,
    body: &str,
    actions: &[&str],
    quarantine: Option<String>,
) -> bool {
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

/// A card that names one detected file and really quarantines it on tap.
/// `severity` is the finding's own severity, so DND still decides correctly.
pub fn threat(severity: &str, path: &str, reason: &str) -> bool {
    show(
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
        "medium",
        text("protect.blocked.title"),
        &format!("{action} — {detail}"),
        &[text("guard.action.open")],
        None,
    )
}

/// Routes a guard event: CRITICAL/HIGH/MEDIUM become cards, LOW does not.
pub fn guard_event(ev: &crate::guard::GuardEvent) {
    if !allowed(&ev.severity) {
        return;
    }
    let title = if ev.r#type == "canary_triggered" {
        text("guard.canary.title")
    } else {
        text("guard.suspicious.title")
    };
    let body = if ev.r#type == "canary_triggered" {
        ev.detail.clone()
    } else {
        format!("{} — {}", ev.process, ev.rule_name)
    };
    let actions = [text("guard.action.open")];
    show(&ev.severity, title, &body, &actions, None);
}

// ---------- copy (ar/en) ----------

/// (Arabic, English) for every string the engine puts on a card, so the alert
/// follows the language the user picked instead of always shouting in English.
const COPY: &[(&str, &str, &str)] = &[
    ("guard.suspicious.title", "🛡️ MI CS — نشاط مشبوه", "🛡️ MI CS — Suspicious activity"),
    ("guard.canary.title", "🥚 MI CS — ملف الطُعم اتحرك!", "🥚 MI CS — Canary touched!"),
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
            "test.title",
            "test.body",
        ] {
            assert!(COPY.iter().any(|(k, ..)| *k == key), "missing copy: {key}");
        }
    }

    #[test]
    fn placeholders_are_filled() {
        assert_eq!(fill("🛡️ {n} files", "{n}", "3"), "🛡️ 3 files");
    }
}
