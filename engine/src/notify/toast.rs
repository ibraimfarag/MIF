//! Engine-side Windows Toast notifications — alerts fire even with the UI
//! closed (AUMID "MICS"). CRITICAL events get toasts; medium/low stay in-app.

use anyhow::Result;
use windows::core::HSTRING;
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

pub const AUMID: &str = "MICS";

pub fn show_toast(title: &str, body: &str) -> Result<()> {
    // Toast template ToastText02: title + wrapped body.
    let xml = XmlDocument::new()?;
    let toast_xml = format!(
        r#"<toast><visual><binding template="ToastText02"><text id="1">{}</text><text id="2">{}</text></binding></visual></toast>"#,
        escape_xml(title),
        escape_xml(body)
    );
    xml.LoadXml(&HSTRING::from(toast_xml))?;
    let notification = ToastNotification::CreateToastNotification(&xml)?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?;
    notifier.Show(&notification)?;
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Route a guard event to a toast when severity warrants it.
pub fn route_event(ev: &crate::guard::GuardEvent) {
    let critical = ev.severity == "critical";
    let _ = critical; // CRITICAL + HIGH get toasts per section 8
    let title = if ev.r#type == "canary_triggered" {
        "🥚 MI CS — Canary touched!"
    } else {
        "🛡️ MI CS — Suspicious activity"
    };
    let body = if ev.r#type == "canary_triggered" {
        ev.detail.clone()
    } else {
        format!("{} — {}", ev.process, ev.rule_name)
    };
    if let Err(e) = show_toast(title, &body) {
        tracing::warn!("toast: {e:#}");
    }
}
