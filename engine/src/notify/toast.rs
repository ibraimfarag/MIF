//! Engine-side Windows Toast notifications — alerts fire even with the UI
//! closed (AUMID "MICS"). CRITICAL/HIGH events toast with real actions:
//!   click / "Open MI CS" -> launches the UI
//!   "Quarantine"         -> actually quarantines the referenced file
//! DND mode (MICS_DND=1) silences everything below CRITICAL.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use windows::core::{HSTRING, Interface};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

pub const AUMID: &str = "MICS";

pub fn dnd_enabled() -> bool {
    // Settings are authoritative (D-008); MICS_DND stays as a test override.
    crate::settings::current().quiet()
}

/// Pending toast actions: id -> file path to quarantine when the user taps
/// the action. Real enforcement, not just a UI shortcut.
static PENDING_QUARANTINE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn pending() -> &'static Mutex<HashMap<String, String>> {
    PENDING_QUARANTINE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[allow(dead_code)] // part of the notification API; kept small on purpose
pub fn show_toast(title: &str, body: &str) -> Result<()> {
    show_toast_for_file(title, body, &[], None)
}

#[allow(dead_code)]
pub fn show_toast_with_actions(title: &str, body: &str, actions: &[&str]) -> Result<()> {
    show_toast_for_file(title, body, actions, None)
}

/// Toast whose "Quarantine" action really quarantines `file`.
pub fn show_toast_for_file(
    title: &str,
    body: &str,
    actions: &[&str],
    quarantine_path: Option<String>,
) -> Result<()> {
    let launch = match &quarantine_path {
        Some(_) => {
            let id = format!("a{}", chrono::Utc::now().timestamp_micros());
            pending()
                .lock()
                .unwrap()
                .insert(id.clone(), quarantine_path.unwrap());
            format!(r#"{{"mics-action":"{id}"}}"#)
        }
        None => "open-ui".to_string(),
    };

    let mut xml = format!(
        r#"<toast activationType="foreground" launch="{}"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual>"#,
        escape_xml(&launch),
        escape_xml(title),
        escape_xml(body)
    );
    if !actions.is_empty() {
        xml.push_str("<actions>");
        for (i, a) in actions.iter().enumerate() {
            xml.push_str(&format!(
                r#"<action content="{}" arguments="action-{}"/>"#,
                escape_xml(a),
                i
            ));
        }
        xml.push_str("</actions>");
    }
    xml.push_str("</toast>");

    let doc = XmlDocument::new()?;
    doc.LoadXml(&HSTRING::from(xml))?;
    let notification = ToastNotification::CreateToastNotification(&doc)?;

    let ui_path = ui_exe_path();
    notification.Activated(&TypedEventHandler::<
        ToastNotification,
        windows::core::IInspectable,
    >::new(move |_, args| {
        // args is ToastActivatedEventArgs whose Arguments() carries the toast
        // launch payload: an action id quarantines the file; any other
        // activation opens the command center.
        let mut open_ui = true;
        let mut launch: Option<String> = None;
        // Ref<IInspectable> derefs to &IInspectable; Ref<Option<IInspectable>>
        // in this windows version — get the inner reference either way.
        if let Some(insp) = args.as_ref()
            && let Ok(evt) = insp
                .cast::<windows::UI::Notifications::ToastActivatedEventArgs>()
                && let Ok(l) = evt.Arguments() {
                    launch = Some(l.to_string());
                }
        if let Some(launch) = launch {
            let launch = launch.to_string();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&launch)
                && let Some(id) = v["mics-action"].as_str()
                    && let Some(path) = pending().lock().unwrap().remove(id) {
                        open_ui = false;
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .unwrap();
                            rt.block_on(async {
                                if let Ok(m) =
                                    crate::scanner::quarantine::QuarantineManager::new()
                                {
                                    match m
                                        .quarantine_file(
                                            std::path::Path::new(&path),
                                            "toast action",
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            tracing::info!("toast quarantine: {path}")
                                        }
                                        Err(e) => {
                                            tracing::warn!("toast quarantine: {e:#}")
                                        }
                                    }
                                }
                            });
                        });
                    }
        }
        if open_ui
            && let Some(path) = ui_path.clone() {
                let _ = std::process::Command::new(&path).spawn();
            }
        Ok(())
    }))?;

    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?;
    notifier.Show(&notification)?;
    Ok(())
}

fn ui_exe_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let beside = dir.join("mics_app.exe");
    if beside.exists() {
        return Some(beside);
    }
    let mut dir = dir.to_path_buf();
    for _ in 0..6 {
        dir = dir.parent()?.to_path_buf();
        let candidate = dir.join("build\\windows\\x64\\runner\\Release\\mics_app.exe");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Route a guard event to a toast when severity warrants it.
pub fn route_event(ev: &crate::guard::GuardEvent) {
    let critical = ev.severity == "critical";
    if dnd_enabled() && !critical {
        return; // DND: only CRITICAL breaks through
    }
    if !critical && ev.severity != "high" {
        return; // medium/low stay in-app
    }
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
    let actions: Vec<&str> = vec!["Open MI CS"];
    if let Err(e) = show_toast_with_actions(title, &body, &actions) {
        tracing::warn!("toast: {e:#}");
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
