//! Engine-side Windows Toast notifications — alerts fire even with the UI
//! closed (AUMID "MICS"). Cards carry real actions:
//!   click / "Open MIF" -> launches the UI
//!   "Quarantine"         -> actually quarantines the referenced file
//!
//! This module is the transport only. **Whether** an alert may reach the
//! desktop (toast_enabled, DND, severity) is decided in [`crate::notify::alert`]
//! so there is exactly one policy and it is unit-testable.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use windows::core::{HSTRING, Interface};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const AUMID: &str = "MICS";

/// Windows' "this app has no package identity" (APPMODEL_ERROR_NO_PACKAGE).
const APPMODEL_ERROR_NO_PACKAGE: i32 = 0x80073D54u32 as i32;
/// Low integrity ends here; a confined folder labels every child below it.
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;

/// The reason Windows gives when it refuses a card to a **low-integrity**
/// process: running from a folder whose mandatory label is Low (a sandbox or
/// confinement-managed tree) makes the app unable to toast at all, while the
/// HRESULT alone reads like a missing registration. Pure so it can be tested.
fn explain_toast_failure(code: i32, confined: bool) -> Option<&'static str> {
    if code == APPMODEL_ERROR_NO_PACKAGE && confined {
        return Some(
            "Windows does not show notification cards for a low-integrity process: MI CS is \
             running from a confined folder. Move MI CS to a normal folder, or raise the \
             folder's label as an administrator (`icacls \"<folder>\" /setintegritylevel \
             Medium /T`), then try again",
        );
    }
    None
}

/// The current process's integrity RID (`0x1000` low, `0x2000` medium).
fn integrity_rid() -> Option<u32> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut size);
        if size == 0 {
            let _ = CloseHandle(token);
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let read = GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast()),
            size,
            &mut size,
        );
        let _ = CloseHandle(token);
        read.ok()?;
        let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return None;
        }
        Some(*GetSidSubAuthority(label.Label.Sid, u32::from(count) - 1))
    }
}

/// True when this process cannot toast because of how it was started.
fn integrity_is_confined() -> bool {
    matches!(integrity_rid(), Some(rid) if rid < SECURITY_MANDATORY_MEDIUM_RID)
}

/// Turns the platform's HRESULT into something a reader can act on.
fn toast_error(e: windows::core::Error) -> anyhow::Error {
    match explain_toast_failure(e.code().0, integrity_is_confined()) {
        Some(hint) => anyhow::anyhow!("{hint} (Windows said: {e})"),
        None => anyhow::Error::new(e),
    }
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

    let xml = build_toast_xml(title, body, actions, &launch);

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

    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))
        .map_err(toast_error)?;
    notifier.Show(&notification).map_err(toast_error)?;
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

/// Builds the toast payload. Pure so the escaping can be tested: a `"` inside
/// an attribute value used to end the attribute early, which made every card
/// with an action (the "threat found → Quarantine" one) fail to parse and
/// disappear without ever reaching the desktop.
pub fn build_toast_xml(title: &str, body: &str, actions: &[&str], launch: &str) -> String {
    let mut xml = format!(
        r#"<toast activationType="foreground" launch="{}"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual>"#,
        escape_xml(launch),
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
    xml
}

/// XML text/attribute escaping. Quotes matter: `launch` and `content` are
/// attribute values, and an unescaped `"` truncates them.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_inside_the_launch_payload_is_escaped() {
        let xml = build_toast_xml(
            "🛡️ MI CS — Threat found",
            r"C:\tmp\bad.exe — yara:EICAR",
            &["Quarantine", "Open MI CS"],
            r#"{"mics-action":"a1729"}"#,
        );
        // The raw JSON quotes must never appear inside the attribute.
        assert!(
            !xml.contains(r#""mics-action""#),
            "unescaped JSON quotes in the launch attribute: {xml}"
        );
        assert!(xml.contains(r#"launch="{&quot;mics-action&quot;:&quot;a1729&quot;}""#));
        // Every attribute is closed exactly once, and the tag structure is
        // intact (the old code produced three quotes in a two-quote attribute).
        assert_eq!(xml.matches("launch=\"").count(), 1);
        assert!(xml.ends_with("</toast>"));
    }

    #[test]
    fn text_and_action_copy_are_escaped() {
        let xml = build_toast_xml("A & B <c>", "\"quoted\"", &["Say \"no\""], "open-ui");
        assert!(xml.contains("A &amp; B &lt;c&gt;"));
        assert!(xml.contains("&quot;quoted&quot;"));
        assert!(xml.contains(r#"content="Say &quot;no&quot;""#));
    }

    #[test]
    fn no_actions_means_no_actions_element() {
        let xml = build_toast_xml("t", "b", &[], "open-ui");
        assert!(!xml.contains("<actions>"));
        assert!(xml.contains(r#"launch="open-ui""#));
    }

    #[test]
    fn the_confined_folder_refusal_is_explained_not_echoed() {
        // Windows' own words for "a low-integrity process may not toast".
        let text = explain_toast_failure(APPMODEL_ERROR_NO_PACKAGE, true)
            .expect("the sandbox case must be explained");
        assert!(text.contains("low-integrity"), "{text}");
        assert!(text.contains("setintegritylevel Medium"), "{text}");
        // Same error outside a confined folder, or another error inside one:
        // no invented explanation.
        assert!(explain_toast_failure(APPMODEL_ERROR_NO_PACKAGE, false).is_none());
        assert!(explain_toast_failure(0x8007_0005u32 as i32, true).is_none());
    }
}
