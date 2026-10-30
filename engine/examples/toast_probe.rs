//! Dev probe: shows exactly which WinRT step of the toast path fails and with
//! which HRESULT. Run with `cargo run --example toast_probe -- [aumid]`.
//!
//! It exists because `notify.test` only reports the last error string: the
//! package-identity failure (0x80073D54) that used to kill every alert could
//! have come from any of the four calls below, and "which one" is the whole
//! diagnosis.

use windows::core::HSTRING;
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

fn main() {
    let aumid = std::env::args().nth(1).unwrap_or_else(|| "MICS".into());
    println!("aumid = {aumid}");

    let xml = r#"<toast activationType="foreground" launch="open-ui"><visual><binding template="ToastGeneric"><text>MI CS probe</text><text>step-by-step toast probe</text></binding></visual></toast>"#;

    let doc = XmlDocument::new();
    println!("1. XmlDocument::new          -> {:?}", doc.as_ref().map(|_| "ok"));

    let doc = match doc {
        Ok(d) => d,
        Err(e) => return println!("   fatal: {e}"),
    };
    let loaded = doc.LoadXml(&HSTRING::from(xml));
    println!("2. XmlDocument::LoadXml      -> {:?}", loaded.as_ref().map(|_| "ok"));

    let toast = ToastNotification::CreateToastNotification(&doc);
    println!("3. CreateToastNotification   -> {:?}", toast.as_ref().map(|_| "ok"));
    let toast = match toast {
        Ok(t) => t,
        Err(e) => return println!("   fatal: {e}"),
    };

    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid.as_str()));
    println!("4. CreateToastNotifierWithId -> {:?}", notifier.as_ref().map(|_| "ok"));
    let notifier = match notifier {
        Ok(n) => n,
        Err(e) => return println!("   fatal: {e}"),
    };

    let shown = notifier.Show(&toast);
    println!("5. ToastNotifier::Show       -> {:?}", shown.as_ref().map(|_| "ok"));
}
