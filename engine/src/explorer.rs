//! The Explorer right-click entry ("Scan this file/folder with MI CS").
//!
//! This is the *opt-in* copy of the verb (D-054). The installer still writes the
//! same three keys for the user who installed MI CS; a portable copy registers
//! nothing until the user turns the entry on in Settings, because a portable app
//! that writes registry keys the moment it first runs is exactly the behaviour
//! people install portable apps to avoid.
//!
//! The whole registration is per-user (`HKEY_CURRENT_USER`), so it needs no
//! elevation and leaves nothing machine-wide behind:
//!
//! ```text
//! HKCU\Software\Classes\*\shell\MICS                    (default) = file label
//! HKCU\Software\Classes\*\shell\MICS\command            (default) = "<exe>" --scan "%1"
//! HKCU\Software\Classes\Directory\shell\MICS            (default) = folder label
//! HKCU\Software\Classes\Directory\shell\MICS\command    (default) = "<exe>" --scan "%1"
//! HKCU\Software\Classes\Directory\Background\shell\MICS (default) = folder label
//! HKCU\Software\Classes\Directory\Background\shell\MICS\command (default) = "<exe>" --scan "%V"
//! ```
//!
//! `%1` is the clicked object and `%V` the folder whose background was clicked;
//! Explorer substitutes them, and the app's existing `--scan` entry point then
//! hands the path to the running window (D-041) instead of starting a second one.
//!
//! Deliberately absent: `Drive`, `AllFilesystemObjects` and the "*" background —
//! a drive root or every object on the machine is a much wider surface than
//! "a file or a folder", and the entry is meant to be small and reversible.

use anyhow::{bail, Context, Result};

/// The verb's key name under every class. Changing it orphans the old tree, so
/// it is part of the persisted shape: `disable` removes exactly this name.
pub const VERB_NAME: &str = "MICS";

/// `*` = any file, `Directory` = a folder, `Directory\Background` = the empty
/// space inside a folder.
pub const CLASSES: [&str; 3] = [r"*", r"Directory", r"Directory\Background"];

/// One registry value to write: the key (relative to `HKEY_CURRENT_USER`), the
/// value name (`""` is the key's default value), and the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerbValue {
    pub subkey: String,
    pub name: String,
    pub value: String,
}

/// The three keys that make up the entry, and the exact set `disable` removes.
pub fn verb_keys() -> Vec<String> {
    CLASSES
        .iter()
        .map(|class| format!(r"Software\Classes\{class}\shell\{VERB_NAME}"))
        .collect()
}

/// The command line Explorer runs for a clicked object.
///
/// Both paths are quoted because a Windows path may contain spaces; there is no
/// shell in between (Explorer calls `CreateProcess`), so the quotes are the whole
/// escaping rule. `selection` is Explorer's placeholder, not user input.
pub fn scan_command(app_path: &str, selection: &str) -> String {
    format!("\"{app_path}\" --scan \"{selection}\"")
}

/// Every value the entry needs, for one language.
///
/// The menu text comes from the UI's pack, not from this module: the engine keeps
/// no copy, so a language added next month needs no engine change. `file_label`
/// and `folder_label` are the whole of the localisation.
pub fn verb_entries(app_path: &str, file_label: &str, folder_label: &str) -> Vec<VerbValue> {
    let mut values = Vec::with_capacity(CLASSES.len() * 3);
    for (class, label, selection) in [
        (r"*", file_label, "%1"),
        (r"Directory", folder_label, "%1"),
        (r"Directory\Background", folder_label, "%V"),
    ] {
        let root = format!(r"Software\Classes\{class}\shell\{VERB_NAME}");
        values.push(VerbValue {
            subkey: root.clone(),
            name: String::new(),
            value: label.to_string(),
        });
        values.push(VerbValue {
            subkey: root.clone(),
            name: "Icon".to_string(),
            value: app_path.to_string(),
        });
        values.push(VerbValue {
            subkey: format!(r"{root}\command"),
            name: String::new(),
            value: scan_command(app_path, selection),
        });
    }
    values
}

/// The part of a verb command line that names the executable: the first quoted
/// run, or the text up to the first space. Kept next to the writer so the two
/// cannot drift: `is_registered` reads back exactly what `scan_command` wrote.
pub fn command_exe(command: &str) -> &str {
    let trimmed = command.trim();
    match trimmed.strip_prefix('"') {
        Some(rest) => rest.split('"').next().unwrap_or(rest),
        None => trimmed.split(' ').next().unwrap_or(trimmed),
    }
}

/// The one seam between this module and the machine: a test's fake registry
/// implements it, and so does [`UserRegistry`].
pub trait VerbRegistry {
    /// Create the key if needed and set one value.
    fn set_value(&self, subkey: &str, name: &str, value: &str) -> Result<()>;
    /// Remove the key and everything below it; a missing key is success.
    fn delete_tree(&self, subkey: &str) -> Result<()>;
    /// Read a key's default value, `None` when the key or value is absent.
    fn read_default(&self, subkey: &str) -> Result<Option<String>>;
}

/// Refuse a path that cannot be a command's executable, before anything is
/// written. A relative path would be resolved against Explorer's own working
/// directory, and a quote in it would break the command line.
fn check_app_path(app_path: &str) -> Result<()> {
    let path = std::path::Path::new(app_path);
    if !path.is_absolute() {
        bail!("app_path must be absolute: {app_path}");
    }
    if !app_path.to_ascii_lowercase().ends_with(".exe") {
        bail!("app_path must name an .exe: {app_path}");
    }
    if app_path.contains('"') || app_path.chars().any(char::is_control) {
        bail!("app_path contains a character a command line cannot carry");
    }
    Ok(())
}

fn check_label(label: &str) -> Result<()> {
    if label.trim().is_empty() {
        bail!("the menu label must not be empty");
    }
    if label.chars().any(char::is_control) {
        bail!("the menu label contains a control character");
    }
    Ok(())
}

/// Write the entry (idempotent: the same values are simply set again).
pub fn enable(
    registry: &dyn VerbRegistry,
    app_path: &str,
    file_label: &str,
    folder_label: &str,
) -> Result<()> {
    check_app_path(app_path)?;
    check_label(file_label)?;
    check_label(folder_label)?;
    for value in verb_entries(app_path, file_label, folder_label) {
        registry
            .set_value(&value.subkey, &value.name, &value.value)
            .with_context(|| {
                format!(
                    "could not write the Explorer entry at HKCU\\{}{}",
                    value.subkey,
                    if value.name.is_empty() { "" } else { " / " }
                )
            })?;
    }
    // Explorer caches menu text, but it does not lie about what is in the
    // registry. Reading the three commands back turns "the write silently did
    // not take" into an error the switch can show instead of a menu item that
    // never appears.
    if !is_registered(registry, app_path)? {
        bail!("the Explorer entry was written but could not be read back");
    }
    Ok(())
}

/// Remove the entry. Removing what is not there is success, so turning the
/// switch off twice is not an error.
pub fn disable(registry: &dyn VerbRegistry) -> Result<()> {
    for key in verb_keys() {
        registry
            .delete_tree(&key)
            .with_context(|| format!("could not remove HKCU\\{key}"))?;
    }
    Ok(())
}

/// Whether the entry at [app_path] is the one currently registered.
///
/// Used at startup so a portable copy whose folder moved refreshes the dead path
/// (and so an installed copy, whose installer wrote the same keys, shows the
/// switch in the state the machine is actually in).
pub fn is_registered(registry: &dyn VerbRegistry, app_path: &str) -> Result<bool> {
    for class in CLASSES {
        let key = format!(r"Software\Classes\{class}\shell\{VERB_NAME}\command");
        let Some(command) = registry.read_default(&key)? else {
            return Ok(false);
        };
        if !command_exe(&command).eq_ignore_ascii_case(app_path) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The real registry, under the signed-in user's own hive.
pub struct UserRegistry;

#[cfg(windows)]
mod win {
    use super::VerbRegistry;
    use anyhow::{bail, Result};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn sz_bytes(s: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(s.len() * 2 + 2);
        for unit in s.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    impl VerbRegistry for super::UserRegistry {
        fn set_value(&self, subkey: &str, name: &str, value: &str) -> Result<()> {
            let key_path = to_wide(subkey);
            let mut key = HKEY::default();
            let created = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(key_path.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE | KEY_READ,
                    None,
                    &mut key,
                    None,
                )
            };
            if created != ERROR_SUCCESS {
                bail!("RegCreateKeyExW failed ({})", created.0);
            }
            let value_name = to_wide(name);
            let data = sz_bytes(value);
            let written = unsafe {
                RegSetValueExW(
                    key,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    REG_SZ,
                    Some(data.as_slice()),
                )
            };
            unsafe {
                let _ = RegCloseKey(key);
            }
            if written != ERROR_SUCCESS {
                bail!("RegSetValueExW failed ({})", written.0);
            }
            Ok(())
        }

        fn delete_tree(&self, subkey: &str) -> Result<()> {
            let key_path = to_wide(subkey);
            let removed = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(key_path.as_ptr())) };
            if removed != ERROR_SUCCESS && removed != ERROR_FILE_NOT_FOUND {
                bail!("RegDeleteTreeW failed ({})", removed.0);
            }
            Ok(())
        }

        fn read_default(&self, subkey: &str) -> Result<Option<String>> {
            let key_path = to_wide(subkey);
            let mut len: u32 = 0;
            let probe = unsafe {
                RegGetValueW(
                    HKEY_CURRENT_USER,
                    PCWSTR(key_path.as_ptr()),
                    PCWSTR::null(),
                    RRF_RT_REG_SZ,
                    None,
                    None,
                    Some(&mut len),
                )
            };
            if probe != ERROR_SUCCESS || len < 2 {
                return Ok(None);
            }
            let mut buffer = vec![0u8; len as usize];
            let read = unsafe {
                RegGetValueW(
                    HKEY_CURRENT_USER,
                    PCWSTR(key_path.as_ptr()),
                    PCWSTR::null(),
                    RRF_RT_REG_SZ,
                    None,
                    Some(buffer.as_mut_ptr() as *mut _),
                    Some(&mut len),
                )
            };
            if read != ERROR_SUCCESS {
                return Ok(None);
            }
            let units: Vec<u16> = buffer
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .take_while(|unit| *unit != 0)
                .collect();
            Ok(Some(String::from_utf16_lossy(&units)))
        }
    }
}

#[cfg(not(windows))]
impl VerbRegistry for UserRegistry {
    fn set_value(&self, _subkey: &str, _name: &str, _value: &str) -> Result<()> {
        bail!("the Explorer entry is a Windows feature")
    }
    fn delete_tree(&self, _subkey: &str) -> Result<()> {
        bail!("the Explorer entry is a Windows feature")
    }
    fn read_default(&self, _subkey: &str) -> Result<Option<String>> {
        Ok(None)
    }
}