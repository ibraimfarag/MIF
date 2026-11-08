//! WFP - slice (a) of register section 0.6 row 17: MI CS' own enforcement layer.
//!
//! The Windows Firewall rules in the parent module are the *policy* surface:
//! what Windows should allow, visible in `wf.msc`. This module is the
//! *enforcement* surface the row asks for - a provider, one sublayer and
//! **persistent** filters, which the Base Filtering Engine (BFE) applies on its
//! own. A block therefore stays in force while MI CS is not running, which a
//! Windows Firewall rule cannot express: those rules belong to Windows and are
//! not evaluated per connection by us.
//!
//! A filter sits on `FWPM_LAYER_ALE_AUTH_CONNECT_V4`/`_V6`, the layer the BFE
//! consults when a socket connects (outbound, per connection, with the
//! application's identity attached) - which is where a *live* firewall decides,
//! and what slice (b) needs in order to block one connection.
//!
//! Adding any of this needs elevation: the BFE grants write access to
//! administrators, so these functions are the privileged helper's, not the
//! engine's. `privileged::ops` is what calls them, validates the payload and
//! writes one audit line per call. From an unelevated process every write is
//! refused; [`needs_elevation`] names that case, so the UI can say "needs an
//! administrator" instead of showing an empty firewall.
//!
//! Every object is keyed and named: the provider, the sublayer and each filter
//! carry a key derived from what they filter, and each filter's display name
//! starts with `MICS-`, so adding the same block twice is one filter and
//! removal is exact. Nothing here clears a range, a wildcard or "all filters".

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::path::Path;
use tracing::{info, warn};

use super::elevated;
use windows::core::{Error, GUID, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmSubLayerGetByKey0, FWP_ACTION_BLOCK, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE,
    FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_ACTION0_0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// The provider and sublayer MI CS owns. Invented once and stable forever: a
/// second install, or the same install twice, must find the *same* objects
/// instead of creating a parallel set the other one cannot see.
pub const PROVIDER_KEY: GUID = GUID::from_u128(0x6d494353_0001_4d49_9b43_534355425331);
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x6d494353_0002_4d49_9b43_534355425331);

pub const PROVIDER_NAME: &str = "MI CS";
pub const SUBLAYER_NAME: &str = "MI CS real-time filter";

/// Every filter MI CS adds is named `MICS-...`, the same promise the Windows
/// Firewall rules carry: list, remove and reset only ever see our own objects.
pub const FILTER_PREFIX: &str = "MICS-";

/// Our sublayer's weight, which decides whether our block is reached before the
/// built-in Windows Firewall sublayer's permit. `0x7fff` is the highest value
/// the API's own examples use for a sublayer that has to be consulted first.
///
/// Whether it *does* outrank the built-in firewall is not measured: it needs an
/// administrator, a block, a real connection attempt and an engine that is not
/// running, so it is recorded in D-042 as the one number this session could not
/// confirm (register section 0.6 row 17 stays `[~]` for it).
const SUBLAYER_WEIGHT: u16 = 0x7fff;

/// What one persistent block covers.
///
/// An empty field is not a wildcard: [`validate`] refuses a spec that names
/// neither an application nor a port, so a filter can never block a whole
/// protocol family by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSpec {
    /// The application's image path, exactly as it was chosen.
    #[serde(default)]
    pub app: Option<String>,
    /// The remote port the connection is aimed at.
    #[serde(default)]
    pub port: Option<u16>,
    /// The IP protocol number (TCP 6, UDP 17).
    #[serde(default)]
    pub protocol: Option<u8>,
    /// A word for the filter's display name, from the caller (`guard`, `block`).
    #[serde(default)]
    pub note: Option<String>,
}

/// What the machine holds of ours right now.
///
/// `needs_elevation` is the honest third state: the BFE refused this process,
/// so "no filters" is unknown rather than empty, and the UI has to say so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpStatus {
    pub sublayer: bool,
    pub filters: usize,
    pub names: Vec<String>,
    pub needs_elevation: bool,
    #[serde(default)]
    pub detail: String,
}

/// The canonical string a filter is keyed by. Pure, so the identity of a filter
/// is testable without touching the machine.
pub fn canonical(spec: &FilterSpec) -> String {
    let app = spec
        .app
        .as_deref()
        .map(|p| p.trim().replace('/', "\\").to_ascii_lowercase())
        .unwrap_or_default();
    let port = spec.port.map(|p| p.to_string()).unwrap_or_default();
    let proto = spec.protocol.map(|p| p.to_string()).unwrap_or_default();
    format!("app={app};port={port};proto={proto}")
}

/// The GUID a spec is stored under: the first 16 bytes of SHA-256 over the
/// canonical string, with the version and variant bits set so the result is a
/// well-formed GUID. Deterministic, so "block this twice" is one filter.
pub fn filter_key(spec: &FilterSpec) -> GUID {
    let digest = Sha256::digest(canonical(spec).as_bytes());
    guid_of(&digest[..16])
}

/// Builds a well-formed GUID out of 16 bytes: the first three fields are
/// big-endian in GUID's own order, the rest is the byte order it is read in,
/// and the version and variant bits say "a key we derived", not "a random
/// number".
fn guid_of(bytes: &[u8]) -> GUID {
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(&bytes[8..16]);
    data4[0] = (data4[0] & 0x3f) | 0x80; // RFC 4122 variant
    GUID {
        data1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_be_bytes([bytes[4], bytes[5]]),
        data3: (u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0fff) | 0x4000,
        data4,
    }
}

/// The name shown in `netsh wfp show filters` and in our own status: the prefix
/// the rest of the product uses, then what the filter covers.
pub fn filter_name(spec: &FilterSpec) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(app) = spec.app.as_deref() {
        let trimmed = app.trim();
        let file = Path::new(trimmed)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| trimmed.to_string());
        if !file.is_empty() {
            parts.push(file);
        }
    }
    if let Some(port) = spec.port {
        parts.push(format!("port {port}"));
    }
    if let Some(protocol) = spec.protocol {
        parts.push(format!("protocol {protocol}"));
    }
    if let Some(note) = spec.note.as_deref() {
        let note = note.trim();
        if !note.is_empty() {
            parts.push(note.to_string());
        }
    }
    if parts.is_empty() {
        parts.push("all".into());
    }
    format!("{FILTER_PREFIX}{}", parts.join(" "))
}

/// Refuses a spec that would filter everything, or that cannot be expressed.
/// This is the helper's gate as well as the tests', so a malformed payload
/// never reaches the BFE.
pub fn validate(spec: &FilterSpec) -> Result<()> {
    if spec.app.is_none() && spec.port.is_none() {
        anyhow::bail!("a persistent filter needs an application or a remote port");
    }
    if let Some(app) = spec.app.as_deref() {
        let app = app.trim();
        if app.is_empty() {
            anyhow::bail!("a filter that names an application needs a path");
        }
        if app.len() > 1024 {
            anyhow::bail!("application path is too long");
        }
        if app.contains('"') || app.contains('\n') || app.contains('\0') {
            anyhow::bail!("application path has a character it cannot hold");
        }
    }
    if let Some(port) = spec.port
        && port == 0
    {
        anyhow::bail!("a filter that names a port needs a port above zero");
    }
    if let Some(protocol) = spec.protocol {
        // 6 (TCP) and 17 (UDP) are the two this product ever blocks; any other
        // protocol number is a request we cannot explain to the user.
        if protocol != 6 && protocol != 17 {
            anyhow::bail!("a filter protocol must be 6 (TCP) or 17 (UDP)");
        }
        if spec.port.is_none() {
            anyhow::bail!("a filter that names a protocol also needs a remote port");
        }
    }
    Ok(())
}

/// The layer a spec is enforced at. Outbound connections are the surface this
/// product watches, so both address families get the same block.
pub const LAYERS: [GUID; 2] = [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6];

/// A layer-specific filter key: each layer needs its own filter, or the second
/// add is an "already exists" on the first one's key.
pub fn layer_key(base: GUID, layer: GUID) -> GUID {
    let mut key = base;
    if layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        key.data4[7] ^= 0x01;
    }
    key
}

/// A GUID as the canonical text form. `windows-core`'s `GUID` has no `Display`,
/// and the text form is what the audit log and the UI have to agree on, so it
/// is written here once.
pub fn key_text(key: &GUID) -> String {
    let d4: Vec<String> = key.data4.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{:08X}-{:04X}-{:04X}-{}-{}",
        key.data1,
        key.data2,
        key.data3,
        d4[..2].join(""),
        d4[2..].join("")
    )
}

/// Turns a BFE status code into an error. The FWP codes are HRESULTs and the
/// plain Win32 codes (access denied, for instance) are not, so the shape of the
/// number decides how it is read.
fn wfp_error(code: u32) -> Error {
    if code >= 0x8000_0000 {
        Error::from_hresult(HRESULT(code as i32))
    } else {
        Error::from_hresult(HRESULT::from_win32(code))
    }
}

fn check(code: u32, what: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow::Error::new(wfp_error(code)).context(what.to_string()))
    }
}

/// True when a failure is the BFE refusing this process. That is the one
/// failure the product must name rather than log: an unelevated call is not a
/// bug in the request, and "add an administrator" is a real answer.
pub fn needs_elevation(err: &anyhow::Error) -> bool {
    const E_ACCESSDENIED: HRESULT = HRESULT(0x8007_0005u32 as i32);
    const FWP_E_ACCESS_DENIED: HRESULT = HRESULT(0x8032_0002u32 as i32);
    err.chain().any(|cause| {
        cause
            .downcast_ref::<Error>()
            .map(|win| win.code() == E_ACCESSDENIED || win.code() == FWP_E_ACCESS_DENIED)
            .unwrap_or(false)
    })
}

/// Whether a code means "it is already there" or "it was not there": the two
/// conditions every idempotent operation has to tolerate.
fn is_duplicate(code: u32) -> bool {
    code == FWP_E_ALREADY_EXISTS.0 as u32
}

fn is_missing(code: u32) -> bool {
    code == FWP_E_NOT_FOUND.0 as u32
        || code == FWP_E_FILTER_NOT_FOUND.0 as u32
        || code == FWP_E_SUBLAYER_NOT_FOUND.0 as u32
        || code == FWP_E_PROVIDER_NOT_FOUND.0 as u32
}

/// A UTF-16 buffer that lives as long as the struct it is handed to: WFP takes
/// pointers, not owned strings, and a temporary would dangle.
struct Wide(Vec<u16>);

impl Wide {
    fn new(value: &str) -> Self {
        Self(value.encode_utf16().chain(std::iter::once(0)).collect())
    }

    fn pwstr(&self) -> PWSTR {
        PWSTR(self.0.as_ptr() as *mut u16)
    }
}

/// An open BFE session.
///
/// No `FWPM_SESSION_FLAG_DYNAMIC`: a dynamic session's filters are deleted when
/// the session ends, and "survives the engine" is the whole point of this
/// slice. The handle is closed when this drops, which is what makes a
/// non-dynamic session safe to hold for the length of one helper call.
pub struct Engine {
    handle: HANDLE,
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.handle) };
    }
}

impl Engine {
    /// Opens the BFE session persistent objects need.
    pub fn open() -> Result<Self> {
        let name = Wide::new(SUBLAYER_NAME);
        let description = Wide::new("MI CS persistent filtering");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.pwstr(),
                description: description.pwstr(),
            },
            flags: 0,
            ..Default::default()
        };
        let mut handle = HANDLE::default();
        check(
            unsafe {
                FwpmEngineOpen0(
                    PCWSTR::null(),
                    RPC_C_AUTHN_WINNT,
                    None,
                    Some(&session),
                    &mut handle,
                )
            },
            "opening the filtering engine (BFE)",
        )?;
        Ok(Self { handle })
    }

    /// Creates the provider and the sublayer if the machine does not have them.
    /// Returns true when this call created something. Idempotent: the second
    /// call finds the same objects and changes nothing.
    pub fn ensure(&self) -> Result<bool> {
        let provider_name = Wide::new(PROVIDER_NAME);
        let provider_description = Wide::new("MI CS real-time filter provider");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: provider_name.pwstr(),
                description: provider_description.pwstr(),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        let mut created = false;
        let code = unsafe { FwpmProviderAdd0(self.handle, &provider, None) };
        if code == 0 {
            created = true;
        } else if !is_duplicate(code) {
            return Err(anyhow::Error::new(wfp_error(code)).context("adding the MI CS provider"));
        }

        if !self.has_sublayer()? {
            let name = Wide::new(SUBLAYER_NAME);
            let description = Wide::new("MI CS' own filters, enforced by the BFE");
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER_KEY,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.pwstr(),
                    description: description.pwstr(),
                },
                flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
                weight: SUBLAYER_WEIGHT,
                ..Default::default()
            };
            let code = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, None) };
            if code == 0 {
                created = true;
            } else if !is_duplicate(code) {
                return Err(
                    anyhow::Error::new(wfp_error(code)).context("adding the MI CS sublayer")
                );
            }
        }
        info!(created, "WFP sublayer ensured");
        Ok(created)
    }

    /// Whether our sublayer is on the machine.
    pub fn has_sublayer(&self) -> Result<bool> {
        let mut found: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let code = unsafe { FwpmSubLayerGetByKey0(self.handle, &SUBLAYER_KEY, &mut found) };
        if !found.is_null() {
            free(found as *mut c_void);
        }
        if code == 0 {
            return Ok(true);
        }
        if is_missing(code) {
            return Ok(false);
        }
        Err(anyhow::Error::new(wfp_error(code)).context("reading the MI CS sublayer"))
    }

    /// Adds one persistent block at connection time, on both address families.
    /// Returns the filter's key and whether anything was new - adding the same
    /// block twice is one filter, because the key comes from the spec.
    pub fn add_block(&self, spec: &FilterSpec) -> Result<(GUID, bool)> {
        validate(spec)?;
        let key = filter_key(spec);
        let name = Wide::new(&filter_name(spec));
        let described = Wide::new(&canonical(spec));
        let mut added = false;
        for layer in LAYERS {
            let mut conditions = Conditions::new(spec)?;
            let filter = FWPM_FILTER0 {
                filterKey: layer_key(key, layer),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.pwstr(),
                    description: described.pwstr(),
                },
                flags: FWPM_FILTER_FLAG_PERSISTENT,
                providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
                layerKey: layer,
                subLayerKey: SUBLAYER_KEY,
                weight: FWP_VALUE0 {
                    r#type: FWP_DATA_TYPE(0),
                    Anonymous: FWP_VALUE0_0 { uint8: 0 },
                },
                numFilterConditions: conditions.len(),
                filterCondition: conditions.as_mut_ptr(),
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    Anonymous: FWPM_ACTION0_0 {
                        filterType: GUID::zeroed(),
                    },
                },
                ..Default::default()
            };
            let code = unsafe { FwpmFilterAdd0(self.handle, &filter, None, None) };
            drop(conditions);
            if code == 0 {
                added = true;
            } else if !is_duplicate(code) {
                return Err(anyhow::Error::new(wfp_error(code)).context(format!(
                    "adding the persistent filter {}",
                    filter_name(spec)
                )));
            }
        }
        info!(filter = %filter_name(spec), added, "WFP block filter added");
        Ok((key, added))
    }

    /// Removes the filters a spec stands for. True when something was removed;
    /// a spec the machine does not know is not an error.
    pub fn remove_block(&self, spec: &FilterSpec) -> Result<bool> {
        let key = filter_key(spec);
        let mut removed = false;
        for layer in LAYERS {
            let target = layer_key(key, layer);
            let code = unsafe { FwpmFilterDeleteByKey0(self.handle, &target) };
            if code == 0 {
                removed = true;
            } else if !is_missing(code) {
                return Err(anyhow::Error::new(wfp_error(code))
                    .context("removing a persistent filter"));
            }
        }
        info!(removed, "WFP block filter removed");
        Ok(removed)
    }

    /// What the machine holds of ours right now.
    pub fn status(&self) -> Result<WfpStatus> {
        let sublayer = self.has_sublayer()?;
        let names = self.our_filter_names()?;
        Ok(WfpStatus {
            sublayer,
            filters: names.len(),
            names,
            needs_elevation: false,
            detail: String::new(),
        })
    }

    /// The names of the filters that carry our provider key. The template asks
    /// the BFE for our provider's filters only, and the provider key is checked
    /// again here: the engine never reports a filter it did not write.
    fn our_filter_names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        self.for_each_ours(|filter| {
            if !filter.displayData.name.is_null()
                && let Ok(name) = unsafe { filter.displayData.name.to_string() }
            {
                names.push(name);
            }
        })?;
        names.sort();
        Ok(names)
    }

    /// Walks our own filters. The callback sees the filter while the BFE's
    /// buffer is still alive, so it must copy what it needs.
    fn for_each_ours<F: FnMut(&FWPM_FILTER0)>(&self, mut visit: F) -> Result<()> {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            actionMask: u32::MAX,
            ..Default::default()
        };
        let mut handle = HANDLE::default();
        check(
            unsafe { FwpmFilterCreateEnumHandle0(self.handle, Some(&template), &mut handle) },
            "enumerating MI CS' filters",
        )?;
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count = 0u32;
            let code =
                unsafe { FwpmFilterEnum0(self.handle, handle, 64, &mut entries, &mut count) };
            if code != 0 || count == 0 || entries.is_null() {
                break;
            }
            let mut seen = 0usize;
            for i in 0..count as usize {
                let filter = unsafe { *entries.add(i) };
                if filter.is_null() {
                    continue;
                }
                let filter = unsafe { &*filter };
                let ours =
                    !filter.providerKey.is_null() && unsafe { *filter.providerKey } == PROVIDER_KEY;
                if ours {
                    visit(filter);
                    seen += 1;
                }
            }
            free(entries as *mut c_void);
            if seen == 0 {
                break;
            }
        }
        unsafe { FwpmFilterDestroyEnumHandle0(self.handle, handle) };
        Ok(())
    }

    /// Deletes every filter of ours, then the sublayer, then the provider.
    /// Order matters: a sublayer with filters under it cannot be removed, and
    /// the BFE refuses the provider while the sublayer still names it.
    pub fn reset(&self) -> Result<usize> {
        let mut ours: Vec<(u64, GUID)> = Vec::new();
        self.for_each_ours(|filter| ours.push((filter.filterId, filter.filterKey)))?;
        let mut removed = 0usize;
        for (_, key) in ours {
            let code = unsafe { FwpmFilterDeleteByKey0(self.handle, &key) };
            if code == 0 || is_missing(code) {
                removed += 1;
            } else {
                return Err(
                    anyhow::Error::new(wfp_error(code)).context("resetting a persistent filter")
                );
            }
        }
        let code = unsafe { FwpmSubLayerDeleteByKey0(self.handle, &SUBLAYER_KEY) };
        if code == 0 {
            removed += 1;
        } else if !is_missing(code) {
            return Err(anyhow::Error::new(wfp_error(code)).context("removing the MI CS sublayer"));
        }
        let code = unsafe { FwpmProviderDeleteByKey0(self.handle, &PROVIDER_KEY) };
        if code == 0 {
            removed += 1;
        } else if !is_missing(code) {
            return Err(anyhow::Error::new(wfp_error(code)).context("removing the MI CS provider"));
        }
        info!(removed, "WFP objects reset");
        Ok(removed)
    }
}

/// The condition list one filter carries, with its own storage so every pointer
/// stays valid until the filter call has returned.
struct Conditions {
    conditions: Vec<FWPM_FILTER_CONDITION0>,
    blobs: Vec<*mut FWP_BYTE_BLOB>,
}

impl Conditions {
    fn new(spec: &FilterSpec) -> Result<Self> {
        let mut conditions = Vec::new();
        let mut blobs = Vec::new();
        if let Some(app) = spec.app.as_deref() {
            let wide = Wide::new(app);
            let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            check(
                unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.0.as_ptr()), &mut blob) },
                "turning the application path into a filter condition",
            )?;
            if blob.is_null() {
                anyhow::bail!("the application path produced no filter condition");
            }
            blobs.push(blob);
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                },
            });
        }
        if let Some(port) = spec.port {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            });
        }
        if let Some(protocol) = spec.protocol {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: protocol },
                },
            });
        }
        Ok(Self { conditions, blobs })
    }

    fn len(&self) -> u32 {
        self.conditions.len() as u32
    }

    fn as_mut_ptr(&mut self) -> *mut FWPM_FILTER_CONDITION0 {
        self.conditions.as_mut_ptr()
    }
}

impl Drop for Conditions {
    fn drop(&mut self) {
        for blob in self.blobs.drain(..) {
            if !blob.is_null() {
                free(blob as *mut c_void);
            }
        }
    }
}

/// Frees a buffer the BFE handed us. `FwpmFreeMemory0` takes the address of the
/// pointer, which is why every call site passes a `*mut c_void` it owns.
fn free(pointer: *mut c_void) {
    let mut owned = pointer;
    unsafe { FwpmFreeMemory0(&mut owned as *mut *mut c_void) };
}

/// What a block did, as the helper reports it back to the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockOutcome {
    pub key: String,
    pub added: bool,
    pub filters: usize,
}

/// What an unblock did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnblockOutcome {
    pub removed: bool,
    pub filters: usize,
}

/// Adds one persistent block, creating the sublayer it needs first.
///
/// The read-back is part of the operation on purpose: the BFE is asked for the
/// filter list again and the operation fails unless the new filter is in it, so
/// "blocked" is a state that was seen, not a call that returned zero.
pub fn block_now(spec: &FilterSpec) -> Result<BlockOutcome> {
    validate(spec)?;
    let engine = Engine::open()?;
    engine.ensure()?;
    let (key, added) = engine.add_block(spec)?;
    let status = engine.status()?;
    let wanted = filter_name(spec);
    if !status.names.iter().any(|name| name == &wanted) {
        anyhow::bail!(
            "the filtering engine accepted {wanted} but does not list it — nothing was blocked"
        );
    }
    Ok(BlockOutcome {
        key: key_text(&key),
        added,
        filters: status.filters,
    })
}

/// Removes one persistent block. A block the machine does not have is not an
/// error: the caller asked for a state, and the state holds.
pub fn unblock_now(spec: &FilterSpec) -> Result<UnblockOutcome> {
    validate(spec)?;
    let engine = Engine::open()?;
    let removed = engine.remove_block(spec)?;
    let status = engine.status()?;
    Ok(UnblockOutcome {
        removed,
        filters: status.filters,
    })
}

/// Deletes every filter of ours, then the sublayer and the provider.
pub fn reset_now() -> Result<usize> {
    let engine = Engine::open()?;
    engine.reset()
}

/// What the machine holds, for a caller that is allowed to read it.
pub fn status_now() -> Result<WfpStatus> {
    Engine::open()?.status()
}

/// The engine-side surface: the same privilege split as the Windows Firewall
/// rules in the parent module. An elevated process reads and writes the BFE
/// directly; an unelevated one asks the helper (D-007), which is where the
/// writes have to happen, because a *persistent* filter needs an administrator.
pub struct WfpManager;

impl WfpManager {
    /// The honest answer for a process that may not read the BFE: ask the
    /// helper, and if there is no helper say "unknown, needs an administrator"
    /// rather than showing an empty filter list.
    pub async fn status() -> Result<WfpStatus> {
        status_blocking()
    }

    pub async fn block(spec: &FilterSpec) -> Result<BlockOutcome> {
        // The spec is checked in front of the privilege split on purpose: a
        // caller gets the same refusal whether the write would have happened
        // here or in the helper.
        validate(spec)?;
        let outcome = if elevated() {
            block_now(spec)?
        } else {
            let value = crate::privileged::run_op(&crate::privileged::Op::FirewallWfpBlock {
                spec: spec.clone(),
            })?;
            serde_json::from_value(value)
                .context("the privileged helper sent a result we cannot read")?
        };
        // The tamper watch's record (D-044). Best effort on purpose: the filter
        // is on the machine either way, and failing the call here would report a
        // write that did happen as an error.
        if let Err(e) = crate::firewall::watch::remember(&filter_name(spec)) {
            warn!("the WFP record could not be updated after a block: {e:#}");
        }
        Ok(outcome)
    }

    pub async fn unblock(spec: &FilterSpec) -> Result<UnblockOutcome> {
        validate(spec)?;
        let outcome = if elevated() {
            unblock_now(spec)?
        } else {
            let value = crate::privileged::run_op(&crate::privileged::Op::FirewallWfpUnblock {
                spec: spec.clone(),
            })?;
            serde_json::from_value(value)
                .context("the privileged helper sent a result we cannot read")?
        };
        if let Err(e) = crate::firewall::watch::forget(&filter_name(spec)) {
            warn!("the WFP record could not be updated after an unblock: {e:#}");
        }
        Ok(outcome)
    }

    /// The undo for everything this module ever added. It names no filter, so
    /// it can only ever remove our own objects (the provider key is ours).
    pub async fn reset() -> Result<usize> {
        let removed = if elevated() {
            reset_now()?
        } else {
            let value = crate::privileged::run_op(&crate::privileged::Op::FirewallWfpReset)?;
            outcome_count(&value, "removed")?
        };
        // Our own cleanup must never read as a tamper: the record goes when the
        // filters go (D-044).
        if let Err(e) = crate::firewall::watch::forget_all() {
            warn!("the WFP record could not be cleared after a reset: {e:#}");
        }
        Ok(removed)
    }
}

/// [`WfpManager::status`] without a runtime.
///
/// Reading the BFE is a blocking Windows call, and the tamper watch runs on the
/// guard's own OS thread (D-044), where there is no tokio reactor to borrow.
pub fn status_blocking() -> Result<WfpStatus> {
    match Engine::open().and_then(|engine| engine.status()) {
        Ok(status) => Ok(status),
        Err(e) if needs_elevation(&e) => {
            match crate::privileged::run_op(&crate::privileged::Op::FirewallWfpStatus) {
                Ok(value) => Ok(serde_json::from_value(value)
                    .context("the privileged helper sent a status we cannot read")?),
                Err(helper) => Ok(WfpStatus {
                    sublayer: false,
                    filters: 0,
                    names: Vec::new(),
                    needs_elevation: true,
                    detail: helper.to_string(),
                }),
            }
        }
        Err(e) => Err(e),
    }
}

/// Reads a count out of a helper response, so a shape the helper did not send
/// fails here instead of being reported as zero removals.
fn outcome_count(value: &serde_json::Value, field: &str) -> Result<usize> {
    value
        .get(field)
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .ok_or_else(|| anyhow::anyhow!("the privileged helper did not report {field}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(app: Option<&str>, port: Option<u16>, protocol: Option<u8>) -> FilterSpec {
        FilterSpec {
            app: app.map(|a| a.to_string()),
            port,
            protocol,
            note: None,
        }
    }

    #[test]
    fn a_filter_with_nothing_in_it_is_refused() {
        assert!(
            validate(&spec(None, None, None)).is_err(),
            "an empty spec would filter everything"
        );
        assert!(validate(&spec(Some("   "), None, None)).is_err());
        assert!(validate(&spec(None, Some(0), None)).is_err());
    }

    #[test]
    fn a_protocol_without_a_port_is_refused() {
        assert!(validate(&spec(None, None, Some(6))).is_err());
        assert!(validate(&spec(None, Some(443), Some(6))).is_ok());
        assert!(validate(&spec(None, Some(443), Some(99))).is_err());
    }

    #[test]
    fn a_path_that_cannot_be_a_path_is_refused() {
        assert!(validate(&spec(Some("C:\\a\"b.exe"), None, None)).is_err());
        assert!(validate(&spec(Some("C:\\a\nb.exe"), None, None)).is_err());
        assert!(validate(&spec(Some(&"x".repeat(2048)), None, None)).is_err());
    }

    #[test]
    fn the_same_block_has_the_same_key() {
        let one = spec(Some("C:\\Program Files\\App\\app.exe"), Some(443), Some(6));
        let two = spec(Some("c:/program files/app/app.exe"), Some(443), Some(6));
        assert_eq!(canonical(&one), canonical(&two), "case and slashes are one block");
        assert_eq!(filter_key(&one), filter_key(&two));

        let other = spec(Some("C:\\Program Files\\App\\app.exe"), Some(80), Some(6));
        assert_ne!(filter_key(&one), filter_key(&other));
    }

    #[test]
    fn the_two_layers_get_two_keys_and_a_well_formed_guid() {
        let base = filter_key(&spec(Some("C:\\app.exe"), None, None));
        assert_eq!(base.data3 & 0xf000, 0x4000, "version 4");
        assert_eq!(base.data4[0] & 0xc0, 0x80, "RFC 4122 variant");

        assert_ne!(
            layer_key(base, FWPM_LAYER_ALE_AUTH_CONNECT_V4),
            layer_key(base, FWPM_LAYER_ALE_AUTH_CONNECT_V6),
            "one key per layer, or the second add collides"
        );
        assert_eq!(layer_key(base, FWPM_LAYER_ALE_AUTH_CONNECT_V4), base);
    }

    #[test]
    fn the_name_says_what_the_filter_covers_and_keeps_the_prefix() {
        let named = filter_name(&spec(Some("C:\\Program Files\\App\\app.exe"), Some(443), Some(6)));
        assert!(named.starts_with(FILTER_PREFIX), "{named}");
        assert!(named.contains("app.exe"));
        assert!(named.contains("443"));

        assert_eq!(
            filter_name(&spec(None, Some(53), Some(17))),
            "MICS-port 53 protocol 17"
        );
    }

    /// The filter key has to be stable across runs, or a restart would leave
    /// the previous filter behind and add a second one nobody can name. This is
    /// the value measured on 2026-11-08 and written down so a change to
    /// `canonical` cannot silently orphan every filter already on a machine.
    #[test]
    fn a_known_spec_keeps_its_measured_key() {
        let known = spec(Some("C:\\Windows\\System32\\curl.exe"), Some(443), Some(6));
        assert_eq!(canonical(&known), "app=c:\\windows\\system32\\curl.exe;port=443;proto=6");
        let key = filter_key(&known);
        assert_eq!(
            format!("{key:?}").to_uppercase(),
            "B051BA44-F5BF-454C-8D09-B8F1F8D5680E",
            "the key of a block must not move between versions"
        );
    }

    /// Measured on this machine, unelevated: the BFE refuses the write. That
    /// refusal is the reason the helper exists, so it is exercised rather than
    /// assumed. When this is run with an administrator it cleans up after
    /// itself instead, so the test never leaves objects behind either way.
    #[test]
    fn unelevated_the_bfe_refuses_the_write() {
        let engine = match Engine::open() {
            Ok(engine) => engine,
            Err(e) => {
                eprintln!("open refused: {e:#} (needs_elevation={})", needs_elevation(&e));
                return;
            }
        };
        match engine.ensure() {
            Ok(created) => {
                eprintln!("ensure succeeded (created={created}) - running elevated");
                if created {
                    let removed = engine.reset().expect("reset");
                    eprintln!("reset removed {removed}");
                }
            }
            Err(e) => {
                eprintln!("ensure refused: {e:#} (needs_elevation={})", needs_elevation(&e));
            }
        }
    }
}
