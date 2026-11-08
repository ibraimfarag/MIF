//! Real Windows Firewall management through the documented COM API
//! (`INetFwPolicy2` / `INetFwRules` / `INetFwRule`) - the same surface Windows'
//! own `wf.msc` drives. This replaces `netsh advfirewall` (register §7, MED):
//! the engine used to parse an external tool's localized English text, wait on a
//! child process that could hang, and depend on a binary that is not ours.
//! Every read below is a property and every write is one COM call with a typed
//! argument, so "what the UI shows" and "what Windows enforces" are the same
//! object instead of a line of console output.
//!
//! Every rule the engine creates is prefixed `MICS-` **and** grouped under
//! "MI CS", so list/remove never touch rules it doesn't own and the Windows
//! firewall UI shows what we added as one block.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;
use windows::core::{BSTR, Error, Interface, IUnknown};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, RPC_E_CHANGED_MODE, VARIANT_BOOL};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NetFwRule, NET_FW_ACTION,
    NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL, NET_FW_IP_PROTOCOL_ANY,
    NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE2_ALL, NET_FW_PROFILE_TYPE2, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIRECTION,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;

pub mod watch;
pub mod wfp;

/// Every rule the engine creates starts with this, so list and remove only ever
/// see MI CS' own rules.
pub const RULE_PREFIX: &str = "MICS-";

/// The group Windows shows in `wf.msc` for the rules above. Setting it is new
/// with this API: `netsh` left our rules ungrouped in the list.
pub const RULE_GROUP: &str = "MI CS";

/// Written into each rule's description so a person reading `wf.msc` knows where
/// it came from, and so a support question has a name to search the docs for.
const RULE_DESCRIPTION: &str = "Created by MI CS from Settings > Network";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirewallRule {
    pub name: String,
    pub enabled: bool,
    pub direction: String,
    pub action: String,
    #[serde(default)]
    pub remote_ip: String,
    #[serde(default)]
    pub local_port: String,
    #[serde(default)]
    pub remote_port: String,
}

/// The three profiles Windows keeps independent policies for. Default-Deny is
/// only honest when all three agree, so every read and write walks this list.
const PROFILES: [(NET_FW_PROFILE_TYPE2, &str); 3] = [
    (NET_FW_PROFILE2_DOMAIN, "Domain"),
    (NET_FW_PROFILE2_PRIVATE, "Private"),
    (NET_FW_PROFILE2_PUBLIC, "Public"),
];

/// `netsh` printed the word `Any` for an unset address or port; the API returns
/// an empty string (addresses) or `*` (any). The screens have always shown
/// `Any`, so the value keeps that spelling instead of leaking two forms of the
/// same state into the UI.
pub(crate) fn or_any(value: &str) -> String {
    match value.trim() {
        "" | "*" => "Any".to_string(),
        other => other.to_string(),
    }
}

/// Direction as the screens and the request payload spell it (`in` / `out`).
pub(crate) fn direction_of(word: &str) -> Option<NET_FW_RULE_DIRECTION> {
    match word.trim().to_ascii_lowercase().as_str() {
        "in" | "inbound" => Some(NET_FW_RULE_DIR_IN),
        "out" | "outbound" => Some(NET_FW_RULE_DIR_OUT),
        _ => None,
    }
}

/// The word the rules list shows. `netsh` printed `In` / `Out`.
pub(crate) fn direction_name(direction: NET_FW_RULE_DIRECTION) -> &'static str {
    if direction == NET_FW_RULE_DIR_OUT {
        "Out"
    } else if direction == NET_FW_RULE_DIR_IN {
        "In"
    } else {
        "Unknown"
    }
}

/// Action as a request spells it (`allow` / `block`).
pub(crate) fn action_of(word: &str) -> Option<NET_FW_ACTION> {
    match word.trim().to_ascii_lowercase().as_str() {
        "allow" | "permit" => Some(NET_FW_ACTION_ALLOW),
        "block" | "deny" => Some(NET_FW_ACTION_BLOCK),
        _ => None,
    }
}

/// The word the rules list shows. `netsh` printed `Allow` / `Block`.
pub(crate) fn action_name(action: NET_FW_ACTION) -> &'static str {
    if action == NET_FW_ACTION_BLOCK {
        "Block"
    } else if action == NET_FW_ACTION_ALLOW {
        "Allow"
    } else {
        "Unknown"
    }
}

/// The IP protocol number the API wants. `netsh` took the word; the API takes
/// the number, so the translation lives here and nowhere else.
pub(crate) fn protocol_of(word: &str) -> Option<NET_FW_IP_PROTOCOL> {
    match word.trim().to_ascii_lowercase().as_str() {
        "any" => Some(NET_FW_IP_PROTOCOL_ANY),
        "tcp" | "6" => Some(NET_FW_IP_PROTOCOL_TCP),
        "udp" | "17" => Some(NET_FW_IP_PROTOCOL_UDP),
        other => other
            .parse::<i32>()
            .ok()
            .filter(|n| (0..=255).contains(n))
            .map(NET_FW_IP_PROTOCOL),
    }
}

/// COM has to be started on the thread that uses it. `CoInitializeEx` says
/// `RPC_E_CHANGED_MODE` when the thread already lives in another apartment
/// (the UI thread of the app does), and that is not a failure: the firewall
/// interfaces work from either. Only a call *we* started is balanced by a
/// `CoUninitialize`, so nothing here can unbalance somebody else's apartment.
struct Apartment {
    ours: bool,
}

impl Apartment {
    fn enter() -> Result<Self> {
        // `S_FALSE` (already started on this thread) is a success and still owes
        // one `CoUninitialize`; `RPC_E_CHANGED_MODE` means somebody else owns
        // the apartment, and then the balance is theirs, not ours.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            return Ok(Self { ours: true });
        }
        if hr == RPC_E_CHANGED_MODE {
            return Ok(Self { ours: false });
        }
        Err(anyhow::anyhow!(
            "COM could not be started: {}",
            Error::from_hresult(hr)
        ))
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.ours {
            unsafe { CoUninitialize() };
        }
    }
}

/// One open handle on the firewall policy, with the apartment kept alive for as
/// long as the interface is used.
///
/// **Field order is load-bearing.** Rust drops fields in declaration order, and
/// releasing a COM interface *after* `CoUninitialize` on that thread is an
/// access violation (measured: `0xc0000005` in the drop, on every call through
/// `list_rules`). The interface is declared first so it is released first, and
/// the apartment - declared last - goes away only once nothing is left to
/// release.
struct Firewall {
    policy: INetFwPolicy2,
    _apartment: Apartment,
}

impl Firewall {
    fn open() -> Result<Self> {
        let apartment = Apartment::enter()?;
        // SAFETY: `NetFwPolicy2` is the documented class id for the policy
        // object; the interface is released by `Drop` like any other COM ref.
        let policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.context(
                "the Windows Firewall API is not reachable (is the Windows Defender Firewall \
                 service stopped?)",
            )?;
        Ok(Self {
            policy,
            _apartment: apartment,
        })
    }

    fn rules(&self) -> Result<INetFwRules> {
        // SAFETY: a plain property call on a live interface.
        unsafe { self.policy.Rules() }.context("the firewall refused to hand over its rule list")
    }
}

/// True when the current process can change the firewall itself.
///
/// When it cannot, the operation goes to the privileged helper (D-007) instead
/// of asking Windows for a fresh UAC prompt per call.
fn elevated() -> bool {
    crate::platform::windows::elevation::is_elevated()
}

/// Default-Deny Outbound per profile. Elevation is the caller's business - this
/// is the body the helper runs.
///
/// Only the outbound half moves: inbound is a separate property
/// (`DefaultInboundAction`) and Windows' own `BlockInbound` must survive both
/// directions.
pub fn set_default_deny_now(enabled: bool) -> Result<()> {
    let action = if enabled {
        NET_FW_ACTION_BLOCK
    } else {
        NET_FW_ACTION_ALLOW
    };
    let firewall = Firewall::open()?;
    info!("Setting the default outbound policy -> {}", action_name(action));
    for (profile, name) in PROFILES {
        // SAFETY: typed property write on a live interface.
        unsafe { firewall.policy.put_DefaultOutboundAction(profile, action) }.with_context(|| {
            format!("the {name} profile refused the new outbound policy")
        })?;
    }
    Ok(())
}

/// The name of the rule MI CS owns for `name`: exactly one `MICS-` prefix.
///
/// The prefix marks ownership, so it is a property of the *rule* and not of the
/// string the caller happened to type: `guard-test`, `MICS-guard-test` and
/// `MICS-MICS-guard-test` all name the one rule `MICS-guard-test`. This is the
/// single place that decides it, because the two callers used to disagree -
/// `add_rule_now` prefixed unconditionally while `remove_rule_now` stripped an
/// *optional* prefix, so `fw.rules.add {name: "MICS-foo"}` created
/// `MICS-MICS-foo` and `fw.rules.remove {name: "MICS-foo"}` then looked for
/// `MICS-foo`, found nothing and reported success (removing a missing rule is
/// deliberately idempotent) - a stray **blocking** rule outliving the removal
/// that claimed to have done it (register 7, MED).
///
/// The strip repeats and ignores ASCII case, so a name an older build doubled
/// can be removed by either of its spellings instead of needing the doubled one.
pub fn owned_rule_name(name: &str) -> Result<String> {
    let mut rest = name.trim();
    loop {
        let stripped = rest
            .get(..RULE_PREFIX.len())
            .filter(|head| head.eq_ignore_ascii_case(RULE_PREFIX))
            .map(|_| &rest[RULE_PREFIX.len()..]);
        match stripped {
            Some(next) => rest = next.trim_start(),
            None => break,
        }
    }
    if rest.is_empty() {
        anyhow::bail!(
            "a firewall rule needs a name beyond MI CS' own `{RULE_PREFIX}` prefix - \
             a rule called `{RULE_PREFIX}` is the prefix, not a name"
        );
    }
    Ok(format!("{RULE_PREFIX}{rest}"))
}

/// Creates one `MICS-` rule under its canonical name (`owned_rule_name`), so the
/// name it returns is the name to remove it by - whatever the request spelled.
/// Shared by the engine and the helper.
pub fn add_rule_now(req: &AddRuleRequest) -> Result<String> {
    let name = owned_rule_name(&req.name)?;
    let direction = direction_of(&req.direction).with_context(|| {
        format!(
            "`{}` is not a firewall direction (use `in` or `out`)",
            req.direction
        )
    })?;
    let action = action_of(&req.action).with_context(|| {
        format!(
            "`{}` is not a firewall action (use `allow` or `block`)",
            req.action
        )
    })?;
    // Windows rejects a port on the `any` protocol with a bare E_INVALIDARG, so
    // say what is wrong while the request is still in our hands. (`netsh` said
    // "The number of arguments provided is not valid" for the same mistake.)
    if (req.local_port.is_some() || req.remote_port.is_some()) && req.protocol.is_none() {
        anyhow::bail!(
            "a rule that names a port also needs `protocol` (`tcp` or `udp`) - Windows has no \
             port rule on the `any` protocol"
        );
    }
    let protocol = match &req.protocol {
        Some(word) => Some(protocol_of(word).with_context(|| {
            format!("`{word}` is not an IP protocol (use `any`, `tcp`, `udp` or a number)")
        })?),
        None => None,
    };

    let firewall = Firewall::open()?;
    let rules = firewall.rules()?;
    // SAFETY: `NetFwRule` is the documented class id for one rule object; every
    // property below is set before the object is added to the collection.
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .context("the firewall refused to create a rule object")?;
    let bstr = |value: &str| BSTR::from(value);
    unsafe {
        rule.SetName(&bstr(&name))
            .context("the rule name was refused")?;
        rule.SetDescription(&bstr(RULE_DESCRIPTION))?;
        rule.SetGrouping(&bstr(RULE_GROUP))?;
        rule.SetDirection(direction)?;
        rule.SetAction(action)?;
        rule.SetEnabled(VARIANT_BOOL::from(true))?;
        // "Any profile", the same reach `netsh` gave a rule it was not told a
        // profile for - except the API's default is *no* profile at all, so
        // leaving this out would create a rule that never fires.
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        if let Some(program) = &req.program {
            rule.SetApplicationName(&bstr(program)).with_context(|| {
                format!("`{program}` was refused as the program of the rule")
            })?;
        }
        if let Some(protocol) = protocol {
            rule.SetProtocol(protocol.0)?;
        }
        if let Some(ports) = &req.local_port {
            rule.SetLocalPorts(&bstr(ports))?;
        }
        if let Some(ports) = &req.remote_port {
            rule.SetRemotePorts(&bstr(ports))?;
        }
        if let Some(addresses) = &req.remote_ip {
            rule.SetRemoteAddresses(&bstr(addresses))?;
        }
        rules
            .Add(&rule)
            .with_context(|| format!("the firewall refused to add the rule {name}"))?;
    }
    info!("Created firewall rule {name} through the firewall API");
    Ok(name)
}

/// Removes one `MICS-` rule by its canonical name (`owned_rule_name`), so the
/// prefixed and unprefixed spellings of a name reach the same rule.
///
/// Removing a rule that is already gone is a success, not an error: the caller
/// asked for it to not be there, and `block_country` removes before it adds. A
/// name that is only the prefix is still refused, because that is a caller
/// mistake rather than a rule that happens to be absent.
pub fn remove_rule_now(name: &str) -> Result<()> {
    let full = owned_rule_name(name)?;
    let firewall = Firewall::open()?;
    let rules = firewall.rules()?;
    // SAFETY: a collection call with an owned string.
    match unsafe { rules.Remove(&BSTR::from(full.as_str())) } {
        Ok(()) => {
            info!("Removed firewall rule {full}");
            Ok(())
        }
        Err(e) if is_missing(&e) => {
            info!("Firewall rule {full} was already gone");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "the firewall refused to remove {full}: {e}"
        )),
    }
}

/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)` - the rule was not there. Windows
/// returns `S_OK` for that case in most builds; this covers the ones that do not.
fn is_missing(e: &windows::core::Error) -> bool {
    let low_word = (e.code().0 as u32) & 0xFFFF;
    low_word == ERROR_FILE_NOT_FOUND.0
}

/// Turns one `VARIANT` from the rule enumerator into a rule we own.
///
/// The firewall hands out an `IDispatch` (measured: `vt = 9`); the uniform
/// `IUnknown` path is kept for a Windows that hands out `VT_UNKNOWN` instead.
/// Either way the interface is cloned before the `VARIANT` is dropped, so no
/// reference is released twice.
fn as_rule(item: &VARIANT) -> Result<INetFwRule> {
    let not_a_rule = "the firewall's rule list contained something that is not a rule";
    if let Ok(dispatch) = IDispatch::try_from(item) {
        return dispatch.cast().context(not_a_rule);
    }
    let unknown = IUnknown::try_from(item).context(not_a_rule)?;
    unknown.cast().context(not_a_rule)
}

/// Walks a COM collection. `INetFwRules` has no indexer, so the only way to see
/// every rule is its enumerator; the `VARIANT`s it hands out own one reference
/// each, which `as_rule` turns into an owned interface.
fn enumerate(rules: &INetFwRules) -> Result<Vec<INetFwRule>> {
    let mut found = Vec::new();
    // SAFETY: a property call on a live collection interface.
    let unknown = unsafe { rules._NewEnum() }
        .context("the firewall refused to enumerate its rules")?;
    let enumerator: IEnumVARIANT = unknown
        .cast()
        .context("the firewall's rule list is not an enumerator")?;
    loop {
        let mut item = [VARIANT::default(); 1];
        let mut fetched = 0u32;
        // SAFETY: one-element buffer, length passed by the binding.
        let hr = unsafe { enumerator.Next(&mut item, &mut fetched) };
        // S_FALSE (not an error) is the end of the list; a real error stops too.
        if hr.is_err() || fetched == 0 {
            break;
        }
        found.push(as_rule(&item[0])?);
    }
    Ok(found)
}

pub struct FirewallManager;

impl FirewallManager {
    /// Default-Deny Outbound per profile (1 = Block, 0 = Allow).
    pub async fn set_default_deny_outbound(enabled: bool) -> Result<()> {
        if elevated() {
            return set_default_deny_now(enabled);
        }
        crate::privileged::run_op(&crate::privileged::Op::FirewallDefaultDeny { enabled })
            .map(|_| ())
    }

    /// True only when **every** profile blocks outbound, so a half-changed
    /// firewall cannot show up as "on".
    pub async fn is_default_deny_enabled() -> Result<bool> {
        let firewall = Firewall::open()?;
        for (profile, name) in PROFILES {
            // SAFETY: typed property read on a live interface.
            let action = unsafe { firewall.policy.get_DefaultOutboundAction(profile) }
                .with_context(|| format!("the {name} profile's outbound policy could not be read"))?;
            if action != NET_FW_ACTION_BLOCK {
                info!("the {name} profile still allows outbound traffic");
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Reads every firewall rule owned by MI CS (MICS-* prefix).
    pub async fn list_rules() -> Result<Vec<FirewallRule>> {
        let firewall = Firewall::open()?;
        let rules = firewall.rules()?;
        let mut found = Vec::new();
        for rule in enumerate(&rules)? {
            // SAFETY: property reads on a rule object the enumerator owns.
            unsafe {
                let name = rule.Name()?.to_string();
                if !name.starts_with(RULE_PREFIX) {
                    continue;
                }
                found.push(FirewallRule {
                    name,
                    enabled: rule.Enabled()?.as_bool(),
                    direction: direction_name(rule.Direction()?).to_string(),
                    action: action_name(rule.Action()?).to_string(),
                    remote_ip: or_any(&rule.RemoteAddresses()?.to_string()),
                    local_port: or_any(&rule.LocalPorts()?.to_string()),
                    remote_port: or_any(&rule.RemotePorts()?.to_string()),
                });
            }
        }
        // The enumerator's order is Windows' business; the screens sort by name
        // so two reads of an unchanged firewall look the same.
        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(found)
    }

    pub async fn add_rule(req: &AddRuleRequest) -> Result<String> {
        // The name is checked in front of the privilege split on purpose: a
        // caller gets the same refusal whether the write would have happened in
        // this process or in the helper, instead of "no helper" on an
        // unelevated machine and "not a name" on an elevated one.
        owned_rule_name(&req.name)?;
        if elevated() {
            return add_rule_now(req);
        }
        let value = crate::privileged::run_op(&crate::privileged::Op::FirewallAddRule {
            rule: req.clone(),
        })?;
        value
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("the privileged helper did not name the new rule"))
    }

    pub async fn remove_rule(name: &str) -> Result<()> {
        // Same reason as `add_rule`: the name rule is the caller's business, not
        // the privilege split's. The helper re-checks it in `remove_rule_now`.
        owned_rule_name(name)?;
        if elevated() {
            return remove_rule_now(name);
        }
        crate::privileged::run_op(&crate::privileged::Op::FirewallRemoveRule {
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Country block: builds one MICS-BLOCK-<CC> rule from the bundled CIDR
    /// list in <rules dir>/blocklists/<CC>.cidr. Offline-first: if the list
    /// is not synced yet, this returns a clear error instead of guessing.
    pub async fn block_country(cc: &str) -> Result<String> {
        let cc = cc.to_uppercase();
        let path = blocklist_path(&cc)?;
        if !path.exists() {
            anyhow::bail!(
                "no local blocklist for {cc} — run sync.now first (intel feeds land in rules/blocklists/)"
            );
        }
        let content = std::fs::read_to_string(&path)?;
        let cidrs = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>();
        if cidrs.is_empty() {
            anyhow::bail!("blocklist for {cc} is empty");
        }
        let name = format!("BLOCK-{cc}");
        let _ = Self::remove_rule(&name).await;
        // One comma-separated address set, exactly as `netsh` received it.
        // Windows documents no ceiling for `RemoteAddresses` and MI CS has not
        // measured what a country-sized list does to the call (changing the
        // firewall needs administrator rights), so this stays one rule instead
        // of guessing a chunk size - the open question is in the register (§7).
        let req = AddRuleRequest {
            name,
            direction: "out".into(),
            action: "block".into(),
            protocol: Some("any".into()),
            remote_ip: Some(cidrs.join(",")),
            local_port: None,
            remote_port: None,
            program: None,
        };
        Self::add_rule(&req).await
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AddRuleRequest {
    pub name: String,
    pub direction: String, // in | out
    pub action: String,    // allow | block
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub remote_ip: Option<String>,
    #[serde(default)]
    pub local_port: Option<String>,
    #[serde(default)]
    pub remote_port: Option<String>,
    #[serde(default)]
    pub program: Option<String>,
}

fn blocklist_path(cc: &str) -> Result<PathBuf> {
    let base = std::env::var("MICS_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("PROGRAMDATA")
                .map(|p| PathBuf::from(p).join("MICS").join("blocklists"))
                .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\blocklists"))
        });
    std::fs::create_dir_all(&base).ok();
    Ok(base.join(format!("{cc}.cidr")))
}
