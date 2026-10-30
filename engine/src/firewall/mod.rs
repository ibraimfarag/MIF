use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

/// Real Windows Firewall management via `netsh advfirewall` — the engine's
/// supported path for whitelist commands. Every rule the engine creates is
/// prefixed `MICS-` so list/remove never touch rules it doesn't own.
pub const RULE_PREFIX: &str = "MICS-";

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

/// How long one `netsh` call may take. The firewall service can restart or get
/// stuck; a request thread must not wait for it forever.
const NETSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

fn run_netsh(args: &[&str]) -> Result<String> {
    run_netsh_plain(args)
}

fn run_netsh_plain(args: &[&str]) -> Result<String> {
    let mut full = vec!["advfirewall"];
    full.extend_from_slice(args);
    // Deadline + background readers: `show rule verbose` prints far more than a
    // pipe buffer, so waiting without draining would time out a healthy netsh.
    let out = crate::platform::windows::process::run_with_deadline(
        "netsh",
        &full,
        "netsh (firewall)",
        NETSH_TIMEOUT,
    )?;
    let text = out.text;
    if !out.success && !text.contains("Ok.") && !text.contains("OK") {
        anyhow::bail!("netsh failed: {}", text.trim());
    }
    Ok(text)
}

/// True when the current process can run `netsh` writes itself.
///
/// When it cannot, the operation goes to the privileged helper (D-007) instead
/// of asking Windows for a fresh UAC prompt per call.
fn elevated() -> bool {
    crate::platform::windows::elevation::is_elevated()
}

/// Default-Deny Outbound per profile (1 = Block, 0 = Allow). Elevation is the
/// caller's business — this is the body the helper runs.
pub fn set_default_deny_now(enabled: bool) -> Result<()> {
    let policy = if enabled { "blockoutbound" } else { "allowoutbound" };
    info!("Setting default outbound policy -> {policy}");
    for profile in ["domainprofile", "privateprofile", "publicprofile"] {
        run_netsh(&["set", profile, "firewallpolicy", policy, "allowinbound"])?;
    }
    Ok(())
}

/// Creates one `MICS-`-prefixed rule. Shared by the engine and the helper.
pub fn add_rule_now(req: &AddRuleRequest) -> Result<String> {
    let name = format!("{}{}", RULE_PREFIX, req.name);
    let mut args = vec![
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={name}"),
        format!("dir={}", req.direction),
        format!("action={}", req.action),
        "enable=yes".to_string(),
    ];
    if let Some(p) = &req.program {
        args.push(format!("program={p}"));
    }
    if let Some(p) = &req.local_port {
        args.push(format!("localport={p}"));
    }
    if let Some(p) = &req.remote_port {
        args.push(format!("remoteport={p}"));
    }
    if let Some(p) = &req.remote_ip {
        args.push(format!("remoteip={p}"));
    }
    if let Some(p) = &req.protocol {
        args.push(format!("protocol={p}"));
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_netsh(&arg_refs)?;
    info!("Created firewall rule {name}");
    Ok(name)
}

/// Removes one `MICS-` rule (the prefix is optional in the argument).
pub fn remove_rule_now(name: &str) -> Result<()> {
    let name = name
        .strip_prefix(RULE_PREFIX)
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_string());
    let full = format!("{}{}", RULE_PREFIX, name);
    let _ = run_netsh(&["firewall", "delete", "rule", &format!("name={full}")])?;
    info!("Removed firewall rule {full}");
    Ok(())
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

    pub async fn is_default_deny_enabled() -> Result<bool> {
        let text = run_netsh(&["show", "domainprofile", "state"])?;
        Ok(text.contains("BlockOutbound") || text.contains("blockoutbound"))
    }

    /// Reads every firewall rule owned by MI CS (MICS-* prefix).
    pub async fn list_rules() -> Result<Vec<FirewallRule>> {
        let text = run_netsh(&["firewall", "show", "rule", "name=all", "verbose"])?;
        let mut rules = Vec::new();
        let mut current: Option<FirewallRule> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if let Some(rest) = line.strip_prefix("Rule Name:") {
                if let Some(r) = current.take()
                    && r.name.starts_with(RULE_PREFIX) {
                        rules.push(r);
                    }
                current = Some(FirewallRule {
                    name: rest.trim().to_string(),
                    enabled: false,
                    direction: String::new(),
                    action: String::new(),
                    remote_ip: String::new(),
                    local_port: String::new(),
                    remote_port: String::new(),
                });
                continue;
            }
            let Some(r) = current.as_mut() else { continue };
            if let Some(v) = line.strip_prefix("Enabled:") {
                r.enabled = v.trim().eq_ignore_ascii_case("yes");
            } else if let Some(v) = line.strip_prefix("Direction:") {
                r.direction = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Action:") {
                r.action = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("LocalPort:") {
                r.local_port = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("RemotePort:") {
                r.remote_port = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("RemoteIP:") {
                r.remote_ip = v.trim().to_string();
            }
        }
        if let Some(r) = current.take()
            && r.name.starts_with(RULE_PREFIX) {
                rules.push(r);
            }
        Ok(rules)
    }

    pub async fn add_rule(req: &AddRuleRequest) -> Result<String> {
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
        // netsh accepts a comma-separated remoteip set; keep batches conservative.
        let joined = cidrs.join(",");
        let req = AddRuleRequest {
            name,
            direction: "out".into(),
            action: "block".into(),
            protocol: Some("any".into()),
            remote_ip: Some(joined),
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
