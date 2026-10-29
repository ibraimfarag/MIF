use anyhow::{Context, Result};
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

fn run_netsh(args: &[&str]) -> Result<String> {
    match run_netsh_plain(args) {
        Ok(t) => Ok(t),
        Err(e) if format!("{e:#}").contains("elevation") => {
            // Architecture rule 3: the engine self-elevates on demand
            // (ShellExecuteW runas equivalent) for admin-required ops.
            info!("netsh needs elevation — relaunching with runas");
            run_netsh_elevated(args)
        }
        Err(e) => Err(e),
    }
}

fn run_netsh_plain(args: &[&str]) -> Result<String> {
    let mut command = std::process::Command::new("netsh");
    command.args(["advfirewall"]).args(args);
    // The engine is a GUI-adjacent process: a console window must never flash.
    crate::platform::windows::elevation::hide_console(&mut command);
    let out = command
        .output()
        .context("failed to launch netsh (firewall op)")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() && !text.contains("Ok.") && !text.contains("OK") {
        anyhow::bail!("netsh failed: {}", text.trim());
    }
    Ok(text)
}

fn run_netsh_elevated(args: &[&str]) -> Result<String> {
    // netsh args used here contain no spaces, so a bare PowerShell array
    // avoids nested-quote pitfalls entirely.
    let arg_line = std::iter::once("advfirewall")
        .chain(args.iter().copied())
        .map(|a| format!("'{a}'"))
        .collect::<Vec<_>>()
        .join(",");
    let ps_arg = format!(
        "Start-Process -FilePath netsh -ArgumentList {arg_line} -Verb RunAs -Wait -WindowStyle Hidden"
    );
    let mut command = std::process::Command::new("powershell");
    command.args(["-NoProfile", "-Command", &ps_arg]);
    crate::platform::windows::elevation::hide_console(&mut command);
    let out = command
        .output()
        .context("failed to launch elevated netsh")?;
    if !out.status.success() {
        anyhow::bail!(
            "elevated netsh failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // Re-read state through a plain (non-admin) query to confirm.
    run_netsh_plain(&["show", "domainprofile", "state"])
        .map(|_| String::new())
        .map_err(|e| anyhow::anyhow!("elevated op did not apply: {e:#}"))
}

pub struct FirewallManager;

impl FirewallManager {
    /// Default-Deny Outbound per profile (1 = Block, 0 = Allow).
    pub async fn set_default_deny_outbound(enabled: bool) -> Result<()> {
        let policy = if enabled { "blockoutbound" } else { "allowoutbound" };
        info!("Setting default outbound policy -> {policy}");
        for profile in ["domainprofile", "privateprofile", "publicprofile"] {
            run_netsh(&["set", profile, "firewallpolicy", policy, "allowinbound"])?;
        }
        Ok(())
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

    pub async fn remove_rule(name: &str) -> Result<()> {
        let name = name.strip_prefix(RULE_PREFIX).map(|s| s.to_string()).unwrap_or_else(|| name.to_string());
        let full = format!("{}{}", RULE_PREFIX, name);
        let _ = run_netsh(&["firewall", "delete", "rule", &format!("name={full}")])?;
        info!("Removed firewall rule {full}");
        Ok(())
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

#[derive(Debug, Serialize, Deserialize)]
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
