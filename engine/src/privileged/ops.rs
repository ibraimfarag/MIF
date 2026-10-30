//! The privileged operation surface, in one place (D-007).
//!
//! No admin work happens inside the unelevated engine any more. The engine sends
//! one of these ops over `\\.\pipe\mics_helper` to the `MICSHelper` service,
//! which runs as LocalSystem with a single UAC prompt at install time.
//!
//! The set is a **closed enum on purpose**: the helper cannot be talked into
//! running an arbitrary command line, so a bug (or a confused caller) can only
//! ask for one of the operations that are documented in
//! `docs/PRIVILEGED-OPS.md`. Every call is logged by the helper before it runs.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Pipe the helper listens on. `MICS_HELPER_PIPE` is the test hook.
pub const DEFAULT_PIPE: &str = "mics_helper";

/// Windows service name (also the `sc.exe` key).
pub const SERVICE_NAME: &str = "MICSHelper";

pub const MAX_HOSTS_BYTES: usize = 4 * 1024 * 1024;

/// The marker the IDS section carries; a hosts file without it is refused so a
/// bug can never hand the helper an arbitrary file to overwrite.
pub const HOSTS_MARKER: &str = "# BEGIN MICS-IDS";

pub fn pipe_name() -> String {
    std::env::var("MICS_HELPER_PIPE").unwrap_or_else(|_| DEFAULT_PIPE.to_string())
}

/// One privileged operation. `op` is the serde tag, so the wire format is
/// `{"op":"firewall.add_rule","rule":{...}}` — the names are the documented
/// ones in `docs/PRIVILEGED-OPS.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Op {
    /// Liveness probe: the helper answers without touching the machine.
    #[serde(rename = "ping")]
    Ping,
    /// Build version, so the UI can tell an outdated helper from a dead one.
    #[serde(rename = "version")]
    Version,
    #[serde(rename = "firewall.default_deny")]
    FirewallDefaultDeny { enabled: bool },
    #[serde(rename = "firewall.add_rule")]
    FirewallAddRule { rule: crate::firewall::AddRuleRequest },
    #[serde(rename = "firewall.remove_rule")]
    FirewallRemoveRule { name: String },
    /// Replaces the system hosts file with a prepared document (the caller has
    /// already taken its snapshot).
    #[serde(rename = "hosts.write")]
    HostsWrite { content: String },
    /// Runs one hardening fix by id; the helper owns the command table.
    #[serde(rename = "hardening.run")]
    HardeningRun { action: String },
    /// Re-applies a snapshot's old state. The script is allow-listed by shape.
    #[serde(rename = "hardening.rollback")]
    HardeningRollback { snapshot: String },
}

impl Op {
    /// Short, log-safe description: the audit log must never contain a whole
    /// hosts file, and it must be readable by a human debugging an incident.
    pub fn audit_summary(&self) -> String {
        match self {
            Op::Ping => "ping".into(),
            Op::Version => "version".into(),
            Op::FirewallDefaultDeny { enabled } => format!("firewall.default_deny enabled={enabled}"),
            Op::FirewallAddRule { rule } => format!(
                "firewall.add_rule name={} dir={} action={}",
                rule.name, rule.direction, rule.action
            ),
            Op::FirewallRemoveRule { name } => format!("firewall.remove_rule name={name}"),
            Op::HostsWrite { content } => format!(
                "hosts.write bytes={} lines={} sha256={}",
                content.len(),
                content.lines().count(),
                sha256_hex(content.as_bytes())
            ),
            Op::HardeningRun { action } => format!("hardening.run action={action}"),
            Op::HardeningRollback { snapshot } => format!(
                "hardening.rollback lines={} sha256={}",
                snapshot.lines().count(),
                sha256_hex(snapshot.as_bytes())
            ),
        }
    }

    /// Refuses an op whose payload does not match the shape it claims to have.
    /// Called by the helper **before** anything is executed or logged, so a bad
    /// request is reported instead of being half-applied.
    pub fn validate(&self) -> Result<()> {
        match self {
            Op::Ping | Op::Version => Ok(()),
            Op::FirewallDefaultDeny { .. } => Ok(()),
            Op::FirewallAddRule { rule } => {
                if rule.name.trim().is_empty() {
                    bail!("firewall rule needs a name");
                }
                if !matches!(rule.direction.as_str(), "in" | "out") {
                    bail!("firewall rule direction must be \"in\" or \"out\"");
                }
                if !matches!(rule.action.as_str(), "allow" | "block") {
                    bail!("firewall rule action must be \"allow\" or \"block\"");
                }
                Ok(())
            }
            Op::FirewallRemoveRule { name } => {
                if name.trim().is_empty() {
                    bail!("firewall rule removal needs a name");
                }
                Ok(())
            }
            Op::HostsWrite { content } => validate_hosts(content),
            Op::HardeningRun { action } => crate::hardening::validate_action(action),
            Op::HardeningRollback { snapshot } => validate_rollback(snapshot),
        }
    }
}

/// Short hash of an op payload, so the audit log can prove *what* was sent
/// without storing the whole document.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())[..16].to_string()
}

/// A hosts document may only contain comments, blank lines and `ip host`
/// pairs. Anything else means the document was not built by the IDS code path.
pub fn validate_hosts(content: &str) -> Result<()> {
    if content.len() > MAX_HOSTS_BYTES {
        bail!(
            "hosts document is too large ({} bytes, limit {MAX_HOSTS_BYTES})",
            content.len()
        );
    }
    if !content.contains(HOSTS_MARKER) {
        bail!("hosts document does not contain the MI CS marker");
    }
    for (index, line) in content.lines().enumerate() {
        // A hosts entry may carry a trailing comment (`127.0.0.1 host # note`).
        let line = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line.trim(),
        };
        if line.is_empty() {
            continue;
        }
        if !is_hosts_entry(line) {
            bail!(
                "hosts line {} is not an address/host pair: {:?}",
                index + 1,
                line
            );
        }
    }
    Ok(())
}

fn is_hosts_entry(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    let Some(address) = parts.next() else {
        return false;
    };
    if address.parse::<Ipv4Addr>().is_err() && address.parse::<Ipv6Addr>().is_err() {
        return false;
    }
    let mut hosts = 0usize;
    for host in parts {
        hosts += 1;
        let valid = !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
        if !valid {
            return false;
        }
    }
    hosts > 0
}

/// A rollback script is generated by `hardening::snapshot_current`, so its
/// possible shapes are known: registry writes under `HKLM`, the SMBv1 switch and
/// the Defender PUA preference. Everything else is refused — a snapshot that
/// cannot be expressed in these shapes is a bug, not something to "just run".
pub fn validate_rollback(snapshot: &str) -> Result<()> {
    if snapshot.trim().is_empty() {
        bail!("rollback script is empty");
    }
    if snapshot.lines().count() > 8 {
        bail!("rollback script has too many lines");
    }
    for line in snapshot.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        for command in line.split(';') {
            let command = command.trim();
            if command.is_empty() {
                continue;
            }
            if !is_allowed_rollback_command(command) {
                bail!("refused rollback command: {command}");
            }
        }
    }
    Ok(())
}

fn is_allowed_rollback_command(command: &str) -> bool {
    if let Some(rest) = command.strip_prefix("reg add ") {
        // reg add "HKLM\KEY" /v NAME [/t REG_DWORD] /d N /f
        let Some((key, tail)) = quoted_key(rest) else {
            return false;
        };
        let Some((name, tail)) = token_after(tail, "/v ") else {
            return false;
        };
        let (kind, tail) = token_after(tail, "/t ").unwrap_or(("REG_DWORD", tail));
        let Some((data, tail)) = token_after(tail, "/d ") else {
            return false;
        };
        return kind.eq_ignore_ascii_case("REG_DWORD")
            && !name.is_empty()
            && !data.is_empty()
            && data.chars().all(|c| c.is_ascii_digit())
            && tail == "/f"
            && is_hklm_key(&key);
    }
    if let Some(rest) = command.strip_prefix("reg delete ") {
        let Some((key, tail)) = quoted_key(rest) else {
            return false;
        };
        let Some((name, tail)) = token_after(tail, "/v ") else {
            return false;
        };
        return !name.is_empty() && tail == "/f" && is_hklm_key(&key);
    }
    if let Some(rest) = command.strip_prefix("Set-SmbServerConfiguration -EnableSMB1Protocol ")
    {
        let value = rest.strip_suffix(" -Force").unwrap_or(rest).trim();
        return matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "false" | "$true" | "$false"
        );
    }
    if let Some(rest) = command.strip_prefix("Set-MpPreference -PUAProtection ") {
        let value = rest.trim();
        return matches!(
            value.to_ascii_lowercase().as_str(),
            "enabled" | "disabled" | "0" | "1" | "2"
        );
    }
    false
}

/// `"HKLM\KEY" rest` → (`HKLM\KEY`, `rest`). A key that is not absolute, or
/// that tries to walk out of its own hive, is not a shape we generate.
fn quoted_key(text: &str) -> Option<(String, &str)> {
    let rest = text.trim_start().strip_prefix('"')?;
    let (key, tail) = rest.split_once('"')?;
    Some((key.trim().to_string(), tail.trim_start()))
}

fn is_hklm_key(key: &str) -> bool {
    key.starts_with("HKLM\\") && !key.contains("..") && !key.contains('/')
}

/// `tail` must start with `flag` and then one whitespace-delimited token;
/// returns (token, remainder).
fn token_after<'a>(tail: &'a str, flag: &str) -> Option<(&'a str, &'a str)> {
    let rest = tail.strip_prefix(flag)?;
    let (token, after) = rest.split_once(' ')?;
    Some((token.trim(), after.trim_start()))
}

/// Parses the helper's own response envelope.
pub fn parse_response(line: &str) -> Result<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_str(line).with_context(|| format!("helper sent an invalid response: {line}"))?;
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let message = value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("the privileged helper refused the operation");
        bail!("{message}");
    }
    Ok(value.get("data").cloned().unwrap_or(serde_json::Value::Null))
}

/// Encodes one request as the newline-delimited frame the pipe carries.
pub fn encode(op: &Op) -> Result<String> {
    let mut line = serde_json::to_string(op)?;
    line.push('\n');
    Ok(line)
}