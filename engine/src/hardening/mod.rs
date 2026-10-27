//! Hardening Center: one-click security fixes with snapshots for rollback.
//! Each fix: snapshot current state -> apply via PowerShell/registry ->
//! record the snapshot so hardening.rollback can restore it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::storage::sqlite::Storage;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HardeningAction {
    pub id: String,
    pub name: String,
    pub name_ar: String,
    pub explanation: String,
    pub applied: bool,
}

/// All supported fixes, with live current-state detection.
pub fn list_actions() -> Vec<HardeningAction> {
    vec![
        HardeningAction {
            id: "pua_protection".into(),
            name: "Enable Defender PUA protection".into(),
            name_ar: "تفعيل حماية ديفندر من البرامج غير المرغوبة".into(),
            explanation: "Blocks potentially unwanted applications (adware, bundlers)."
                .into(),
            applied: crate::platform::windows::collectors::WindowsCollectors
                .pua_enabled(),
        },
        HardeningAction {
            id: "smbv1_off".into(),
            name: "Disable SMBv1".into(),
            name_ar: "تعطيل SMBv1".into(),
            explanation: "Removes the EternalBlue-class worm surface (WannaCry/NotPetya)."
                .into(),
            applied: !crate::platform::windows::collectors::WindowsCollectors
                .smbv1_enabled(),
        },
        HardeningAction {
            id: "rdp_off".into(),
            name: "Disable Remote Desktop (RDP)".into(),
            name_ar: "تعطيل سطح المكتب البعيد".into(),
            explanation: "Closes the most-brute-forced remote entry point when unused."
                .into(),
            applied: crate::platform::windows::collectors::WindowsCollectors
                .rdp_disabled(),
        },
        HardeningAction {
            id: "uac_on".into(),
            name: "Enable UAC + Secure Desktop".into(),
            name_ar: "تفعيل UAC مع سطح المكتب الآمن".into(),
            explanation: "Every admin action needs explicit consent on a protected desktop."
                .into(),
            applied: crate::platform::windows::collectors::WindowsCollectors
                .uac_enabled(),
        },
        HardeningAction {
            id: "defender_scan_quick".into(),
            name: "Trigger a Defender quick scan".into(),
            name_ar: "تشغيل فحص سريع بديفندر".into(),
            explanation: "Orchestrates Windows Defender's own engine (MpCmdRun).".into(),
            applied: false,
        },
    ]
}

fn ps_run(command: &str) -> Result<String> {
    // Elevation-aware PowerShell runner (same path as firewall ops).
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", command])
        .output()
        .context("launch powershell")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() && !text.contains("elevation") {
        anyhow::bail!("powershell failed: {}", text.trim());
    }
    Ok(text)
}

fn ps_run_elevated(command: &str) -> Result<()> {
    let escaped = command.replace('\'', "''");
    let ps_arg = format!(
        "Start-Process -FilePath powershell -ArgumentList @('-NoProfile','-Command','{}') -Verb RunAs -Wait -WindowStyle Hidden",
        escaped
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_arg])
        .output()
        .context("launch elevated powershell")?;
    if !out.status.success() {
        anyhow::bail!(
            "elevated powershell failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn snapshot_dir() -> PathBuf {
    std::env::var("PROGRAMDATA")
        .map(|p| PathBuf::from(p).join("MICS").join("hardening"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\hardening"))
}

/// Applies one hardening fix. Snapshots the touched state first; rollback
/// restores exactly what was snapshotted (never guesses).
pub async fn apply(action_id: &str) -> Result<String> {
    let snap = snapshot_current(action_id)?;
    let storage = Storage::open()?;
    storage.save_hardening_snapshot(action_id, &snap)?;

    let (cmd, needs_admin) = match action_id {
        "pua_protection" => (
            "Set-MpPreference -PUAProtection Enabled".to_string(),
            false,
        ),
        "smbv1_off" => (
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; \
             reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\" /v Start /t REG_DWORD /d 4 /f"
                .to_string(),
            true,
        ),
        "rdp_off" => (
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f"
                .to_string(),
            true,
        ),
        "uac_on" => (
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f; \
             reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f"
                .to_string(),
            true,
        ),
        "defender_scan_quick" => (
            "Start-Process -FilePath 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -ArgumentList '-Scan','-ScanType','1' -WindowStyle Hidden"
                .to_string(),
            false,
        ),
        _ => anyhow::bail!("unknown hardening action {action_id}"),
    };

    let result = if needs_admin {
        ps_run_elevated(&cmd)
    } else {
        ps_run(&cmd).map(|_| ())
    };
    match result {
        Ok(()) => {
            storage.mark_hardening_applied(action_id, true)?;
            Ok(snap)
        }
        Err(e) => {
            storage.mark_hardening_applied(action_id, false)?;
            Err(e)
        }
    }
}

/// Captures the exact values a rollback would restore, as a PowerShell
/// script that re-applies the OLD state.
fn snapshot_current(action_id: &str) -> Result<String> {
    let script = match action_id {
        "pua_protection" => "Set-MpPreference -PUAProtection (Get-MpPreference).PUAProtection",
        "smbv1_off" => {
            "$s=(Get-SmbServerConfiguration).EnableSMB1Protocol; $m=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' -ErrorAction SilentlyContinue).Start; \"Set-SmbServerConfiguration -EnableSMB1Protocol `$s -Force; reg add \\\"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\\\" /v Start /t REG_DWORD /d $m /f\""
        }
        "rdp_off" => {
            "$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections; \"reg add \\\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\\" /v fDenyTSConnections /t REG_DWORD /d $v /f\""
        }
        "uac_on" => {
            "$a=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA; $p=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').PromptOnSecureDesktop; \"reg add \\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\\" /v EnableLUA /t REG_DWORD /d $a /f; reg add \\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\\" /v PromptOnSecureDesktop /t REG_DWORD /d $p /f\""
        }
        _ => return Ok(String::new()), // scans have nothing to roll back
    };
    let out = ps_run(script)?;
    // Keep only the generated rollback command line(s).
    let rollback: String = out
        .lines()
        .filter(|l| l.contains("reg add") || l.contains("Set-Smb") || l.contains("Set-Mp"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(rollback)
}

pub async fn rollback(action_id: &str) -> Result<()> {
    let storage = Storage::open()?;
    let snap = storage
        .latest_hardening_snapshot(action_id)?
        .ok_or_else(|| anyhow::anyhow!("no snapshot recorded for {action_id}"))?;
    if snap.trim().is_empty() {
        anyhow::bail!("snapshot is empty — nothing to roll back");
    }
    ps_run_elevated(&snap)?;
    storage.mark_hardening_applied(action_id, false)?;
    Ok(())
}

#[allow(dead_code)]
pub fn snapshots_list() -> Result<Vec<(String, String, i64)>> {
    Storage::open()?.list_hardening_snapshots()
}
