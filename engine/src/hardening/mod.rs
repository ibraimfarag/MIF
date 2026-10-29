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

/// Runs PowerShell with a hard deadline.
///
/// A UAC prompt that nobody answers used to block this thread (and the UI's
/// busy spinner) forever, because `Start-Process -Verb RunAs -Wait` simply
/// waits. A timeout turns that into a clear, actionable error instead.
fn ps_run_with_timeout(args: &[&str], timeout: std::time::Duration) -> Result<(bool, String)> {
    use std::io::Read;
    use std::process::Stdio;
    let mut command = std::process::Command::new("powershell");
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    // Never flash a console window at the user (GUI parent process).
    crate::platform::windows::elevation::hide_console(&mut command);
    let mut child = command.spawn().context("launch powershell")?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait()? {
            Some(status) => {
                let mut text = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut text);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut text);
                }
                return Ok((status.success(), text));
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!(
                        "the operation did not finish within {}s — a UAC prompt may have been \
                         cancelled or left unanswered",
                        timeout.as_secs()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

fn ps_run(command: &str) -> Result<String> {
    let (ok, text) =
        ps_run_with_timeout(&["-NoProfile", "-Command", command], std::time::Duration::from_secs(60))?;
    if !ok && !text.contains("elevation") {
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
    // Elevation needs room for the user to read and answer the prompt.
    let (ok, text) = ps_run_with_timeout(
        &["-NoProfile", "-Command", &ps_arg],
        std::time::Duration::from_secs(120),
    )?;
    if !ok {
        anyhow::bail!("elevated powershell failed: {}", text.trim());
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
            // Defender's own settings API requires an elevated token.
            true,
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

    // If the engine already has an elevated token (the normal case: the UI
    // manifest requests administrator), run the command directly — a second
    // self-elevation would only add a pointless UAC prompt attributed to
    // PowerShell. Only unelevated engines need the RunAs path.
    let result = if needs_admin && !crate::platform::windows::elevation::is_elevated() {
        ps_run_elevated(&cmd).map_err(|e| {
            anyhow::anyhow!(
                "{e}\nThis fix changes a system-wide setting. Start MI CS from its normal \
                 shortcut (Windows asks for permission once at launch) or run it as \
                 administrator, then retry."
            )
        })
    } else {
        ps_run(&cmd)
            .map(|_| ())
            .map_err(|e| {
                anyhow::anyhow!(
                    "{e}\nIf the message above mentions permissions, MI CS is running without \
                     administrator rights."
                )
            })
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
