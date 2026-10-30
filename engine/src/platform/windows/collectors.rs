use crate::platform::traits::{
    AuditFinding, FindingStatus, NetworkConnection, PlatformCollectors, ScheduledTaskEntry,
    Severity, SoftwareEntry, StartupEntry,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tracing::warn;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET as AF;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ, KEY_WOW64_32KEY, REG_VALUE_TYPE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};

pub struct WindowsCollectors;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn read_dword(root: HKEY, subkey: &str, value: &str) -> Option<u32> {
    let sk = to_wide(subkey);
    let v = to_wide(value);
    let mut data: u32 = 0;
    let mut size = 4u32;
    let mut ty = REG_VALUE_TYPE(0);
    let err = unsafe {
        RegGetValueW(
            root,
            PCWSTR(sk.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_DWORD,
            Some(&mut ty),
            Some(&mut data as *mut u32 as *mut _),
            Some(&mut size),
        )
    };
    (err == ERROR_SUCCESS).then_some(data)
}

fn read_string(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let sk = to_wide(subkey);
    let v = to_wide(value);
    let mut len: u32 = 0;
    let err = unsafe {
        RegGetValueW(
            root,
            PCWSTR(sk.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut len),
        )
    };
    if err != ERROR_SUCCESS || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    let err = unsafe {
        RegGetValueW(
            root,
            PCWSTR(sk.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut len),
        )
    };
    if err != ERROR_SUCCESS {
        return None;
    }
    // Returned buffer is UTF-16LE, possibly without the trailing nul.
    let words: Vec<u16> = buf
        .as_chunks::<2>().0.iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&words);
    Some(s.trim_end_matches('\0').to_string())
}

/// Enumerates subkey names under `subkey` (opened with KEY_WOW64_32KEY where
/// callers pass the 32-bit view flag for the Uninstall hives).
fn enum_subkeys(root: HKEY, subkey: &str, extra_access: Option<REGSAM>) -> Vec<String> {
    use windows::Win32::System::Registry::RegOpenKeyExW;
    let sk = to_wide(subkey);
    let mut hkey = HKEY::default();
    let access = KEY_READ | extra_access.unwrap_or(REGSAM(0));
    let err = unsafe {
        RegOpenKeyExW(root, PCWSTR(sk.as_ptr()), None, access, &mut hkey)
    };
    if err != ERROR_SUCCESS {
        return Vec::new();
    }

    let mut names = Vec::new();
    for i in 0..4096u32 {
        let mut name_buf = [0u16; 260];
        let mut name_len = 260u32;
        let err = unsafe {
            RegEnumKeyExW(hkey, i, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None)
        };
        if err != ERROR_SUCCESS {
            break;
        }
        names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    names
}

use windows::Win32::System::Registry::REG_SAM_FLAGS as REGSAM;

fn finding(
    section: &str,
    item: &str,
    status: FindingStatus,
    severity: Severity,
    description: impl Into<String>,
    fix_available: bool,
) -> AuditFinding {
    AuditFinding {
        section: section.to_string(),
        item: item.to_string(),
        status,
        severity,
        description: description.into(),
        fix_available,
    }
}

#[async_trait]
impl PlatformCollectors for WindowsCollectors {
    async fn audit_defender(&self) -> Result<Vec<AuditFinding>> {
        let mut findings = Vec::new();
        const RTP: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
        const DEF: &str = r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";

        // Prefer the policy key; fall back to the live Defender key.
        let disabled = read_dword(HKEY_LOCAL_MACHINE, RTP, "DisableRealtimeMonitoring")
            .or_else(|| read_dword(HKEY_LOCAL_MACHINE, DEF, "DisableRealtimeMonitoring"));
        match disabled {
            Some(1) => findings.push(finding(
                "Defender",
                "Real-time Protection",
                FindingStatus::Vulnerable,
                Severity::Critical,
                "Windows Defender real-time protection is DISABLED".to_string(),
                true,
            )),
            Some(_) => findings.push(finding(
                "Defender",
                "Real-time Protection",
                FindingStatus::Secure,
                Severity::Critical,
                "Real-time protection is enabled".to_string(),
                false,
            )),
            None => {
                // Policy/live keys absent — ask Defender itself. A refused WMI
                // query still exits 0 with empty stdout, and reading that as
                // "disabled" raised a Critical false alarm on a healthy machine;
                // only a real boolean counts, everything else is honestly
                // unknown.
                match defender_rtp_state() {
                    Some(true) => findings.push(finding(
                        "Defender",
                        "Real-time Protection",
                        FindingStatus::Secure,
                        Severity::Critical,
                        "Real-time protection is enabled".to_string(),
                        false,
                    )),
                    Some(false) => findings.push(finding(
                        "Defender",
                        "Real-time Protection",
                        FindingStatus::Vulnerable,
                        Severity::Critical,
                        "Windows Defender real-time protection is DISABLED".to_string(),
                        true,
                    )),
                    None => findings.push(finding(
                        "Defender",
                        "Real-time Protection",
                        FindingStatus::Unknown,
                        Severity::High,
                        "Real-time protection state not readable (Defender's status API \
                         refused the query — another security product may own the machine, \
                         or MIF may need administrator rights)"
                            .to_string(),
                        false,
                    )),
                }
            }
        }

        // AntiSpyware enabled (the master on/off of the Defender engine).
        const AS: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender";
        if let Some(1) = read_dword(HKEY_LOCAL_MACHINE, AS, "DisableAntiSpyware") { findings.push(finding(
            "Defender",
            "AntiSpyware Engine",
            FindingStatus::Vulnerable,
            Severity::Critical,
            "Windows Defender AntiSpyware is disabled by policy".to_string(),
            true,
        )) }

        // PUA (potentially unwanted app) blocking, in Defender's own enum:
        // 0 = off, 1 = block, 2 = audit. Reading only the Group Policy key (as
        // this check used to) reported "not explicitly enabled" for a machine
        // that had the setting on through the Windows Security toggle or
        // Set-MpPreference, and then offered a repair that could not change
        // anything — a false positive with a broken fix attached.
        let (pua_status, pua_detail, pua_fixable) = pua_verdict(pua_state());
        findings.push(finding(
            "Defender",
            "PUA Protection",
            pua_status,
            Severity::Medium,
            pua_detail,
            pua_fixable,
        ));

        // Defender exclusions are a classic malware persistence trick — enumerate them all.
        const EXCL: &str = r"SOFTWARE\Microsoft\Windows Defender\Exclusions";
        let mut excluded = 0usize;
        for kind in ["Paths", "Extensions", "Processes", "IpAddresses"] {
            excluded += enum_subkeys(HKEY_LOCAL_MACHINE, &format!("{EXCL}\\{kind}"), None).len();
        }
        if excluded > 0 {
            findings.push(finding(
                "Defender",
                "Scan Exclusions",
                FindingStatus::Warning,
                Severity::High,
                format!("{excluded} Defender exclusion(s) configured — verify each one is trusted"),
                false,
            ));
        } else {
            findings.push(finding(
                "Defender",
                "Scan Exclusions",
                FindingStatus::Secure,
                Severity::High,
                "No Defender scan exclusions configured".to_string(),
                false,
            ));
        }

        Ok(findings)
    }

    async fn audit_firewall(&self) -> Result<Vec<AuditFinding>> {
        let mut findings = Vec::new();
        const POL: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        for (name, subkey) in [
            ("Domain", "DomainProfile"),
            ("Private", "StandardProfile"),
            ("Public", "PublicProfile"),
        ] {
            let enabled = read_dword(
                HKEY_LOCAL_MACHINE,
                &format!("{POL}\\{subkey}"),
                "EnableFirewall",
            )
            .or_else(|| {
                read_dword(
                    HKEY_LOCAL_MACHINE,
                    &format!(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{subkey}"),
                    "EnableFirewall",
                )
            });
            match enabled {
                Some(0) => findings.push(finding(
                    "Firewall",
                    &format!("{name} Profile"),
                    FindingStatus::Vulnerable,
                    Severity::High,
                    format!("Windows Firewall is DISABLED for the {name} profile"),
                    true,
                )),
                _ => findings.push(finding(
                    "Firewall",
                    &format!("{name} Profile"),
                    FindingStatus::Secure,
                    Severity::High,
                    format!("Firewall enabled for the {name} profile"),
                    false,
                )),
            }
        }

        // Default outbound action per profile (1 = allow — Windows default).
        for (name, subkey) in [
            ("Domain", "DomainProfile"),
            ("Private", "StandardProfile"),
            ("Public", "PublicProfile"),
        ] {
            let deny = read_dword(
                HKEY_LOCAL_MACHINE,
                &format!(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{subkey}"),
                "DefaultOutboundAction",
            );
            if deny == Some(1) {
                findings.push(finding(
                    "Firewall",
                    &format!("{name} Outbound Policy"),
                    FindingStatus::Secure,
                    Severity::Medium,
                    format!("{name} profile already uses Default-Deny Outbound"),
                    false,
                ));
            }
        }

        Ok(findings)
    }

    async fn audit_rdp(&self) -> Result<Vec<AuditFinding>> {
        const TERM: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
        let mut findings = Vec::new();
        match read_dword(HKEY_LOCAL_MACHINE, TERM, "fDenyTSConnections") {
            Some(0) => findings.push(finding(
                "Remote Access",
                "RDP",
                FindingStatus::Warning,
                Severity::High,
                "RDP (Remote Desktop) is ENABLED — a common brute-force target; disable if unused",
                true,
            )),
            Some(_) => findings.push(finding(
                "Remote Access",
                "RDP",
                FindingStatus::Secure,
                Severity::High,
                "RDP is disabled".to_string(),
                false,
            )),
            None => findings.push(finding(
                "Remote Access",
                "RDP",
                FindingStatus::Unknown,
                Severity::Medium,
                "RDP state not readable".to_string(),
                false,
            )),
        }

        // NLA requirement when RDP is on.
        let nla = read_dword(HKEY_LOCAL_MACHINE, TERM, "UserAuthentication");
        if nla == Some(0) {
            findings.push(finding(
                "Remote Access",
                "RDP Network Level Authentication",
                FindingStatus::Vulnerable,
                Severity::High,
                "RDP is exposed WITHOUT Network Level Authentication".to_string(),
                true,
            ));
        }

        Ok(findings)
    }

    async fn audit_smbv1(&self) -> Result<Vec<AuditFinding>> {
        let mut findings = Vec::new();
        // SMB1 server flag: 0 = disabled. The value is frequently *absent* on a
        // hardened Windows 10/11 (it is only written when someone changes it),
        // and `mrxsmb10` is absent when the SMBv1 feature was removed entirely.
        // Treating "absent" as "enabled" produced a critical false positive.
        let smb1 = read_dword(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        );
        let mrxsmb10 = read_dword(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
            "Start",
        );
        let server_on = smb1.map(|v| v != 0).unwrap_or(false);
        // Missing driver key = the legacy stack is not installed at all.
        let client_on = mrxsmb10.map(|v| v != 4).unwrap_or(false);
        let enabled = server_on || client_on;
        if enabled {
            findings.push(finding(
                "Legacy Protocols",
                "SMBv1",
                FindingStatus::Vulnerable,
                Severity::Critical,
                "SMBv1 is ENABLED — vulnerable to EternalBlue-class worms (WannaCry/NotPetya)",
                true,
            ));
        } else {
            findings.push(finding(
                "Legacy Protocols",
                "SMBv1",
                FindingStatus::Secure,
                Severity::Critical,
                "SMBv1 is disabled (legacy stack not enabled)".to_string(),
                false,
            ));
        }
        Ok(findings)
    }

    async fn audit_uac(&self) -> Result<Vec<AuditFinding>> {
        let mut findings = Vec::new();
        const UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        match read_dword(HKEY_LOCAL_MACHINE, UAC, "EnableLUA") {
            Some(0) => findings.push(finding(
                "Account Control",
                "UAC",
                FindingStatus::Vulnerable,
                Severity::Critical,
                "User Account Control is fully DISABLED — every process runs with full admin rights",
                true,
            )),
            _ => {
                let secure_desktop = read_dword(HKEY_LOCAL_MACHINE, UAC, "PromptOnSecureDesktop");
                if secure_desktop == Some(0) {
                    findings.push(finding(
                        "Account Control",
                        "UAC Secure Desktop",
                        FindingStatus::Warning,
                        Severity::Medium,
                        "UAC prompts shown on the regular desktop (dimming disabled) — clickjacking risk",
                        true,
                    ));
                } else {
                    findings.push(finding(
                        "Account Control",
                        "UAC",
                        FindingStatus::Secure,
                        Severity::High,
                        "UAC is enabled".to_string(),
                        false,
                    ));
                }
            }
        }
        Ok(findings)
    }

    async fn audit_admins(&self) -> Result<Vec<AuditFinding>> {
        // `net localgroup` requires no elevation and is locale-stable for the
        // group name on en-US; fall back to well-known SID group name resolution.
        let output = std::process::Command::new("net")
            .args(["localgroup", "Administrators"])
            .output();
        let mut members: Vec<String> = Vec::new();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            // Lines between the dashed separator and the trailing summary line.
            let mut in_list = false;
            for line in text.lines() {
                if line.starts_with("---") {
                    if in_list {
                        break;
                    }
                    in_list = true;
                    continue;
                }
                if in_list {
                    let name = line.trim();
                    if !name.is_empty()
                        && !name.starts_with("The command completed")
                        && !name.contains("-----")
                    {
                        members.push(name.to_string());
                    }
                }
            }
        }

        if members.is_empty() {
            return Ok(vec![finding(
                "Local Admins",
                "Administrators Group",
                FindingStatus::Unknown,
                Severity::Medium,
                "Could not enumerate the Administrators group".to_string(),
                false,
            )]);
        }

        let count = members.len();
        let list = members.join(", ");
        Ok(vec![finding(
            "Local Admins",
            "Administrators Group",
            if count > 3 {
                FindingStatus::Warning
            } else {
                FindingStatus::Secure
            },
            Severity::High,
            format!("{count} account(s) with admin rights: {list}"),
            false,
        )])
    }

    async fn audit_startup(&self) -> Result<Vec<StartupEntry>> {
        let mut entries = Vec::new();
        const RUN_HKLM: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const RUN_HKLM_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
        const RUN_HKCU: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

        for (root, subkey, location) in [
            (HKEY_LOCAL_MACHINE, RUN_HKLM, r"HKLM\...\Run"),
            (HKEY_LOCAL_MACHINE, RUN_HKLM_32, r"HKLM\...\Run (32-bit)"),
            (HKEY_CURRENT_USER, RUN_HKCU, r"HKCU\...\Run"),
        ] {
            for name in enum_subkeys_values(root, subkey) {
                if let Some(cmd) = read_string(root, subkey, &name) {
                    entries.push(StartupEntry {
                        name,
                        command: cmd,
                        location: location.to_string(),
                    });
                }
            }
        }

        // Startup folders (per-user + all-users).
        for (dir, location) in [
            (
                std::env::var("APPDATA").map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
                "Startup Folder (user)",
            ),
            (
                std::env::var("PROGRAMDATA").map(|p| PathBuf::from(p).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
                "Startup Folder (all users)",
            ),
        ] {
            if let Ok(dir) = dir
                && let Ok(rd) = std::fs::read_dir(&dir) {
                    for e in rd.flatten() {
                        entries.push(StartupEntry {
                            name: e.file_name().to_string_lossy().to_string(),
                            command: e.path().to_string_lossy().to_string(),
                            location: location.to_string(),
                        });
                    }
                }
        }

        Ok(entries)
    }

    async fn audit_scheduled_tasks(&self) -> Result<Vec<ScheduledTaskEntry>> {
        // Non-Microsoft tasks are the interesting ones; enumerate the Tasks
        // folder skipping the Microsoft subtree.
        let mut tasks = Vec::new();
        let tasks_dir = PathBuf::from(r"C:\Windows\System32\Tasks");
        let stack = vec![tasks_dir.clone()];
        let mut visited = 0usize;
        let mut stack = stack;
        while let Some(dir) = stack.pop() {
            if visited > 2000 {
                break;
            }
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                visited += 1;
                let path = e.path();
                if path.is_dir() {
                    if path.file_name().map(|n| n == "Microsoft").unwrap_or(false)
                        && dir == tasks_dir
                    {
                        continue;
                    }
                    stack.push(path);
                } else {
                    let rel = path
                        .strip_prefix(&tasks_dir)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let name = rel.rsplit('/').next().unwrap_or(&rel).to_string();
                    tasks.push(ScheduledTaskEntry { name, path: rel });
                }
            }
        }
        tasks.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(tasks)
    }

    async fn audit_hosts_file(&self) -> Result<Vec<AuditFinding>> {
        let hosts = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
        let content = std::fs::read_to_string(&hosts).context("hosts file unreadable")?;
        let mut suspicious: Vec<String> = Vec::new();
        let mut mappings = 0usize;
        for line in content.lines() {
            // Strip inline comments (a line like "127.0.0.1 foo # note" keeps only the mapping).
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            mappings += 1;
            let mut parts = line.split_whitespace();
            let ip = parts.next().unwrap_or("");
            let domain = parts.next().unwrap_or("");
            // Redirects to loopback / 0.0.0.0 are blocklist-style entries (safe intent).
            // Anything pointing at a real remote IP or non-loopback LAN host is worth reviewing.
            let blocked_style = ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0";
            if !blocked_style && !domain.is_empty() {
                suspicious.push(format!("{domain} -> {ip}"));
            }
        }

        if suspicious.is_empty() {
            Ok(vec![finding(
                "Hosts File",
                "hosts entries",
                FindingStatus::Secure,
                Severity::High,
                format!("hosts file OK ({mappings} mapping(s), none redirecting to remote IPs)"),
                false,
            )])
        } else {
            let preview = suspicious.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
            Ok(vec![finding(
                "Hosts File",
                "hosts entries",
                FindingStatus::Warning,
                Severity::High,
                format!(
                    "hosts file redirects {} domain(s) to non-loopback IPs — verify they are intentional: {}",
                    suspicious.len(),
                    preview
                ),
                false,
            )])
        }
    }

    async fn audit_remote_tools(&self) -> Result<Vec<AuditFinding>> {
        const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
        let known = [
            ("AnyDesk", "anydesk"),
            ("TeamViewer", "TeamViewer"),
            ("RustDesk", "rustdesk"),
            ("TightVNC", "tvnserver"),
            ("UltraVNC", "uvnc_service"),
            ("RealVNC", "vncserver"),
            ("Ammyy Admin", "ammyy"),
            ("Radmin", "rserver3"),
            ("Chrome Remote Desktop", "chromoting"),
        ];
        let mut found = Vec::new();
        for (label, svc) in known {
            if read_dword(HKEY_LOCAL_MACHINE, &format!("{SERVICES}\\{svc}"), "Start").is_some() {
                found.push(label.to_string());
            }
        }

        Ok(vec![finding(
            "Remote Access",
            "Remote-control Tools",
            if found.is_empty() {
                FindingStatus::Secure
            } else {
                FindingStatus::Warning
            },
            Severity::High,
            if found.is_empty() {
                "No known remote-access tools installed".into()
            } else {
                format!("Remote-access tools detected: {}", found.join(", "))
            },
            false,
        )])
    }

    async fn get_network_connections(&self) -> Result<Vec<NetworkConnection>> {
        // Process id -> name map via sysinfo (single refresh, reused by TCP+UDP).
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        let mut connections = Vec::new();

        unsafe {
            // ---- TCP ----
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            let mut buf = vec![0u8; size as usize];
            let err = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if err == 0 {
                let base = buf.as_ptr() as *const u32;
                let n = *base;
                let rows = base.add(1) as *const MIB_TCPROW_OWNER_PID;
                for i in 0..n as usize {
                    let r = *rows.add(i);
                    let state = tcp_state_name(r.dwState);
                    let pid = r.dwOwningPid;
                    connections.push(NetworkConnection {
                        local_address: format_ipv4_port(r.dwLocalAddr, r.dwLocalPort),
                        remote_address: format_ipv4_port(r.dwRemoteAddr, r.dwRemotePort),
                        protocol: "TCP".to_string(),
                        state,
                        process_id: pid,
                        process_name: process_name(&sys, pid),
                        country: crate::ids::geoip::lookup(&format_ipv4_ip(r.dwRemoteAddr)),
                    });
                }
            } else {
                warn!("GetExtendedTcpTable failed with error {err}");
            }

            // ---- UDP ----
            let mut size: u32 = 0;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            let mut buf = vec![0u8; size as usize];
            let err = GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if err == 0 {
                let base = buf.as_ptr() as *const u32;
                let n = *base;
                let rows = base.add(1) as *const MIB_UDPROW_OWNER_PID;
                for i in 0..n as usize {
                    let r = *rows.add(i);
                    let pid = r.dwOwningPid;
                    connections.push(NetworkConnection {
                        local_address: format_ipv4_port(r.dwLocalAddr, r.dwLocalPort),
                        remote_address: "*:*".to_string(),
                        protocol: "UDP".to_string(),
                        state: "-".to_string(),
                        process_id: pid,
                        process_name: process_name(&sys, pid),
                        country: String::new(),
                    });
                }
            } else {
                warn!("GetExtendedUdpTable failed with error {err}");
            }
        }

        Ok(connections)
    }

    async fn get_software_inventory(&self) -> Result<Vec<SoftwareEntry>> {
        const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let roots: [(HKEY, &str, REGSAM); 3] = [
            (HKEY_LOCAL_MACHINE, UNINSTALL, KEY_WOW64_32KEY), // 64-bit view via default + 32-bit
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                REGSAM(0),
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                REGSAM(0),
            ),
        ];

        for (root, subkey, access) in roots {
            for key in enum_subkeys(root, subkey, Some(access)) {
                let full = format!("{subkey}\\{key}");
                let name = read_string(root, &full, "DisplayName");
                let Some(name) = name else { continue };
                if name.trim().is_empty() || !seen.insert(name.to_lowercase()) {
                    continue;
                }
                entries.push(SoftwareEntry {
                    name,
                    version: read_string(root, &full, "DisplayVersion").unwrap_or_default(),
                    publisher: read_string(root, &full, "Publisher").unwrap_or_default(),
                    install_location: read_string(root, &full, "InstallLocation")
                        .filter(|s| !s.trim().is_empty()),
                });
            }
        }

        entries.sort_by_key(|a| a.name.to_lowercase());
        Ok(entries)
    }
}

// ---- state helpers used by the Hardening Center (mirror the audit checks) ----

/// Defender's effective `PUAProtection` value: a Group Policy / MDM setting
/// wins over Defender's local preference store, which is where the Windows
/// Security switch and `Set-MpPreference -PUAProtection` persist the choice —
/// the same precedence the real-time protection check above already applies,
/// and the one `Get-MpPreference` reports.
pub fn pua_state() -> Option<u32> {
    pua_effective(
        read_dword(HKEY_LOCAL_MACHINE, PUA_POLICY_KEY, "PUAProtection"),
        read_dword(HKEY_LOCAL_MACHINE, PUA_LIVE_KEY, "PUAProtection"),
    )
}

/// Group Policy / MDM (`HKLM\SOFTWARE\Policies\...`) outranks the local
/// preference store (`HKLM\SOFTWARE\Microsoft\Windows Defender`).
pub fn pua_effective(policy: Option<u32>, live: Option<u32>) -> Option<u32> {
    policy.or(live)
}

const PUA_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine";
const PUA_LIVE_KEY: &str = r"SOFTWARE\Microsoft\Windows Defender";

/// Asks Defender for its real-time protection state; `Some` only when Defender
/// actually answered with a boolean.
pub(crate) fn defender_rtp_state() -> Option<bool> {
    let mut command = std::process::Command::new("powershell");
    command
        .args([
            "-NoProfile",
            "-Command",
            "(Get-MpComputerStatus).RealTimeProtectionEnabled",
        ])
        .stdin(std::process::Stdio::null());
    // A console app started from a GUI process must not flash a console window.
    crate::platform::windows::elevation::hide_console(&mut command);
    let out = command.output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_mp_bool(&String::from_utf8_lossy(&out.stdout))
}

/// PowerShell prints booleans as `True`/`False`. Anything else — empty output
/// from a denied WMI query (which still exits 0), a localised string, banner
/// noise — is not an answer, and must not be turned into "protection is off".
pub(crate) fn parse_mp_bool(stdout: &str) -> Option<bool> {
    match stdout.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Maps a `PUAProtection` value to the audit verdict: status, description and
/// whether the fix button should be offered. Audit mode logs suspicious apps
/// but never blocks them, so it is a warning, not a pass.
pub fn pua_verdict(state: Option<u32>) -> (FindingStatus, &'static str, bool) {
    match state {
        Some(1) => (
            FindingStatus::Secure,
            "Potentially unwanted app blocking is enabled",
            false,
        ),
        Some(2) => (
            FindingStatus::Warning,
            "PUA protection is in audit mode — unwanted apps are reported but not blocked",
            true,
        ),
        _ => (
            FindingStatus::Warning,
            "PUA protection is not explicitly enabled",
            true,
        ),
    }
}

impl WindowsCollectors {
    pub fn pua_enabled(&self) -> bool {
        pua_state() == Some(1)
    }

    pub fn smbv1_enabled(&self) -> bool {
        let smb1 = read_dword(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        );
        let mrxsmb10 = read_dword(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
            "Start",
        );
        smb1 != Some(0) && mrxsmb10 != Some(4)
    }

    pub fn rdp_disabled(&self) -> bool {
        read_dword(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        ) != Some(0)
    }

    pub fn uac_enabled(&self) -> bool {
        read_dword(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        ) != Some(0)
    }
}

/// Reads every *value name* under a key (for Run-key enumeration).
fn enum_subkeys_values(root: HKEY, subkey: &str) -> Vec<String> {
    use windows::Win32::System::Registry::{RegOpenKeyExW, RegEnumValueW};
    let sk = to_wide(subkey);
    let mut hkey = HKEY::default();
    let err = unsafe { RegOpenKeyExW(root, PCWSTR(sk.as_ptr()), None, KEY_READ, &mut hkey) };
    if err != ERROR_SUCCESS {
        return Vec::new();
    }
    let mut names = Vec::new();
    for i in 0..1024u32 {
        let mut name_buf = [0u16; 260];
        let mut name_len = 260u32;
        let err = unsafe {
            RegEnumValueW(hkey, i, Some(windows::core::PWSTR(name_buf.as_mut_ptr())), &mut name_len, None, None, None, None)
        };
        if err != ERROR_SUCCESS {
            break;
        }
        names.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    names
}

fn format_ipv4_ip(addr: u32) -> String {
    Ipv4Addr::new(
        (addr & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 24) & 0xFF) as u8,
    )
    .to_string()
}

pub fn format_ipv4_port(addr: u32, port_net_order: u32) -> String {
    let ip = Ipv4Addr::new(
        (addr & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 24) & 0xFF) as u8,
    );
    // The port arrives in network byte order inside the low 16 bits.
    let port = (port_net_order & 0xFFFF) as u16;
    let port = port.swap_bytes();
    format!("{ip}:{port}")
}

fn tcp_state_name(state: u32) -> String {
    match state {
        1 => "CLOSED",
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
    .to_string()
}

fn process_name(sys: &sysinfo::System, pid: u32) -> String {
    sys.process(sysinfo::Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| "System/Unknown".into())
}
