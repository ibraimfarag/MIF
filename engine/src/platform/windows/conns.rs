//! What a live connection row means, and what a one-click block sends.
//!
//! This module owns the whole walk over Windows' connection tables
//! ([`snapshot`]) and everything in it a unit test can hold, because the API
//! calls themselves cannot be tested without a running machine:
//!
//!   * the note a one-click filter carries (the helper's validator is the only
//!     thing that accepts it, so the note is built to pass rather than trimmed
//!     later);
//!   * whether a row can become a filter at all - a row with no image path (a
//!     kernel connection, or a process this token may not query), no peer port
//!     (a UDP socket, which Windows keeps no peer for) or a protocol this
//!     product does not filter answers `None`, so the UI offers no button
//!     instead of one that fails;
//!   * the address formatting both families go through.
//!
//! Slice (b) of register section 0.6 row 17; the decision is D-043.

use crate::platform::traits::{NetworkBlock, NetworkConnection};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::warn;
use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The IP protocol numbers this product ever blocks.
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// The longest note the privileged helper accepts.
pub const NOTE_MAX: usize = 40;

/// The note a one-click filter carries into the BFE's display name.
///
/// Windows stores that name and `netsh wfp show filters` prints it, so the note
/// has to be a word, not a sentence. Anything the helper's validator would
/// refuse becomes `-`, the result is capped, and an empty result falls back to a
/// fixed word rather than an empty one.
pub fn conn_note(process_name: &str) -> String {
    let mut out = String::new();
    for ch in process_name.chars() {
        if out.chars().count() >= NOTE_MAX {
            break;
        }
        let keep = ch.is_ascii_alphanumeric() || ch == ' ' || ch == '-' || ch == '_';
        out.push(if keep { ch } else { '-' });
    }
    let trimmed = out.trim_matches(|c: char| c == ' ' || c == '-').to_string();
    if trimmed.is_empty() {
        "connection".to_string()
    } else {
        trimmed
    }
}

/// The spec a one-click block sends, or `None` when this row cannot be one.
///
/// The engine builds it, so the UI sends what the engine already validated
/// instead of assembling a spec out of display strings.
pub fn block_for(
    image_path: &str,
    protocol: u8,
    remote_port: u16,
    process_name: &str,
) -> Option<NetworkBlock> {
    let path = image_path.trim();
    if path.is_empty() || remote_port == 0 {
        return None;
    }
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return None;
    }
    Some(NetworkBlock {
        app: path.to_string(),
        port: remote_port,
        protocol,
        note: conn_note(process_name),
    })
}

/// A port as Windows reports it: network byte order inside the low 16 bits.
pub fn port_of(net_order: u32) -> u16 {
    ((net_order & 0xFFFF) as u16).swap_bytes()
}

/// `[addr]:port`, with the scope id when the address has one. Brackets because a
/// bare `fe80::1%12:443` cannot be read back unambiguously.
pub fn format_ipv6_socket(addr: &[u8; 16], scope_id: u32, port: u16) -> String {
    let ip = Ipv6Addr::from(*addr);
    if scope_id != 0 {
        format!("[{ip}%{scope_id}]:{port}")
    } else {
        format!("[{ip}]:{port}")
    }
}

/// The image path behind a pid.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` is the narrowest right that answers this,
/// so the engine does not need to be able to read another process's memory to
/// name it. `None` means the process is gone, is a kernel thread, or is
/// protected from this token - and a row without a path is a row the UI cannot
/// offer to block, which is why this returns an `Option` instead of a guess.
pub fn image_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let queried =
            QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(handle);
        if queried.is_err() || len == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        let path = path.trim().to_string();
        if path.is_empty() { None } else { Some(path) }
    }
}

/// One pass over Windows' four connection tables.
///
/// The tables are the kernel's own connection state, read in usermode through
/// `GetExtendedTcpTable` / `GetExtendedUdpTable`: no driver, no callout, no
/// per-packet work - and D-043 records why that is the right shape for a list
/// the user acts on. It is a **snapshot**, not a push: a connection that appears
/// and disappears between two calls is never seen, and the UI says so.
///
/// IPv6 is walked as well as IPv4, because a block on a connection whose peer
/// Windows reported as `[2001:db8::1]:443` has to be expressible.
pub fn snapshot() -> Vec<NetworkConnection> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut paths: HashMap<u32, String> = HashMap::new();
    let mut connections = Vec::new();

    // ---- TCP, IPv4 ----
    if let Some(buf) = table(|ptr, size| unsafe {
        GetExtendedTcpTable(ptr, size, false, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) {
        let (n, rows) = rows::<MIB_TCPROW_OWNER_PID>(&buf);
        for i in 0..n {
            let r = unsafe { *rows.add(i) };
            connections.push(row(
                &sys,
                &mut paths,
                Row {
                    pid: r.dwOwningPid,
                    local: format_ipv4_port(r.dwLocalAddr, r.dwLocalPort),
                    remote: format_ipv4_port(r.dwRemoteAddr, r.dwRemotePort),
                    protocol: "TCP",
                    protocol_number: IPPROTO_TCP,
                    state: tcp_state_name(r.dwState),
                    remote_port: port_of(r.dwRemotePort),
                    country: crate::ids::geoip::lookup(&format_ipv4_ip(r.dwRemoteAddr)),
                },
            ));
        }
    }

    // ---- TCP, IPv6 ----
    if let Some(buf) = table(|ptr, size| unsafe {
        GetExtendedTcpTable(ptr, size, false, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) {
        let (n, rows) = rows::<MIB_TCP6ROW_OWNER_PID>(&buf);
        for i in 0..n {
            let r = unsafe { *rows.add(i) };
            connections.push(row(
                &sys,
                &mut paths,
                Row {
                    pid: r.dwOwningPid,
                    local: format_ipv6_socket(&r.ucLocalAddr, r.dwLocalScopeId, port_of(r.dwLocalPort)),
                    remote: format_ipv6_socket(
                        &r.ucRemoteAddr,
                        r.dwRemoteScopeId,
                        port_of(r.dwRemotePort),
                    ),
                    protocol: "TCP",
                    protocol_number: IPPROTO_TCP,
                    state: tcp_state_name(r.dwState),
                    remote_port: port_of(r.dwRemotePort),
                    country: String::new(),
                },
            ));
        }
    }

    // ---- UDP, IPv4 ----
    // A UDP row has no peer in the table Windows keeps, so the peer port is 0
    // and the row carries no block spec: "block this UDP socket" is not a thing
    // the machine can express, and the UI says that instead of guessing.
    if let Some(buf) = table(|ptr, size| unsafe {
        GetExtendedUdpTable(ptr, size, false, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)
    }) {
        let (n, rows) = rows::<MIB_UDPROW_OWNER_PID>(&buf);
        for i in 0..n {
            let r = unsafe { *rows.add(i) };
            connections.push(row(
                &sys,
                &mut paths,
                Row {
                    pid: r.dwOwningPid,
                    local: format_ipv4_port(r.dwLocalAddr, r.dwLocalPort),
                    remote: "*:*".to_string(),
                    protocol: "UDP",
                    protocol_number: IPPROTO_UDP,
                    state: "-".to_string(),
                    remote_port: 0,
                    country: String::new(),
                },
            ));
        }
    }

    // ---- UDP, IPv6 ----
    if let Some(buf) = table(|ptr, size| unsafe {
        GetExtendedUdpTable(ptr, size, false, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)
    }) {
        let (n, rows) = rows::<MIB_UDP6ROW_OWNER_PID>(&buf);
        for i in 0..n {
            let r = unsafe { *rows.add(i) };
            connections.push(row(
                &sys,
                &mut paths,
                Row {
                    pid: r.dwOwningPid,
                    local: format_ipv6_socket(&r.ucLocalAddr, r.dwLocalScopeId, port_of(r.dwLocalPort)),
                    remote: "*:*".to_string(),
                    protocol: "UDP",
                    protocol_number: IPPROTO_UDP,
                    state: "-".to_string(),
                    remote_port: 0,
                    country: String::new(),
                },
            ));
        }
    }

    connections
}

/// The two-call shape every one of those tables has: ask for the size, then fill
/// a buffer. `None` means the table is empty or unreadable - both are "nothing to
/// show", and the second one says so in the log rather than silently.
fn table<F>(mut call: F) -> Option<Vec<u8>>
where
    F: FnMut(Option<*mut c_void>, &mut u32) -> u32,
{
    let mut size: u32 = 0;
    let _ = call(None, &mut size);
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let err = call(Some(buf.as_mut_ptr() as *mut c_void), &mut size);
    if err != 0 {
        warn!("a connection table could not be read: error {err}");
        return None;
    }
    Some(buf)
}

/// A table's rows: the count is a `u32` at the start of the buffer and the rows
/// follow it, which is the layout of all four tables.
fn rows<T>(buf: &[u8]) -> (usize, *const T) {
    let base = buf.as_ptr() as *const u32;
    let n = unsafe { *base } as usize;
    (n, unsafe { base.add(1) as *const T })
}

/// One table row, before the process behind it is named.
struct Row<'a> {
    pid: u32,
    local: String,
    remote: String,
    protocol: &'a str,
    protocol_number: u8,
    state: String,
    remote_port: u16,
    country: String,
}

fn row(sys: &sysinfo::System, paths: &mut HashMap<u32, String>, r: Row<'_>) -> NetworkConnection {
    let name = process_name(sys, r.pid);
    let path = paths
        .entry(r.pid)
        .or_insert_with(|| image_path(r.pid).unwrap_or_default())
        .clone();
    let block = block_for(&path, r.protocol_number, r.remote_port, &name);
    NetworkConnection {
        local_address: r.local,
        remote_address: r.remote,
        protocol: r.protocol.to_string(),
        state: r.state,
        process_id: r.pid,
        process_name: name,
        country: r.country,
        process_path: path,
        protocol_number: r.protocol_number,
        remote_port: r.remote_port,
        block,
    }
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
    format!("{}:{}", format_ipv4_ip(addr), port_of(port_net_order))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::wfp::FilterSpec;
    use serde_json::json;

    #[test]
    fn a_note_is_a_word_the_helper_accepts() {
        // The helper refuses anything outside letters, digits, spaces, dashes
        // and underscores, and anything longer than 40 characters.
        assert_eq!(conn_note("chrome.exe"), "chrome-exe");
        assert_eq!(conn_note("MI CS Guard"), "MI CS Guard");
        assert_eq!(conn_note("a\\b/c:d\ne"), "a-b-c-d-e");
        assert_eq!(conn_note("").is_empty(), false);
        assert_eq!(conn_note("   "), "connection");
        assert_eq!(conn_note("---").len() <= NOTE_MAX, true);

        let long = conn_note(&"x".repeat(80));
        assert_eq!(long.chars().count(), NOTE_MAX);
        for note in ["chrome.exe", "", "   ", &"x".repeat(80), "a\\b"] {
            let note = conn_note(note);
            assert!(note.len() <= NOTE_MAX);
            assert!(
                note.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_'),
                "note {note:?} has a character the helper refuses"
            );
        }
    }

    #[test]
    fn a_row_without_a_path_or_a_peer_port_is_not_blockable() {
        assert!(block_for("", IPPROTO_TCP, 443, "x").is_none());
        assert!(block_for("   ", IPPROTO_TCP, 443, "x").is_none());
        assert!(block_for(r"C:\a.exe", IPPROTO_TCP, 0, "a").is_none());
        // Protocol 1 is ICMP: this product does not filter it.
        assert!(block_for(r"C:\a.exe", 1, 443, "a").is_none());
        assert!(block_for(r"C:\a.exe", IPPROTO_TCP, 443, "a").is_some());
        assert!(block_for(r"C:\a.exe", IPPROTO_UDP, 53, "a").is_some());
    }

    #[test]
    fn the_spec_a_click_sends_is_the_one_the_helper_validates() {
        let block = block_for(r"C:\Program Files\App\app.exe", IPPROTO_TCP, 8443, "app.exe")
            .expect("blockable");
        // Same field names the `fw.wfp.block` params are read by, which is what
        // lets the UI forward this object untouched.
        let value = serde_json::to_value(&block).expect("serialize");
        assert_eq!(
            value,
            json!({"app": r"C:\Program Files\App\app.exe", "port": 8443, "protocol": 6, "note": "app-exe"})
        );

        // And the helper's own gate accepts it: the one-click path cannot build
        // a spec the closed operation set would refuse.
        let spec: FilterSpec = serde_json::from_value(value).expect("same names");
        crate::firewall::wfp::validate(&spec).expect("the derived spec is valid");
        let op = crate::privileged::ops::Op::FirewallWfpBlock { spec };
        op.validate().expect("the helper accepts it");
    }

    #[test]
    fn a_note_that_would_be_refused_is_replaced_not_trimmed_away() {
        // A process name is not under our control: the note has to be safe even
        // for names with quotes and non-ASCII characters.
        let note = conn_note("weird\"name\ttab");
        let spec = FilterSpec {
            app: Some(r"C:\a.exe".into()),
            port: Some(443),
            protocol: Some(6),
            note: Some(note),
        };
        crate::firewall::wfp::validate(&spec).expect("valid");
        crate::privileged::ops::Op::FirewallWfpBlock { spec }
            .validate()
            .expect("the helper accepts it");
    }

    #[test]
    fn ports_and_v6_addresses_read_back_the_way_windows_reports_them() {
        // 443 in network byte order, inside the low 16 bits.
        assert_eq!(port_of(0x0000_BB01), 443);
        assert_eq!(port_of(0x0000_3500), 53);

        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(format_ipv6_socket(&loopback, 0, 443), "[::1]:443");
        assert_eq!(format_ipv6_socket(&loopback, 12, 443), "[::1%12]:443");

        let mut global = [0u8; 16];
        global[0] = 0x20;
        global[1] = 0x01;
        global[2] = 0x0d;
        global[3] = 0xb8;
        global[15] = 1;
        assert_eq!(format_ipv6_socket(&global, 0, 80), "[2001:db8::1]:80");
    }

    #[test]
    fn the_running_process_can_name_its_own_image() {
        // The path a row carries is what the filter matches, so it has to be a
        // real path and not a name. This is the one place the API is called from
        // a test: our own process is always queryable.
        assert_eq!(image_path(0), None);
        let own = image_path(std::process::id()).expect("our own image path");
        assert!(
            own.to_ascii_lowercase().ends_with(".exe"),
            "expected an image path, got {own:?}"
        );
        assert!(own.contains('\\'), "expected an absolute path, got {own:?}");
    }
}
