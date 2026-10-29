//! Minimal offline GeoIP: resolves an IP to a country by looking it up in the
//! installed country CIDR blocklists (rules blocklists <CC>.cidr — the same
//! files the country-block firewall rules use). No external DB needed; the
//! intel arrives with the synced blocklists.

use anyhow::Result;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

struct Range {
    start: u32,
    end: u32,
    country: String,
}

/// Reloadable on purpose: the intel sync re-reads the installed country lists
/// and must be able to make the result visible without an engine restart.
static TABLE: OnceLock<RwLock<Vec<Range>>> = OnceLock::new();

fn table() -> &'static RwLock<Vec<Range>> {
    TABLE.get_or_init(|| RwLock::new(load_ranges()))
}

/// Directory holding `<CC>.cidr` country lists. Beside the executable first
/// (portable/installed layout), then the machine-wide data directory.
pub fn blocklist_dir() -> PathBuf {
    for base in [
        std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())),
        std::env::var("MICS_RULES_DIR").ok().map(PathBuf::from),
        std::env::current_dir().ok(),
    ]
    .into_iter()
    .flatten()
    {
        let p = base.join("rules").join("blocklists");
        if p.exists() {
            return p;
        }
    }
    std::env::var("PROGRAMDATA")
        .map(|p| PathBuf::from(p).join("MICS").join("blocklists"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\blocklists"))
}

/// ISO country codes that have an installed list (file stem of `<CC>.cidr`).
pub fn installed_countries() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(blocklist_dir())
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let path = e.path();
                    if path.extension().map(|x| x != "cidr").unwrap_or(true) {
                        return None;
                    }
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_uppercase())
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// Re-reads the installed lists and returns how many CIDR ranges are now live.
/// Called by the intel sync so GeoIP freshness follows the files.
pub fn refresh() -> usize {
    let ranges = load_ranges();
    let count = ranges.len();
    if let Ok(mut table) = table().write() {
        *table = ranges;
    }
    count
}

fn load_ranges() -> Vec<Range> {
    let mut ranges = Vec::new();
    let dir = blocklist_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return ranges;
    };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().map(|x| x != "cidr").unwrap_or(true) {
            continue;
        }
        let Some(cc) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            if let Some((base, prefix, _)) = parse_cidr_line(line) {
                let start = u32::from(base);
                let size = 1u64 << (32 - prefix);
                let end = start + (size - 1) as u32;
                ranges.push(Range { start, end, country: cc.to_uppercase() });
            }
        }
    }
    ranges.sort_by_key(|r| r.start);
    ranges
}

/// One `<ipv4>/<prefix>` line, ignoring blanks and `#` comments. Split out so
/// the intel sync can validate a downloaded country list without a second
/// parser drifting away from this one.
pub fn parse_cidr_line(line: &str) -> Option<(Ipv4Addr, u8, String)> {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    let (ip, prefix) = line.split_once('/')?;
    let base = ip.trim().parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.trim().parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((base, prefix, line.to_string()))
}

/// Returns the ISO country code for an IPv4, or "" when unknown/private.
pub fn lookup(ip: &str) -> String {
    let Ok(addr) = ip.split(':').next().unwrap_or(ip).parse::<Ipv4Addr>() else {
        return String::new();
    };
    let n = u32::from(addr);
    // Private / loopback are not GeoIP material.
    if addr.is_private() || addr.is_loopback() || addr.is_link_local() {
        return "LOCAL".into();
    }
    let ranges = match table().read() {
        Ok(r) => r,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Binary search for the last range with start <= n.
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if ranges[mid].start <= n {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo > 0 {
        let r = &ranges[lo - 1];
        if n >= r.start && n <= r.end {
            return r.country.clone();
        }
    }
    String::new()
}

/// Loads the table eagerly (kept for callers that want to pay the parse cost
/// up front instead of on the first lookup).
#[allow(dead_code)]
pub fn warm() -> Result<()> {
    let _ = table();
    Ok(())
}
