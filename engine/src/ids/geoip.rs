//! Minimal offline GeoIP: resolves an IP to a country by looking it up in the
//! installed country CIDR blocklists (rules blocklists <CC>.cidr — the same
//! files the country-block firewall rules use). No external DB needed; the
//! intel arrives with the synced blocklists.

use anyhow::Result;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::OnceLock;

struct Range {
    start: u32,
    end: u32,
    country: String,
}

static TABLE: OnceLock<Vec<Range>> = OnceLock::new();

fn blocklist_dir() -> PathBuf {
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

fn table() -> &'static Vec<Range> {
    TABLE.get_or_init(|| {
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
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                let Some((ip, prefix)) = line.split_once('/') else {
                    continue;
                };
                let (Ok(base), Ok(prefix)) = (ip.parse::<Ipv4Addr>(), prefix.parse::<u8>()) else {
                    continue;
                };
                if prefix > 32 {
                    continue;
                }
                let start = u32::from(base);
                let size = 1u64 << (32 - prefix);
                let end = start + (size - 1) as u32;
                ranges.push(Range { start, end, country: cc.to_uppercase() });
            }
        }
        ranges.sort_by_key(|r| r.start);
        ranges
    })
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
    let ranges = table();
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

/// Loads the table eagerly (called by net.connections path once).
pub fn warm() -> Result<()> {
    let _ = table();
    Ok(())
}
