//! Feed parsers for the intel sources.
//!
//! They are pure functions on purpose: the network is the only untestable part
//! of a sync, so everything that can silently produce wrong intel (a renamed
//! column, a hosts file whose loopback names look like domains, a catalog that
//! changed shape) is decided here and covered by tests.
//!
//! Every default feed in [`super`] was fetched by hand against its live
//! endpoint before being wired in: a parser that quietly returns an empty list
//! would otherwise look like a successful sync with zero intelligence.

use crate::storage::sqlite::KevRow;

/// Names that ship in every hosts file and are not indicators.
const LOOPBACK_NAMES: [&str; 9] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-allnodes",
    "ip6-allrouters",
];

/// Hosts-file blocklist (the StevenBlack/hosts layout, MIT):
/// `0.0.0.0 domain` / `127.0.0.1 domain`, `#` starts a comment.
///
/// Duplicates are left in: the database counts *new* rows anyway, and hashing
/// 76k names here would cost more than the insert it saves.
pub fn parse_hosts_blocklist(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let _sink = parts.next(); // 0.0.0.0 / 127.0.0.1
        let Some(name) = parts.next() else { continue };
        let name = name.trim().to_lowercase();
        if is_blockable_host(&name) {
            out.push(name);
        }
    }
    out
}

fn is_blockable_host(name: &str) -> bool {
    if LOOPBACK_NAMES.contains(&name) {
        return false;
    }
    // A domain, not an address or a stray token: at least one dot, DNS length,
    // and only the characters a hostname may contain.
    if name.len() < 4 || name.len() > 253 || !name.contains('.') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// sha256 feeds, in the three shapes that are actually in the wild:
/// plain lines of 64 hex characters, `hash;tag;tag` exports, and the URLhaus
/// CSV (`"id","date_time",…,"sha256_hash",…`). CSV column names are matched, so
/// an upstream column reorder does not silently drop every hash.
pub fn parse_hash_feed(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut sha_col: Option<usize> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') && !line.contains("sha256") {
            continue;
        }
        if line.starts_with('"') {
            let cols: Vec<&str> = line.split("\",\"").collect();
            match sha_col {
                // The header row is the one that names the sha256 column.
                None => {
                    sha_col = cols
                        .iter()
                        .position(|c| c.to_lowercase().contains("sha256"));
                }
                Some(i) => {
                    if let Some(h) = cols.get(i).and_then(|c| clean_hash(c)) {
                        out.push(h);
                    }
                }
            }
            continue;
        }
        // `hash;tags` keeps the hash in the first field.
        let head = line.split(';').next().unwrap_or(line);
        if let Some(h) = clean_hash(head) {
            out.push(h);
        }
    }
    out
}

fn clean_hash(raw: &str) -> Option<String> {
    let h = raw.trim().trim_matches('"').trim().to_lowercase();
    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(h)
    } else {
        None
    }
}

/// CISA Known Exploited Vulnerabilities catalog (US Government work, public
/// domain): `{ "catalogVersion": "...", "count": N, "vulnerabilities": [ … ] }`.
/// Returns the catalog version plus the entries, so the caller can store both.
pub fn parse_kev_catalog(json: &serde_json::Value) -> (String, Vec<KevRow>) {
    let version = json["catalogVersion"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let mut rows = Vec::new();
    let Some(items) = json["vulnerabilities"].as_array() else {
        return (version, rows);
    };
    for item in items {
        let Some(cve_id) = item["cveID"].as_str() else {
            continue;
        };
        rows.push(KevRow {
            cve_id: cve_id.to_string(),
            vendor: item["vendorProject"].as_str().unwrap_or("").to_string(),
            product: item["product"].as_str().unwrap_or("").to_string(),
            date_added: item["dateAdded"].as_str().unwrap_or("").to_string(),
            due_date: item["dueDate"].as_str().unwrap_or("").to_string(),
            ransomware: item["knownRansomwareCampaignUse"]
                .as_str()
                .map(|v| v.eq_ignore_ascii_case("known"))
                .unwrap_or(false),
        });
    }
    (version, rows)
}


