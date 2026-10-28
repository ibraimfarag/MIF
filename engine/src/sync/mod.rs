//! Sync manager (section 6): fetch intel feeds when online, queue work when
//! offline, and report freshness. Sources are URL-configurable so the
//! community packs stay decoupled from the code.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

use crate::storage::sqlite::Storage;

/// Parses a hash feed: plain lines of sha256 OR the URLhaus CSV format
/// (`"id","date_time",...,"sha256_hash",...,"file_type",...`). Column names
/// are matched so upstream format tweaks don't break the parser.
fn parse_hash_feed(text: &str) -> Vec<String> {
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
        if line.contains('"') && line.starts_with('"') {
            // CSV row.
            let cols: Vec<&str> = line.split("\",\"").collect();
            if sha_col.is_none() {
                let header = line.to_lowercase();
                if let Some((i, _)) = header
                    .split("\",\"")
                    .enumerate()
                    .find(|(_, c)| c.contains("sha256"))
                {
                    sha_col = Some(i);
                }
                continue; // header row
            }
            if let Some(i) = sha_col
                && let Some(h) = cols.get(i) {
                    let h = h.trim_matches('"').trim().to_lowercase();
                    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
                        out.push(h);
                    }
                }
        } else if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push(line.to_lowercase());
        }
    }
    out
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub online: bool,
    pub ioc_hashes_added: usize,
    pub ioc_hash_total: u64,
    pub sources: Vec<SourceResult>,
}

#[derive(Debug, Serialize)]
pub struct SourceResult {
    pub source: String,
    pub ok: bool,
    pub detail: String,
}

pub struct SyncManager {
    client: Client,
    storage: Storage,
}

impl SyncManager {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("MI-CS-Engine/0.1")
            .build()?;
        Ok(Self { client, storage: Storage::open()? })
    }

    pub async fn online(&self) -> bool {
        // Real reachability probe against two independent endpoints.
        for url in ["https://dns.google/resolve?name=example.com", "https://1.1.1.1/"] {
            if self.client.get(url).send().await.is_ok() {
                return true;
            }
        }
        false
    }

    pub async fn sync_now(&self) -> Result<SyncReport> {
        let online = self.online().await;
        let mut report = SyncReport {
            online,
            ioc_hashes_added: 0,
            ioc_hash_total: self.storage.ioc_hash_count()?,
            sources: vec![],
        };
        if !online {
            return Ok(report);
        }

        // IOC hash feeds: the real abuse.ch URLhaus feed by default (full CSV
        // — sha256 column parsed), plus an optional extra source via env.
        let urls: Vec<(String, String)> = vec![
            (
                "urlhaus".to_string(),
                "https://urlhaus.abuse.ch/downloads/csv_recent/".to_string(),
            ),
            ("mics_extra".to_string(), std::env::var("MICS_IOC_FEED_URL").unwrap_or_default()),
        ]
        .into_iter()
        .filter(|(_, u)| !u.is_empty())
        .collect();

        for (source, url) in urls {
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.unwrap_or_default();
                    let hashes: Vec<(String, String)> = parse_hash_feed(&text)
                        .into_iter()
                        .map(|h| (h, source.clone()))
                        .collect();
                    match self.storage.add_ioc_hashes(&hashes) {
                        Ok(n) => {
                            report.ioc_hashes_added += n;
                            report.sources.push(SourceResult {
                                source,
                                ok: true,
                                detail: format!("{n} new hashes"),
                            });
                        }
                        Err(e) => report.sources.push(SourceResult {
                            source,
                            ok: false,
                            detail: format!("db: {e:#}"),
                        }),
                    }
                }
                Ok(resp) => report.sources.push(SourceResult {
                    source,
                    ok: false,
                    detail: format!("HTTP {}", resp.status()),
                }),
                Err(e) => report.sources.push(SourceResult {
                    source,
                    ok: false,
                    detail: format!("{e:#}"),
                }),
            }
        }

        // Flush the offline VT queue now that we're back online.
        let vt = crate::scanner::vt::VtClient::new();
        let ops = self.storage.pop_queue_ops("vt_lookup", 100)?;
        for (id, payload) in ops {
            if let Ok(hash) = serde_json::from_str::<String>(&payload)
                && vt.lookup_hash(&hash).await.is_ok() {
                    let _ = self.storage.remove_queue_op(id);
                }
        }

        self.storage.set_sync_state("ioc_hashes", "v1")?;
        report.ioc_hash_total = self.storage.ioc_hash_count()?;
        Ok(report)
    }

    /// Self-update manifest check: {version, url, sha256, size, notes_en, notes_ar}.
    pub async fn check_update(&self, url: &str) -> Result<serde_json::Value> {
        let resp = self.client.get(url).send().await.context("fetch update manifest")?;
        let manifest: serde_json::Value = resp.json().await.context("manifest json")?;
        let current = env!("CARGO_PKG_VERSION");
        let latest = manifest["version"].as_str().unwrap_or(current);
        Ok(serde_json::json!({
            "status": if latest != current { "available" } else { "up_to_date" },
            "current": current,
            "latest": latest,
            "download_url": manifest["url"].as_str(),
            "sha256": manifest["sha256"].as_str(),
            "notes_en": manifest["notes_en"].as_str(),
            "notes_ar": manifest["notes_ar"].as_str(),
        }))
    }

    /// Background loop: waits for connectivity, then refreshes intel on the
    /// cadence stored in settings (re-read every cycle, so changing the value
    /// in the UI applies without restarting the engine).
    pub fn start_auto_sync(rt: tokio::runtime::Handle) {
        std::thread::spawn(move || {
            // First tick after 2 min, then every interval.
            std::thread::sleep(std::time::Duration::from_secs(120));
            loop {
                let sm = match SyncManager::new() {
                    Ok(sm) => sm,
                    Err(_) => continue,
                };
                let online = rt.block_on(sm.online());
                if online {
                    match rt.block_on(sm.sync_now()) {
                        Ok(report) => {
                            tracing::info!(
                                "auto-sync: +{} hashes, total {}",
                                report.ioc_hashes_added,
                                report.ioc_hash_total
                            );
                        }
                        Err(e) => tracing::warn!("auto-sync failed: {e:#}"),
                    }
                }
                let hours = crate::settings::current().sync_hours().clamp(1, 168);
                std::thread::sleep(std::time::Duration::from_secs(hours as u64 * 3600));
            }
        });
    }

    pub async fn fetch_manifest(&self, url: &str) -> Result<serde_json::Value> {
        let resp = self.client.get(url).send().await.context("fetch manifest")?;
        resp.json().await.context("manifest json")
    }

    pub async fn download(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.client.get(url).send().await.context("download")?;
        if !resp.status().is_success() {
            anyhow::bail!("download returned {}", resp.status());
        }
        Ok(resp.bytes().await?.to_vec())
    }

    pub async fn get_status(&self) -> Result<serde_json::Value> {
        let online = self.online().await;
        Ok(serde_json::json!({
            "online": online,
            "ioc_hash_total": self.storage.ioc_hash_count()?,
            "vt_queue_len": self.storage.queue_len("vt_lookup")?,
        }))
    }
}
