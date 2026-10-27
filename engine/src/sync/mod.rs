//! Sync manager (section 6): fetch intel feeds when online, queue work when
//! offline, and report freshness. Sources are URL-configurable so the
//! community packs stay decoupled from the code.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

use crate::storage::sqlite::Storage;

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

        // IOC hash feed: MICS_IOC_FEED_URL (CSV: sha256 per line, `#source`
        // comment header optional) — community-pack friendly.
        let urls: Vec<(String, String)> = [
            ("mics_starter".to_string(), std::env::var("MICS_IOC_FEED_URL").unwrap_or_default()),
        ]
        .iter()
        .filter(|(_, u)| !u.is_empty())
        .map(|(s, u)| (s.clone(), u.clone()))
        .collect();

        for (source, url) in urls {
            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.unwrap_or_default();
                    let hashes: Vec<(String, String)> = text
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty() && !l.starts_with('#') && l.len() == 64)
                        .map(|l| (l.to_lowercase(), source.clone()))
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
            if let Ok(hash) = serde_json::from_str::<String>(&payload) {
                if vt.lookup_hash(&hash).await.is_ok() {
                    let _ = self.storage.remove_queue_op(id);
                }
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

    /// Background loop: waits for connectivity, then refreshes intel every
    /// `interval_hours`. Runs for the engine's lifetime (spawned by --serve).
    /// Background loop: waits for connectivity, then refreshes intel every
    /// `interval_hours`. Runs for the engine's lifetime; needs the tokio
    /// handle because sync IO is async.
    pub fn start_auto_sync(rt: tokio::runtime::Handle, interval_hours: u64) {
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
                std::thread::sleep(std::time::Duration::from_secs(
                    (interval_hours.clamp(1, 168) * 3600) as u64,
                ));
            }
        });
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
