//! VirusTotal v3 hash lookup. Free tier: 4 req/min — enforced locally.
//! Offline: the lookup is queued in sync_queue and flushed on reconnect.

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde_json::Value;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::storage::sqlite::Storage;

pub struct VtClient {
    client: Client,
}

static LAST_REQUEST: OnceLock<std::sync::Mutex<Instant>> = OnceLock::new();
static REQ_COUNT: AtomicU32 = AtomicU32::new(0);

#[allow(dead_code)]
impl VtClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("MI-CS-Engine/0.1")
            .build()
            .unwrap_or_default();
        Self { client }
    }

    fn api_key() -> String {
        std::env::var("MICS_VT_API_KEY").unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn configured() -> bool {
        !Self::api_key().is_empty()
    }

    /// 4 requests per 60 s (free tier); blocks locally before sending.
    async fn respect_rate_limit() {
        let gate = LAST_REQUEST
            .get_or_init(|| std::sync::Mutex::new(Instant::now() - Duration::from_secs(60)));
        loop {
            // Compute the wait under the lock, release it, then sleep —
            // the guard must never be held across an await.
            let wait = {
                #[allow(unused_mut)]
            let mut last = gate.lock().unwrap();
                let elapsed = last.elapsed();
                if REQ_COUNT.load(Ordering::SeqCst) >= 4 {
                    if elapsed >= Duration::from_secs(60) {
                        REQ_COUNT.store(0, Ordering::SeqCst);
                        None
                    } else {
                        Some(Duration::from_secs(60) - elapsed)
                    }
                } else {
                    None
                }
            };
            if let Some(w) = wait {
                tokio::time::sleep(w).await;
                REQ_COUNT.store(0, Ordering::SeqCst);
                continue;
            }
            #[allow(unused_mut)]
            let mut last = gate.lock().unwrap();
            *last = Instant::now();
            REQ_COUNT.fetch_add(1, Ordering::SeqCst);
            return;
        }
    }

    /// Returns (malicious_count, engines_total) or an error.
    pub async fn lookup_hash(&self, sha256: &str) -> Result<(u64, u64)> {
        let key = Self::api_key();
        if key.is_empty() {
            bail!("no VT API key configured (Settings → MICS_VT_API_KEY)");
        }
        Self::respect_rate_limit().await;
        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let resp = self
            .client
            .get(url)
            .header("x-apikey", key)
            .send()
            .await
            .context("VT request")?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok((0, 0)); // unknown to VT — not malicious
        }
        if !resp.status().is_success() {
            bail!("VT returned {}", resp.status());
        }
        let body: Value = resp.json().await.context("VT json")?;
        let stats = &body["data"]["attributes"]["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let total = ["malicious", "suspicious", "undetected", "harmless", "timeout"]
            .iter()
            .filter_map(|k| stats[*k].as_u64())
            .sum();
        Ok((malicious, total))
    }

    /// Online lookup, or queue for the next sync when offline.
    pub async fn lookup_or_queue(&self, sha256: &str) -> Result<(u64, u64, bool)> {
        if self.is_online().await {
            let r = self.lookup_hash(sha256).await?;
            Ok((r.0, r.1, false))
        } else {
            Storage::open()?.queue_op("vt_lookup", &serde_json::to_string(sha256)?)?;
            Ok((0, 0, true))
        }
    }

    async fn is_online(&self) -> bool {
        self.client
            .get("https://dns.google/resolve?name=example.com")
            .send()
            .await
            .is_ok()
    }
}
