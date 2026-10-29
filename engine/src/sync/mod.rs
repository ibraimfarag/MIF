//! Intel sync (section 6): fetch intel feeds when online, remember per-source
//! state, and report freshness. Sources are a fixed registry (D-012): each one
//! is consumed by a real feature, carries its own last-success/last-error and
//! its own next-due time, so one dead feed cannot hide the others behind a
//! single "last synced" number.
//!
//! Feed URLs are overridable (`MICS_IOC_FEED_URL`, `MICS_IOC_DOMAIN_FEED_URL`,
//! `MICS_KEV_FEED_URL`) so an air-gapped or licensed mirror can be pointed at
//! without a rebuild.

pub mod feeds;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

use crate::storage::sqlite::{Storage, SyncStateRow};

/// Marks a source that has nothing to do until it is configured. Distinct from
/// a failure: it never counts against the backoff and never claims freshness.
/// The storage layer writes this value, hence `pub(crate)`.
pub const NOT_CONFIGURED: &str = "not-configured";

/// How often the background thread wakes up to run whatever is due.
const TICK: Duration = Duration::from_secs(300);

/// The intel sources. Adding one means adding a `run_source` arm, a row on the
/// Intel screen and an i18n label — nothing picks them up by magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    IocHashes,
    IocDomains,
    Kev,
    /// Local country CIDR lists: no network, but the same state model so GeoIP
    /// freshness is as visible as the feeds'.
    LocalBlocklists,
}

impl Source {
    pub const ALL: [Source; 4] = [
        Source::IocHashes,
        Source::IocDomains,
        Source::Kev,
        Source::LocalBlocklists,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Source::IocHashes => "ioc_hashes",
            Source::IocDomains => "ioc_domains",
            Source::Kev => "kev",
            Source::LocalBlocklists => "geoip_blocklists",
        }
    }

    /// Sources that need the network. The local one must keep reporting while
    /// the machine is offline.
    pub fn network(self) -> bool {
        !matches!(self, Source::LocalBlocklists)
    }

    fn env_override(self) -> &'static str {
        match self {
            Source::IocHashes => "MICS_IOC_FEED_URL",
            Source::IocDomains => "MICS_IOC_DOMAIN_FEED_URL",
            Source::Kev => "MICS_KEV_FEED_URL",
            Source::LocalBlocklists => "",
        }
    }

    /// Live-checked defaults. The abuse.ch exports are deliberately absent:
    /// they answer `410 Gone` without an Auth-Key, so pointing at them would
    /// produce a permanent, misleading failure.
    fn default_url(self) -> &'static str {
        match self {
            // No key-free public sha256 feed survived the 2026 abuse.ch
            // lockdown; the user supplies one (their own MISP, an enterprise
            // mirror, or an abuse.ch Auth-Key URL).
            Source::IocHashes => "",
            Source::IocDomains => "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            Source::Kev => {
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            }
            Source::LocalBlocklists => "",
        }
    }

    pub fn feed_url(self) -> String {
        // The hash feed is user-configured (Settings → Intelligence) because no
        // key-free public export exists any more; the env hook lives in
        // `Settings::ioc_feed_url` so both paths agree.
        if self == Source::IocHashes {
            return crate::settings::current().ioc_feed_url().trim().to_string();
        }
        let env = self.env_override();
        if !env.is_empty()
            && let Ok(url) = std::env::var(env)
            && !url.trim().is_empty()
        {
            return url.trim().to_string();
        }
        self.default_url().to_string()
    }
}

/// What one source run produced. `ok` + `not_configured` are separate on
/// purpose: "nothing to do" must never look like success or like breakage.
struct Outcome {
    ok: bool,
    not_configured: bool,
    version: String,
    detail: String,
    items: i64,
    added: usize,
}

impl Outcome {
    fn ok(version: &str, detail: String, items: i64, added: usize) -> Self {
        Self { ok: true, not_configured: false, version: version.into(), detail, items, added }
    }
    fn not_configured(detail: &str) -> Self {
        Self {
            ok: false,
            not_configured: true,
            version: NOT_CONFIGURED.into(),
            detail: detail.into(),
            items: 0,
            added: 0,
        }
    }
    fn failed(detail: String) -> Self {
        Self { ok: false, not_configured: false, version: String::new(), detail, items: 0, added: 0 }
    }
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub online: bool,
    pub ioc_hashes_added: usize,
    pub ioc_hash_total: u64,
    pub ioc_domain_total: u64,
    pub kev_total: u64,
    pub sources: Vec<SourceResult>,
}

#[derive(Debug, Serialize)]
pub struct SourceResult {
    pub source: String,
    /// ok | failed | not_configured | skipped (not due this pass).
    pub state: String,
    pub ok: bool,
    pub detail: String,
    pub added: usize,
    pub items: i64,
    pub next_due: Option<i64>,
}

/// Retry ladder for a source that just failed: 15 minutes, doubling per
/// consecutive failure, never beyond the normal cadence — a flaky feed must not
/// end up polled more often than the schedule it replaces.
pub fn backoff_secs(failures: u32, cadence: i64) -> i64 {
    let base: i64 = 15 * 60;
    let factor = 1i64 << failures.saturating_sub(1).min(6);
    base.saturating_mul(factor).min(cadence.max(base))
}

/// State of a source as the UI reads it.
pub fn state_of(row: Option<&SyncStateRow>) -> &'static str {
    match row {
        None => "never",
        Some(r) if r.version.as_deref() == Some(NOT_CONFIGURED) => "not_configured",
        Some(r) if r.failures > 0 && r.last_error.is_some() => "failed",
        Some(r) if r.last_success.is_none() => "never",
        Some(_) => "ok",
    }
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
        // The UI polls the status once a minute: cache a positive probe for
        // 30 s and give each probe a short deadline, otherwise an offline
        // machine would tie up a request for the 30 s client timeout.
        static LAST: std::sync::OnceLock<std::sync::Mutex<Option<(bool, std::time::Instant)>>> =
            std::sync::OnceLock::new();
        let cache = LAST.get_or_init(|| std::sync::Mutex::new(None));
        if let Ok(guard) = cache.lock()
            && let Some((value, at)) = *guard
            && at.elapsed() < Duration::from_secs(30)
        {
            return value;
        }

        let mut online = false;
        for url in ["https://dns.google/resolve?name=example.com", "https://1.1.1.1/"] {
            if self
                .client
                .get(url)
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .is_ok()
            {
                online = true;
                break;
            }
        }
        if let Ok(mut guard) = cache.lock() {
            *guard = Some((online, std::time::Instant::now()));
        }
        online
    }

    /// Manual sync (the chip and the Settings button): everything runs now,
    /// including sources that are not due.
    pub async fn sync_now(&self) -> Result<SyncReport> {
        self.run(false).await
    }

    /// Scheduled pass: only the sources whose next-due time has passed.
    pub async fn run_due(&self) -> Result<SyncReport> {
        self.run(true).await
    }

    async fn run(&self, due_only: bool) -> Result<SyncReport> {
        let online = self.online().await;
        let cadence = self.cadence_secs();
        let now = chrono::Utc::now().timestamp();
        let mut report = SyncReport {
            online,
            ioc_hashes_added: 0,
            ioc_hash_total: self.storage.ioc_hash_count()?,
            ioc_domain_total: self.storage.ioc_domain_count()?,
            kev_total: self.storage.kev_count()?,
            sources: Vec::new(),
        };
        if !online {
            // Offline is not a source failure: nothing was attempted, so
            // nothing is recorded and no backoff is spent.
            return Ok(report);
        }

        let states = self.storage.sync_states()?;
        for source in Source::ALL {
            let row = states.iter().find(|r| r.source == source.id());
            let due = row
                .and_then(|r| r.next_due)
                .map(|d| d <= now)
                .unwrap_or(true);
            if due_only && !due {
                report.sources.push(SourceResult {
                    source: source.id().into(),
                    state: "skipped".into(),
                    ok: true,
                    detail: "not due".into(),
                    added: 0,
                    items: row.map(|r| r.items).unwrap_or(0),
                    next_due: row.and_then(|r| r.next_due),
                });
                continue;
            }

            let outcome = self.run_source(source).await;
            let failures = row.map(|r| r.failures).unwrap_or(0);
            let next_due = now
                + if outcome.ok || outcome.not_configured {
                    cadence
                } else {
                    backoff_secs(failures + 1, cadence)
                };
            if outcome.ok {
                self.storage.record_sync_success(
                    source.id(),
                    &outcome.version,
                    &outcome.detail,
                    outcome.items,
                    Some(next_due),
                )?;
            } else if outcome.not_configured {
                self.storage.record_sync_skipped(source.id(), &outcome.detail, Some(next_due))?;
            } else {
                tracing::warn!("intel source {} failed: {}", source.id(), outcome.detail);
                self.storage
                    .record_sync_failure(source.id(), &outcome.detail, Some(next_due))?;
            }

            report.ioc_hashes_added += outcome.added;
            report.sources.push(SourceResult {
                source: source.id().into(),
                state: if outcome.ok {
                    "ok".into()
                } else if outcome.not_configured {
                    "not_configured".into()
                } else {
                    "failed".into()
                },
                ok: outcome.ok,
                detail: outcome.detail,
                added: outcome.added,
                items: outcome.items,
                next_due: Some(next_due),
            });
        }

        // Flush the offline VT queue now that we're back online.
        let vt = crate::scanner::vt::VtClient::new();
        let ops = self.storage.pop_queue_ops("vt_lookup", 100)?;
        for (id, payload) in ops {
            if let Ok(hash) = serde_json::from_str::<String>(&payload)
                && vt.lookup_hash(&hash).await.is_ok()
            {
                let _ = self.storage.remove_queue_op(id);
            }
        }

        report.ioc_hash_total = self.storage.ioc_hash_count()?;
        report.ioc_domain_total = self.storage.ioc_domain_count()?;
        report.kev_total = self.storage.kev_count()?;
        Ok(report)
    }

    fn cadence_secs(&self) -> i64 {
        crate::settings::current().sync_hours().clamp(1, 168) as i64 * 3600
    }

    async fn run_source(&self, source: Source) -> Outcome {
        match source {
            Source::IocHashes => self.run_ioc_hashes().await,
            Source::IocDomains => self.run_ioc_domains().await,
            Source::Kev => self.run_kev().await,
            Source::LocalBlocklists => self.run_local_blocklists(),
        }
    }

    async fn fetch_text(&self, url: &str) -> Result<String> {
        self.fetch_text_auth(url, "").await
    }

    /// Some feeds (abuse.ch) authenticate with an `Auth-Key` header rather than
    /// a query parameter, so the key never lands in a URL that gets logged.
    async fn fetch_text_auth(&self, url: &str, auth_key: &str) -> Result<String> {
        let mut req = self.client.get(url);
        if !auth_key.trim().is_empty() {
            req = req.header("Auth-Key", auth_key.trim());
        }
        let resp = req.send().await.context("request")?;
        if !resp.status().is_success() {
            anyhow::bail!("HTTP {}", resp.status());
        }
        resp.text().await.context("body")
    }

    async fn run_ioc_hashes(&self) -> Outcome {
        let url = Source::IocHashes.feed_url();
        if url.is_empty() {
            return Outcome::not_configured(
                "no hash feed configured — set one in Settings → Intelligence (abuse.ch needs an Auth-Key)",
            );
        }
        let text = match self
            .fetch_text_auth(&url, &crate::settings::current().ioc_feed_key())
            .await
        {
            Ok(t) => t,
            Err(e) => return Outcome::failed(format!("{e:#}")),
        };
        let hashes: Vec<(String, String)> = feeds::parse_hash_feed(&text)
            .into_iter()
            .map(|h| (h, "feed".to_string()))
            .collect();
        if hashes.is_empty() {
            return Outcome::failed(format!("no sha256 hash found in {url}"));
        }
        match self.storage.add_ioc_hashes(&hashes) {
            Ok(n) => {
                let total = self.storage.ioc_hash_count().unwrap_or(0) as i64;
                Outcome::ok(
                    &feed_host(&url),
                    format!("{n} new of {} rows", hashes.len()),
                    total,
                    n,
                )
            }
            Err(e) => Outcome::failed(format!("db: {e:#}")),
        }
    }

    async fn run_ioc_domains(&self) -> Outcome {
        let url = Source::IocDomains.feed_url();
        let text = match self.fetch_text(&url).await {
            Ok(t) => t,
            Err(e) => return Outcome::failed(format!("{e:#}")),
        };
        let domains: Vec<(String, String)> = feeds::parse_hosts_blocklist(&text)
            .into_iter()
            .map(|d| (d, "stevenblack".to_string()))
            .collect();
        if domains.is_empty() {
            return Outcome::failed(format!("no hostname found in {url}"));
        }
        match self.storage.add_ioc_domains(&domains, "dns-blocklist") {
            Ok(added) => {
                let total = self.storage.ioc_domain_count().unwrap_or(0) as i64;
                Outcome::ok(
                    "stevenblack",
                    format!("{added} new of {} blocked names", domains.len()),
                    total,
                    added,
                )
            }
            Err(e) => Outcome::failed(format!("db: {e:#}")),
        }
    }

    async fn run_kev(&self) -> Outcome {
        let url = Source::Kev.feed_url();
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Outcome::failed(format!("{e:#}")),
        };
        if !resp.status().is_success() {
            return Outcome::failed(format!("HTTP {}", resp.status()));
        }
        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return Outcome::failed(format!("json: {e:#}")),
        };
        let (version, rows) = feeds::parse_kev_catalog(&body);
        if rows.is_empty() {
            return Outcome::failed("catalog contained no CVE".to_string());
        }
        match self.storage.set_kev_catalog(&rows) {
            Ok(n) => Outcome::ok(
                &version,
                format!("{n} actively exploited CVEs (catalog {version})"),
                n as i64,
                0,
            ),
            Err(e) => Outcome::failed(format!("db: {e:#}")),
        }
    }

    /// Country CIDR lists already on disk. Nothing is downloaded here: the
    /// public country lists carry their own licence, so the engine reports what
    /// is installed (and reloads the GeoIP table) instead of shipping one.
    fn run_local_blocklists(&self) -> Outcome {
        let dir = crate::ids::geoip::blocklist_dir();
        let countries = crate::ids::geoip::installed_countries();
        let ranges = crate::ids::geoip::refresh();
        if countries.is_empty() {
            return Outcome::not_configured(&format!(
                "no country list in {} — GeoIP stays empty until one is added",
                dir.display()
            ));
        }
        Outcome::ok(
            "local",
            format!("{} country lists, {ranges} ranges", countries.len()),
            ranges as i64,
            0,
        )
    }

    /// Background loop: waits for connectivity, then runs whatever is due.
    /// A source sets its own next-due time, so a dead feed backs off without
    /// delaying the healthy ones.
    pub fn start_auto_sync(rt: tokio::runtime::Handle) {
        std::thread::spawn(move || {
            // First tick after 2 min, then a short tick that only does work
            // when a source is actually due.
            std::thread::sleep(Duration::from_secs(120));
            loop {
                let sm = match SyncManager::new() {
                    Ok(sm) => sm,
                    Err(_) => continue,
                };
                match rt.block_on(sm.run_due()) {
                    Ok(report) if !report.sources.is_empty() => {
                        for s in &report.sources {
                            if s.state != "skipped" {
                                tracing::info!("auto-sync: {} -> {} ({})", s.source, s.state, s.detail);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("auto-sync failed: {e:#}"),
                }
                std::thread::sleep(TICK);
            }
        });
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

    /// Everything the UI needs for the Intel screen and the freshness badge.
    pub async fn get_status(&self) -> Result<serde_json::Value> {
        let online = self.online().await;
        let states = self.storage.sync_states()?;
        let now = chrono::Utc::now().timestamp();
        let mut sources: Vec<serde_json::Value> = Source::ALL
            .iter()
            .map(|s| {
                let row = states.iter().find(|r| r.source == s.id());
                source_json(s.id(), s.network(), false, row, now)
            })
            .collect();

        // `nvd` has no feed to poll — it is recorded by the vulnerability scan
        // itself — so it gets a row marked on-demand instead of a schedule that
        // would never run.
        let nvd = states.iter().find(|r| r.source == "nvd");
        sources.push(source_json("nvd", true, true, nvd, now));

        // "Intel freshness" means the newest successful *network* sync: a local
        // list refresh must not make an offline machine look up to date.
        let last_success = states
            .iter()
            .filter(|r| {
                Source::ALL
                    .iter()
                    .any(|s| s.network() && s.id() == r.source)
            })
            .filter_map(|r| r.last_success)
            .max();

        Ok(serde_json::json!({
            "online": online,
            "ioc_hash_total": self.storage.ioc_hash_count()?,
            "ioc_domain_total": self.storage.ioc_domain_count()?,
            "kev_total": self.storage.kev_count()?,
            "cve_cache_total": self.storage.cached_cve_count()?,
            "geoip_countries": crate::ids::geoip::installed_countries().len(),
            "vt_queue_len": self.storage.queue_len("vt_lookup")?,
            "last_success": last_success,
            // Seconds since the last successful intel sync; null when the
            // machine has never synced (fresh, fully-offline install).
            "age_seconds": last_success.map(|t| (now - t).max(0)),
            "sync_interval_hours": crate::settings::current().sync_hours(),
            "sources": sources,
        }))
    }
}

/// One source row, shaped once so the UI can render every source with the same
/// widget (and so a missing row reads as "never" instead of crashing a screen).
fn source_json(
    id: &str,
    network: bool,
    on_demand: bool,
    row: Option<&SyncStateRow>,
    now: i64,
) -> serde_json::Value {
    serde_json::json!({
        "source": id,
        "network": network,
        "on_demand": on_demand,
        "state": state_of(row),
        "last_success": row.and_then(|r| r.last_success),
        "last_attempt": row.and_then(|r| r.last_attempt),
        "age_seconds": row.and_then(|r| r.last_success).map(|t| (now - t).max(0)),
        "next_due": row.and_then(|r| r.next_due),
        "seconds_to_due": row.and_then(|r| r.next_due).map(|d| (d - now).max(0)),
        "failures": row.map(|r| r.failures).unwrap_or(0),
        "last_error": row.and_then(|r| r.last_error.clone()),
        "detail": row.and_then(|r| r.detail.clone()),
        "version": row.and_then(|r| r.version.clone()),
        "items": row.map(|r| r.items).unwrap_or(0),
    })
}

/// Feed name for the `version` column: the host is enough to tell one mirror
/// from another without storing a full URL in the UI.
fn feed_host(url: &str) -> String {
    url.split("//")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("feed")
        .to_string()
}
