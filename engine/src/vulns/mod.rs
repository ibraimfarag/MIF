use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};
use reqwest::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use crate::platform::traits::PlatformCollectors;
use crate::storage::sqlite::Storage;

/// NVD's public limit is 5 requests / 30 s, so the loop waits between
/// applications. That is also why the scan is a job: minutes of work behind a
/// blocking RPC is a spinner the user cannot cancel.
const RATE_LIMIT: Duration = Duration::from_millis(6500);

/// Progress is only useful if a cancel is felt within a fraction of the step,
/// so the rate-limit pause is sliced rather than slept in one go.
const PAUSE_SLICE: Duration = Duration::from_millis(200);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub cvss: f64,
    pub description: String,
    pub published: String,
    /// In CISA's Known Exploited Vulnerabilities catalog: this one is being
    /// exploited in the wild, which outranks its CVSS score for prioritisation.
    #[serde(default)]
    pub known_exploited: bool,
    /// The catalog's remediation due date (only when `known_exploited`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kev_due: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoftwareVulns {
    pub software: String,
    pub version: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub from_cache: bool,
}

/// NVD API 2.0 client with a local SQLite cache. Online: query + persist.
/// Offline: serve the cache and flag it (`from_cache`), so the UI shows
/// "intel last synced" honesty instead of pretending it's live.
pub struct VulnScanner {
    client: Client,
    storage: Storage,
    /// CVE id -> KEV entry, read once per scanner: a couple of thousand rows,
    /// and the difference between "this CVE exists" and "it is exploited now".
    kev: std::collections::HashMap<String, crate::storage::sqlite::KevRow>,
}

/// Known-app -> NVD keyword map. Real CPE matching needs the Phase-5 intel
/// sync; keyword search against NVD returns the same CVE set for these apps.
const KEYWORD_MAP: &[(&str, &str)] = &[
    ("google chrome", "Google Chrome"),
    ("microsoft edge", "Microsoft Edge"),
    ("firefox", "Mozilla Firefox"),
    ("7-zip", "7-Zip"),
    ("vlc media player", "VLC media player"),
    ("winrar", "WinRAR"),
    ("notepad++", "Notepad++"),
    ("adobe", "Adobe Acrobat"),
    ("java", "Oracle Java"),
    ("openvpn", "OpenVPN"),
    ("git", "Git"),
    ("node", "Node.js"),
    ("python", "Python"),
    ("putty", "PuTTY"),
    ("wireshark", "Wireshark"),
    ("vmware", "VMware Workstation"),
    ("docker", "Docker Desktop"),
    ("steam", "Steam"),
    ("discord", "Discord"),
    ("obs studio", "OBS Studio"),
    ("gimp", "GIMP"),
    ("libreoffice", "LibreOffice"),
    ("teamviewer", "TeamViewer"),
    ("anydesk", "AnyDesk"),
    ("openssl", "OpenSSL"),
    ("curl", "curl"),
    ("ffmpeg", "FFmpeg"),
    ("utorrent", "uTorrent"),
    ("internet download manager", "Internet Download Manager"),
];

/// Marks CVEs that CISA lists as exploited in the wild. Free-standing so the
/// annotation can be tested without a network client or a database.
pub fn annotate_kev(
    vulns: &mut [Vulnerability],
    kev: &std::collections::HashMap<String, crate::storage::sqlite::KevRow>,
) {
    for vuln in vulns {
        if let Some(entry) = kev.get(&vuln.cve_id) {
            vuln.known_exploited = true;
            if !entry.due_date.is_empty() {
                vuln.kev_due = Some(entry.due_date.clone());
            }
        }
    }
}

impl VulnScanner {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("MI-CS-Engine/0.1")
            .build()
            .context("build http client")?;
        let storage = Storage::open()?;
        let kev = match storage.kev_catalog() {
            Ok(rows) => rows.into_iter().map(|r| (r.cve_id.clone(), r)).collect(),
            Err(e) => {
                // No catalog yet (never synced) is normal on a fresh install;
                // the scan still works, it just cannot flag exploited CVEs.
                tracing::warn!("KEV catalog unavailable: {e:#}");
                std::collections::HashMap::new()
            }
        };
        Ok(Self { client, storage, kev })
    }

    /// Applications worth looking up, in inventory order, with the NVD keyword
    /// and the installed version. The job's only entry point: `vuln.scan` (the
    /// blocking variant) is gone, so there is exactly one scanning path (و4).
    async fn targets(&self, max_apps: usize) -> Result<Vec<(String, String, String)>> {
        let collectors = crate::platform::windows::collectors::WindowsCollectors;
        let inventory = collectors.get_software_inventory().await?;
        let mut targets: Vec<(String, String, String)> = Vec::new();
        for sw in &inventory {
            let lowered = sw.name.to_lowercase();
            for (needle, keyword) in KEYWORD_MAP {
                if lowered.contains(needle) {
                    targets.push((sw.name.clone(), keyword.to_string(), sw.version.clone()));
                    break;
                }
            }
            if targets.len() >= max_apps {
                break;
            }
        }
        Ok(targets)
    }

    /// One application: cache first, NVD when the cache is cold. The cache is
    /// what makes a re-scan of an unchanged machine instant and offline-safe.
    async fn scan_one(
        &self,
        name: &str,
        keyword: &str,
        version: &str,
        tally: &mut ScanTally,
    ) -> SoftwareVulns {
        let cached = match self.storage.cached_cves_for(name) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("CVE cache read failed for {name}: {e:#}");
                Vec::new()
            }
        };
        if !cached.is_empty() {
            let mut vulnerabilities: Vec<Vulnerability> = cached
                .into_iter()
                .map(|c| Vulnerability {
                    cve_id: c.cve_id,
                    cvss: c.cvss,
                    description: c.description,
                    published: c.published,
                    known_exploited: false,
                    kev_due: None,
                })
                .collect();
            annotate_kev(&mut vulnerabilities, &self.kev);
            tally.cached += 1;
            tally.cves += vulnerabilities.len();
            return SoftwareVulns {
                software: name.to_string(),
                version: version.to_string(),
                from_cache: true,
                vulnerabilities,
            };
        }

        match self.fetch_nvd(keyword, name).await {
            Ok(mut vulns) => {
                annotate_kev(&mut vulns, &self.kev);
                tally.live += 1;
                tally.cves += vulns.len();
                SoftwareVulns {
                    software: name.to_string(),
                    version: version.to_string(),
                    from_cache: false,
                    vulnerabilities: vulns,
                }
            }
            Err(e) => {
                tracing::warn!("NVD fetch failed for {name}: {e:#}");
                tally.failed += 1;
                tally.last_error = Some(format!("{e:#}"));
                SoftwareVulns {
                    software: name.to_string(),
                    version: version.to_string(),
                    from_cache: true,
                    vulnerabilities: vec![],
                }
            }
        }
    }

    /// Records the scan as the `nvd` intel source, so CVE freshness sits next
    /// to the feed freshness on the Intel screen. Called only after real work:
    /// a scan that found nothing to look up must not claim a successful sync.
    fn record_nvd_state(&self, tally: &ScanTally) {
        if tally.live == 0 && tally.cached == 0 && tally.last_error.is_none() {
            return;
        }
        let cadence = crate::settings::current().sync_hours().clamp(1, 168) as i64 * 3600;
        let now = chrono::Utc::now().timestamp();
        let cached = self.storage.cached_cve_count().unwrap_or(0) as i64;
        if tally.live > 0 || tally.last_error.is_none() {
            let detail = if tally.live > 0 {
                format!(
                    "{} live NVD lookups ({} from cache, {} CVEs)",
                    tally.live, tally.cached, tally.cves
                )
            } else {
                format!("{} applications served from cache", tally.cached)
            };
            let _ = self
                .storage
                .record_sync_success("nvd", "NVD 2.0", &detail, cached, Some(now + cadence));
        } else if let Some(err) = tally.last_error.as_deref() {
            let _ = self.storage.record_sync_failure(
                "nvd",
                err,
                Some(now + crate::sync::backoff_secs(1, cadence)),
            );
        }
    }

    async fn fetch_nvd(&self, keyword: &str, software_key: &str) -> Result<Vec<Vulnerability>> {
        let mut url = reqwest::Url::parse("https://services.nvd.nist.gov/rest/json/cves/2.0")?;
        url.query_pairs_mut()
            .append_pair("keywordSearch", keyword)
            .append_pair("resultsPerPage", "10");

        let mut req = self.client.get(url);
        let key = crate::settings::current().nvd_key();
        if !key.is_empty() {
            req = req.header("apiKey", key);
        }
        let resp = req.send().await.context("NVD request")?;
        if !resp.status().is_success() {
            anyhow::bail!("NVD returned {}", resp.status());
        }
        let body: serde_json::Value = resp.json().await.context("NVD json")?;

        let mut out = Vec::new();
        if let Some(items) = body["vulnerabilities"].as_array() {
            for item in items {
                let cve = &item["cve"];
                let Some(id) = cve["id"].as_str() else { continue };
                let desc = cve["descriptions"]
                    .as_array()
                    .and_then(|ds| {
                        ds.iter()
                            .find(|d| d["lang"] == "en")
                            .and_then(|d| d["value"].as_str())
                    })
                    .unwrap_or("")
                    .to_string();
                // Prefer v3.1, then v3.0, then v2 base score.
                let metric = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
                    .iter()
                    .find_map(|m| cve["metrics"][m].as_array().and_then(|a| a.first()));
                let cvss = metric
                    .and_then(|m| {
                        m["cvssData"]["baseScore"]
                            .as_f64()
                            .or_else(|| m["impactScore"].as_f64())
                    })
                    .unwrap_or(0.0);
                let published = cve["published"].as_str().unwrap_or("").to_string();
                self.storage
                    .cache_cve(id, cvss, &desc, software_key, &published)?;
                out.push(Vulnerability {
                    cve_id: id.to_string(),
                    cvss,
                    description: desc,
                    published,
                    known_exploited: false,
                    kev_due: None,
                });
            }
        }
        Ok(out)
    }
}

/// What one pass over the applications produced, for the `nvd` source state.
#[derive(Default)]
struct ScanTally {
    live: usize,
    cached: usize,
    cves: usize,
    failed: usize,
    last_error: Option<String>,
}

/// Rate-limit pause that a cancel can cut short, so stopping a scan does not
/// wait for the slowest step of the loop.
pub(crate) async fn pause(duration: Duration, cancel: Option<&AtomicBool>) {
    let mut left = duration;
    while left > Duration::ZERO {
        if cancel.is_some_and(|c| c.load(Ordering::SeqCst)) {
            return;
        }
        let slice = left.min(PAUSE_SLICE);
        tokio::time::sleep(slice).await;
        left = left.saturating_sub(slice);
    }
}

pub(crate) fn pct(done: usize, total: usize) -> u32 {
    if total == 0 {
        return 0;
    }
    ((done as f64 / total as f64) * 100.0).clamp(0.0, 100.0) as u32
}

/// Starts a vulnerability scan as a durable, cancellable job and returns its
/// id. Progress, findings and the terminal state are all persisted, so closing
/// the window (or restarting the engine) never loses what was already checked.
pub fn start_scan(max_apps: usize, rt: tokio::runtime::Handle) -> Result<String> {
    if crate::jobs::active_count() > 0 {
        anyhow::bail!("another job is running");
    }
    let job_id = crate::jobs::new_job_id("vuln_scan");
    let storage = Storage::open()?;
    // A vulnerability scan has no root path and no quarantine stage: the job row
    // exists so the UI can poll it and so a restart leaves a visible record.
    storage.create_job(&job_id, "vuln_scan", "", false)?;
    let cancel = crate::jobs::register(&job_id);
    let id = job_id.clone();
    rt.spawn(async move {
        run_scan_job(id.clone(), max_apps, cancel).await;
        crate::jobs::unregister(&id);
    });
    Ok(job_id)
}

async fn run_scan_job(job_id: String, max_apps: usize, cancel: Arc<AtomicBool>) {
    let storage = match Storage::open() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("vuln_scan {job_id}: storage unavailable: {e:#}");
            crate::jobs::finished(&job_id, "failed", 0);
            return;
        }
    };
    let scanner = match VulnScanner::new() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("vuln_scan {job_id} init failed: {e:#}");
            let _ = storage.set_job_state(&job_id, "failed", Some(&format!("{e:#}")));
            crate::jobs::progress(&job_id, "failed", 0, "init failed", 0, 0, 0, 0);
            crate::jobs::finished(&job_id, "failed", 0);
            return;
        }
    };
    let _ = storage.set_job_state(&job_id, "running", None);
    crate::jobs::progress(&job_id, "running", 0, "collecting software inventory", 0, 0, 0, 0);

    let targets = match scanner.targets(max_apps).await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("vuln_scan {job_id}: inventory failed: {e:#}");
            let _ = storage.set_job_state(&job_id, "failed", Some(&format!("{e:#}")));
            crate::jobs::progress(&job_id, "failed", 0, "inventory failed", 0, 0, 0, 0);
            crate::jobs::finished(&job_id, "failed", 0);
            return;
        }
    };
    let total = targets.len();
    let _ = storage.set_job_total(&job_id, total as i64);

    let mut tally = ScanTally::default();
    let mut findings = 0i64;
    let mut state = "done";
    for (i, (name, keyword, version)) in targets.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            state = "cancelled";
            break;
        }
        let item = scanner.scan_one(name, keyword, version, &mut tally).await;
        let cves = item.vulnerabilities.len() as i64;
        findings += cves;
        // Persisted per application: a cancelled or interrupted scan still
        // shows everything it did check.
        if let Ok(payload) = serde_json::to_string(&item) {
            let _ = storage.add_job_finding(&job_id, i as i64, &payload);
        }
        let _ = storage.set_job_progress(
            &job_id,
            (i + 1) as i64,
            (i + 1) as i64,
            tally.failed as i64,
            findings,
        );
        crate::jobs::progress(
            &job_id,
            "running",
            pct(i + 1, total),
            name,
            (i + 1) as i64,
            tally.failed as i64,
            total as i64,
            findings,
        );
        if i + 1 < total {
            pause(RATE_LIMIT, Some(&cancel)).await;
        }
    }

    let _ = storage.set_job_progress(
        &job_id,
        tally.live as i64 + tally.cached as i64,
        tally.live as i64 + tally.cached as i64,
        tally.failed as i64,
        findings,
    );
    let _ = storage.set_job_state(&job_id, state, None);
    scanner.record_nvd_state(&tally);
    crate::jobs::progress(
        &job_id,
        state,
        if state == "done" { 100 } else { pct(tally.live + tally.cached, total) },
        state,
        (tally.live + tally.cached) as i64,
        tally.failed as i64,
        total as i64,
        findings,
    );
    crate::jobs::finished(&job_id, state, findings);
}
