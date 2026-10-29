use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use crate::platform::traits::PlatformCollectors;
use crate::storage::sqlite::Storage;

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

    pub async fn scan(&self, max_apps: usize) -> Result<Vec<SoftwareVulns>> {
        let collectors = crate::platform::windows::collectors::WindowsCollectors;
        let inventory = collectors.get_software_inventory().await?;

        let mut targets: Vec<(String, String)> = Vec::new();
        for sw in &inventory {
            let lowered = sw.name.to_lowercase();
            for (needle, keyword) in KEYWORD_MAP {
                if lowered.contains(needle) {
                    targets.push((sw.name.clone(), keyword.to_string()));
                    break;
                }
            }
            if targets.len() >= max_apps {
                break;
            }
        }

        let mut results = Vec::new();
        let mut live = 0usize;
        let mut served_cache = 0usize;
        let mut last_error: Option<String> = None;
        for (name, keyword) in &targets {
            let version = inventory
                .iter()
                .find(|s| &s.name == name)
                .map(|s| s.version.clone())
                .unwrap_or_default();

            let cached = self.storage.cached_cves_for(name)?;
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
                served_cache += 1;
                results.push(SoftwareVulns {
                    software: name.clone(),
                    version: version.clone(),
                    from_cache: true,
                    vulnerabilities,
                });
                continue;
            }

            match self.fetch_nvd(keyword, name).await {
                Ok(mut vulns) => {
                    annotate_kev(&mut vulns, &self.kev);
                    live += 1;
                    results.push(SoftwareVulns {
                        software: name.clone(),
                        version,
                        from_cache: false,
                        vulnerabilities: vulns,
                    });
                }
                Err(e) => {
                    tracing::warn!("NVD fetch failed for {name}: {e:#}");
                    last_error = Some(format!("{e:#}"));
                    results.push(SoftwareVulns {
                        software: name.clone(),
                        version,
                        from_cache: true,
                        vulnerabilities: vec![],
                    });
                }
            }
            // NVD public rate limit: 5 requests / 30 s without a key.
            tokio::time::sleep(Duration::from_millis(6500)).await;
        }
        self.record_nvd_state(live, served_cache, last_error.as_deref());
        Ok(results)
    }

    /// Records the scan as the `nvd` intel source, so CVE freshness sits next
    /// to the feed freshness on the Intel screen. Called only after real work:
    /// a scan that found nothing to look up must not claim a successful sync.
    fn record_nvd_state(&self, live: usize, served_cache: usize, last_error: Option<&str>) {
        if live == 0 && served_cache == 0 && last_error.is_none() {
            return;
        }
        let cadence = crate::settings::current().sync_hours().clamp(1, 168) as i64 * 3600;
        let now = chrono::Utc::now().timestamp();
        let cached = self.storage.cached_cve_count().unwrap_or(0) as i64;
        if live > 0 || last_error.is_none() {
            let detail = if live > 0 {
                format!("{live} live NVD lookups ({served_cache} from cache)")
            } else {
                format!("{served_cache} applications served from cache")
            };
            let _ = self
                .storage
                .record_sync_success("nvd", "NVD 2.0", &detail, cached, Some(now + cadence));
        } else if let Some(err) = last_error {
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
