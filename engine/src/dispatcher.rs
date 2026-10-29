use crate::rpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use serde_json::json;
use std::path::PathBuf;
use tracing::{info, warn, error};
use crate::platform::traits::PlatformCollectors;
pub struct Dispatcher;

fn error_response(req: JsonRpcRequest, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(json!(JsonRpcError {
            code: -32602,
            message: message.to_string(),
            data: None,
        })),
        id: req.id,
    }
}

/// A known method that failed: keep the real reason instead of the generic
/// "Method failed internally", so the UI can show something actionable
/// ("requires administrator rights", "the operation timed out", ...).
fn detailed_error(req: JsonRpcRequest, method: &str, e: anyhow::Error) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(json!(JsonRpcError {
            code: -32000,
            message: format!("{method} failed: {e:#}"),
            data: None,
        })),
        id: req.id,
    }
}

impl Dispatcher {
    pub async fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
        info!("Processing request: {}", req.method);

        let mut unknown = false;
        let result = match req.method.as_str() {
            "ping" => {
                info!("Ping received");
                Some(json!("pong"))
            }
            "status" => {
                Some(json!({
                    "state": "running",
                    "version": "0.1.0",
                    "platform": "windows"
                }))
            }
            "audit.run" => {
                info!("Running full system audit...");
                let collectors = crate::platform::windows::collectors::WindowsCollectors;
                match crate::platform::traits::run_full_audit(&collectors).await {
                    Ok(report) => Some(report),
                    Err(e) => {
                        error!("audit.run failed: {e:#}");
                        None
                    }
                }
            }
            "net.connections" => {
                info!("Fetching network connections...");
                let collectors = crate::platform::windows::collectors::WindowsCollectors;
                if let Ok(conns) = collectors.get_network_connections().await {
                    Some(json!(conns))
                } else {
                    None
                }
            }
            "fw.default_deny.enable" => {
                info!("Enabling default outbound deny...");
                if let Err(e) = crate::firewall::FirewallManager::set_default_deny_outbound(true).await {
                    error!("Firewall error: {:?}", e);
                    None
                } else {
                    Some(json!({"status": "success", "message": "Outbound traffic blocked"}))
                }
            }
            "fw.default_deny.disable" => {
                info!("Disabling default outbound deny...");
                if let Err(e) = crate::firewall::FirewallManager::set_default_deny_outbound(false).await {
                    error!("Firewall error: {:?}", e);
                    None
                } else {
                    Some(json!({"status": "success", "message": "Outbound traffic allowed"}))
                }
            }
            "vuln.scan" => {
                info!("Running vulnerability scan...");
                let max_apps = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("max_apps"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10) as usize;
                match crate::vulns::VulnScanner::new() {
                    Ok(scanner) => match scanner.scan(max_apps).await {
                        Ok(results) => Some(json!(results)),
                        Err(e) => {
                            error!("vuln.scan failed: {e:#}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("vuln.scan init failed: {e:#}");
                        None
                    }
                }
            }
            "fw.rules.list" => {
                match crate::firewall::FirewallManager::list_rules().await {
                    Ok(rules) => Some(json!(rules)),
                    Err(e) => {
                        error!("fw.rules.list failed: {e:#}");
                        None
                    }
                }
            }
            "fw.rules.add" => {
                let Some(params) = req.params.clone() else {
                    return error_response(req, "missing params");
                };
                let parsed: anyhow::Result<crate::firewall::AddRuleRequest> =
                    serde_json::from_value(params)
                        .map_err(|e| anyhow::anyhow!("invalid rule params: {e}"));
                match parsed {
                    Ok(r) => match crate::firewall::FirewallManager::add_rule(&r).await {
                        Ok(name) => Some(json!({"status": "created", "name": name})),
                        Err(e) => {
                            error!("fw.rules.add failed: {e:#}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("fw.rules.add invalid: {e:#}");
                        None
                    }
                }
            }
            "fw.rules.remove" => {
                let Some(name) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                else {
                    return error_response(req, "missing rule name");
                };
                match crate::firewall::FirewallManager::remove_rule(&name).await {
                    Ok(()) => Some(json!({"status": "removed", "name": name})),
                    Err(e) => {
                        error!("fw.rules.remove failed: {e:#}");
                        None
                    }
                }
            }
            "fw.default_deny.status" => {
                match crate::firewall::FirewallManager::is_default_deny_enabled().await {
                    Ok(on) => Some(json!({"default_deny_outbound": on})),
                    Err(e) => {
                        error!("fw.default_deny.status failed: {e:#}");
                        None
                    }
                }
            }
            "fw.country.block" => {
                let Some(cc) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("country"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                else {
                    return error_response(req, "missing country code");
                };
                match crate::firewall::FirewallManager::block_country(&cc).await {
                    Ok(name) => Some(json!({"status": "blocked", "rule": name})),
                    Err(e) => {
                        error!("fw.country.block failed: {e:#}");
                        None
                    }
                }
            }
            "scan.start" => {
                info!("Starting scan job of {:?}", req.params);
                let root = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|v| v.as_str())
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from(r"C:\\"));
                let quarantine = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("quarantine"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // Returns immediately: the scan itself runs as a durable job and
                // reports through `progress` / `job_finished` notifications.
                match crate::scanner::start_scan(
                    root.clone(),
                    quarantine,
                    tokio::runtime::Handle::current(),
                ) {
                    Ok(job_id) => Some(json!({
                        "job_id": job_id,
                        "state": "running",
                        "path": root.to_string_lossy(),
                        "quarantine": quarantine,
                    })),
                    Err(e) => {
                        error!("scan.start failed: {e:#}");
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(json!(JsonRpcError {
                                code: -32000,
                                message: format!("scan.start: {e:#}"),
                                data: None,
                            })),
                            id: req.id,
                        };
                    }
                }
            }
            "scan.stop" => {
                let stopped = crate::scanner::stop_active_scan();
                Some(json!({"stopped": stopped}))
            }
            "job.list" => {
                let limit = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as u32;
                match crate::storage::sqlite::Storage::open().and_then(|s| s.list_jobs(limit)) {
                    Ok(list) => Some(json!(list)),
                    Err(e) => {
                        error!("job.list: {e:#}");
                        None
                    }
                }
            }
            "job.get" => {
                let Some(job_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("job_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing job_id");
                };
                match crate::storage::sqlite::Storage::open() {
                    Ok(s) => match s.get_job(&job_id) {
                        Ok(Some(job)) => {
                            let findings = s.job_findings(&job_id).unwrap_or_default();
                            Some(json!({
                                "job": job,
                                "findings": findings
                                    .iter()
                                    .filter_map(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                                    .collect::<Vec<_>>(),
                                "running": crate::jobs::is_running(&job_id),
                            }))
                        }
                        Ok(None) => {
                            return error_response(req, &format!("job not found: {job_id}"));
                        }
                        Err(e) => {
                            error!("job.get: {e:#}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("job.get: {e:#}");
                        None
                    }
                }
            }
            "job.cancel" => {
                let Some(job_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("job_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing job_id");
                };
                let cancelled = crate::jobs::cancel(&job_id);
                Some(json!({"cancelled": cancelled, "job_id": job_id}))
            }
            "job.resume" => {
                // Resume a job that is not currently running (e.g. interrupted
                // by an engine restart that auto-resume skipped).
                let Some(job_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("job_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing job_id");
                };
                match crate::scanner::resume_job(&job_id, tokio::runtime::Handle::current()) {
                    Ok(true) => Some(json!({"status": "resumed", "job_id": job_id})),
                    Ok(false) => Some(json!({"status": "not_resumable", "job_id": job_id})),
                    Err(e) => {
                        error!("job.resume: {e:#}");
                        None
                    }
                }
            }
            "quarantine.list" => {
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.list() {
                        Ok(items) => Some(json!(items)),
                        Err(e) => { error!("quarantine.list: {e:#}"); return detailed_error(req, "quarantine.list", e); }
                    },
                    Err(e) => { error!("quarantine.list: {e:#}"); return detailed_error(req, "quarantine.list", e); }
                }
            }
            "quarantine.restore" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("blob_id")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing blob_id");
                };
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.restore_file(&id).await {
                        Ok(orig) => Some(json!({"status": "restored", "path": orig})),
                        Err(e) => { error!("quarantine.restore: {e:#}"); return detailed_error(req, "quarantine.restore", e); }
                    },
                    Err(e) => { error!("quarantine.restore: {e:#}"); return detailed_error(req, "quarantine.restore", e); }
                }
            }
            "quarantine.delete" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("blob_id")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing blob_id");
                };
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.delete_blob(&id).await {
                        Ok(()) => Some(json!({"status": "deleted"})),
                        Err(e) => { error!("quarantine.delete: {e:#}"); return detailed_error(req, "quarantine.delete", e); }
                    },
                    Err(e) => { error!("quarantine.delete: {e:#}"); return detailed_error(req, "quarantine.delete", e); }
                }
            }
            "defender.scan.quick" => {
                // Defender orchestration: MpCmdRun quick scan (no console flash).
                let mut command = tokio::process::Command::new("powershell");
                command.args(["-NoProfile", "-Command",
                    r#"Start-Process -FilePath 'C:\Program Files\Windows Defender\MpCmdRun.exe' -ArgumentList '-Scan','-ScanType','1' -Wait"#]);
                command.creation_flags(
                    crate::platform::windows::elevation::CREATE_NO_WINDOW,
                );
                let out = command.output().await;
                match out {
                    Ok(o) if o.status.success() => Some(json!({"status": "done"})),
                    Ok(o) => {
                        error!("defender scan failed: {}", String::from_utf8_lossy(&o.stderr));
                        None
                    }
                    Err(e) => { error!("defender scan: {e:#}"); None }
                }
            }
            "quarantine.add" => {
                info!("Quarantining file...");
                let path = req.params.as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|p| p.as_str())
                    .map(std::path::PathBuf::from);
                
                if let Some(p) = path {
                    let qm = crate::scanner::quarantine::QuarantineManager::new().ok();
                    if let Some(mgr) = qm {
                        if let Ok(dest) = mgr.quarantine_file(&p, "manual request").await {
                            Some(json!({"status": "quarantined", "path": dest}))
                        } else {
                            None
                        }
                    } else { None }
                } else { None }
            }
            "sync.now" => {
                info!("Syncing intelligence...");
                match crate::sync::SyncManager::new() {
                    Ok(sm) => match sm.sync_now().await {
                        Ok(res) => Some(json!({"status": "success", "report": res})),
                        Err(e) => { error!("sync.now: {e:#}"); return detailed_error(req, "sync.now", e); }
                    },
                    Err(e) => { error!("sync.now: {e:#}"); return detailed_error(req, "sync.now", e); }
                }
            }
            "sync.status" => {
                info!("Checking sync status...");
                match crate::sync::SyncManager::new() {
                    Ok(sm) => match sm.get_status().await {
                        Ok(state) => Some(state),
                        Err(e) => { error!("sync.status: {e:#}"); return detailed_error(req, "sync.status", e); }
                    },
                    Err(e) => { error!("sync.status: {e:#}"); return detailed_error(req, "sync.status", e); }
                }
            }
            "guard.start" => {
                crate::guard::start_guard();
                Some(json!({"status": "running"}))
            }
            "guard.stop" => {
                crate::guard::stop_guard();
                Some(json!({"status": "stopped"}))
            }
            "guard.status" => Some(crate::guard::status_json()),
            "guard.rules.list" => match crate::guard::load_rules() {
                Ok(r) => Some(json!(r)),
                Err(e) => { error!("guard.rules.list: {e:#}"); return detailed_error(req, "guard.rules.list", e); }
            },
            "guard.rules.add" => {
                // Rules live in JSON files (hot-reloaded every 30 s); add appends
                // to the user rules file so the starter pack stays pristine.
                let Some(rule) = req.params.as_ref().and_then(|p| {
                    serde_json::from_value::<crate::guard::GuardRule>(p.clone()).ok()
                }) else {
                    return error_response(req, "invalid rule params");
                };
                let dir = crate::guard::rules_dir();
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join("user.json");
                let mut list: Vec<crate::guard::GuardRule> = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default();
                list.push(rule);
                let payload = serde_json::to_string_pretty(&list)
                    .map_err(|e| anyhow::anyhow!("serialize rules: {e}"));
                match payload.and_then(|p| std::fs::write(&path, p).map_err(|e| anyhow::anyhow!("write rules: {e}"))) {
                    Ok(()) => Some(json!({"status": "added", "file": path})),
                    Err(e) => { error!("guard.rules.add: {e:#}"); return detailed_error(req, "guard.rules.add", e); }
                }
            }
            "canary.list" => Some(json!(crate::guard::canary::list_decoys())),
            "canary.configure" => {
                let Some(paths) = req.params.as_ref().and_then(|p| p.get("paths")).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>()) else {
                    return error_response(req, "missing paths array");
                };
                let cfg = crate::guard::canary::CanaryConfig { paths };
                match crate::guard::canary::save_config(&cfg) {
                    Ok(()) => {
                        let _ = crate::guard::canary::deploy_decoys();
                        Some(json!({"status": "saved"}))
                    }
                    Err(e) => { error!("canary.configure: {e:#}"); return detailed_error(req, "canary.configure", e); }
                }
            }
            "canary.deploy" => match crate::guard::canary::deploy_decoys() {
                Ok(n) => Some(json!({"created": n})),
                Err(e) => { error!("canary.deploy: {e:#}"); return detailed_error(req, "canary.deploy", e); }
            },
            "incident.list" => {
                let limit = req.params.as_ref().and_then(|p| p.get("limit")).and_then(|v| v.as_u64()).unwrap_or(50) as u32;
                match crate::smart::correlator::list_incidents(limit) {
                    Ok(list) => Some(json!(list)),
                    Err(e) => { error!("incident.list: {e:#}"); return detailed_error(req, "incident.list", e); }
                }
            }
            "incident.close" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("incident_id")).and_then(|v| v.as_i64()) else {
                    return error_response(req, "missing incident_id");
                };
                match crate::smart::correlator::close_incident(id) {
                    Ok(()) => Some(json!({"status": "closed"})),
                    Err(e) => { error!("incident.close: {e:#}"); return detailed_error(req, "incident.close", e); }
                }
            }
            "noise.stats" => match crate::smart::noise_learner::stats() {
                Ok(s) => Some(json!(s)),
                Err(e) => { error!("noise.stats: {e:#}"); return detailed_error(req, "noise.stats", e); }
            },
            "noise.mute" => {
                let Some(cat) = req.params.as_ref().and_then(|p| p.get("category")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing category");
                };
                match crate::smart::noise_learner::mute_category(&cat) {
                    Ok(()) => Some(json!({"status": "muted"})),
                    Err(e) => { error!("noise.mute: {e:#}"); return detailed_error(req, "noise.mute", e); }
                }
            }
            "noise.unmute" => {
                let Some(cat) = req.params.as_ref().and_then(|p| p.get("category")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing category");
                };
                match crate::smart::noise_learner::unmute_category(&cat) {
                    Ok(()) => Some(json!({"status": "unmuted"})),
                    Err(e) => { error!("noise.unmute: {e:#}"); return detailed_error(req, "noise.unmute", e); }
                }
            }
            "guard.event.dismiss" => {
                let Some(cat) = req.params.as_ref().and_then(|p| p.get("category")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing category");
                };
                match crate::smart::noise_learner::record_dismissal(&cat) {
                    Ok(stat) => Some(json!(stat)),
                    Err(e) => { error!("noise dismissal: {e:#}"); None }
                }
            }
            "ids.status" => match crate::ids::status() {
                Ok(s) => Some(json!(s)),
                Err(e) => { error!("ids.status: {e:#}"); return detailed_error(req, "ids.status", e); }
            },
            "ids.block.add" => {
                let Some(domains) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("domains"))
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>())
                else {
                    return error_response(req, "missing domains");
                };
                match crate::ids::add_domains(&domains) {
                    Ok(n) => Some(json!({"added": n})),
                    Err(e) => { error!("ids.block.add: {e:#}"); return detailed_error(req, "ids.block.add", e); }
                }
            }
            "ids.block.remove" => {
                let Some(d) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("domain"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing domain");
                };
                match crate::ids::remove_domain(&d) {
                    Ok(()) => Some(json!({"status": "removed"})),
                    Err(e) => { error!("ids.block.remove: {e:#}"); return detailed_error(req, "ids.block.remove", e); }
                }
            }
            "ids.blocklist.import" => {
                let Some(p) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing path");
                };
                match crate::ids::import_blocklist(&p) {
                    Ok(n) => Some(json!({"imported": n})),
                    Err(e) => { error!("ids.blocklist.import: {e:#}"); return detailed_error(req, "ids.blocklist.import", e); }
                }
            }
            "geoip.lookup" => {
                let Some(ip) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("ip"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing ip");
                };
                Some(json!({"country": crate::ids::geoip::lookup(&ip)}))
            }
            "update.download" => {
                match crate::update::download_and_verify().await {
                    Ok(path) => Some(json!({"status": "staged", "path": path})),
                    Err(e) => { error!("update.download: {e:#}"); return detailed_error(req, "update.download", e); }
                }
            }
            "update.apply" => {
                let p = req
                    .params
                    .as_ref()
                    .and_then(|pp| pp.get("staged"))
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        crate::settings::Settings::base_dir()
                            .join("update")
                            .join("update.zip")
                    });
                match crate::update::apply(&p) {
                    Ok(msg) => Some(json!({"status": "applied", "detail": msg})),
                    Err(e) => { error!("update.apply: {e:#}"); return detailed_error(req, "update.apply", e); }
                }
            }
            "notify.test" => {
                // Settings screen: proves toasts (and DND) actually work.
                match crate::notify::toast::show_toast(
                    "🛡️ MI CS — test notification",
                    "Notifications are working. This is what a HIGH alert looks like.",
                ) {
                    Ok(()) => Some(json!({"status": "sent"})),
                    Err(e) => {
                        error!("notify.test: {e:#}");
                        None
                    }
                }
            }
            "hardening.list" => Some(json!(crate::hardening::list_actions())),
            "hardening.apply" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("action")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing action");
                };
                match crate::hardening::apply(&id).await {
                    Ok(_) => Some(json!({"status": "applied", "action": id})),
                    Err(e) => { error!("hardening.apply: {e:#}"); return detailed_error(req, "hardening.apply", e); }
                }
            }
            "hardening.rollback" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("action")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing action");
                };
                match crate::hardening::rollback(&id).await {
                    Ok(()) => Some(json!({"status": "rolled_back", "action": id})),
                    Err(e) => { error!("hardening.rollback: {e:#}"); return detailed_error(req, "hardening.rollback", e); }
                }
            }
            "report.export" => match crate::reports::export_markdown().await {
                Ok(path) => Some(json!({"status": "exported", "path": path})),
                Err(e) => { error!("report.export: {e:#}"); return detailed_error(req, "report.export", e); }
            },
            "llm.explain" => {
                let finding = req.params.as_ref().and_then(|p| p.get("finding")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let lang = req.params.as_ref().and_then(|p| p.get("lang")).and_then(|v| v.as_str()).unwrap_or("ar").to_string();
                match crate::llm::LmClient::new().explain(&finding, &lang).await {
                    Ok(text) => Some(json!({"explanation": text})),
                    Err(e) => { error!("llm.explain: {e:#}"); return detailed_error(req, "llm.explain", e); }
                }
            }
            "nl.command" => {
                let Some(text) = req.params.as_ref().and_then(|p| p.get("text")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing text");
                };
                let mut result = crate::llm::parse_nl(&text);
                // Execute matched whitelisted command immediately.
                if result.matched {
                    let sub = JsonRpcRequest {
                        jsonrpc: "2.0".into(),
                        method: result.command.clone(),
                        params: Some(result.params.clone()),
                        id: Some(json!(900000)),
                    };
                    let inner = Box::pin(Dispatcher::handle_request(sub)).await;
                    result.reply = if inner.result.is_some() {
                        format!("{} ✓", result.reply)
                    } else {
                        format!("{} — engine returned an error", result.reply)
                    };
                    return JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        result: Some(json!({
                            "nl": result,
                            "engine_result": inner.result,
                        })),
                        error: None,
                        id: req.id,
                    };
                }
                Some(json!({"nl": result}))
            }
            "app.relaunch_elevated" => {
                // One-shot elevation of the UI, requested explicitly by the user
                // from Settings. The engine stays unelevated; only the new UI
                // process (and the engine it starts) gets an elevated token.
                let engine = std::env::current_exe().unwrap_or_default();
                let app = engine
                    .parent()
                    .map(|d| d.join("mics_app.exe"))
                    .unwrap_or_else(|| std::path::PathBuf::from("mics_app.exe"));
                if !app.exists() {
                    return detailed_error(
                        req,
                        "app.relaunch_elevated",
                        anyhow::anyhow!("mics_app.exe not found next to the engine"),
                    );
                }
                let ps_arg = format!(
                    "Start-Process -FilePath '{}' -Verb RunAs",
                    app.display()
                );
                let mut command = std::process::Command::new("powershell");
                command.args(["-NoProfile", "-Command", &ps_arg]);
                crate::platform::windows::elevation::hide_console(&mut command);
                match command.output() {
                    Ok(o) if o.status.success() => Some(json!({"status": "launched"})),
                    Ok(o) => {
                        let text = String::from_utf8_lossy(&o.stderr).trim().to_string();
                        return detailed_error(
                            req,
                            "app.relaunch_elevated",
                            anyhow::anyhow!(
                                "elevation was refused or cancelled{}",
                                if text.is_empty() { String::new() } else { format!(": {text}") }
                            ),
                        );
                    }
                    Err(e) => {
                        return detailed_error(
                            req,
                            "app.relaunch_elevated",
                            anyhow::Error::new(e),
                        );
                    }
                }
            }
            "service.install" => {
                // Boot-with-windows: scheduled task running the engine --service at logon.
                let exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("service.install: {e:#}");
                        return error_response(req, "cannot resolve engine exe");
                    }
                };
                // Boot-with-windows: HKCU Run entry (no admin needed; the
                // scheduled-task variant requires elevation and is documented).
                let out = std::process::Command::new("reg")
                    .args([
                        "add",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", "MICS-Engine",
                        "/t", "REG_SZ",
                        "/d", &format!("\"{}\" --service", exe.display()),
                        "/f",
                    ])
                    .output();
                match out {
                    Ok(o) if o.status.success() => Some(json!({"status": "installed"})),
                    Ok(o) => { error!("service.install: {}", String::from_utf8_lossy(&o.stderr)); None }
                    Err(e) => { error!("service.install: {e:#}"); return detailed_error(req, "service.install", anyhow::Error::new(e)); }
                }
            }
            "service.remove" => {
                let out = std::process::Command::new("reg")
                    .args([
                        "delete",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", "MICS-Engine",
                        "/f",
                    ])
                    .output();
                match out {
                    Ok(o) if o.status.success() => Some(json!({"status": "removed"})),
                    Ok(o) => { error!("service.remove: {}", String::from_utf8_lossy(&o.stderr)); None }
                    Err(e) => { error!("service.remove: {e:#}"); return detailed_error(req, "service.remove", anyhow::Error::new(e)); }
                }
            }
            "settings.get" => Some(json!(crate::settings::current())),
            "settings.set" => {
                let Some(patch) = req.params.clone() else {
                    return error_response(req, "missing settings object");
                };
                match crate::settings::patch(&patch) {
                    Ok(next) => {
                        // Settings that change engine behaviour take effect on
                        // the next decision (sync tick, new toast, next scan);
                        // anything requiring a restart is documented in the UI.
                        crate::jobs::notify(
                            "event",
                            json!({ "type": "settings.changed", "data": next }),
                        );
                        Some(json!(next))
                    }
                    Err(e) => {
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(json!(JsonRpcError {
                                code: -32602,
                                message: format!("settings.set: {e:#}"),
                                data: None,
                            })),
                            id: req.id,
                        };
                    }
                }
            }
            "update.check" => {
                // Manifest-based self-update check (URL comes from settings).
                let url = crate::settings::current().update_url();
                if url.is_empty() {
                    Some(json!({"status": "disabled", "detail": "no update manifest URL configured"}))
                } else {
                    match crate::sync::SyncManager::new() {
                        Ok(sm) => match sm.check_update(&url).await {
                            Ok(info) => Some(json!(info)),
                            Err(e) => { error!("update.check: {e:#}"); return detailed_error(req, "update.check", e); }
                        },
                        Err(e) => { error!("update.check: {e:#}"); return detailed_error(req, "update.check", e); }
                    }
                }
            }
            _ => {
                unknown = true;
                warn!("Unknown method: {}", req.method);
                None
            }
        };
        // Distinguish "unknown method" (-32601) from "known method that
        // failed internally" (-32000) so the UI shows honest errors.
        match result {
            Some(res) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(res),
                error: None,
                id: req.id,
            },
            None if unknown => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(json!(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", req.method),
                    data: None,
                })),
                id: req.id,
            },
            None => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(json!(JsonRpcError {
                    code: -32000,
                    message: format!("Method failed internally: {}", req.method),
                    data: None,
                })),
                id: req.id,
            },
        }
    }
}
