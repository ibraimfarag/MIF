use crate::rpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use serde_json::json;
use tracing::{info, warn, error};
use crate::platform::traits::PlatformCollectors;
pub struct Dispatcher;

impl Dispatcher {
    pub async fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
        info!("Processing request: {}", req.method);

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
                let scanner = crate::vulns::VulnScanner::new();
                if let Ok(results) = scanner.scan_software().await {
                    // Format results for JSON-RPC
                    let formatted: Vec<_> = results.into_iter().map(|(sw, v)| {
                        json!({
                            "software": sw.name,
                            "version": sw.version,
                            "vulnerabilities": v
                        })
                    }).collect();
                    Some(json!(formatted))
                } else {
                    None
                }
            }
            "scan.start" => {
                info!("Starting smart file scan...");
                let triage = crate::scanner::TriageEngine::new();
                if let Ok(queue) = triage.triage_directory(&std::path::PathBuf::from("C:\\")) {
                    let yara_rules = "rule TestRule { strings: $a = \"malware\" condition: $a }";
                    let yara_res = crate::scanner::yara_engine::YaraEngine::new(yara_rules);
                    
                    if let Ok(yara) = yara_res {
                        let mut results = Vec::new();
                        for item in queue {
                            if let Ok(matches) = yara.scan_file(&item.path) {
                                if !matches.is_empty() {
                                    results.push(json!({
                                        "path": item.path,
                                        "priority": item.priority,
                                        "matches": matches
                                    }));
                                }
                            }
                        }
                        Some(json!(results))
                    } else {
                        warn!("YARA engine failed to initialize, skipping scan");
                        None
                    }
                } else {
                    None
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
                        if let Ok(dest) = mgr.quarantine_file(&p).await {
                            Some(json!({"status": "quarantined", "path": dest}))
                        } else {
                            None
                        }
                    } else { None }
                } else { None }
            }
            "sync.now" => {
                info!("Syncing intelligence...");
                let sm = crate::sync::SyncManager::new();
                if let Ok(res) = sm.sync_now().await {
                    Some(json!({"status": "success", "message": res}))
                } else {
                    None
                }
            }
            "sync.status" => {
                info!("Checking sync status...");
                let sm = crate::sync::SyncManager::new();
                if let Ok(state) = sm.get_status().await {
                    Some(json!(state))
                } else {
                    None
                }
            }
            _ => {
                warn!("Unknown method: {}", req.method);
                None
            }
        };
        if let Some(res) = result {
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(res),
                error: None,
                id: req.id,
            }
        } else {
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(json!(JsonRpcError {
                    code: -32601,
                    message: "Method not found".to_string(),
                    data: None,
                })),
                id: req.id,
            }
        }
    }
}
