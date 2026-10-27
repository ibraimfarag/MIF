use crate::rpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use serde_json::json;
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
                match crate::vulns::VulnScanner::new().and_then(|s| Ok(s)) {
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
                info!("Starting scan of {:?}", req.params);
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
                match crate::scanner::run_scan(&root, quarantine).await {
                    Ok(report) => Some(json!(report)),
                    Err(e) => {
                        error!("scan.start failed: {e:#}");
                        None
                    }
                }
            }
            "scan.stop" => {
                let stopped = crate::scanner::stop_active_scan();
                Some(json!({"stopped": stopped}))
            }
            "quarantine.list" => {
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.list() {
                        Ok(items) => Some(json!(items)),
                        Err(e) => { error!("quarantine.list: {e:#}"); None }
                    },
                    Err(e) => { error!("quarantine.list: {e:#}"); None }
                }
            }
            "quarantine.restore" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("blob_id")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing blob_id");
                };
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.restore_file(&id).await {
                        Ok(orig) => Some(json!({"status": "restored", "path": orig})),
                        Err(e) => { error!("quarantine.restore: {e:#}"); None }
                    },
                    Err(e) => { error!("quarantine.restore: {e:#}"); None }
                }
            }
            "quarantine.delete" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("blob_id")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing blob_id");
                };
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.delete_blob(&id).await {
                        Ok(()) => Some(json!({"status": "deleted"})),
                        Err(e) => { error!("quarantine.delete: {e:#}"); None }
                    },
                    Err(e) => { error!("quarantine.delete: {e:#}"); None }
                }
            }
            "defender.scan.quick" => {
                // Defender orchestration: MpCmdRun quick scan.
                let out = tokio::process::Command::new("powershell")
                    .args(["-NoProfile", "-Command",
                        r#"Start-Process -FilePath 'C:\Program Files\Windows Defender\MpCmdRun.exe' -ArgumentList '-Scan','-ScanType','1' -Wait"#])
                    .output()
                    .await;
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
                        Err(e) => { error!("sync.now: {e:#}"); None }
                    },
                    Err(e) => { error!("sync.now: {e:#}"); None }
                }
            }
            "sync.status" => {
                info!("Checking sync status...");
                match crate::sync::SyncManager::new() {
                    Ok(sm) => match sm.get_status().await {
                        Ok(state) => Some(state),
                        Err(e) => { error!("sync.status: {e:#}"); None }
                    },
                    Err(e) => { error!("sync.status: {e:#}"); None }
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
