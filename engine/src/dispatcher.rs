use crate::rpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use serde_json::json;
use anyhow::Result;
use tracing::{info, warn};use crate::platform::traits::PlatformCollectors;
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
                
                let mut all_findings = Vec::new();
                
                if let Ok(findings) = collectors.audit_defender().await {
                    all_findings.extend(findings);
                }
                if let Ok(findings) = collectors.audit_firewall().await {
                    all_findings.extend(findings);
                }
                if let Ok(findings) = collectors.audit_rdp().await {
                    all_findings.extend(findings);
                }
                if let Ok(findings) = collectors.audit_smbv1().await {
                    all_findings.extend(findings);
                }

                Some(json!(all_findings))
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
            _ => {
                warn!("Unknown method: {}", req.method);
                None
            }
        };
// ...existing code...

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
