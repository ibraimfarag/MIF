use crate::rpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use serde_json::json;
use anyhow::Result;
use tracing::{info, warn};

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
