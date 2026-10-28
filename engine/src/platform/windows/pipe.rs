//! Named-pipe JSON-RPC server (primary transport, spec section 5).
//!
//! One instance per connection; the UI reconnects transparently. Every
//! connected client also receives the engine's push traffic (`event`,
//! `progress`) through the shared broadcast channel in [`crate::jobs`], so a
//! scan progress bar keeps moving without polling and a canary alert reaches
//! the UI the moment it fires.
//!
//! The accept loop never exits on transient errors: a failed `create` (for
//! example while the previous instance is still tearing down) is retried with
//! a short backoff. This used to be the reason the pipe closed right after the
//! first client connected.

use anyhow::{Context, Result};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use crate::rpc::JsonRpcRequest;

pub const PIPE_NAME: &str = r"\\.\pipe\mics_engine";

/// Pipe name actually served. `MICS_PIPE_NAME` isolates a test/dev engine from
/// the real one (same code path, different pipe).
pub fn resolved_pipe_name() -> String {
    std::env::var("MICS_PIPE_NAME").unwrap_or_else(|_| PIPE_NAME.to_string())
}

const BACKOFF: std::time::Duration = std::time::Duration::from_millis(300);

pub async fn run_pipe_server() -> Result<()> {
    let name = resolved_pipe_name();
    info!("Starting Named Pipe server on {name}");
    let mut first = true;
    loop {
        let mut opts = ServerOptions::new();
        if first {
            // Only the very first instance is exclusive; later iterations must
            // be allowed to create a fresh instance while one is connected.
            opts.first_pipe_instance(true);
        }
        let server = match opts.create(&name) {
            Ok(s) => {
                first = false;
                s
            }
            Err(e) => {
                warn!("pipe create failed ({e}) — retrying");
                tokio::time::sleep(BACKOFF).await;
                continue;
            }
        };
        if let Err(e) = server.connect().await {
            warn!("pipe connect failed ({e}) — retrying");
            tokio::time::sleep(BACKOFF).await;
            continue;
        }
        info!("client connected to pipe");
        tokio::spawn(async move {
            if let Err(e) = handle_client(server).await {
                warn!("pipe client ended: {e:#}");
            }
        });
    }
}

async fn handle_client(stream: NamedPipeServer) -> Result<()> {
    let (rd, wr) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    // One writer owns the write half: responses and pushed notifications are
    // serialized here so two tasks can never interleave half a line.
    let mut writer = wr;
    let writer_task = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if writer.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if writer.write_all(b"\n").await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    // Forward engine push traffic (guard events, job progress) to this client.
    let mut events = crate::jobs::subscribe();
    let notify_tx = out_tx.clone();
    let notify_task = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(msg) => {
                    if notify_tx.send(msg).is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("pipe client lagged, dropped {n} notifications");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.context("read pipe")?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<JsonRpcRequest>(trimmed) {
            Ok(req) => {
                let resp = crate::dispatcher::Dispatcher::handle_request(req).await;
                if let Ok(text) = serde_json::to_string(&resp)
                    && out_tx.send(text).is_err() {
                        break;
                    }
            }
            Err(e) => {
                // JSON-RPC 2.0 parse error: keep the connection alive.
                let err = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") },
                });
                let _ = out_tx.send(err.to_string());
            }
        }
    }

    drop(out_tx);
    notify_task.abort();
    let _ = writer_task.await;
    info!("client disconnected from pipe");
    Ok(())
}

/// Pushes a JSON-RPC notification to every connected pipe client.
pub fn notify(method: &str, params: serde_json::Value) {
    crate::jobs::notify(method, params);
}
