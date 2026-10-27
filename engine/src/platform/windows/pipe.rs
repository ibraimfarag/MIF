use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use crate::rpc::{JsonRpcRequest, JsonRpcResponse};
use anyhow::{Result, Context};
use tracing::{info, error};

pub async fn run_pipe_server() -> Result<()> {
    let pipe_name = r"\\.\pipe\mics_engine";
    info!("Starting Named Pipe server on {}", pipe_name);

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe_name)
            .context("Failed to create named pipe")?;

        server.connect().await.context("Failed to connect to pipe")?;
        info!("Client connected to pipe");
        
        let stream = server;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                error!("Error handling pipe client: {:?}", e);
            }
        });
    }
}

async fn handle_client(mut stream: NamedPipeServer) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await.context("Failed to read from pipe")?;
        if bytes_read == 0 {
            info!("Client disconnected from pipe");
            break;
        }

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                error!("Invalid JSON-RPC request: {:?}", e);
                continue;
            }
        };

        let response = crate::dispatcher::Dispatcher::handle_request(req).await;
        let resp_json = serde_json::to_string(&response).context("Failed to serialize response")?;
        
        writer.write_all(format!("{}\n", resp_json).as_bytes()).await.context("Failed to write to pipe")?;
        writer.flush().await.context("Failed to flush pipe")?;
    }
    Ok(())
}
