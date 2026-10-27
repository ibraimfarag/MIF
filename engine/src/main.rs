mod rpc;
mod platform;
mod dispatcher;

use clap::{Parser, Subcommand};
use anyhow::Result;
use tokio::io::AsyncBufReadExt;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "mics-engine")]
#[command(about = "MI CS Engine - Backend for Cybersecurity Command Center", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the engine in serve mode (stdio)
    Serve,
    /// Start the engine as a background service (Named Pipe)
    Service,
    /// Run a specific audit action
    Audit {
        #[arg(short, long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve) => {
            info!("Starting engine in --serve mode (stdio)...");
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).await.is_err() || line.is_empty() { break; }
                if let Ok(req) = serde_json::from_str::<rpc::JsonRpcRequest>(&line) {
                    let resp = dispatcher::Dispatcher::handle_request(req).await;
                    println!("{}", serde_json::to_string(&resp).unwrap());
                }
            }
        }
        Some(Commands::Service) => {
            info!("Starting engine in --service mode (Named Pipe)...");
            if let Err(e) = platform::windows::pipe::run_pipe_server().await {
                error!("Pipe server error: {:?}", e);
            }
        }
        Some(Commands::Audit { json }) => {
            info!("Running system audit (json: {})...", json);
        }
        None => {
            println!("MI CS Engine v0.1.0");
            println!("Use --help for more information");
        }
    }

    Ok(())
}
