use crate::platform::traits::PlatformCollectors;
mod rpc;
mod platform;
mod dispatcher;
mod firewall;
mod vulns;
mod scanner;
mod sync;
mod benchmark;
mod guard;
mod ids;
mod hardening;
mod llm;
mod notify;
mod reports;
mod smart;
mod storage;

use clap::{Parser, Subcommand};
use anyhow::Result;
use tokio::io::AsyncBufReadExt;
use tracing::{error, Level};
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
    /// Start the engine in serve mode (stdio JSON-RPC)
    Serve,
    /// Start the engine as a background service (Named Pipe JSON-RPC)
    Service,
    /// Run the full system audit and print results
    Audit {
        #[arg(short, long)]
        json: bool,
    },
    /// List live TCP/UDP connections with owning processes
    Connections {
        #[arg(short, long)]
        json: bool,
    },
    /// List installed software inventory
    Inventory {
        #[arg(short, long)]
        json: bool,
    },
    /// Scan a folder (triage-ordered: IOC hashes then YARA)
    Scan {
        #[arg(short, long)]
        path: String,
        /// Quarantine detected files
        #[arg(long, default_value_t = false)]
        quarantine: bool,
        #[arg(short, long)]
        json: bool,
    },
    /// Measure idle RAM/CPU against the spec budgets
    Benchmark,
    /// List quarantine entries
    Quarantine {
        #[arg(short, long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so stdout stays clean for JSON consumers (CLI pipe usage).
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve) => {
            tracing::info!("Starting engine in --serve mode (stdio)...");
            // Auto intel-sync cadence (hours) comes from UI settings.
            let sync_hours: u64 = std::env::var("MICS_SYNC_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6);
            sync::SyncManager::start_auto_sync(tokio::runtime::Handle::current(), sync_hours);
            // Forward guard events as JSON-RPC notifications on stdout.
            let mut events = guard::subscribe_events();
            tokio::spawn(async move {
                while let Some(ev) = events.recv().await {
                    // CRITICAL/HIGH events toast even with the UI closed.
                    if ev.severity == "critical" || ev.severity == "high" {
                        notify::toast::route_event(&ev);
                    }
                    let note = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "event",
                        "params": serde_json::to_value(&ev).unwrap_or_default()
                    });
                    println!("{}", serde_json::to_string(&note).unwrap_or_default());
                }
            });
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).await.is_err() || line.is_empty() {
                    break;
                }
                if let Ok(req) = serde_json::from_str::<rpc::JsonRpcRequest>(&line) {
                    let resp = dispatcher::Dispatcher::handle_request(req).await;
                    println!("{}", serde_json::to_string(&resp)?);
                }
            }
        }
        Some(Commands::Service) => {
            tracing::info!("Starting engine in --service mode (Named Pipe)...");
            if let Err(e) = platform::windows::pipe::run_pipe_server().await {
                error!("Pipe server error: {e:#}");
            }
        }
        Some(Commands::Audit { json }) => {
            let collectors = platform::windows::collectors::WindowsCollectors;
            let report = platform::traits::run_full_audit(&collectors).await?;
            emit(&report, json)?;
        }
        Some(Commands::Connections { json }) => {
            let collectors = platform::windows::collectors::WindowsCollectors;
            let conns = collectors.get_network_connections().await?;
            emit(
                &serde_json::to_value(&conns)?,
                json,
            )?;
        }
        Some(Commands::Inventory { json }) => {
            let collectors = platform::windows::collectors::WindowsCollectors;
            let sw = collectors.get_software_inventory().await?;
            emit(&serde_json::to_value(&sw)?, json)?;
        }
        Some(Commands::Scan { path, quarantine, json }) => {
            let report = scanner::run_scan(&std::path::PathBuf::from(path), quarantine).await?;
            emit(&serde_json::to_value(&report)?, json)?;
        }
        Some(Commands::Benchmark) => {
            let b = benchmark::run();
            println!("{}", serde_json::to_string_pretty(&b)?);
        }
        Some(Commands::Quarantine { json }) => {
            let m = scanner::quarantine::QuarantineManager::new()?;
            let items = m.list()?;
            emit(&serde_json::to_value(&items)?, json)?;
        }
        None => {
            println!("MI CS Engine v0.1.0");
            println!("Use --help for more information");
        }
    }

    Ok(())
}

/// JSON mode prints machine-readable output; human mode prints a compact table.
fn emit(value: &serde_json::Value, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }

    if let Some(score) = value.get("score") {
        println!("MI CS Security Score: {score}/100");
        println!();
        if let Some(findings) = value.get("findings").and_then(|f| f.as_array()) {
            for f in findings {
                let section = f.get("section").and_then(|v| v.as_str()).unwrap_or("?");
                let item = f.get("item").and_then(|v| v.as_str()).unwrap_or("?");
                let status = f.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                println!("[{status:^9}] {section} :: {item}");
                if let Some(d) = f.get("description").and_then(|v| v.as_str()) {
                    println!("           {d}");
                }
            }
        }
        if let Some(startup) = value.get("startup_entries").and_then(|f| f.as_array()) {
            println!();
            println!("Startup entries ({}):", startup.len());
            for s in startup {
                println!(
                    "  {} [{}] -> {}",
                    s.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    s.get("location").and_then(|v| v.as_str()).unwrap_or("?"),
                    s.get("command").and_then(|v| v.as_str()).unwrap_or("?")
                );
            }
        }
        if let Some(tasks) = value.get("scheduled_tasks").and_then(|f| f.as_array()) {
            println!();
            println!("Non-Microsoft scheduled tasks ({}):", tasks.len());
            for t in tasks {
                println!(
                    "  {} ({})",
                    t.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    t.get("path").and_then(|v| v.as_str()).unwrap_or("?")
                );
            }
        }
        return Ok(());
    }

    // Arrays (connections / inventory).
    if let Some(items) = value.as_array() {
        for item in items {
            println!("{item}");
        }
    } else {
        println!("{value}");
    }
    Ok(())
}
