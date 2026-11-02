use crate::platform::traits::PlatformCollectors;
mod crash;
mod rpc;
mod platform;
mod dispatcher;
mod firewall;
mod vulns;
mod scanner;
mod sync;
mod benchmark;
#[cfg(test)]
mod tests;
mod guard;
mod ids;
mod hardening;
mod jobs;
mod llm;
mod notify;
mod privileged;
mod reports;
mod settings;
mod smart;
mod update;
mod storage;
mod watchdog;

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

#[derive(Subcommand, Debug)]
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
    /// List recent scan jobs and their persisted state
    Jobs {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(short, long)]
        json: bool,
    },
    /// Resume an interrupted scan job by id
    ResumeJob { job_id: String },
    /// Print one job with its findings
    Job {
        job_id: String,
        #[arg(short, long)]
        json: bool,
    },
    /// Install (or repair) the privileged helper service — this is the one step
    /// that needs a UAC prompt (run elevated once by the engine, not by hand).
    InstallHelper,
    /// Stop and delete the privileged helper service (needs elevation).
    UninstallHelper,
    /// Service entry point used by the SCM for the privileged helper.
    HelperService,
    /// Run the privileged helper in the foreground (diagnostics/tests).
    HelperConsole,
    /// Print the privileged helper's state and audit log location.
    HelperStatus {
        #[arg(short, long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    // Whatever the command decides is logged **and** returned: the engine runs
    // detached with no console, so a message that only reached stderr was lost
    // (that is how `install-helper` exited 2 with nothing in the log file, and
    // why the UI could only report an exit code).
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("{e:#}");
            eprintln!("Error: {e:#}");
            1
        }
    };
    let _ = std::io::Write::flush(&mut std::io::stdout());
    std::process::exit(code);
}

async fn run() -> Result<()> {
    // Logs go to stderr (so stdout stays clean for JSON consumers) and to a
    // rotating file: a detached service engine has no console, and support
    // needs to know what happened overnight.
    let file_writer = log_file_writer();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(file_writer)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default subscriber failed");

    // A panic must leave a report behind before the process dies (panic =
    // "abort" in release). Installed before anything can panic.
    crash::install_panic_hook();

    // Settings are the single source of truth (D-008) and must be loaded
    // before any subsystem reads them.
    let settings = settings::init();

    // Parsed by hand so a refused command line is written to the log file too:
    // `Cli::parse()` prints to a stderr this process may not have, and then the
    // only trace of the failure is a bare exit code at the caller.
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        if e.use_stderr() {
            tracing::error!("command line refused: {e}");
        }
        e.exit()
    });

    // One line per process start: the service engine is detached, so this is
    // how support tells "did it even start?" apart from "did it crash later?".
    let mode = match &cli.command {
        Some(Commands::Serve) => "serve",
        Some(Commands::Service) => "service",
        Some(Commands::Audit { .. }) => "audit",
        Some(Commands::Connections { .. }) => "connections",
        Some(Commands::Inventory { .. }) => "inventory",
        Some(Commands::Scan { .. }) => "scan",
        Some(Commands::Benchmark) => "benchmark",
        Some(Commands::Quarantine { .. }) => "quarantine",
        Some(Commands::Jobs { .. }) => "jobs",
        Some(Commands::ResumeJob { .. }) => "resume-job",
        Some(Commands::Job { .. }) => "job",
        Some(Commands::InstallHelper) => "install-helper",
        Some(Commands::UninstallHelper) => "uninstall-helper",
        Some(Commands::HelperService) => "helper-service",
        Some(Commands::HelperConsole) => "helper-console",
        Some(Commands::HelperStatus { .. }) => "helper-status",
        None => "idle",
    };
    tracing::info!(
        "MI CS engine {} starting (mode={mode}, pid={}, data={})",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        settings::Settings::base_dir().display()
    );
    // Where a support case will be read from: "send me the file in this folder"
    // needs the folder in the log, not in a source file.
    tracing::info!("crash reports: {}", crash::reports_dir_path().display());

    // Windows gives a process the integrity label of the folder its image sits
    // in, and a Low process cannot write Medium state. Serving anyway produces
    // two errors that read like unrelated bugs — SQLite saying "attempt to write
    // a readonly database" and the helper saying "installed but not answering" —
    // for a machine where both are fine. Say the real reason once and stop.
    if needs_normal_integrity(&cli.command)
        && platform::windows::integrity::below_medium()
        && std::env::var_os("MICS_ALLOW_LOW_INTEGRITY").is_none()
    {
        let exe = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "mics-engine.exe".to_string());
        anyhow::bail!(
            "MI CS was started from a Low-integrity location ({exe}). Windows gives a process the \
             label of the folder its image is in, and this one is below Medium, so the engine \
             cannot write its state database (\"attempt to write a readonly database\") or reach \
             the privileged helper (\"installed but not answering\") — both are healthy. The \
             folder carries the label, not the program: run the installed copy in \
             %LOCALAPPDATA%\\MI CS, or extract the release ZIP outside a web root or sandbox \
             folder. MICS_ALLOW_LOW_INTEGRITY=1 runs anyway, for a diagnostic probe."
        );
    }

    match cli.command {
        Some(Commands::Serve) => {
            // Single engine per machine (D-006): if a service instance (or a
            // previous UI-spawned one) already owns the slot, exit quietly so
            // the caller can connect to the pipe instead of starting a rival.
            let _instance = match platform::windows::single_instance::acquire() {
                Some(g) => g,
                None => {
                    eprintln!("MI CS engine already running — connect to the pipe");
                    return Ok(());
                }
            };
            crash::begin_session("serve");
            // A plain thread, not a tokio task: it is still there when the
            // runtime is not, which is what makes it able to report the hang.
            watchdog::start_session();
            tracing::info!("Starting engine in --serve mode (stdio)...");
            sync::SyncManager::start_auto_sync(tokio::runtime::Handle::current());
            resume_jobs_on_startup();
            // Forward guard events as JSON-RPC notifications on stdout.
            let mut events = guard::subscribe_events();
            tokio::spawn(async move {
                while let Ok(ev) = events.recv().await {
                    // Every event goes through the alert gate: it decides which
                    // severities reach the desktop (and honours toast_enabled +
                    // DND), so a new severity cannot bypass the policy here.
                    notify::alert::guard_event(&ev);
                    notify::sound::play_for_severity(&ev.severity);
                    let note = serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "event",
                        "params": serde_json::to_value(&ev).unwrap_or_default()
                    });
                    println!("{}", serde_json::to_string(&note).unwrap_or_default());
                }
            });
            // Job progress / completion notifications share the same stdout.
            let mut notifs = jobs::subscribe();
            tokio::spawn(async move {
                while let Ok(msg) = notifs.recv().await {
                    println!("{msg}");
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
            // The stdio client went away (the UI closed): a deliberate end, not a
            // crash, so the next start must not file one.
            crash::end_session("clean");
        }
        Some(Commands::Service) => {
            let _instance = match platform::windows::single_instance::acquire() {
                Some(g) => g,
                None => {
                    tracing::info!("MI CS engine already running — exiting");
                    return Ok(());
                }
            };
            crash::begin_session("service");
            // See `serve`: the hang detector starts with the session and lives
            // outside the runtime it watches.
            watchdog::start_session();
            tracing::info!("Starting engine in --service mode (Named Pipe)...");
            sync::SyncManager::start_auto_sync(tokio::runtime::Handle::current());
            resume_jobs_on_startup();
            // 24/7 protection: with the service running, the guard is armed
            // even when the UI is closed (unless the user turned it off, or a
            // test sets MICS_NO_GUARD=1). `guard.start` from the UI is a no-op
            // when it is already running.
            if std::env::var("MICS_NO_GUARD").is_err() && settings.guard_autostart {
                guard::start_guard();
            }
            // Guard events go to every pipe client; the alert gate decides
            // which of them also become desktop cards (and sounds).
            let mut events = guard::subscribe_events();
            tokio::spawn(async move {
                while let Ok(ev) = events.recv().await {
                    notify::alert::guard_event(&ev);
                    notify::sound::play_for_severity(&ev.severity);
                    platform::windows::pipe::notify(
                        "event",
                        serde_json::json!({
                            "type": ev.r#type,
                            "data": serde_json::to_value(&ev).unwrap_or_default()
                        }),
                    );
                }
            });
            if let Err(e) = platform::windows::pipe::run_pipe_server().await {
                error!("Pipe server error: {e:#}");
            }
            crash::end_session("clean");
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
            let report = scanner::run_scan(&std::path::PathBuf::from(path), quarantine)?;
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
        Some(Commands::Jobs { limit, json }) => {
            let storage = storage::sqlite::Storage::open()?;
            let jobs = storage.list_jobs(limit)?;
            emit(&serde_json::to_value(&jobs)?, json)?;
        }
        Some(Commands::ResumeJob { job_id }) => {
            let resumed =
                scanner::resume_job(&job_id, tokio::runtime::Handle::current())?;
            println!("{}", if resumed { "resumed" } else { "not_resumable" });
        }
        Some(Commands::Job { job_id, json }) => {
            let storage = storage::sqlite::Storage::open()?;
            let job = storage
                .get_job(&job_id)?
                .ok_or_else(|| anyhow::anyhow!("job not found: {job_id}"))?;
            let findings = storage.job_findings(&job_id)?;
            let payload = serde_json::json!({
                "job": job,
                "findings": findings
                    .iter()
                    .filter_map(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                    .collect::<Vec<_>>(),
            });
            emit(&payload, json)?;
        }
        Some(Commands::InstallHelper) => {
            let exe = privileged::service::current_exe()?;
            let state = privileged::service::install(&exe)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Some(Commands::UninstallHelper) => {
            let state = privileged::service::uninstall()?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Some(Commands::HelperService) => {
            // Blocking by design: the SCM calls service_main on the main thread
            // and this returns only when the service is stopped.
            privileged::service::run_service()?;
        }
        Some(Commands::HelperConsole) => {
            privileged::server::run_console()?;
        }
        Some(Commands::HelperStatus { json }) => {
            emit(&serde_json::to_value(privileged::status())?, json)?;
        }
        None => {
            println!("MI CS Engine v0.1.0");
            println!("Use --help for more information");
        }
    }

    Ok(())
}

/// Commands that work below Medium integrity.
///
/// The helper-inspection commands only *read* state and are exactly what a
/// Low run needs for diagnosis, so they stay usable. Everything else writes the
/// state database or owns a pipe the UI attaches to, which a Low process cannot
/// do usefully (see `platform::windows::integrity`).
fn needs_normal_integrity(command: &Option<Commands>) -> bool {
    !matches!(
        command,
        Some(Commands::HelperConsole)
            | Some(Commands::HelperService)
            | Some(Commands::HelperStatus { .. })
    )
}

/// Log sink: stderr **and** `%PROGRAMDATA%\MICS\logs\engine.log`.
///
/// The service engine is started detached (no console), so without a file log
/// a support case ("it stopped at 3am") would be undebuggable. The file is
/// rotated once at 5 MB so it can never grow without bound.
struct TeeWriter {
    file: std::sync::Mutex<std::fs::File>,
}

struct TeeGuard<'a> {
    file: std::sync::MutexGuard<'a, std::fs::File>,
}

impl std::io::Write for TeeGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stderr().write_all(buf);
        self.file.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stderr().flush();
        self.file.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeWriter {
    type Writer = TeeGuard<'a>;
    fn make_writer(&'a self) -> Self::Writer {
        TeeGuard {
            file: self.file.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}

fn log_file_writer() -> TeeWriter {
    use std::io::Write;
    let dir = settings::Settings::base_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("engine.log");
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > 5 * 1024 * 1024 {
            let _ = std::fs::rename(&path, dir.join("engine.old.log"));
        }
    let open = |p: &std::path::Path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
    };
    // An existing log written by an *elevated* engine may not be writable by
    // the unelevated one (per-user autostart). Falling straight to the NUL sink
    // would silently lose all diagnostics, so try a fresh per-pid file first.
    let file = open(&path)
        .or_else(|_| open(&dir.join(format!("engine-{}.log", std::process::id()))))
        .or_else(|_| std::fs::OpenOptions::new().append(true).open("NUL"))
        .unwrap_or_else(|_| std::fs::File::create("NUL").expect("NUL sink"));
    let mut f = file;
    let _ = writeln!(f);
    TeeWriter {
        file: std::sync::Mutex::new(f),
    }
}

/// Marks stale jobs as interrupted, then resumes them.
///
/// A scan that was running when the engine stopped is not lost: its queue and
/// cursor are in SQLite, so it continues from the next unexamined file.
/// `MICS_NO_AUTO_RESUME=1` disables this (used by tests and by users who want
/// scans to be explicit).
fn resume_jobs_on_startup() {
    if std::env::var("MICS_NO_AUTO_RESUME").is_ok() || !settings::current().auto_resume_scans {
        return;
    }
    match storage::sqlite::Storage::open() {
        Ok(s) => {
            let marked = s.mark_jobs_interrupted().unwrap_or(0);
            if marked > 0 {
                tracing::info!("marked {marked} unfinished job(s) as interrupted");
            }
        }
        Err(e) => tracing::warn!("jobs storage unavailable: {e:#}"),
    }
    let resumed = scanner::resume_interrupted(tokio::runtime::Handle::current());
    if resumed > 0 {
        tracing::info!("resumed {resumed} interrupted scan job(s)");
    }
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
