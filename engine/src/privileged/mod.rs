//! The engine's side of D-007: talk to the privileged helper instead of asking
//! Windows for a second UAC prompt.
//!
//! `MICSHelper` is installed once (`--install-helper`, one UAC prompt, launched
//! from the UI or automatically the first time an admin operation is needed) and
//! from then on the unelevated engine and UI can firewall, rewrite hosts and
//! harden the machine with no prompt at all.

pub mod ops;
pub mod server;
pub mod service;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::time::{Duration, Instant};

pub use ops::{Op, SERVICE_NAME};
// Only the tests call the validators through this module path; production code
// validates inside `ops` itself.
#[cfg(test)]
pub use ops::{validate_hosts, validate_rollback};

/// One privileged op can run PowerShell for up to two minutes.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// The helper re-creates its pipe instance between clients, so a connect can
/// catch that gap; retry briefly instead of reporting a dead helper.
const CONNECT_ATTEMPTS: u32 = 20;
const CONNECT_PAUSE: Duration = Duration::from_millis(100);
/// How long an install may take before we call it failed (the user has to read
/// and answer one prompt inside this window).
const INSTALL_TIMEOUT: Duration = Duration::from_secs(180);

/// What the UI shows. `reachable` is the field that proves the chain works.
#[derive(Debug, Clone, Serialize)]
pub struct HelperStatus {
    pub service: String,
    pub installed: bool,
    pub running: bool,
    pub state: String,
    pub reachable: bool,
    pub version: Option<String>,
    pub elevated: bool,
    pub pipe: String,
}

pub fn status() -> HelperStatus {
    let state = service::query();
    let probe = server::probe();
    HelperStatus {
        service: SERVICE_NAME.to_string(),
        installed: state.installed,
        running: state.running,
        state: state.state,
        reachable: probe.is_some(),
        version: probe.as_ref().map(|p| p.version.clone()),
        elevated: probe.as_ref().map(|p| p.elevated).unwrap_or(false),
        pipe: ops::pipe_name(),
    }
}

/// Sends one op and returns its `data` payload.
pub fn call(op: &Op) -> Result<Value> {
    let request = ops::encode(op)?;
    let (sender, receiver) = std::sync::mpsc::channel();
    // A thread owns the blocking pipe I/O, so a helper that stops answering
    // cannot wedge the caller forever.
    std::thread::spawn(move || {
        let _ = sender.send(exchange(&request));
    });
    match receiver.recv_timeout(REQUEST_TIMEOUT) {
        Ok(result) => result,
        Err(_) => bail!(
            "the privileged helper did not answer within {}s",
            REQUEST_TIMEOUT.as_secs()
        ),
    }
}

fn exchange(request: &str) -> Result<Value> {
    use std::io::{BufRead, BufReader, Write};
    let path = format!(r"\\.\pipe\{}", ops::pipe_name());
    let mut last = None;
    for attempt in 0..CONNECT_ATTEMPTS {
        match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
            Ok(mut pipe) => {
                pipe.write_all(request.as_bytes())
                    .context("send to the privileged helper")?;
                pipe.flush().ok();
                let mut reader = BufReader::new(pipe);
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .context("read the privileged helper's answer")?;
                if line.trim().is_empty() {
                    bail!("the privileged helper closed the connection without answering");
                }
                return ops::parse_response(line.trim());
            }
            Err(e) => {
                last = Some(e);
                if attempt + 1 < CONNECT_ATTEMPTS {
                    std::thread::sleep(CONNECT_PAUSE);
                }
            }
        }
    }
    Err(anyhow::Error::new(last.unwrap_or_else(|| {
        std::io::Error::other("no pipe")
    })))
    .with_context(|| {
        format!(
            "the privileged helper is not reachable on {path} — install it in Settings → Engine \
             (one Windows prompt), then retry"
        )
    })
}

/// Installs (or repairs) the helper with a single UAC prompt. Returns the live
/// status, so the caller can report exactly what happened.
pub fn install() -> Result<HelperStatus> {
    if let Some(probe) = server::probe()
        && probe.elevated
    {
        return Ok(status());
    }
    run_elevated_once("--install-helper")?;
    wait_until_reachable()
}

/// Removes the service (one UAC prompt; the helper is the only thing that is
/// ever asked to run elevated, so this is rare).
pub fn uninstall() -> Result<HelperStatus> {
    run_elevated_once("--uninstall-helper")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if server::probe().is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(status())
}

fn run_elevated_once(flag: &str) -> Result<()> {
    let exe = service::current_exe()?;
    crate::platform::windows::elevation::run_elevated(&exe, &[flag], INSTALL_TIMEOUT)
}

fn wait_until_reachable() -> Result<HelperStatus> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let probe = server::probe();
        if probe.as_ref().map(|p| p.elevated).unwrap_or(false) {
            return Ok(status());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let state = status();
    bail!(
        "the privileged helper is installed but not answering (state={}, reachable={})",
        state.state,
        state.reachable
    )
}

/// Makes sure the helper exists, installing it (one UAC prompt) when it does
/// not. Called by the privileged entry points so a first-time user gets the
/// same "it just works" behaviour as before — but only ever once.
pub fn ensure() -> Result<()> {
    if let Some(probe) = server::probe()
        && probe.elevated
    {
        return Ok(());
    }
    install().map(|_| ())
}

/// `ensure()` + `call()`: the path every privileged operation takes.
pub fn run_op(op: &Op) -> Result<Value> {
    ensure()?;
    call(op)
}