//! The engine's side of D-007: talk to the privileged helper instead of asking
//! Windows for a second UAC prompt.
//!
//! `MICSHelper` is installed once (`install-helper`, one UAC prompt, launched
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

/// The elevated step, as the CLI spells it: the **name of a subcommand**, not a
/// flag. Calling it `--install-helper` (the obvious guess from the constant's
/// own documentation) made clap refuse the argument and exit 2 before the child
/// logged anything, so the UI could only say "the elevated step failed (exit
/// code 2)" — and every privileged operation went through that same call.
///
/// `the_elevated_step_is_a_subcommand_the_cli_accepts` in `src/tests.rs` parses
/// these strings with the real CLI, so the spelling cannot drift again.
pub const INSTALL_COMMAND: &str = "install-helper";
pub const UNINSTALL_COMMAND: &str = "uninstall-helper";

/// What `MICSHelper`'s `binPath` runs: the service body, and a subcommand too.
///
/// The same mistake lived a third time here, and a hidden child hides it twice
/// over: the SCM starts the process, clap refuses `--helper-service`, the process
/// exits 2, and the only symptom the engine sees is
/// `sc start failed: [SC] StartService FAILED 1053` — a service that does not
/// answer in time. `bin_path()` is the only place allowed to build this string,
/// and `tests.rs` asserts the built `binPath` carries no `--` spelling.
pub const SERVICE_COMMAND: &str = "helper-service";

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
    /// The program the service is registered to run (`sc qc`), when Windows says.
    pub bin_path: Option<String>,
    /// True when that program is gone, so the registration cannot work.
    pub stale: bool,
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
        bin_path: state.binary,
        stale: state.binary_missing,
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
    run_elevated_once(INSTALL_COMMAND)?;
    wait_until_reachable()
}

/// Removes the service (one UAC prompt; the helper is the only thing that is
/// ever asked to run elevated, so this is rare).
pub fn uninstall() -> Result<HelperStatus> {
    run_elevated_once(UNINSTALL_COMMAND)?;
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
    // A service whose program is gone cannot answer, and integrity is not the
    // reason. Saying "start MI CS from its installed folder" would be wrong
    // advice here; the fix is to register the helper again, which rewrites
    // `binPath` from the folder this copy runs in. Two ways to arrive here: the
    // user moved or replaced the MI CS folder, or a package update replaced the
    // versioned folder inside `WindowsApps` (`docs/SIGNING.md` §3, D-038).
    if state.stale {
        bail!(
            "the privileged helper is installed but its service points at a program that is gone \
             ({}). MI CS has moved since the helper was installed, or the folder it ran from was \
             replaced — a package update does exactly that. Install the helper again (Settings → \
             Engine → Install helper) and it is registered from the folder this copy runs in",
            state.bin_path.as_deref().unwrap_or("a path Windows would not name")
        );
    }
    // The pipe is owned by LocalSystem, so a client below Medium integrity is
    // refused at the access check and this probe fails for a helper that is
    // running perfectly. Naming the level turns "not answering" into something a
    // user can act on (`docs/TODO.md` trap 21).
    let integrity = crate::platform::windows::integrity::current()
        .map(crate::platform::windows::integrity::name)
        .unwrap_or("unknown");
    bail!(
        "the privileged helper is installed but not answering (state={}, reachable={}, this process \
         runs at {} integrity). The helper is LocalSystem and only clients at Medium or above may \
         open its pipe: start MI CS from its installed folder (%LOCALAPPDATA%\\MI CS) — a build \
         started out of a Low-integrity folder (a web root, a sandbox output dir) cannot reach it",
        state.state,
        state.reachable,
        integrity
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