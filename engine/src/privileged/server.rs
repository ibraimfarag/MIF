//! The privileged side of D-007: the pipe the `MICSHelper` service serves.
//!
//! Runs elevated (LocalSystem when installed as a service, or whatever token
//! `--helper-console` was started with). Every request is validated against the
//! closed [`Op`] set, logged to `%PROGRAMDATA%\MICS\logs\priv.log` **before** it
//! runs and again with its outcome, and then executed through the same code the
//! engine uses — the helper is a gate, not a second implementation.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use super::ops::{self, Op};

/// Read deadline for one request. Hardening runs PowerShell, which can take a
/// couple of minutes on a busy machine.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// The pipe is reachable by LocalSystem, administrators and *interactive* users
/// only — the same people who could answer a UAC prompt themselves. Nothing else
/// on the machine can ask the helper for anything.
const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";

/// Serves requests until `stop` is set (SCM stop) or the process dies.
///
/// `ready` is signalled once the first pipe instance exists, so a caller (and
/// the integration test) can connect without racing the bind.
pub async fn serve(stop: &AtomicBool, ready: Option<Sender<()>>) -> Result<()> {
    let name = format!(r"\\.\pipe\{}", ops::pipe_name());
    let attributes = pipe_security_attributes()?;
    let mut first = true;
    let mut ready = ready;
    info!("privileged helper listening on {name}");

    while !stop.load(Ordering::SeqCst) {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        first = false;
        let server = unsafe {
            options.create_with_security_attributes_raw(
                &name,
                std::ptr::addr_of!(attributes) as *mut std::ffi::c_void,
            )
        }
        .with_context(|| format!("create {name}"))?;
        if let Some(sender) = ready.take() {
            let _ = sender.send(());
        }

        // A cancelled `connect` would leave the instance half-bound, so wait for
        // a real client instead of polling. The SCM stop handler (and anyone
        // else) wakes the loop by connecting and closing again.
        if let Err(e) = server.connect().await {
            warn!("helper accept failed: {e}");
            continue;
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Err(e) = handle_client(server).await {
            warn!("helper request failed: {e:#}");
        }
    }

    info!("privileged helper stopped");
    Ok(())
}

/// Connects once and closes: makes a blocked `connect()` return so the loop can
/// notice that the service is stopping. Best effort by design.
pub fn wake() -> bool {
    let name = format!(r"\\.\pipe\{}", ops::pipe_name());
    std::fs::File::open(name).is_ok()
}

async fn handle_client(server: NamedPipeServer) -> Result<()> {
    // Who is asking? The pipe grants INTERACTIVE (D-007), so the helper answers
    // the engine and nothing else. Read from the connected handle before it is
    // split into halves, because the check needs the pipe, not the stream.
    let caller = {
        use std::os::windows::io::AsRawHandle;
        let handle = windows::Win32::Foundation::HANDLE(server.as_raw_handle());
        crate::platform::windows::caller::client_image_path(handle)
    };
    let allowed = crate::platform::windows::caller::configured_engine_path();
    let refused = match caller {
        Ok(path) if crate::platform::windows::caller::is_authorised(&path, allowed.as_deref()) => {
            None
        }
        Ok(path) => {
            warn!(
                "privileged helper refused {}: not the engine it serves",
                path.display()
            );
            Some(refusal("this pipe only serves the MI CS engine"))
        }
        Err(e) => {
            // No pid means the client is already gone, or the query was refused.
            // Either way there is no one to answer, and guessing is not an option.
            warn!("privileged helper could not identify its client: {e:#}");
            Some(refusal("the helper could not identify the calling process"))
        }
    };

    let (read_half, mut write_half) = tokio::io::split(server);
    let mut reader = BufReader::new(read_half);
    // A client that was already turned away is not allowed to hold the single
    // request slot for the full deadline: wait briefly for its line so it can read
    // the reason, then close.
    let deadline = if refused.is_some() {
        Duration::from_secs(5)
    } else {
        REQUEST_TIMEOUT
    };
    let mut line = String::new();
    let response = match refused {
        Some(explanation) => match tokio::time::timeout(deadline, reader.read_line(&mut line)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(_)) => explanation,
            Err(_) => return Ok(()),
        },
        None => match tokio::time::timeout(deadline, reader.read_line(&mut line)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Ok(()),
            Ok(Ok(_)) => match serde_json::from_str::<Op>(line.trim()) {
                Ok(op) => respond(&op),
                Err(e) => refusal(&format!("unknown or malformed request: {e}")),
            },
            Err(_) => refusal("the request timed out"),
        },
    };
    write_half.write_all(response.as_bytes()).await?;
    write_half.flush().await?;
    Ok(())
}

/// Validates, logs and runs one op, then answers with the envelope the engine's
/// client parses (`{"ok":true,"data":…}` / `{"ok":false,"error":…}`).
pub fn respond(op: &Op) -> String {
    let started = Instant::now();
    audit_start(op);
    let result = op.validate().and_then(|()| run(op));
    audit_end(op, started.elapsed(), &result);
    match result {
        Ok(data) => format!("{}\n", json!({ "ok": true, "data": data })),
        Err(e) => refusal(&format!("{e:#}")),
    }
}

fn refusal(message: &str) -> String {
    format!("{}\n", json!({ "ok": false, "error": message }))
}

/// The closed set of things the helper will do. Note the elevation check: a
/// helper without an elevated token is a broken install, and saying so beats
/// letting every operation fail with a confusing "Access is denied".
fn run(op: &Op) -> Result<Value> {
    if !crate::platform::windows::elevation::is_elevated()
        && !matches!(op, Op::Ping | Op::Version)
    {
        bail!(
            "the privileged helper is running without an elevated token — \
             uninstall and reinstall it from Settings → Engine"
        );
    }
    match op {
        Op::Ping => Ok(json!({
            "pong": true,
            "pid": std::process::id(),
            "version": env!("CARGO_PKG_VERSION")
        })),
        Op::Version => Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "elevated": crate::platform::windows::elevation::is_elevated()
        })),
        Op::FirewallDefaultDeny { enabled } => {
            crate::firewall::set_default_deny_now(*enabled)?;
            Ok(json!({ "enabled": *enabled }))
        }
        Op::FirewallAddRule { rule } => {
            let name = crate::firewall::add_rule_now(rule)?;
            Ok(json!({ "name": name }))
        }
        Op::FirewallRemoveRule { name } => {
            crate::firewall::remove_rule_now(name)?;
            Ok(json!({ "name": name }))
        }
        Op::HostsWrite { content } => {
            crate::ids::write_hosts_now(content)?;
            Ok(json!({
                "bytes": content.len(),
                "lines": content.lines().count()
            }))
        }
        Op::HardeningRun { action } => {
            crate::hardening::run_now(action)?;
            Ok(json!({ "action": action }))
        }
        Op::HardeningRollback { snapshot } => {
            crate::hardening::run_rollback_now(snapshot)?;
            Ok(json!({ "lines": snapshot.lines().count() }))
        }
    }
}

/// `SECURITY_ATTRIBUTES` carrying [`PIPE_SDDL`]. The descriptor is leaked on
/// purpose: it has to outlive every pipe instance, and the helper binds one for
/// its whole life.
fn pipe_security_attributes() -> Result<SECURITY_ATTRIBUTES> {
    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .context("build the privileged pipe ACL")?;
    }
    Ok(SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    })
}

fn log_path() -> PathBuf {
    // Test hook: the audit log is machine-wide, so tests point it at a scratch
    // file instead of writing into the real one.
    if let Ok(path) = std::env::var("MICS_HELPER_LOG") {
        return PathBuf::from(path);
    }
    let base = std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"));
    base.join("MICS").join("logs").join("priv.log")
}

fn audit_start(op: &Op) {
    append(&format!("phase=start {}", op.audit_summary()));
}

fn audit_end(op: &Op, elapsed: Duration, result: &Result<Value>) {
    let outcome = match result {
        Ok(_) => "ok=true".to_string(),
        Err(e) => format!("ok=false error={}", one_line(&format!("{e:#}"))),
    };
    append(&format!(
        "phase=done {outcome} dur_ms={} {}",
        elapsed.as_millis(),
        op.audit_summary()
    ));
}

/// Free-form lines (service start/stop) go through the same file so the record
/// is complete.
pub fn audit_note(note: &str) {
    append(&format!("phase=note {}", one_line(note)));
}

fn one_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

fn append(line: &str) {
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    rotate_if_needed(&path);
    let entry = format!("{} {line}\n", chrono::Utc::now().to_rfc3339());
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write;
            let _ = file.write_all(entry.as_bytes());
        }
        // Auditing must never take the helper down, but it must be visible.
        Err(e) => warn!("could not write {}: {e}", path.display()),
    }
}

fn rotate_if_needed(path: &std::path::Path) {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() < LIMIT {
        return;
    }
    let rotated = path.with_extension("1.log");
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(path, &rotated);
}

/// What the UI shows for the helper. `reachable` is the only field that proves
/// the whole chain works (service installed, running, pipe ACL, protocol).
#[derive(Debug, Clone, serde::Serialize)]
pub struct HelperVersion {
    pub version: String,
    pub elevated: bool,
}

/// Asks a running helper for its version. `None` means "not answering".
pub fn probe() -> Option<HelperVersion> {
    let value = super::call(&Op::Version).ok()?;
    Some(HelperVersion {
        version: value.get("version")?.as_str()?.to_string(),
        elevated: value.get("elevated").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

/// Test/diagnostic entry point: serves on the configured pipe in the current
/// process without involving the SCM.
///
/// The CLI already runs inside a tokio runtime, so building a second one and
/// blocking this thread on it panics ("cannot start a runtime from within a
/// runtime") — which is what `--helper-console` used to do on every start. The
/// loop therefore gets its own thread and runtime, exactly like the SCM's
/// service thread and the integration test.
pub fn run_console() -> Result<()> {
    audit_note(&format!(
        "console helper started (pid={}, pipe={})",
        std::process::id(),
        ops::pipe_name()
    ));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let worker = spawn_loop(Some(ready_tx));
    wait_until_bound(&ready_rx)?;
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("the helper console thread panicked"))?
}

/// Drives [`serve`] on a dedicated thread with its own runtime. Returns the
/// thread handle, so a foreground caller can wait for it.
fn spawn_loop(ready: Option<Sender<()>>) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build the helper runtime")?;
        let stop = AtomicBool::new(false);
        runtime.block_on(serve(&stop, ready))
    })
}

/// Waits for the pipe instance to exist. `Disconnected` means the runtime never
/// started, which is a different failure from a slow bind.
fn wait_until_bound(ready_rx: &std::sync::mpsc::Receiver<()>) -> Result<()> {
    match ready_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(()) => Ok(()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            bail!("the helper runtime could not start")
        }
        Err(_) => bail!("the helper pipe was never bound within 10s"),
    }
}

/// Starts the console loop on a background thread and returns once the pipe is
/// bound — the integration test drives the real protocol through it.
#[cfg(test)]
pub fn spawn_console() -> Result<()> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    // Detached on purpose: the test process owns it until it exits.
    let _worker = spawn_loop(Some(ready_tx));
    wait_until_bound(&ready_rx)
}