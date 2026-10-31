//! Installing, querying and supervising the `MICSHelper` service (D-007).
//!
//! The service definition is a one-line `sc create` pointing back at this same
//! executable with `--helper-service`, so there is nothing extra to ship and an
//! upgrade cannot leave an old helper behind: `install-helper` rewrites the
//! definition with the current path.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::time::Duration;
use tracing::{error, info};
use windows::core::{w, PWSTR};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
    SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows::Win32::System::Threading::GetCurrentProcessId;

use super::ops::SERVICE_NAME;
use super::server;

const DESCRIPTION: &str = "Runs MI CS privileged operations (firewall, hosts, hardening) on \
                           behalf of the unelevated MI CS UI. Every call is audited in \
                           %PROGRAMDATA%\\MICS\\logs\\priv.log (D-007).";

/// Set by the SCM stop handler; the pipe loop polls it between clients.
static STOP: AtomicBool = AtomicBool::new(false);
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

/// `binPath` for `sc create`: the current executable plus the service flag.
/// Quoted because the install path contains spaces (`Program Files`).
pub fn bin_path(exe: &Path) -> String {
    format!("\"{}\" --helper-service", exe.display())
}

/// Argument vector for `sc create` (pure, so the quoting is testable).
pub fn sc_create_args(exe: &Path) -> Vec<String> {
    vec![
        "create".into(),
        SERVICE_NAME.into(),
        "binPath=".into(),
        bin_path(exe),
        "start=".into(),
        "auto".into(),
        "DisplayName=".into(),
        "MI CS privileged helper".into(),
        "obj=".into(),
        "LocalSystem".into(),
    ]
}

/// What `sc query` told us.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HelperState {
    pub installed: bool,
    pub running: bool,
    pub state: String,
}

impl HelperState {
    pub fn missing() -> Self {
        Self {
            installed: false,
            running: false,
            state: "not_installed".into(),
        }
    }
}

/// Parses the `STATE : 4  RUNNING` line of `sc query`.
///
/// `sc` answers a service that was never installed with a message ("The
/// specified service does not exist as an installed service." / `FAILED 1060`)
/// instead of a STATE line. That is the normal "not installed" answer, not an
/// unreadable state — reporting `unknown` there made Settings claim it could
/// not tell, which is the one thing it could tell.
pub fn parse_query(text: &str) -> HelperState {
    if text.contains("does not exist") || text.contains("FAILED 1060") {
        return HelperState::missing();
    }
    let mut state = "unknown".to_string();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("STATE") else {
            continue;
        };
        let Some((_, value)) = rest.split_once(':') else {
            continue;
        };
        let mut words = value.split_whitespace();
        let _code = words.next();
        if let Some(word) = words.next() {
            state = word.to_ascii_lowercase();
        }
    }
    let running = state == "running";
    HelperState {
        installed: state != "unknown",
        running,
        state,
    }
}

/// How long one `sc.exe` call may take. The service control manager can be busy
/// (another install in flight, a slow stop) and a request must not wait forever.
const SC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The `sc.exe` call for the helper service, with a deadline: query, create,
/// start, stop and delete all go through it, and installing the helper polls the
/// pipe right afterwards.
pub(crate) fn sc_call(args: Vec<String>) -> crate::platform::windows::process::ToolCall {
    crate::platform::windows::process::ToolCall::new(
        "sc (privileged helper service)",
        "sc",
        SC_TIMEOUT,
    )
    .args(args)
}

fn run_sc(args: &[String]) -> Result<String> {
    let out = sc_call(args.to_vec()).run().context("run sc.exe")?;
    if !out.success {
        bail!(
            "sc {} failed: {}",
            args.first().map(String::as_str).unwrap_or(""),
            out.text.trim()
        );
    }
    Ok(out.text)
}

/// Current service state. A missing service is a normal answer, not an error.
pub fn query() -> HelperState {
    match run_sc(&["query".to_string(), SERVICE_NAME.to_string()]) {
        Ok(text) => parse_query(&text),
        Err(_) => HelperState::missing(),
    }
}

/// Creates (or re-creates) the service and starts it. Must run elevated — it is
/// the body of `install-helper`, which the engine launches once with a UAC
/// prompt on behalf of the user.
pub fn install(exe: &Path) -> Result<HelperState> {
    if !crate::platform::windows::elevation::is_elevated() {
        bail!("installing the privileged helper needs an elevated process");
    }
    server::audit_note(&format!("install requested for {}", exe.display()));
    // Idempotent: drop any previous definition so an upgraded exe path and the
    // current description are picked up, then create and start it.
    let _ = run_sc(&["stop".into(), SERVICE_NAME.into()]);
    let _ = run_sc(&["delete".into(), SERVICE_NAME.into()]);
    run_sc(&sc_create_args(exe))?;
    let _ = run_sc(&[
        "description".into(),
        SERVICE_NAME.into(),
        DESCRIPTION.into(),
    ]);
    run_sc(&["start".to_string(), SERVICE_NAME.to_string()])?;

    // Prove the whole chain (service + pipe ACL + protocol) before reporting
    // success: "sc said Ok" is not the same as "the engine can use it".
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if server::probe().is_some() {
            let state = query();
            server::audit_note(&format!("install finished, helper state={}", state.state));
            return Ok(state);
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    bail!("the helper service was created but never answered on its pipe");
}

/// Stops and deletes the service (elevated; body of `uninstall-helper`).
pub fn uninstall() -> Result<HelperState> {
    if !crate::platform::windows::elevation::is_elevated() {
        bail!("removing the privileged helper needs an elevated process");
    }
    // Only a *failing* delete is interesting: a service that was never
    // installed is already in the desired state.
    let _ = run_sc(&["stop".into(), SERVICE_NAME.into()]);
    if let Err(e) = run_sc(&["delete".into(), SERVICE_NAME.into()]) {
        let text = format!("{e:#}");
        if !text.contains("1060") && !text.contains("does not exist") {
            return Err(e);
        }
    }
    server::audit_note("helper service removed");
    Ok(query())
}

/// Runs as the service body: the SCM calls `service_main` on a fresh thread and
/// this blocks until the process is stopped.
pub fn run_service() -> Result<()> {
    let name = w!("MICSHelper");
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_ptr() as *mut u16),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
        .map_err(|e| anyhow::anyhow!("StartServiceCtrlDispatcher failed (is this launched by the SCM?): {e}"))
}

extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let Ok(handle) = (unsafe {
        RegisterServiceCtrlHandlerExW(w!("MICSHelper"), Some(service_control), None)
    }) else {
        return;
    };
    STATUS_HANDLE.store(handle.0 as isize, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0);
    server::audit_note(&format!(
        "service starting (pid={}) version={} pipe={}",
        unsafe { GetCurrentProcessId() },
        env!("CARGO_PKG_VERSION"),
        super::ops::pipe_name()
    ));
    report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);

    let outcome = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(server::serve(&STOP, None)),
        Err(e) => Err(e.into()),
    };
    if let Err(e) = outcome {
        error!("privileged helper loop ended: {e:#}");
        server::audit_note(&format!("service loop ended with an error: {e:#}"));
    }
    report(SERVICE_STOPPED, 0);
}

extern "system" fn service_control(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        STOP.store(true, Ordering::SeqCst);
        report(SERVICE_STOP_PENDING, 0);
        server::audit_note("service stop requested");
        // Make the blocked accept() return so the loop can exit promptly.
        server::wake();
        info!("privileged helper stopping");
    }
    0
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, accepted: u32) {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    let handle = SERVICE_STATUS_HANDLE(raw as *mut core::ffi::c_void);
    unsafe {
        if let Err(e) = SetServiceStatus(handle, &status) {
            error!("SetServiceStatus: {e}");
        }
    }
}

/// The executable the service should point at (the running one).
pub fn current_exe() -> Result<std::path::PathBuf> {
    std::env::current_exe().context("locate the engine executable")
}
