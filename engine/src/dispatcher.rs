use crate::rpc::{JsonRpcRequest, JsonRpcResponse, JsonRpcError};
use serde_json::json;
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};
use crate::platform::traits::PlatformCollectors;
use crate::platform::windows::process::ToolCall;
pub struct Dispatcher;

/// How long one `reg.exe` call for the autostart entry may take. Writing an
/// `HKCU\...\Run` value is instant; a registry filter driver can still stall it,
/// and that used to hold `service.install` / `service.remove` open forever.
const REG_ENTRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long a Defender quick scan may take before the request gives up. The scan
/// really does run for minutes, so the budget is generous — it only exists so an
/// unanswered `-Wait` cannot pin this request for the rest of the session.
const DEFENDER_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1800);

/// The transport carried the request and the process that sent it is not this
/// product, so the one method that acts on the user's behalf is refused. Its own
/// code, so a caller can tell "the engine declined you" apart from "the engine
/// could not do it" (-32000) and "you sent nonsense" (-32602).
const REFUSED_CALLER: i32 = -32003;

/// The autostart entry's registry call, with a deadline. `action` is `add` or
/// `delete`; `what` names the operation in the timeout error.
pub(crate) fn reg_entry(action: &'static str, args: &[&str], what: &'static str) -> ToolCall {
    ToolCall::new(what, "reg", REG_ENTRY_TIMEOUT)
        .arg(action)
        .args(args)
}

fn error_response(req: JsonRpcRequest, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(json!(JsonRpcError {
            code: -32602,
            message: message.to_string(),
            data: None,
        })),
        id: req.id,
    }
}

/// A known method that failed: keep the real reason instead of the generic
/// "Method failed internally", so the UI can show something actionable
/// ("requires administrator rights", "the operation timed out", ...).
fn detailed_error(req: JsonRpcRequest, method: &str, e: anyhow::Error) -> JsonRpcResponse {
    let mut message = format!("{method} failed: {e:#}");
    if let Some(hint) = readonly_hint(&e) {
        message.push_str(" — ");
        message.push_str(&hint);
    }
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(json!(JsonRpcError {
            code: -32000,
            message,
            data: None,
        })),
        id: req.id,
    }
}

/// The explanation appended when a failure is SQLite's `SQLITE_READONLY`.
///
/// "attempt to write a readonly database" is an access refusal, but nothing in
/// that sentence says so; the user went looking for a corrupt file while the
/// folder's permissions (or the process's integrity level) were the problem.
pub(crate) fn readonly_hint(e: &anyhow::Error) -> Option<String> {
    let readonly = e.chain().any(|cause| {
        cause
            .to_string()
            .to_ascii_lowercase()
            .contains("readonly database")
    });
    readonly.then(crate::storage::sqlite::readonly_hint)
}

/// The filter a `fw.wfp.*` call asks about, read from the request params. A
/// spec with neither an application nor a port is refused here, in front of the
/// privilege split, so the caller gets the same answer either way.
pub(crate) fn filter_spec(req: &JsonRpcRequest) -> Option<crate::firewall::wfp::FilterSpec> {
    let params = req.params.as_ref()?;
    let spec = crate::firewall::wfp::FilterSpec {
        app: params
            .get("app")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|app| !app.is_empty())
            .map(String::from),
        port: params
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|p| u16::try_from(p).ok()),
        protocol: params
            .get("protocol")
            .and_then(|v| v.as_u64())
            .and_then(|p| u8::try_from(p).ok()),
        note: params
            .get("note")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|note| !note.is_empty())
            .map(String::from),
    };
    // The same gate the helper applies, so a spec that could never be written
    // is refused before it is put on the wire.
    crate::firewall::wfp::validate(&spec).ok()?;
    Some(spec)
}

impl Dispatcher {
    /// `caller` is the image of the process on the other end of the transport that
    /// carried `req`, when that transport can name it: the pipe asks the kernel for
    /// the client's process id (see `platform::windows::pipe`). `None` means the
    /// transport cannot name its peer (the stdio loop) or the read failed — and the
    /// methods that decide something on the user's behalf treat that as "not this
    /// product", so an unidentifiable caller cannot inherit a permission.
    pub async fn handle_request(req: JsonRpcRequest, caller: Option<&Path>) -> JsonRpcResponse {
        info!("Processing request: {}", req.method);
        // Proof of life for the hang detector, plus the method its report names
        // if this runtime stops answering (ز2-ب). A no-op when no session
        // started a watchdog, as in a unit test.
        crate::watchdog::note_request(&req.method);

        let mut unknown = false;
        let result = match req.method.as_str() {
            "ping" => {
                info!("Ping received");
                Some(json!("pong"))
            }
            "status" => {
                // The real build, not a literal: the version comes from the crate
                // and the platform names the architecture, which is the first
                // thing to check when someone reports an ARM64 or x64 problem.
                // `integrity` is D-025's third answer: what this copy's own signed
                // manifest says about the files next to the engine — read from a
                // cache, so a heartbeat never re-hashes the package.
                Some(json!({
                    "state": "running",
                    "version": env!("CARGO_PKG_VERSION"),
                    "platform": format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                    "pid": std::process::id(),
                    "integrity": crate::selfcheck::state().state.as_str(),
                }))
            }
            "shutdown" => {
                // The UI's own quit path (D-039): reply first, then end. The
                // pipe server holds the connection open just long enough for
                // this answer to be written, so the app knows its engine is
                // stopping on purpose rather than losing it. Only the app that
                // started this engine sends it (the client checks that before
                // calling), and the parent watch is the second, harsher route
                // to the same place when the app dies without asking.
                crate::lifecycle::request("the app asked the engine to stop (shutdown)");
                Some(json!({ "status": "stopping" }))
            }
            "audit.run" => {
                // `params.sections` runs a subset (re-check one thing after a fix);
                // absent or empty means the full audit the dashboard shows.
                let requested = match crate::platform::traits::requested_sections(req.params.as_ref()) {
                    Ok(sections) => sections,
                    Err(e) => return error_response(req, &format!("audit.run: {e:#}")),
                };
                // `params.merge: true` re-reads those sections on top of the last
                // full audit, so a fix refreshes one section in milliseconds
                // without replacing the report with an uncomparable partial one.
                let merge = match crate::platform::traits::merge_requested(
                    req.params.as_ref(),
                    requested.as_deref(),
                ) {
                    Ok(merge) => merge,
                    Err(e) => return error_response(req, &format!("audit.run: {e:#}")),
                };
                match (&requested, merge) {
                    (Some(list), true) => info!("Re-reading audit sections: {}", list.join(", ")),
                    (Some(list), false) => info!("Running audit for: {}", list.join(", ")),
                    (None, _) => info!("Running full system audit..."),
                }
                let collectors = crate::platform::windows::collectors::WindowsCollectors;
                if merge {
                    let names = requested.unwrap_or_default();
                    // Collected before the cache is locked: the lock is never held
                    // across an await.
                    let fresh = crate::platform::traits::collect_audit(&collectors, Some(&names)).await;
                    match crate::platform::traits::with_audit_cache(|cache| cache.merge(fresh, &names)) {
                        Ok(report) => Some(report),
                        Err(e) => {
                            error!("audit.run merge: {e:#}");
                            return detailed_error(req, "audit.run", e);
                        }
                    }
                } else {
                    let pass = crate::platform::traits::collect_audit(&collectors, requested.as_deref()).await;
                    // Only a full audit is a valid base for a later merge.
                    if requested.is_none() {
                        crate::platform::traits::with_audit_cache(|cache| cache.remember(pass.clone()));
                    }
                    Some(pass.report(requested.is_some(), &[]))
                }
            }
            "net.connections" => {
                info!("Fetching network connections...");
                let collectors = crate::platform::windows::collectors::WindowsCollectors;
                if let Ok(conns) = collectors.get_network_connections().await {
                    Some(json!(conns))
                } else {
                    None
                }
            }
            "fw.default_deny.enable" => {
                info!("Enabling default outbound deny...");
                if let Err(e) = crate::firewall::FirewallManager::set_default_deny_outbound(true).await {
                    error!("Firewall error: {:?}", e);
                    None
                } else {
                    crate::notify::alert::protection(
                        "default outbound deny",
                        "outbound traffic is blocked except allowed rules",
                    );
                    Some(json!({"status": "success", "message": "Outbound traffic blocked"}))
                }
            }
            "fw.default_deny.disable" => {
                info!("Disabling default outbound deny...");
                if let Err(e) = crate::firewall::FirewallManager::set_default_deny_outbound(false).await {
                    error!("Firewall error: {:?}", e);
                    None
                } else {
                    Some(json!({"status": "success", "message": "Outbound traffic allowed"}))
                }
            }
            "vuln.scan.start" => {
                info!("Starting vulnerability scan job of {:?}", req.params);
                let max_apps = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("max_apps"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10) as usize;
                // Returns immediately: the scan runs as a durable job (NVD's
                // rate limit makes it minutes long) and reports through
                // `progress` / `job_finished`.
                match crate::vulns::start_scan(max_apps, tokio::runtime::Handle::current()) {
                    Ok(job_id) => Some(json!({
                        "job_id": job_id,
                        "state": "running",
                        "max_apps": max_apps,
                    })),
                    Err(e) => {
                        error!("vuln.scan.start failed: {e:#}");
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(json!(JsonRpcError {
                                code: -32000,
                                message: format!("vuln.scan.start: {e:#}"),
                                data: None,
                            })),
                            id: req.id,
                        };
                    }
                }
            }
            "fw.rules.list" => {
                match crate::firewall::FirewallManager::list_rules().await {
                    Ok(rules) => Some(json!(rules)),
                    Err(e) => {
                        error!("fw.rules.list failed: {e:#}");
                        None
                    }
                }
            }
            "fw.rules.add" => {
                let Some(params) = req.params.clone() else {
                    return error_response(req, "missing params");
                };
                let parsed: anyhow::Result<crate::firewall::AddRuleRequest> =
                    serde_json::from_value(params)
                        .map_err(|e| anyhow::anyhow!("invalid rule params: {e}"));
                match parsed {
                    Ok(r) => match crate::firewall::FirewallManager::add_rule(&r).await {
                        Ok(name) => Some(json!({"status": "created", "name": name})),
                        Err(e) => {
                            error!("fw.rules.add failed: {e:#}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("fw.rules.add invalid: {e:#}");
                        None
                    }
                }
            }
            "fw.rules.remove" => {
                let Some(name) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                else {
                    return error_response(req, "missing rule name");
                };
                match crate::firewall::FirewallManager::remove_rule(&name).await {
                    Ok(()) => Some(json!({"status": "removed", "name": name})),
                    Err(e) => {
                        error!("fw.rules.remove failed: {e:#}");
                        None
                    }
                }
            }
            "fw.default_deny.status" => {
                match crate::firewall::FirewallManager::is_default_deny_enabled().await {
                    Ok(on) => Some(json!({"default_deny_outbound": on})),
                    Err(e) => {
                        error!("fw.default_deny.status failed: {e:#}");
                        None
                    }
                }
            }
            "fw.country.block" => {
                let Some(cc) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("country"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                else {
                    return error_response(req, "missing country code");
                };
                match crate::firewall::FirewallManager::block_country(&cc).await {
                    Ok(name) => {
                        crate::notify::alert::protection(
                            &format!("country {cc} blocked"),
                            &name,
                        );
                        Some(json!({"status": "blocked", "rule": name}))
                    }
                    Err(e) => {
                        error!("fw.country.block failed: {e:#}");
                        None
                    }
                }
            }
            // MI CS' own WFP objects (register section 0.6 row 17, slice a). The
            // writes need an administrator, so they go through the helper; the
            // status is answered honestly when nothing can read the BFE at all.
            "fw.wfp.status" => match crate::firewall::wfp::WfpManager::status().await {
                Ok(status) => Some(json!(status)),
                Err(e) => {
                    error!("fw.wfp.status failed: {e:#}");
                    return detailed_error(req, "fw.wfp.status", e);
                }
            },
            "fw.wfp.block" => {
                let Some(spec) = filter_spec(&req) else {
                    return error_response(req, "missing app or port to block");
                };
                match crate::firewall::wfp::WfpManager::block(&spec).await {
                    Ok(outcome) => Some(json!({
                        "status": "blocked",
                        "key": outcome.key,
                        "added": outcome.added,
                        "filters": outcome.filters,
                    })),
                    Err(e) => {
                        error!("fw.wfp.block failed: {e:#}");
                        return detailed_error(req, "fw.wfp.block", e);
                    }
                }
            }
            "fw.wfp.unblock" => {
                let Some(spec) = filter_spec(&req) else {
                    return error_response(req, "missing app or port to unblock");
                };
                match crate::firewall::wfp::WfpManager::unblock(&spec).await {
                    Ok(outcome) => Some(json!({
                        "status": "unblocked",
                        "removed": outcome.removed,
                        "filters": outcome.filters,
                    })),
                    Err(e) => {
                        error!("fw.wfp.unblock failed: {e:#}");
                        return detailed_error(req, "fw.wfp.unblock", e);
                    }
                }
            }
            "fw.wfp.reset" => match crate::firewall::wfp::WfpManager::reset().await {
                Ok(removed) => Some(json!({"status": "reset", "removed": removed})),
                Err(e) => {
                    error!("fw.wfp.reset failed: {e:#}");
                    return detailed_error(req, "fw.wfp.reset", e);
                }
            },
            // The tamper watch (D-044), on demand: the guard thread polls it
            // about every 30 s, and this is the same look a caller can ask for —
            // including raising the alert when something recorded is gone.
            "fw.wfp.watch" => match crate::firewall::watch::poll() {
                Ok(report) => Some(
                    serde_json::to_value(report)
                        .unwrap_or_else(|e| json!({"state": "unknown", "detail": e.to_string()})),
                ),
                Err(e) => {
                    error!("fw.wfp.watch failed: {e:#}");
                    return detailed_error(req, "fw.wfp.watch", e);
                }
            },
            // A second launch, and the Explorer verb's `--scan` (D-041): the
            // window that is already open comes forward, scanning the handed
            // over path when there is one. `delivered` is the caller's answer —
            // true means another client took it and this process has nothing to
            // show, false means it is the window and scans the path itself.
            //
            // The transport is not the gate any more. The pipe is Low-labelled so
            // that a release unpacked into a folder Windows calls Low can still
            // drive its own engine, and Low is where the sandboxes live: what may
            // ask for a handover is decided from the caller's image instead
            // (`caller::handover_allowed`), which is the only thing a Low process
            // of a foreign build cannot borrow.
            "app.activate" => {
                let allowed = caller.is_some_and(crate::platform::windows::caller::handover_allowed);
                if !allowed {
                    let image = caller
                        .map(|path| path.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "an unidentified process".to_string());
                    warn!("app.activate refused: {image} is not this product");
                    return JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(json!(JsonRpcError {
                            code: REFUSED_CALLER,
                            message: format!(
                                "app.activate: {image} may not drive this window — only the \
                                 app itself, or a process signed with the same certificate, \
                                 can hand a path to it"
                            ),
                            data: None,
                        })),
                        id: req.id,
                    };
                }
                let path = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|p| !p.is_empty());
                Some(json!({"delivered": crate::jobs::announce_activation(path)}))
            }
            "scan.schedule" => Some(json!(crate::scanner::schedule_status())),
            "scan.start" => {
                info!("Starting scan job of {:?}", req.params);
                let root = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|v| v.as_str())
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from(r"C:\\"));
                let quarantine = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("quarantine"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // Returns immediately: the scan itself runs as a durable job and
                // reports through `progress` / `job_finished` notifications.
                match crate::scanner::start_scan(
                    root.clone(),
                    quarantine,
                    tokio::runtime::Handle::current(),
                ) {
                    Ok(job_id) => Some(json!({
                        "job_id": job_id,
                        "state": "running",
                        "path": root.to_string_lossy(),
                        "quarantine": quarantine,
                    })),
                    Err(e) => {
                        error!("scan.start failed: {e:#}");
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(json!(JsonRpcError {
                                code: -32000,
                                message: format!("scan.start: {e:#}"),
                                data: None,
                            })),
                            id: req.id,
                        };
                    }
                }
            }
            "scan.stop" => {
                let stopped = crate::scanner::stop_active_scan();
                Some(json!({"stopped": stopped}))
            }
            "job.list" => {
                let limit = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as u32;
                match crate::storage::sqlite::Storage::open().and_then(|s| s.list_jobs(limit)) {
                    Ok(list) => Some(json!(list)),
                    Err(e) => {
                        error!("job.list: {e:#}");
                        None
                    }
                }
            }
            "job.get" => {
                let Some(job_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("job_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing job_id");
                };
                match crate::storage::sqlite::Storage::open() {
                    Ok(s) => match s.get_job(&job_id) {
                        Ok(Some(job)) => {
                            let findings = s.job_findings(&job_id).unwrap_or_default();
                            Some(json!({
                                "job": job,
                                "findings": findings
                                    .iter()
                                    .filter_map(|t| serde_json::from_str::<serde_json::Value>(t).ok())
                                    .collect::<Vec<_>>(),
                                "running": crate::jobs::is_running(&job_id),
                            }))
                        }
                        Ok(None) => {
                            return error_response(req, &format!("job not found: {job_id}"));
                        }
                        Err(e) => {
                            error!("job.get: {e:#}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("job.get: {e:#}");
                        None
                    }
                }
            }
            "job.cancel" => {
                let Some(job_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("job_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing job_id");
                };
                let cancelled = crate::jobs::cancel(&job_id);
                Some(json!({"cancelled": cancelled, "job_id": job_id}))
            }
            "job.resume" => {
                // Resume a job that is not currently running (e.g. interrupted
                // by an engine restart that auto-resume skipped).
                let Some(job_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("job_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing job_id");
                };
                match crate::scanner::resume_job(&job_id, tokio::runtime::Handle::current()) {
                    Ok(true) => Some(json!({"status": "resumed", "job_id": job_id})),
                    Ok(false) => Some(json!({"status": "not_resumable", "job_id": job_id})),
                    Err(e) => {
                        error!("job.resume: {e:#}");
                        None
                    }
                }
            }
            "crash.list" => {
                let limit = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("limit"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(50) as usize;
                Some(json!(crate::crash::list(limit)))
            }
            "crash.get" => {
                let Some(bug_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("bug_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing bug_id");
                };
                match crate::crash::get(&bug_id) {
                    Some(report) => Some(report),
                    None => {
                        return error_response(req, &format!("no such report: {bug_id}"));
                    }
                }
            }
            "crash.delete" => {
                let Some(bug_id) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("bug_id"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing bug_id");
                };
                // A malformed id is a client bug, not "nothing to delete": say so
                // instead of answering `false` to something that was never a
                // report. A well-formed id that is not there stays idempotent.
                if !crate::crash::valid_bug_id(&bug_id) {
                    return error_response(req, &format!("not a bug id: {bug_id}"));
                }
                let deleted = crate::crash::delete(&bug_id);
                Some(json!({"deleted": deleted, "bug_id": bug_id}))
            }
            "quarantine.list" => {
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.list() {
                        Ok(items) => Some(json!(items)),
                        Err(e) => { error!("quarantine.list: {e:#}"); return detailed_error(req, "quarantine.list", e); }
                    },
                    Err(e) => { error!("quarantine.list: {e:#}"); return detailed_error(req, "quarantine.list", e); }
                }
            }
            "quarantine.restore" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("blob_id")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing blob_id");
                };
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.restore_file(&id).await {
                        Ok(orig) => Some(json!({"status": "restored", "path": orig})),
                        Err(e) => { error!("quarantine.restore: {e:#}"); return detailed_error(req, "quarantine.restore", e); }
                    },
                    Err(e) => { error!("quarantine.restore: {e:#}"); return detailed_error(req, "quarantine.restore", e); }
                }
            }
            "quarantine.delete" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("blob_id")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing blob_id");
                };
                match crate::scanner::quarantine::QuarantineManager::new() {
                    Ok(m) => match m.delete_blob(&id).await {
                        Ok(()) => Some(json!({"status": "deleted"})),
                        Err(e) => { error!("quarantine.delete: {e:#}"); return detailed_error(req, "quarantine.delete", e); }
                    },
                    Err(e) => { error!("quarantine.delete: {e:#}"); return detailed_error(req, "quarantine.delete", e); }
                }
            }
            "defender.scan.quick" => {
                // Defender orchestration: MpCmdRun quick scan (no console flash).
                let mut command = tokio::process::Command::new("powershell");
                command.args(["-NoProfile", "-Command",
                    r#"Start-Process -FilePath 'C:\Program Files\Windows Defender\MpCmdRun.exe' -ArgumentList '-Scan','-ScanType','1' -Wait"#]);
                command.creation_flags(
                    crate::platform::windows::elevation::CREATE_NO_WINDOW,
                );
                let out = tokio::time::timeout(DEFENDER_SCAN_TIMEOUT, command.output()).await;
                match out {
                    Ok(Ok(o)) if o.status.success() => Some(json!({"status": "done"})),
                    Ok(Ok(o)) => {
                        error!("defender scan failed: {}", String::from_utf8_lossy(&o.stderr));
                        None
                    }
                    Ok(Err(e)) => { error!("defender scan: {e:#}"); None }
                    Err(_) => {
                        error!(
                            "defender scan did not finish within {}s",
                            DEFENDER_SCAN_TIMEOUT.as_secs()
                        );
                        None
                    }
                }
            }
            "quarantine.add" => {
                info!("Quarantining file...");
                let path = req.params.as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|p| p.as_str())
                    .map(std::path::PathBuf::from);
                
                if let Some(p) = path {
                    let qm = crate::scanner::quarantine::QuarantineManager::new().ok();
                    if let Some(mgr) = qm {
                        if let Ok(dest) = mgr.quarantine_file(&p, "manual request").await {
                            Some(json!({"status": "quarantined", "path": dest}))
                        } else {
                            None
                        }
                    } else { None }
                } else { None }
            }
            "sync.now" => {
                info!("Syncing intelligence...");
                match crate::sync::SyncManager::new() {
                    Ok(sm) => match sm.sync_now().await {
                        Ok(res) => Some(json!({"status": "success", "report": res})),
                        Err(e) => { error!("sync.now: {e:#}"); return detailed_error(req, "sync.now", e); }
                    },
                    Err(e) => { error!("sync.now: {e:#}"); return detailed_error(req, "sync.now", e); }
                }
            }
            "sync.status" => {
                info!("Checking sync status...");
                match crate::sync::SyncManager::new() {
                    Ok(sm) => match sm.get_status().await {
                        Ok(state) => Some(state),
                        Err(e) => { error!("sync.status: {e:#}"); return detailed_error(req, "sync.status", e); }
                    },
                    Err(e) => { error!("sync.status: {e:#}"); return detailed_error(req, "sync.status", e); }
                }
            }
            "guard.start" => {
                crate::guard::start_guard();
                Some(json!({"status": "running"}))
            }
            "guard.stop" => {
                crate::guard::stop_guard();
                Some(json!({"status": "stopped"}))
            }
            "guard.status" => Some(crate::guard::status_json()),
            "guard.rules.list" => match crate::guard::load_rules() {
                Ok(r) => Some(json!(r)),
                Err(e) => { error!("guard.rules.list: {e:#}"); return detailed_error(req, "guard.rules.list", e); }
            },
            "guard.rules.add" => {
                // Rules live in JSON files (hot-reloaded every 30 s); add appends
                // to the user rules file so the starter pack stays pristine.
                let Some(rule) = req.params.as_ref().and_then(|p| {
                    serde_json::from_value::<crate::guard::GuardRule>(p.clone()).ok()
                }) else {
                    return error_response(req, "invalid rule params");
                };
                let dir = crate::guard::rules_dir();
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join("user.json");
                let mut list: Vec<crate::guard::GuardRule> = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or_default();
                list.push(rule);
                let payload = serde_json::to_string_pretty(&list)
                    .map_err(|e| anyhow::anyhow!("serialize rules: {e}"));
                match payload.and_then(|p| std::fs::write(&path, p).map_err(|e| anyhow::anyhow!("write rules: {e}"))) {
                    Ok(()) => Some(json!({"status": "added", "file": path})),
                    Err(e) => { error!("guard.rules.add: {e:#}"); return detailed_error(req, "guard.rules.add", e); }
                }
            }
            "canary.list" => Some(json!(crate::guard::canary::list_decoys())),
            "canary.status" => Some(crate::guard::canary::status_json()),
            "canary.configure" => {
                let Some(paths) = req.params.as_ref().and_then(|p| p.get("paths")).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>()) else {
                    return error_response(req, "missing paths array");
                };
                let cfg = crate::guard::canary::CanaryConfig { paths };
                match crate::guard::canary::save_config(&cfg) {
                    Ok(()) => {
                        // Re-arm rather than only deploy: the extra decoy (or the
                        // removed one) has to reach the watcher's baseline, and a
                        // file *this* call creates is the only kind that gets the
                        // settle window.
                        match crate::guard::canary::arm_watchers() {
                            Ok(()) => Some(json!({"status": "saved"})),
                            Err(e) => { error!("canary.configure: {e:#}"); return detailed_error(req, "canary.configure", e); }
                        }
                    }
                    Err(e) => { error!("canary.configure: {e:#}"); return detailed_error(req, "canary.configure", e); }
                }
            }
            "canary.deploy" => match crate::guard::canary::arm_watchers_detailed() {
                Ok(n) => Some(json!({"created": n})),
                Err(e) => { error!("canary.deploy: {e:#}"); return detailed_error(req, "canary.deploy", e); }
            },
            "incident.list" => {
                let limit = req.params.as_ref().and_then(|p| p.get("limit")).and_then(|v| v.as_u64()).unwrap_or(50) as u32;
                match crate::smart::correlator::list_incidents(limit) {
                    Ok(list) => Some(json!(list)),
                    Err(e) => { error!("incident.list: {e:#}"); return detailed_error(req, "incident.list", e); }
                }
            }
            "incident.close" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("incident_id")).and_then(|v| v.as_i64()) else {
                    return error_response(req, "missing incident_id");
                };
                match crate::smart::correlator::close_incident(id) {
                    Ok(()) => Some(json!({"status": "closed"})),
                    Err(e) => { error!("incident.close: {e:#}"); return detailed_error(req, "incident.close", e); }
                }
            }
            "noise.stats" => match crate::smart::noise_learner::stats() {
                Ok(s) => Some(json!(s)),
                Err(e) => { error!("noise.stats: {e:#}"); return detailed_error(req, "noise.stats", e); }
            },
            "noise.mute" => {
                let Some(cat) = req.params.as_ref().and_then(|p| p.get("category")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing category");
                };
                match crate::smart::noise_learner::mute_category(&cat) {
                    Ok(()) => Some(json!({"status": "muted"})),
                    Err(e) => { error!("noise.mute: {e:#}"); return detailed_error(req, "noise.mute", e); }
                }
            }
            "noise.unmute" => {
                let Some(cat) = req.params.as_ref().and_then(|p| p.get("category")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing category");
                };
                match crate::smart::noise_learner::unmute_category(&cat) {
                    Ok(()) => Some(json!({"status": "unmuted"})),
                    Err(e) => { error!("noise.unmute: {e:#}"); return detailed_error(req, "noise.unmute", e); }
                }
            }
            "guard.event.dismiss" => {
                let Some(cat) = req.params.as_ref().and_then(|p| p.get("category")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing category");
                };
                match crate::smart::noise_learner::record_dismissal(&cat) {
                    Ok(stat) => Some(json!(stat)),
                    Err(e) => { error!("noise dismissal: {e:#}"); None }
                }
            }
            "ids.status" => match crate::ids::status() {
                Ok(s) => Some(json!(s)),
                Err(e) => { error!("ids.status: {e:#}"); return detailed_error(req, "ids.status", e); }
            },
            "ids.block.add" => {
                let Some(domains) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("domains"))
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>())
                else {
                    return error_response(req, "missing domains");
                };
                match crate::ids::add_domains(&domains) {
                    Ok(n) => {
                        crate::notify::alert::protection(
                            &format!("{n} domain(s) added to the DNS blocklist"),
                            "hosts file updated",
                        );
                        Some(json!({"added": n}))
                    }
                    Err(e) => { error!("ids.block.add: {e:#}"); return detailed_error(req, "ids.block.add", e); }
                }
            }
            "ids.block.remove" => {
                let Some(d) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("domain"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing domain");
                };
                match crate::ids::remove_domain(&d) {
                    Ok(()) => Some(json!({"status": "removed"})),
                    Err(e) => { error!("ids.block.remove: {e:#}"); return detailed_error(req, "ids.block.remove", e); }
                }
            }
            "ids.blocklist.import" => {
                let Some(p) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("path"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing path");
                };
                match crate::ids::import_blocklist(&p) {
                    Ok(n) => {
                        crate::notify::alert::protection(
                            &format!("{n} domain(s) imported into the DNS blocklist"),
                            "hosts file updated",
                        );
                        Some(json!({"imported": n}))
                    }
                    Err(e) => { error!("ids.blocklist.import: {e:#}"); return detailed_error(req, "ids.blocklist.import", e); }
                }
            }
            "geoip.lookup" => {
                let Some(ip) = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("ip"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                else {
                    return error_response(req, "missing ip");
                };
                Some(json!({"country": crate::ids::geoip::lookup(&ip)}))
            }
            "update.download" => {
                match crate::update::download_and_verify().await {
                    Ok(path) => Some(json!({"status": "staged", "path": path})),
                    Err(e) => { error!("update.download: {e:#}"); return detailed_error(req, "update.download", e); }
                }
            }
            "update.apply" => {
                let p = req
                    .params
                    .as_ref()
                    .and_then(|pp| pp.get("staged"))
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        crate::settings::Settings::base_dir()
                            .join("update")
                            .join("update.zip")
                    });
                match crate::update::apply(&p) {
                    Ok(msg) => Some(json!({"status": "applied", "detail": msg})),
                    Err(e) => { error!("update.apply: {e:#}"); return detailed_error(req, "update.apply", e); }
                }
            }
            "notify.test" => {
                // Settings screen: proves desktop cards (and DND) actually work
                // — the answer has to be the truth, so a disabled setting or a
                // card Windows refused is reported instead of "sent".
                if !crate::notify::alert::enabled() {
                    return error_response(
                        req,
                        "desktop notifications are turned off in Settings",
                    );
                }
                match crate::notify::toast::show_toast(
                    crate::notify::alert::text("test.title"),
                    crate::notify::alert::text("test.body"),
                ) {
                    Ok(()) => Some(json!({"status": "sent"})),
                    Err(e) => {
                        error!("notify.test: {e:#}");
                        return detailed_error(req, "notify.test", e);
                    }
                }
            }
            "hardening.list" => Some(json!(crate::hardening::list_actions())),
            "hardening.apply" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("action")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing action");
                };
                match crate::hardening::apply(&id).await {
                    Ok(_) => Some(json!({"status": "applied", "action": id})),
                    Err(e) => { error!("hardening.apply: {e:#}"); return detailed_error(req, "hardening.apply", e); }
                }
            }
            "hardening.rollback" => {
                let Some(id) = req.params.as_ref().and_then(|p| p.get("action")).and_then(|v| v.as_str()).map(String::from) else {
                    return error_response(req, "missing action");
                };
                match crate::hardening::rollback(&id).await {
                    Ok(()) => Some(json!({"status": "rolled_back", "action": id})),
                    Err(e) => { error!("hardening.rollback: {e:#}"); return detailed_error(req, "hardening.rollback", e); }
                }
            }
            "report.export" => match crate::reports::export_markdown().await {
                Ok(path) => Some(json!({"status": "exported", "path": path})),
                Err(e) => { error!("report.export: {e:#}"); return detailed_error(req, "report.export", e); }
            },
            "helper.status" => Some(json!(crate::privileged::status())),
            "helper.install" => {
                // The user has to answer one UAC prompt inside this call, so it
                // runs off the runtime: a blocked worker would stop answering
                // the UI's heartbeat while the prompt is on screen.
                match tokio::task::spawn_blocking(crate::privileged::install).await {
                    Ok(Ok(status)) => Some(json!(status)),
                    Ok(Err(e)) => return detailed_error(req, "helper.install", e),
                    Err(e) => return detailed_error(req, "helper.install", anyhow::Error::new(e)),
                }
            }
            "helper.uninstall" => {
                match tokio::task::spawn_blocking(crate::privileged::uninstall).await {
                    Ok(Ok(status)) => Some(json!(status)),
                    Ok(Err(e)) => return detailed_error(req, "helper.uninstall", e),
                    Err(e) => return detailed_error(req, "helper.uninstall", anyhow::Error::new(e)),
                }
            }
            "service.install" => {
                // Boot-with-windows: scheduled task running the engine --service at logon.
                let exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("service.install: {e:#}");
                        return error_response(req, "cannot resolve engine exe");
                    }
                };
                // Boot-with-windows: HKCU Run entry (no admin needed; the
                // scheduled-task variant requires elevation and is documented).
                let data = format!("\"{}\" --service", exe.display());
                let out = reg_entry(
                    "add",
                    &[
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", "MICS-Engine",
                        "/t", "REG_SZ",
                        "/d", data.as_str(),
                        "/f",
                    ],
                    "reg add (service.install: autostart entry)",
                )
                .run();
                match out {
                    Ok(o) if o.success => Some(json!({"status": "installed"})),
                    Ok(o) => { error!("service.install: {}", o.text.trim()); None }
                    Err(e) => { error!("service.install: {e:#}"); return detailed_error(req, "service.install", e); }
                }
            }
            "service.remove" => {
                let out = reg_entry(
                    "delete",
                    &[
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        "/v", "MICS-Engine",
                        "/f",
                    ],
                    "reg delete (service.remove: autostart entry)",
                )
                .run();
                match out {
                    Ok(o) if o.success => Some(json!({"status": "removed"})),
                    Ok(o) => { error!("service.remove: {}", o.text.trim()); None }
                    Err(e) => { error!("service.remove: {e:#}"); return detailed_error(req, "service.remove", e); }
                }
            }
            "settings.get" => Some(json!(crate::settings::current())),
            "settings.set" => {
                let Some(patch) = req.params.clone() else {
                    return error_response(req, "missing settings object");
                };
                match crate::settings::patch(&patch) {
                    Ok(next) => {
                        // Settings that change engine behaviour take effect on
                        // the next decision (sync tick, new toast, next scan);
                        // anything requiring a restart is documented in the UI.
                        crate::jobs::notify(
                            "event",
                            json!({ "type": "settings.changed", "data": next }),
                        );
                        Some(json!(next))
                    }
                    Err(e) => {
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(json!(JsonRpcError {
                                code: -32602,
                                message: format!("settings.set: {e:#}"),
                                data: None,
                            })),
                            id: req.id,
                        };
                    }
                }
            }
            // The opt-in Explorer right-click entry (D-054). The app is the only
            // caller, and it brings the labels: they come from its language pack,
            // so the engine never stores a translation for a language it does not
            // know. Per-user HKCU, no elevation, and `enabled:false` removes
            // exactly the keys `enabled:true` wrote.
            "explorer.menu.set" => {
                let params = req.params.clone().unwrap_or_else(|| json!({}));
                let Some(enabled) = params.get("enabled").and_then(|v| v.as_bool()) else {
                    return error_response(req, "explorer.menu.set requires enabled (true|false)");
                };
                let applied = if enabled {
                    let app_path = params
                        .get("app_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    let file_label = params
                        .get("file_label")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let folder_label = params
                        .get("folder_label")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    crate::explorer::enable(
                        &crate::explorer::UserRegistry,
                        &app_path,
                        &file_label,
                        &folder_label,
                    )
                } else {
                    crate::explorer::disable(&crate::explorer::UserRegistry)
                };
                if let Err(e) = applied {
                    error!("explorer.menu.set failed: {e:#}");
                    return detailed_error(req, "explorer.menu.set", e);
                }
                // The registry is the thing that happened; the flag is the memory
                // of it (so a moved copy refreshes the stale path at next start).
                // Persisting second means a failed write never claims success.
                match crate::settings::patch(&json!({ "explorer_menu": enabled })) {
                    Ok(next) => {
                        crate::jobs::notify(
                            "event",
                            json!({ "type": "settings.changed", "data": next }),
                        );
                        Some(json!({ "enabled": enabled, "settings": next }))
                    }
                    Err(e) => {
                        error!("explorer.menu.set: {e:#}");
                        return detailed_error(req, "explorer.menu.set", e);
                    }
                }
            }
            "update.check" => {
                // Manifest-based self-update check. The URL is the user's own or
                // the channel's compiled-in default (D-046), and this is the only
                // thing that fetches it — there is no timer behind it.
                match crate::update::check().await {
                    Ok(info) => Some(info),
                    Err(e) => { error!("update.check: {e:#}"); return detailed_error(req, "update.check", e); }
                }
            }
            _ => {
                unknown = true;
                warn!("Unknown method: {}", req.method);
                None
            }
        };
        // Distinguish "unknown method" (-32601) from "known method that
        // failed internally" (-32000) so the UI shows honest errors.
        match result {
            Some(res) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(res),
                error: None,
                id: req.id,
            },
            None if unknown => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(json!(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", req.method),
                    data: None,
                })),
                id: req.id,
            },
            None => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(json!(JsonRpcError {
                    code: -32000,
                    message: format!("Method failed internally: {}", req.method),
                    data: None,
                })),
                id: req.id,
            },
        }
    }
}
