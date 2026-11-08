//! Named-pipe JSON-RPC server (primary transport, spec section 5).
//!
//! One instance per connection; the UI reconnects transparently. Every
//! connected client also receives the engine's push traffic (`event`,
//! `progress`) through the shared broadcast channel in [`crate::jobs`], so a
//! scan progress bar keeps moving without polling and a canary alert reaches
//! the UI the moment it fires.
//!
//! The accept loop never exits on transient errors: a failed `create` (for
//! example while the previous instance is still tearing down) is retried with a
//! short backoff. This used to be the reason the pipe closed right after the
//! first client connected.
//!
//! Every instance carries an explicit ACL (see [`pipe_security_attributes`]):
//! the user running the engine, `SYSTEM` and administrators — nobody else. The
//! default ACL Windows applies to a pipe grants `Everyone` and `ANONYMOUS LOGON`
//! read access, which let any local account on a shared machine attach to a free
//! instance and read the broadcast stream (`docs/THREAT-MODEL.md`, F-1).

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::ffi::c_void;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::rpc::JsonRpcRequest;

pub const PIPE_NAME: &str = r"\\.\pipe\mics_engine";

/// Full path for a configured pipe: `mics_engine` and `\\.\pipe\mics_engine`
/// name the same pipe, so both test hooks accept either form.
///
/// They used to disagree — `MICS_PIPE_NAME` wanted the full path and
/// `MICS_HELPER_PIPE` the bare name — so passing the other form served a
/// different pipe: Windows accepts `\\.\pipe\\\.\pipe\x` as a name of its own
/// (measured), which is why the mistake was silent instead of an error, and why
/// no client asking for the plain name could reach it. One function now answers
/// "what is this name" for both hooks, so they cannot drift apart again.
pub fn pipe_path(name: &str) -> String {
    let name = name.trim();
    if name.to_ascii_lowercase().starts_with(r"\\.\pipe\") {
        name.to_string()
    } else {
        format!(r"\\.\pipe\{name}")
    }
}

/// The same name without the `\\.\pipe\` prefix, for the callers that add it.
pub fn bare_pipe_name(value: &str) -> String {
    let value = value.trim();
    match value
        .to_ascii_lowercase()
        .strip_prefix(r"\\.\pipe\")
    {
        Some(_) => value[r"\\.\pipe\".len()..].to_string(),
        None => value.to_string(),
    }
}

/// Pipe name actually served. `MICS_PIPE_NAME` isolates a test/dev engine from
/// the real one (same code path, different pipe).
pub fn resolved_pipe_name() -> String {
    std::env::var("MICS_PIPE_NAME")
        .map(|name| pipe_path(&name))
        .unwrap_or_else(|_| PIPE_NAME.to_string())
}

const BACKOFF: std::time::Duration = std::time::Duration::from_millis(300);

/// The ACL every engine pipe instance carries: full control for `SYSTEM`,
/// administrators and the user who runs the engine — and nothing for anyone
/// else. `P` marks it protected, so no inherited ACE can widen it.
///
/// The engine and the UI run as the same user in every supported mode (the UI
/// starts the engine, or the autostart entry does), so naming that user's SID is
/// what keeps the transport working while `Everyone`/`ANONYMOUS LOGON` lose the
/// read access Windows' default pipe ACL would hand them.
fn pipe_sddl() -> Result<String> {
    let user = current_user_sid().context("resolve the current user for the pipe ACL")?;
    Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{user})"))
}

/// `SECURITY_ATTRIBUTES` carrying [`pipe_sddl`]. The descriptor is leaked on
/// purpose: it has to outlive every instance the accept loop creates, and the
/// process serves one pipe for its whole life.
fn pipe_security_attributes() -> Result<SECURITY_ATTRIBUTES> {
    let sddl: Vec<u16> = pipe_sddl()?
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .context("build the engine pipe ACL")?;
    }
    Ok(SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    })
}

/// The current process's user SID, as an SDDL string (`S-1-5-21-…`).
fn current_user_sid() -> Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("open the process token")?;
        let sid = read_token_user(token);
        let _ = CloseHandle(token);
        sid
    }
}

fn read_token_user(token: HANDLE) -> Result<String> {
    unsafe {
        // The first call only sizes the buffer: asking for zero bytes reports
        // the size through `needed` and fails, which is why the result is
        // deliberately ignored.
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            bail!("the process token reports no user information");
        }
        let mut buffer = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .context("read the process token's user")?;

        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut text).context("format the user SID")?;
        let sid = text.to_string().context("read the formatted SID")?;
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        Ok(sid)
    }
}

/// One pipe instance, with `attributes` applied when they could be built.
///
/// A caller that cannot build an ACL is served anyway (with the default one) and
/// told about it: refusing to start would turn a hardening problem into a
/// "the engine does not run" problem.
fn create_instance(
    name: &str,
    first: bool,
    attributes: Option<&mut SECURITY_ATTRIBUTES>,
) -> std::io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    if first {
        // Only the very first instance is exclusive; later iterations must
        // be allowed to create a fresh instance while one is connected.
        opts.first_pipe_instance(true);
    }
    match attributes {
        Some(attrs) => unsafe {
            opts.create_with_security_attributes_raw(name, attrs as *mut _ as *mut c_void)
        },
        None => opts.create(name),
    }
}

pub async fn run_pipe_server() -> Result<()> {
    let name = resolved_pipe_name();
    // Built once and reused for every instance; the descriptor inside is leaked
    // deliberately, because it must outlive the loop.
    let mut attributes = match pipe_security_attributes() {
        Ok(attrs) => Some(attrs),
        Err(e) => {
            warn!("engine pipe ACL not applied ({e:#}) — instances carry the default DACL");
            None
        }
    };
    info!("Starting Named Pipe server on {name}");
    let mut first = true;
    loop {
        // A stop can be asked for while no client is attached — the app that
        // started this engine closed, or `shutdown` arrived on another
        // connection — and then the accept below would park forever. This is
        // the second half of that wake-up (the first is the request itself).
        if crate::lifecycle::requested() {
            break;
        }
        let server = match create_instance(&name, first, attributes.as_mut()) {
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
        tokio::select! {
            connected = server.connect() => {
                if let Err(e) = connected {
                    warn!("pipe connect failed ({e}) — retrying");
                    tokio::time::sleep(BACKOFF).await;
                    continue;
                }
            }
            _ = crate::lifecycle::wait() => {
                info!("stop requested while waiting for a client — closing the pipe");
                break;
            }
        }
        info!("client connected to pipe");
        tokio::spawn(async move {
            if let Err(e) = handle_client(server).await {
                warn!("pipe client ended: {e:#}");
            }
        });
    }
    // `shutdown` is answered on the connection that asked for it, and that
    // answer is written by a task of its own: without this pause the process
    // can end before the caller reads "stopping" and the UI would have to treat
    // its own deliberate shutdown as a lost connection. Bounded, local, and
    // shorter than the client's own timeout.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    info!("pipe server stopped");
    Ok(())
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
    // A card raised while nobody was connected waited for this moment: the
    // `unclean-exit` report is filed while the engine is still starting, before
    // any client could be attached (D-024). Subscribing first means a card
    // raised from here on is delivered live and never parked twice.
    for card in crate::notify::alert::take_pending() {
        let _ = out_tx.send(crate::jobs::envelope(
            crate::notify::alert::CARD_METHOD,
            card,
        ));
    }
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
                // Never let one request block the connection: a vulnerability
                // scan talks to NVD for minutes and the UI's 15 s heartbeat
                // runs on this same pipe, so a ping queued behind it was read
                // as "engine connection lost". Responses carry their `id`, so
                // the client does not care about ordering.
                let tx = out_tx.clone();
                tokio::spawn(async move {
                    let resp = crate::dispatcher::Dispatcher::handle_request(req).await;
                    if let Ok(text) = serde_json::to_string(&resp) {
                        let _ = tx.send(text);
                    }
                });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows::Win32::Security::DACL_SECURITY_INFORMATION;

    /// The DACL of a live pipe object, read back from the handle the server
    /// itself holds — the same measurement an outsider would make.
    fn sddl_of(server: &NamedPipeServer) -> String {
        unsafe {
            let mut dacl = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            let status = GetSecurityInfo(
                HANDLE(server.as_raw_handle()),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                Some(&mut descriptor),
            );
            assert_eq!(status, ERROR_SUCCESS, "GetSecurityInfo failed");

            let mut text = PWSTR::null();
            let mut len = 0u32;
            assert!(
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    Some(&mut len),
                )
                .is_ok(),
                "SDDL conversion failed"
            );
            let sddl = text.to_string().unwrap_or_default();
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            sddl
        }
    }

    fn unique_name(tag: &str) -> String {
        format!(r"\\.\pipe\mics_test_{tag}_{}", std::process::id())
    }

    #[tokio::test]
    async fn the_engine_pipe_grants_only_the_owner_system_and_administrators() {
        let mut attributes = pipe_security_attributes().expect("build the pipe ACL");
        let server = create_instance(&unique_name("acl"), true, Some(&mut attributes))
            .expect("create the pipe");
        let sddl = sddl_of(&server);
        // `GA` in the SDDL is mapped to the concrete rights of a pipe object
        // when the descriptor is applied, so it is read back as `FA` (full
        // access) — the same grant in its stored form.
        let user = current_user_sid().expect("current user SID");

        // SDDL replaces the built-in Administrator account's SID with the `LA` alias
        // when the descriptor is converted back to text, which is what happened on
        // GitHub's Windows runner (2026-11-05, D-030): the same grant, written the
        // other way. A directory-owner test cannot see this, so it is tolerated here
        // and nowhere else.
        let grants_the_user = sddl.contains(&format!("(A;;FA;;;{user})"))
            || (user.ends_with("-500") && sddl.contains("(A;;FA;;;LA)"));
        assert!(grants_the_user, "{sddl}");
        assert!(sddl.contains("(A;;FA;;;SY)"), "{sddl}");
        assert!(sddl.contains("(A;;FA;;;BA)"), "{sddl}");
        assert_eq!(
            sddl.matches("(A;;").count(),
            3,
            "exactly three ACEs expected: {sddl}"
        );
        for denied in [";;;WD)", ";;;AN)", ";;;IU)"] {
            assert!(
                !sddl.contains(denied),
                "{denied} must not be granted on the engine pipe: {sddl}"
            );
        }
    }

    #[test]
    fn the_pipe_acl_is_protected_and_names_a_real_user_sid() {
        let sddl = pipe_sddl().expect("build the SDDL");
        assert!(sddl.starts_with("D:P("), "the DACL must be protected: {sddl}");
        let user = current_user_sid().expect("current user SID");
        assert!(user.starts_with("S-1-"), "not a SID: {user}");
        assert!(sddl.contains(&user), "{sddl}");
    }

    #[test]
    fn both_pipe_hooks_accept_a_bare_name_or_a_full_path() {
        // The form `MICS_HELPER_PIPE` used to require, and the form
        // `MICS_PIPE_NAME` used to require, must name the same pipe.
        assert_eq!(pipe_path("mics_test"), r"\\.\pipe\mics_test");
        assert_eq!(pipe_path(r"\\.\pipe\mics_test"), r"\\.\pipe\mics_test");
        assert_eq!(pipe_path(r"\\.\PIPE\mics_test"), r"\\.\PIPE\mics_test");
        assert_eq!(pipe_path("  mics_test  "), r"\\.\pipe\mics_test");
        // Idempotent: a caller may normalize twice without doubling the prefix.
        assert_eq!(pipe_path(&pipe_path("mics_test")), r"\\.\pipe\mics_test");

        assert_eq!(bare_pipe_name(r"\\.\pipe\mics_test"), "mics_test");
        assert_eq!(bare_pipe_name("mics_test"), "mics_test");
        assert_eq!(bare_pipe_name("  mics_test "), "mics_test");
        // Only the real prefix is stripped, and the round trip is lossless for
        // every accepted form.
        assert_eq!(bare_pipe_name(r"\\.\pipelines\x"), r"\\.\pipelines\x");
        for name in ["mics_test", r"\\.\pipe\mics_test"] {
            assert_eq!(pipe_path(&bare_pipe_name(name)), r"\\.\pipe\mics_test");
        }
    }
}
