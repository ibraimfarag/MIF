//! Running an external Windows tool with a deadline.
//!
//! Every command the engine spawns is someone else's code: PowerShell waiting on
//! a prompt nobody answers, `reg.exe` behind an antivirus filter, `taskkill`
//! against a process that is already gone, a scanner that never returns. Without
//! a deadline the caller's thread waits forever and the UI sits on a spinner with
//! no way out. (The firewall used to be in this list and is not any more: it
//! speaks the Windows Firewall API in-process, D-028.)
//!
//! Two things this module gets right that a naive `output()` does not:
//!
//! 1. **A deadline.** The child is killed and the call fails with a message that
//!    names the operation, instead of blocking a request thread.
//! 2. **Draining while waiting.** A tool can print far more than a pipe buffer
//!    (64 KiB) - `reg query` over a large key, a PowerShell snapshot of every
//!    service. Polling `try_wait` without reading the pipes makes the child block
//!    on write and never exit, so a "timeout" would fire on a process that was
//!    about to finish. The readers here run on their own threads and collect
//!    everything.
//!
//! Call sites do not build a `Command` themselves: they describe the call as a
//! [`ToolCall`] (program, arguments, operation name, deadline) and run it. That
//! keeps the one place that starts a process auditable, and a test below fails
//! when a bare `Command::new` appears anywhere else in `src/`.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// What a finished child produced.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// `true` when the process exited with code 0.
    pub success: bool,
    /// stdout followed by stderr, lossily decoded (Windows tools are not always
    /// UTF-8, and a failed decode must not hide the error text).
    pub text: String,
}

/// One external tool the engine runs: what it is, how long it may take, and the
/// name of the operation it performs.
///
/// The name is what the timeout error reports, so a stalled `net.exe` says
/// `net localgroup (audit: local administrators) did not finish within 20s`
/// instead of timing out anonymously. Arguments are `OsString` because a path
/// handed to a tool must survive a round trip, not go through a lossy decode.
#[derive(Debug, Clone)]
pub struct ToolCall {
    program: &'static str,
    args: Vec<OsString>,
    what: &'static str,
    timeout: Duration,
}

impl ToolCall {
    pub fn new(what: &'static str, program: &'static str, timeout: Duration) -> Self {
        Self {
            program,
            args: Vec::new(),
            what,
            timeout,
        }
    }

    /// Appends one argument.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends a whole argument list.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Replaces the deadline. Call sites pass theirs to [`ToolCall::new`]; the
    /// tests shrink it so a proven deadline costs 300 ms instead of 20 s.
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The operation's name, exactly as it appears in the timeout error.
    /// Production reads it out of the error itself; the tests assert on it.
    #[cfg(test)]
    pub fn what(&self) -> &'static str {
        self.what
    }

    pub fn run(&self) -> Result<CommandOutput> {
        spawn_with_deadline(self.program, &self.args, self.what, self.timeout)
    }

    /// Points the same call at another program, keeping its name and deadline.
    ///
    /// Test-only: this is how a call site proves its own deadline is wired by
    /// aiming its exact call at a program that never returns.
    #[cfg(test)]
    pub fn retarget(mut self, program: &'static str, args: &[&str]) -> Self {
        self.program = program;
        self.args = args.iter().map(OsString::from).collect();
        self
    }
}

/// Runs `program args` and waits at most `timeout` for it.
///
/// `what` names the operation in the timeout error (`"reg.exe (snapshot)"`), so the
/// log and the UI say which step hung instead of a bare "timed out".
fn spawn_with_deadline(
    program: &str,
    args: &[OsString],
    what: &str,
    timeout: Duration,
) -> Result<CommandOutput> {
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // The engine sits next to a GUI: no console window may flash.
    crate::platform::windows::elevation::hide_console(&mut command);

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to launch {program} ({what})"))?;

    let stdout = child.stdout.take().map(read_in_background);
    let stderr = child.stderr.take().map(read_in_background);

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().with_context(|| format!("waiting for {program}"))? {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!(
                        "{what} did not finish within {}s — the tool was stopped so it could \
                         not block the engine",
                        timeout.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };

    let text = format!(
        "{}{}",
        stdout.map(join_reader).unwrap_or_default(),
        stderr.map(join_reader).unwrap_or_default()
    );
    Ok(CommandOutput {
        success: status.success(),
        text,
    })
}

type Reader = std::thread::JoinHandle<String>;

fn read_in_background<R: Read + Send + 'static>(mut stream: R) -> Reader {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stream.read_to_end(&mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    })
}

fn join_reader(reader: Reader) -> String {
    reader.join().unwrap_or_default()
}

/// Proves one call site's deadline: runs *its* call against a program that never
/// returns and asserts that the deadline fires, that the error names the call,
/// and that it fires promptly.
///
/// Shared by the per-call-site tests in `crate::tests`, so each one is a single
/// line and they cannot drift apart in what they check.
#[cfg(test)]
pub(crate) fn assert_deadline_is_enforced(call: ToolCall) {
    let what = call.what().to_string();
    let started = Instant::now();
    let err = call
        // ~10 s of pinging, with a 300 ms budget.
        .retarget("cmd", &["/c", "ping", "-n", "10", "127.0.0.1"])
        .with_timeout(Duration::from_millis(300))
        .run()
        .expect_err("a call whose program outlives the deadline must fail");
    let message = format!("{err:#}");
    assert!(
        message.contains(&what),
        "the timeout error must name the call site ({what}): {message}"
    );
    assert!(message.contains("did not finish within"), "{message}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{what}: the deadline was not enforced: {:?}",
        started.elapsed()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(program: &'static str, args: &[&str], what: &'static str, secs: u64) -> ToolCall {
        ToolCall::new(what, program, Duration::from_secs(secs)).args(args)
    }

    #[test]
    fn captures_output_from_a_command_that_finishes() {
        let out = call("cmd", &["/c", "echo hello-deadline"], "the test command", 10)
            .run()
            .expect("a short command finishes");
        assert!(out.success, "{out:?}");
        assert!(out.text.contains("hello-deadline"), "{out:?}");
    }

    #[test]
    fn a_hung_command_is_killed_at_the_deadline() {
        // The helper aims the call at a 10 s ping, so the arguments here do not
        // matter — only the operation's name, which the error must carry.
        assert_deadline_is_enforced(call("cmd", &[], "the hung step", 10));
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_is_collected_whole() {
        // ~200 KiB, comfortably past the 64 KiB pipe buffer: a reader that only
        // looks at the pipes after the child exits would deadlock here.
        let out = call(
            "cmd",
            &[
                "/c",
                "for /l %i in (1,1,5000) do @echo 0123456789012345678901234567890123456789",
            ],
            "the chatty step",
            30,
        )
        .run()
        .expect("the command finishes");
        assert!(
            out.success,
            "{:?}",
            out.text.chars().take(200).collect::<String>()
        );
        assert!(
            out.text.len() > 150_000,
            "expected the whole output, got {} byte(s)",
            out.text.len()
        );
    }

    /// The gate that keeps this module the only spawn path: a new
    /// `Command::new` anywhere else in `src/` fails the suite unless it is one
    /// of the documented fire-and-forget launches or an async call with its own
    /// `tokio::time::timeout`.
    #[test]
    fn external_commands_only_run_through_tool_call() {
        /// Files allowed to start a process that nothing waits on — the only
        /// kind of spawn that cannot hold a request — and why.
        const FIRE_AND_FORGET: &[(&str, &str)] = &[
            (
                "src/update.rs",
                "relaunches the UI after an update; the handle is dropped",
            ),
            (
                "src/notify/toast.rs",
                "opens a link from a card action; the handle is dropped",
            ),
        ];
        /// Files allowed to spawn asynchronously, provided the future carries
        /// its own deadline.
        const ASYNC_SITES: &[(&str, &str)] = &[(
            "src/dispatcher.rs",
            "defender.scan.quick (a real Defender scan runs for minutes by design) \
             wrapped in tokio::time::timeout",
        )];

        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        collect_rs_files(&manifest.join("src"), &mut files);
        assert!(
            files.len() > 20,
            "the scan did not find the source tree ({})",
            files.len()
        );

        let mut offenders = Vec::new();
        for file in &files {
            let rel = file
                .strip_prefix(manifest)
                .unwrap_or(file)
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(file).unwrap_or_default();
            let fire_and_forget = FIRE_AND_FORGET.iter().any(|(f, _)| *f == rel);
            for (index, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue; // prose, not a spawn
                }
                if !line.contains("Command::new(") {
                    continue;
                }
                if fire_and_forget {
                    // The file may only start a process it never waits on: the
                    // exemption is the launch itself, not the whole module.
                    if line.contains(".spawn()") {
                        continue;
                    }
                    offenders.push(format!(
                        "{rel}:{} launches a process in an allow-listed file but does not \
                         drop the handle (.spawn()): {}",
                        index + 1,
                        trimmed
                    ));
                    continue;
                }
                if line.contains("tokio::process::Command::new(") {
                    if rel == "src/platform/windows/process.rs" {
                        continue; // this scan's own source, not a spawn
                    }
                    if !ASYNC_SITES.iter().any(|(f, _)| *f == rel) {
                        offenders.push(format!("{rel}:{} async spawn is not allow-listed", index + 1));
                    } else if !source.contains("tokio::time::timeout(") {
                        offenders.push(format!(
                            "{rel}:{} async spawn has no tokio::time::timeout",
                            index + 1
                        ));
                    }
                    continue;
                }
                if rel != "src/platform/windows/process.rs" {
                    offenders.push(format!(
                        "{rel}:{} spawns a process outside process::ToolCall: {}",
                        index + 1,
                        trimmed
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "every external tool must run through process::ToolCall (deadline + named \
             operation), or be one of the documented exceptions:\n{}",
            offenders.join("\n")
        );

        // The allowlist must not rot: those files exist, and a fire-and-forget
        // launch must never be waited on.
        for (rel, why) in FIRE_AND_FORGET.iter().chain(ASYNC_SITES) {
            let path = manifest.join(rel);
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("the allowlist names {rel} ({why}): {e}"));
            if FIRE_AND_FORGET.iter().any(|(f, _)| f == rel) {
                assert!(
                    !source.contains(".output()"),
                    "{rel} is allow-listed as fire-and-forget ({why}) but waits on the child"
                );
                assert!(
                    source.contains(".spawn()"),
                    "{rel} is allow-listed as fire-and-forget ({why}) but launches nothing"
                );
            }
        }
    }

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                out.push(path);
            }
        }
    }
}
