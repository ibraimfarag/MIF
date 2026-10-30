//! Running an external Windows tool with a deadline.
//!
//! Every command the engine spawns is someone else's code: `netsh` talking to a
//! firewall service that is restarting, PowerShell waiting on a prompt nobody
//! answers, a scanner that never returns. Without a deadline the caller's thread
//! waits forever and the UI sits on a spinner with no way out.
//!
//! Two things this module gets right that a naive `output()` does not:
//!
//! 1. **A deadline.** The child is killed and the call fails with a message that
//!    names the operation, instead of blocking a request thread.
//! 2. **Draining while waiting.** `netsh advfirewall show rule verbose` prints far
//!    more than a pipe buffer (64 KiB). Polling `try_wait` without reading the
//!    pipes makes the child block on write and never exit, so a "timeout" would
//!    fire on a process that was about to finish. The readers here run on their
//!    own threads and collect everything.

use anyhow::{Context, Result};
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

/// Runs `program args` and waits at most `timeout` for it.
///
/// `what` names the operation in the timeout error (`"netsh (firewall)"`), so the
/// log and the UI say which step hung instead of a bare "timed out".
pub fn run_with_deadline(
    program: &str,
    args: &[&str],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_from_a_command_that_finishes() {
        let out = run_with_deadline(
            "cmd",
            &["/c", "echo hello-deadline"],
            "the test command",
            Duration::from_secs(10),
        )
        .expect("a short command finishes");
        assert!(out.success, "{out:?}");
        assert!(out.text.contains("hello-deadline"), "{out:?}");
    }

    #[test]
    fn a_hung_command_is_killed_at_the_deadline() {
        let started = Instant::now();
        // ~10 s of pinging, with a 300 ms budget.
        let err = run_with_deadline(
            "cmd",
            &["/c", "ping", "-n", "10", "127.0.0.1"],
            "the hung step",
            Duration::from_millis(300),
        )
        .expect_err("a command that outlives the deadline must fail");
        let message = format!("{err:#}");
        assert!(message.contains("the hung step"), "{message}");
        assert!(message.contains("did not finish within"), "{message}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline was not enforced: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_is_collected_whole() {
        // ~200 KiB, comfortably past the 64 KiB pipe buffer: a reader that only
        // looks at the pipes after the child exits would deadlock here.
        let out = run_with_deadline(
            "cmd",
            &[
                "/c",
                "for /l %i in (1,1,5000) do @echo 0123456789012345678901234567890123456789",
            ],
            "the chatty step",
            Duration::from_secs(30),
        )
        .expect("the command finishes");
        assert!(out.success, "{:?}", out.text.chars().take(200).collect::<String>());
        assert!(
            out.text.len() > 150_000,
            "expected the whole output, got {} byte(s)",
            out.text.len()
        );
    }
}