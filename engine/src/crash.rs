//! Crash reporting, first half: detect it, name it, write it down (ز2).
//!
//! Nothing in this module sends anything anywhere. One JSON bundle and one
//! readable text file per distinct failure are written under
//! `<data dir>\crashes\`, and the UI reads them over the pipe
//! (`crash.list` / `crash.get` / `crash.delete`). Delivery off the machine is a
//! separate step and needs **D-023** (`AGENTS.md` rule 8), so there is no URL,
//! no socket and no HTTP client in this file on purpose.
//!
//! What is detected here:
//!
//! * **a panic** - through the hook installed by [`install_panic_hook`]. The
//!   shipped engine is built with `panic = "abort"` (ج1/D-021), and the hook
//!   still runs before the process dies, so the report is written first.
//! * **a run that never said goodbye** - [`begin_session`] writes a marker when
//!   the engine starts and [`end_session`] closes it on the way out. Finding an
//!   unclosed marker at startup means the previous engine was killed, lost
//!   power, or died without a panic.
//!
//! A **hang** is the third case and it is deliberately not here: a process that
//! is hung cannot report its own hang. The UI decides that from a `ping` it
//! never got an answer to, and files the report through a `crash.note`-style
//! method that ships with that detector - so nothing here names a kind that
//! cannot be produced yet.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A panic that reached the hook.
pub const KIND_PANIC: &str = "panic";
/// The previous run ended without closing its session marker.
pub const KIND_UNCLEAN_EXIT: &str = "unclean-exit";

/// How many log lines travel with a report. Enough to see what was happening,
/// small enough to paste into a message.
const LOG_TAIL_LINES: usize = 60;
/// How much of the log file to read at most when taking that tail.
const LOG_TAIL_BYTES: usize = 64 * 1024;

// ------------------------------------------------------------------ layout

/// Where the session marker and the reports live. Resolved once per process,
/// like the settings data dir it comes from (`MICS_DATA_DIR` is the test hook).
fn root() -> PathBuf {
    crate::settings::Settings::base_dir()
}

fn marker_path(root: &Path) -> PathBuf {
    root.join("session.json")
}

fn reports_dir(root: &Path) -> PathBuf {
    root.join("crashes")
}

/// The directory reports are written to. The UI never needs it (it uses the
/// pipe), but support does: "open this folder and send me the file".
pub fn reports_dir_path() -> PathBuf {
    reports_dir(&root())
}

/// A report file, or `None` for an id that is not one of ours.
///
/// The id comes from a pipe client, so it is checked character by character: a
/// `bug_id` of `..\..\settings.json` must not be able to read or delete
/// anything outside the reports directory.
pub fn report_path(root: &Path, bug_id: &str) -> Option<PathBuf> {
    valid_bug_id(bug_id).then(|| reports_dir(root).join(format!("{bug_id}.json")))
}

/// `MICS-<yyyymmdd>-<6 hex>`, nothing else. See [`bug_id_for`].
pub fn valid_bug_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("MICS-") else {
        return false;
    };
    let (day, hash) = match rest.split_once('-') {
        Some(parts) => parts,
        None => return false,
    };
    day.len() == 8
        && day.bytes().all(|b| b.is_ascii_digit())
        && hash.len() == 6
        && hash.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `MICS-<day>-<hash>`: the hash is over the *failure*, not over the moment it
/// happened, so the same crash gets the same id on every machine that runs the
/// same version - which is what makes "send me the bug id" a useful sentence and
/// what lets a repeat be counted instead of filed again.
///
/// The version is part of the hash on purpose: a crash that survives an update
/// is a different report, and mixing builds would hide that.
fn bug_id_for(kind: &str, message: &str, location: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(b"\x1f");
    hasher.update(kind.as_bytes());
    hasher.update(b"\x1f");
    // The message can carry a temp path or a job id; hashing keeps the id stable
    // for the same failure while never putting those in a filename by hand.
    hasher.update(message.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(location.unwrap_or("").as_bytes());
    let digest = hasher.finalize();
    let hash = hex::encode(&digest[..3]);
    format!(
        "MICS-{}-{hash}",
        chrono::Utc::now().format("%Y%m%d")
    )
}

// ------------------------------------------------------------------ bundle

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub bug_id: String,
    /// [`KIND_PANIC`] or [`KIND_UNCLEAN_EXIT`] today; the hang detector adds its own.
    pub kind: String,
    /// First time this failure was seen (RFC 3339, UTC).
    pub created: String,
    /// Last time it was seen - a repeat updates this and bumps `occurrences`.
    pub last_seen: String,
    pub occurrences: u32,
    pub version: String,
    pub message: String,
    /// `file:line` where it happened, when the runtime knows.
    pub location: Option<String>,
    /// The session marker as it was when the report was written.
    pub session: Option<serde_json::Value>,
    /// Tail of the engine log, newest last, with secret-looking values removed.
    pub log_tail: Vec<String>,
}

/// The marker that says "an engine is running, and it is this one".
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Marker {
    pid: u32,
    mode: String,
    started: String,
    version: String,
    /// `None` while running; `clean` or `panic` once it said goodbye.
    #[serde(default)]
    ended: Option<String>,
}

fn read_marker(root: &Path) -> Option<Marker> {
    let text = std::fs::read_to_string(marker_path(root)).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_marker(root: &Path, marker: &Marker) -> std::io::Result<()> {
    let path = marker_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(marker).unwrap_or_default();
    // Write beside the marker and swap it in: a marker that is half written
    // reads as "no previous session", which would hide a real crash.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;
    let _ = std::fs::remove_file(&path);
    match std::fs::rename(&tmp, &path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// ------------------------------------------------------------------ writing

/// Record a failure and return its bug id, or `None` when nothing could be
/// written (a read-only data dir must not turn a report into a second failure).
fn note_in(root: &Path, kind: &str, message: &str, location: Option<&str>) -> Option<String> {
    let bug_id = bug_id_for(kind, message, location);
    let now = timestamp();
    let existing = report_path(root, &bug_id)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str::<Report>(&text).ok());

    let report = Report {
        bug_id: bug_id.clone(),
        kind: kind.to_string(),
        created: existing
            .as_ref()
            .map(|r| r.created.clone())
            .unwrap_or_else(|| now.clone()),
        last_seen: now,
        occurrences: existing.as_ref().map(|r| r.occurrences + 1).unwrap_or(1),
        version: env!("CARGO_PKG_VERSION").to_string(),
        message: message.to_string(),
        location: location.map(str::to_string),
        session: read_marker(root)
            .and_then(|m| serde_json::to_value(m).ok()),
        log_tail: log_tail(root),
    };

    let dir = reports_dir(root);
    std::fs::create_dir_all(&dir).ok()?;
    let json = serde_json::to_string_pretty(&report).ok()?;
    std::fs::write(dir.join(format!("{bug_id}.json")), json).ok()?;
    std::fs::write(dir.join(format!("{bug_id}.txt")), render(&report)).ok()?;
    Some(bug_id)
}

fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The human half: what a user can read and paste into a message.
fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!("MI CS bug report {}\n", report.bug_id));
    out.push_str(&format!("kind      : {}\n", report.kind));
    out.push_str(&format!(
        "when      : {} (first seen){} \n",
        report.created,
        if report.occurrences > 1 {
            format!(", last {} - {} time(s)", report.last_seen, report.occurrences)
        } else {
            String::new()
        }
    ));
    out.push_str(&format!("version   : {}\n", report.version));
    if let Some(location) = &report.location {
        out.push_str(&format!("where     : {location}\n"));
    }
    if let Some(session) = &report.session {
        let pid = session.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let mode = session
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let started = session
            .get("started")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        out.push_str(&format!("session   : {mode} pid {pid}, started {started}\n"));
    }
    out.push_str("\nwhat happened:\n");
    out.push_str(&format!("{}\n", report.message));
    out.push_str(&format!(
        "\nlast {} engine log lines (oldest first):\n",
        report.log_tail.len()
    ));
    for line in &report.log_tail {
        out.push_str(line);
        out.push('\n');
    }
    out
}

// ------------------------------------------------------------------ reading

/// Every report, newest first. `limit` of 0 means "no limit".
pub fn list(limit: usize) -> Vec<serde_json::Value> {
    list_in(&root(), limit)
}

fn list_in(root: &Path, limit: usize) -> Vec<serde_json::Value> {
    let Some(entries) = std::fs::read_dir(reports_dir(root)).ok() else {
        return Vec::new();
    };
    let mut reports: Vec<Report> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|text| serde_json::from_str::<Report>(&text).ok())
        .collect();
    reports.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    if limit > 0 {
        reports.truncate(limit);
    }
    reports
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "bug_id": r.bug_id,
                "kind": r.kind,
                "created": r.created,
                "last_seen": r.last_seen,
                "occurrences": r.occurrences,
                "message": clip(&r.message, 200),
                "location": r.location,
            })
        })
        .collect()
}

/// One report, or `None` for an unknown or malformed id.
pub fn get(bug_id: &str) -> Option<serde_json::Value> {
    get_in(&root(), bug_id)
}

fn get_in(root: &Path, bug_id: &str) -> Option<serde_json::Value> {
    let path = report_path(root, bug_id)?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Report>(&text)
        .ok()
        .and_then(|r| serde_json::to_value(r).ok())
}

/// Remove a report (both halves). `false` for an unknown or malformed id.
pub fn delete(bug_id: &str) -> bool {
    delete_in(&root(), bug_id)
}

fn delete_in(root: &Path, bug_id: &str) -> bool {
    let Some(json) = report_path(root, bug_id) else {
        return false;
    };
    let text = report_path(root, bug_id).map(|p| p.with_extension("txt"));
    let removed = std::fs::remove_file(&json).is_ok();
    if let Some(text) = text {
        let _ = std::fs::remove_file(text);
    }
    removed
}

// ------------------------------------------------------------------ session

/// Write the session marker, and file a report if the previous engine never
/// closed its own.
///
/// Only the two long-running modes call this (`serve`, `service`): the CLI
/// one-shots are started and stopped by whoever asked for them, so their
/// disappearance is not news - but a panic in one of them is still reported,
/// because the hook is process-wide.
pub fn begin_session(mode: &str) {
    begin_session_in(&root(), mode);
}

fn begin_session_in(root: &Path, mode: &str) {
    if let Some(previous) = read_marker(root) {
        match previous.ended.as_deref() {
            // The panic hook already wrote a report for this run; filing a
            // second one would double-count the same crash.
            Some("panic") => {}
            Some(_) => {}
            None => {
                let message = format!(
                    "the {} engine (pid {}, started {}) stopped without a clean exit",
                    previous.mode, previous.pid, previous.started
                );
                let _ = note_in(
                    root,
                    KIND_UNCLEAN_EXIT,
                    &message,
                    Some("main.rs:session"),
                );
            }
        }
    }
    let _ = write_marker(
        root,
        &Marker {
            pid: std::process::id(),
            mode: mode.to_string(),
            started: timestamp(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ended: None,
        },
    );
}

/// Close the marker this process wrote. `reason` is `clean` or `panic`.
pub fn end_session(reason: &str) {
    end_session_in(&root(), reason);
}

fn end_session_in(root: &Path, reason: &str) {
    let Some(mut marker) = read_marker(root) else {
        return;
    };
    // Never close a marker that belongs to another process.
    if marker.pid != std::process::id() {
        return;
    }
    marker.ended = Some(reason.to_string());
    let _ = write_marker(root, &marker);
}

/// Report a panic, then let the default hook print it.
///
/// The closure is three lines of glue on purpose: everything that can get the
/// payload wrong is [`panic_payload_message`] and [`record_panic`], which are
/// testable without installing a global hook (a global hook in a test binary
/// would fire on every other test's deliberate panic).
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()));
        let _ = record_panic(&root(), info.payload(), location);
        // Tells the next start that this run is accounted for.
        end_session("panic");
        previous(info);
    }));
}

/// The message a panic payload carries, whatever shape it has.
///
/// `panic!("text")` and `panic!("{}", x)` produce different payload types, and a
/// third one exists for `panic_any`: the report must survive all of them rather
/// than panic a second time inside the handler for the first one.
fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        return (*text).to_string();
    }
    if let Some(text) = payload.downcast_ref::<String>() {
        return text.clone();
    }
    "panic with a payload that is not a string".to_string()
}

fn record_panic(
    root: &Path,
    payload: &(dyn std::any::Any + Send),
    location: Option<String>,
) -> Option<String> {
    note_in(
        root,
        KIND_PANIC,
        &panic_payload_message(payload),
        location.as_deref(),
    )
}

// ------------------------------------------------------------------ helpers

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The newest log file's last [`LOG_TAIL_LINES`] lines, secrets removed.
fn log_tail(root: &Path) -> Vec<String> {
    let logs = root.join("logs");
    let newest = ["engine.log", &format!("engine-{}.log", std::process::id())]
        .iter()
        .map(|name| logs.join(name))
        .filter_map(|path| {
            let meta = std::fs::metadata(&path).ok()?;
            Some((meta.modified().ok()?, path))
        })
        .max_by_key(|(modified, _)| *modified);
    let Some((_, path)) = newest else {
        return Vec::new();
    };
    let (bytes, truncated) = read_tail_bytes(&path, LOG_TAIL_BYTES);
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if truncated {
        lines.remove(0);
    }
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    lines[start..]
        .iter()
        .map(|line| redact_secrets(line))
        .collect()
}

/// Last `max` bytes of a file, and whether anything before them was dropped.
fn read_tail_bytes(path: &Path, max: usize) -> (Vec<u8>, bool) {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return (Vec::new(), false);
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let truncated = len > max as u64;
    if truncated {
        let _ = file.seek(SeekFrom::End(-(max as i64)));
    }
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    (buf, truncated)
}

/// Remove the value after any key-looking name.
///
/// The engine does not log settings values today, so this is insurance rather
/// than a fix: a report is meant to be sent to someone else, and the one thing
/// that must never leave the machine by accident is an API key.
fn redact_secrets(line: &str) -> String {
    const NEEDLES: [&str; 5] = ["key", "token", "secret", "password", "authorization"];
    let mut out = String::with_capacity(line.len());
    for token in line.split_inclusive(char::is_whitespace) {
        let trailing: String = token
            .chars()
            .rev()
            .take_while(|c| c.is_whitespace())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let body = token.trim_end();
        let lower = body.to_ascii_lowercase();
        let mut secret = false;
        for needle in NEEDLES {
            let Some(pos) = lower.find(needle) else {
                continue;
            };
            let after = lower[pos + needle.len()..]
                .trim_start_matches(['"', '\'', ' ']);
            if after.starts_with('=') || after.starts_with(':') {
                secret = true;
                break;
            }
        }
        if secret {
            out.push_str(&format!("<redacted>{trailing}"));
        } else {
            out.push_str(token);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own per test: the data dir is resolved once per
    /// process, so the tests never touch the real one and never share.
    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mics-crash-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_bug_id_is_stable_shape_and_only_that_shape_is_accepted() {
        let a = bug_id_for(KIND_PANIC, "index out of bounds", Some("x.rs:1"));
        let b = bug_id_for(KIND_PANIC, "index out of bounds", Some("x.rs:1"));
        let c = bug_id_for(KIND_PANIC, "index out of bounds", Some("x.rs:2"));
        assert_eq!(a, b, "the same failure must get the same id");
        assert_ne!(a, c, "a different place is a different failure");
        assert!(valid_bug_id(&a), "{a} should be a valid id");
        assert!(a.starts_with("MICS-"), "{a}");
        assert_eq!(a.len(), "MICS-20261102-abcdef".len());

        for bad in [
            "",
            "MICS",
            "MICS-",
            "MICS-2026-a1b2c3",
            "MICS-2026110-a1b2c3",
            "MICS-20261102-a1b2c",
            "MICS-20261102-A1B2C3",
            "MICS-20261102-a1b2c3-extra",
            "mics-20261102-a1b2c3",
            "MICS-20261102-../../etc",
            "..\\..\\settings.json",
        ] {
            assert!(!valid_bug_id(bad), "{bad:?} must not be a report id");
        }
    }

    #[test]
    fn a_report_s_path_is_inside_the_reports_directory_or_nowhere() {
        let root = Path::new(r"C:\state");
        let path = report_path(root, "MICS-20261102-a1b2c3").unwrap();
        assert_eq!(
            path,
            PathBuf::from(r"C:\state\crashes\MICS-20261102-a1b2c3.json")
        );
        assert!(report_path(root, r"..\..\settings.json").is_none());
        assert!(report_path(root, "MICS-20261102-a1b2c3/../../x").is_none());
    }

    #[test]
    fn a_report_is_written_as_json_and_as_something_a_human_can_read() {
        let root = temp_root("write");
        let id = note_in(&root, KIND_PANIC, "attempt to subtract with overflow", Some("a.rs:9"))
            .expect("report written");

        let json = std::fs::read_to_string(reports_dir(&root).join(format!("{id}.json")))
            .unwrap();
        let report: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(report.kind, KIND_PANIC);
        assert_eq!(report.occurrences, 1);
        assert_eq!(report.location.as_deref(), Some("a.rs:9"));
        assert_eq!(report.message, "attempt to subtract with overflow");
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));

        let text = std::fs::read_to_string(reports_dir(&root).join(format!("{id}.txt")))
            .unwrap();
        assert!(text.starts_with(&format!("MI CS bug report {id}")), "{text}");
        assert!(text.contains("attempt to subtract with overflow"), "{text}");
        assert!(text.contains("a.rs:9"), "{text}");
    }

    #[test]
    fn the_same_failure_twice_is_one_report_with_a_count() {
        let root = temp_root("dedupe");
        let first = note_in(&root, KIND_PANIC, "boom", Some("a.rs:1")).unwrap();
        let second = note_in(&root, KIND_PANIC, "boom", Some("a.rs:1")).unwrap();
        assert_eq!(first, second);

        let reports = list_in(&root, 0);
        assert_eq!(reports.len(), 1, "a repeat must not file a second report");
        assert_eq!(reports[0]["occurrences"], 2);
        let created = reports[0]["created"].as_str().unwrap().to_string();

        // A third one keeps the first sighting and moves `last_seen`.
        note_in(&root, KIND_PANIC, "boom", Some("a.rs:1")).unwrap();
        let reports = list_in(&root, 0);
        assert_eq!(reports[0]["occurrences"], 3);
        assert_eq!(reports[0]["created"].as_str().unwrap(), created);
    }

    #[test]
    fn reports_are_listed_newest_first_and_can_be_read_and_removed() {
        let root = temp_root("list");
        let a = note_in(&root, KIND_PANIC, "first", Some("a.rs:1")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let b = note_in(&root, KIND_UNCLEAN_EXIT, "second", Some("main.rs:session"))
            .unwrap();
        assert_ne!(a, b);

        let ids: Vec<String> = list_in(&root, 0)
            .iter()
            .map(|r| r["bug_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, vec![b.clone(), a.clone()], "newest first");
        assert_eq!(list_in(&root, 1).len(), 1, "limit is honoured");

        let one = get_in(&root, &a).expect("the report is readable");
        assert_eq!(one["message"], "first");
        assert!(get_in(&root, "MICS-20261102-ffffff").is_none(), "unknown id");
        assert!(get_in(&root, "../session").is_none(), "malformed id");

        assert!(delete_in(&root, &a));
        assert!(get_in(&root, &a).is_none());
        assert!(!reports_dir(&root).join(format!("{a}.txt")).exists());
        assert!(!delete_in(&root, &a), "already gone");
        assert!(!delete_in(&root, "not-an-id"));
        assert_eq!(list_in(&root, 0).len(), 1, "the other report is untouched");
    }

    #[test]
    fn a_session_that_never_closed_is_reported_once_on_the_next_start() {
        let root = temp_root("session");
        begin_session_in(&root, "service");
        let marker: Marker =
            serde_json::from_str(&std::fs::read_to_string(marker_path(&root)).unwrap())
                .unwrap();
        assert_eq!(marker.pid, std::process::id());
        assert_eq!(marker.mode, "service");
        assert!(marker.ended.is_none());
        assert!(list_in(&root, 0).is_empty(), "first start: nothing to report");

        // A clean stop leaves a closed marker, which is not a crash.
        end_session_in(&root, "clean");
        begin_session_in(&root, "service");
        assert!(list_in(&root, 0).is_empty(), "clean exits are not crashes");

        // A panic already filed its own report: do not file a second one.
        end_session_in(&root, "panic");
        begin_session_in(&root, "service");
        assert!(list_in(&root, 0).is_empty(), "panic is reported by the hook");

        // No `ended` at all is the killed/power-loss case.
        std::fs::write(
            marker_path(&root),
            serde_json::to_string(&Marker {
                pid: 4242,
                mode: "service".into(),
                started: "2026-11-01T22:00:00Z".into(),
                version: "0.0.9".into(),
                ended: None,
            })
            .unwrap(),
        )
        .unwrap();
        begin_session_in(&root, "service");
        let reports = list_in(&root, 0);
        assert_eq!(reports.len(), 1, "an unclosed marker is one report");
        assert_eq!(reports[0]["kind"], KIND_UNCLEAN_EXIT);
        let message = reports[0]["message"].as_str().unwrap();
        assert!(message.contains("pid 4242"), "{message}");
        assert!(message.contains("2026-11-01T22:00:00Z"), "{message}");

        // And the report is not filed again on the start after that.
        end_session_in(&root, "clean");
        begin_session_in(&root, "service");
        assert_eq!(list_in(&root, 0).len(), 1);
    }

    #[test]
    fn a_panic_payload_is_read_whatever_shape_it_has() {
        // `panic!("literal")` sends a `&str`, `panic!("{}", x)` a `String`, and
        // `panic_any` anything at all. None of them may make the handler fail.
        let literal: &'static str = "index out of bounds";
        let owned = String::from("assertion failed: left == right");
        assert_eq!(
            panic_payload_message(&*boxed(literal)),
            "index out of bounds"
        );
        assert_eq!(
            panic_payload_message(&*boxed(owned)),
            "assertion failed: left == right"
        );
        assert_eq!(
            panic_payload_message(&*boxed(42_u64)),
            "panic with a payload that is not a string"
        );
    }

    /// A payload in the same shape `PanicHookInfo::payload` hands the hook:
    /// a boxed `Any + Send` holding the value itself.
    fn boxed<T: std::any::Any + Send>(value: T) -> Box<dyn std::any::Any + Send> {
        Box::new(value)
    }

    #[test]
    fn the_panic_path_writes_a_panic_report() {
        let root = temp_root("panic");
        let location = Some("engine/src/thing.rs:42".to_string());
        let literal: &'static str = "attempt to divide by zero";
        let id = record_panic(&root, &*boxed(literal), location)
            .expect("a panic must produce a report");
        let report = get_in(&root, &id).unwrap();
        assert_eq!(report["kind"], KIND_PANIC);
        assert_eq!(report["message"], "attempt to divide by zero");
        assert_eq!(report["location"], "engine/src/thing.rs:42");
        // The same panic twice is one report, which is what the count is for.
        record_panic(
            &root,
            &*boxed(literal),
            Some("engine/src/thing.rs:42".into()),
        )
        .unwrap();
        assert_eq!(get_in(&root, &id).unwrap()["occurrences"], 2);
    }

    #[test]
    fn a_stale_report_directory_is_not_an_error_and_empty_means_empty() {
        let root = temp_root("empty");
        assert!(list_in(&root, 0).is_empty());
        assert!(get_in(&root, "MICS-20261102-a1b2c3").is_none());
        assert!(!delete_in(&root, "MICS-20261102-a1b2c3"));
        // A file that is not a report must not break the listing.
        std::fs::create_dir_all(reports_dir(&root)).unwrap();
        std::fs::write(reports_dir(&root).join("notes.txt"), "hello").unwrap();
        std::fs::write(reports_dir(&root).join("broken.json"), "{not json").unwrap();
        assert!(list_in(&root, 0).is_empty());
    }

    #[test]
    fn secrets_are_taken_out_of_the_log_tail() {
        assert_eq!(
            redact_secrets("ioc feed key=\"abcdef\" loaded"),
            "ioc feed <redacted> loaded"
        );
        assert_eq!(
            redact_secrets("using nvd_api_key=1234567890 for the query"),
            "using <redacted> for the query"
        );
        assert_eq!(
            redact_secrets("Authorization: Bearer abc.def"),
            "<redacted> Bearer abc.def"
        );
        // Ordinary lines keep their words.
        assert_eq!(
            redact_secrets("scan finished: 12 files, 0 findings"),
            "scan finished: 12 files, 0 findings"
        );
        assert_eq!(
            redact_secrets("monkey business"),
            "monkey business",
            "a word containing 'key' but no value after it"
        );
        // The trailing newline survives, or the tail would become one line.
        assert!(redact_secrets("token=abc\n").ends_with('\n'));
        // Non-ASCII text is not cut in the middle of a character.
        assert_eq!(
            redact_secrets("خطأ token=abc في الطلب"),
            "خطأ <redacted> في الطلب"
        );
    }

    #[test]
    fn the_log_tail_shows_the_end_of_the_file_and_says_how_much_it_kept() {
        let root = temp_root("tail");
        let logs = root.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let body = (1..=200)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(logs.join("engine.log"), body).unwrap();

        let tail = log_tail(&root);
        assert_eq!(tail.len(), LOG_TAIL_LINES);
        assert_eq!(tail.last().unwrap(), "line 200");
        assert_eq!(tail.first().unwrap(), "line 141");
    }

    #[test]
    fn a_report_with_no_log_file_and_no_location_still_works() {
        let root = temp_root("nolog");
        assert!(log_tail(&root).is_empty());
        let id = note_in(&root, KIND_UNCLEAN_EXIT, "stopped without a clean exit", None)
            .unwrap();
        let report = get_in(&root, &id).unwrap();
        assert_eq!(report["kind"], KIND_UNCLEAN_EXIT);
        assert_eq!(report["log_tail"].as_array().unwrap().len(), 0);
        assert_eq!(report["location"], serde_json::Value::Null);
    }

    #[test]
    fn a_long_message_is_clipped_in_the_list_but_whole_in_the_report() {
        let root = temp_root("clip");
        let long = "x".repeat(500);
        let id = note_in(&root, KIND_PANIC, &long, None).unwrap();
        let listed = &list_in(&root, 0)[0];
        let clipped = listed["message"].as_str().unwrap();
        assert!(clipped.chars().count() <= 200, "{}", clipped.chars().count());
        assert!(clipped.ends_with('…'));
        let full = get_in(&root, &id).unwrap();
        assert_eq!(full["message"].as_str().unwrap().len(), 500);
    }
}
