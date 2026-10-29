use anyhow::{Context, Result};
use rusqlite::Connection;
use std::sync::Mutex;

/// Local intelligence cache (section 6 of the brief). One small wrapper used
/// by every module that persists state — nothing is user-machine specific.
pub struct Storage {
    conn: Mutex<Connection>,
}

#[allow(dead_code)]
impl Storage {
    pub fn open() -> Result<Self> {
        let base = crate::settings::Settings::base_dir();
        std::fs::create_dir_all(&base).context("create MICS data dir")?;
        let conn = Connection::open(base.join("mics.db"))
            .context("open mics.db")?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                cvss REAL,
                description TEXT,
                matched_software TEXT,
                published TEXT,
                fetched_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS sync_state (
                source TEXT PRIMARY KEY,
                last_success INTEGER,
                version TEXT
             );
             CREATE TABLE IF NOT EXISTS ioc_hashes (
                sha256 TEXT PRIMARY KEY,
                source TEXT,
                added_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS ioc_domains (
                domain TEXT PRIMARY KEY,
                source TEXT,
                category TEXT,
                added_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS quarantine (
                blob_id TEXT PRIMARY KEY,
                original_path TEXT,
                reason TEXT,
                quarantined_at INTEGER,
                size INTEGER,
                restored INTEGER DEFAULT 0,
                deleted INTEGER DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                severity TEXT,
                opened_at INTEGER,
                updated_at INTEGER,
                closed INTEGER DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS incident_events (
                incident_id INTEGER,
                seq INTEGER,
                payload TEXT
             );
             CREATE TABLE IF NOT EXISTS hardening_snapshots (
                action_id TEXT,
                snapshot TEXT,
                taken_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS hardening_state (
                action_id TEXT PRIMARY KEY,
                applied INTEGER
             );
             CREATE TABLE IF NOT EXISTS noise (
                category TEXT PRIMARY KEY,
                dismissals INTEGER DEFAULT 0,
                muted INTEGER DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS sync_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                payload TEXT,
                created_at INTEGER
             );
             -- Durable scan jobs: the queue is persisted so a scan survives an
             -- engine restart and resumes at the exact file it stopped on.
             CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                kind TEXT,
                root TEXT,
                state TEXT,              -- queued | running | done | cancelled | failed | interrupted
                total INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                scanned INTEGER DEFAULT 0,
                skipped INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                error TEXT,
                quarantine INTEGER DEFAULT 0,
                created_at INTEGER,
                updated_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS job_files (
                job_id TEXT,
                seq INTEGER,
                path TEXT,
                score INTEGER,
                PRIMARY KEY (job_id, seq)
             );
             CREATE TABLE IF NOT EXISTS job_findings (
                job_id TEXT,
                seq INTEGER,
                payload TEXT,
                PRIMARY KEY (job_id, seq)
             );",
        )
        .context("init schema")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn cache_cve(
        &self,
        cve_id: &str,
        cvss: f64,
        description: &str,
        matched_software: &str,
        published: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache VALUES (?1,?2,?3,?4,?5,strftime('%s','now'))",
            rusqlite::params![cve_id, cvss, description, matched_software, published],
        )?;
        Ok(())
    }

    /// Cached CVEs matched to a software name (offline view).
    pub fn cached_cves_for(&self, software: &str) -> Result<Vec<CachedCve>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cve_id, cvss, description, published FROM cve_cache
             WHERE matched_software = ?1 ORDER BY cvss DESC",
        )?;
        let rows = stmt.query_map([software], |r| {
            Ok(CachedCve {
                cve_id: r.get(0)?,
                cvss: r.get(1)?,
                description: r.get(2)?,
                published: r.get(3)?,
            })
        })?;
        Ok(rows.flatten().collect())
    }

    pub fn all_cached_cves(&self) -> Result<Vec<(String, String, f64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cve_id, matched_software, cvss FROM cve_cache ORDER BY cvss DESC",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .flatten()
            .collect();
        Ok(rows)
    }

    pub fn set_sync_state(&self, source: &str, version: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sync_state VALUES (?1, strftime('%s','now'), ?2)",
            rusqlite::params![source, version],
        )?;
        Ok(())
    }

    pub fn get_sync_state(&self, source: &str) -> Result<Option<(i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT last_success, version FROM sync_state WHERE source = ?1")?;
        let mut rows = stmt.query([source])?;
        if let Some(r) = rows.next()? {
            return Ok(Some((r.get(0)?, r.get(1)?)));
        }
        Ok(None)
    }

    /// Timestamp of the last successful sync for a source (None = never).
    pub fn sync_last_success(&self, source: &str) -> Result<Option<i64>> {
        let conn = self.conn.lock().unwrap();
        let value: Option<i64> = conn
            .query_row(
                "SELECT last_success FROM sync_state WHERE source = ?1",
                [source],
                |r| r.get(0),
            )
            .ok();
        Ok(value)
    }

    // ---- IOC hashes ----

    pub fn ioc_hash_lookup(&self, sha256: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT source FROM ioc_hashes WHERE sha256 = ?1")?;
        let mut rows = stmt.query([sha256])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn add_ioc_hashes(&self, hashes: &[(String, String)]) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let mut inserted = 0usize;
        for (hash, source) in hashes {
            let n = conn.execute(
                "INSERT OR IGNORE INTO ioc_hashes VALUES (?1, ?2, strftime('%s','now'))",
                rusqlite::params![hash, source],
            )?;
            inserted += n;
        }
        Ok(inserted)
    }

    /// Full IOC hash map for the scan loop (SQLite only on open/close, not per file).
    pub fn dump_ioc_hashes(&self) -> Result<std::collections::HashMap<String, String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT sha256, source FROM ioc_hashes")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .flatten()
            .collect();
        Ok(rows)
    }

    pub fn add_ioc_domain(&self, domain: &str, source: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO ioc_domains VALUES (?1, ?2, 'block', strftime('%s','now'))",
            rusqlite::params![domain, source],
        )?;
        Ok(())
    }

    pub fn ioc_hash_count(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM ioc_hashes", [], |r| r.get(0))?)
    }

    // ---- quarantine ----

    pub fn record_quarantine(
        &self,
        blob_id: &str,
        original_path: &str,
        reason: &str,
        size: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO quarantine VALUES (?1,?2,?3,strftime('%s','now'),?4,0,0)",
            rusqlite::params![blob_id, original_path, reason, size],
        )?;
        Ok(())
    }

    pub fn mark_restored(&self, blob_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE quarantine SET restored = 1 WHERE blob_id = ?1",
            [blob_id],
        )?;
        Ok(())
    }

    pub fn mark_deleted(&self, blob_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE quarantine SET deleted = 1 WHERE blob_id = ?1",
            [blob_id],
        )?;
        Ok(())
    }

    pub fn get_quarantine_entry(&self, blob_id: &str) -> Result<Option<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT original_path, reason FROM quarantine WHERE blob_id = ?1")?;
        let mut rows = stmt.query([blob_id])?;
        Ok(rows
            .next()?
            .map(|r| -> rusqlite::Result<(String, String)> { Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)) })
            .transpose()?)
    }

    pub fn list_quarantine(
        &self,
    ) -> Result<Vec<crate::scanner::quarantine::QuarantineEntry>> {
        use crate::scanner::quarantine::QuarantineEntry;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT blob_id, original_path, reason, quarantined_at, size, restored
             FROM quarantine WHERE deleted = 0 ORDER BY quarantined_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(QuarantineEntry {
                blob_id: r.get(0)?,
                original_path: r.get(1)?,
                reason: r.get(2)?,
                quarantined_at: r.get(3)?,
                size: r.get(4)?,
                restored: r.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.flatten().collect())
    }

    // ---- offline sync queue ----

    pub fn queue_op(&self, kind: &str, payload: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sync_queue (kind, payload, created_at)
             VALUES (?1, ?2, strftime('%s','now'))",
            rusqlite::params![kind, payload],
        )?;
        Ok(())
    }

    pub fn pop_queue_ops(&self, kind: &str, limit: usize) -> Result<Vec<(i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload FROM sync_queue WHERE kind = ?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![kind, limit as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .flatten()
            .collect();
        Ok(rows)
    }

    pub fn remove_queue_op(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sync_queue WHERE id = ?1", [id])?;
        Ok(())
    }

    // ---- incidents ----

    pub fn create_incident(&self, title: &str, severity: &str, at: i64) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO incidents (title, severity, opened_at, updated_at) VALUES (?1,?2,?3,?3)",
            rusqlite::params![title, severity, at],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn append_incident_event(&self, id: i64, ev: &crate::guard::GuardEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let seq: i64 = conn.query_row(
            "SELECT COALESCE(MAX(seq),0)+1 FROM incident_events WHERE incident_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        conn.execute(
            "INSERT INTO incident_events VALUES (?1,?2,?3)",
            rusqlite::params![id, seq, serde_json::to_string(ev)?],
        )?;
        Ok(())
    }

    pub fn get_incident(&self, id: i64) -> Result<Option<crate::smart::correlator::Incident>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT incident_id, title, severity, opened_at, updated_at, closed
             FROM incidents WHERE incident_id = ?1",
        )?;
        let mut rows = stmt.query([id])?;
        let Some(row) = rows.next()? else { return Ok(None) };
        let mut inc = crate::smart::correlator::Incident {
            incident_id: row.get(0)?,
            title: row.get(1)?,
            severity: row.get(2)?,
            opened_at: row.get(3)?,
            updated_at: row.get(4)?,
            closed: row.get::<_, i64>(5)? != 0,
            timeline: vec![],
        };
        drop(rows);
        drop(stmt);
        let mut stmt = conn.prepare(
            "SELECT payload FROM incident_events WHERE incident_id = ?1 ORDER BY seq",
        )?;
        let payload_rows = stmt.query_map([id], |r| r.get::<_, String>(0))?;
        for p in payload_rows.flatten() {
            if let Ok(ev) = serde_json::from_str(&p) {
                inc.timeline.push(ev);
            }
        }
        Ok(Some(inc))
    }

    pub fn update_incident(&self, inc: &crate::smart::correlator::Incident) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let seq: i64 = conn.query_row(
            "SELECT COALESCE(MAX(seq),0) FROM incident_events WHERE incident_id = ?1",
            [inc.incident_id],
            |r| r.get(0),
        )?;
        if let Some(ev) = inc.timeline.last() {
            conn.execute(
                "INSERT OR REPLACE INTO incident_events VALUES (?1,?2,?3)",
                rusqlite::params![inc.incident_id, seq, serde_json::to_string(ev)?],
            )?;
        }
        conn.execute(
            "UPDATE incidents SET severity=?2, updated_at=?3 WHERE incident_id=?1",
            rusqlite::params![inc.incident_id, inc.severity, inc.updated_at],
        )?;
        Ok(())
    }

    pub fn list_incidents(&self, limit: u32) -> Result<Vec<crate::smart::correlator::Incident>> {
        // Open one storage per id — get_incident takes its own lock.
        let ids: Vec<i64> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT incident_id FROM incidents ORDER BY updated_at DESC LIMIT ?1",
            )?;
            stmt.query_map([limit], |r| r.get(0))?
                .flatten()
                .collect()
        };
        let storage = Storage::open()?;
        Ok(ids
            .iter()
            .filter_map(|id| storage.get_incident(*id).ok().flatten())
            .collect())
    }

    pub fn close_incident(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE incidents SET closed=1 WHERE incident_id=?1", [id])?;
        Ok(())
    }

    // ---- hardening ----

    pub fn save_hardening_snapshot(&self, action_id: &str, snapshot: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO hardening_snapshots VALUES (?1,?2,strftime('%s','now'))",
            rusqlite::params![action_id, snapshot],
        )?;
        Ok(())
    }

    pub fn mark_hardening_applied(&self, action_id: &str, applied: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO hardening_state VALUES (?1,?2)
             ON CONFLICT(action_id) DO UPDATE SET applied = ?2",
            rusqlite::params![action_id, applied as i64],
        )?;
        Ok(())
    }

    pub fn latest_hardening_snapshot(&self, action_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let v: Option<String> = conn
            .query_row(
                "SELECT snapshot FROM hardening_snapshots WHERE action_id=?1
                 ORDER BY taken_at DESC LIMIT 1",
                [action_id],
                |r| r.get(0),
            )
            .ok();
        Ok(v)
    }

    pub fn list_hardening_snapshots(&self) -> Result<Vec<(String, String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT action_id, snapshot, taken_at FROM hardening_snapshots
             ORDER BY taken_at DESC LIMIT 50",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?
            .flatten()
            .collect();
        Ok(rows)
    }

    // ---- noise learner ----

    pub fn bump_dismissal(&self, category: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO noise (category, dismissals, muted) VALUES (?1,1,0)
             ON CONFLICT(category) DO UPDATE SET dismissals = dismissals + 1",
            [category],
        )?;
        Ok(())
    }

    pub fn get_dismissal(&self, category: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let n: Option<i64> = conn
            .query_row(
                "SELECT dismissals FROM noise WHERE category=?1",
                [category],
                |r| r.get(0),
            )
            .ok();
        Ok(n.unwrap_or(0))
    }

    pub fn set_muted(&self, category: &str, muted: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO noise (category, dismissals, muted) VALUES (?1,0,?2)
             ON CONFLICT(category) DO UPDATE SET muted = ?2",
            rusqlite::params![category, muted as i64],
        )?;
        Ok(())
    }

    pub fn is_muted(&self, category: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let m: Option<i64> = conn
            .query_row("SELECT muted FROM noise WHERE category=?1", [category], |r| r.get(0))
            .ok();
        Ok(m.unwrap_or(0) != 0)
    }

    pub fn all_dismissals(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT category, dismissals FROM noise WHERE dismissals > 0 ORDER BY dismissals DESC",
        )?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .flatten()
            .collect();
        Ok(rows)
    }

    pub fn queue_len(&self, kind: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM sync_queue WHERE kind = ?1",
            [kind],
            |r| r.get(0),
        )?)
    }

    // ---- scan jobs (resumable) ----

    pub fn create_job(&self, job_id: &str, kind: &str, root: &str, quarantine: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO jobs
             (job_id, kind, root, state, total, processed, scanned, skipped,
              findings_count, error, quarantine, created_at, updated_at)
             VALUES (?1,?2,?3,'queued',0,0,0,0,0,NULL,?4,
                     strftime('%s','now'),strftime('%s','now'))",
            rusqlite::params![job_id, kind, root, quarantine as i64],
        )?;
        Ok(())
    }

    pub fn set_job_state(&self, job_id: &str, state: &str, error: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET state=?2, error=?3, updated_at=strftime('%s','now')
             WHERE job_id=?1",
            rusqlite::params![job_id, state, error],
        )?;
        Ok(())
    }

    /// Stores one chunk of the enumerated, triage-ordered queue.
    pub fn set_job_files(&self, job_id: &str, files: &[(i64, String, i64)]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO job_files (job_id, seq, path, score)
                 VALUES (?1,?2,?3,?4)",
            )?;
            for (seq, path, score) in files {
                stmt.execute(rusqlite::params![job_id, seq, path, score])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_job_total(&self, job_id: &str, total: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs SET total=?2, updated_at=strftime('%s','now') WHERE job_id=?1",
            rusqlite::params![job_id, total],
        )?;
        Ok(())
    }

    pub fn job_files_after(
        &self,
        job_id: &str,
        after_seq: i64,
        limit: usize,
    ) -> Result<Vec<(i64, String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, path, score FROM job_files
             WHERE job_id=?1 AND seq>?2 ORDER BY seq ASC LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![job_id, after_seq, limit as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?
            .flatten()
            .collect();
        Ok(rows)
    }

    pub fn set_job_progress(
        &self,
        job_id: &str,
        processed: i64,
        scanned: i64,
        skipped: i64,
        findings_count: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE jobs
             SET processed=?2, scanned=?3, skipped=?4, findings_count=?5,
                 updated_at=strftime('%s','now')
             WHERE job_id=?1",
            rusqlite::params![job_id, processed, scanned, skipped, findings_count],
        )?;
        Ok(())
    }

    pub fn add_job_finding(&self, job_id: &str, seq: i64, payload: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO job_findings (job_id, seq, payload)
             VALUES (?1,?2,?3)",
            rusqlite::params![job_id, seq, payload],
        )?;
        Ok(())
    }

    pub fn job_findings(&self, job_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT payload FROM job_findings WHERE job_id=?1 ORDER BY seq ASC",
        )?;
        let rows = stmt
            .query_map([job_id], |r| r.get::<_, String>(0))?
            .flatten()
            .collect();
        Ok(rows)
    }

    pub fn get_job(&self, job_id: &str) -> Result<Option<JobRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT job_id, kind, root, state, total, processed, scanned, skipped,
                    findings_count, error, quarantine, created_at, updated_at
             FROM jobs WHERE job_id=?1",
        )?;
        let row = stmt
            .query_row([job_id], map_job)
            .ok();
        Ok(row)
    }

    pub fn list_jobs(&self, limit: u32) -> Result<Vec<JobRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT job_id, kind, root, state, total, processed, scanned, skipped,
                    findings_count, error, quarantine, created_at, updated_at
             FROM jobs ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], map_job)?.flatten().collect();
        Ok(rows)
    }

    /// Jobs that were in flight when the engine stopped (or that never started).
    pub fn resumable_jobs(&self) -> Result<Vec<JobRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT job_id, kind, root, state, total, processed, scanned, skipped,
                    findings_count, error, quarantine, created_at, updated_at
             FROM jobs WHERE state IN ('queued','running','interrupted')
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], map_job)?.flatten().collect();
        Ok(rows)
    }

    /// Marks every unfinished job as interrupted (called at engine startup).
    pub fn mark_jobs_interrupted(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE jobs SET state='interrupted', updated_at=strftime('%s','now')
             WHERE state IN ('queued','running')",
            [],
        )?;
        Ok(n)
    }
}

fn map_job(r: &rusqlite::Row<'_>) -> rusqlite::Result<JobRow> {
    Ok(JobRow {
        job_id: r.get(0)?,
        kind: r.get(1)?,
        root: r.get(2)?,
        state: r.get(3)?,
        total: r.get(4)?,
        processed: r.get(5)?,
        scanned: r.get(6)?,
        skipped: r.get(7)?,
        findings_count: r.get(8)?,
        error: r.get(9)?,
        quarantine: r.get::<_, i64>(10)? != 0,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JobRow {
    pub job_id: String,
    pub kind: String,
    pub root: String,
    pub state: String,
    pub total: i64,
    pub processed: i64,
    pub scanned: i64,
    pub skipped: i64,
    pub findings_count: i64,
    pub error: Option<String>,
    #[serde(skip)]
    pub quarantine: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct CachedCve {
    pub cve_id: String,
    pub cvss: f64,
    pub description: String,
    pub published: String,
}
