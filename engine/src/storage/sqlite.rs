use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;

/// Local intelligence cache (section 6 of the brief). One small wrapper used
/// by every module that persists state — nothing is user-machine specific.
pub struct Storage {
    conn: Mutex<Connection>,
}

#[allow(dead_code)]
impl Storage {
    pub fn open() -> Result<Self> {
        let base = std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("MICS"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS"));
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
}

#[derive(Debug, serde::Serialize)]
pub struct CachedCve {
    pub cve_id: String,
    pub cvss: f64,
    pub description: String,
    pub published: String,
}
