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
