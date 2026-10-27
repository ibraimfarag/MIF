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
}

#[derive(Debug, serde::Serialize)]
pub struct CachedCve {
    pub cve_id: String,
    pub cvss: f64,
    pub description: String,
    pub published: String,
}
