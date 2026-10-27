//! Quarantine: AES-256-GCM encrypted blobs under %PROGRAMDATA%\MICS\Quarantine.
//! The master key lives in a sidecar file encrypted with DPAPI (machine scope),
//! per the security notes — never plaintext.
#![allow(deprecated)]

use getrandom::fill as getrandom_fill;

fn rand_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom_fill(buf).map_err(|e| anyhow::anyhow!("rng failed: {e}"))
}
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::Digest;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::storage::sqlite::Storage;

const MAGIC: &[u8; 4] = b"MQ1 ";

#[derive(Debug, Serialize)]
pub struct QuarantineEntry {
    pub blob_id: String,
    pub original_path: String,
    pub reason: String,
    pub quarantined_at: i64,
    pub size: u64,
    pub restored: bool,
}

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    pub fn new() -> Result<Self> {
        let path = std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("MICS").join("Quarantine"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\Quarantine"));
        fs::create_dir_all(&path).context("create quarantine dir")?;
        Ok(Self { quarantine_dir: path })
    }

    /// Loads (or creates) the AES-256 master key, DPAPI-protected on disk.
    fn get_encryption_key(&self) -> Result<Vec<u8>> {
        let key_file = self.quarantine_dir.join("master.key");
        if key_file.exists() {
            let protected = fs::read(&key_file).context("read master.key")?;
            let key = windows_dpapi::decrypt_data(
                &protected,
                windows_dpapi::Scope::Machine,
                None,
            )
            .map_err(|e| anyhow::anyhow!("DPAPI decrypt failed: {e}"))?;
            return Ok(key);
        }
        let mut key = vec![0u8; 32];
        rand_bytes(&mut key)?;
        let protected = windows_dpapi::encrypt_data(
            &key,
            windows_dpapi::Scope::Machine,
            None,
        )
        .map_err(|e| anyhow::anyhow!("DPAPI protect failed: {e}"))?;
        fs::write(&key_file, protected).context("write master.key")?;
        Ok(key)
    }

    pub async fn quarantine_file(&self, path: &Path, reason: &str) -> Result<PathBuf> {
        info!("Quarantining {path:?} ({reason})");
        let original = path.to_path_buf();
        let data = tokio::fs::read(&original)
            .await
            .with_context(|| format!("read {}", original.display()))?;
        let digest = sha2::Sha256::digest(&data);
        let blob_id = hex::encode(digest);

        let key = self.get_encryption_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        rand_bytes(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;

        let mut blob = Vec::with_capacity(4 + 12 + ciphertext.len() + 2);
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        // Original-path trailer: [ciphertext][path bytes][u16 path length LE]
        // so restore finds the length at the very end of the blob.
        let orig_str = original.to_string_lossy().into_owned();
        let orig = orig_str.as_bytes();
        blob.extend_from_slice(orig);
        blob.extend_from_slice(&(orig.len() as u16).to_le_bytes());

        let dest = self.quarantine_dir.join(&blob_id);
        tokio::fs::write(&dest, &blob).await.context("write blob")?;

        // Only remove the original after the encrypted copy is durable.
        tokio::fs::remove_file(&original)
            .await
            .with_context(|| format!("remove original {}", original.display()))?;

        let storage = Storage::open()?;
        storage.record_quarantine(
            &blob_id,
            &original.to_string_lossy(),
            reason,
            data.len() as u64,
        )?;
        Ok(dest)
    }

    pub async fn restore_file(&self, blob_id: &str) -> Result<String> {
        let storage = Storage::open()?;
        let blob_path = self.quarantine_dir.join(blob_id);
        let blob = tokio::fs::read(&blob_path).await.context("read blob")?;
        if blob.len() < 4 + 12 + 2 || &blob[..4] != MAGIC {
            anyhow::bail!("invalid quarantine blob");
        }
        let nonce = Nonce::from_slice(&blob[4..16]);
        let tail = &blob[16..];

        // Source of truth for the original path: the DB record (verified);
        // fall back to the blob trailer for DB-less restores.
        let orig_path = match storage.get_quarantine_entry(blob_id)? {
            Some((path, _reason)) => path,
            None => {
                let orig_len =
                    u16::from_le_bytes([tail[tail.len() - 2], tail[tail.len() - 1]]) as usize;
                String::from_utf8_lossy(&tail[tail.len() - 2 - orig_len..tail.len() - 2])
                    .to_string()
            }
        };
        let path_bytes = orig_path.as_bytes();
        let ciphertext = &tail[..tail.len() - 2 - path_bytes.len()];

        let key = self.get_encryption_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let plain = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decrypt failed: {e}"))?;

        let target = PathBuf::from(&orig_path);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        tokio::fs::write(&target, &plain)
            .await
            .with_context(|| format!("restore to {orig_path}"))?;
        tokio::fs::remove_file(&blob_path).await.ok();
        storage.mark_restored(blob_id)?;
        info!("Restored {blob_id} -> {orig_path}");
        Ok(orig_path)
    }

    pub async fn delete_blob(&self, blob_id: &str) -> Result<()> {
        let blob_path = self.quarantine_dir.join(blob_id);
        tokio::fs::remove_file(&blob_path).await.ok();
        Storage::open()?.mark_deleted(blob_id)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        Storage::open()?.list_quarantine()
    }
}
