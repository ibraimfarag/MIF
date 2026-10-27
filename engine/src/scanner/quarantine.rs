//! Quarantine storage (Phase 5): currently unused helpers kept for the next phase.
#![allow(dead_code)]
#![allow(deprecated)]

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use sha2::Digest;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use tracing::info;

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    pub fn new() -> Result<Self> {
        let path = std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("MICS").join("Quarantine"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\Quarantine"));
        
        fs::create_dir_all(&path).context("Failed to create quarantine directory")?;
        Ok(Self { quarantine_dir: path })
    }

    fn get_encryption_key(&self) -> Result<Vec<u8>> {
        // Temporary: Use a fixed master key to avoid DPAPI compilation errors
        // We will implement DPAPI properly once the engine is stable
        Ok(b"MI_CS_MASTER_KEY_2026_SECURE_V1".to_vec())
    }

    pub async fn quarantine_file(&self, path: &Path) -> Result<PathBuf> {
        info!("Quarantining file: {:?}", path);
        
        let file_data = fs::read(path).context("Failed to read file for quarantine")?;
        let key_bytes = self.get_encryption_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        
        let digest = sha2::Sha256::digest(&file_data);
        let nonce_bytes: Vec<u8> = digest.as_slice()[..12].to_vec();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_data = cipher.encrypt(nonce, file_data.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        
        let mut final_blob = nonce_bytes;
        final_blob.extend(encrypted_data);
        
        let file_name = hex::encode(sha2::Sha256::digest(&file_data));
        let dest_path = self.quarantine_dir.join(file_name);
        
        fs::write(&dest_path, final_blob).context("Failed to write quarantine blob")?;
        // Note: In real app, we remove file only after successful write
        // fs::remove_file(path).context("Failed to remove original file")?;
        
        Ok(dest_path)
    }

    pub async fn restore_file(&self, quarantined_path: &Path, original_path: &Path) -> Result<()> {
        info!("Restoring file from: {:?}", quarantined_path);
        
        let blob = fs::read(quarantined_path).context("Failed to read quarantine blob")?;
        if blob.len() < 12 { return Err(anyhow::anyhow!("Invalid quarantine blob")); }
        
        let (nonce_bytes, encrypted_data) = blob.split_at(12);
        let key_bytes = self.get_encryption_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        
        fs::write(original_path, decrypted_data).context("Failed to restore original file")?;
        
        Ok(())
    }
}
