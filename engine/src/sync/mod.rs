use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use reqwest::Client;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub last_success: String,
    pub version: String,
    pub next_due: String,
}

pub struct SyncManager {
    client: Client,
    state_file: PathBuf,
}

impl SyncManager {
    pub fn new() -> Result<Self> {
        let state_file = std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("MICS").join("sync_state.json"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\sync_state.json"));
        
        Ok(Self {
            client: Client::new(),
            state_file,
        })
    }

    pub async fn sync_now(&self) -> Result<String> {
        info!("Starting intelligence synchronization...");
        
        // 1. Check connectivity
        if !self.check_connectivity().await {
            return Err(anyhow::anyhow!("No internet connection. Operating in offline mode."));
        }

        // 2. Sync sequence: IOCs -> YARA Rules -> GeoIP -> CVEs
        self.sync_ioc_hashes().await?;
        self.sync_yara_rules().await?;
        
        self.update_sync_state().await?;
        
        Ok("Synchronization completed successfully".to_string())
    }

    async fn check_connectivity(&self) -> bool {
        // Simple probe to a reliable DNS or API
        reqwest::get("https://1.1.1.1").await.is_ok()
    }

    async fn sync_ioc_hashes(&self) -> Result<()> {
        info!("Syncing IOC hashes...");
        // Simulated API call to get latest hashes
        Ok(())
    }

    async fn sync_yara_rules(&self) -> Result<()> {
        info!("Syncing YARA rules...");
        // Simulated download of rules from GitHub
        Ok(())
    }

    async fn update_sync_state(&self) -> Result<()> {
        let state = SyncState {
            last_success: chrono::Utc::now().to_rfc3339(),
            version: "1.0.0".to_string(),
            next_due: chrono::Utc::now().to_rfc3339(), // simplified
        };
        
        let json = serde_json::to_string_pretty(&state)?;
        fs::write(&self.state_file, json).await.context("Failed to write sync state")?;
        Ok(())
    }

    pub async fn get_status(&self) -> Result<SyncState> {
        let content = fs::read_to_string(&self.state_file).await.context("No sync state found")?;
        let state: SyncState = serde_json::from_str(&content)?;
        Ok(state)
    }
}
