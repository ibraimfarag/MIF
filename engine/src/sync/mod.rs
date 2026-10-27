use serde::{Deserialize, Serialize};
use anyhow::Result;
use reqwest::Client;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub last_success: String,
    pub version: String,
    pub next_due: String,
}

pub struct SyncManager {
    client: Client,
    storage_path: PathBuf,
}

impl SyncManager {
    pub fn new() -> Self {
        let storage_path = std::env::var("PROGRAMDATA")
            .map(|p| PathBuf::from(p).join("MICS").join("sync"))
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\MICS\sync"));
        
        Self {
            client: Client::new(),
            storage_path,
        }
    }

    pub async fn sync_now(&self) -> Result<String> {
        info!("Starting intelligence sync...");
        
        // Ensure directory exists
        fs::create_dir_all(&self.storage_path).await?;

        // Simulated sync sequence:
        // 1. Fetch IOC Hashes -> 2. IOC Domains -> 3. YARA Rules
        
        // Simulation of a successful sync
        let update_info = "Synced: 1200 hashes, 450 domains, 12 YARA rules. Version: 2026.10.27.01";
        
        // Save state to local file
        let state = SyncState {
            last_success: chrono::Utc::now().to_rfc3339(),
            version: "2026.10.27.01".to_string(),
            next_due: "2026-10-28T00:00:00Z".to_string(),
        };
        
        let state_json = serde_json::to_string_pretty(&state)?;
        fs::write(self.storage_path.join("state.json"), state_json).await?;

        Ok(update_info.to_string())
    }

    pub async fn get_status(&self) -> Result<SyncState> {
        let state_path = self.storage_path.join("state.json");
        if !state_path.exists() {
            return Err(anyhow::anyhow!("No sync state found. Run sync first."));
        }
        
        let content = fs::read_to_string(state_path).await?;
        let state: SyncState = serde_json::from_str(&content)?;
        Ok(state)
    }
}
