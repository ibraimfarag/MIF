use yara_x::Rules;
use anyhow::{Result, Context};
use std::path::Path;
use std::fs;

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    pub fn new(rules_source: &str) -> Result<Self> {
        // Use a simplified approach to avoid API version mismatches
        let rules = Rules::compile(rules_source).context("Failed to compile YARA rules")?;
        Ok(Self { rules })
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<String>> {
        let data = fs::read(path).context("Failed to read file for YARA scan")?;
        let matches = self.rules.scan(&data).context("YARA scan failed")?;
        
        Ok(matches.into_iter().map(|m| m.identifier().to_string()).collect())
    }
}
