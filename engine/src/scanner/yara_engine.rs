use yara_x::{Compiler, Rules};
use anyhow::{Result, Context};
use std::path::Path;
use std::fs;

pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    pub fn new(rules_source: &str) -> Result<Self> {
        let compiler = Compiler::new();
        let rules = compiler.compile(rules_source).context("Failed to compile YARA rules")?;
        Ok(Self { rules })
    }

    pub fn scan_file(&self, path: &Path) -> Result<Vec<String>> {
        let data = fs::read(path).context("Failed to read file for YARA scan")?;
        let matches = self.rules.scan_all(&data).context("YARA scan failed")?;
        
        Ok(matches.into_iter().map(|m| m.identifier().to_string()).collect())
    }
}
