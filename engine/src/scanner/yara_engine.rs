use yara_x::{Compiler, Scanner};
use anyhow::{Result, Context};
use std::path::Path;
use std::fs;

pub struct YaraEngine {
    rules: yara_x::Rules,
}

impl YaraEngine {
    pub fn new(rules_source: &str) -> Result<Self> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(rules_source)
            .context("Failed to add YARA source")?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    #[allow(dead_code)]
    pub fn scan_file(&self, path: &Path) -> Result<Vec<String>> {
        let data = fs::read(path).context("Failed to read file for YARA scan")?;
        self.scan_bytes(&data)
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner.scan(data).context("YARA scan failed")?;
        let mut matched = Vec::new();
        for rule in results.matching_rules() {
            matched.push(rule.identifier().to_string());
        }
        Ok(matched)
    }
}
