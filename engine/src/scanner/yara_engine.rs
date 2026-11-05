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

#[cfg(test)]
mod tests {
    use super::YaraEngine;

    /// The pack a release ships (`engine\rules\yara\starter.yar`), compiled the way
    /// the scanner compiles it. A hand-edited rule that stops matching has to fail
    /// here, in the fast tier, instead of on a user's machine — which is exactly how
    /// `Malicious_Macro_AutoOpen` shipped comparing the zip magic against `0x504B`
    /// ("KP" in file order) and could therefore never fire on a real document.
    const PACK: &str = include_str!("../../rules/yara/starter.yar");

    /// One vector per rule that a text file can hold the pack to, and the rule that
    /// must fire for it. `scripts\verify-rules.ps1` scans this same folder through a
    /// real engine and the packaged rules, so the two cannot drift apart.
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "certutil.bat",
            "Suspicious_BAT_Certutil_Download",
            include_str!("../../testdata/detection/certutil.bat"),
        ),
        (
            "ps-download.ps1",
            "Suspicious_Cmd_PowerShell_Download",
            include_str!("../../testdata/detection/ps-download.ps1"),
        ),
        (
            "vbs-dropper.vbs",
            "Suspicious_VBS_Dropper",
            include_str!("../../testdata/detection/vbs-dropper.vbs"),
        ),
        (
            "app.hta",
            "Suspicious_HTA_Exec",
            include_str!("../../testdata/detection/app.hta"),
        ),
        (
            "pk-macro.txt",
            "Malicious_Macro_AutoOpen",
            include_str!("../../testdata/detection/pk-macro.txt"),
        ),
        (
            "double-extension.txt",
            "Double_Extension_Emailer",
            include_str!("../../testdata/detection/double-extension.txt"),
        ),
        (
            "ransom-note.txt",
            "Ransom_Note_Names",
            include_str!("../../testdata/detection/ransom-note.txt"),
        ),
        (
            "task-create.txt",
            "Suspicious_Scheduled_Task_Creator",
            include_str!("../../testdata/detection/task-create.txt"),
        ),
    ];

    /// Rules no text vector can reach, each with the measured reason. A rule that is
    /// in neither this table nor [`VECTORS`] fails the count below, so adding a rule
    /// to the pack means deciding which of the two it is.
    const UNREACHABLE: &[(&str, &str)] = &[
        (
            "EICAR_Test_File",
            "the EICAR string is what Defender itself reacts to, so a committed \
             fixture would be quarantined and the gate would fail for the wrong reason",
        ),
        (
            "Tiny_Packed_Pe_Installer",
            "a PE-shaped fixture has to be binary; a malformed one in the tree is \
             quarantine bait and a real one is a build artifact",
        ),
    ];

    /// The rule names the shipped pack declares, in file order.
    fn declared_rules() -> Vec<String> {
        PACK.lines()
            .filter_map(|line| line.trim().strip_prefix("rule "))
            .filter_map(|rest| {
                rest.split(|c: char| c.is_whitespace() || c == '{' || c == ':')
                    .next()
            })
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn engine() -> YaraEngine {
        YaraEngine::new(PACK).expect("the shipped pack must compile")
    }

    #[test]
    fn every_shipped_rule_is_either_proven_or_named() {
        let declared = declared_rules();
        let proven: Vec<&str> = VECTORS.iter().map(|(_, rule, _)| *rule).collect();
        assert!(!declared.is_empty(), "no rules parsed out of the shipped pack");

        for rule in &declared {
            let known = proven.contains(&rule.as_str())
                || UNREACHABLE.iter().any(|(name, _)| name == rule);
            assert!(
                known,
                "the pack ships {rule}, which has no vector in engine\\testdata\\detection \
                 and no reason in UNREACHABLE - prove it or name what stops it"
            );
        }
        for (name, reason) in UNREACHABLE {
            assert!(
                declared.iter().any(|rule| rule == name),
                "{name} is listed as unreachable ({reason}) but the pack no longer declares it"
            );
        }
        for name in &proven {
            assert!(
                declared.iter().any(|rule| rule == name),
                "a vector expects {name}, which the pack no longer declares"
            );
        }
        assert_eq!(
            declared.len(),
            proven.len() + UNREACHABLE.len(),
            "every declared rule is either proven by a vector or named as unreachable"
        );
    }

    #[test]
    fn the_shipped_pack_catches_every_vector_it_has() {
        let engine = engine();
        for (file, rule, content) in VECTORS {
            let matched = engine
                .scan_bytes(content.as_bytes())
                .expect("a vector must scan");
            assert!(
                matched.iter().any(|name| name == rule),
                "{file} must be caught by {rule}, the pack matched {matched:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_file_matches_nothing() {
        let engine = engine();
        let clean = include_str!("../../testdata/detection/clean.txt");
        assert!(
            engine.scan_bytes(clean.as_bytes()).unwrap().is_empty(),
            "a file with nothing in it must not be reported"
        );
    }

    #[test]
    fn the_macro_rule_reads_the_zip_magic_the_way_a_zip_writes_it() {
        // `uint16(0)` is little-endian, so the `50 4B` a zip/OOXML container starts
        // with reads as 0x4B50. The pair below is the measurement that caught the
        // inverted constant, and it is what keeps it from coming back.
        let engine = engine();
        let container = b"PK\nSub AutoOpen()\nCreateObject(\"WScript.Shell\").Run \"calc.exe\"\n";
        assert_eq!(
            engine.scan_bytes(container).unwrap(),
            vec!["Malicious_Macro_AutoOpen".to_string()],
            "a container that starts like a zip and carries macro strings must be caught"
        );
        let inverted = b"KP\nSub AutoOpen()\nCreateObject(\"WScript.Shell\").Run \"calc.exe\"\n";
        assert!(
            engine.scan_bytes(inverted).unwrap().is_empty(),
            "\"KP\" is not a container magic, and a rule that matches it matches no document"
        );
    }
}
