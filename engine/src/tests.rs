//! Unit tests for core engine logic (spec section 15: cargo test green).

#[cfg(test)]
mod tests {
    use crate::platform::windows::collectors::format_ipv4_port;
    use crate::scanner::triage_score;
    use std::path::Path;

    #[test]
    fn formats_ipv4_and_port() {
        // Windows stores the address bytes in network order, which the
        // formatter reads back little-endian: 192.168.1.4 -> 0x0401A8C0.
        let ip = 0x0401A8C0u32;
        // Port 443 arrives network-order in the low 16 bits.
        let port = 443u16.swap_bytes() as u32;
        assert_eq!(format_ipv4_port(ip, port), "192.168.1.4:443");
    }

    #[test]
    fn temp_exe_scores_higher_than_system_pdf() {
        let temp_exe = Path::new(r"C:\Users\u\AppData\Local\Temp\thing.exe");
        let sys_pdf = Path::new(r"C:\Windows\docs\manual.pdf");
        assert!(triage_score(temp_exe) > triage_score(sys_pdf));
    }

    #[test]
    fn double_extension_scores() {
        let p = Path::new(r"C:\Users\u\Downloads\invoice.pdf.exe");
        assert!(triage_score(p) >= 30 + 30);
    }

    #[test]
    fn nl_parser_matches_arabic_full_audit() {
        let r = crate::llm::parse_nl("افحص النظام");
        assert!(r.matched);
        assert_eq!(r.command, "audit.run");
    }

    #[test]
    fn nl_parser_matches_scan_with_path() {
        let r = crate::llm::parse_nl(r#"افحص مجلد "C:\Users\x\Downloads""#);
        assert!(r.matched);
        assert_eq!(r.command, "scan.start");
        // parse_nl lowercases the input; Windows paths are case-insensitive.
        assert_eq!(
            r.params["path"].as_str().unwrap().to_lowercase(),
            r"c:\users\x\downloads"
        );
    }

    #[test]
    fn nl_parser_unmatched_input_is_honest() {
        let r = crate::llm::parse_nl("اطبخ لي بيضة");
        assert!(!r.matched);
        assert_eq!(r.command, "");
    }

    #[test]
    fn pua_live_preference_counts_when_no_policy_is_set() {
        use crate::platform::windows::collectors::pua_effective;
        // The regression: the audit read the Group Policy key alone, so a
        // machine with PUA blocking enabled through Windows Security was
        // reported as "not explicitly enabled" and offered a repair.
        assert_eq!(pua_effective(None, Some(1)), Some(1));
        assert_eq!(pua_effective(None, Some(0)), Some(0));
        // A policy outranks the local preference store.
        assert_eq!(pua_effective(Some(0), Some(1)), Some(0));
        assert_eq!(pua_effective(Some(2), Some(1)), Some(2));
        // Nothing anywhere: Defender's built-in default, reported as unset.
        assert_eq!(pua_effective(None, None), None);
    }

    #[test]
    fn pua_verdict_only_passes_blocking() {
        use crate::platform::windows::collectors::pua_verdict;
        use crate::platform::traits::FindingStatus;
        assert!(matches!(
            pua_verdict(Some(1)),
            (FindingStatus::Secure, _, false)
        ));
        // Audit mode reports unwanted apps but never blocks them.
        assert!(matches!(
            pua_verdict(Some(2)),
            (FindingStatus::Warning, _, true)
        ));
        assert!(matches!(
            pua_verdict(Some(0)),
            (FindingStatus::Warning, _, true)
        ));
        assert!(matches!(
            pua_verdict(None),
            (FindingStatus::Warning, _, true)
        ));
    }

    #[test]
    fn unreadable_defender_status_is_not_a_false_alarm() {
        use crate::platform::windows::collectors::parse_mp_bool;
        // A refused WMI query exits 0 with empty stdout: that used to be read as
        // "real-time protection is DISABLED" (Critical) on a healthy machine.
        assert_eq!(parse_mp_bool(""), None);
        assert_eq!(parse_mp_bool("Access is denied\n"), None);
        assert_eq!(parse_mp_bool("True"), Some(true));
        assert_eq!(parse_mp_bool(" False "), Some(false));
    }

    #[test]
    fn pua_snapshot_restores_the_exact_state() {
        use crate::hardening::{parse_pua_state, pua_rollback};
        // The snapshot must never write: it only reports what is there.
        assert_eq!(parse_pua_state("pua=1\n").unwrap(), Some(1));
        assert_eq!(parse_pua_state("pua=absent").unwrap(), None);
        assert!(parse_pua_state("noise only").is_err());
        assert!(pua_rollback(Some(0)).contains("/d 0 /f"));
        assert!(pua_rollback(Some(2)).contains("/d 2 /f"));
        // Nothing was set before, so the rollback removes the value instead of
        // guessing a default.
        assert!(pua_rollback(None).contains("reg delete"));
    }

    // ---- intel sync (P3c) ----

    /// Throwaway database file; each test gets its own directory.
    fn temp_db(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mics-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("mics.db")
    }

    #[test]
    fn hosts_blocklist_keeps_domains_and_drops_loopback() {
        use crate::sync::feeds::parse_hosts_blocklist;
        let text = "# Title: test\n\
                    127.0.0.1 localhost\n\
                    0.0.0.0 ads.example.com\n\
                    255.255.255.255 broadcasthost\n\
                    0.0.0.0 bad-domain.example.org # inline comment\n\
                    broken\n";
        let domains = parse_hosts_blocklist(text);
        // The loopback names every hosts file ships are not indicators, and a
        // line without a hostname is not a domain.
        assert!(!domains.contains(&"localhost".to_string()));
        assert!(!domains.contains(&"broadcasthost".to_string()));
        assert!(domains.contains(&"ads.example.com".to_string()));
        assert!(
            domains.contains(&"bad-domain.example.org".to_string()),
            "an inline comment must not swallow the hostname"
        );
        assert_eq!(domains.len(), 2, "unexpected extra rows: {domains:?}");
    }

    #[test]
    fn hash_feed_reads_the_sha256_column_after_the_header() {
        use crate::sync::feeds::parse_hash_feed;
        let h = "a".repeat(64);
        let csv = format!("\"firstseen\",\"sha256_hash\"\n\"2026-01-01\",\"{h}\"\n");
        assert_eq!(parse_hash_feed(&csv), vec![h.clone()]);
        // Plain lists and `hash;tags` exports both keep working.
        assert_eq!(parse_hash_feed(&format!("{h}\n")), vec![h.clone()]);
        assert_eq!(parse_hash_feed(&format!("{h};trojan;win32\n")), vec![h]);
        assert!(parse_hash_feed("not-a-hash\n").is_empty());
    }

    #[test]
    fn kev_catalog_parser_flags_known_ransomware() {
        use crate::sync::feeds::parse_kev_catalog;
        let json = serde_json::json!({
            "catalogVersion": "2026.10.29",
            "count": 1,
            "vulnerabilities": [{
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor",
                "product": "Product",
                "dateAdded": "2026-10-01",
                "dueDate": "2026-10-21",
                "knownRansomwareCampaignUse": "Known"
            }]
        });
        let (version, rows) = parse_kev_catalog(&json);
        assert_eq!(version, "2026.10.29");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].due_date, "2026-10-21");
        assert!(rows[0].ransomware);
    }

    #[test]
    fn cidr_parser_rejects_anything_that_is_not_an_ipv4_network() {
        use crate::ids::geoip::parse_cidr_line;
        assert!(parse_cidr_line("1.2.3.0/24").is_some());
        assert!(parse_cidr_line("  1.2.3.0/24   ").is_some());
        assert!(parse_cidr_line("1.2.3.0/33").is_none());
        assert!(parse_cidr_line("1.2.3.0").is_none());
        assert!(parse_cidr_line("# comment").is_none());
    }

    #[test]
    fn backoff_ladder_doubles_then_settles_on_the_cadence() {
        let cadence = 6 * 3600;
        assert_eq!(crate::sync::backoff_secs(1, cadence), 900);
        assert_eq!(crate::sync::backoff_secs(2, cadence), 1800);
        assert_eq!(crate::sync::backoff_secs(3, cadence), 3600);
        // A feed that keeps failing is retried at the normal cadence, never
        // more often (which would hammer a dead host) and never less.
        assert_eq!(crate::sync::backoff_secs(9, cadence), cadence);
    }

    #[test]
    fn sync_state_keeps_the_last_success_through_failures() {
        use crate::storage::sqlite::Storage;
        use crate::sync::state_of;
        let path = temp_db("sync-state");
        let storage = Storage::open_at(&path).unwrap();
        storage
            .record_sync_success("ioc_domains", "stevenblack", "10 new", 10, Some(1000))
            .unwrap();
        storage.record_sync_failure("ioc_domains", "HTTP 500", Some(2000)).unwrap();
        storage.record_sync_failure("ioc_domains", "HTTP 502", Some(3000)).unwrap();

        let row = storage
            .sync_states()
            .unwrap()
            .into_iter()
            .find(|r| r.source == "ioc_domains")
            .expect("row for ioc_domains");
        assert_eq!(row.failures, 2, "consecutive failures must count");
        assert!(row.last_success.is_some(), "the last good sync must survive");
        assert_eq!(row.last_error.as_deref(), Some("HTTP 502"));
        assert_eq!(row.next_due, Some(3000));
        assert_eq!(state_of(Some(&row)), "failed");

        // A success clears the error and restarts the ladder.
        storage
            .record_sync_success("ioc_domains", "stevenblack", "20 new", 20, Some(4000))
            .unwrap();
        let row = storage
            .sync_states()
            .unwrap()
            .into_iter()
            .find(|r| r.source == "ioc_domains")
            .unwrap();
        assert_eq!(row.failures, 0);
        assert_eq!(row.last_error, None);
        assert_eq!(state_of(Some(&row)), "ok");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unconfigured_source_is_not_reported_as_a_failure() {
        use crate::storage::sqlite::Storage;
        use crate::sync::state_of;
        let path = temp_db("sync-skip");
        let storage = Storage::open_at(&path).unwrap();
        storage
            .record_sync_skipped("ioc_hashes", "no feed configured", Some(5000))
            .unwrap();
        let row = storage
            .sync_states()
            .unwrap()
            .into_iter()
            .find(|r| r.source == "ioc_hashes")
            .unwrap();
        assert_eq!(row.failures, 0, "nothing was attempted, so nothing failed");
        assert_eq!(row.last_success, None, "a skipped source is not fresh");
        assert_eq!(state_of(Some(&row)), "not_configured");
        assert_eq!(state_of(None), "never");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Found by live-probing the P3c3 feed settings: a source that had been
    /// reported as "not configured" kept that label after the user configured it
    /// and the fetch failed, so the screen showed the one thing that was no
    /// longer true about it.
    #[test]
    fn a_configured_source_that_fails_stops_reading_as_unconfigured() {
        use crate::storage::sqlite::Storage;
        use crate::sync::state_of;
        let path = temp_db("sync-configured-then-failed");
        let storage = Storage::open_at(&path).unwrap();
        storage
            .record_sync_skipped("ioc_hashes", "no feed configured", Some(5000))
            .unwrap();
        storage
            .record_sync_failure("ioc_hashes", "no sha256 hash found in feed", Some(900))
            .unwrap();
        let row = storage
            .sync_states()
            .unwrap()
            .into_iter()
            .find(|r| r.source == "ioc_hashes")
            .unwrap();
        assert_eq!(row.failures, 1);
        assert_eq!(row.version, None, "the stale marker must be cleared");
        assert_eq!(state_of(Some(&row)), "failed");

        // Taking the URL away again puts it back into the honest state.
        storage
            .record_sync_skipped("ioc_hashes", "no feed configured", Some(5000))
            .unwrap();
        let row = storage
            .sync_states()
            .unwrap()
            .into_iter()
            .find(|r| r.source == "ioc_hashes")
            .unwrap();
        assert_eq!(state_of(Some(&row)), "not_configured");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn old_sync_state_table_is_migrated_in_place() {
        use crate::storage::sqlite::Storage;
        let path = temp_db("sync-migrate");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // The table exactly as a shipped build created it.
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sync_state (
                    source TEXT PRIMARY KEY,
                    last_success INTEGER,
                    version TEXT
                 );",
            )
            .unwrap();
        }
        // Opening it must add the intel columns instead of failing or losing
        // the row that is already there.
        let storage = Storage::open_at(&path).unwrap();
        storage.record_sync_success("kev", "2026.10.29", "3 CVEs", 3, Some(123)).unwrap();
        let row = storage
            .sync_states()
            .unwrap()
            .into_iter()
            .find(|r| r.source == "kev")
            .expect("row written into the migrated table");
        assert_eq!(row.items, 3);
        assert_eq!(row.failures, 0);
        assert_eq!(row.next_due, Some(123));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn kev_catalog_swap_does_not_accumulate_entries() {
        use crate::storage::sqlite::{KevRow, Storage};
        let path = temp_db("kev");
        let storage = Storage::open_at(&path).unwrap();
        let row = |id: &str| KevRow {
            cve_id: id.into(),
            vendor: "V".into(),
            product: "P".into(),
            date_added: "2026-10-01".into(),
            due_date: "2026-10-21".into(),
            ransomware: true,
        };
        storage.set_kev_catalog(&[row("CVE-2026-0001")]).unwrap();
        storage.set_kev_catalog(&[row("CVE-2026-0002")]).unwrap();
        assert_eq!(
            storage.kev_count().unwrap(),
            1,
            "a CVE dropped upstream must not linger in the catalog"
        );
        let catalog = storage.kev_catalog().unwrap();
        assert_eq!(catalog[0].cve_id, "CVE-2026-0002");
        assert_eq!(catalog[0].due_date, "2026-10-21");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A cancelled vuln scan must not sit through the 6.5 s NVD pause: that is
    /// the difference between "cancel" and "cancel after the next step".
    #[test]
    fn vuln_scan_pause_is_interrupted_by_cancel() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let cancelled = AtomicBool::new(true);
        let start = Instant::now();
        rt.block_on(crate::vulns::pause(
            Duration::from_secs(6),
            Some(&cancelled),
        ));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "pause ignored the cancel flag: {:?}",
            start.elapsed()
        );

        let running = AtomicBool::new(false);
        let start = Instant::now();
        rt.block_on(crate::vulns::pause(
            Duration::from_millis(300),
            Some(&running),
        ));
        assert!(start.elapsed() >= Duration::from_millis(250));
    }

    #[test]
    fn vuln_scan_progress_is_bounded() {
        use crate::vulns::pct;
        assert_eq!(pct(0, 0), 0, "an empty target list must not divide by zero");
        assert_eq!(pct(1, 4), 25);
        assert_eq!(pct(4, 4), 100);
        assert_eq!(pct(9, 4), 100, "progress never exceeds 100 %");
    }

    #[test]
    fn vulnerability_annotation_marks_only_exploited_cves() {
        use crate::storage::sqlite::KevRow;
        use crate::vulns::{Vulnerability, annotate_kev};
        let mut kev = std::collections::HashMap::new();
        kev.insert(
            "CVE-2026-0001".to_string(),
            KevRow {
                cve_id: "CVE-2026-0001".into(),
                vendor: "V".into(),
                product: "P".into(),
                date_added: "2026-10-01".into(),
                due_date: "2026-10-21".into(),
                ransomware: false,
            },
        );
        let make = |id: &str| Vulnerability {
            cve_id: id.into(),
            cvss: 9.8,
            description: "x".into(),
            published: "2026-10-01".into(),
            known_exploited: false,
            kev_due: None,
        };
        let mut vulns = vec![make("CVE-2026-0001"), make("CVE-2026-0009")];
        annotate_kev(&mut vulns, &kev);
        assert!(vulns[0].known_exploited, "a catalogued CVE is exploited now");
        assert_eq!(vulns[0].kev_due.as_deref(), Some("2026-10-21"));
        assert!(!vulns[1].known_exploited, "an uncatalogued CVE is not");
        assert!(vulns[1].kev_due.is_none());
    }

    // ---- privileged helper (P1.5, D-007) ----

    #[test]
    fn privileged_op_set_is_closed() {
        use crate::privileged::Op;
        // Only the documented operations exist: a request for anything else is
        // a malformed frame, not something the helper tries to interpret.
        assert!(serde_json::from_str::<Op>(r#"{"op":"shell.run","command":"whoami"}"#).is_err());
        assert!(serde_json::from_str::<Op>(r#"{"op":"FirewallDefaultDeny","enabled":true}"#).is_err());
        assert!(matches!(
            serde_json::from_str::<Op>(r#"{"op":"ping"}"#).unwrap(),
            Op::Ping
        ));
        assert!(matches!(
            serde_json::from_str::<Op>(r#"{"op":"firewall.default_deny","enabled":true}"#).unwrap(),
            Op::FirewallDefaultDeny { enabled: true }
        ));
    }

    #[test]
    fn privileged_payloads_are_validated_before_anything_runs() {
        use crate::firewall::AddRuleRequest;
        use crate::privileged::Op;

        let rule = |direction: &str, action: &str, name: &str| AddRuleRequest {
            name: name.into(),
            direction: direction.into(),
            action: action.into(),
            protocol: None,
            remote_ip: None,
            local_port: None,
            remote_port: None,
            program: None,
        };
        assert!(Op::FirewallAddRule {
            rule: rule("out", "block", "X")
        }
        .validate()
        .is_ok());
        assert!(
            Op::FirewallAddRule {
                rule: rule("both", "block", "X")
            }
            .validate()
            .is_err(),
            "a direction netsh does not accept must never reach netsh"
        );
        assert!(
            Op::FirewallAddRule {
                rule: rule("out", "drop", "X")
            }
            .validate()
            .is_err()
        );
        assert!(
            Op::FirewallAddRule {
                rule: rule("out", "block", "  ")
            }
            .validate()
            .is_err()
        );
        assert!(Op::FirewallRemoveRule { name: String::new() }.validate().is_err());
        assert!(
            Op::HardeningRun {
                action: "delete_everything".into()
            }
            .validate()
            .is_err(),
            "the hardening table is a whitelist, not a lookup that guesses"
        );
        assert!(
            Op::HardeningRun {
                action: "smbv1_off".into()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn hosts_documents_are_shape_checked() {
        use crate::privileged::validate_hosts;
        let good = "# Copyright\n127.0.0.1 localhost\n::1 localhost\n\
                    \n# BEGIN MICS-IDS (managed — do not edit)\n\
                    0.0.0.0 ads.example.com\t# inline comment\n# END MICS-IDS\n";
        assert!(validate_hosts(good).is_ok());

        // A document without our marker is not something the IDS path produced.
        assert!(validate_hosts("127.0.0.1 localhost\n").is_err());
        // Neither is one that smuggles a second file's worth of commands in.
        assert!(validate_hosts("# BEGIN MICS-IDS\ncmd /c whoami\n").is_err());
        assert!(validate_hosts("# BEGIN MICS-IDS\n0.0.0.0 bad host/path\n").is_err());
        assert!(validate_hosts(&format!("# BEGIN MICS-IDS\n{}\n", "0.0.0.0 a.b\n".repeat(400_000))).is_err());
    }

    #[test]
    fn rollback_scripts_are_allow_listed() {
        use crate::hardening::pua_rollback;
        use crate::privileged::validate_rollback;

        // Exactly the shapes `hardening::snapshot_current` generates.
        for generated in [
            pua_rollback(Some(1)),
            pua_rollback(None),
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f".to_string(),
            "Set-SmbServerConfiguration -EnableSMB1Protocol True -Force; reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\" /v Start /t REG_DWORD /d 2 /f".to_string(),
            "Set-MpPreference -PUAProtection Disabled".to_string(),
        ] {
            assert!(
                validate_rollback(&generated).is_ok(),
                "the helper must accept a script we generated: {generated}"
            );
        }

        for hostile in [
            "cmd /c del C:\\Windows\\System32\\config\\SAM",
            "powershell -NoProfile -EncodedCommand ZQBjAGgAbwA=",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil\" /v Start /t REG_SZ /d x /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v x /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SYSTEM\\..\\..\\evil\" /v Start /t REG_DWORD /d 1 /f",
            "Set-MpPreference -PUAProtection Enabled; cmd /c calc",
            "reg add \"HKLM\\SYSTEM\\x\" /v Start /t REG_DWORD /d 4 /f > C:\\Windows\\Temp\\out.txt",
            "`whoami`",
        ] {
            assert!(
                validate_rollback(hostile).is_err(),
                "the helper must refuse this: {hostile}"
            );
        }
        assert!(validate_rollback("").is_err());
        assert!(validate_rollback(&"reg add \"HKLM\\x\" /v a /t REG_DWORD /d 1 /f\n".repeat(9)).is_err());
    }

    #[test]
    fn service_definition_quotes_the_install_path() {
        use crate::privileged::service::{bin_path, parse_query};
        let path = Path::new(r"C:\Program Files\MIF\mics-engine.exe");
        assert_eq!(
            bin_path(path),
            "\"C:\\Program Files\\MIF\\mics-engine.exe\" --helper-service"
        );
        let args = crate::privileged::service::sc_create_args(path);
        assert!(args.contains(&"obj=".to_string()) && args.contains(&"LocalSystem".to_string()));
        // `sc` parses its own argv, so `key=` and the value travel as separate
        // argv entries; only the value carries the quotes the path needs.
        let bin = args
            .iter()
            .position(|a| a == "binPath=")
            .expect("binPath is passed to sc");
        assert_eq!(args[bin + 1], bin_path(path));
        assert!(args[bin + 1].contains('"'));

        let running = parse_query("SERVICE_NAME: MICSHelper\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n");
        assert!(running.installed && running.running);
        assert_eq!(running.state, "running");
        let stopped = parse_query("        STATE              : 1  STOPPED\n");
        assert!(stopped.installed && !stopped.running);
        // `sc query` on a service that was never installed says nothing useful,
        // which is a normal answer rather than an error.
        assert_eq!(
            parse_query("The specified service does not exist as an installed service."),
            crate::privileged::service::HelperState::missing()
        );
    }

    #[test]
    fn privileged_requests_are_audited_and_refused_when_malformed() {
        use crate::privileged::Op;
        use crate::privileged::server;
        // One test owns both env hooks (parallel tests must not race on them).
        let dir = std::env::temp_dir().join(format!("mics-helper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("priv.log");
        unsafe {
            std::env::set_var("MICS_HELPER_LOG", &log);
            std::env::set_var("MICS_HELPER_PIPE", format!("mics_helper_test_{}", std::process::id()));
        }

        // A document that is not ours is refused *before* anything is logged as
        // started, and the answer is the envelope the client expects.
        let refused = server::respond(&Op::HostsWrite {
            content: "no marker here\n".into(),
        });
        assert!(refused.contains("\"ok\":false"), "{refused}");
        assert!(refused.contains("marker"), "{refused}");

        // The real protocol, over a real pipe, in this process.
        server::spawn_console().expect("helper pipe binds");
        let pong = crate::privileged::call(&Op::Ping).expect("ping answers");
        assert_eq!(pong["pong"], serde_json::json!(true));
        let version = crate::privileged::call(&Op::Version).expect("version answers");
        assert_eq!(
            version["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            version["elevated"].as_bool(),
            Some(crate::platform::windows::elevation::is_elevated()),
            "the helper reports its own token state instead of assuming it is elevated"
        );

        // A well-shaped request in an unelevated test process must be refused
        // with the reason, not silently half-applied.
        let unelevated = server::respond(&Op::HardeningRun {
            action: "smbv1_off".into(),
        });
        if !crate::platform::windows::elevation::is_elevated() {
            assert!(unelevated.contains("\"ok\":false"), "{unelevated}");
            assert!(unelevated.contains("elevated token"), "{unelevated}");
        }

        let text = std::fs::read_to_string(&log).expect("audit log written");
        assert!(text.contains("phase=start hosts.write"), "{text}");
        assert!(text.contains("phase=done ok=false"), "{text}");
        assert!(text.contains("phase=done ok=true dur_ms="), "{text}");
        // The audit line proves *what* was sent without copying the document.
        assert!(text.contains("sha256="), "{text}");
        assert!(!text.contains("no marker here"), "the log must not carry payloads: {text}");
    }

    #[test]
    fn the_rules_source_is_reported_once_per_change() {
        // Guard rules hot-reload every 30 s; repeating the same line forever would
        // bury the log, and the file a scan used is evidence that a package is
        // complete (its own `rules\guard` folder, not the built-in pack).
        assert!(crate::guard::note_rules_source(r"C:\x\rules\guard", 2));
        assert!(
            !crate::guard::note_rules_source(r"C:\x\rules\guard", 2),
            "an unchanged source must not be logged again"
        );
        assert!(
            crate::guard::note_rules_source(r"C:\x\rules\guard", 3),
            "a changed rule count is news"
        );
        assert!(crate::guard::note_rules_source("the built-in starter pack", 3));
    }

    #[test]
    fn audit_sections_are_parsed_or_refused_never_ignored() {
        use serde_json::json;
        let sections = crate::platform::traits::requested_sections;

        // No params, no `sections`, or an empty list: the full audit.
        assert!(sections(None).unwrap().is_none());
        assert!(sections(Some(&json!({}))).unwrap().is_none());
        assert!(sections(Some(&json!({"sections": []}))).unwrap().is_none());

        let picked = sections(Some(&json!({"sections": ["firewall", "hosts"]})))
            .unwrap()
            .expect("a named subset");
        assert_eq!(picked, vec!["firewall".to_string(), "hosts".to_string()]);

        // Duplicates collapse instead of running a section twice.
        let twice = sections(Some(&json!({"sections": ["uac", "uac"]}))).unwrap().unwrap();
        assert_eq!(twice, vec!["uac".to_string()]);

        // A typo must be an error: silently ignoring it would return a perfect
        // score over checks that never ran.
        let unknown = sections(Some(&json!({"sections": ["firewal"]}))).unwrap_err();
        let message = format!("{unknown:#}");
        assert!(message.contains("unknown section"), "{message}");
        assert!(message.contains("firewall"), "the error lists what is known: {message}");

        assert!(sections(Some(&json!({"sections": "firewall"}))).is_err());
        assert!(sections(Some(&json!({"sections": [7]}))).is_err());
    }

    /// Counts which collectors ran, so "honours `params.sections`" is a fact and
    /// not a claim about the dispatcher's shape.
    struct CountingCollectors {
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl CountingCollectors {
        fn new() -> Self {
            Self { calls: std::sync::Mutex::new(Vec::new()) }
        }

        fn note(&self, name: &'static str) {
            self.calls.lock().unwrap().push(name);
        }

        fn called(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }

        fn finding(section: &str) -> Vec<crate::platform::traits::AuditFinding> {
            vec![crate::platform::traits::AuditFinding {
                section: section.to_string(),
                item: format!("{section} check"),
                status: crate::platform::traits::FindingStatus::Vulnerable,
                severity: crate::platform::traits::Severity::Critical,
                description: "insecure".into(),
                fix_available: false,
            }]
        }
    }

    #[async_trait::async_trait]
    impl crate::platform::traits::PlatformCollectors for CountingCollectors {
        async fn audit_defender(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("defender");
            Ok(Self::finding("defender"))
        }
        async fn audit_firewall(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("firewall");
            Ok(Self::finding("firewall"))
        }
        async fn audit_rdp(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("rdp");
            Ok(Vec::new())
        }
        async fn audit_smbv1(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("smbv1");
            Ok(Vec::new())
        }
        async fn audit_uac(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("uac");
            Ok(Vec::new())
        }
        async fn audit_admins(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("admins");
            Ok(Vec::new())
        }
        async fn audit_hosts_file(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("hosts");
            Ok(Vec::new())
        }
        async fn audit_remote_tools(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.note("remote_tools");
            Ok(Vec::new())
        }
        async fn audit_startup(&self) -> anyhow::Result<Vec<crate::platform::traits::StartupEntry>> {
            self.note("startup");
            Ok(Vec::new())
        }
        async fn audit_scheduled_tasks(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::ScheduledTaskEntry>> {
            self.note("scheduled_tasks");
            Ok(Vec::new())
        }
        async fn get_network_connections(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::NetworkConnection>> {
            self.note("net.connections");
            Ok(Vec::new())
        }
        async fn get_software_inventory(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::SoftwareEntry>> {
            self.note("inventory");
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn a_partial_audit_runs_only_what_was_asked_for() {
        let collectors = CountingCollectors::new();
        let report = crate::platform::traits::run_audit(&collectors, Some(&["firewall".to_string()]))
            .await
            .expect("a named section runs");

        assert_eq!(collectors.called(), vec!["firewall"], "only the asked-for section ran");
        assert_eq!(report["sections"], serde_json::json!(["firewall"]));
        assert_eq!(report["partial"], serde_json::json!(true));
        assert_eq!(report["startup_entries"], serde_json::json!([]));
        // One CRITICAL finding (penalty 25) and nothing else looked at.
        assert_eq!(report["score"], serde_json::json!(75));
        assert_eq!(report["findings"].as_array().map(|f| f.len()), Some(1));
    }

    #[tokio::test]
    async fn a_full_audit_runs_every_section_and_is_not_partial() {
        let collectors = CountingCollectors::new();
        let report = crate::platform::traits::run_audit(&collectors, None)
            .await
            .expect("the full audit runs");

        let called = collectors.called();
        for name in [
            "defender", "firewall", "rdp", "smbv1", "uac", "admins", "hosts", "remote_tools",
            "startup", "scheduled_tasks",
        ] {
            assert!(called.contains(&name), "{name} did not run: {called:?}");
        }
        assert_eq!(report["partial"], serde_json::json!(false));
        assert_eq!(
            report["sections"].as_array().map(|s| s.len()),
            Some(10),
            "8 checks + 2 inventory lists"
        );
        // defender + firewall each contribute a CRITICAL (25 + 25).
        assert_eq!(report["score"], serde_json::json!(50));
    }
}
