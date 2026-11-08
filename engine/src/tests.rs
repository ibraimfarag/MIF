//! Unit tests for core engine logic (spec section 15: cargo test green).

#[cfg(test)]
mod tests {
    use crate::platform::windows::conns::format_ipv4_port;
    use crate::scanner::triage_score;
    use std::path::Path;

    /// The one elevated step is launched as a CLI **subcommand**; the flag
    /// spelling (`--install-helper`) is a clap usage error that exits 2 before
    /// the child can log anything, so the UI could only report an exit code and
    /// every privileged operation failed on it. Parsing the same strings with
    /// the real CLI is what keeps the two from drifting apart again.
    ///
    /// All three run the engine: the two the UI triggers, and the body the SCM
    /// starts for the installed service (`binPath`).
    #[test]
    fn the_elevated_step_is_a_subcommand_the_cli_accepts() {
        use clap::Parser;
        for command in [
            crate::privileged::INSTALL_COMMAND,
            crate::privileged::UNINSTALL_COMMAND,
            crate::privileged::SERVICE_COMMAND,
        ] {
            crate::Cli::try_parse_from(["mics-engine", command]).unwrap_or_else(|e| {
                panic!("{command} is not a command the CLI accepts: {e}")
            });
        }
    }

    /// A refused command line must not be silent: the spelling above was wrong
    /// for a day and the only trace was `exit code 2` at the caller.
    #[test]
    fn the_flag_spelling_of_the_elevated_step_is_refused() {
        use clap::Parser;
        for flag in [
            format!("--{}", crate::privileged::INSTALL_COMMAND),
            format!("--{}", crate::privileged::UNINSTALL_COMMAND),
            format!("--{}", crate::privileged::SERVICE_COMMAND),
        ] {
            let err = match crate::Cli::try_parse_from(["mics-engine", flag.as_str()]) {
                Ok(_) => panic!("{flag} was accepted — the CLI spells it without dashes"),
                Err(e) => e,
            };
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{flag}: expected a usage error, got {err}"
            );
        }
    }

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
            "a direction the firewall API does not accept must never reach it"
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

    /// The WFP ops are part of the closed set (D-007, amended by D-042): four
    /// named tags, no "add any filter" surface, and the spec travels as data the
    /// helper validates rather than as a command it interprets.
    #[test]
    fn the_wfp_ops_are_part_of_the_closed_set() {
        use crate::firewall::wfp::FilterSpec;
        use crate::privileged::Op;

        assert!(matches!(
            serde_json::from_str::<Op>(r#"{"op":"firewall.wfp.status"}"#).unwrap(),
            Op::FirewallWfpStatus
        ));
        assert!(matches!(
            serde_json::from_str::<Op>(r#"{"op":"firewall.wfp.reset"}"#).unwrap(),
            Op::FirewallWfpReset
        ));
        assert!(matches!(
            serde_json::from_str::<Op>(
                r#"{"op":"firewall.wfp.block","spec":{"app":"C:\\app.exe","port":443,"protocol":6}}"#
            )
            .unwrap(),
            Op::FirewallWfpBlock { .. }
        ));
        assert!(
            serde_json::from_str::<Op>(r#"{"op":"firewall.wfp.add_any","filter":"*"}"#).is_err(),
            "the helper does not take a filter description it did not define"
        );
        assert!(
            serde_json::from_str::<Op>(r#"{"op":"wfp.block","app":"x"}"#).is_err(),
            "nor one under a second spelling"
        );

        // A spec round-trips, so the engine and the helper agree on the wire.
        let spec = FilterSpec {
            app: Some("C:\\app.exe".into()),
            port: Some(443),
            protocol: Some(6),
            note: Some("guard".into()),
        };
        let line = serde_json::to_string(&Op::FirewallWfpBlock { spec: spec.clone() }).unwrap();
        match serde_json::from_str::<Op>(&line).unwrap() {
            Op::FirewallWfpBlock { spec: back } => assert_eq!(back, spec),
            other => panic!("a block op came back as {other:?}"),
        }
    }

    /// The validation in front of the BFE: a spec that would filter everything,
    /// or a note that would put a sentence (or a newline) into the machine's
    /// filtering table, is refused before anything is written.
    #[test]
    fn a_wfp_filter_spec_is_checked_before_it_reaches_the_bfe() {
        use crate::firewall::wfp::FilterSpec;
        use crate::privileged::Op;

        let spec = |app: Option<&str>, port: Option<u16>, note: Option<&str>| FilterSpec {
            app: app.map(String::from),
            port,
            protocol: port.map(|_| 6),
            note: note.map(String::from),
        };

        assert!(Op::FirewallWfpBlock {
            spec: spec(None, None, None)
        }
        .validate()
        .is_err());
        assert!(Op::FirewallWfpBlock {
            spec: spec(Some("C:\\app.exe"), Some(443), Some("guard"))
        }
        .validate()
        .is_ok());
        assert!(
            Op::FirewallWfpBlock {
                spec: spec(Some("C:\\app.exe"), None, Some("guard\nfirewall.wfp.reset"))
            }
            .validate()
            .is_err(),
            "a filter name is one line the machine stores, not a place for a second request"
        );
        assert!(Op::FirewallWfpBlock {
            spec: spec(Some("C:\\app.exe"), None, Some(&"x".repeat(41)))
        }
        .validate()
        .is_err());
        assert!(Op::FirewallWfpUnblock {
            spec: spec(None, Some(0), None)
        }
        .validate()
        .is_err());
    }

    /// What the audit log gets: the filter's name (what it covers) and its key,
    /// never the directory the application sits in.
    #[test]
    fn a_wfp_audit_line_names_the_filter_not_the_folder() {
        use crate::firewall::wfp::{filter_key, key_text, FilterSpec};
        use crate::privileged::Op;

        let spec = FilterSpec {
            app: Some("C:\\Users\\someone\\Downloads\\setup.exe".into()),
            port: Some(8443),
            protocol: Some(6),
            note: Some("guard".into()),
        };
        let line = Op::FirewallWfpBlock { spec: spec.clone() }.audit_summary();
        assert!(line.starts_with("firewall.wfp.block "), "{line}");
        assert!(line.contains("setup.exe"), "{line}");
        assert!(line.contains("8443"), "{line}");
        assert!(line.contains(&key_text(&filter_key(&spec))), "{line}");
        assert!(
            !line.contains("someone") && !line.contains("Downloads"),
            "the audit line carries the name, not the path: {line}"
        );
    }

    /// The RPC parameters a `fw.wfp.*` call carries. A request with nothing to
    /// filter is refused before the privilege split, so the caller gets the same
    /// answer whether or not a helper is installed.
    #[test]
    fn wfp_rpc_params_become_a_spec_or_a_refusal() {
        use crate::dispatcher::filter_spec;
        use crate::rpc::JsonRpcRequest;
        use serde_json::json;

        let request = |params: serde_json::Value| JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "fw.wfp.block".into(),
            params: Some(params),
            id: Some(json!(1)),
        };

        let spec = filter_spec(&request(json!({"app": " C:\\app.exe ", "port": 443, "protocol": 6})))
            .expect("a spec with an application and a port");
        assert_eq!(spec.app.as_deref(), Some("C:\\app.exe"));
        assert_eq!(spec.port, Some(443));
        assert_eq!(spec.protocol, Some(6));
        assert_eq!(spec.note, None);

        assert!(filter_spec(&request(json!({}))).is_none(), "nothing to filter");
        assert!(filter_spec(&request(json!({"app": ""}))).is_none());
        assert!(
            filter_spec(&request(json!({"port": 70000}))).is_none(),
            "a port that is not a port"
        );
        assert!(filter_spec(&request(json!({"port": 443, "protocol": 99}))).is_none());
    }

    #[test]
    fn hosts_documents_are_shape_checked() {        use crate::privileged::validate_hosts;
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

        // A BOM the file already carried is an encoding marker, not line 1. This
        // machine's hosts file starts with one, and every IDS write was refused
        // with `line 1 is not an address/host pair: "\u{feff}"` (2026-11-01).
        let with_bom = format!("\u{feff}{good}");
        assert!(
            validate_hosts(&with_bom).is_ok(),
            "a document the IDS path builds from a BOM-prefixed hosts file must validate"
        );
        // The BOM buys no leniency for what follows it.
        assert!(validate_hosts("\u{feff}# BEGIN MICS-IDS\ncmd /c whoami\n").is_err());
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
            // The shape the snapshot writes today: a literal, which is the only one
            // PowerShell binds to a [bool] parameter.
            "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force; reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10\" /v Start /t REG_DWORD /d 2 /f".to_string(),
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

    /// Every script we hand PowerShell must **parse**. The SMBv1 snapshot shipped
    /// with `\"` inside a double-quoted PowerShell string (not an escape), so every
    /// apply died as `UnexpectedToken` before it could reach the elevated step and
    /// the user got the raw parser dump. Parse only — `[scriptblock]::Create`
    /// never runs what it compiles — so this stays a test instead of a probe.
    #[test]
    fn every_powershell_script_we_generate_parses() {
        let mut scripts: Vec<(String, String)> = Vec::new();
        for action in crate::hardening::list_actions() {
            let (command, _) = crate::hardening::command_for(&action.id)
                .unwrap_or_else(|e| panic!("no command for {}: {e}", action.id));
            scripts.push((format!("apply-{}", action.id), command));
            if let Some(snapshot) = crate::hardening::snapshot_script(&action.id) {
                scripts.push((format!("snapshot-{}", action.id), snapshot.to_string()));
            }
        }
        scripts.push((
            "snapshot-pua_protection".to_string(),
            crate::hardening::PUA_STATE_SCRIPT.to_string(),
        ));
        assert_scripts_parse(&scripts);
    }

    /// What a snapshot prints has to be a script the helper will accept, and it
    /// has to work **unelevated** — that is the whole reason it is a read.
    #[test]
    fn snapshots_run_unelevated_and_are_acceptable_rollbacks() {
        for action in ["pua_protection", "smbv1_off", "rdp_off", "uac_on"] {
            let snapshot = crate::hardening::snapshot_current(action)
                .unwrap_or_else(|e| panic!("the {action} snapshot failed: {e:#}"));
            assert!(
                !snapshot.trim().is_empty(),
                "the {action} snapshot is empty — a rollback would have nothing to restore"
            );
            crate::privileged::validate_rollback(&snapshot).unwrap_or_else(|e| {
                panic!("the {action} snapshot is not an acceptable rollback: {e}\n{snapshot}")
            });
            if action == "smbv1_off" {
                // Measured 2026-11-01 on a real machine: the snapshot formatted the
                // boolean with `-f $s`, which prints `True`, and
                // `-EnableSMB1Protocol True` binds the *string* "True" — the CIM
                // cmdlet answers "Boolean parameters accept only Boolean values and
                // numbers" and the rollback dies before it runs. The allow-list
                // accepted the word, so only a literal check catches this.
                assert!(
                    snapshot.contains("$true") || snapshot.contains("$false"),
                    "the SMBv1 rollback must carry a PowerShell boolean literal, not a word: {snapshot}"
                );
            }
        }
    }

    /// `-Command` carries a quoted registry path intact. The apply commands embed
    /// one anyway (`reg add "HKLM\..."`); a runner that let the shell eat those
    /// quotes would fail in exactly the place the snapshot just stopped failing.
    /// Read-only on purpose.
    #[test]
    fn a_quoted_registry_path_survives_the_powershell_runner() {
        let out = crate::hardening::ps_run(
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\" /v ProgramFilesDir",
        )
        .expect("a read-only reg query must run");
        assert!(
            out.contains("ProgramFilesDir"),
            "the quoted path did not reach reg.exe: {out}"
        );
    }

    /// The firewall is driven through the COM API now, so what used to be a
    /// parser for `netsh`'s English text is a translation into the typed values
    /// the API takes: the words the UI and the request payload use on one side,
    /// the protocol numbers and direction enums Windows enforces on the other.
    /// `Any` stays the word the screens have always shown for an unset field.
    #[test]
    fn the_firewall_speaks_the_api_s_own_language() {
        use crate::firewall::{
            action_name, action_of, direction_name, direction_of, or_any, protocol_of,
        };
        use windows::Win32::NetworkManagement::WindowsFirewall::{
            NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP,
            NET_FW_IP_PROTOCOL_UDP, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        };

        // Directions and actions: the payload's words in, the shown word out.
        assert_eq!(direction_of("out"), Some(NET_FW_RULE_DIR_OUT));
        assert_eq!(direction_of(" In "), Some(NET_FW_RULE_DIR_IN));
        assert_eq!(direction_of("both"), None, "the API has no `both`");
        assert_eq!(direction_name(NET_FW_RULE_DIR_OUT), "Out");
        assert_eq!(direction_name(NET_FW_RULE_DIR_IN), "In");
        assert_eq!(action_of("block"), Some(NET_FW_ACTION_BLOCK));
        assert_eq!(action_of("Allow"), Some(NET_FW_ACTION_ALLOW));
        assert_eq!(action_of("drop"), None);
        assert_eq!(action_name(NET_FW_ACTION_BLOCK), "Block");
        assert_eq!(action_name(NET_FW_ACTION_ALLOW), "Allow");

        // Protocols: the words `netsh` took, plus the numbers the API also
        // accepts, and nothing that is not a protocol at all.
        assert_eq!(protocol_of("any").map(|p| p.0), Some(NET_FW_IP_PROTOCOL_ANY.0));
        assert_eq!(protocol_of("TCP").map(|p| p.0), Some(NET_FW_IP_PROTOCOL_TCP.0));
        assert_eq!(protocol_of("udp").map(|p| p.0), Some(NET_FW_IP_PROTOCOL_UDP.0));
        assert_eq!(protocol_of("6").map(|p| p.0), Some(NET_FW_IP_PROTOCOL_TCP.0));
        assert_eq!(protocol_of("47").map(|p| p.0), Some(47), "GRE is a real protocol");
        assert_eq!(protocol_of("tcp/udp"), None);
        assert_eq!(protocol_of("999"), None, "a byte holds a protocol number");

        // One state, one spelling: `netsh` printed `Any`, the API returns an
        // empty address string or `*`, and the screens show `Any`.
        assert_eq!(or_any(""), "Any");
        assert_eq!(or_any("*"), "Any");
        assert_eq!(or_any(" 10.0.0.0/8,192.168.0.0/16 "), "10.0.0.0/8,192.168.0.0/16");
    }

    /// A port rule without a protocol is refused before it reaches Windows -
    /// which would answer with a bare `E_INVALIDARG` - and a rule without a
    /// profile is *not* what the API's defaults would give (no profile at all,
    /// so a rule that never fires), which is why the code sets the mask.
    #[test]
    fn a_port_rule_needs_a_protocol_and_every_rule_gets_every_profile() {
        use crate::firewall::{add_rule_now, AddRuleRequest};

        let port_rule = |protocol: Option<&str>| AddRuleRequest {
            name: "verify-port".into(),
            direction: "out".into(),
            action: "block".into(),
            protocol: protocol.map(String::from),
            remote_ip: None,
            local_port: Some("4444".into()),
            remote_port: None,
            program: None,
        };
        let refused = add_rule_now(&port_rule(None)).expect_err("no protocol, no port rule");
        let message = format!("{refused:#}");
        assert!(
            message.contains("protocol") && message.contains("tcp"),
            "the refusal names the missing piece and the fix: {message}"
        );

        // The protocol is translated before anything is created, so a bad word
        // is also a refusal the caller can act on rather than an HRESULT.
        let mistyped = add_rule_now(&port_rule(Some("tcp/udp"))).expect_err("not a protocol");
        assert!(
            format!("{mistyped:#}").contains("tcp/udp"),
            "the refusal quotes what it did not understand"
        );

        use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE2_ALL;
        assert_eq!(
            NET_FW_PROFILE2_ALL.0, 0x7FFF_FFFF,
            "the mask the code sets on every rule is `all profiles`"
        );
    }

    /// The `MICS-` prefix marks ownership of a rule, so it is added exactly once
    /// however the caller spelled the name - and a name an older build doubled is
    /// still removable by either spelling. Before this, `add` prefixed
    /// unconditionally while `remove` stripped an *optional* prefix, so the two
    /// spellings named two different rules and a stray **blocking** rule could
    /// outlive the removal that reported success (register 7, MED).
    #[test]
    fn a_rule_name_carries_one_prefix_however_it_is_spelled() {
        use crate::firewall::{owned_rule_name, RULE_PREFIX};

        let canonical = "MICS-guard-test";
        for spelling in [
            "guard-test",
            "MICS-guard-test",
            "mics-guard-test",
            "MICS-MICS-guard-test",
            "  mics-MICS-guard-test  ",
        ] {
            assert_eq!(
                owned_rule_name(spelling).expect(spelling),
                canonical,
                "`{spelling}` names the rule `{canonical}`"
            );
        }

        // Every other rule is untouched: the prefix is the engine's, the rest of
        // the name belongs to the caller.
        assert_eq!(
            owned_rule_name("BLOCK-RU").expect("a country rule"),
            "MICS-BLOCK-RU"
        );
        assert_eq!(
            owned_rule_name("MICS-BLOCK-RU").expect("already canonical"),
            "MICS-BLOCK-RU"
        );

        // A name that is only the prefix is not a name: refused with a sentence
        // that quotes the prefix. The check runs before any COM call, so this
        // test touches no firewall.
        for empty in ["MICS-", "mics-", "MICS-MICS-", "   "] {
            let refused = owned_rule_name(empty).expect_err("not a name");
            assert!(
                format!("{refused:#}").contains(RULE_PREFIX),
                "the refusal quotes the prefix that needs a name after it: {refused:#}"
            );
        }
    }

    /// Compiles each script with `[scriptblock]::Create` in one PowerShell
    /// process (a parse, never an execution) and reports every one that fails.
    fn assert_scripts_parse(scripts: &[(String, String)]) {
        let dir = std::env::temp_dir().join(format!("mics-ps-parse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp dir for the parse check");
        for (index, (name, script)) in scripts.iter().enumerate() {
            std::fs::write(dir.join(format!("{index:02}-{name}.ps1")), script)
                .expect("write the script to parse");
        }
        let command = format!(
            "$bad=0; Get-ChildItem -LiteralPath '{}' -Filter *.ps1 | Sort-Object Name | \
             ForEach-Object {{ try {{ $null=[scriptblock]::Create((Get-Content -Raw -LiteralPath $_.FullName)) }} \
             catch {{ $bad=1; Write-Output ('PARSE-FAIL ' + $_.Name + ': ' + $_.Exception.Message) }} }}; \
             exit $bad",
            dir.display()
        );
        let out = match crate::hardening::ps_run(&command) {
            Ok(text) => text,
            // The parse check itself exits 1 when a script does not compile, and
            // `ps_run` turns that into the PowerShell text we want to show.
            Err(e) => format!("{e:#}"),
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !out.contains("PARSE-FAIL"),
            "a script we generate does not parse:\n{out}"
        );
    }

    #[test]
    fn service_definition_quotes_the_install_path() {
        use crate::privileged::service::{bin_path, parse_query};
        use crate::privileged::SERVICE_COMMAND;
        let path = Path::new(r"C:\Program Files\MI CS\mics-engine.exe");
        assert_eq!(
            bin_path(path),
            format!("\"C:\\Program Files\\MI CS\\mics-engine.exe\" {SERVICE_COMMAND}")
        );
        // The service body is a subcommand. Spelled `--helper-service` the SCM
        // starts a process that clap refuses (exit 2) and then only reports
        // `sc start failed: 1053` — which is exactly how this shipped once, with
        // this very test asserting the broken string. So assert the *shape*, not
        // a literal: the built binPath must never contain a `--` flag.
        assert!(
            !bin_path(path).contains("--"),
            "the service body is a subcommand, not a flag: {}",
            bin_path(path)
        );
        assert!(bin_path(path).ends_with(SERVICE_COMMAND));
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
        // Parsing a state must not invent a registration: the program a service
        // runs comes from `sc qc`, which only `query()` may run.
        assert_eq!(stopped.binary, None);
        assert!(!stopped.binary_missing);
    }

    #[test]
    fn service_config_parsing_finds_the_registered_program() {
        use crate::privileged::service::{binary_is_missing, parse_qc};
        // The shape `sc qc` prints for the helper: a quoted program (the install
        // path contains spaces) followed by the service subcommand.
        let helper = "\r\nSERVICE_NAME: MICSHelper\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        BINARY_PATH_NAME   : \"C:\\Program Files\\MI CS\\mics-engine.exe\" helper-service\r\n        START_TYPE         : 2   AUTO_START\r\n";
        assert_eq!(
            parse_qc(helper).as_deref(),
            Some(r"C:\Program Files\MI CS\mics-engine.exe")
        );
        // A service installed without quotes and without arguments (measured
        // against `sc qc Spooler` on Windows 11, 2026-11-07).
        let plain = "        BINARY_PATH_NAME   : C:\\WINDOWS\\System32\\spoolsv.exe\n        LOAD_ORDER_GROUP   : SpoolerGroup\n";
        assert_eq!(
            parse_qc(plain).as_deref(),
            Some(r"C:\WINDOWS\System32\spoolsv.exe")
        );
        // Nothing to read: a failed query, a line that is not this one, and an
        // unterminated quote. Guessing would let the caller report a stale
        // service that is not there.
        assert_eq!(parse_qc("[SC] OpenService FAILED 1060:"), None);
        assert_eq!(parse_qc("        START_TYPE         : 2   AUTO_START\n"), None);
        assert_eq!(
            parse_qc("        BINARY_PATH_NAME   : \"C:\\gone.exe helper-service\n"),
            None
        );
        assert_eq!(parse_qc("        BINARY_PATH_NAME   :\n"), None);

        // The stale case the message is built from: a registered program that is
        // not on disk, versus a real one, versus no answer at all.
        assert!(binary_is_missing(Some(r"C:\no-such-folder-mics\mics-engine.exe")));
        assert!(!binary_is_missing(None));
        let here = std::env::current_exe()
            .expect("the test binary has a path")
            .to_string_lossy()
            .to_string();
        assert!(!binary_is_missing(Some(here.as_str())));
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
        // The helper only answers the engine image (F-2). A test binary is
        // `mics-engine-<hash>.exe`, so the test names itself through the same hook
        // the installer uses instead of loosening the check for everyone.
        let own_exe = std::env::current_exe().expect("the test binary has a path");
        unsafe {
            std::env::set_var("MICS_HELPER_LOG", &log);
            std::env::set_var("MICS_HELPER_PIPE", format!("mics_helper_test_{}", std::process::id()));
            std::env::set_var("MICS_ENGINE_PATH", &own_exe);
        }

        // A document that is not ours is refused *before* anything is logged as
        // started, and the answer is the envelope the client expects.
        let refused = server::respond(&Op::HostsWrite {
            content: "no marker here\n".into(),
        });
        assert!(refused.contains("\"ok\":false"), "{refused}");
        assert!(refused.contains("marker"), "{refused}");

        // Cargo captures this unless the case fails, and on a machine whose default
        // owner policy differs from this one the facts are exactly what a log needs to
        // name the refusal (D-030). GitHub's runner needed them and could not be read
        // without a signed-in browser.
        eprintln!(
            "facts: installer={:?} caller={:?} log={}",
            crate::platform::windows::caller::installer_account(),
            crate::platform::windows::caller::describe(std::process::id())
                .map(|caller| (caller.sid, caller.is_administrator)),
            log.display()
        );

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

    #[test]
    fn the_local_admin_list_parser_reads_between_the_separators() {
        use crate::platform::windows::collectors::parse_admin_list;
        // The shape `net localgroup Administrators` prints, separators included.
        let text = "Alias name     Administrators\nComment        Administrators have complete access\n\n\
                    Members\n\
                    -------------------------------------------------------------------\n\
                    Administrator\n\
                    DESKTOP\\ibrahim\n\
                    -------------------------------------------------------------------\n\
                    The command completed successfully.\n\n";
        assert_eq!(
            parse_admin_list(text),
            vec!["Administrator".to_string(), "DESKTOP\\ibrahim".to_string()]
        );
        // A refused query prints no list: empty, never a phantom member.
        assert!(parse_admin_list("The command completed successfully.\n").is_empty());
        assert!(parse_admin_list("").is_empty());
    }

    /// Every spawn site that used to be a bare `Command::output()` now runs
    /// through `process::ToolCall`, and this aims **each site's own call** at a
    /// program that never returns: the deadline is proven per call site, not
    /// assumed from the shape of the code. One failure names the site.
    #[test]
    fn every_spawn_site_enforces_its_deadline() {
        use crate::platform::windows::process::{assert_deadline_is_enforced, ToolCall};

        let sites: Vec<ToolCall> = vec![
            // Audit: `net localgroup` and Defender's WMI status query.
            crate::platform::windows::collectors::admin_probe(),
            crate::platform::windows::collectors::defender_rtp_probe(),
            // Update: `Expand-Archive` of the staged zip.
            crate::update::extract_call("update.zip", "extracted"),
            // Autostart entry: service.install / service.remove.
            crate::dispatcher::reg_entry(
                "add",
                &["/f"],
                "reg add (service.install: autostart entry)",
            ),
            // Startup: the one-time data-directory ACL grant.
            crate::settings::data_dir_acl_call(std::path::Path::new(r"C:\x"), "user"),
            // Guard: the tree-kill responder.
            crate::guard::taskkill_call(4321),
            // Privileged helper: every `sc.exe` call (query/create/start/stop/delete).
            crate::privileged::service::sc_call(vec!["query".to_string()]),
        ];
        assert_eq!(sites.len(), 7, "a spawn site was added or removed — cover it here");
        for call in sites {
            assert_deadline_is_enforced(call);
        }
    }

    /// One finding per section, secure or failing on demand.
    ///
    /// It reproduces the real collectors' display-name collision on purpose:
    /// `rdp` and `remote_tools` both report their findings under "Remote Access",
    /// which is exactly what a merge keyed by display name would get wrong.
    #[derive(Default)]
    struct SectionMock {
        secure: Vec<&'static str>,
        failing: Vec<&'static str>,
    }

    impl SectionMock {
        fn secure_only(ids: &[&'static str]) -> Self {
            Self {
                secure: ids.to_vec(),
                failing: Vec::new(),
            }
        }

        fn section(
            &self,
            id: &'static str,
        ) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            if self.failing.contains(&id) {
                anyhow::bail!("{id} collector failed");
            }
            let display = match id {
                "rdp" | "remote_tools" => "Remote Access",
                "defender" => "Defender",
                "firewall" => "Firewall",
                "smbv1" => "Legacy Protocols",
                "uac" => "Account Control",
                "admins" => "Local Admins",
                _ => "Hosts File",
            };
            let secure = self.secure.contains(&id);
            Ok(vec![crate::platform::traits::AuditFinding {
                section: display.to_string(),
                item: format!("{id} check"),
                status: if secure {
                    crate::platform::traits::FindingStatus::Secure
                } else {
                    crate::platform::traits::FindingStatus::Vulnerable
                },
                // Low = penalty 3, so eight insecure sections score 76 and one
                // fix is a visible +3 rather than a saturating 0.
                severity: crate::platform::traits::Severity::Low,
                description: format!("{id} state"),
                fix_available: true,
            }])
        }
    }

    #[async_trait::async_trait]
    impl crate::platform::traits::PlatformCollectors for SectionMock {
        async fn audit_defender(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("defender")
        }
        async fn audit_firewall(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("firewall")
        }
        async fn audit_rdp(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("rdp")
        }
        async fn audit_smbv1(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("smbv1")
        }
        async fn audit_uac(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("uac")
        }
        async fn audit_admins(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("admins")
        }
        async fn audit_hosts_file(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("hosts")
        }
        async fn audit_remote_tools(&self) -> anyhow::Result<Vec<crate::platform::traits::AuditFinding>> {
            self.section("remote_tools")
        }
        async fn audit_startup(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::StartupEntry>> {
            Ok(Vec::new())
        }
        async fn audit_scheduled_tasks(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::ScheduledTaskEntry>> {
            Ok(Vec::new())
        }
        async fn get_network_connections(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::NetworkConnection>> {
            Ok(Vec::new())
        }
        async fn get_software_inventory(
            &self,
        ) -> anyhow::Result<Vec<crate::platform::traits::SoftwareEntry>> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn a_merged_audit_keeps_the_score_and_every_other_section() {
        use crate::platform::traits::{collect_audit, AuditCache};

        let mut cache = AuditCache::default();
        let base = collect_audit(&SectionMock::default(), None).await;
        cache.remember(base);

        // The user fixed RDP: only that section is re-read.
        let fresh = collect_audit(
            &SectionMock::secure_only(&["rdp"]),
            Some(&["rdp".to_string()]),
        )
        .await;
        let report = cache
            .merge(fresh, &["rdp".to_string()])
            .expect("a remembered full audit is a base");

        assert_eq!(report["partial"], serde_json::json!(false), "the merged report is complete");
        assert_eq!(report["merged"], serde_json::json!(true));
        assert_eq!(report["refreshed"], serde_json::json!(["rdp"]));
        assert_eq!(
            report["sections"].as_array().map(|s| s.len()),
            Some(10),
            "every section is still reported (8 checks + 2 inventory lists)"
        );

        let findings = report["findings"].as_array().expect("findings");
        assert_eq!(findings.len(), 8, "the RDP finding is replaced, not duplicated");
        let remote: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["section"] == "Remote Access")
            .collect();
        assert_eq!(
            remote.len(),
            2,
            "both sections that display as 'Remote Access' survive a merge"
        );
        let rdp = remote.iter().find(|f| f["item"] == "rdp check").expect("rdp");
        assert_eq!(rdp["status"], serde_json::json!("Secure"));
        let tools = remote
            .iter()
            .find(|f| f["item"] == "remote_tools check")
            .expect("remote_tools");
        assert_eq!(
            tools["status"],
            serde_json::json!("Vulnerable"),
            "an untouched section keeps its finding"
        );
        // Eight insecure Low findings = 24 penalty -> 76; fixing RDP -> 21 -> 79.
        assert_eq!(report["score"], serde_json::json!(79));
    }

    /// A merged report is honest about age: the sections the merge did not re-read
/// keep the time they were actually collected, and the ones it did re-read carry
/// the new time. Without this the UI could only show one timestamp for the whole
/// report, which is wrong for every section but the refreshed one.
#[tokio::test]
    async fn a_merged_audit_keeps_the_age_of_every_section_it_did_not_re_read() {
        use crate::platform::traits::{collect_audit, AuditCache};

        let mut cache = AuditCache::default();
        let mut base = collect_audit(&SectionMock::default(), None).await;
        assert_eq!(base.stamps.len(), 10, "8 checks + 2 inventory lists, each stamped");
        // Make both sections visibly old, so "it moved" cannot be a same-second
        // coincidence (the stamps have one-second resolution).
        base.stamps.insert("defender".to_string(), 1_000_000);
        base.stamps.insert("rdp".to_string(), 1_000_000);
        cache.remember(base);

        let fresh = collect_audit(
            &SectionMock::secure_only(&["rdp"]),
            Some(&["rdp".to_string()]),
        )
        .await;
        let report = cache.merge(fresh, &["rdp".to_string()]).expect("base");

        let times = report["section_times"].as_object().expect("section_times");
        assert_eq!(
            times["defender"], serde_json::json!(1_000_000),
            "an untouched section keeps the time it was really collected"
        );
        assert!(
            times["rdp"].as_i64().unwrap_or(0) > 1_000_000,
            "a refreshed section carries the re-read's time, not the old one: {times:?}"
        );
        assert_eq!(
            times.len(),
            10,
            "every section still has a stamp, merged or not"
        );

        // A finding names the section id it came from: the display name is not
        // unique, and the UI resolves the age through the id.
        let handled = ["defender", "firewall", "rdp", "smbv1", "uac", "admins", "hosts", "remote_tools"];
        for finding in report["findings"].as_array().expect("findings") {
            let id = finding["id"].as_str().expect("every finding carries its section id");
            assert!(handled.contains(&id), "unexpected section id {id}");
        }
    }

    #[tokio::test]
    async fn a_section_that_fails_on_the_re_read_leaves_no_stale_finding() {
        use crate::platform::traits::{collect_audit, AuditCache};

        let mut cache = AuditCache::default();
        cache.remember(collect_audit(&SectionMock::default(), None).await);
        let failing = SectionMock {
            failing: vec!["rdp"],
            ..Default::default()
        };
        let fresh = collect_audit(&failing, Some(&["rdp".to_string()])).await;
        let report = cache
            .merge(fresh, &["rdp".to_string()])
            .expect("the base is there");

        assert_eq!(
            report["sections"].as_array().map(|s| s.len()),
            Some(9),
            "a section whose collector failed is reported as not run (7 checks + 2 lists)"
        );
        assert!(
            report["findings"]
                .as_array()
                .expect("findings")
                .iter()
                .all(|f| f["item"] != "rdp check"),
            "the old finding must not stay behind pretending to be fresh"
        );
        assert!(
            report["section_times"].get("rdp").is_none(),
            "nor may its age stay behind: a section that did not run has no time"
        );
    }

    #[tokio::test]
    async fn merging_without_a_full_audit_is_refused() {
        use crate::platform::traits::{collect_audit, AuditCache};

        let mut cache = AuditCache::default();
        let fresh = collect_audit(
            &SectionMock::secure_only(&["rdp"]),
            Some(&["rdp".to_string()]),
        )
        .await;
        let err = cache
            .merge(fresh, &["rdp".to_string()])
            .expect_err("a partial report cannot be the base");
        let message = format!("{err:#}");
        assert!(message.contains("no full audit"), "{message}");
    }

    #[test]
    fn merge_needs_sections_and_a_boolean() {
        use crate::platform::traits::merge_requested;
        use serde_json::json;

        let sections = vec!["rdp".to_string()];
        assert!(!merge_requested(None, None).unwrap());
        assert!(!merge_requested(Some(&json!({})), None).unwrap());
        assert!(
            !merge_requested(Some(&json!({"merge": false})), None).unwrap(),
            "an explicit false is still a normal audit"
        );
        assert!(merge_requested(Some(&json!({"merge": true})), Some(&sections)).unwrap());
        assert!(
            merge_requested(Some(&json!({"merge": true})), None).is_err(),
            "merging with nothing to re-read is a full audit, not a merge"
        );
        assert!(
            merge_requested(Some(&json!({"merge": "yes"})), Some(&sections)).is_err(),
            "a non-boolean merge must be refused, never guessed"
        );
    }

    /// `attempt to write a readonly database` is an access refusal, but the
    /// sentence reads like a damaged file — a user spent a session looking at
    /// the database while the folder's label was the problem
    /// (`docs/TODO.md` trap 21). The RPC error must carry the directory and the
    /// repair, not just SQLite's words.
    #[test]
    fn a_readonly_database_failure_names_the_directory_and_the_fix() {
        let err = anyhow::anyhow!(
            "sync.now failed: attempt to write a readonly database: Error code 8: \
             Attempt to write a readonly database"
        );
        let hint = crate::dispatcher::readonly_hint(&err).expect("this is a readonly failure");
        let dir = crate::settings::Settings::base_dir();
        assert!(
            hint.contains(&dir.display().to_string()),
            "the hint must name {dir:?}: {hint}"
        );
        assert!(
            hint.contains("not writable") && hint.contains("administrator"),
            "the hint must say what is wrong and what to do: {hint}"
        );
        assert!(
            hint.contains("integrity"),
            "the hint must mention the integrity level it measured: {hint}"
        );

        // Everything else keeps its own message: no SQLite hint on a timeout.
        assert!(
            crate::dispatcher::readonly_hint(&anyhow::anyhow!("the operation timed out")).is_none()
        );
    }

    /// The integrity guard is about serving state, not about being able to
    /// inspect the helper: `helper-status`/`helper-console` must keep working at
    /// Low (they are how a Low run is diagnosed), every other command must not.
    #[test]
    fn only_the_helper_inspection_commands_run_below_medium() {
        let low_safe = [
            Some(crate::Commands::HelperStatus { json: true }),
            Some(crate::Commands::HelperConsole),
            Some(crate::Commands::HelperService),
        ];
        for command in low_safe {
            assert!(
                !crate::needs_normal_integrity(&command),
                "{command:?} must stay usable for diagnosis"
            );
        }
        let stateful = [
            Some(crate::Commands::Serve),
            Some(crate::Commands::Service { parent: None }),
            Some(crate::Commands::Scan {
                path: "C:\\".into(),
                quarantine: false,
                json: false,
            }),
            Some(crate::Commands::InstallHelper),
        ];
        for command in stateful {
            assert!(
                crate::needs_normal_integrity(&command),
                "{command:?} must not serve state below Medium"
            );
        }
    }
}
