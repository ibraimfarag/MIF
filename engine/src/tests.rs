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
}
