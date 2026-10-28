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
}
