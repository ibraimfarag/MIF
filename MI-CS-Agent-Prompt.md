# 🛡️ MI CS — Project Brief & Build Prompt (v2.2)
# MI CS = Mourad Ibrahim — Cyber Security
# Copy this entire file to the agent. The agent must follow it exactly.

---

# 0) COMMUNICATION RULES (HIGHEST PRIORITY)

1. This prompt is written in English, but **you MUST always reply to the user in Egyptian Arabic (العربية المصرية)** — every status update, explanation, question, and summary. Code, identifiers, commit messages, and docs stay in English.
2. Do NOT paraphrase or weaken the specs. If a decision is not covered, pick the simplest reliable option and explain it in Egyptian Arabic.
3. Execute phases IN ORDER. After each phase: show what was built + acceptance proof (real command output) + wait for user confirmation.

# 1) PROJECT DESCRIPTION

**MI CS** (Mourad Ibrahim — Cyber Security) is a free, open-source, cross-platform cybersecurity command center: multi-layer defense wall + malware scanner + real-time process/network monitor + vulnerability scanner + hardening center — with a **smart UI** that adapts, prioritizes, and explains. Built by the community, for the community.

**This is a PRODUCT for ANY computer in the world — not a tool for one machine:**
- Platform order: **Windows first (v1.0) → Linux (v1.x) → macOS (v2.x)**. All three are first-class targets; the platform-trait rule (section 2) makes each a port, not a rewrite.
- Performance baseline is a LOW-END machine: Windows 10 21H2+ or Windows 11, 4-core CPU / 8 GB RAM / HDD (budgets in section 15). Nothing may assume a developer-grade PC.
- No user-specific paths, no hardcoded names, no machine-specific assumptions — standard config/data dirs per OS everywhere.

**Product identity:**
- Name everywhere: **MI CS** (app title, window title, pipe name, data folder, AUMID, README).
- Tagline (AR): "حماية ذكية، شفافة، ومفتوحة المصدر" / (EN): "Smart. Transparent. Open-source defense."
- **License: GPL-3.0-or-later.** Every dependency must be GPL-compatible (ClamAV GPL is fine; avoid anything non-commercial-only). The repo ships LICENSE, README (AR+EN), CONTRIBUTING.md, SECURITY.md, and a GitHub Actions CI from day one.
- **No telemetry, ever.** No accounts, no paid tiers, no ads. Optional donations link only.

**Defense in Depth — 5 layers:**
- **L1 Network Gate:** managed firewall (Default-Deny Outbound) + GeoIP country blocking + DNS filtering
- **L2 Attack Radar:** IDS (Suricata/ET-Open rules) — design-first, implemented late
- **L3 Response:** real-time process monitoring (ETW) + automatic response (kill tree + quarantine)
- **L4 File Engines:** YARA + ClamAV signature sets + daily IOC feeds + VirusTotal + CAPA capability analysis
- **L5 Mind:** event correlation into incidents + local LLM assistant (LM Studio) that explains threats in the user's language

**Product principles:**
- **Offline-First:** all core features (audit, firewall, ETW guard, YARA, canaries, quarantine) work with zero internet. Internet only enriches intel; offline the app uses last-synced intelligence and says so.
- **Complete System:** the engine runs 24/7 as a background service, even when the UI is closed.
- **Smart by design:** the app doesn't just show data — it prioritizes, correlates, explains, and suggests the next action (section 7).
- **Full transparency:** everything local in SQLite; nothing leaves the machine except explicit VT/NVD/LLM lookups.

# 2) ARCHITECTURE

```
┌───────────────────────────────────────────┐
│  MI CS Desktop UI (app/) — Flutter        │
│  12 screens, dark theme, AR/EN, smart UX  │
└──────────────┬────────────────────────────┘
               │ JSON-RPC 2.0 over Named Pipe (primary)
               │      \\.\pipe\mics_engine
               │      (stdio kept for CLI mode)
┌──────────────▼────────────────────────────┐
│  mics_engine.exe  (Rust)                  │
│  modes: --serve | --service | CLI actions │
│  collectors │ scanner │ firewall │ guard  │
│  storage: SQLite │ sync manager │ notify  │
│  smart: triage.rs correlator.rs nlp_cmd.rs│
└───────────────────────────────────────────┘
```

**Mandatory architecture rules:**
1. The UI NEVER touches OS APIs directly — everything goes through the engine.
2. The engine accepts ONLY whitelisted commands; anything else → JSON-RPC error.
3. Admin-required operations are done by the engine via self-elevation (`ShellExecuteW runas`) on demand; the app starts unelevated.
4. Every collector works standalone via CLI (e.g. `mics_engine.exe --audit --json`).
5. **Platform portability rule (from day one):** all OS-specific code lives behind Rust traits (`PlatformCollectors`, `PlatformFirewall`, `PlatformGuard`, `PlatformNotify`) with a `windows/` implementation now — Linux and macOS are new implementations, not rewrites. The Flutter UI must contain ZERO OS-specific logic.
6. Engine lifecycle: scheduled task at logon, `--service` mode, listening on the pipe. Closing the UI → tray; engine keeps protecting.

# 3) ENVIRONMENT

- Windows 11 x64, Git Bash available.
- Pre-installed: Visual Studio 2026 Community (MSVC 14.50 + SDK 10.0.26100), CMake 3.29, Git 2.55, Node 24.
- Install first (Phase 0):
  - Flutter stable 3.47.8 x64: `https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_3.47.8-stable.zip` → extract to `C:\dev\flutter`, add to PATH.
  - Rust via rustup: `https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe -y` (stable-msvc).
  - Verify: `flutter doctor` (ignore Android), `cargo --version`.

# 4) REPO STRUCTURE (Monorepo)

```
C:\Users\<account>\Projects\mi-cs\
├─ app\                      # Flutter (flutter create --platforms=windows mics_app)
│  └─ lib\
│     ├─ main.dart
│     ├─ core\              # theme, router, ipc_client, i18n, connectivity_watcher
│     ├─ models\            # engine JSON schema mirrors
│     ├─ providers\         # Riverpod
│     └─ features\          # one folder per module (12)
├─ engine\                   # Rust crate: mics-engine
│  └─ src\
│     ├─ main.rs            # CLI + mode dispatch
│     ├─ rpc.rs             # JSON-RPC dispatch + whitelist + pipe/stdio
│     ├─ platform\          # traits.rs + windows\ (collectors, firewall, guard impls)
│     ├─ scanner\           # yara_engine.rs hash.rs triage.rs ioc_feeds.rs vt.rs capa.rs quarantine.rs
│     ├─ firewall\          # wfp_rules.rs geoip.rs dns_filter.rs
│     ├─ guard\             # etw_sessions.rs rules_engine.rs responder.rs canary.rs
│     ├─ smart\             # correlator.rs (incidents) nlp_cmd.rs (NL commands) noise_learner.rs
│     ├─ sync\              # connectivity.rs sync_queue.rs feeds_updater.rs
│     ├─ notify\            # toast.rs (Windows Toast)
│     ├─ update\            # self_updater.rs
│     ├─ vulns\             # inventory.rs cpe_match.rs nvd_client.rs
│     ├─ llm\               # lmstudio_client.rs (OpenAI-compatible)
│     └─ storage\           # sqlite.rs migrations.rs
├─ rules\                    # yara\ sigma\ blocklists\
├─ docs\                     # this file, decisions log, THREAT-MODEL.md
├─ LICENSE (GPL-3.0) ├─ README.md (AR+EN) ├─ CONTRIBUTING.md ├─ SECURITY.md
└─ .github\workflows\ci.yml # build + clippy + analyze on push
```

# 5) IPC PROTOCOL (mandatory)

- JSON-RPC 2.0, JSON-Lines, UTF-8. Transport per OS (identical messages everywhere): Windows = named pipe `\\.\pipe\mics_engine`; Linux/macOS = Unix domain socket; stdio (`--serve`) everywhere for CLI/testing.
- Request: `{"jsonrpc":"2.0","id":42,"method":"audit.run","params":{"sections":["defender"]}}`
- Push events: `{"jsonrpc":"2.0","method":"event","params":{"type":"threat_detected","data":{...}}}`
- Progress: `{"jsonrpc":"2.0","method":"progress","params":{"id":42,"pct":37,"detail":"..."}}`
- Auto-reconnect backoff 1→2→5→10s; heartbeat `ping` every 15s.

Whitelist (v1):
`ping` | `status` | `audit.run` | `net.connections` | `fw.rules.list/add/remove` | `fw.default_deny.enable/disable` | `scan.start/stop` | `quarantine.list/restore/delete` | `vuln.scan` | `guard.start/stop` | `guard.rules.list/add` | `defender.scan.quick/full` | `hardening.apply/rollback` | `llm.explain` | `report.export` | `sync.now` | `sync.status` | `update.check/install` | `notify.test` | `nl.command` | `incident.list/detail`

Events: `process_created` | `net_connection` | `dns_query` | `threat_detected` | `canary_triggered` | `firewall_blocked` | `incident_created` | `sync.updated` | `update.available` | `engine.state`

# 6) OFFLINE-FIRST + UPDATE SYSTEM

**Local intelligence cache (SQLite):**
`ioc_hashes(sha256, source, added_at)` | `ioc_domains(domain, source, category, added_at)` | `yara_rules(id, name, body, source, version, enabled)` | `geoip(ip_range, country, asn)` | `cve_cache(cve_id, cvss, affected_cpe, published, fetched_at)` | `sync_state(source, last_success, version, next_due)`

**Sync manager:**
1. Connectivity: Windows NLM callback + 60s fallback poll + real reachability probe.
2. On reconnect (or every N hours if auto_sync): fetch in order — IOC hashes → IOC domains → YARA packs → GeoIP (monthly) → CVE incremental. Per-source backoff + rate limits.
3. Offline: network ops queue in `sync_queue`, auto-run on reconnect; UI shows OFFLINE badge + "Intel last updated Xh ago".
4. Acceptance: internet off → audit/firewall/guard/YARA/canaries all work; reconnect → intel badge updates within 5 min.

**Self-update:** manifest JSON (GitHub Releases): `{version, url, sha256, size, notes_en, notes_ar}`; check at start + 24h + manual; download → verify SHA256 → install only on explicit user press. Silent offline.

# 7) SMART FEATURES (what "Smart App & Smart UI" means concretely)

1. **Smart Triage (engine/scanner/triage.rs):** every file gets a heuristic priority score (location × entropy × packer indicators × signature × file age) — the scanner scans the riskiest files FIRST, so real threats surface in seconds instead of minutes. Scan progress shows "triaged queue".
2. **Incident Correlator (smart/correlator.rs):** related events (process + network + DNS + file) are grouped into ONE incident with a kill-chain timeline, instead of spamming isolated alerts. Dashboard shows incidents, not raw noise.
3. **Natural-language command bar (smart/nlp_cmd.rs):** an omnibox in the app — the user types "افحص مجلد التنزيلات" or "block all traffic from Russia"; a local LLM (LM Studio, function-calling) maps it to whitelist commands ONLY. Offline fallback: regex intent matcher for ~20 common intents (scan X, block country Y, run audit...). The LLM can never execute anything outside the whitelist.
4. **Noise Learner (smart/noise_learner.rs):** if the user dismisses the same notification category 5×, the app offers to mute it. Notifications get grouped and condensed.
5. **Adaptive Dashboard:** cards re-order by current risk; a "What should I do now?" panel shows the single highest-impact next action (one-click). After every audit/hardening, the score delta is shown live (+12 → green flash).
6. **Smart UI states:** every screen has designed empty / loading / error / offline-degraded states with one-click suggested actions — never a blank screen. Skeletons + animated transitions (120–250ms).
7. **MI CS Assistant:** the LLM analyst explains any finding/incident in Egyptian Arabic or English ("explain this threat"), with graceful fallback to pre-written explanation templates when LM Studio is off.

# 8) NOTIFICATIONS SYSTEM

- Engine-side Windows Toasts via `windows` crate (`ToastNotificationManager`), AUMID `"MICS"`, so alerts fire even with UI closed.
- Routing: CRITICAL (malware, canary touched) → toast+sound+banner+tray badge; HIGH (suspicious rule fired, firewall block wave, CVE ≥ 9.0) → toast; MEDIUM/LOW → in-app only.
- Toast actions: "Open MI CS", "Quarantine". DND mode in Settings. `notify.test` command. Intel-update toasts are MEDIUM.

# 9) MODULES (12 screens)

1. **Dashboard** — security score 0–100 (critical 25/high 15/medium 8/low 3), incidents feed, live events, L1–L5 health cards, OFFLINE badge, "What should I do now?" smart panel.
2. **System Audit** — Defender+exclusions, firewall profiles, RDP, SMBv1, admins, startup, scheduled tasks, hosts, remote-access tools. Findings with severity + Fix buttons.
3. **Malware Scanner** — folder/drive scan: triage-ordered queue → SHA256 vs ioc_hashes → YARA-x → VT (online, else queued) → AES-256-GCM quarantine (DPAPI key) → quarantine manager.
4. **Network Monitor + Firewall** — live connections (process/remote/GeoIP/suspicious badge), Default-Deny Outbound toggle (FirewallAPI COM), country blocks, block log.
5. **IDS (L2)** — Suricata/ET-Open or blocklist-based minimal mode (feed domains/IPs enforced on DNS+connections); full Suricata integration late.
6. **Vulnerability Scanner** — software inventory → CPE → NVD API 2.0 (cached offline) → CVEs with CVSS.
7. **Process Guard (ETW)** — ferrisetw sessions (kernel-process + DNS), Sigma-like JSON rules hot-reloaded; starter rules: office→cmd/powershell, script from %TEMP%, schtasks by unknown parent, canary access; optional tree-kill.
8. **Canaries** — decoy files in configurable paths (ReadDirectoryChangesW); touch = CRITICAL.
9. **Hardening Center** — one-click fixes (Defender max, SMBv1 off, RDP off, SmartScreen Block, Controlled Folder Access) with AR/EN explanation + rollback snapshots.
10. **Incidents** — correlated kill-chain timelines (from correlator), export as report.
11. **Reports** — all history + Markdown/PDF export.
12. **Settings** — language AR/EN, VT key, NVD key, LM Studio URL, sync policy, notifications/DND, canary paths, boot-with-windows, updater toggle, NL command bar on/off.

# 10) UI SPEC (Dark Cyber)

- Background `#0A0E14`, surfaces `#111826`, borders `#1E293B`, cyan `#22D3EE`, green `#34D399`, red `#F43F5E`, orange `#FB923C`, text `#E2E8F0`. MI CS logo concept: shield + "MI CS" wordmark, monochrome cyan.
- Fonts: `Cairo` (AR) + `JetBrains Mono` (numbers/hashes). google_fonts.
- Left icon rail with glow selection; top bar: score, engine state, intel freshness, language toggle, NL command omnibox.
- Dashboard: animated circular gauge (CustomPainter), incident timeline, glass cards (blur 10, opacity 0.06), score delta animations.
- CVE cards: severity stripe + mono CVSS. All strings via i18n (`ar.json`/`en.json`), Arabic RTL default. Riverpod, go_router, fl_chart.

# 11) APPROVED LIBRARIES

**Flutter:** flutter_riverpod, go_router, fl_chart, window_manager, tray_manager, local_notifier, path_provider, file_selector, dio, drift, intl+flutter_localizations, google_fonts, pdf, connectivity_plus.

**Rust:** windows (Registry, IpHelper, WinSock, Shell, Notifications, Diagnostics_ETW), tokio, serde/serde_json, rusqlite (bundled), yara-x, reqwest (rustls), aes-gcm, sha2, hex, sysinfo, ferrisetw, chrono, tracing, clap, anyhow + thiserror, windows-dpapi.

**Rust rules:** no `unwrap()` in production; collectors behind platform traits with unit tests; errors as JSON-RPC errors; clippy zero warnings.

# 12) EXECUTION PHASES (order; pause after each for user confirmation)

**Phase 0 — Environment:** install Flutter + Rust. Prove with `flutter doctor` + `cargo --version`.
**Phase 1 — Skeleton + transports:** monorepo + LICENSE(GPL-3)/README/CONTRIBUTING/SECURITY + CI yml; engine `--serve` stdio ping AND `--service` pipe; Flutter connects with auto-reconnect. Prove: ping→pong log.
**Phase 2 — Engine v1:** audit collectors (Defender+exclusions, firewall, RDP, SMBv1, admins, startup, tasks, hosts, remote tools), net.connections, software inventory, platform traits scaffolding. Prove: `mics_engine.exe --audit --json` real data.
**Phase 3 — UI v1:** theme + router + 12 skeletons; full Dashboard (real score) + System Audit + smart UI states; AR/EN RTL complete. **Acceptance:** app shows real score + live audit on the user's machine.
**Phase 4 — Network + Vulns:** Network Monitor (offline GeoIP + suspicious badges), Firewall Manager (Default-Deny via COM, country blocks), Vuln Scanner (CPE→NVD cached). **Acceptance:** wf.msc shows created rules; offline keeps screens alive.
**Phase 5 — Files + sync:** triage-ordered scanning, YARA (10 starter rules), IOC feeds, quarantine AES-GCM, VT + offline queue, Defender orchestration, sync manager. **Acceptance:** EICAR detected→quarantined→restored; offline scan works; reconnect updates intel + toast.
**Phase 6 — Real-time guard + smart:** ETW guard + sigma rules hot-reload + canaries + responder; correlator (incidents); noise learner. **Acceptance:** reproduced office→cmd rule fires; canary → CRITICAL toast with UI closed; related events appear as ONE incident.
**Phase 7 — Product v1.0:** Windows toasts with actions; boot scheduled task + tray mode; self-updater; Hardening Center with rollback; Incidents screen; Reports/export; MI CS Assistant (LM Studio + NL command bar with offline regex fallback); **packaging: NSIS installer + portable ZIP + bundled offline intel pack + SHA256SUMS**; Release build + Arabic README v1. **Acceptance:** reboot → engine auto-connects; internet off → full functionality with badge; on → intel self-updates; NL bar executes whitelisted commands; a fresh install from the installer works fully offline until first sync; benchmark budgets (section 15) met and reported.

# 13) PLATFORM ROADMAP + PRODUCT-GRADE DISTRIBUTION (design now, implementations later)

**Platform order: Windows (v1.0) → Linux (v1.x) → macOS (v2.x). NO mobile targets.**

- **Windows (now):** full scope above. Packaging: NSIS/Inno installer (bundled engine exe + Flutter exe) + portable ZIP build. Code signing optional at first (document it in SECURITY.md).
- **Linux (next):** Flutter desktop + same Rust engine behind platform traits. Collectors: procfs/systemd units/journald; firewall via nftables/ufw wrappers; guard via auditd (eBPF later). Packaging: .deb + .rpm + AppImage; engine as systemd user service; notifications via org.freedesktop.Notifications; autostart via XDG autostart/systemd.
- **macOS (later):** Flutter desktop + same Rust engine. Collectors: EndpointSecurity framework (Apple's EDR API — requires entitlement; fall back to OpenBSM/log queries without it), launchd services inventory, `security` keychain audit; firewall via pf (pfctl wrapper) + NetworkExtension later; guard via EndpointSecurity auth events (kill/audit) or OpenBSM monitoring. Packaging: .app bundle + notarized .dmg (Xcode CLT needed in CI); notifications via UNUserNotificationCenter.
- **Cross-platform invariants enforced from Phase 1:** UI contains zero OS logic; all collectors behind traits; transport abstraction (named pipe / UDS); paths via `dirs`-style standard dirs; the sync/notify/update modules call the same trait API on every OS.

**Product-grade distribution requirements (start in Phase 7, mature later):**
- CI builds a release for every OS via GitHub Actions matrix (`windows-latest`, `ubuntu-latest`, `macos-latest`) on tag push → GitHub Releases with per-OS artifacts + SHA256SUMS file.
- Self-updater (section 6) reads the same manifest per-OS channel and verifies SHA256 before install.
- Offline intel packs: rules/feeds bundled in the installer so a fresh install works fully offline until first sync.
- Document per-OS data dirs: Windows `%PROGRAMDATA%\MICS\`, Linux `~/.local/state/mics/` + `/etc/mics/`, macOS `~/Library/Application Support/MICS/`.
- Document these constraints in `docs/THREAT-MODEL.md` during Phase 2.

# 14) SECURITY & HONESTY NOTES (non-negotiable)

- No kernel driver — usermode protection (ETW + WFP + watchers); stated in About.
- Engine deletes nothing except explicit quarantine commands; hardening snapshots before changes.
- Keys via DPAPI/Credential Manager, never plaintext.
- EICAR is the only test sample ever used.
- Rate limits: VT free 4/min; NVD 5/30s (50/30s with key).
- All data in standard OS dirs (section 13 list) — nothing external except explicit VT/NVD/LLM.
- GPL compliance: no dependency with incompatible license; keep `docs/DECISIONS.md` logging license choices.

# 15) QUALITY BAR + PERFORMANCE BUDGETS

- `cargo clippy` zero warnings; `cargo test` green; `flutter analyze` clean; CI green.
- One commit per phase, conventional messages.
- Code/comments in English; user-facing replies in Egyptian Arabic; UI strings via i18n.
- No placeholders, no TODOs, no stubs — everything written must actually work.

**Performance budgets (the product must run on a 4-core / 8 GB / HDD machine — measure, don't guess):**
- Engine idle: CPU < 1% average, RAM < 150 MB, zero sustained disk churn.
- During full scan: UI stays responsive (the engine runs scanning in a worker pool; the UI thread never blocks); CPU capped at ~70% unless the user raises it in Settings.
- ETW guard overhead: < 3% CPU under normal desktop load; events batched (no per-event pipeline wake-ups).
- UI cold start < 3 s on the baseline machine; installer size < 120 MB; first-run audit completes < 60 s.
- Every phase's acceptance includes: `engine.exe --benchmark` numbers reported (idle RAM/CPU measured via `sysinfo`) and no regression against the previous phase.
