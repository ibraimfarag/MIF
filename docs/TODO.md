# MI CS — Living TODO & Handoff

> **Purpose.** This is the single source of truth for *what is planned, what is
> done, what is broken, and how to verify it*. Any agent (or human) picking up
> this repo must read this file first, then `docs/DECISIONS.md`.
>
> **Update discipline.** Work on this file in the same commit as the code it
> describes: tick checkboxes, append to the Done log with the commit hash, move
> anything discovered into "Known issues", and keep "Next up" accurate. Never
> rewrite history — append.
>
> Last updated: 2026-10-29 · P1, P2 (settings/i18n/sounds/theme) and P3 (badge +
> update flow) done · **next: P1.5 (single-elevation helper)**, then P4 packaging,
> P5 documentation/hardening, P6 QA harness. README is written; the app runs
> unelevated and was verified end-to-end on a real machine.

---

## 1. What this project is

**MI CS** = Windows-first cybersecurity command center. Flutter UI + Rust engine
(`mics-engine.exe`), JSON-RPC 2.0 over `\\.\pipe\mics_engine`.
Product brief: `MI-CS-Agent-Prompt.md` (v2.2). License GPL-3.0-or-later (D-001).

Repo layout: Flutter app at **repo root** (`lib/`, `windows/`), engine in
`engine/` (Rust crate `mics-engine`), rules in `engine/rules/`, docs in `docs/`.

---

## 2. Quick start (copy-paste)

```powershell
# Engine
cd engine
$env:YRX_REGENERATE_MODULES_RS = "false"     # yara-x build script writes into the cargo registry
cargo build --release
cargo test                                    # expected: 6 passed
cargo clippy --release -- -D warnings         # expected: zero warnings

# App
cd ..
flutter analyze --no-pub                      # expected: No issues found
flutter test --no-pub                         # expected: 4 passed
flutter build windows --release

# Package the two binaries together (the app resolves mics-engine.exe beside itself)
Copy-Item engine\target\release\mics-engine.exe build\windows\x64\runner\Release\ -Force
```

If `cargo` fails with `Access is denied ... .cargo-build-lock` inside
`engine/target`, build into a writable target dir instead and copy the exe:

```powershell
$env:CARGO_TARGET_DIR = "$env:TEMP\mics-target"
cargo build --release
# then copy $env:TEMP\mics-target\release\mics-engine.exe next to mics_app.exe
```

### Run modes and test hooks

| Mode / variable | Effect |
|---|---|
| `mics-engine.exe service` | Production mode: named pipe + guard + auto-sync + auto-resume |
| `mics-engine.exe serve` | stdio JSON-RPC (CLI/tests only; **not** the UI transport) |
| `mics-engine.exe scan --path X --json` | One-off scan; waits for the job and prints the report |
| `mics-engine.exe jobs --json` / `job <id> --json` / `resume-job <id>` | Inspect/resume jobs |
| `MICS_PIPE_NAME` | Serve a different pipe (isolated dev/test engine) |
| `MICS_NO_SINGLETON=1` | Allow an engine next to the real one (with `MICS_PIPE_NAME`) |
| `MICS_NO_GUARD=1` | Do not arm the guard in service mode (tests: no canary files) |
| `MICS_NO_AUTO_RESUME=1` | Do not resume interrupted jobs at startup |
| `PROGRAMDATA` | Relocate all state (`mics.db`, `logs/`, `Quarantine/`) — used by tests |
| `MICS_ENGINE_PATH` | Force the UI to use a specific engine binary |

Data lives in `%PROGRAMDATA%\MICS\` (`mics.db`, `logs/engine.log`,
`Quarantine/`, `blocklists/`, `canaries.json`, `settings.json` — the last one is
not implemented yet, see D-008).

### Verification tools

| Tool | Proves |
|---|---|
| `dart run tool/pipe_smoke.dart` | The **production** `PipeConnection` talks to the engine (ping/status/job.list) |
| `dart run tool/pipe_probe.dart <dir>` | Raw protocol: request/response + `progress` + `job_finished` push |
| `mics-engine.exe benchmark` | RAM/CPU against the §15 budgets |

Both tools need an engine to talk to; start one with an isolated pipe first
(`MICS_PIPE_NAME`, `MICS_NO_SINGLETON`, `MICS_NO_GUARD`, `PROGRAMDATA`).

---

## 3. Where we are

**Start here if you are new:** run the four checks in section 2, launch
`build\windows\x64\runner\Release\mics_app.exe`, and read the Done log below.
Everything that could be verified without administrator rights is done; the
remaining work needs a UAC prompt you can click (P1.5) or a purchased certificate
(P4).

| Phase | Scope | State |
|---|---|---|
| P0 | Environment (Flutter/Rust) | done (pre-existing) |
| **P1** | Pipe transport, single instance, resumable jobs, window corners, engine file log, decisions log | **done — `dcce43f`** |
| **P2a** | Settings as the single source of truth + full Settings screen (D-008) | **done — `341b57c`** |
| **P2b** | Per-module i18n + live system theme (D-009) | **done — `98bd15b`** |
| **P2c** | In-house sounds, engine + UI playback (D-004) | **done — `36572cd`** |
| **P2d** | First real-run bug sweep (SMBv1 false positive, static layer cards, hang on UAC, mojibake) | **done — `747faf9`** |
| **P3a** | Offline badge, sync status, update flow, unelevated UI, real error messages, no console windows (D-010) | **done — `8836402`** |
| **P3b** | Sticky data directory with a real write test (D-011) | **done — `9ad3ad9`** |
| **README** | Bilingual, honest README (what it does / does not, requirements, data, privacy, build, testing) | **done** |
| **P1.5** | Single-elevation privileged helper (D-007) | **next — needs one interactive UAC prompt** |
| P3c | Incremental intel pipeline + dedicated sync screen; default update manifest URL | planned |
| P4 | Code signing (real cert), x64+ARM64, NSIS installer, SBOM/notices | planned |
| P5 | Threat model, integrity/anti-tamper, protection-matrix doc | planned |
| P6 | Full QA harness + HTML report, malware lab (later) | planned |

### Done log (append only)

- **P4a — the icon is now everywhere, at every size**
  - Both Windows icons shipped only 16/32/48/256, so 20/24/40/64/96/128 were
    upscaled by the shell and looked blurry. `tool/make_icons.py` now renders
    all ten standard sizes from a 256×256 PNG master (`assets/icons/mics.png`)
    into `windows/runner/resources/app_icon.ico` (embedded in `mics_app.exe`)
    and `assets/icons/mics.ico` (tray), and `test/icon_test.dart` fails the build
    if a size disappears or the two icons drift apart.
  - Verified on the built binary: the icon embedded in `mics_app.exe` is
    pixel-identical to the master at 32×32 (mean channel difference 0.00), and
    the runner loads it for the window class (`IDI_APP_ICON`), so Explorer,
    taskbar, Alt-Tab and the title bar all get the same art. The portable folder
    was refreshed and the stale `mics-engine.old.exe` removed.
- **P3b — sticky data directory (last blocker for unelevated runs)**
  - An unelevated engine still failed with *"attempt to write a readonly
    database"*: `%PROGRAMDATA%\MICS` was writable as a folder, but the database
    and its WAL sidecars had been created by a raised run and were read-only for
    the user.
  - Writability is now proven with a real `BEGIN IMMEDIATE` transaction plus
    per-file append checks; the chosen directory is recorded in
    `%LOCALAPPDATA%\MICS\.data-dir` and reused, so an elevated run and the
    unelevated autostart can never disagree about where state lives (D-011).
  - Verified: `mics-engine.exe scan --path …` runs unelevated against
    `%LOCALAPPDATA%\MICS`, scans the files and reports the YARA match; the app
    launches with no UAC, polls `sync.status` and completes an audit.
  - Docs: bilingual, honest `README.md` (what it does / does **not** do,
    requirements, data locations, privacy, five-layer matrix, build, testing,
    troubleshooting) replaces the stub.
- **P3a — updates, offline badge, sync status; elevation and data-dir fixes**
  - **Offline badge + intel freshness** in the title bar (`_IntelChip`): reads the
    engine's `sync.status` once a minute, shows Online/Offline and "intel 12m
    ago" (or "never synced"), and syncs on tap. `sync.status` gained
    `last_success` / `age_seconds` / `sync_interval_hours`, and the engine's
    reachability probe is now cached (30 s) with a 3 s deadline so an offline
    machine cannot stall a poll.
  - **Update flow** in Settings: check → show current/latest + release notes +
    channel → "Download and install" (`update.download` then `update.apply`),
    with the real error surfaced when it fails.
  - **UI is `asInvoker`** (D-010): no UAC at launch. Hardening/firewall commands
    run directly when the engine is elevated, otherwise fall back to RunAs with
    a clear message; new `app.relaunch_elevated` RPC + "Relaunch as
    administrator" button for deliberate elevation.
  - **Errors are no longer swallowed**: 33 dispatcher error paths now return the
    real reason instead of "Method failed internally".
  - **No console windows**: every `powershell` / `netsh` / `taskcmd` / `reg`
    spawn uses `CREATE_NO_WINDOW` (this is what made PowerShell flash during an
    audit fix).
  - **Data directory** resolution + one-time ACL repair (D-011); engine log falls
    back to a per-pid file when an elevated predecessor's log is not writable.
  - **Guard rules are embedded**: a missing `rules/guard` directory now falls
    back to the compiled-in starter pack instead of leaving the guard with zero
    rules; `rules/` is also shipped next to the app.
  - **Fixed a real build bug**: `windows/runner/CMakeLists.txt` added a
    `/MANIFESTUAC:requireAdministrator` link option that conflicted with
    `runner.exe.manifest`, making every build fail with
    `LNK1327 / c1010001`. The manifest is now the single source of the level.
  - Evidence: `cargo test` 12/12, `cargo clippy` clean, `flutter analyze` clean,
    `flutter test` 18/18; live run shows the app launching with no UAC, the chip
    polling `sync.status`, the guard loading the embedded rules, and a fresh
    `engine-<pid>.log` because the old log belonged to an elevated run.
- **P2d — first real run on the user's machine (bug sweep)**
  - Ran the built app for real and inspected screenshots. Found and fixed:
    - **L1–L5 cards were static** (`layersProvider` was never consumed); they now
      show live engine state (L3/L4/L5 active, L2 idle, L1 partial).
    - **SMBv1 critical false positive**: absent registry values (`SMB1` under
      LanmanServer, `mrxsmb10` key) were treated as "enabled". Audit score on the
      reference machine went 37 → 62 after the fix; the hardening card no longer
      offers a bogus fix.
    - **`hardening.apply` could hang forever** when a UAC prompt went unanswered
      (`Start-Process -Verb RunAs -Wait`); all hardening PowerShell calls now have
      a deadline and fail with an actionable error.
    - **i18n files were re-encoded as mojibake** by a PowerShell edit
      (`Get-Content -Raw` defaults to ANSI on Windows PowerShell 5.1). Repaired
      and now guarded by a test (`no mojibake in any pack`).
    - **Omnibox hint was Arabic-only**; translated and covered by the lint test.
    - **`/100` rendered reversed in RTL**; numeric suffixes are now LTR.
    - **ETW session name was fixed**, so a crashed predecessor left a stale
      kernel session that forced the 2 s poll fallback forever; the name now
      includes the pid.
    - **Engine data dir is a single function** (`Settings::base_dir`) with a
      `MICS_DATA_DIR` override, and the engine logs the resolved path at startup.
  - Evidence: `cargo test` 12/12, `cargo clippy` clean, `flutter analyze` clean,
    `flutter test` 18/18; screenshots in `_screens/` (dark English, light English,
    dark Arabic with RTL rail).
- **P2c — notification sounds (D-004)**
  - In-house WAV pack `assets/sounds/{info,success,warning,critical}.wav`
    (generated tones, no third-party licence).
  - Engine: `engine/src/notify/sound.rs` plays critical/high cues with the UI
    closed (`PlaySound` from bytes embedded in the binary), gated by
    `sound_enabled` + DND.
  - UI: `audioplayers` (MIT) + `SoundRouter` maps `canary_triggered`,
    `process_suspicious`, `threat_detected` and `job_finished` to cues, honouring
    the Settings volume slider, the toggle and DND; "play a test sound" button.
  - Evidence: `cargo clippy` clean, `cargo test` 12/12 (2 new: cue selection +
    embedded WAV validity), `flutter analyze` clean, `flutter test` 17/17
    (2 new asset checks), packaged build ships the 4 WAVs and
    `audioplayers_windows_plugin.dll`.
- **P2b — translations as module files + live theme (D-009)**
  - `assets/i18n/<lang>/<module>.json`: 16 modules, 169 keys, Arabic and
    English at full parity; loader merges modules with graceful degradation.
  - `tool/split_i18n.dart` documents the module-assignment rule and can
    re-split a flat pack.
  - Two gates: `test/i18n_parity_test.dart` (same modules, same keys, no empty
    values, same `{placeholders}`) and `test/i18n_lint_test.dart` (no
    user-facing literal inside `Text('…')`; interpolations and a small
    brand/legal allowlist excepted).
  - All 13 screens extracted to keys (buttons, labels, tooltips, hints,
    section titles, empty states and the long explanatory copy); only brand,
    licence and a literal path remain hardcoded by design.
  - Theme: `MicsApp` observes `didChangePlatformBrightness`, so "System"
    follows a Windows theme switch without restarting.
  - Evidence: `flutter test` 15/15 (5 parity + 1 lint added), `flutter analyze`
    clean, packaged build contains `data/flutter_assets/assets/i18n/{ar,en}/`
    with 16 module files each.
- **P2a — settings as the single source of truth (D-008)**
  - `engine/src/settings.rs`: typed document + defaults + `apply_patch`
    validation (unknown keys and out-of-range values are rejected with
    `-32602`), atomic save (`.tmp` + rename), process-wide cache.
  - JSON-RPC `settings.get` / `settings.set`; a successful set broadcasts
    `event{type: settings.changed}`. New `notify.test` so the UI can prove
    toasts/DND work.
  - Engine consumers now read the document instead of env vars: guard
    autostart, auto-resume, DND, LM Studio URL/model, VT key, NVD key, update
    manifest URL, auto-sync cadence (re-read each cycle → applies live).
  - UI: `AppSettings` mirrors the same snake_case keys; the Settings screen is
    complete (appearance, protection, notifications+sounds, intel+schedule,
    integrations, updates, engine, about); every control writes through
    `settings.set`; `setLang`/`setThemeMode` now patch one field instead of
    rebuilding the object (the old "changing the language wipes settings" bug);
    legacy `shared_preferences` are migrated once; the local cache exists only
    so the window paints before the engine answers.
  - Evidence: `cargo test` 10/10 (4 new settings tests), `cargo clippy` clean,
    `flutter analyze` clean, `flutter test` 9/9 (5 new model tests);
    `settings.get` returns defaults, `settings.set` persists to
    `%PROGRAMDATA%\MICS\settings.json` and emits the event, an invalid value
    (`sync_interval_hours: 0`) is rejected with the reason, `notify.test`
    returns `{"status":"sent"}`.
- `dcce43f` **P1**
  - One engine per machine (named mutex) + pipe server that survives transient
    create failures and forwards `event`/`progress` to every client.
  - UI attaches to the pipe (`lib/core/ipc/pipe_client.dart`), starts the engine
    detached only when nothing is listening; 15 s heartbeat; 1→2→5→10 s backoff.
  - Durable scan jobs: queue + cursor + findings in SQLite; `job.list/get/
    cancel/resume`; CLI `jobs`/`job`/`resume-job`; auto-resume at startup.
  - Scanner screen shows live progress and reattaches to a running job.
  - Window corners: DWM (Win11) + `SetWindowRgn` fallback (Win10), cleared when
    maximized.
  - Engine logs to stderr **and** `%PROGRAMDATA%\MICS\logs\engine.log` (5 MB
    rotation) — the detached service has no console.
  - `docs/DECISIONS.md` D-001…D-008.
  - Evidence: `cargo clippy` clean, `cargo test` 6/6, `flutter analyze` clean,
    `flutter test` 4/4, 401-file scan found a YARA match, killed engine at
    `processed=64` → resumed to `processed=401 / state=done` with findings
    intact, `tool/pipe_smoke.dart` ALL PASS.
- `cee9c57` (previous session) ETW kernel provider, actionable toast, portable
  assets.

---

## 4. User's 21-point request list — status

| # | Request | State | Where / note |
|---|---|---|---|
| 1 | Rounded window corners | **done** (needs visual check on Win10 + HiDPI) | `lib/core/window/window_corners.dart` |
| 2 | Translation as separate files with keys | **done** — 16 module files × 2 languages, 169 keys, parity + no-hardcoded-copy tests | D-009 |
| 3 | Code signing | **partial** — self-signed script works; trusted cert deferred | D-002, `scripts/sign.ps1` |
| 4 | Permissions asked once, publisher name | **todo P1.5** — today every admin op spawns its own UAC prompt | D-007 |
| 5 | Complete advanced Settings screen | **done** — 8 sections, every field writes through `settings.set` | D-008 |
| 6 | App update paths | **partial** — the manifest URL + channel are now real settings and `update.check` uses them; no extraction/apply UI, no rollback screen | P3 |
| 7 | CVE/intel update paths | **partial** — NVD keyword search + cache; no incremental sync, no scheduler UI | P3 |
| 8 | Dark/light mode | **done** — palette, System mode follows live OS switches; light contrast audit still pending | P2 |
| 9 | Not hackable / not reverse-engineerable | **todo P5** — no obfuscation, no integrity manifest; be honest in README | P5 |
| 10 | README: what it does / does not + requirements | **done** — bilingual README with a capability matrix, requirements, data locations, privacy, build and troubleshooting | `README.md` |
| 11 | x64 / x86 / ARM64 | **decided** — x64 + ARM64; 32-bit UI impossible (Flutter), ARM64 build legs pending | D-003; P4 |
| 12 | Protection types | **todo P5** — one matrix doc: layer → protects against / does not | `docs/PROTECTION-MATRIX.md` |
| 13 | Full test walk-through with a report | **todo P6** — two smoke tools exist; no feature-wide harness/report | P6 |
| 14 | Malware corpus for testing | **deferred** — EICAR only, and only inside a VM lab | P6 (later) |
| 15 | Engine restart must not lose a scan | **done** — durable jobs + auto-resume, verified | `engine/src/jobs.rs` |
| 16 | Interactive sounds + control | **done** — in-house pack, engine cue with the UI closed, UI volume/mute/DND, test button | D-004 |
| 17 | Protect the project from theft | **decided** — GPL + trademark + signing, never secrecy | D-001 |
| 18 | Cheapen the project + licenses | **partial** — GPL-3 shipped; no SBOM/NOTICES/cost sheet | P4 |
| 19 | Professional README | **done** — see row 10 | `README.md` |
| 20 | L5 wording vs reality (LLM) | **decided** — optional local LLM + templates; wording fix in P5 | D-005 |
| 21 | Living TODO/handoff file | **done** — this file | — |

---

## 5. Next up — P1.5 (single elevation)

Everything else in P2/P3 that could be verified without administrator rights is
done (settings, i18n, sounds, theme, offline badge, update flow, transport,
resumable jobs). What remains needs either one interactive UAC prompt (P1.5) or
money (P4 signing certificate).

### P1.5 — one UAC prompt, publisher-attributed (D-007)
- [ ] `docs/PRIVILEGED-OPS.md`: enumerate every admin operation (firewall
      add/remove/default-deny, hosts rewrite, hardening apply/rollback, Defender
      orchestration, startup entry).
- [ ] Windows service `MICSHelper` installed once (`sc create`) via a one-shot
      elevated helper; UI stays `asInvoker`.
- [ ] Helper protocol over its own named pipe with an ACL limited to the
      interactive user; every call logged to the state folder's `logs\priv.log`.
- [ ] Engine routes the privileged operations through the helper; remove the
      per-operation `Start-Process -Verb RunAs` calls in `firewall/mod.rs`,
      `ids/mod.rs`, `hardening/mod.rs`, and the "Relaunch as administrator" stop
      gap in the Settings screen.
- [ ] Acceptance: enabling Default-Deny, SMBv1 off and a hosts import in one
      session produces **one** UAC prompt during install and **zero** after.
- Note: the prompt shows "MI CS" as publisher only with a trusted certificate
  (D-002) — until then it shows the helper's unsigned identity.

### Leftovers from P2 (non-blocking)
- [ ] Light-mode contrast audit (text/borders/severity colours) with screenshots.
- [ ] `docs/PROTECTION-MATRIX.md` (today the README carries the matrix).

---

## 6. Backlog by phase

### P3 — updates & intel
- [x] Update check + channels + download/apply **UI** (`update.check`,
      `update.download`, `update.apply`), with release notes and real errors.
- [ ] Default update manifest URL compiled in (still user-supplied) and a signed
      manifest check before applying.
- [x] OFFLINE badge + "intel last updated Xh ago" in the title bar, tap to sync.
- [ ] Intel pipeline hardening: IOC domains → YARA packs → GeoIP in the same
      scheduled pass; per-source backoff; `sync_state.next_due`.
- [ ] A dedicated sync/intel screen with per-source results and last-error text
      (today the chip + a Settings row cover it).

### P4 — release engineering
- [ ] Authenticode: OV/EV or Azure Trusted Signing; sign DLLs then EXEs;
      timestamp; `signtool verify` in CI; document SmartScreen reality.
- [ ] Build legs: x64 (primary) + ARM64 (app + `aarch64-pc-windows-msvc` engine);
      optional x86 **CLI** build only (D-003).
- [ ] NSIS installer (bundled engine + rules + offline intel) next to the portable
      ZIP; regenerate ZIP + `SHA256SUMS` from the current build.
- [ ] SBOM (CycloneDX), `THIRD-PARTY-NOTICES`, dependency-license audit,
      `docs/COST.md` (the only real cost is the signing certificate).

### P5 — trust & truth
- [ ] `docs/THREAT-MODEL.md` (assets, adversaries, trust boundaries, what a
      usermode product cannot do: no kernel driver).
- [ ] `docs/PROTECTION-MATRIX.md`: per layer, what is detected/blocked and what is
      not (hosts-based L2, polling canaries, netsh firewall, no ClamAV/CAPA).
- [ ] Integrity: signed SHA256 manifest of shipped files, self-check at startup,
      "unofficial build" banner on mismatch.
- [ ] Build hardening: Dart `--obfuscate --split-debug-info`, Rust LTO/strip/
      `panic=abort`, PE mitigations.
- [ ] README rewrite: what it does / **does not do**, requirements (Win10 21H2+/
      Win11, x64 or ARM64, 4 cores, 8 GB, ~500 MB, one UAC at install), privacy,
      data locations, uninstall, screenshots, build instructions, GPL notice.
- [ ] Fix L5/assistant wording everywhere (README, About, brief): "event
      correlation + optional local-LLM explanations", command bar is regex.

### P6 — QA
- [ ] `qa/` harness: feature manifest → drives every JSON-RPC method (happy path,
      invalid params, permission failure, schema), UI widget tests per screen,
      E2E on the built artifact, performance budgets → `qa/report.html` + `.md`.
- [ ] CI runs the harness; a feature that is not registered fails the build.
- [ ] Malware lab (later): isolated VM + snapshots, EICAR/AMTSO first, samples
      never in the repo, detection-efficacy report.

---

## 7. Known issues / risk register

| Sev | Issue | Where |
|---|---|---|
| HIGH | Admin-only fixes (firewall/hosts/hardening) need the user to press "Relaunch as administrator" until the single-elevation helper (P1.5) lands | `dispatcher.rs`, Settings |
| HIGH | No installer; `dist/` ZIP predates P1/P2 and must be regenerated (the unpacked `dist/MICS-portable` has the current binaries) | `dist/` |
| MED | `status` returns hardcoded `version: 0.1.0` / `platform: windows` | `dispatcher.rs` |
| MED | `audit.run` ignores `params.sections` | `dispatcher.rs` |
| MED | VirusTotal client is dead code (only reachable from the sync queue, which nothing fills) | `scanner/vt.rs` |
| MED | IDS = hosts-file blocklist (DNS only); no Suricata/ET-Open | `ids/mod.rs` |
| MED | Canaries detect mtime/size changes by polling; a read-only open is not detected | `guard/canary.rs` |
| MED | Firewall uses `netsh`, not FirewallAPI COM | `firewall/mod.rs` |
| MED | `firewall` and `ids` still call `netsh` / elevated PowerShell **without a timeout** (hardening was fixed) — an unanswered UAC prompt can block those requests | `firewall/mod.rs`, `ids/mod.rs` |
| MED | Offline badge/freshness exists in the title bar, but there is no dedicated sync screen with per-source results | `app_shell.dart` |
| MED | Benchmark CPU 2.97 % vs the < 1 % budget (`budget_ok:false`) | `benchmark.rs` |
| LOW | `docs/` has no THREAT-MODEL yet (the README carries the layer matrix) | `docs/` |
| LOW | Light-mode palette has not been contrast-audited | `app_theme.dart` |
| LOW | UI is not yet obfuscated and ships without an integrity manifest | P5 |

Resolved during P1/P2a (keep for context): pipe closed after the first client;
blocking read + write on one handle deadlocked (fixed with `PeekNamedPipe`);
`scan.start` blocked the UI for the whole scan; engine had no log file; settings
were UI-only and language/theme changes wiped them; engine options ignored
settings and read environment variables only.

---

## 8. Environment traps (learned the hard way)

1. **`engine/target` may be ACL-locked** → `cargo` fails on
   `.cargo-build-lock`. Use `CARGO_TARGET_DIR=$env:TEMP\mics-target` and copy the
   exe; never try to "fix" it by hand.
2. **yara-x build script** writes into the cargo registry; always set
   `YRX_REGENERATE_MODULES_RS=false` when the registry is read-only.
3. **Flutter tooling** needs to write into the SDK directory; in a restricted
   environment set `APPDATA`/`LOCALAPPDATA` to a writable dir (Dart telemetry
   otherwise crashes with `Access is denied`).
4. **Named pipes are blocked in restricted sandboxes** → transport tests must run
   unconfined. Use `MICS_PIPE_NAME` to avoid a real running engine.
5. **A running engine/binary cannot be overwritten.** Rename it
   (`mics-engine.exe` → `mics-engine.old.exe`) — Windows allows renaming a
   running exe — then copy the new one. This is the same trick the self-updater
   uses.
6. **Processes started by a differently-tokened shell** can hold the real pipe
   and cannot be killed from a new shell; use `MICS_PIPE_NAME` for tests and ask
   the user to close stray `mics_app`/`mics-engine` from Task Manager.
7. **`cargo build` prints "Finished in ~2 s"** when nothing changed — that is a
   no-op, not a stale build. Check the exe timestamp before assuming staleness.
8. The app resolves the engine as: `MICS_ENGINE_PATH` → beside `mics_app.exe` →
   `engine/target/release` (dev). In a packaged layout the exe must sit beside
   the app.
9. **Never rewrite `assets/i18n/*.json` with PowerShell.** Windows PowerShell
   5.1's `Get-Content -Raw` decodes as ANSI, so a read-modify-write turns Arabic
   into `Ø­...` and `—` into `â€“`. Use the `write` tool, or
   `[System.IO.File]::ReadAllText/WriteAllText` with an explicit UTF-8 encoding.
   The parity test now fails on mojibake; `tool/fix_i18n_encoding.dart` repairs
   simple cases (CP1252-only characters like `€` cannot be auto-repaired).
10. **Isolated runs:** set `MICS_DATA_DIR` (state) or `PROGRAMDATA` (parent of
    `MICS`) for the engine. The resolved path is printed in the startup log line
    (`data=...`), which is the fastest way to tell which store a process uses.
11. **Screenshots for UI verification:** `GetWindowRect` + `CopyFromScreen` on
    `mics_app`'s `MainWindowHandle` works; prefer that over clicking. Blind
    mouse clicks can hit destructive buttons (a stray click started a hardening
    action during this session).

---

## 9. Definition of done (per phase)

A phase is done only when all of these hold and are pasted into the Done log:

- `cargo clippy --release -- -D warnings` → zero warnings
- `cargo test` → green
- `flutter analyze --no-pub` → no issues
- `flutter test --no-pub` → green
- The phase's own acceptance scenario executed for real (not "should work")
- `docs/DECISIONS.md` and this file updated, code committed with a conventional
  message, one commit per phase
