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
> Last updated: 2026-10-30 · P1, P2 (settings/i18n/sounds/theme), P3 (badge +
> update flow, sticky data dir), the P3d/P3e real-run sweeps (Defender checks,
> pipe concurrency), P3c1 (intel source registry, D-012), P3c2 (vulnerability
> scan as a cancellable job), P3c3 (Intel screen, configurable hash feed, KEV
> badge) and **P7 (desktop alert cards: one alert gate, full coverage, ar/en
> copy, AUMID-free toast proven by Windows' own notification history)** and
> **P1.5 (the privileged helper: closed op set, validate-before-run, audit-first,
> one-prompt install, `verify-helper.ps1` — only the elevated install itself is
> left, and that needs one click from you)** and **the portable release
> (`make-release.ps1` → ZIP + `SHA256SUMS` + `rules\`, and `verify-release.ps1`
> which extracts the archive and proves it serves the helper protocol, shows a
> card and loads its own rules)** done,
> plus the state-reporting fix those live probes found · **naming is settled**
> (Task Manager: `MI Cyber Security` + `MiShild Background`, one shared icon;
> inside the product and on every card: `MI CS`; desktop shortcut `MICS`) and
> **Authenticode signing works locally** (`make-release.ps1 -Sign`: every binary
> `Valid`, `signtool verify /pa` passes) and **every external tool call now has a
> deadline** (one `ToolCall` choke point; a test fails on any other
> `Command::new`) · **next: install the helper once (one
> UAC prompt), then the NSIS installer and the P6 QA harness**; the cheap wins
> below need neither elevation nor money, then P4, P5, P6. README is written;
> the app runs unelevated and was verified end-to-end on a real machine.
>
> **New session? Read §0 "Resume here" first** — current state, the next
> ordered steps, what is blocked on a human, and the environment must-knows.

---

## 0. Resume here — a new session starts with this section

**Where the project stands** (2026-10-30, `main` @ `7f963b9`). The whole
*unelevated* half of the product is implemented and verified on a real Windows 11
machine: audit + one-click fixes, file scanner (YARA + IOC cache), encrypted
quarantine, process guard + canaries, firewall/hosts through the privileged
helper, intel sync (D-012), resumable jobs, desktop notification cards, bilingual
UI with full RTL, sounds, the 8-section Settings screen, a portable ZIP +
`SHA256SUMS`, and Authenticode signing that works on this machine. The names and
icons are settled and a probe now fails the release if they drift:

| Surface | Name |
|---|---|
| Task Manager / Properties — the app (`mics_app.exe`) | `MI Cyber Security` |
| Task Manager / Properties — the engine (`mics-engine.exe`) | `MiShild Background` |
| Inside the product (window title, title bar, tray, card headers) | `MI CS` |
| Desktop shortcut — icon taken from `mics_app.exe` | `MICS` |
| Start Menu shortcut | `MI CS` |

Both executables carry the **same icon**; the engine embeds
`windows/runner/resources/app_icon.ico` at build time.

**Artifacts on this machine.** `dist\MICS-portable\` + the signed
`dist\MICS-portable-0.1.0-x64.zip` + `dist\SHA256SUMS` (all gitignored — the
scripts are the versioned part; `scripts\make-release.ps1 -Sign` re-creates and
re-hashes them), and the runnable install in `%LOCALAPPDATA%\MI CS` (69 files,
both binaries `Valid`).

> **Run the copy in `%LOCALAPPDATA%\MI CS`, never the one under `dist`.**
> `dist` sits in a low-integrity web root (`H:\FlyEnv\...\server\www\`): Windows
> refuses notification cards to a process launched from there
> (`0x80073D54 ... confined folder`), and that folder has already been emptied once
> by host tooling outside this repo (trap 16).

### 0.1 Do this next — needs no elevation and no money (in this order)

1. **The UI should re-run one audit section, not the whole audit (LOW).**
   `audit.run` accepts `params.sections` (7 ms for one section vs 1.7 s for all,
   unknown names refused); `lib/providers/providers.dart` still asks for
   everything after a fix. Change the caller, keep the full audit for first load.
2. **`docs/THREAT-MODEL.md` + `docs/PROTECTION-MATRIX.md`** (P5, wording only).
   Assets, adversaries, trust boundaries, what a usermode product cannot do (no
   kernel driver), and per layer what is detected/blocked and what is not
   (hosts-based L2, polling canaries, `netsh` firewall, no ClamAV/CAPA).
3. **Guard CPU: 2.97 % against the < 1 % budget (MED)** — either lower it
   (polling intervals, cheaper process enumeration) or move the budget to a
   measured, justified number and say so in the README.
4. **Light-mode contrast audit (LOW)** — text, borders and severity colours with
   before/after numbers.
5. **AUMID registration (LOW, fold into the installer)** — register
   `HKCU\Software\Classes\AppUserModelId\MICS` (and the shortcut property) so
   Windows' own notification settings label the source "MI CS" instead of `MICS`.
   Cards work without it; nothing about toast delivery depends on it.

### 0.2 Blocked on the user

1. **One UAC prompt — install the privileged helper (this finishes P1.5).**
   In the running app: **Settings → Engine → Install helper**. Then, in the same
   session, enable Default-Deny, turn SMBv1 off and import a hosts list: expect
   **zero** further prompts and one `phase=start`/`phase=done` pair per operation
   in `%PROGRAMDATA%\MICS\logs\priv.log`. Everything under that step is already
   proven unelevated by `scripts\verify-helper.ps1`.
2. **A real OV/EV certificate (this is the public half of P4).** The local half is
   done: `scripts\make-release.ps1 -Sign` self-signs, trusts the certificate in
   `CurrentUser\Root` + `TrustedPublisher`, signs DLLs then EXEs before hashing and
   zipping. A public release needs the certificate (the `-PfxPath`/`-PfxPassword`
   path already timestamps), and only then does SmartScreen stop warning strangers.
3. **Two decisions:** the VirusTotal client is dead code — wire the sync queue that
   is supposed to fill it, or delete it and say so in the README (MED); and whether
   the Start-Menu shortcut should also be named `MICS` (today it is `MI CS`).

### 0.3 The big phases that remain

- **P4 release engineering:** NSIS installer (bundled engine + rules + offline
  intel, one UAC prompt, shortcut + AUMID registration), the signing certificate,
  SBOM (CycloneDX) + `THIRD-PARTY-NOTICES` + `docs/COST.md`, ARM64 leg
  (Flutter + `aarch64-pc-windows-msvc` engine).
- **P5 trust & truth:** signed SHA256 manifest of shipped files + startup
  self-check and an "unofficial build" banner, build hardening (Dart
  `--obfuscate --split-debug-info`, Rust LTO/strip/`panic=abort`, PE mitigations),
  and the deliberate README rewrite ("what it does / does not do").
- **P6 QA:** `qa/` harness that drives every JSON-RPC method (happy path, invalid
  params, permission failure, schema) plus per-screen widget tests and an E2E run
  on the built artifact, emitting `qa/report.html`/`.md`; CI fails when a feature
  is not registered.
- **P3:** a default update manifest URL compiled in and a signature check on the
  manifest before applying (today both are user-supplied).

### 0.4 Environment must-knows (the short version of §8)

- **Before every commit**, all four from `AGENTS.md`: `cargo test`,
  `cargo clippy --release -- -D warnings`, `flutter analyze --no-pub`,
  `flutter test --no-pub`. Set `$env:CARGO_TARGET_DIR = "$env:TEMP\mics-target"`
  and `$env:YRX_REGENERATE_MODULES_RS = "false"` first.
- **One phase = one conventional commit**, and this file is updated in the same
  commit. Commit messages are written to a file under `.git\` and passed with
  `git commit -F` (the write tool cannot expand `$env:TEMP`).
- **Proof is textual, never visual**: engine logs, Windows' own toast history
  (`scripts\verify-toast.ps1 -HistoryOnly`), `Get-AuthenticodeSignature`,
  `VersionInfo.FileDescription`, the Shell API, `verify-*.ps1` `RESULT:` lines.
- **PowerShell 5.1 traps** (§8): native stderr + `$ErrorActionPreference = "Stop"`
  turns progress output into a terminating error; `Copy-Item -Recurse` nests;
  never delete the live package folder; UTF-8 must be written with
  `[System.IO.File]::WriteAllLines(..., UTF8Encoding($false))` to avoid the
  double-encoded README that happened once. Scripts stay ASCII-only.
- **Reply to the user in Egyptian Arabic**; code, comments, docs and commit
  messages in English. Never add telemetry or cloud calls; the UI never touches OS
  APIs — everything goes through the engine over JSON-RPC (`lib/core/ipc/`).

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
cargo test                                    # expected: 16 passed
cargo clippy --release -- -D warnings         # expected: zero warnings

# App
cd ..
flutter analyze --no-pub                      # expected: No issues found
flutter test --no-pub                         # expected: 24 passed
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
| `scripts\verify-toast.ps1` | A real notification card reached the desktop: clears the AUMID's history, triggers a card, reads the history back (text + actions). `-HistoryOnly` reads cards an already-running engine produced |
| `scripts\verify-helper.ps1` | The privileged helper's protocol **unelevated**: ping/version answer, a privileged op is refused without an elevated token, an unmarked hosts document and a malformed firewall rule are refused, an op outside the closed set is refused, the audit log keeps intent/outcome but never the payload, `helper-status` sees it |
| `mics-engine.exe helper-status --json` | The status chain the UI renders (`installed/running/state/reachable/version/elevated/pipe`) |
| `mics-engine.exe helper-console` | Serves the privileged protocol in the foreground on `MICS_HELPER_PIPE` without the SCM (diagnostics, `verify-helper.ps1`) |
| `scripts\make-release.ps1` | Builds the published artifact: clean `dist\MICS-portable` (engine + `rules` + app), `VERSION`, `MICS-portable-<version>-x64.zip`, `dist\SHA256SUMS`; fails instead of shipping an incomplete folder |
| `scripts\verify-release.ps1` | The artifact is what it claims: every checksum matches, the zip has every required file and exactly 2 rule packs (no `rules\rules`), and the **extracted** copy answers the helper protocol, puts a real card on the desktop, and loads its own `rules\guard` + `rules\yara` rather than the built-in fallback |
| `cargo run --example toast_probe` | Which WinRT step of the toast path fails, with the HRESULT (diagnoses "no card at all") |

Both tools need an engine to talk to; start one with an isolated pipe first
(`MICS_PIPE_NAME`, `MICS_NO_SINGLETON`, `MICS_NO_GUARD`, `PROGRAMDATA`).

---

## 3. Where we are

**Start here if you are new:** run the four checks in section 2, launch
`build\windows\x64\runner\Release\mics_app.exe`, and read the Done log below.
Everything that could be verified without administrator rights is done, including
the published portable archive; the remaining work needs a UAC prompt you can
click (P1.5) or a purchased certificate (P4).

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
| **P3d** | Second real-run bug sweep: Defender PUA false positive, read-only snapshot, verified apply | **done** |
| **P3e** | Third real-run bug sweep: concurrent pipe dispatch, heartbeat only when idle, vuln-scan deadline | **done** |
| **P3c1** | Intel source registry: per-source state, backoff/next-due, DNS-blocklist domains, CISA KEV catalog | **done** |
| **P1.5** | Single-elevation privileged helper (D-007): closed op set, validation, audit-first, install/uninstall, Settings card, `verify-helper.ps1` | **code complete + unelevated acceptance passed — one interactive UAC prompt left (enabling the service itself) — `e406275`** |
| **P3c2** | Vulnerability scan as a cancellable job with live progress | **done** |
| P3c3 | Intel/Sync screen: per-source state, numbers, next attempt, last error, on-demand NVD; configurable hash feed; KEV badge | **done** |
| **P7** | Desktop alert cards: one alert gate (`toast_enabled` + DND + severity), guard/scan/protection coverage, ar/en copy, history-based acceptance probe (D-013) | **done — `3859901`** |
| **Release** | Portable package assembled by script: engine + `rules` + app + `VERSION` + ZIP + `SHA256SUMS`, and a probe that runs the extracted copy (helper, card, own rules) | **done — this commit** |
| P4 | Code signing (real cert), x64+ARM64, NSIS installer, SBOM/notices | planned |
| P5 | Threat model, integrity/anti-tamper, protection-matrix doc | planned |
| P6 | Full QA harness + HTML report, malware lab (later) | planned |

### Done log (append only)

- **spawns — no external tool can wedge a request any more, and a test now
  enforces that instead of trusting the code**
  - The last deadline-free spawns from the register row are gone. Every external
    program the engine runs goes through one choke point,
    `platform/windows/process.rs::ToolCall` (program + arguments + the operation's
    name + a deadline): `net localgroup` (20 s) and Defender's
    `Get-MpComputerStatus` (30 s) in the audit, `Expand-Archive` in the update
    step (300 s), the two autostart `reg` calls (15 s), the one-time `icacls`
    grant (120 s), the guard's `taskkill` (15 s) and the helper's `sc.exe` (30 s)
    — plus the two callers that already had a deadline (`netsh` 20 s, the
    hardening PowerShell steps 60 s) moved onto the same API. The Defender
    quick-scan branch is asynchronous, so it got its own `tokio::time::timeout`
    (30 min): a real scan runs for minutes by design, but an unanswered `-Wait`
    can no longer pin the request for the session.
  - A stopped tool names itself: `net localgroup (audit: local administrators)
    did not finish within 20s — the tool was stopped so it could not block the
    engine`. `net localgroup` also gained `CREATE_NO_WINDOW`, which it was the
    last spawn to be missing (it could flash a console during an audit).
  - **Found by trying to break it:** the first version of the enforcement test
    allow-listed whole *files*, so a `Command::new` added anywhere in `update.rs`
    passed. A canary proved it (the bare call was reported as fine), the
    exemption is now the launch itself — the line must drop the handle
    (`.spawn()`) — and the same canary now fails the test with
    `src/update.rs:134 launches a process in an allow-listed file but does not
    drop the handle`. The only two exceptions are the relaunch-the-UI spawn and
    opening a link from a card; the async site must contain its own
    `tokio::time::timeout`.
  - Per-call-site proof: the shared `assert_deadline_is_enforced` helper aims
    *each site's exact call* at a program that never returns and asserts the
    deadline fires, promptly, with the site's own name. `cargo test` 54/54 (3
    new: the enforcement scan, the seven-site deadline test, and the extracted
    `net localgroup` parser), clippy clean, `flutter analyze` clean,
    `flutter test` 31/31.
  - Live on this machine (throwaway `serve` engine, isolated `MICS_DATA_DIR`,
    both streams to files per trap 13): `audit.run {sections:["admins",
    "defender"]}` answered in **2.2 s** with `2 account(s) with admin rights:
    Administrator, <account>` (the real `net localgroup` output, parsed) and
    `Real-time protection is enabled` (the real WMI query — no policy key exists
    here, so this is the fallback path), `score: 100`, `partial: true`.
    `service.install` → `{"status":"installed"}` and the machine's own registry
    read back `MICS-Engine = "...\mics-target\release\mics-engine.exe" --service`;
    `service.remove` → `{"status":"removed"}` and the value was gone —
    `RESULT: PASS`, the key left exactly as found.

- **naming, settled — two kinds of name on purpose, and one icon everywhere**
  - The previous step put `MIF` on every surface; that was one word too many. What
    the user actually wants, and what the product now does:
    - **Task Manager / Properties**: the app is **MI Cyber Security**
      (`FileDescription` + `ProductName` in `windows/runner/Runner.rc`), the
      engine is **MiShild Background** (`engine/build.rs`).
    - **Inside the product**: the name is **MI CS** — window title, title bar, tray
      tooltip, tray menu, About line, and the header of every notification card
      (`🛡️ MI CS — ...`), in both languages.
    - **Desktop**: one shortcut named **MICS**, its icon taken from
      `mics_app.exe`; the Start-Menu shortcut stays **MI CS**.
    - Identifiers keep their spelling: the `MICS-*` firewall rule prefix, the
      `MICS` AUMID and the `MICS_*` test hooks.
  - **One icon for both halves.** `mics-engine.exe` had no icon resource at all,
    so Windows substituted the generic one wherever it appeared. `engine/build.rs`
    now adds `resource.set_icon("../windows/runner/resources/app_icon.ico")` — the
    same file the Flutter runner embeds — with the same
    `MICS_REQUIRE_VERSION_RESOURCE=1` strictness (a missing icon is a build error
    in release packaging, a warning otherwise). Measured, not assumed: the icon
    Windows reports for `mics_app.exe` and for `mics-engine.exe` hashes to the
    same `7F64E14BA527FD48` (it differed before, `18BDCA4692AED201`).
  - `scripts/create-shortcuts.ps1`: the desktop shortcut is `MICS.lnk` and both
    shortcuts use `mics_app.exe,0` as the icon location, so `desktop.ico` is no
    longer referenced by anything (the asset still ships and
    `test/icon_test.dart` still proves it is a real, distinct icon). `-AppDir`
    now selects the copy to launch, and the pre-rename `MI CS.lnk` was removed
    from the desktop.
  - Verified textually: window title `MI CS`, Task Manager names `MI Cyber
    Security` + `MiShild Background`, identical icon hash for both binaries, a
    card in Windows' toast history reading `🛡️ MI CS — test notification`, and
    `verify-release.ps1` asserting `MI Cyber Security` end to end.
    `cargo test` 51/51, clippy clean, `flutter analyze` clean, `flutter test` 31/31.

- **branding — the app is "MIF" everywhere a person can see it**
  > Superseded by the entry above: the visible name ended up **MI CS**, and the
  > Task Manager name **MI Cyber Security**, not MIF.
  - Second naming step after `MiShild Background`: the window title, the tray
    tooltip and the title-bar text, the in-app product string (en: `MIF`, ar:
    `مركز MIF للدفاع السيبراني`), the audit assistant, the network-rules copy, the
    update-restart message, the CLI banner and the notification card headers all
    say **MIF** now, in both languages.
  - One constant instead of three literals: `lib/core/window/app_identity.dart`
    (`appDisplayName`). `window_corners.dart` finds the window with `FindWindowW`
    by that exact title, so a rename that missed it would silently stop the
    rounded corners from being applied — the constant makes that impossible.
  - `test/i18n_lint_test.dart` keeps its allow-list of intentionally
    untranslated brand strings; it now lists `MIF` instead of `MI CS` (the lint
    caught the rename, which is why the allow-list exists).
  - Verified end to end on this machine, all of it textual: window title `MIF`
    (`Get-Process ... MainWindowTitle`), Task Manager names `MIF` +
    `MiShild Background` (shell API and version resource), and a real card in
    Windows' own toast history reading
    `🛡️ MIF — test notification | Notifications are working...` from the signed
    install in `%LOCALAPPDATA%\MI CS`.
  - Kept as "MI CS" on purpose: the project/docs name, the `MICS-*` firewall rule
    prefix, the `MICS` AUMID and the `MICS_*` test hooks — those are identifiers,
    not labels.

- **signing — a locally trusted certificate, one flag away**
  - Second SmartScreen report, now the hard block: *"Windows protected your PC —
    Microsoft Defender SmartScreen prevented an unrecognized app from starting"*.
    That is the reputation path refusing an unsigned file it has never seen; no
    policy on this machine is wrong (Smart App Control off, SmartScreen default,
    endpoints reachable — measured last phase).
  - `scripts/sign.ps1` already had a `-SelfSigned` mode but could not work: it
    always asked a public timestamp server to countersign a self-signed signature
    (rejected), and it only printed `signtool verify` for one file. It now skips
    timestamping in that mode, trusts the certificate in `CurrentUser\Root` +
    `CurrentUser\TrustedPublisher` through `certutil -user` (no elevation, no
    prompt), verifies **every** target, and exits non-zero unless all of them come
    back `Valid`.
  - `make-release.ps1 -Sign` (and `-PfxPath/-PfxPassword` for a real certificate)
    signs the **staged** binaries before hashing and zipping, so `SHA256SUMS`
    describes the signed files rather than the unsigned ones, and a failed
    signature aborts the release without publishing anything.
  - Verified: all eight binaries `Valid` with
    `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`; `certutil`-installed trust
    present in both stores; `signtool verify /pa /all` →
    `Successfully verified`; `verify-release.ps1` → `RESULT: PASS` on the signed
    zip; `%LOCALAPPDATA%\MI CS` refreshed from it (69 files).
  - Honest limit: this is **local** trust. It removes the prompt on this machine;
    it gives the file no public reputation. A public release still needs an OV/EV
    certificate (P4), and until then anyone else downloading the zip sees the same
    block and must choose *More info → Run anyway*.

- **naming — the engine now has a name in Task Manager**
  - Request: in Task Manager the engine appeared as `mics-engine`; it should read
    **MiShild Background**.
  - Task Manager's Processes tab does not show a file name — it shows the
    `FileDescription` from the executable's version resource, and falls back to the
    file name when there is no resource. The engine had **no version resource at
    all** (the app did, from Flutter's runner `.rc`, which is why the app read
    "MI CS Command Center" and the engine read `mics-engine.exe`).
  - `engine/build.rs` + `winresource` (a Windows-only build dependency) embed
    `FileDescription = "MiShild Background"`, `ProductName = MI CS`,
    `CompanyName = Mourad Ibrahim Cyber Security`, `FileVersion`/`ProductVersion`
    from `CARGO_PKG_VERSION` (so the resource cannot drift from `status`), and
    `OriginalFilename = mics-engine.exe` — honest about the real file name.
  - The **file name stays `mics-engine.exe`**: the app's lookup, the helper service
    registration, every probe and `MICS_ENGINE_PATH` depend on it, and a path with
    a space would leak into all of them.
  - `MICS_REQUIRE_VERSION_RESOURCE=1` (set by `make-release.ps1`) turns "no `rc.exe`
    on this toolchain" into a build error instead of a silent warning, so a package
    can never ship an engine under the wrong name. `make-release.ps1` now builds
    the engine itself (one command per release) and prints
    `engine name: MiShild Background`; `verify-release.ps1` asserts the extracted
    engine reports exactly that.
  - Verified: `[PASS] the engine presents itself as 'MiShild Background' (Task
    Manager, Properties)` plus the full release check `RESULT: PASS`; the built PE
    reports `FileDescription = MiShild Background`, `FileVersion = 0.1.0`.
    (`Win32_Process.Description` is *not* the field Task Manager reads — it returns
    `explorer.exe` for Explorer — so the assertion uses the version resource.)
  - Note for the user: `MiShild` is spelled exactly as requested; if the intended
    brand is `MiShield`, it is a one-line change in `engine/build.rs`.
  - Follow-up in the same area: the **app** is now `MIF` (its `FileDescription`
    and `ProductName` in `windows/runner/Runner.rc`, and `sign.ps1`'s `/d`), so
    the Processes tab reads `MIF` + `MiShild Background`. File names are unchanged
    (`mics_app.exe`, `mics-engine.exe`) because the scripts, the app's engine
    lookup and `MICS_ENGINE_PATH` depend on them. Verified through the shell API
    the Task Manager uses: `mics_app.exe -> 'MIF'`, `mics-engine.exe ->
    'MiShild Background'`, both `Valid` after signing.
  - Still carrying the old product string on purpose, pending a decision: the
    window title, tray tooltip and in-app name (`lib/main.dart`,
    `lib/core/window/window_corners.dart` — which must match the window title
    exactly — and `assets/i18n/*/app.json`), plus the notification card header
    (`MI CS`). Renaming those is a product-wide branding change, not a Task
    Manager one.

- **first-run friction — the SmartScreen prompt, explained and documented**
  - Report: *"SmartScreen can't be reached right now / Publisher: Unknown
    Publisher / App: mics_app.exe"*.
  - Investigated: both installed copies are `NotSigned` (expected), **no
    mark-of-the-web** on either, SmartScreen policy is untouched
    (`SmartScreenEnabled` unset in HKCU and HKLM, no `EnableSmartScreen` policy),
    **Smart App Control is off** (`VerifiedAndReputablePolicyState = 0`), and
    `smartscreen.microsoft.com` / `checkappexec.microsoft.com` resolve and accept
    TCP 443. So nothing on this machine is broken: an unsigned, brand-new binary
    has no reputation to check, and the dialog's own wording ("can't be reached")
    means the *lookup* failed — behind a proxy/VPN/flaky link that is what you get.
  - Integrity checked instead, which is what actually matters before running an
    unknown exe: `sha256(mics_app.exe)` in both copies equals the published
    `SHA256SUMS` value `e5209573…`.
  - Bypass proven, not assumed: `Start-Process "$env:LOCALAPPDATA\MI CS\mics_app.exe"`
    started the app with no prompt (Explorer's double-click is what invokes the
    hook); the test instance was stopped afterwards so only the user's session
    stayed running.
  - `make-release.ps1` now prints `signed : NotSigned` and points at the
    troubleshooting entry instead of letting the first launch be a surprise.
    README (EN + AR) gained the symptom, the run-anyway / `Start-Process` path,
    the hash check and the `Unblock-File`-the-zip-before-extracting recipe.
  - The durable fix stays P4 (a trusted code-signing certificate); until then this
    is expected behaviour for every download, not a defect in MI CS.

- **packaging — a release build no longer eats the copy you are running**
  - Found the hard way: MI CS was running from `dist\MICS-portable` when
    `make-release.ps1` began by deleting that folder. The delete failed on a
    plugin DLL the running app had loaded — *after* removing `data\` and `rules\`
    — leaving a package without an asset bundle and a victim still running from
    it. Restored the folder and fixed the cause, not the symptom.
  - `make-release.ps1` now assembles into `dist\MICS-portable.staging`, runs the
    required-file checks there, zips from there, and only then swaps the staging
    build into `dist\MICS-portable` — and only when no process is running from
    that folder. Otherwise it leaves the folder untouched and says which process
    is using it; the zip is the release either way.
  - `SHA256SUMS` kept the same shape but changed meaning: the zip line is checked
    where the zip sits, and the `MICS-portable/...` lines are checked **inside the
    extracted zip**, so a working folder that lags (or is absent) can no longer
    produce a false "hash mismatch". That false alarm is exactly what the
    verification printed first (`listed b7361e67 / actual d092f559`), which is
    the harness doing its job on a real ambiguity.
  - Verified end to end: `RESULT: PASS` with `MICS-portable/mics-engine.exe
    (inside the zip)`, the helper protocol from the extracted engine, a real card
    on the desktop, and the package's own `rules\` loaded (6 guard rules + the
    extracted `starter.yar`). The live folder was left alone, as designed, while
    `mics_app`/`mics-engine` were running from it.

- **protocol fidelity — the RPC layer stopped guessing**
  - `status` used to answer with literals (`version: "0.1.0"`, `platform:
    "windows"`). It now reports the crate version, the real `os-arch`
    (`windows-x86_64` / `windows-aarch64`) and the engine's pid, so an ARM64 or
    x64 build problem is visible from the first response. Verified live:
    `{"state":"running","version":"0.1.0","platform":"windows-x86_64","pid":66988}`.
  - `audit.run` ignored `params.sections` and always ran all ten collectors. It
    now runs exactly the sections asked for, reports `sections: [...]` and
    `partial: true/false`, and refuses an unknown name with `-32602` plus the list
    of known names instead of quietly scoring checks that never ran. Absent or
    empty `sections` still means the full audit the dashboard shows, so no UI
    change was needed.
  - Live: `audit.run {sections:["firewall"]}` answered in **7 ms** (full audit:
    1,747 ms), returned only the three firewall findings, `partial=true`,
    `startup_entries=[]`. A typo (`"firewal"`) got
    `-32602 unknown section "firewal" — known sections: defender, firewall, rdp,
    smbv1, uac, admins, hosts, remote_tools, startup, scheduled_tasks`, and
    `sections: "firewall"` (not an array) got its own `-32602`.
  - Tests (3 new, 51 total): the parser (absent/empty/duplicate/unknown/non-array,
    the error lists what is known) and a counting `PlatformCollectors` mock that
    proves a partial audit calls **only** the requested collector, keeps the score
    over what ran, and that a full audit runs all ten and is not partial.
  - This is what a "fix" button needs next: after applying a fix the UI can
    re-check that one section in milliseconds instead of re-running the audit.

- **reliability — no external tool can wedge a request any more**
  - `engine/src/platform/windows/process.rs`: one `run_with_deadline(program,
    args, what, timeout)` used by `firewall::run_netsh` (20 s) and
    `hardening::ps_run_with_timeout` (60 s), replacing two ad-hoc
    `Command::output()`/poll implementations.
  - **The real bug it fixes:** the old hardening loop polled `try_wait` without
    reading the child's pipes, so any command that printed more than a pipe buffer
    (64 KiB) blocked on write and never exited — a timeout would then fire on a
    process that was about to finish, and its output was lost. The new runner
    drains stdout/stderr on their own threads while it waits. `netsh advfirewall
    show rule name=all verbose` is exactly that kind of output.
  - Live proof: `fw.rules.list` over the real pipe returned the machine's MICS
    rule in 3.4 s through the new path (`MICS-TEST-BLOCK-EXAMPLE`,
    203.0.113.0/24) — that call is a full `netsh` dump, the >64 KiB case.
  - Tests (3 new, 48 total): a command that finishes is captured; a ~10 s ping
    with a 300 ms budget fails at the deadline with the operation named and
    returns in well under 5 s; ~200 KiB of output is collected whole.
  - Honest scope: `ids` spawns nothing itself (it goes through the privileged
    helper), so its register row was about the wrong module. The remaining
    deadline-free spawns are the audit collectors, the update step and two
    `reg query` reads — recorded as the new MED row instead of being claimed as
    fixed.

- **release — the portable package is now assembled, published and provable**
  - What shipped: `scripts\make-release.ps1` builds `dist\MICS-portable` from a
    clean folder (Flutter release output + the cargo-built engine + `engine\rules`
    + `VERSION`), refuses to continue when any required file is missing, and
    produces `dist\MICS-portable-0.1.0-x64.zip` + `dist\SHA256SUMS` (paths
    relative to `dist\`, so a plain `Get-FileHash` loop verifies them).
    `scripts\verify-release.ps1` then checks the artifact the way a user would:
    every checksum, the file list *and* the rules layout, then it extracts the zip
    to a temp folder and runs the two existing probes against the extracted copy
    plus a scan.
  - **Found while doing it:** the deployed `dist\MICS-portable` had **no `rules\`
    folder at all**, so the shipped product could not have its rule packs updated
    (the guard and YARA loaders silently fall back to the compiled-in packs). The
    README's build step 3 said to copy them, but every hand-run deploy since then
    copied only the binaries. That is why packaging is now one script instead of
    three remembered commands.
  - **Found by the probe:** the first version of the script produced
    `rules\rules\...` - `Copy-Item -Recurse` into an existing destination nests the
    source folder instead of merging (trap 14) - and `verify-release.ps1` now
    asserts the rules layout, not just that two files exist somewhere.
  - **The engine now says which rules it loaded** (`YARA rules from <path>`,
    `guard: N rule(s) from <dir>`), once per change so a 30 s hot-reload cannot
    bury the log. Without that line, "the package is complete" was unprovable;
    with it, the probe asserts the extracted copy used *its own* `rules\guard`
    (6 rules) and `rules\yara\starter.yar`, not the built-in fallback.
  - Live acceptance (`scripts\verify-release.ps1`, `RESULT: PASS`): 5/5 checksums
    match; the zip holds every required file and exactly 2 rule files; the
    extracted engine answers the helper protocol (full `verify-helper.ps1` PASS);
    the extracted engine put a real card on the desktop
    (`🛡️ MI CS — إشعار تجريبي`, read back from Windows' own history); the scan and
    the guard both loaded rules from the extracted folder; `VERSION` reads
    `MI CS 0.1.0 (portable, x64)`. Artifact: 63.7 MB folder, 24.3 MB zip.
  - Still open for the user: the NSIS installer and a signed/trusted publisher
    (P4), and the one interactive UAC prompt that finishes P1.5.
  - Checks: `cargo test` 45/45 (one new test for the once-per-change rule
    reporting), clippy clean, `flutter analyze` clean, `flutter test` 31/31.

- **P1.5 — the privileged helper: one prompt instead of one per action**
  - What shipped: `MICSHelper`, a LocalSystem service that points back at the
    same `mics-engine.exe --helper-service`, plus the engine's client
    (`engine/src/privileged/`): a **closed** op set (ping/version, three firewall
    ops, hosts rewrite, hardening run/rollback), shape validation *before*
    anything runs, `phase=start`/`phase=done` audit lines that carry a payload
    hash instead of the payload, one-time install/uninstall that poll the pipe
    and only report success when the helper actually answers, and a Settings card
    that renders `missing / not_running / unelevated / ready` from
    `state` + `version` + token facts. `firewall/`, `ids/` and `hardening/` no
    longer spawn `-Verb RunAs`: they run in-process when already elevated and
    route through the helper otherwise. The operation list, the wire format, the
    validation rules and the audit format are written down in
    `docs/PRIVILEGED-OPS.md` — the file the code had been citing without it
    existing.
  - **Bug found and fixed by running it, not by reading it:** `helper-console`
    panicked on every start — `Cannot start a runtime from within a runtime`,
    because the CLI already runs inside tokio and the console path built a second
    runtime and blocked the same thread. The pipe was therefore never served, and
    every probe against it timed out. The loop now gets its own thread and runtime
    (the same shape the SCM service thread and the integration test use); the
    duplicate runtime code in the test helper collapsed into that one function.
  - Unelevated acceptance (real requests over a real pipe, `scripts\verify-helper.ps1`,
    `RESULT: PASS`): `ping` → `pong:true`; `version` → `0.1.0, elevated:false`;
    `hardening.run smbv1_off` → refused ("running without an elevated token");
    `hosts.write` without the marker → refused; malformed firewall rule →
    refused with the rule it broke; `{"op":"shell.exec"}` → refused and the
    answer lists the eight allowed ops (the closed set, proven by the platform's
    own deserializer). Audit log: `phase=start`/`phase=done ok=… dur_ms=…`,
    `sha256=dab82ccbcffeb900` for the document, and assertably **no payload**.
    `helper-status --json` goes from `not_installed/reachable:false` to
    `reachable:true, version:0.1.0, elevated:false` once the console helper is up.
  - **Not verified, on purpose:** the elevated install itself (`sc create`, the
    LocalSystem pipe ACL). It needs one interactive UAC prompt, which no
    automated run can answer, so the docs and the commit say "code complete,
    install pending" rather than claiming the phase is done. Acceptance for that
    step: Settings → Engine → Install helper (one prompt), then Default-Deny off
    and on again with **zero** additional prompts.
  - Checks: `cargo test` 44/44, `cargo clippy --release -- -D warnings` clean,
    `flutter analyze --no-pub` clean, `flutter test --no-pub` 31/31.
  - Drive-by: `parse_query` now answers `not_installed` for a never-installed
    service instead of `unknown` (its own test already expected that), which is
    what makes the Settings card say "not installed" instead of "cannot tell".

- **P7 — "anything that happens" never reached the desktop as a card**
  - Symptom (the user's own words): a caught virus or any protection action
    should pop a card above the taskbar. None did. Two independent causes turned
    up, one in the code and one in the machine:
    1. **The one card that names a malicious file could never parse.** Its
       `launch` payload (`{"mics-action":"…"}`) was interpolated into an XML
       *attribute* with an escaper that handled `& < >` but not `"`, so
       `LoadXml` rejected every actionable toast — the "Threat found →
       Quarantine" card, i.e. exactly the virus case.
    2. **Nothing started from this workspace could toast at all.** Every alert
       failed with `The process has no package identity. (0x80073D54)`. The
       binary was not at fault and neither was a missing registration: the
       workspace tree carries a `Mandatory Label\Low Mandatory Level:(OI)(CI)(NW)`
       label (the DSH sandbox's confinement of the folder), every file under it
       inherits it, and a process whose image is labelled Low runs at Low
       integrity — where Windows refuses desktop cards. Proof: a copy of
       `powershell.exe` inside the repo reports `Mandatory Label\Low Mandatory
       Level (S-1-16-4096)` and the same file on `C:\` reports Medium; the engine
       fails from `H:\…\MIF\…` and shows a real card from `%TEMP%` and from
       `H:\mics-loc-test`, same bytes, same second. The earlier "the deployed
       binary is stale" reading was wrong — the deployed run was simply the one
       started from the labelled tree (see trap 8.11).
  - Also missing: coverage (only CRITICAL/HIGH guard events + scan *criticals at
    the end of a run*), an off switch for cards alone, and any card for
    protection actions (firewall/IDS) or for Arabic users (titles were English).
  - Fix (D-013): one gate, `engine/src/notify/alert.rs` — `decide(severity,
    toast_enabled, dnd)` as a pure function, `toast_enabled` as a real setting
    (engine + Settings switch + `ar`/`en` copy), guard events of every severity
    routed through it, scan findings carded **as they are found with their own
    severity** (first three individually, the rest as one summary), quarantine
    confirmations, and firewall/IDS actions confirming themselves. `toast.rs`
    builds the payload in one tested function that escapes quotes, and a refused
    card now explains itself: when the platform answers `NO_PACKAGE` and the
    process is below medium integrity, `notify.test` and the engine log say the
    app is running from a confined folder and how to fix it, instead of echoing
    an HRESULT that reads like a registration problem.
  - Acceptance (live, this machine): a CLI scan of a benign text file that the
    bundled YARA pack flags (`yara:Ransom_Note_Names`, `severity: high`) logged
    `alert shown (high): 🛡️ MI CS — Threat found` and Windows' own notification
    history returns the card:
    `🛡️ MI CS — Threat found | …\ransom-note.txt — yara:Ransom_Note_Names` with
    `<action content="Quarantine" …/>` and an escaped
    `launch="{&quot;mics-action&quot;:&quot;a1793359091380827&quot;}"`.
    `scripts/verify-toast.ps1` is the repeatable version (history + UI
    Automation, `-HistoryOnly` for cards an already-running engine produced),
    plus `cargo run --example toast_probe` to name the failing WinRT step.
  - Checks: `cargo test` 44/44, `cargo clippy --release -- -D warnings` clean,
    `flutter analyze --no-pub` clean, `flutter test --no-pub` 31/31.
  - Drive-by fixes for the in-flight P1.5 work (it was not green):
    `parse_query` reported a never-installed helper as `unknown` instead of
    `not_installed` (its own test documented the right answer), an unused
    re-export and a dead `HelperStatus::usable` tripped `-D warnings`.
  - **Still open for the user:** a card can only appear once MI CS is launched
    from a medium-integrity location. Running the app straight out of this repo
    keeps failing until the folder's label is raised (one elevated command, trap
    8.11); the portable copy under `%LOCALAPPDATA%` works with no prompt.

- **fix — a source that failed after being configured still read "Not configured"**
  - Found by live-probing the new feed settings rather than by a test: point
    `ioc_feed_url` at a local feed that returns no usable rows, and `sync.status`
    reported `ioc_hashes` as `state=not_configured` *while* carrying
    `failures=1` and `last_error="no sha256 hash found in ..."`. `state_of`
    checked the stored "not configured" version marker before the failure, so the
    screen showed the one thing that was definitely no longer true about the
    source — exactly the misleading-state class P3c3 exists to remove.
  - Fix: the newest attempt decides the state (failure before the marker), and
    `record_sync_failure` clears the marker so a row cannot contradict itself.
    Taking the URL away again still puts the source back to `not_configured`.
    Regression test added (`cargo test` 30/30).
  - Live evidence after the fix: with the feed URL configured, `sync.status`
    reports `ioc_hashes state=failed items=0 fail=1 err="no sha256 hash found in
    http://127.0.0.1:8799/hashes.csv"`, and the captured request from the
    throwaway listener shows the key travelling as a header (`auth-key:
    probe-key`), never in the URL.
- **P3c3 — intel was only visible as one aggregate "last synced" number**
  - Symptom: after P3c1 the engine knew exactly which feed was fresh, which was
    failing and which had never been configured — and none of it reached the
    user. The only surface was a top-bar chip showing one age, and the one source
    a user *could* have fixed (`ioc_hashes`, the sha256 blocklist whose public
    abuse.ch export now needs an Auth-Key) was configurable only through an
    environment variable.
  - Fix: a 13th module, Intelligence (`/intel`, new `intel.json` pack in both
    languages). It reports the totals the machine actually holds (blocked
    domains, KEV CVEs, cached CVEs, hashes, country lists) and then one card per
    source with its own state chip (OK / Failing / Not configured / Never ran),
    its own count in the right unit, freshness, when the next attempt is due
    (or "on demand" for the NVD row a scan produces), and the last error when it
    is failing. Offline says so instead of showing a stale timestamp.
  - Also in this phase: `ioc_feed_url` / `ioc_feed_key` are now real settings
    (engine document + Settings → Intelligence rows, env hooks preserved) and the
    Auth-Key is sent as an `Auth-Key` header rather than a query parameter, so it
    cannot end up in a logged URL; `Vuln` carries `known_exploited`/`kev_due` and
    vulnerability cards show a `KEV` badge with the catalog's remediation date,
    because "exploited in the wild" outranks the CVSS number next to it.
  - Tests: the second widget test suite (`test/intel_screen_test.dart`) pins the
    report's honesty — every source visible with its own numbers, the failing
    source naming `HTTP 503`, the on-demand NVD row, and the offline state — and
    it reads the real language packs from disk so a copy regression fails the
    test rather than the user's screen. `cargo test` 29/29, `flutter test` 28/28,
    clippy and analyze clean.
- **P3c2 — the Vulnerabilities screen was a spinner you could not cancel**
  - Symptom: `vuln.scan` was one blocking RPC covering NVD lookups plus a 6.5 s
    rate-limit pause per application, so a cold scan left the screen spinning
    for minutes with no progress, no cancel and no way to see what had already
    been checked.
  - Fix: `vuln.scan.start` returns a `job_id` immediately and the scan runs as a
    durable job (`kind: vuln_scan`): per-application results are written to
    `job_findings` as it goes, `progress` notifications carry
    `pct`/`current app`/`checked of total`/CVEs so far, and `job.cancel` stops it
    within 200 ms because the rate-limit pause is sliced and re-checks the flag.
    The screen shows a progress card with a Stop button, re-attaches to a job
    that outlived the window, and renders whatever was persisted even for a
    cancelled run. The blocking `vuln.scan` stays for probes. New i18n keys in
    both languages; the project's first widget test covers this flow (start calls
    `vuln.scan.start` and never the blocking RPC, progress is matched by job id,
    Stop calls `job.cancel`, the terminal event renders the persisted findings).
  - Evidence (throwaway engine): `vuln.scan.start` answered in **0.06 s** with a
    job id; live notifications were `pct=0 'collecting software inventory'` then
    `pct=25 '7-Zip 23.01' checked=1/4 findings=1`; cancelling at 1.6 s produced
    `state=cancelled` + `job_finished` within 0.1 s, and `job.get` afterwards
    returned `state=cancelled, total=4, processed=1` with the one application it
    managed to check (including `CVE-2025-0411 known_exploited=true`). `cargo
    test` 29/29, `flutter test` 26/26, both analyzers/clippy clean.
- **P3c1 — the intel pipeline could not tell one dead feed from another (it was all dead)**
  - Symptom: the sync chip always showed "never synced" and `sync.now` returned
    `HTTP 410 Gone`. The default URLhaus export is gone: abuse.ch now requires an
    Auth-Key for every public export, so the only source the engine had was
    permanently broken — and the single aggregate `last_success` row could not
    show which feed was the problem.
  - Fix: intel is now a registry of named sources (`ioc_hashes`, `ioc_domains`,
    `kev`, `geoip_blocklists`, plus the on-demand `nvd` row the vulnerability
    scan records itself). Each keeps `last_success`, `last_attempt`, `failures`,
    `last_error`, `next_due`, `detail` and `items`; the scheduler runs only what
    is due; a failure backs off 15 min × 2ⁿ capped at the cadence; "not
    configured" is its own state that never counts as a failure and never
    claims freshness. Defaults are feeds that actually answer today:
    StevenBlack/hosts (MIT) for DNS-blocklist domains and the CISA KEV catalog
    (public domain) for actively-exploited CVEs. `Vulnerability` now carries
    `known_exploited` + `kev_due`.
  - Evidence (throwaway engine, `MICS_DATA_DIR` isolated, `sync.now` in 2.5 s):
    `ioc_domains` 76,737 blocked names, `kev` 1,764 exploited CVEs (catalog
    2026.10.29), `ioc_hashes` `not_configured` with the Auth-Key reason,
    `geoip_blocklists` `not_configured` with the directory it looked in; a second
    sync added 0 rows; `sync_state` rows carry a ~6 h `next_due` and
    `failures: 0`. `cargo test` 26/26, `cargo clippy` clean.
- **P3e — the Vulnerabilities screen could not survive its own scan**
  - Symptom: pressing Scan showed `EngineException(-1): engine connection
    lost: heartbeat failed` while the engine was alive and answering a second
    pipe client immediately.
  - Cause: `handle_client` awaited every request inside the connection's read
    loop, so `vuln.scan` (NVD lookups plus a 6.5 s rate-limit sleep per
    application — minutes for ten apps) also blocked that connection's `ping`.
    The UI's 15 s heartbeat gives up after 5 s, tears the connection down and
    fails every in-flight request with "connection lost", so the scan died as
    collateral damage rather than the engine falling over.
  - Fix: the pipe dispatches each request in its own task (responses carry
    their `id`, so ordering does not matter); `Storage::open` now sets
    `busy_timeout=5000` because two handlers can write at once; the heartbeat
    only probes when nothing is in flight; and `vuln.scan` gets a 10-minute
    client deadline instead of the 120 s default, since the work really is
    minutes on NVD's public rate limit.
  - Evidence: live test against a throwaway engine on `\\.\pipe\mics_test` —
    with `vuln.scan` in flight the `ping` was answered in **81 ms** (it used to
    be queued behind the scan); `cargo test` 16/16, `cargo clippy` clean,
    `flutter analyze` clean, `flutter test` 24/24.
- **P3d — second real-run bug sweep: the Defender checks that guessed instead of reading**
  - **False positive.** "Defender PUA Protection — *PUA protection is not
    explicitly enabled*" was reported on a machine where PUA blocking was
    already on: the check read only the Group Policy key
    (`…\Policies\Microsoft\Windows Defender\MpEngine\PUAProtection`) and ignored
    Defender's own preference store (`…\Microsoft\Windows Defender\
    PUAProtection`), which is where the Windows Security toggle and
    `Set-MpPreference -PUAProtection` persist the choice. PUA state now resolves
    policy first and then the live store — the same precedence the real-time
    protection check already used, and what `Get-MpPreference` reports — so the
    audit, the hardening card and `Get-MpPreference` finally agree. Audit mode
    (2) is reported as a warning (reported, not blocked), not as a pass.
  - **The repair itself failed before it could elevate.** Every click on Fix
    returned `EngineException(-32000) … powershell failed: Set-MpPreference :
    You don't have enough permissions to perform the requested operation`,
    because `snapshot_current` recorded the old value by *calling
    `Set-MpPreference`* — so the snapshot needed an elevated token, ran through
    the unelevated PowerShell path, and the request died before it could reach
    the `RunAs` fallback. The snapshot is strictly read-only now (registry
    read — no WMI provider, works unelevated), and the rollback restores the
    exact value the snapshot saw, removing the value when Defender had nothing
    set instead of guessing its default. A snapshot that still needs
    administrator rights now says so instead of dumping the raw CMDlet error.
  - **A refused status query is not "protection is off".** The real-time
    protection fallback asked `Get-MpComputerStatus` and checked only the exit
    code — a denied WMI query exits 0 with empty stdout, so a healthy machine
    was flagged **Critical: "real-time protection is DISABLED"** (seen live in
    the sandboxed run, audit score 45). Only a real `True`/`False` answer counts
    now; anything else is reported as *unknown* with the reason. That call also
    flashed a console window (the only spawn that skipped `CREATE_NO_WINDOW`) —
    fixed while there.
  - **Exit code 0 is no longer treated as proof.** `hardening.apply` re-reads
    the same state check the UI shows and now fails honestly if Windows still
    reports the setting unchanged (a policy override or Defender tamper
    protection putting the old value back); the PUA permission hint names
    tamper protection and points at Virus & threat protection → Manage
    settings, instead of blaming a missing administrator token alone.
  - Evidence: `cargo test` 16/16 (four new tests: policy-vs-live precedence,
    the verdict mapping, the exact rollback command, and "an empty Defender
    answer is not a false alarm"), `cargo clippy` clean, `flutter analyze`
    clean ("No issues found"), `flutter test` 24/24. Live `serve`-mode check: `audit.run` reports
    PUA = `Secure` / `fix_available:false` (was `Warning` with a broken Fix
    button) and real-time protection = `Unknown` instead of the false
    Critical, and `hardening.list` agrees (`pua_protection applied=true`). On
    the reference machine PUA is already blocking (`…\Microsoft\Windows Defender\
    PUAProtection = 1`) while Tamper Protection is on (`Features\
    TamperProtection = 5`), which is why the setting refused to be written
    programmatically — and why the honest "unchanged" error matters.
- **P4b — two icon designs, three files, no upscaling anywhere**
  - The shipping art is now vector: `assets/icons/task.svg` (taskbar, Alt-Tab,
    Explorer, title bar, tray) and `assets/icons/Desktop.svg` (desktop shortcut
    only — a `.lnk` keeps its own icon location, which is how the desktop can
    differ from the taskbar).
  - Pipeline: `tool/rasterize_icons.ps1` renders both SVGs at 1024 px with
    transparency (headless Chrome/Edge — the only offline rasteriser available),
    then `tool/make_icons.py` trims the transparent border, centres the art at
    94 % of a square canvas and writes `windows/runner/resources/app_icon.ico`
    (task), `assets/icons/mics.ico` (task) and `assets/icons/desktop.ico`
    (desktop) with all ten sizes.
  - `scripts/create-shortcuts.ps1` creates the desktop shortcut (desktop art)
    and the Start-Menu shortcut (embedded task art); both were created and
    verified on the reference machine.
  - Fixed two real defects: the files were crossed (the executable carried the
    desktop art while the tray carried the task art), and the artwork filled only
    ~55 % of the canvas, which made every icon look undersized next to others.
  - `test/icon_test.dart` now fails if `desktop.ico` is a copy of the task icon
    or if the SVG sources/masters disappear. Verified on the rebuilt binary: the
    embedded icon matches `task.png` exactly (mean channel difference 0.00) and
    differs from the desktop art (110.15).
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
| 4 | Permissions asked once, publisher name | **partial P1.5** — the helper, its closed op set, audit trail and Settings card are shipped and proven unelevated; one interactive UAC prompt still installs the service, and publisher naming still needs D-002's certificate | D-007, `docs/PRIVILEGED-OPS.md` |
| 5 | Complete advanced Settings screen | **done** — 8 sections, every field writes through `settings.set` | D-008 |
| 6 | App update paths | **partial** — the manifest URL + channel are real settings and `update.check`/`download`/`apply` work; no compiled-in default manifest, no signature check on the manifest, no rollback screen | P3, P4 |
| 7 | CVE/intel update paths | **done** — per-source scheduled sync with state/backoff (D-012), Intel screen with per-source results and last errors, vulnerability scan as a cancellable job with live progress, KEV badge on exploited CVEs | D-012, P3c1–P3c3 |
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

## 5. Next up — one prompt, then the installer

Everything else in P2/P3 that could be verified without administrator rights is
done (settings, i18n, sounds, theme, offline badge, update flow, transport,
resumable jobs, desktop cards, and the portable ZIP + `SHA256SUMS` that
`verify-release.ps1` checks end to end). What remains needs either one interactive
UAC prompt (finishing P1.5) or money (P4 signing certificate).

### P1.5 — one UAC prompt, publisher-attributed (D-007)
- [x] `docs/PRIVILEGED-OPS.md`: every admin operation enumerated (firewall
      add/remove/default-deny, hosts rewrite, hardening apply/rollback) with its
      payload, validation, audit record and reversibility.
- [x] Windows service `MICSHelper` installed once (`sc create`) via a one-shot
      elevated helper; UI stays `asInvoker`, Settings card shows the state.
- [x] Helper protocol over its own named pipe with an ACL limited to LocalSystem,
      administrators and interactive users; every call logged to the state
      folder's `logs\priv.log` before and after it runs.
- [x] Engine routes the privileged operations through the helper; the
      per-operation `Start-Process -Verb RunAs` calls are gone from
      `firewall/mod.rs`, `ids/mod.rs`, `hardening/mod.rs`, and with them the
      "Relaunch as administrator" stop gap in the Settings screen.
- [ ] **Acceptance (needs you):** install the helper once from
      **Settings → Engine → Install helper** (one prompt), then enable Default-Deny,
      turn SMBv1 off and import a hosts list in one session: **zero** further
      prompts, and `logs\priv.log` carries one `phase=start`/`phase=done` pair per
      operation. Everything below that step is already proven unelevated by
      `scripts\verify-helper.ps1`.
- Note: the prompt shows "MI CS" as publisher only with a trusted certificate
  (D-002) — until then it shows the helper's unsigned identity.

### Leftovers from P2 (non-blocking)
- [ ] Light-mode contrast audit (text/borders/severity colours) with screenshots.
- [ ] `docs/PROTECTION-MATRIX.md` (today the README carries the matrix).

### Cheap wins — no elevation, no money, no new subsystem
These can be done in any order and each is one small commit. They are listed
because P1.5 and P4 both need something only you can supply (a UAC prompt and a
signing certificate respectively), so this is the work that is always available.

- [x] `status` returns the real crate version and platform instead of hardcoded
      `0.1.0` / `windows` (now `windows-x86_64` + pid).
- [x] `audit.run` honours `params.sections` instead of running everything
      (7 ms for one section instead of 1.7 s; unknown names are refused).
- [x] Add timeouts to the `netsh` / elevated-PowerShell calls in `firewall/mod.rs`
      and `ids/mod.rs`, the way hardening was fixed — an unanswered prompt or a
      stalled service must not wedge a request. Done as a shared runner
      (`platform/windows/process.rs`) for every spawn in `firewall` and
      `hardening`; `ids` spawns nothing itself (it goes through the helper).
      Extended to **every** external tool: the audit probes, the update extract,
      the autostart `reg` calls, `icacls`, `taskkill` and `sc.exe` all run through
      `ToolCall`, the async Defender scan carries its own `tokio::time::timeout`,
      and a test fails on any bare `Command::new` outside the runner.
- [ ] Decide the VirusTotal client's fate: wire the sync queue that fills it, or
      delete the dead code and say so in the README (MED).
- [x] Regenerate the portable ZIP + `SHA256SUMS` from the current
      `dist/MICS-portable`, so the published artifact matches the deployed build
      (`scripts\make-release.ps1` + `scripts\verify-release.ps1`; the folder now
      also ships `rules\`, which every previous deploy had dropped).
- [ ] ARM64 build leg (Flutter + `aarch64-pc-windows-msvc` engine), per D-003.
- [ ] Trim the guard/benchmark CPU from 2.97 % towards the < 1 % budget, or move
      the budget to a measured, justified number (MED).
- [ ] `docs/PROTECTION-MATRIX.md` + `docs/THREAT-MODEL.md` (P5 wording work, no
      code involved).

---

## 6. Backlog by phase

### P3 — updates & intel
- [x] Update check + channels + download/apply **UI** (`update.check`,
      `update.download`, `update.apply`), with release notes and real errors.
- [ ] Default update manifest URL compiled in (still user-supplied) and a signed
      manifest check before applying.
- [x] OFFLINE badge + "intel last updated Xh ago" in the title bar, tap to sync.
- [x] Intel pipeline hardening: named sources in one scheduled pass, per-source
      state + backoff + `sync_state.next_due`, DNS-blocklist domains, CISA KEV
      catalog (D-012). YARA/IPC packs wait for a signature-delivery mechanism.
- [x] A dedicated sync/intel screen with per-source results and last-error text,
      plus a configurable hash feed (`ioc_feed_url`/`ioc_feed_key`) — P3c3.

### P4 — release engineering
- [ ] Authenticode: OV/EV or Azure Trusted Signing; sign DLLs then EXEs;
      timestamp; `signtool verify` in CI; document SmartScreen reality.
      *Reality measured 2026-10-30:* the app is `NotSigned`, Smart App Control is
      off, SmartScreen policy is default, and the reputation endpoints are
      reachable — yet Windows still shows "SmartScreen can't be reached right now"
      / "Unknown publisher", because an unsigned first-seen binary has no
      reputation to look up. Even a working lookup would only say "unknown".
      => The **local** half is solved (`make-release.ps1 -Sign` with a self-signed
      certificate trusted in `CurrentUser\Root` + `TrustedPublisher`: all binaries
      `Valid`, `signtool verify /pa` passes, prompts stop on this machine). What
      remains in this item is only the **public** half: a real OV/EV (or Azure
      Trusted Signing) certificate, timestamping through the `-PfxPath` path, and
      CI wiring — the scripts already take it.
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
| HIGH | No installer: the portable ZIP + `SHA256SUMS` are produced and verified, but there is no NSIS installer, no code signing and no published download | `dist/`, P4 |
| HIGH | A user who copies the package by hand can drop `rules\` and get the compiled-in starter pack silently (the engine now logs which file it used, and `verify-release.ps1` fails when the package is incomplete) | `dist/`, `guard/mod.rs`, `scanner/mod.rs` |
| LOW | `audit.run` can now re-check one section in milliseconds, but the UI still re-runs the whole audit after a fix (the engine side is ready, the caller is not) | `dispatcher.rs`, `providers.dart` |
| MED | Defender **tamper protection** refuses programmatic preference writes, so `Set-MpPreference -PUAProtection` can fail even when the engine is elevated; `hardening.apply` now detects the no-op and points at the Windows Security switch instead of claiming success | `hardening/mod.rs` |
| LOW | `vuln.scan` (the blocking variant) still exists for probes and scripts; it shares the scanner with the job but has no progress/cancel of its own | `vulns/mod.rs`, `dispatcher.rs` |
| LOW | Alerts are attributed by AUMID `MICS` without registering an AppUserModelID (no Start-Menu shortcut property, no `HKCU\Software\Classes\AppUserModelId\MICS`), so Windows' own notification settings/Action Center label the source as `MICS` rather than "MI CS". Registration is not required for the card to appear (proven with cards in the history), and adding it changes a shortcut outside the app folder — fold it into the P4 installer | `notify/toast.rs`, `scripts/create-shortcuts.ps1` |
| MED | VirusTotal client is dead code (only reachable from the sync queue, which nothing fills) | `scanner/vt.rs` |
| MED | IDS = hosts-file blocklist (DNS only); no Suricata/ET-Open | `ids/mod.rs` |
| MED | Canaries detect mtime/size changes by polling; a read-only open is not detected | `guard/canary.rs` |
| MED | Firewall uses `netsh`, not FirewallAPI COM | `firewall/mod.rs` |
| MED | Benchmark CPU 2.97 % vs the < 1 % budget (`budget_ok:false`) | `benchmark.rs` |
| LOW | Country CIDR lists are read from disk only (public country-list licences are unclear), so GeoIP stays empty on a fresh install until lists are placed in `rules\blocklists` or `%PROGRAMDATA%\MICS\blocklists` | `ids/geoip.rs` |
| LOW | No key-free sha256 hash feed exists any more (abuse.ch needs an Auth-Key), so `ioc_hashes` reports `not_configured` until the user pastes a URL + key in Settings → Intelligence (env hooks `MICS_IOC_FEED_URL`/`MICS_IOC_FEED_KEY` still work) | `sync/mod.rs` |
| LOW | `docs/` has no THREAT-MODEL yet (the README carries the layer matrix) | `docs/` |
| LOW | Light-mode palette has not been contrast-audited | `app_theme.dart` |
| LOW | UI is not yet obfuscated and ships without an integrity manifest | P5 |

## Icon sizes required for the application

The Windows UI uses a single master PNG (`assets/icons/mics.png`, 256 × 256) that is
converted by `tool/make_icons.py` into the standard set of **ten** icon sizes. All
three delivery formats (embedded app icon, tray icon, installer resources) must
contain each of the following dimensions:

| Size (px) | Usage inside Windows |
|----------|----------------------|
| 16 × 16   | Toolbar, small menus |
| 20 × 20   | Title‑bar icons in Small‑size mode |
| 24 × 24   | Desktop shortcuts (Large‑icons) |
| 32 × 32   | Window / Explorer icon |
| 40 × 40   | Control panel icons (Large‑icons) |
| 48 × 48   | Start menu icon (Medium) |
| 64 × 64   | Task‑bar icon at High‑DPI |
| 96 × 96   | Task‑bar / Start at High‑DPI |
| 128 × 128 | Tile in Start‑menu |
| 256 × 256 *master* | Source for generating all the above sizes |

**Pending icon‑related tasks**
- [ ] Ensure `test/icon_test.dart` passes for all sizes without loss.
- [ ] Verify `windows/runner/resources/app_icon.ico` includes all sizes.

**Other remaining tasks**
- [ ] Light‑mode contrast audit and add screenshots to documentation.
- [ ] Complete `docs/PROTECTION-MATRIX.md` as a standalone document (currently only in README).
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
12. **The workspace is a low-integrity tree, and Windows refuses toasts to
    low-integrity processes.** The DSH sandbox labels the workspace root
    `Mandatory Label\Low Mandatory Level:(OI)(CI)(NW)`; every file created under
    it inherits that label, and a process whose image is Low runs at Low
    integrity. Symptom: `CreateToastNotifierWithId` fails with
    `0x80073D54 The process has no package identity` (which reads like a missing
    registration) for **every** alert, while the identical binary copied to
    `%TEMP%` or `H:\mics-loc-test` shows the card. Diagnose with
    `icacls <path>` (look for the `Mandatory Label` line) or by copying
    `powershell.exe` into the folder and running `whoami /groups` from it.
    Fixes: run the app from a normal folder (a portable copy under
    `%LOCALAPPDATA%` needs no prompt), or raise the label once as an
    administrator — `icacls "<folder>" /setintegritylevel Medium /T /C`. A
    medium-integrity process cannot do it (no `SeRelabelPrivilege`): `icacls`
    answers "Access is denied". The engine detects this case itself and says so
    instead of echoing the HRESULT (`notify/test`, engine log).
13. **Windows PowerShell 5.1 can deadlock when a native command's stderr is
    redirected into a PowerShell stream** (`& .\mics-engine.exe helper-status
    2>$null | Out-String` hung forever while the engine was already gone). The
    engine logs to stderr on purpose, so this bites every probe. Redirect both
    streams to files instead
    (`Start-Process -Wait -RedirectStandardOutput x.json -RedirectStandardError y.txt`)
    and read the files — that is what `scripts\verify-helper.ps1` does.
14. **`Copy-Item -Recurse` into an existing folder nests instead of merging**:
    `Copy-Item engine\rules dist\MICS-portable\rules -Recurse` a second time
    produces `dist\MICS-portable\rules\rules\...`, and the rule loaders then read
    the outer folder and find nothing. Packaging scripts must delete the
    destination first (and a probe should assert the layout, not just that the
    files exist somewhere).
15. **Never delete the live package folder in place.** `make-release.ps1` used to
    `Remove-Item dist\MICS-portable -Recurse -Force` before assembling, and MI CS
    was running from that folder: the delete died on `audioplayers_windows_plugin.dll`
    (loaded by the running app) *after* it had already removed `data\` and
    `rules\` — a half-empty package, and a running app missing its assets. Two
    rules now: assemble into `MICS-portable.staging` and swap it in only when no
    process is running from the target (otherwise leave the folder alone and say
    so), and let `SHA256SUMS` describe **the zip and its contents** rather than the
    mutable folder — `verify-release.ps1` checks those entries against the
    extracted copy, so a stale working folder can no longer fail the release
    verification (it did, with `listed b7361e67 / actual d092f559`).

16. **The published folder can disappear without any of our code doing it.** On
    2026-10-30 at 17:18:03 the whole of `dist\` (the folder, the zip and
    `SHA256SUMS`) was gone between one command and the next. Ruled out by
    measurement: no Defender detection or quarantine (the operational log's last
    entry is hours older, `Get-MpThreatDetection` shows nothing for that path), no
    script in the repo removes `dist\*` (only `$staging`, `$zip`, `$portable`
    individually), `dist` is not a reparse point, and an ordinary delete of a
    *child container* there should have been refused anyway — the tree carries
    `Everyone:(CI)(DENY)(DC)` plus a Low Mandatory Level label, i.e. this is a
    host-managed web root (`H:\FlyEnv\...\server\www\`) with ACLs we did not set.
    So the agent is outside the repo and unproven. Two consequences, both now
    standing rules: `dist\` is a *build output* and never the thing to run or
    trust (re-create it with `scripts\make-release.ps1 -Sign`, which is
    idempotent and re-hashes), and the runnable copy lives in
    `%LOCALAPPDATA%\MI CS`, outside the managed tree.
    - Related trap, same tree: a package sitting inside that low-integrity tree
      **cannot raise notification cards at all**. The engine says so itself now —
      `notify.test` from `dist\MICS-portable\mics-engine.exe` answers
      `0x80073D54 ... MIF is running from a confined folder`. That is also why a
      card read out of the toast history right after such a run was *stale* (it
      came from an older session) and still said "MI CS" after the rename: always
      clear the history before reading it back (`verify-toast.ps1` does), and prove
      cards from `%LOCALAPPDATA%\MI CS`, not from `dist`.

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
