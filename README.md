# 🛡️ MI CS — Mourad Ibrahim Cyber Security

**Smart. Transparent. Open-source defense.** · **حماية ذكية، شفافة، ومفتوحة المصدر**

MI CS is a free, open-source cybersecurity command center for Windows: a
multi-layer defense wall, malware scanner, real-time process monitor,
vulnerability scanner and hardening center — with an interface that prioritises,
explains, and suggests the next action instead of dumping raw data.

> **Status: pre-release.** The features below are implemented and covered by
> tests, but packaging, code signing and the single-elevation helper are still
> in progress. Live status: [`docs/TODO.md`](docs/TODO.md). Design decisions:
> [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## What MI CS does

| Area | What you actually get |
|---|---|
| **System audit** | Real checks: Defender status, firewall profiles, RDP, SMBv1, UAC + secure desktop, local administrators, startup entries, non-Microsoft scheduled tasks, hosts file, remote-access tools. Returns a 0–100 score with the highest-impact finding first and a one-click fix where one exists. |
| **Malware scanner** | Triage-ordered scan (location × extension × size × age): SHA-256 against a local IOC cache first, then YARA rules. Runs as a **durable job** — if the engine restarts mid-scan it resumes at the exact next file, and the UI shows live progress. |
| **Quarantine** | Detections are encrypted with AES-256-GCM; the master key is protected with DPAPI. Files can be restored or deleted from the app. |
| **Process guard (L3)** | Watches process creation against Sigma-like JSON rules (`rules/guard/*.json`, hot-reloaded). Alerts, optional kill-tree response, canary (decoy) files that raise a CRITICAL alert when touched, an incident correlator that groups related events into one kill-chain timeline, and a noise learner that offers to mute what you keep dismissing. |
| **Network monitor** | Live TCP/UDP connections with owning process, plus a firewall manager: default-deny outbound toggle and every rule MI CS creates is prefixed `MICS-`. Country blocking works from a locally synced CIDR list. |
| **IDS (L2, minimal)** | Domain blocklist enforced through a managed section of the hosts file, so every application on the machine is blocked from those domains. |
| **Vulnerability scanner** | Matches installed software against the NVD database (API 2.0), with an offline cache and honest "from cache" labelling. Runs as a cancellable job with live progress, and flags CVEs that CISA lists as **exploited in the wild** (KEV badge with the remediation date). |
| **Intelligence** | One card per intel source (DNS blocklist, CISA KEV, file hashes, country lists, NVD) with its own state, count, next attempt and last error, plus what the machine actually holds. Sources that need a URL or key say so instead of silently staying empty. |
| **Hardening center** | Five one-click fixes (Defender PUA protection, SMBv1 off, RDP off, UAC + secure desktop, Defender quick scan). Every change takes a snapshot first and can be rolled back. |
| **Reports** | One-click Markdown security report (score, findings, startup entries, incident kill-chains) written to `Documents\MICS-Reports\`. |
| **Notifications** | A desktop card above the taskbar for **every** security event: a file the scanner catches (with a working **Quarantine** button), a suspicious process, a canary touch, or a protection action (default-deny, country block, hosts blocklist update). Cards fire **even when the window is closed**, speak the app language (AR/EN), and follow one policy: CRITICAL/HIGH/MEDIUM become cards, LOW stays in the app, do-not-disturb keeps only CRITICAL, and a switch turns cards off entirely. In-house notification sounds with volume and mute are separate. |
| **Privileged helper** | Admin work (firewall, hosts file, hardening) goes through one LocalSystem service installed with a **single** UAC prompt instead of one per action. The operation set is closed and documented (`docs/PRIVILEGED-OPS.md`), every call is audited before and after it runs, and an unelevated helper refuses instead of half-applying. |
| **Languages** | Arabic and English, complete, with full RTL layout. Language packs are per-module files; adding a language is one folder plus one line. |

**Architecture in one line:** a Flutter UI talks JSON-RPC 2.0 over the named pipe
`\\.\pipe\mics_engine` to a single Rust engine (`mics-engine.exe`), which owns
every OS call. The UI never touches system APIs.

Two different kinds of name, on purpose. **In Task Manager** the two halves are
listed as **MI Cyber Security** (the app) and **MiShild Background** (the engine),
and both wear the **same icon** — those strings and that icon come from each
executable's version resource, so the files are still `mics_app.exe` and
`mics-engine.exe` (the names every script, the app's engine lookup and
`MICS_ENGINE_PATH` use). Right-click → *Properties* → *Details* shows the same
thing; the *Details* tab of Task Manager always shows the file name.

**Inside the product** the name is **MI CS**: the window title, the title bar, the
tray tooltip and the header of every notification card. The desktop shortcut is
**MICS** and takes its icon from `mics_app.exe`, so the desktop, the taskbar,
Alt-Tab, Explorer and the engine's Task Manager row all show one icon. The
`MICS-*` firewall rule prefix and the `MICS_*` test hooks are identifiers and keep
their spelling.

## What MI CS does **not** do

Honesty is a feature. Today, MI CS does **not**:

- install a **kernel driver** or filter network traffic inline — it is a usermode
  product and cannot see traffic before the OS does;
- ship **ClamAV**, **CAPA** or a **Suricata/ET-Open** IDS engine; L4 is IOC
  hashes + YARA, and L2 is a hosts-file domain blocklist (documented as
  "minimal mode");
- detect **any writer touch** on a canary file — decoys are monitored by
  mtime/size polling, so a read-only open is not noticed (writes, renames and
  deletes are);
- use the **VirusTotal** client in the scan path yet (the client exists, but
  nothing queues a lookup);
- promise that an update is signed by *us* and not just by *someone*: the payload
  must carry an embedded Authenticode signature from `CN=MI CS Code Signing` that
  Windows trusts (`docs/THREAT-MODEL.md` F-3), but the pin is the signer's name, not
  its thumbprint;
- guarantee that "fix" buttons work without administrator rights: firewall,
  hosts-file and hardening changes are privileged. The app installs its
  **privileged helper** with one Windows prompt the first time you use such a
  fix, and never asks again (see `docs/PRIVILEGED-OPS.md`);
- hide the fact that **unsigned binaries show "Unknown publisher"** in Windows
  dialogs. That needs a trusted Authenticode certificate and is planned;
- claim **idle CPU below the 1 % budget**: the guard loop costs **0.156 % of one
  core = 0.0028 % of a 56-thread machine** (`scripts/measure-guard-cpu.ps1`, guard on
  versus `MICS_NO_GUARD=1`), so the budget holds whether it is read per core or per
  machine — and it did not before: 3.52 % of a core until the poll loop was trimmed,
  and the "2.97 %" quoted earlier came from a benchmark that was mostly measuring its
  own probe (`mics-engine benchmark` now reports its own `GetProcessTimes`, with
  `cpu_percent` and `cpu_percent_of_machine`). RAM is ~12 MB, inside budget.

## Requirements

| | |
|---|---|
| **OS** | Windows 10 21H2+ or Windows 11 (x64). Windows 11 ARM64: planned. 32-bit Windows: not supported — Flutter has no 32-bit Windows desktop target. |
| **CPU / RAM** | 4 cores / 8 GB. The engine idles at ~11 MB RAM. |
| **Disk** | ~150 MB for the app + engine, plus whatever the quarantine and intel cache grow to. |
| **Privileges** | none to start: the app runs unelevated. The first firewall/hosts/hardening fix asks **once** to install MI CS's privileged helper (a LocalSystem service); after that, privileged actions need no prompt. |
| **Network** | optional. Everything core works offline; the network is used only for intel sync, NVD lookups, VirusTotal (if you add a key) and a local LM Studio instance (if you run one). |

## Install and first run

Today MI CS ships as a **portable folder and a portable archive** (an installer is
still to come):

1. Take `MICS-portable-<version>-x64.zip`, or the already-unpacked
   `dist\MICS-portable` folder, and put it anywhere (for example
   `C:\Program Files\MI CS\`). `dist\SHA256SUMS` lists the SHA-256 of the zip and
   of the files inside it, so a single extracted file can be checked too. The
   unpacked folder is a convenience copy: if MI CS is running from it,
   `make-release.ps1` leaves it alone rather than deleting files in use — the zip
   is the release.
2. Run `mics_app.exe`. Windows may warn about an unknown publisher, or SmartScreen
   may say it **can't reach** its reputation service — the build is unsigned, so
   there is nothing for it to verify. The
   [Troubleshooting](#troubleshooting) table has the run-anyway, hash-check and
   `Unblock-File` steps; signing is planned (see [What MI CS does not do](#what-mi-cs-does-not-do)).
3. The app starts the engine automatically, runs a first audit (~10 s) and shows
   your score with the single most valuable fix to make.
4. The first privileged fix asks once to install the helper
   (`Settings → Engine → Install helper` also does it explicitly); the card then
   shows **ready** and no later action prompts again.

The engine log says which rule file it loaded (`rules\yara\starter.yar` and
`rules\guard\starter.json` next to the binaries, hot-reloaded): if it ever says
"built-in starter pack" instead, the copy is incomplete — `rules\` is missing.

**Uninstall:** quit MI CS from the tray, remove the helper
(`Settings → Engine → Remove helper`, one prompt), delete the app folder, then
delete the data folder below. The only registry entry MI CS can create is an
optional `HKCU\...\Run` value (`Settings → Engine → Start with Windows`), removed
by the same screen.

## Where your data lives

| What | Location |
|---|---|
| State (database, settings, logs, quarantine, synced blocklists) | `%PROGRAMDATA%\MICS`, or `%LOCALAPPDATA%\MICS` when the machine-wide folder is not writable by your user. The chosen path is remembered in `%LOCALAPPDATA%\MICS\.data-dir` and printed at engine startup as `data=…`. |
| Settings | `settings.json` in the state folder — read by **both** the UI and the engine so they can never disagree. |
| Engine log | `logs\engine.log`, rotated at 5 MB (a per-process file is used if the main log is not writable). |
| Quarantine | `Quarantine\` — AES-256-GCM blobs, master key protected with DPAPI. |
| Reports | `Documents\MICS-Reports\` |
| Canary decoys | `Documents` and `Desktop` by default; configurable in Settings. |
| Rules | `rules\` next to the executable (YARA + guard JSON), hot-reloaded; the shipped package includes the packs, and the engine logs which file it used. A built-in starter pack is the fallback when that folder is missing. |

Set `MICS_DATA_DIR` to relocate the whole state folder (portable mode).

## Privacy

- **No telemetry, no accounts, no ads.** Nothing about your usage is reported
  anywhere.
- Nothing leaves the machine except what you explicitly trigger: intel sync
  (public IOC feeds), NVD queries, VirusTotal lookups (only with your own key)
  and a local LM Studio instance on `127.0.0.1` (only if you run one).
- State is local SQLite plus plain files you can inspect and delete.

## The five layers

| Layer | Implemented as | Protects against | Does not cover |
|---|---|---|---|
| **L1 Network Gate** | Windows Firewall management (`netsh`): default-deny outbound, `MICS-*` rules, per-country CIDR blocking | Unwanted outbound traffic and known-bad ranges, once rules exist | No deep packet inspection — it is policy, not an inline filter |
| **L2 Attack Radar** | Managed hosts-file domain blocklist + GeoIP tables from synced blocklists | Name resolution to known malicious/tracking domains, for every app | Raw-IP traffic, DoH inside apps, no packet inspection |
| **L3 Response** | Process guard (2 s poll unelevated, kernel ETW when elevated), Sigma-like rules, kill-tree, canaries, incident correlator | Suspicious process creation, persistence attempts, ransomware-style decoy touches | Not a kernel driver; an attacker who is already admin is out of scope |
| **L4 File Engines** | Triage scanner: SHA-256 vs local IOC cache, then YARA rules | Known-bad files by hash and by pattern | No ClamAV signatures, no CAPA, no unpacking |
| **L5 Mind** | Incident correlation (kill-chain timeline) + assistant: built-in AR/EN templates, optionally a **local** LLM (LM Studio) | Alert fatigue — related events become one incident with a story | The command bar is rule-based (regex intents), not an LLM planner |

## Settings

One screen, eight sections; every field is validated and persisted by the engine:

- **Appearance / language** — dark, light, follow system (live), AR/EN.
- **Protection** — guard autostart, resume interrupted scans, default
  auto-quarantine, canary paths.
- **Notifications & sounds** — desktop cards on/off, do-not-disturb, sounds
  on/off, volume, test toast, test sound.
- **Intelligence & schedule** — refresh interval (1–168 h), NVD key, optional hash
  feed URL and Auth-Key, sync now, live connectivity and freshness.
- **Integrations** — VirusTotal key, LM Studio URL and model.
- **Updates** — manifest URL, stable/beta channel, check, download and install.
- **Engine** — executable path, connection state, start with Windows, and the
  **privileged helper** card (state, version, install/repair/remove).
- **About** — version, license, tagline.

## Building from source

Prerequisites: **Flutter 3.x** (Windows desktop enabled), **Rust stable** (MSVC
toolchain) and **Visual Studio 2022** with *Desktop development with C++*.

```powershell
# 1) Engine
cd engine
$env:YRX_REGENERATE_MODULES_RS = "false"   # yara-x build script; safe with a read-only cargo registry
cargo build --release

# 2) App
cd ..
flutter pub get
flutter build windows --release

# 3) Assemble the portable release (engine + rules + app + zip + SHA256SUMS)
powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1
```

`MICS_ENGINE_PATH` overrides the engine location if you keep it elsewhere.
`make-release.ps1` first checks that the committed third-party inventory
(`sbom.cdx.json` and `THIRD-PARTY-NOTICES`) still describes the lockfiles, and
ships both in the package; regenerate them with `dart run tool\sbom.dart` after
any dependency change. It then assembles into a staging folder, copies
`engine\rules` next to the binaries (the guard and YARA packs are hot-reloaded
from there — a package without them silently falls back to the compiled-in pack),
refuses to continue if anything required is missing, writes `VERSION`, and
produces `dist\MICS-portable-<version>-x64.zip` plus `dist\SHA256SUMS`. The
staging build is then swapped into `dist\MICS-portable` — unless MI CS is running
from that folder, in which case it is left untouched and only the zip is
refreshed. Add `-SkipBuild` to repackage without rebuilding the app, or
`-EnginePath <exe>` when cargo builds somewhere else.

Check what you just produced — hashes, completeness, and that the extracted copy
serves the privileged helper protocol, puts a real card on the desktop, and loads
its **own** rules rather than the fallback:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify-release.ps1
```

**Signing (this is what stops the SmartScreen prompt).** Windows blocks an
unsigned binary it has never seen. Sign the package in the same step as the build:

```powershell
# self-signed certificate, trusted on this machine only - no certificate to buy,
# no elevation, and Windows shows the publisher instead of refusing the app
powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Sign

# or with a real OV/EV certificate for a public release (this also timestamps)
powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Sign `
  -PfxPath cert.pfx -PfxPassword "***"
```

`-Sign` signs `mics_app.exe`, `mics-engine.exe` and the bundled DLLs **before**
they are hashed and zipped, so `SHA256SUMS` describes the signed files. The
self-signed mode creates `CN=MI CS Code Signing` in `Cert:\CurrentUser\My` and
trusts it in `CurrentUser\Root` + `CurrentUser\TrustedPublisher` (neither needs
administrator rights), then verifies every file and fails the release if one does
not come back `Valid`. A self-signed signature is **local trust only**: it removes
the prompt on your machine, it does not give the file a public reputation — that
needs a real certificate and downloads by strangers (see `docs/TODO.md`, P4).

**Icons.** `assets/icons/mics.png` is the 256×256 master art. Both Windows icons
— `windows/runner/resources/app_icon.ico` (embedded in `mics_app.exe`, so it is
what Explorer, the taskbar, Alt-Tab, the title bar and the UAC dialog show) and
`assets/icons/mics.ico` (the tray icon) — are generated from it at every
standard size:

```powershell
python tool/make_icons.py            # regenerate both from the master
python tool/make_icons.py logo.png   # adopt new art as the master first
```

`test/icon_test.dart` fails the build if either icon loses a size
(16/20/24/32/40/48/64/96/128/256) or if the two drift apart.

## Testing

```powershell
cd engine
cargo test                                # 51 tests
cargo clippy --release -- -D warnings     # must stay clean
cd ..
flutter analyze --no-pub                  # must report no issues
flutter test --no-pub                     # 31 tests

# End-to-end transport check (needs an engine on an isolated pipe)
$env:MICS_PIPE_NAME   = '\\.\pipe\mics_engine_test'
$env:MICS_NO_SINGLETON = '1'; $env:MICS_NO_GUARD = '1'
dart run tool\pipe_smoke.dart             # production pipe client: ping/status/job.list
dart run tool\pipe_probe.dart <folder>     # raw protocol + progress/job_finished push

# A real notification card reached the desktop (reads Windows' own history)
powershell -ExecutionPolicy Bypass -File scripts\verify-toast.ps1

# The privileged helper's protocol, refusals and audit trail - no UAC needed
powershell -ExecutionPolicy Bypass -File scripts\verify-helper.ps1

# The published archive: hashes, completeness, and the extracted copy running
powershell -ExecutionPolicy Bypass -File scripts\verify-release.ps1
```

Test hooks exist so an isolated engine can be run without touching production
code: `MICS_DATA_DIR`, `MICS_PIPE_NAME`, `MICS_NO_SINGLETON`, `MICS_NO_GUARD`,
`MICS_NO_AUTO_RESUME`, `MICS_ENGINE_PATH`, `MICS_HELPER_PIPE`,
`MICS_HELPER_LOG`.

## Icons

Two designs, three icon files, one pipeline:

| Source (vector) | Used for | Output |
|---|---|---|
| `assets/icons/task.svg` | taskbar, Alt-Tab, Explorer, window title bar, **the engine's Task Manager row** and the **desktop shortcut** | `windows/runner/resources/app_icon.ico` (embedded in `mics_app.exe`; the engine embeds the same file at build time) |
| `assets/icons/task.svg` | tray icon and any packaged copy | `assets/icons/mics.ico` |
| `assets/icons/Desktop.svg` | bundled alternative art, shipped but not used by any shortcut today | `assets/icons/desktop.ico` |

One product, one icon: `scripts/create-shortcuts.ps1` writes a desktop shortcut
named **MICS** (plus **MI CS** in the Start Menu), and both take their icon from
`mics_app.exe` — so the desktop, the taskbar, Alt-Tab, Explorer and the engine's
row in Task Manager show the same art. `engine/build.rs` embeds the very same
`.ico` into `mics-engine.exe`; without that the engine would show Windows' generic
icon.

```powershell
# 1) render the SVGs to 1024 px transparent masters (Chrome/Edge headless)
powershell -ExecutionPolicy Bypass -File tool\rasterize_icons.ps1

# 2) trim, centre and write every Windows size into the three .ico files
python tool\make_icons.py

# 3) create desktop + Start-Menu shortcuts with the right art
powershell -ExecutionPolicy Bypass -File scripts\create-shortcuts.ps1

# 4) register the AUMID so Windows names the notification source "MI CS"
powershell -ExecutionPolicy Bypass -File scripts\register-aumid.ps1
```

`register-aumid.ps1` writes `HKCU\Software\Classes\AppUserModelId\MICS`
(`DisplayName`, `IconUri`) and tags both shortcuts with
`System.AppUserModel.ID = MICS`, which is what makes the Action Center and
Settings → Notifications show **MI CS** instead of the raw id the engine raises
cards under. It needs no elevation and no new file, and `-Remove` undoes both;
`scripts\verify-aumid.ps1` reads the key, the shortcut property and the Shell's
own `Get-StartApps` AppID back, and exits non-zero with the list of what did not
hold.

Every icon carries the ten sizes Windows actually asks for — **16, 20, 24, 32,
40, 48, 64, 96, 128, 256** — so no surface has to upscale and look soft. Give
the rasteriser art at **256×256 or larger** (Windows never uses more than 256;
1024 is what keeps that 256 frame crisp). `test/icon_test.dart` fails the build
if a size disappears, if the task icons drift apart, or if `desktop.ico` becomes
a copy of the task icon.

## Project layout

| Path | What |
|---|---|
| `lib/` | Flutter UI (Riverpod, go_router) — speaks JSON-RPC only. |
| `engine/` | Rust engine: audit collectors, scanner, guard, firewall, IDS, hardening, jobs, settings, storage. |
| `engine/rules/` | Bundled YARA pack and Sigma-like guard rules (hot-reloaded). |
| `assets/i18n/<lang>/<module>.json` | Translation packs — one file per module, one folder per language. |
| `assets/sounds/` | In-house notification cues. |
| `assets/icons/` | Icon sources (`task.svg`, `Desktop.svg`) and the generated `.ico` files. |
| `scripts/` | User-facing helpers and acceptance probes: code signing, shortcuts, `verify-toast.ps1`, `verify-helper.ps1`. |
| `docs/` | `TODO.md` (live status), `DECISIONS.md` (why things are the way they are), `PRIVILEGED-OPS.md` (the helper's complete operation list). |
| `tool/` | Developer probes, icon pipeline and one-off helpers (not shipped). |

## Troubleshooting

| Symptom | Meaning / what to do |
|---|---|
| "Unknown publisher" / *Windows protected your PC* | Builds are unsigned by default. Sign them with a certificate trusted on your machine: `powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Sign` (self-signed, no admin, no purchase) — then the publisher is named and the block stops. A public release needs a real OV/EV certificate; see [Building from source](#building-from-source). |
| SmartScreen says *"SmartScreen can't be reached right now"* or *"Windows protected your PC"* | Not a virus report — Windows is saying it could not verify a publisher, and (when the message says *can't be reached*) the reputation check itself failed, e.g. behind a proxy, VPN or flaky link. Choose **More info → Run anyway**, or launch without the Explorer hook: `Start-Process "$env:LOCALAPPDATA\MI CS\mics_app.exe"`. Before running anything you downloaded, verify it: `Get-FileHash .\MICS-portable-0.1.0-x64.zip -Algorithm SHA256` and compare with `SHA256SUMS`. If the zip was downloaded, unblock it **before** extracting (`Unblock-File .\MICS-portable-0.1.0-x64.zip`) and the extracted files inherit no mark-of-the-web. |
| A fix reports a permissions error | That change needs administrator rights: use **Settings → Engine → Install helper** (one prompt), then retry — it should not ask again. |
| No desktop cards appear | Check **Settings → Notifications → Desktop notifications** and do-not-disturb (it keeps only CRITICAL). Windows also refuses cards to a **low-integrity** process, which is what you get when the app runs from a confined/sandboxed folder — including a web-root tree like `...\server\www\`, where the folder carries a Low Mandatory Level label: move MI CS to a normal folder (`%LOCALAPPDATA%\MI CS` is the tested one), or raise the folder's label with `icacls "<folder>" /setintegritylevel Medium /T` as an administrator. The engine names the reason itself in `notify.test`'s error and in the log. |
| Engine shows *Engine not found* | `mics-engine.exe` must sit next to `mics_app.exe` (or set `MICS_ENGINE_PATH`). |
| A scan looks stuck | It is a durable job — watch the progress card. Closing the window does not stop it, and killing the engine is safe: it resumes at the next file. |
| Offline | Only intel sync needs the network. The chip shows `Offline` and how old the synced intel is. |
| Need the engine log | `logs\engine.log` inside the state folder (see *Where your data lives*); privileged calls are in `logs\priv.log`. |

## Contributing, security, license

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, test and submit changes.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability.
- [`AGENTS.md`](AGENTS.md) — rules for automated contributors.
- **License: GPL-3.0-or-later.** Every dependency must be GPL-compatible; no
  telemetry, no paid tiers, optional donation link only.
- **Every dependency is accounted for.** [`sbom.cdx.json`](sbom.cdx.json)
  (CycloneDX 1.6) lists all 579 components behind the two lockfiles — 483 Rust
  crates, 87 Dart packages, 6 Flutter SDK packages, the Cairo and JetBrains Mono
  fonts, and the Visual C++ runtime the app needs but does not ship — each with the
  license it declares and the SHA-256 the lockfile pins.
  [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES) names the option MI CS relies on
  wherever a crate offers a choice ("MIT OR Apache-2.0") and reproduces the full
  text of every one of those licenses. Both files are generated from the lockfiles
  by `dart run tool\sbom.dart`, are regenerated into the package by
  `make-release.ps1`, and `dart run tool\sbom.dart --check` fails when they no
  longer describe the tree.
- **Third-party intel feeds.** Two public data sets are fetched by the scheduled
  sync and keep their own licenses: [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
  (MIT) is used as the DNS blocklist, and the
  [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (US Government work, public domain) marks CVEs that are exploited in the wild.
  Both are downloaded to your machine and are never redistributed with the app.
  The hash blocklist has no bundled default: abuse.ch's public exports now need
  an Auth-Key, so `ioc_hashes` stays empty until you paste your own feed URL and
  key into Settings → Intelligence. The
  [Intelligence screen](lib/features/intel/screens/intel_screen.dart) shows what
  each source produced, when it is due next and the last error if it is failing.

---

## نظرة عامة بالعربية

**MI CS** (مراد إبراهيم — الأمن السيبراني) تطبيق مجاني مفتوح المصدر للويندوز:
جدار دفاع متعدد الطبقات + فاحص ملفات + مراقبة عمليات لحظية + فاحص ثغرات + مركز
تقوية — بواجهة **ترتّب** النتائج وتشرحها وتقول لك تعمل إيه بعد كده.

فيه نوعين من الأسماء، وده مقصود. **في التاسك مانجر** الجزئين بيظهروا باسم
**MI Cyber Security** (الواجهة) و **MiShild Background** (المحرك)، والاتنين
شايلين **نفس الأيقونة** — الاسم والأيقونة جايين من version resource بتاع كل exe،
فالملفات لسه `mics_app.exe` و`mics-engine.exe` (الأسماء اللي كل السكريبتات والبحث
بتاع الواجهة و`MICS_ENGINE_PATH` بيعتمدوا عليها). كليك يمين → *Properties* →
*Details* بيوضّح نفس الاسم، وتاب *Details* في التاسك مانجر بيعرض اسم الملف دايمًا.

**جوه التطبيق** الاسم هو **MI CS**: عنوان النافذة، والشريط العلوي، ونص أيقونة
التاسك بار، وهيدر كل كارت إشعار. وأيقونة سطح المكتب اسمها **MICS** وبتاخد
أيقونتها من `mics_app.exe`، فسطح المكتب والتاسك بار وAlt-Tab والـ Explorer وسطر
المحرك في التاسك مانجر كلهم بيوروا نفس الأيقونة. أما بادئة قواعد الجدار `MICS-*`
ومتغيرات الاختبار `MICS_*` فهي معرّفات وباقية زي ما هي.

**اللي بيعمله فعلاً:** فحص نظام حقيقي (ديفندر، جدار الحماية، RDP، SMBv1، UAC،
المدراء، بدء التشغيل، المهام المجدولة، ملف hosts) بدرجة من 100 وإصلاح بضغطة واحدة؛
فحص ملفات مرتّب حسب الخطورة (SHA-256 مقابل كاش IOC ثم قواعد YARA) وبيكمّل لوحده لو
المحرك اتقفل في النص؛ حجر مشفّر AES-256-GCM بمفتاح محمي بـ DPAPI؛ حارس عمليات
بقواعد قابلة للتحديث + فخاخ (ملفات طُعم) + قتل شجرة العملية + ربط الحوادث في خط
زمني واحد؛ مراقبة اتصالات وتحكّم في جدار الحماية؛ حجب دومينات عبر hosts؛ مطابقة
البرامج المثبّتة بقاعدة NVD؛ تقارير Markdown؛ **كارت إشعار على سطح المكتب لكل
حدث أمني** — ملف الفاحص لقاه (وزرار حجر شغال)، عملية مشبوهة، فخ اتلمس، أو إجراء
حماية اتنفّذ — بيظهر حتى لو النافذة مقفولة، وبلغتك، وبزرار واحد في الإعدادات
يقفله؛ وأصوات داخلية بمستوى صوت وكتم؛ واجهة عربي/إنجليزي كاملة مع RTL. وكل شغل
المدير (فايروول / hosts / تقوية) بيمر على **خدمة مساعدة واحدة** بتتثبّت بضغطة UAC
واحدة بدل ضغطة لكل عملية، وكل عملية بتتسجّل قبلها وبعدها في `logs\priv.log`.

**اللي مابيعملهوش (بصراحة):** مفيش درايفر kernel ولا فلترة ترافيك داخلية؛ مفيش
ClamAV ولا CAPA ولا Suricata؛ الفخاخ بتتكشف بالـ polling — يعني قراءة الملف
للقراءة فقط مش بتتسجّل؛ عميل VirusTotal موجود بس لسه مش مربوط بمسار الفحص؛
التحديثات بتتحقق بـ SHA-256 بس (من غير توقيع رقمي)؛ ملفات التنفيذ **غير موقّعة**
فوندوز بيقول «ناشر غير معروف»؛ وضغطة UAC الواحدة اللي بتثبّت خدمة المساعدة لسه
محتاجة تتجرّب بإيدك (الكود والاختبارات والرفض الآمن جاهزين ومُتأكَّد منهم).

**المتطلبات:** ويندوز 10 (21H2+) أو 11، 64-bit. معالج 4 أنوية و8 جيجا رام
(المحرك بيستهلك ~11 ميجا في الخمول) وحوالي 150 ميجا مساحة. التطبيق بيفتح
**من غير صلاحيات مدير**، وأول إصلاح إداري بيطلب ضغطة UAC **مرة واحدة** لتثبيت
خدمة المساعدة وبعدها مفيش أي طلب تاني، والنت مش مطلوبة غير للتحديثات — الفحص
والحماية والحجر والتقوية كلهم شغالين أوفلاين.

**الخصوصية:** مفيش أي تتبّع ولا حسابات. كل حاجة محلية في SQLite، ومفيش حاجة بتطلع
من الجهاز غير اللي إنت تشغّله بنفسك (تحديث الاستخبارات، NVD، VirusTotal بمفتاحك،
أو LM Studio محلي).

**ملفات البيانات:** `%PROGRAMDATA%\MICS` — أو `%LOCALAPPDATA%\MICS` لو الأول
مش قابل للكتابة بحسابك. الاختيار بيتسجّل في `%LOCALAPPDATA%\MICS\.data-dir`
وبيتطبع في أول سطر لوج للمحرك (`data=…`). تقدر تحدّد المكان بنفسك بمتغيّر
`MICS_DATA_DIR`.

**الترخيص:** GPL-3.0-or-later — كل الاعتماديات لازم تكون متوافقة مع GPL.

**التشغيل من السورس:** محتاج Flutter 3.x و Rust stable و Visual Studio 2022
(Desktop C++)، وبعد البناء انسخ `mics-engine.exe` ومجلد `rules` جنب
`mics_app.exe` — التفاصيل كاملة فوق في قسم *Building from source*.

**الاختبارات:** `cargo test` (51) و `cargo clippy` نضيف، و`flutter analyze`
بدون ملاحظات و`flutter test` (31). وفيه أدوات تحقق بتختبر الحقيقة مش الكود:
`tool/` لنقل البيانات بين الواجهة والمحرك، و`scripts\verify-toast.ps1` بيتأكد إن
كارت إشعار وصل فعلًا لسطح المكتب، و`scripts\verify-helper.ps1` بيختبر بروتوكول
خدمة المساعدة ورفضها الآمن من غير أي UAC، و`scripts\verify-release.ps1` بيتأكد إن
النسخة المنشورة مطابقة للـ SHA256SUMS وكاملة وإن نسختها المستخرجة بتشتغل فعلًا
وبتحمّل قواعدها من جوه الحزمة نفسها.

**النسخة الجاهزة:** `scripts\make-release.ps1` بيتأكد الأول إن ملفات الإفصاح عن
مكونات الطرف التالت (`sbom.cdx.json` بصيغة CycloneDX 1.6 و`THIRD-PARTY-NOTICES`)
لسه مطابقة لملفات الـ lock، وبيشحنهم جوه النسخة — ولو غيّرت أي مكتبة، جدّدهم بـ
`dart run tool\sbom.dart`؛ بعد كده بيجهّز النسخة في فولدر مؤقت
(المحرك + مجلد `rules` + الواجهة) وبيطلّع
`dist\MICS-portable-<version>-x64.zip` مع `dist\SHA256SUMS`، وبيرفض يكمّل لو أي
ملف أساسي ناقص. الفولدر المؤقت بيتنقل مكان `dist\MICS-portable` بعد كده — إلا لو
فيه نسخة من MI CS شغالة منه، ساعتها بيسيبه زي ما هو وبيحدّث الـ zip بس، عشان
مايمسحش ملفات مستخدمة (ده اللي حصل مرة وخلى الفولدر أنقص). لوج المحرك بيقول حمّل
قواعد منين — لو قال «built-in starter pack» يبقى مجلد `rules` ناقص من النسخة.

**لو ظهرت رسالة SmartScreen** («Windows protected your PC» أو «SmartScreen can't be
reached right now» أو «ناشر غير معروف») فالحل إنك توقّع النسخة بمفتاح موثوق على
جهازك، من غير فلوس ومن غير صلاحيات مدير:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\make-release.ps1 -Sign
```

ده بيعمل شهادة `CN=MI CS Code Signing` ويحطها في `CurrentUser\Root` و
`CurrentUser\TrustedPublisher`، ويوقّع `mics_app.exe` و`mics-engine.exe` وكل
الـ DLLs **قبل** الهاش والـ zip، فويّندوز بيبقى عنده ناشر يسمّيه بدل ما يرفض
التطبيق. التوقيع الذاتي ثقة **محلية** بس — بيشيل الرسالة على جهازك، لكنه مش
سمعة عامة؛ النشر للناس محتاج شهادة حقيقية (P4).


**ولو الكروت مش بتظهر:** اتأكد من **Settings -> Notifications -> Desktop notifications**
ومن وضع عدم الإزعاج (بيسمح بالـ CRITICAL بس). وكمان ويندوز بيرفض الكروت لأي عملية
**سلامتها منخفضة (low integrity)** — وده بيحصل لو شغّلت التطبيق من فولدر مقيّد أو من
شجرة سيرفر ويب زي `...\server\www\`، لأن الفولدر ساعتها شايل Low Mandatory Level label:
انقل MI CS لفولدر عادي (`%LOCALAPPDATA%\MI CS` هو المجرّب)، أو ارفع تصنيف الفولدر
بأمر مدير: `icacls "<folder>" /setintegritylevel Medium /T`. والمحرك نفسه بيقول السبب
في رسالة `notify.test` وفي اللوج.

ولو الرسالة لسه ظاهرة: اختار **More info → Run anyway**، أو شغّل التطبيق من غير
هوك الـ Explorer: `Start-Process "$env:LOCALAPPDATA\MI CS\mics_app.exe"`. وقبل ما
تشغّل أي حاجة نزّلتها، اتأكد منها:
`Get-FileHash .\MICS-portable-0.1.0-x64.zip -Algorithm SHA256` وقارنه بالـ
`SHA256SUMS`. ولو الـ zip اتنزّل من النت، اعمل له `Unblock-File` **قبل** ما تفكّه.

**الحالة الحالية:** التطبيق شغال فعليًا: بيرفع المحرك، بيعمل فحص حقيقي،
بيسجّل النتائج، وبيكمّل أي فحص اتقطع، وبطلّع كارت على سطح المكتب لكل حدث. اللي
فاضل: **ضغطة UAC واحدة** بتثبّت خدمة المساعدة (كل اللي تحتها متأكَّد منه)،
شهادة توقيع، مثبّت رسمي، ودعم ARM64 — كلها متتبَّعة في
[`docs/TODO.md`](docs/TODO.md).
