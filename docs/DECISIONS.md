# MI CS — Decisions Log

Durable record of product/engineering decisions. One entry per decision:
what was decided, why, and what it commits us to. Code and docs stay in
English; user-facing replies are Egyptian Arabic.

---

## D-001 — License: GPL-3.0-or-later + trademark protection

**Status:** accepted (2026-10-28)

**Decision.** The project stays GPL-3.0-or-later. Protection against misuse is
achieved through brand and distribution integrity, not through hiding source:

- trademark on the "MI CS" name and shield mark (registration is a later,
  user-owned action);
- Authenticode-signed release binaries;
- a signed integrity manifest (SHA256 of shipped files);
- an explicit "unofficial build" notice in the About screen and README for
  builds that fail the integrity check.

**Why.** The product brief promises free/open-source. A source-available or
non-commercial license would contradict that identity and break the community
premise, while obfuscation of a GPL work is legally fragile.

**Commits us to.** Publishing `LICENSE` (already present), keeping the source
public, and documenting that "protection" means attribution + integrity +
trademark — never secrecy. See D-007 for the technical integrity work.

---

## D-002 — Code signing: self-signed now, trusted certificate later

**Status:** accepted (2026-10-28)

**Decision.** Ship development/portable builds signed with the existing
self-signed script (`scripts/sign.ps1 -SelfSigned`). A publicly trusted
certificate is deferred to the release phase and is a user decision at that
time (OV vs EV vs Azure Trusted Signing).

**Why.** Signing infrastructure and the verify step must exist from day one,
but a certificate costs money and requires identity/business validation with
lead time. Deferring it does not block any engineering work.

**Commits us to.** Keeping `sign.ps1` working, adding signature verification to
the release checklist, and documenting in `SECURITY.md` + README that unsigned
or self-signed builds show "Unknown publisher" in UAC and may trigger
SmartScreen warnings.

**Amendment (2026-11-07, D-035 — the certificate is no longer "later").** The
deferral above assumed the release phase would buy one. It will not: the project
buys nothing, and a publicly trusted certificate is **closed as not-purchased**
rather than postponed. Everything else in this entry stands — `sign.ps1`, the
verify step, and the honest README wording — and the wiring is *better* than it
was, because D-034 makes a donated certificate a two-secret drop-in with no code
change. What replaces the certificate is the free, checkable evidence D-035
names. Read D-035 before touching anything about signing, SmartScreen or the
`CN=MI CS Code Signing` pin.

---

## D-003 — Architectures: x64 + ARM64, optional x86 CLI only

**Status:** accepted (2026-10-28)

**Decision.** Ship Windows x64 (primary) and Windows ARM64 (app + engine).
A 32-bit (x86) desktop UI is **out of scope** because Flutter has no 32-bit
Windows desktop target. Optionally build an x86 CLI build of the engine
(`i686-pc-windows-msvc`) for legacy/automation use — no UI.

**Why.** Windows 11 is 64-bit only, and the UI technology cannot produce a
32-bit binary at all. Promising a 32-bit app would be a promise the stack
cannot keep.

**Commits us to.** Documenting the limitation and its reason in the README
("Requirements"), and adding an ARM64 build leg to CI when ARM64 hardware or
runners are available for verification.

**Amendment (2026-11-03, ب2 — the leg is wired, and here is where it stops).**
The engine half is real: `scripts\build-engine-arm64.ps1` builds
`aarch64-pc-windows-msvc` (engine **and** test binaries) and
`verify-hardening.ps1 -Arch arm64` reads the PE back (`machine 0xAA64`, CFG,
ASLR/DEP, stripped). Three prerequisites are not where a Windows developer would
look, and that is measured, not assumed: the MSVC ARM64 build tools live in
**Visual Studio 18 Community** on this machine, while the 2022 Build Tools have
only x64/x86 toolchains and no `lib\arm64`; `ring` needs a **clang** for its
assembly and the VS LLVM component ships only `clang-format`/`clang-tidy`, so the
build uses the **Android NDK's** LLVM (clang 19) as a build-time tool; the
Windows SDK already has the arm64 import libraries.

Two limits are architectural rather than local: **Flutter has no Windows
cross-compile flag** — `flutter build windows` picks the target from the host
(`windows-arm64` only when the host is ARM64, `commands\build_windows.dart`), and
this SDK's cache holds `windows-x64*` only — so a portable ARM64 package needs an
ARM64 host, while its engine can be built anywhere. **Correction (2026-11-04):**
an earlier version of this paragraph said GitHub's ARM64 Windows runners were
public-repo only and that a `windows-11-arm` job "would queue forever". That was
wrong: the runners reference lists `windows-11-arm` for **private** repositories
as well (2 vCPU/8 GB, drawing on the account's included minutes) and for public
ones (4 vCPU/16 GB, free and unlimited). What is true is different and still
matters: no ARM64 job has been written or run yet, an ARM64 job on a private repo
costs minutes, and a Windows runner is an **administrator with UAC disabled**, so
CI can install the helper and drive privileged operations but cannot reproduce the
"one prompt, then no prompts" half of P1.5. The consequence for this decision is
therefore the opposite of what was written: the ARM64 app leg and the ARM64 test
run are reachable through CI without an ARM64 machine, which is planned work, not
a limitation. **Second correction (2026-11-04, measured on the first run):** the
ARM64 *app* leg is not reachable through CI either, because Flutter publishes no
Windows ARM64 SDK at all — 0 of the **747** archives in
`storage.googleapis.com/flutter_infra_release/releases/releases_windows.json`
mention arm64 — and `subosito/flutter-action@v2` says it in as many words when the
runner is ARM64: `Unable to determine Flutter version for channel: stable version:
any architecture: arm64` (release run 41922523593, job 126898444291). The two ARM64
jobs now ask for what exists: the **engine** job runs `cargo test --release`
natively on `windows-11-arm` (the host target is already
`aarch64-pc-windows-msvc`), and the packaging job asks for the **x64** SDK to run
under emulation plus `targets: aarch64-pc-windows-msvc` for the engine half, which
`make-release.ps1 -Arch arm64` checks for before it packages. Whether the app then
builds as ARM64 is exactly what that job answers: `flutter build windows` takes the
target from the host platform, and `verify-hardening.ps1 -Arch arm64` refuses an
x64 package, so a green job would mean a real ARM64 app and a red one means the
tooling cannot do it yet. Until then the ARM64 claim stays engine-level. The SBOM stays
architecture-independent on purpose — it describes the dependency set, which is
shared — and the artifact names its own arch (`-<arch>.zip`, the `VERSION` line,
and the PE machine that `verify-release.ps1` refuses to disagree with).

Until an ARM64 machine exists, the claim for this leg is **"built and
compile-verified, never executed"**, and no runtime number is carried across from
the x64 runs.

---

## D-004 — Notification sounds: in-house pack + Windows system sounds

**Status:** implemented (2026-10-29)

**Decision.** Ship a small in-house generated sound pack (a handful of short
WAV cues: info / success / warning / critical) plus Windows system sounds for
generic events. No third-party audio assets.

**Why.** Zero licensing risk, zero cost, small installer, full control over
tone and duration on a low-end machine.

**Implementation notes.**
- `assets/sounds/{info,success,warning,critical}.wav` are generated tones
  (16-bit mono), produced in-house; `test/sound_assets_test.dart` asserts every
  cue exists and is a valid RIFF/WAVE file, and that no stray files are shipped.
- Two playback paths by design:
  - **engine** (`engine/src/notify/sound.rs`): critical/high cues play even when
    the UI is closed, via `PlaySound` straight from bytes embedded in the binary
    (no asset path to lose, no extra file to install). Respects
    `sound_enabled` and DND. Windows' `PlaySound` has no per-app volume, so the
    engine cue follows the system volume — documented in the module.
  - **UI** (`lib/core/audio/sound_service.dart`): every cue, honouring the
    Settings volume slider, the on/off toggle and DND. `SoundRouter` maps engine
    events (`canary_triggered`, `process_suspicious`, `threat_detected`,
    `job_finished` with findings) to cues, and works with either transport
    payload shape.
- Settings gained a "play a test sound" button next to the toast test.

**Commits us to.** Keeping the pack in-house; any third-party asset must be
recorded in `THIRD-PARTY-NOTICES` before it ships (P4).

---

## D-005 — AI assistant: optional local LLM, honest wording

**Status:** accepted (2026-10-28)

**Decision.** The "MI CS Assistant" stays an **optional** enhancement:

- explanations always work via built-in AR/EN templates;
- if a local LM Studio (OpenAI-compatible) instance is reachable, explanations
  are generated by it;
- the natural-language command bar is a **rule-based intent parser** (regex);
  it is not an LLM planner;
- no cloud LLM, no telemetry, nothing leaves the machine.

**Why.** The current code implements exactly this, while the README claims
"LLM-powered analysis" for L5. Shipping a documented capability that the code
does not implement is the fastest way to lose trust.

**Commits us to.** Rewriting L5 and the assistant section in the README and in
the product brief as "event correlation + optional local-LLM explanations",
and adding a "What MI CS does not do" section. Any future LLM planning must
ship with function-calling against the whitelist and be documented before it
is advertised.

---

## D-006 — Single transport and single engine instance

**Status:** implemented (2026-10-28)

**Decision.** The UI connects to the engine over the Windows named pipe
`\\.\pipe\mics_engine` (service mode) instead of spawning its own stdio engine.
A single-instance mutex (`Local\MICS_Engine_Singleton`) guarantees exactly one
engine per machine. The engine pushes `event` and `progress` notifications on
the same connection.

**Why.** The old app spawned `mics-engine --serve` while the autostart entry ran
`mics-engine --service`: two engines fighting over the firewall, guard, and
quarantine, and a UI close lost every in-flight scan.

**Implementation notes.**
- `engine/src/platform/windows/pipe.rs`: accept loop that survives transient
  create failures, one writer task per client, notification forwarder.
- `engine/src/platform/windows/single_instance.rs`: named-mutex guard.
- `engine/src/jobs.rs` + `engine/src/scanner/mod.rs`: durable jobs. The
  triage-ordered queue, the cursor (`jobs.processed`), and all findings are in
  SQLite, so a crash/restart resumes at the exact next file.
  `MICS_NO_AUTO_RESUME=1` disables automatic resume.
- `lib/core/ipc/pipe_client.dart`: `CreateFileW` + two isolates (blocking
  `ReadFile` / `WriteFile`), UTF-8 line framing, reconnect with 1→2→5→10 s
  backoff and a 15 s `ping` heartbeat.
- `--serve` remains for CLI and tests only; it is no longer the app's transport.
- Engine logs go to stderr **and** `%PROGRAMDATA%\MICS\logs\engine.log`
  (rotated at 5 MB) because the detached service has no console.
- `MICS_NO_GUARD=1` is a test hook that keeps the service from arming the guard.

**Known limitation.** Settings that reach the engine as environment variables
(VT key, LM Studio URL, sync interval) only apply when this app starts the
engine. D-008 moves them into `settings.json`, which the engine reads directly.

---

## D-007 — Elevation: one prompt, through a privileged helper

**Status:** implemented, one interactive prompt left to verify (2026-10-30)

**Decision.** All admin operations go through a single privileged helper
installed once (Windows service). The UI runs `asInvoker` and never triggers
UAC for individual actions.

**Why.** Today every firewall/hosts/hardening operation spawns its own
`-Verb RunAs` PowerShell, so the user sees repeated prompts attributed to
"Windows PowerShell" rather than to MI CS.

**Commits us to.** Publishing the exact privileged operation list in
`docs/THREAT-MODEL.md`, auditing every call, and documenting that a
publisher-named UAC prompt requires the trusted certificate from D-002.

**Implementation addendum (2026-10-30).** The list now lives in
`docs/PRIVILEGED-OPS.md` (the threat model will link to it, not duplicate it),
and the helper is `MICSHelper`, a LocalSystem service that points back at the
same `mics-engine.exe helper-service` (a subcommand, not a flag — see D-007 rule 4),
so an upgrade rewrites the definition
instead of leaving an old helper behind.

1. **`Op` is a closed enum**, not a command line: eight named operations
   (ping/version, three firewall ops, hosts rewrite, hardening run/rollback).
   There is no variant that runs an arbitrary command, so a bug cannot turn the
   pipe into "SYSTEM shell as a service".
2. **Validate before executing.** Payload shape (rule direction/action, hosts
   document marker + address/host pairs, rollback commands limited to shapes this
   codebase generates) is checked *before* the op runs or is logged as started.
   The hosts path therefore cannot overwrite an arbitrary file.
3. **Audit first, payload never.** Every call writes `phase=start` and
   `phase=done ok=… dur_ms=…` to `%PROGRAMDATA%\MICS\logs\priv.log`; documents are
   represented by `bytes`/`lines`/`sha256[..16]`, never copied.
4. **One prompt, then none.** `install-helper` is the only elevated step and is
   started by the engine (`ensure()`) on the first privileged action. It polls the
   pipe for 20 s and only reports success when the helper answers — "sc said Ok"
   is not evidence. `uninstall-helper` treats a missing service as done. Both are
   CLI subcommands, so the engine must not spell them as flags: `Cli` refuses
   `--install-helper` with a usage error (exit 2) before the child logs anything,
   which is exactly how the first shipped build failed silently. The two names
   live in `privileged::INSTALL_COMMAND`/`UNINSTALL_COMMAND` and a test parses
   them with the real CLI.
5. **Refuse, do not half-apply.** A helper started without an elevated token
   answers the privileged ops with the reason; `--helper-console` exists to prove
   exactly that unelevated (`scripts\verify-helper.ps1`, `docs/PRIVILEGED-OPS.md`).
6. The old per-operation `Start-Process -Verb RunAs` paths are gone from
   `firewall/`, `ids/` and `hardening/`: those modules now call
   `privileged::run_op` when they are not already elevated.

**Still unproven:** the elevated install itself (service creation, LocalSystem
pipe ACL) needs one interactive UAC prompt that no automated run can answer. The
Settings card reports `not_installed / not_running / unelevated / ready` from
`socket + version + token` facts, so the first real install is observable.

---

## D-008 — Settings are a single source of truth

**Status:** implemented (2026-10-28)

**Decision.** Application settings live in one file
(`%PROGRAMDATA%\MICS\settings.json`) read by both the UI and the engine.
Every setting has a UI control, a default, validation, and a documented effect.

**Why.** The old `AppSettings` model defined DND, VT key, LM Studio URL, sync
interval, and update manifest URL, but no screen exposed them, `patchSettings`
was never called, and changing the language rebuilt the object from two fields
— silently wiping every other setting. Engine-side options were environment
variables that only applied when *this app* started the engine.

**Implementation notes.**
- `engine/src/settings.rs`: typed document, `serde(default)` so an older file
  still loads, `apply_patch` rejects unknown keys and out-of-range values
  (`-32602` with the reason), atomic write (`.tmp` + rename), process-wide cache.
- JSON-RPC `settings.get` / `settings.set`; a successful set broadcasts
  `event{type: settings.changed}` so any connected surface refreshes.
- Consumers read the document instead of the environment: guard autostart,
  auto-resume, DND (`toast.rs`), LM Studio URL/model, NVD key, update
  manifest URL, and the auto-sync cadence (re-read every cycle, so a change
  applies without restarting the engine).
- Environment variables remain as a **test override** and are documented as
  such (`MICS_SYNC_HOURS`, `MICS_DND`, `MICS_LM_URL`,
  `MICS_LM_MODEL`, `MICS_UPDATE_MANIFEST_URL`, `NVD_API_KEY`).
- UI: `AppSettings` is a typed mirror of the same field names; every control
  calls `settings.set`, the state updates from the engine's response, and the
  last known document is cached in `shared_preferences` only so the window can
  paint before the engine answers. Legacy preferences are migrated once
  (`settingsMigratedV2`).
- Added `notify.test` so the Settings screen can prove toasts (and DND) work.

**Commits us to.** Adding a new setting means: field in `settings.rs` + default +
validation + UI control + a test — never a UI-only preference.

---

## D-009 — Translations are per-module files, guarded by tests

**Status:** implemented (2026-10-28)

**Decision.** Every language is a folder (`assets/i18n/<lang>/`) with one JSON
file per module (app, nav, engine, dashboard, common, audit, scanner, network,
ids, vulns, guard, canaries, hardening, incidents, reports, settings). Keys stay
flat and namespaced (`scanner.scan`), the loader merges the modules into one
lookup table, and two tests make drift impossible to merge:

- parity: identical module files, identical key sets, no empty values, identical
  `{placeholders}` in every language;
- lint: user-facing copy must arrive through `context.tr(...)`; a literal inside
  `Text('…')` fails the build unless it is pure interpolation or an explicitly
  allowed brand/legal/path string.

**Why.** One flat `ar.json`/`en.json` pair becomes unmergeable as the app grows,
and a missing key silently degrades to English — the user sees a half-translated
screen with no signal. Splitting by screen also means a contributor translating
one screen touches one file.

**Commits us to.** Adding a language = copy a folder + one line in
`bundledLangs`. Adding a key = same commit in every language folder. No widget
may hardcode copy.

---

## D-010 — The UI runs unelevated; elevation is explicit and per-need

**Status:** implemented (2026-10-29)

**Decision.** `mics_app.exe` is manifested `asInvoker`. It never asks for
administrator rights at launch. Privileged work is done by the engine, which:

1. runs the command directly when its token is already elevated, and only falls
   back to `Start-Process -Verb RunAs` when it is not;
2. returns the real failure reason over JSON-RPC (never the generic
   "Method failed internally"), including a hint when the cause is permissions;
3. offers `app.relaunch_elevated`, which the Settings screen exposes as
   "Relaunch as administrator" for the user who actually wants those fixes.

**Why.** The previous manifest asked for `requireAdministrator`, which made every
launch a UAC prompt attributed to an unsigned "unknown publisher" — the single
most alarming thing a security tool can do — and contradicted the architecture
rule that the UI starts unelevated. It also hid failures behind a generic error.

**Commits us to.** Keeping the single-elevation helper (D-007) as the end state;
until then, admin-only actions must fail with a clear, actionable message and a
one-click way to elevate deliberately.

---

## D-011 — Data directory resolution and permissions

**Status:** implemented (2026-10-29)

**Decision.** State lives in the first location that is actually usable:

1. `MICS_DATA_DIR` (explicit override: portable mode, tests, isolated runs);
2. the directory remembered in `%LOCALAPPDATA%\MICS\.data-dir`;
3. `%PROGRAMDATA%\MICS` (the documented machine-wide layout) — chosen when the
   folder *and* the existing database/`settings.json` are writable, or when the
   engine is elevated (it can then repair them);
4. `%LOCALAPPDATA%\MICS` otherwise.

The choice is sticky: the first successful resolution is written to the pointer
file, so an elevated run and an unelevated autostart run can never disagree
about where the state lives. "Writable" is proven with a real
`BEGIN IMMEDIATE` transaction on the database, not just a folder probe — a
directory created by an earlier elevated run can be writable while its database
and WAL sidecars are read-only for this user.

When the engine is elevated and the machine-wide directory is not fully writable
for the current user, it grants that user modify rights once (`icacls /T`,
idempotent, recorded with a marker file).

**Why.** Running the engine unelevated (D-010, and the autostart entry) against a
directory created by an earlier elevated run produced "attempt to write a
readonly database" — the engine could start but could not persist anything. A
data directory that silently cannot be written is worse than a second location.

**Commits us to.** Documenting the resolved path in the startup log line
(`data=...`) and in the README; the installer (P4) must create the machine-wide
directory with the right ACL so (3) never triggers on a normal install.

## D-012 — Intel is a registry of named sources, each with its own state and backoff

**Context.** Until P3c the sync was one pass over two hard-coded URLs guarded by
a single `last_success` row. Testing it against the live endpoints exposed two
problems at once: the abuse.ch CSV exports now answer `410 Gone` (they require
an Auth-Key), so the only source the engine had was permanently broken, and
because the state was a single number the UI could only ever say "never synced"
- it could not name the dead feed, let alone keep the healthy ones running.

**Decision.** Intel is a fixed registry of named sources:

| source | what it feeds | default | cadence |
|---|---|---|---|
| `ioc_hashes` | file-hash blocklist (`ioc_hashes`) | none - needs a URL (abuse.ch now wants an Auth-Key) | sync interval |
| `ioc_domains` | DNS blocklist (`ioc_domains`) | StevenBlack/hosts (MIT) | sync interval |
| `kev` | `kev_cves`, annotates vulnerability results | CISA KEV catalog (public domain) | sync interval |
| `geoip_blocklists` | country CIDR lists already on disk | none - read from disk, never downloaded | sync interval |
| `nvd` | CVE cache (`cve_cache`) | NVD 2.0 during a vulnerability scan | on demand |

1. Every source stores `last_success`, `last_attempt`, `failures`, `last_error`,
   `next_due`, `detail` and `items`. The scheduled pass runs only what is due; a
   manual "sync now" runs everything.
2. A failure backs off `15 min x 2^n`, capped at the normal cadence: a dead feed
   is retried *less* often than the schedule, never more often.
3. "Not configured" is a state of its own: it counts as neither success nor
   failure, never claims freshness, and never spends the backoff ladder.
4. `age_seconds`/`last_success` in `sync.status` mean the newest successful
   *network* source, so a local list refresh cannot make an offline machine look
   up to date.
5. No source ships a URL we cannot honestly fetch: country CIDR lists are read
   from disk because the public country-list licences are unclear, and YARA/IOC
   packs beyond what the bundled `engine/rules/` already carries (Neo23x0's
   signature-base is CC BY-NC) wait for a real signature-delivery mechanism.
6. `nvd` is reported as an on-demand row recorded by the vulnerability scan
   itself, rather than scheduled - there is no feed to poll.

**Why.** One aggregate freshness number hides exactly what an operator needs:
which feed is stale, why it failed, and when the next attempt happens. Keeping a
dead default URL in the code is worse than shipping no default at all.

**Commits us to.** Adding a source means adding it to the registry, an i18n
label and a row on the Intel screen. StevenBlack and CISA must be credited in
the README/NOTICES when their data is used, and any new feed must be live-probed
before it becomes a default.

**Addendum (P3c3).** The one source a user can legitimately supply is the hash
feed, so `ioc_feed_url`/`ioc_feed_key` are stored in the settings document (env
hooks `MICS_IOC_FEED_URL`/`MICS_IOC_FEED_KEY` still win, as everywhere else) and
edited from Settings → Intelligence; the key is sent as an `Auth-Key` header, not
a query parameter, so it cannot leak into a logged URL. `sync.status` carries the
per-source rows (`source`, `state`, `items`, `detail`, `last_error`, `failures`,
`age_seconds`, `seconds_to_due`, `on_demand`) so the UI renders the registry
instead of inventing its own summary. Exploit status is data, not decoration:
`Vulnerability` carries `known_exploited`/`kev_due` and the UI shows a KEV badge,
because a CVSS score alone cannot say which of two 8.8s is being exploited today.

**Amendment (و4, 2026-11-03).** The two keys are no longer stored in the settings
document. `nvd_api_key` and `ioc_feed_key` live in `<data dir>\secrets.dat`,
DPAPI-protected at machine scope (the primitive the quarantine master key uses —
the same threat decision, F-6) behind a `MS1\0` header, written before the
document and replaced atomically; `settings.json` carries neither field, and a
file an older build wrote is migrated on the next start, once. `settings.get`
still returns the values (the UI prefills the inputs and it is the same
interactive user), so this changes what is at rest, not the RPC contract. The
environment hooks keep winning, as they always have.

---

## D-013 — Desktop alert cards: one policy gate, engine-side, verified by Windows' own record

**Status:** accepted (2026-10-30)

**Decision.** Every security event that can reach the desktop goes through one
gate, `engine/src/notify/alert.rs`, and the engine (not the UI) shows the card:

1. **One policy.** `alert::decide(severity, toast_enabled, dnd)` is a pure
   function: `toast_enabled = false` silences everything; do-not-disturb lets
   only CRITICAL through; CRITICAL/HIGH/MEDIUM become cards and LOW stays in the
   app. Producers (guard events, scan findings, firewall/IDS actions) call
   `alert::*` and never `toast::*`, so a new event cannot invent its own rules.
2. **`toast_enabled` is a real setting** in the D-008 document (default `true`,
   Settings → Notifications, `settings.set`), not an env var.
3. **Coverage is "anything that happens", not "anything critical".** The guard
   loop now hands *every* event to the gate, the scanner cards a file the moment
   it is found (first three individually, the rest as one summary), and every
   protection action the product performs (default-deny, country block, hosts
   blocklist) confirms itself on the desktop.
4. **Copy follows `settings.lang`.** The engine writes the card, but the reader
   is the user: titles/actions exist in `ar` and `en` in the engine's copy table
   (`alert::text`), while paths, rule names and reasons stay data.
5. **A card is proven by Windows, not by a return value.**
   `scripts/verify-toast.ps1` clears the AUMID's notification history, triggers a
   card and reads the history back (text included), optionally with the live
   notification window from UI Automation. `Show()` returning `Ok` is not
   evidence, and neither is a failure: the first live probe blamed a stale
   binary, and the real cause was that the app was started from a folder whose
   files carry a Low integrity label — a low-integrity process cannot toast at
   all, and Windows reports it as "no package identity" (`0x80073D54`) whatever
   the AUMID is. The engine now recognises that combination and names it, because
   the raw HRESULT sends the reader chasing a registration problem that does not
   exist.

**Why.** The request that started this phase was "anything that happens — a
caught virus, an attack — should put a card above the taskbar". The engine
already had a toast transport, but only CRITICAL/HIGH guard events used it, the
text was English-only, there was no off switch for cards alone, and the one card
that names a malicious file could never appear: its `launch` payload
(`{"mics-action":"…"}`) was interpolated into an XML *attribute* without escaping
`"`, so `LoadXml` rejected every such toast. A notification layer that fails
silently is worse than none, which is why the policy is pure and testable and the
acceptance test reads Windows' record.

**Commits us to.** New event types call `alert::*`; adding a copy string means
adding it in both languages (the alert tests pin every key the producers use);
`cargo test`, `cargo clippy --release -- -D warnings`, `flutter analyze` and
`flutter test` stay green; and a release is only "alerting" once
`scripts/verify-toast.ps1` reports PASS against the **deployed** binary.

**D-024 adds a second destination, not a second policy.** The rules above still govern
the desktop card; D-024 turns "LOW stays in the app" into a surface (an in-app card in
the window's bottom corner) and fixes what `toast_enabled` and do-not-disturb mean for
it. One gate, two destinations.

## D-024 — In-app alert cards: a second destination of the same gate, not a second policy

**Status:** accepted (2026-11-02)

**Context.** D-013 ended the policy with "LOW stays in the app", but there was no "app"
to stay in: every consumer of the engine's push stream either stored the event (the
Guard screen's list, the incident log) or played a sound, and nothing ever put anything
in front of the user. The desktop card was also the *only* surface, so a user who
switched desktop notifications off said "do not interrupt me" and lost the alerts
entirely, while a LOW event — a rule the user wrote, a process the guard caught but did
not consider dangerous — had nowhere to land at all.

**Decision.** The gate in `engine/src/notify/alert.rs` gains a second destination.
D-013's policy for the desktop is untouched.

1. **One gate, two destinations.** A producer still calls `alert::*` and nothing else.
   The gate decides the desktop card (`decide`, exactly as D-013 fixed it) and the
   in-app card (`decide_in_app`) from the same inputs.
2. **`toast_enabled` is the desktop's switch, not the app's.** Turning desktop
   notifications off silences Windows toasts and nothing else. The in-app cards keep
   coming, which is what makes the switch usable instead of a way to go blind.
3. **Do-not-disturb is the only switch that silences the app**, and it means the same
   thing on both surfaces: CRITICAL passes, everything below it waits. An event with no
   severity is a producer bug, never a card.
4. **LOW reaches the app.** That is what "stays in the app" meant; the desktop still
   refuses it, because a card above the taskbar for every LOW event is a log file.
5. **The engine decides and words the card**, as in D-013: `settings.lang` picks the
   copy and the card arrives as a JSON-RPC push named `alert`
   (`{kind, severity, title, body, bug_id?, report_kind?}`) on the same pipe. The UI
   never reads the settings to decide whether to show a card — it paints what arrives.
6. **A card raised before a UI exists is kept, not lost.** With no transport subscribed
   the engine parks cards in a short queue (`PENDING_CAP = 5`, oldest dropped) and
   hands them to the first client that connects: the `unclean-exit` report is filed
   while the engine is still starting, seconds before the window attaches to the pipe.
   A card is a nudge, not a record, which is why the queue is short.
7. **A filed crash report raises a card carrying its bug id** (ز2-ج gave the id a
   surface; this is how a user learns one exists). The id travels as its own field, and
   the card says delivery is off, because it is: no report has a delivery state until
   ز2-د (D-023). The panic path's card is best effort — the engine is aborting — and the
   bundle on disk, not the card, is the record there.
8. **The card lives in the shell, not in an overlay.** It is a widget in `AppShell`'s
   `Stack`, so it exists on every screen, the UI sweep in `qa/ui` sees and taps it like
   any other control, and the ledger fails if it (or its close button) disappears. It
   sits in the bottom corner — right in LTR, left in RTL, from `rtlProvider` — never
   auto-hides, closes on its own button, and its body opens the screen that explains
   that class of alert. At most three are visible and the newest wins, because the
   record is elsewhere: the Guard screen, the incident list, `crash.list`.

**Why.** "Anything that happens should put a card above the taskbar" was D-013's
request; this is the same request for a user who is looking at the window, and it
answers the contradiction D-013 left behind — LOW had no destination. The alternative
(the UI watching `eventStream` and deciding for itself) would have created a second
policy with its own idea of DND, which is exactly what D-013 forbids.

**Commits us to.** A new alert producer calls `alert::*` and lets the gate choose the
destinations; `settings.lang` stays the only source of card copy, in both languages
(`every_copy_key_exists_in_both_languages` pins it); the `alert` method is a *push*, so
it is not a `qa/methods.json` row (that registry is request methods and stays at 65);
and `flutter test` keeps the shell ledger honest.

## D-014 — A section re-check merges into the last full audit; the engine owns the score

**Context.** `audit.run` can run named `params.sections` (7 ms for one check
against ~1.7 s for the sweep), and the fix buttons needed it: after a fix the
audit screen left the card claiming the machine was still vulnerable (it never
refreshed at all), and the hardening screen re-ran every collector to move one
number. Replacing the report with the partial one is not an option — a score over
part of the checks is not comparable with the full one. Live on the reference
machine the `hosts` section alone scores 85 where the full audit scores 70, so the
dashboard would have shown a number that means something different from the one it
had just replaced.

**Decision.** `audit.run {sections:[...], merge:true}` re-reads those sections and
merges them into the last full audit the engine process remembers.

1. The base is a *full* audit (`audit.run` without `sections`) — the only pass
   that is remembered. A merge with no base is refused (`-32000`, "run the full
   audit first") instead of guessing; the UI turns that refusal into the full
   sweep.
2. The merged report stays complete: `partial:false`, every section listed, and
   one score computed over every finding by `AuditPass::report`. `merged:true`
   with `refreshed:[ids]` says what was re-read, so a complete-looking report is
   explainable rather than suspicious.
3. Merging is keyed by **section id**, not by a finding's display `section`:
   `rdp` and `remote_tools` both report under "Remote Access", so a display-name
   merge would delete one of them and flatter the score. A unit test pins it.
4. A section whose collector fails on the re-read is dropped from the report
   (reported by omission from `sections`), never kept as a stale finding.
5. `merge` must be a boolean and requires `sections`; anything else is `-32602`.

**Why.** A fix is a state change, and the UI must show the machine as it is now
without paying for every collector. Keeping the score in one place — the engine —
is what makes "re-check one section" safe: a client never re-derives a security
number.

**Commits us to.** Any client that re-checks a section passes `merge:true` (or
accepts `partial:true` explicitly); the action-id → section-id table stays in one
place per side (`lib/models/audit_models.dart`, pinned by a Dart test); the merge
keeps its tests (id-keyed replacement, the display-name collision, a failed
re-read, the refusal without a base); and the engine stays the only place that
turns findings into a score.

## D-015 — The engine pipe names its callers: an explicit ACL, not Windows' default

**Context.** `docs/THREAT-MODEL.md` measured the engine's pipe instead of
assuming it, and found Windows' default ACL for a pipe created by an unelevated
process:

```
D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)(A;;FR;;;WD)(A;;FR;;;AN)
```

`Everyone` and `ANONYMOUS LOGON` had read access, so on a machine with more than
one account, another local user could attach to a free pipe instance and read the
broadcast stream the engine pushes to every client — guard alerts, scan progress,
incident text. They could not send a request (that needs write access), so the
leak was confidentiality only, but it was a leak a security product cannot shrug
at.

**Decision.** The engine creates every pipe instance with an explicit, protected
SDDL:

```
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<current user SID>)
```

1. The user SID is read from the engine's own token at startup and written into
   the DACL, because the engine and the UI run as the same user in every supported
   mode (the UI starts the engine, or the autostart entry does). That is what
   keeps the transport working while the two permissive ACEs disappear.
2. `P` (protected) prevents any inherited ACE from widening the DACL later.
3. A failure to build the descriptor is **not** fatal: the engine logs a warning
   and serves with the default ACL. Availability wins over hardening here, and the
   choice is recorded in the threat model's open questions instead of hiding in
   code.
4. The helper's pipe is separate and unchanged (D-007, `PRIVILEGED-OPS.md`): it
   grants `INTERACTIVE`, and the question of verifying the caller there is still
   open (F-2).

**Why.** A pipe that only its owner, `SYSTEM` and administrators can talk to is
the smallest surface that still works, and the fix is measurable: the DACL is read
back from the live object in tests, so the property cannot regress silently.

**Commits us to.** Keeping the engine and the UI in one user session (a
service-mode engine running as `SYSTEM` would have to name the interactive user
deliberately — a new decision); keeping the ACL tests that read the DACL back with
`GetSecurityInfo`; and updating the threat model's F-1 entry whenever this
boundary moves.

## D-016 — An update payload must carry a signature Windows trusts inside the file

**Context.** `update.apply` extracted the release ZIP and copied the binaries over
the running ones while trusting only the manifest's SHA-256. That hash says "this is
the archive the manifest described"; it does not say "someone with a code-signing
certificate produced it". A manifest served by a compromised mirror (or a mirror the
user pointed the engine at) could describe any archive and the hash would match it.
The manifest cannot be cleartext outside loopback any more (F-3a), which narrows the
window but does not close it.

**Decision.** Before a single byte is copied, `mics-engine.exe` and `mics_app.exe`
in the extracted payload must pass `WinVerifyTrust` with
`WINTRUST_ACTION_GENERIC_VERIFY_V2`, `WTD_CHOICE_FILE`, `WTD_UI_NONE` and no
revocation checking (`platform/windows/signature.rs`). Windows builds the chain and
checks the signature over the PE image; anything unsigned, tampered or signed by an
untrusted root aborts the apply and nothing is replaced.

1. **Embedded signatures only.** Catalog-signed files (most Windows system
   binaries) answer `TRUST_E_NOSIGNATURE` to this call. That is correct for this
   use: a payload must carry its own signature, not rely on a catalog entry that a
   different machine may not have.
2. **The payload is checked where it is extracted**, before `copy_over`, so a
   refusal costs nothing and leaves the running install untouched.
3. **The signer is pinned by name.** After the chain check, the signer's display
   name is read from the same provider state (`WTHelperProvDataFromStateData` →
   `WTHelperGetProvSignerFromChain` → `CertGetNameStringW`) and compared with
   `EXPECTED_SIGNER_CN = "MI CS Code Signing"`. A valid signature from any other
   certificate is refused, and the error names the signer it found. That name is
   part of the release contract: `scripts/make-release.ps1 -Sign` must keep using
   it.
4. **The pin is the subject name, not the thumbprint.** A thumbprint cannot be
   committed here while the certificate is re-issued locally — the next release
   would refuse its own payload. So the residual is a certificate with the same CN
   issued by a CA that failed identity validation; that is what F-3 keeps, instead
   of the previous "any trusted certificate passes".

**Why.** It turns the update path from "trust the bytes because a document agreed
with them" into "the bytes are signed by the MI CS certificate, and Windows accepts
the chain". A tampered payload — or one signed by a different identity — can no
longer replace the running binaries even when the manifest and the archive hash
agree.

**Commits us to.** Keeping the two signed payload names (`mics-engine.exe`,
`mics_app.exe`) as the ones the update stages; keeping the four tests (a junk file
is refused, the signed release passes, a single flipped byte is refused, and a
different CN is refused while ours is accepted) and the signed artifact that makes
the positive cases real; keeping the CN in `make-release.ps1` and in
`EXPECTED_SIGNER_CN` in step; and recording the thumbprint gap rather than treating
this as "updates are fully verified".

## D-017 — The helper asks who is calling, and only answers the engine

**Context.** D-007 gives the LocalSystem helper one pipe, and D-015 recorded the
engine pipe's ACL. The helper's pipe is different on purpose: it grants
`INTERACTIVE` full access, because the engine runs as the logged-on user and the
alternative was a UAC prompt for every privileged action. Measured, the DACL is

```
D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;IU)
```

so on a machine with more than one account, a standard user can ask `SYSTEM` to open
an inbound firewall rule, replace the managed hosts section, or run a hardening
action — no prompt, inside the closed op set but still `SYSTEM`. That is F-2, and
`docs/THREAT-MODEL.md` has carried it as a real, bounded risk.

**Decision.** Every accepted connection is identified before anything is read:

1. `GetNamedPipeClientProcessId` names the client process from the connected pipe.
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW`
   give its image path. The process handle is held until the path is read, so the pid
   cannot be recycled between the two calls — a check on a recycled pid would be
   worse than no check.
3. The caller is authorised when the image is `mics-engine.exe` (file name,
   case-insensitive) **or** the path equals `MICS_ENGINE_PATH` exactly. The second
   form is the hook the installer records and the one the verification scripts use to
   name themselves; it adds one trusted client rather than replacing the name rule.
4. The caller's **token user SID** (`OpenProcessToken` +
   `GetTokenInformation(TokenUser)`) must equal the owner SID of
   `%PROGRAMDATA%\MICS`, the account that created it — the elevated installer. That
   is what stops a *different* local user from copying the engine and driving the
   helper: the image check passes, the SID does not. When the directory does not
   exist (portable run, console helper in a fresh checkout) there is no recorded
   account, so the helper logs that once and lets the image check stand alone; a
   console helper already runs with the caller's own token, so refusing there would
   cost the development flows and buy nothing.
5. A refusal is answered in-band (`this pipe only serves the MI CS engine`, or
   `...the account MI CS was installed for`) after the request line arrives, so a
   client can read why; it is `WARN`-logged with the refused pid, image and SID; it
   produces **no** audit entry, because nothing was started; and it gets a 5 s
   deadline instead of the 300 s request deadline, so a refused client cannot occupy
   the single request slot.
6. If the pid cannot be read at all, nothing is answered and nothing runs. "Cannot
   tell who you are" is a refusal, not a pass.

**Why.** The helper is the only component that acts with `SYSTEM`, and "any
interactive user" was the widest statement in the whole design. Checking the caller
costs three API calls on a path that already opens a pipe, and it is measurable: the
live refusals and log lines are in `docs/PRIVILEGED-OPS.md`, the owner-vs-token test
reads both SIDs back on this machine, and the decision table is unit-tested in
`platform/windows/caller.rs`.

**What this is not.** A process running *as the installing user* can still drive the
helper. That is D-007's accepted trade — that user can answer a UAC prompt himself,
so the helper is not an escalation for him — and it is the residual recorded in the
threat model instead of being papered over. The portable fallback (no
`%PROGRAMDATA%\MICS`, image check only) is the other residual, filed LOW in the
register.

**Commits us to.** Keeping the caller check on the connect path rather than inside
`respond`, so an unauthorised client never reaches validation or the audit trail;
keeping `MICS_ENGINE_PATH` documented (AGENTS rule 5) as "the one extra client the
helper will answer", and keeping `scripts/verify-helper.ps1` naming itself through
it instead of loosening the rule; keeping `%PROGRAMDATA%\MICS` created by the
elevated side only, because it now doubles as the install-time account record; and
updating F-2's row whenever the check moves.

---

## D-018 — The third-party inventory is generated from the lockfiles, committed beside them, and checked

1. `tool\sbom.dart` builds two files from what is already pinned: `sbom.cdx.json`
   (CycloneDX 1.6) and `THIRD-PARTY-NOTICES` (Markdown). Its inputs are
   `cargo metadata --locked --offline` for every crate's *declared* SPDX expression,
   checksum and source directory; `pubspec.lock` plus `dart pub deps --json` for
   every Dart package and its sha256; the Flutter SDK's own `LICENSE`; the two
   shipped fonts; and a four-entry list of what no lockfile mentions (Cairo,
   JetBrains Mono, `flutter_windows.dll`, the Visual C++ runtime the app needs but
   does not ship).
2. The output is deterministic: no timestamp, and the BOM serial number is the
   SHA-256 of the sorted component coordinates laid out as a UUID. Two runs over
   the same lockfiles are byte-identical, so a diff in the committed file means a
   real dependency change and nothing else.
3. Both files are committed at the repo root and copied into the portable package.
   `dart run tool\sbom.dart --check` exits 1 when they no longer describe the tree;
   `scripts\make-release.ps1` refuses to build in that case, before it starts
   building; and `scripts\verify-release.ps1` reads them back out of the zip and
   checks the document parses, every component names a license and the notices
   report a clean audit.
4. Which license MI CS relies on is computed, not chosen by hand: an SPDX evaluator
   treats `OR` as "either side is enough", `AND` as "every side", `WITH` as
   narrowing the id it sits on, and picks the permissive option from a fixed
   preference list (MIT first) so `MIT OR Apache-2.0` and `Apache-2.0 OR MIT`
   conclude the same id. An id that is neither in the permissive set nor in the
   copyleft set is reported as unclassified and fails the audit, so a new
   dependency with an unfamiliar license stops the release instead of shipping.
5. `scope` separates what ships from what does not: a crate is `required` when it
   is reachable from a workspace member through normal dependencies, a Dart package
   when it is reachable from the root's non-dev dependencies. Only `required`
   components are audited; a dev- or build-only component is still listed, with its
   license, because a scanner should be able to see it.
6. Where a component ships no license text of its own - the fonts keep theirs in
   the TrueType `name` table, and `typenum` ships a LICENSE that is just the
   expression - the text is quoted once under the id from the first component that
   did supply one, and the fonts' copyright lines are read out of the `.ttf`
   binaries rather than guessed. `assets\fonts\OFL-1.1.txt` is the committed OFL 1.1
   text for the two fonts: no font file carries it.

**Why.** D-004 promises the third-party assets in `THIRD-PARTY-NOTICES`, and the
register carries a HIGH row for "no SBOM/notices". A generated file that nothing
checks rots silently, and generating it only inside a release build would mean a
license change is invisible to whoever reviews the commit that caused it. Measured
on this machine (2026-10-31): **579 components** - 483 Rust crates, 87 Dart
packages, 6 Flutter SDK packages, 2 fonts, 1 not-shipped runtime - of which **541
ship**; **8 licenses** relied on (MIT 444, BSD-3-Clause 73, Apache-2.0 35,
Unicode-3.0 18, Zlib 3, ISC 2, OFL-1.1 2, CDLA-Permissive-2.0 1); **0 copyleft, 0
unclassified, 0 missing texts**; the only copyleft-flavoured expression in the tree
is `r-efi`'s `MIT OR Apache-2.0 OR LGPL-2.1-or-later`, where a named permissive
option exists and the notices say it is the one we take.

**What this is not.** Not a vulnerability scan: there is no CVE data here, that is
the scanner's job. Not a per-file copyright harvest: the copyright column names the
holder of the text that was quoted, so a crate that ships no text contributes no
line (29 of 541 shipped components, mostly macOS- and wasm-only crates whose sources
were never extracted into the cargo cache). Not signed: the SBOM describes what is
inside, and ج2's manifest is where integrity checking starts.

**Commits us to.** Regenerating both files in the same commit as any dependency
change, because the freshness test derives the component set from `Cargo.lock` and
`pubspec.lock` and fails when they disagree; keeping the evaluator fail-closed
instead of adding per-package exceptions when a new license looks odd; keeping
`--check` in the release path so a package cannot ship an inventory that does not
describe it; and keeping the four manual entries honest - the Visual C++ runtime
stays `scope: excluded` with a name instead of an invented SPDX id.

---

## D-019 — There is no VirusTotal client: file reputation is local

1. `engine\src\scanner\vt.rs`, the `vt_api_key` setting with its `MICS_VT_API_KEY`
   test hook, the `sync_queue` table and the four storage calls that served it
   (`queue_op`, `pop_queue_ops`, `remove_queue_op`, `queue_len`), the
   Settings → Integrations field with its i18n keys, and the `vt_queue_len` field
   of the sync report are deleted. The sync pass no longer flushes a lookup queue.
2. Nothing replaces it. File reputation is what the machine already holds: the
   IOC sha256 cache the user's own feed fills (`ioc_feed_url`), the YARA pack, and
   the guard's behavioural rules. A hash is never sent anywhere for a verdict.
3. `README.md` states it in both languages — in the "what it does not do" list,
   the network row and the privacy paragraph — and `docs\THREAT-MODEL.md` §B6 no
   longer lists a VirusTotal destination, because no code could reach one. The
   secrets asset A7 and residual risk F-5 shrink to the two keys that remain.

**Why.** The client was unreachable by construction: only the offline queue could
call it, and nothing filled that queue, so what shipped was a settings field, an
outbound destination, a queue table and a column of the sync status that together
made the scanner look more capable than it is. The user decided on 2026-10-31 to
delete it rather than build the queue that would feed it. A dead client is worse
than an absent one: it is a secret to leak (A7/F-5) and a destination to justify
for a capability the product does not have.

**What this is not.** Not a decision against hash reputation — a key-free sha256
feed can return through the existing `ioc_feed_url`, which the scanner already
consults. Not a claim that multi-engine verdicts are unwanted, only that they are
neither bought nor wired (`docs\COST.md` §3). Not a migration: the `sync_queue`
table is dropped from the schema, and an existing database keeps an orphan table
that SQLite ignores.

**Commits us to.** Keeping the "does not" lists honest. If a reputation lookup
ever returns, it ships in one commit with its §B6 destination row, its key's
masking story (F-5, DPAPI) and the UI field that names it — and the register row
that records its absence today is closed by that commit, not by a comment.

---

## D-020 — The Start-Menu shortcut stays «MI CS»; the names are frozen by probes

**Status:** decided (2026-10-31); every name in the table was already implemented.

**Decision.** The user-facing names do not change. In Task Manager and file
Properties the app is `MI Cyber Security` and the engine is `MiShild Background`;
inside the product it is `MI CS` (window title, title bar, tray tooltip, card
headers, Windows' notification source label); the **desktop** shortcut is `MICS`
and the **Start-Menu** shortcut is `MI CS`. The last one was the open question —
renaming it to `MICS` was on the table — and the answer is to leave it alone.

**Why.** Two names for one product only confuse when no rule explains them. This
split has one: `MI CS` is the product, `MICS` is the search-and-folder token
(`%LOCALAPPDATA%\MI CS` is the historical exception). Renaming the Start-Menu entry
would put the Windows surface at odds with the notification source label the
AUMID script writes (`DisplayName "MI CS"`), so the same app would be filed under
two labels in the two places a user goes looking for it.

**Not a setting.** Nothing in `settings.json` names the product and no code
branches on these strings: they are constants in the `windows\runner` resources,
`scripts\create-shortcuts.ps1` and `scripts\register-aumid.ps1`.
`scripts\verify-aumid.ps1` reads the registered label back, and
`scripts\verify-release.ps1` fails when either binary's `FileDescription` drifts —
which is what keeps the table in `docs\TODO.md` §0.0 honest.

**Commits us to.** If a name ever changes it changes in all of: both PE version
resources, the icon/shortcut scripts, the AUMID script, the §0.0 naming table and
the README's naming section — in one commit, because a half-renamed product is
exactly what those probes exist to catch.

---

## D-021 — The shipped binaries are hardened, and the PE is what proves it

**Status:** decided (2026-10-31); implemented in the release build.

**Decision.** One release recipe, four parts, every one of them read back out of
the artifact rather than taken from the flags:

1. **The engine is built for shipping, not for debugging.** `[profile.release]`
   in `engine\Cargo.toml` sets `lto = "fat"`, `codegen-units = 1`,
   `panic = "abort"` and `strip = "symbols"`.
2. **Control Flow Guard is on in both binaries.** The engine asks rustc for it
   (`-C control-flow-guard=yes` in `engine\.cargo\config.toml`, which passes
   `/guard:cf` to the compiler *and* the linker); the app asks for it in
   `windows\runner\CMakeLists.txt`. Setting it at link time only produces an
   empty function table, which is why both sides do it.
3. **The Dart release is obfuscated** (`--obfuscate --split-debug-info`), and the
   symbol table is written to `dist\symbols\<version>` — outside the package and
   outside git.
4. **Neither claim is trusted.** `scripts\verify-hardening.ps1` parses the PE
   (`DllCharacteristics`, the load-config `GuardFlags`, the debug directory) and
   `make-release.ps1` refuses to package anything that fails it, so "we set
   `/guard:cf`" can never quietly stop being "the file has a guard table".

**Why.** These are the mitigations that cost nothing at runtime for a program
that already does its own bounds checking, and they decide whether a memory-safety
bug in a dependency is a crash or a control-flow hijack. `DllCharacteristics`
already carried `ASLR`/`DEP`/`HIGH_ENTROPY_VA` before this decision (measured, not
assumed), but **Control Flow Guard was not actually on**: the shipped
`mics_app.exe` and `mics-engine.exe` reported `GUARD_CF` absent and
`CF_FUNCTION_TABLE_PRESENT` absent, so indirect calls were unguarded. Stripping
also removes the PDB path and the source layout from the artifact, and LTO with
one codegen unit removes the split-object seams a patch would aim at. Obfuscation
is a speed bump, not a secret: it raises the cost of reading the Dart logic
without hiding it from the auditors this project invites (F-11 in
`docs\THREAT-MODEL.md` says the same thing about the whole surface).

**What is deliberately not claimed.**
* **`/guard:ehcont`** — `link.exe` refuses it (`LNK2047`) unless every object
  carries EH continuation metadata, and `libstd` is not built with it;
  `/force:guardehcont` would ship an incomplete table, so no EH-continuation
  guarantee is made on x64.
* **`/CETCOMPAT`** — the shadow-stack marker cannot be verified on this machine
  (running a process under a shadow stack needs elevation and CET hardware that
  is not available here), and a mitigation nobody measured is what this project
  does not ship. It can arrive when a machine can prove it.
* **`/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA`** — already the default of both
  toolchains; they are *checked*, not added.

**Commits us to.** Any binary that ships must pass `verify-hardening.ps1`, and a
Dart symbol table never enters the ZIP, a commit or the README. The crash-forensics
cost is accepted and named: the engine has no unwinder (a panicking task now ends
the process), and a stack trace needs the `dist\symbols\<version>` file that only
the build machine has. A future "crash report" feature would have to ship a
symbol upload, which would be a new decision, not a quiet un-stripping.

## D-022 — The installer is the same package, per-machine by default, and it never invents state

**Context.** The ZIP is not a product: a stranger has to know which folder to unpack
where, `rules\` must land beside the binaries or the engine silently falls back to
its compiled-in pack, the AUMID has to be registered or Windows shows an anonymous
source on the notification card, and nothing appears in Apps & features to remove it
again. ب3 wraps the artifact `make-release.ps1` already produces and
`verify-release.ps1` already proves.

**Decision.** One NSIS script (`installer\mics.nsi`) driven by defines from
`scripts\make-installer.ps1`:

* It packages **`dist\MICS-portable` unchanged** — the same bytes the ZIP gate
  checked — and re-runs `verify-hardening.ps1` on those binaries first. The installer
  is a wrapper, never a second assembly path that could drift from the release.
* **Per-machine is the default** (`RequestExecutionLevel admin`, `$PROGRAMFILES64`),
  so one UAC prompt installs for every user. The `-TestUser` define compiles the
  *same* script as a per-user, no-UAC build under `%LOCALAPPDATA%`; that variant
  exists so the install/uninstall path can be verified end-to-end without a human
  clicking anything, and `scripts\verify-installer.ps1` (step 3) will use it.
* **Shortcuts and the AUMID are part of the install**, because they are part of the
  product: the Start-Menu folder, the desktop icon, `HKCU\Software\Classes\AppUserModelId\MICS`
  and the Apps-&-features entry. The uninstaller removes all four.
* **Upgrade reuses the previous location** (the uninstall key's `InstallLocation`)
  and closes a running `mics_app.exe` before overwriting files, instead of installing
  a second copy beside the first.
* The installer **does not create data**: no `%PROGRAMDATA%\MICS` ACL change, no
  service, no registry state beyond the four keys above. The engine keeps choosing
  its own state directory, and the privileged helper stays the app's job (ب4 folds
  it in). That keeps the installer uninstallable and auditable on its own.

**What this costs.** Per-machine installs need the human's UAC click, so the
per-machine path cannot be verified by an agent alone — it is verified as the
per-user build plus a manual run.

**Step 2 (2026-11-01) closed the two things step 1 left open, without widening what
the installer owns:**

* The shortcuts carry `System.AppUserModel.ID` — a Shell property on the `.lnk`, not
  a registry value, so `WriteRegStr` cannot write it — because the installer unpacks
  `scripts\register-aumid.ps1` (with its interop file) into its temporary
  `$PLUGINSDIR` and calls it. **Never** into `$INSTDIR`: the packaged bytes stay
  exactly the ones the release gate checked, and nothing new is installed. A
  property that cannot be written costs the label on the card, not the card, so a
  failure warns in the details log instead of aborting the install.
* The uninstaller **refuses** to remove a copy the privileged helper still points at
  (it asks `scripts\check-helper-ownership.ps1`, which is read-only) and tells the
  user to remove the helper in the app first. It does **not** stop or delete the
  service in either direction: that service is the app's to create and to remove,
  which is what "never invents state" has to mean for an uninstaller too. Folding the
  helper's *install* in remains ب4, and it is ب4 that will have to revisit this rule.

---

## D-025 — The integrity manifest lives inside the signed engine

**Status:** accepted (2026-11-03)

**Context.** F-11 keeps the LOW row "no signed integrity manifest, so a
repackaged copy is not detectable by the app itself", and D-001 promises a signed
SHA-256 manifest plus an "unofficial build" notice for builds that fail the check.
D-016 rule 1 already fixed the primitive for anything the engine trusts: an
**embedded** Authenticode signature checked by `WinVerifyTrust` plus a signer-CN
pin, because a catalog entry a different machine may not have is not a proof. A
manifest cannot be a loose `.json` next to the binaries either: whoever repackages
the install edits it, and the program would believe the edit. So the question was
never "what format", it was "what carries the signature".

**Decision.** (ج2, two commits: the producer, then the reader.)

1. **Carrier.** The manifest is one JSON document — `format`, `version`, and
   `files: [{path, bytes, sha256}]`, sorted by path, paths relative to the package
   root — stored as an `RT_RCDATA` resource named `MICS_MANIFEST` inside
   `mics-engine.exe`. It is **not** shipped as a loose file: a copy nothing
   verifies is a trap. `scripts\verify-manifest.ps1 -Measure` prints it.
2. **Authenticity comes from the container, not the document.** Editing the
   manifest breaks the engine's Authenticode signature; re-signing with any other
   certificate fails the `EXPECTED_SIGNER_CN` pin that
   `engine\src\platform\windows\signature.rs` already enforces for updates.
3. **The engine is not listed in its own manifest** (self-reference). Its
   integrity is its signature; the release `SHA256SUMS` and the installer cover
   the file itself.
4. **Order in `make-release.ps1`.** Stage → hardening and opsec gates → sign
   every PE → build the manifest from those final bytes (signatures included) →
   inject the resource into the staged engine → sign the engine again (its
   signature must cover the injected bytes) → `verify-manifest.ps1` re-reads the
   resource from the staged package and re-hashes every listed file. A package
   whose manifest does not describe it never leaves the staging folder.
5. **Three states, one banner.** `status` gains `integrity`:
   - `ok` — signed by MI CS Code Signing, Windows trusts the chain, and every
     listed file hashes as published;
   - `untrusted-certificate` — our CN, but this Windows does not trust the
     certificate yet (the self-signed situation D-002 records). About says so in
     one neutral line and **no banner** appears, because the build is ours;
   - `unverified` — missing or broken signature, another signer, unreadable
     manifest, or a listed file that is missing, renamed or changed. About shows
     the notice and the engine raises an alert card naming what failed.
6. **Local only.** The check reads the install directory and nothing else: no
   network, no new file, no new dependency (`sha2` and the `windows` crate are
   already there).

**Why.** It turns "the app trusts the bytes because a document agreed with them"
into "the bytes carry a signature this build was told to expect, and every file
matches the one the release signed for" — with the primitive already proven in
`signature.rs`, and without a second signature format, a catalog store, or a loose
file to edit. The three states keep the notice honest under D-002: a self-signed
official copy is not "unofficial", and the strict reading ("an untrusted chain is
an integrity failure") would put the banner on every copy we ship until a CA
certificate exists — a signal that always fires says nothing.

**What this is not.** Not a defence against a determined repackager who rebuilds
the engine from source and patches the constant: it is GPL, and F-11 says so. The
banner tells the user what the bytes are; it does not stop a patched build, and it
does not replace code-signing trust (that is D-002's certificate, and no decision
here changes it). Not "anybody Windows trusts": the CN pin is what makes a
differently-signed rebuild visible, and its residual is the one D-016 rule 4
records.

**Commits us to.** Keeping the resource name, the `format: 1` envelope and the
sorted path list stable, so the self-check, `verify-manifest.ps1` and ط2's tamper
tests all read the same thing; keeping the manifest build **after** signing in
`make-release.ps1`, and re-signing the engine after the injection; and measuring
one consequence instead of waving it through — the manifest names every shipped
file, so `data\flutter_assets\...` enters the engine's strings and its `flutter`
count in `qa\opsec-baseline.json` **rises** with a written reason, which also
means the QA report is regenerated in that commit.

**Amendment (2026-11-03, the producer commit).** Point 4's order moved one step
because the resource API cannot do what that order assumed: `BeginUpdateResource` /
`EndUpdateResource` rewrites the PE and leaves the certificate table that was
already embedded inconsistent with the new layout, so `signtool` then refuses the
file (`SignedCode::Sign returned error: 0x800700C1`, measured on the staged
engine on 2026-11-03; injecting into a *never-signed* engine and signing it
afterwards is accepted). The engine is therefore signed **once, after** the
injection: `make-release.ps1` signs every staged binary except the engine
(`sign.ps1 -Except`), builds the manifest from those signed bytes, injects it, and
then signs the engine (`sign.ps1 -Only`). Both properties point 4 wanted survive,
and `verify-manifest.ps1` proves the pair on the staged package: the manifest
covers the signatures of every file it lists, and the engine's signature covers
the manifest bytes.

**Amendment (2026-11-03, the reader commit).** Three things point 5 could only
settle once it was code, and one surface it did not name:

1. **"Our certificate, not trusted yet" has to be read without a chain.** A failed
   `WinVerifyTrust` returns no provider state at all, so the two "not trusted"
   cases are indistinguishable through it. `signature::embedded_signer_name` reads
   the signer certificate straight out of the PKCS#7 blob instead
   (`CryptQueryObject` → `CryptMsgGetParam` → `CertFindCertificateInStore` →
   `CertGetNameStringW`), and `Trust::UntrustedRoot` is returned **only** when the
   status is exactly `CERT_E_UNTRUSTEDROOT` *and* that certificate is ours. This is
   the amendment that matters: a changed byte reports `TRUST_E_BAD_DIGEST` and
   leaves our certificate in the file, so treating "the status was negative but the
   certificate is ours" as the quiet state would have made a patched engine
   `untrusted-certificate` — silence, for exactly the attack F-11 is about.
2. **The card is gated on the document being there; the About line is not.** Point
   5 says `unverified` raises a card, and a development build has no resource and
   is therefore `unverified`: as written, every `flutter run` would raise "these
   files are not the published build" — true, and noise aimed at the people
   building it. A card is a nudge, not a record, so it fires only when the copy
   *carries* a document that disagrees; Settings → About says `unverified` in both
   cases (the log line always does), so a repackager who strips the resource loses
   the nudge and not the notice.
3. **The verdict is computed once, at start-up, and cached in the process.** The
   manifest is ~10 KB and the folder ~30 MB: `status` answers the UI's 15 s
   heartbeat, and re-hashing a package per beat is not a self-check, it is a tax.
4. **One more surface than point 5 named.** About shows a line in *all three*
   states — green for `ok`, muted for `untrusted-certificate`, the notice for
   `unverified` — because "is this copy the published one?" is the question that
   screen is open to answer, and an empty answer there is a missed one. Only
   `unverified` is a banner.

Also decided by the same commit, at the format level: Rust validates the document's
envelope, its duplicates, its escaping paths and its 64-hex hashes, but **not** its
sort order. Sorting is the producer's contract and `verify-manifest.ps1` enforces
it; refusing a package the release gate accepted over a UTF-16-versus-byte
collation difference would be a worse failure than the ordering was there for.

**Amendment (2026-11-03, the tamper commit).** Point 2 said the manifest's
authenticity is the engine's Authenticode signature plus the `EXPECTED_SIGNER_CN`
pin, and only the *engine* enforced it: `verify-manifest.ps1` failed on
`HashMismatch` and tolerated everything else, including **no signature at all**.
`scripts\verify-tamper.ps1` measured the consequence — a copy of the package whose
engine had been stripped (`signtool remove /s`) still reported
`RESULT: PASS - all 68 listed file(s) hash as the signed manifest says`, so a
repackaged folder with the document intact and the signature gone could clear the
release gate while the app, which does ask `signature::trust()`, said `unverified`.
The gate and the app therefore disagreed about who publishes MI CS, and the
disagreement was on the permissive side. The rule now holds on both: the packaged
engine must carry a signature whose subject is the pinned `MI CS Code Signing`
(no signer, another subject and `HashMismatch` all refuse the package; a
`Valid` status or an untrusted root with that subject — a machine that has not
trusted the self-signed certificate yet — are accepted, mirroring
`Trust::Ours`/`Trust::UntrustedRoot`). The name lives in exactly one place for
PowerShell, `$script:MicsSignerCn` in `scripts\manifest-resource.ps1`, and
`test\package_integrity_test.dart` reads `EXPECTED_SIGNER_CN` out of
`signature.rs` and fails if the two spellings drift apart.

---

## D-026 — The installer owns the privileged helper's whole life, so the product asks for UAC once

**Status:** decided (2026-11-03); implemented in `installer\mics.nsi` and
`scripts\check-helper-ownership.ps1`.

**Context.** D-007 buys elevation with one prompt through the `MICSHelper` service,
and D-022 made the installer deliberately *not* create it: the product asked once to
install itself, then again at the first fix that needs administrator rights, when
`Settings -> Engine` ran the engine's elevated `install-helper`. Two prompts for one
program is the exact cost D-007 exists to avoid, and the second one arrives at the
worst possible moment — in the middle of the job the user is trying to finish. ب4 is
D-022's own footnote ("the privileged helper stays the app's job (ب4 folds it in)").

**Decision.** On a per-machine install the installer creates the service, and on
uninstall it removes it:

* **Install** runs the shipped engine's own `install-helper` — the same command the
  app's button runs — with the elevation the installer already holds. The service
  definition (`sc create` with the quoted binPath and the `helper-service` argument,
  the description, the start type) therefore stays in exactly one place,
  `engine\src\privileged\service.rs`; NSIS never spells it out a second time. A
  failure is reported and **not fatal**: the install completes, the details pane says
  the service was not created, and the app's repair path (one prompt, later) is
  exactly what a portable copy has always had.
* **Uninstall** asks `scripts\check-helper-ownership.ps1 -Remove`: the same check that
  already refuses to delete a folder the helper points at now stops and deletes the
  service **when, and only when, its binPath points at `$INSTDIR`**. The `sc` calls are
  scoped to the service name derived from the key that was read (`HELPER_SVC_KEY`'s
  leaf), so a verification build pointed at a synthetic key cannot delete the machine's
  real `MICSHelper` — and an unelevated caller cannot either, which is what keeps the
  refusal path measurable.
* **It still refuses when it cannot.** An uninstaller started without administrator
  rights, a service it may not delete, a definition it cannot read: nothing is removed,
  the error level is 5, and the message names `Settings -> Engine -> Remove helper` as
  the manual way out. Install and uninstall are symmetric: whatever this installer
  created it takes away, and whatever it did not, it leaves alone.
* **Portable copies are unchanged.** Nothing creates the service for them, so D-007's
  one-prompt path through the app is still how they get one, and the uninstaller's
  refusal still protects a copy the helper points at.

**What this costs.** The installer now owns state, which D-022 deliberately avoided:
one entry under `HKLM\SYSTEM\CurrentControlSet\Services`. That widening is paid for
with rule 6's reversibility: `install-helper` stops and deletes any previous definition
before creating its own, so an upgrade or a repair converges on the current `$INSTDIR`
instead of leaving a second service; the uninstaller deletes the service before it
deletes a single file; and neither touches the audit trail in `%PROGRAMDATA%\MICS`.
The per-machine path still needs one human UAC click to be *measured* — compiling both
variants and running the per-user one end to end prove the script and the per-user
path, not the boxing of a real service — so `scripts\verify-installer.ps1` keeps
measuring what it can, and the per-machine run stays the documented manual step, as
D-022 says about itself.

---

## D-027 — A scheduled scan is opt-in, report-only, and needs the engine running

**Status:** decided (2026-11-03); implemented in `engine\src\scanner\mod.rs`
(`start_schedule`, `scan.schedule`) and `engine\src\settings.rs`.

**Context.** The register's MED row was blunt: the hash and YARA dimensions only
apply *while a scan job is running*, so a machine nobody scans has no file-level
detection at all — Windows Defender is the real-time layer, and the audit says so
loudly when it is off. The cheapest honest half of that row is a scan that starts
itself; the expensive half (real-time watching, و2) is an architecture decision and
is not in this entry.

**Decision.** The engine owns a scan schedule, and it is three small facts:

* **`scan_interval_hours` — 0 disables it, and 0 is the default.** A scanning program
  that starts walking a disk the first time it is installed, on a schedule nobody
  chose, is a surprise, not a feature. The settings validation accepts 0 (off) or
  1..168 hours, and the UI offers a short list.
* **`scan_target` — empty means the current user's profile folder.** It is validated
  as an absolute path (the engine's working directory is not the user's idea of
  "here") but not for existence, because a folder on a stick that is usually plugged
  in must not make the setting unwritable; a target that is missing when the scan
  falls due records the attempt and tries again next interval, one log line per
  interval instead of one per tick.
* **The engine records when it last started one** (`meta['scan.last_scheduled']` in
  the state database, not in `settings.json`: settings are the user's, this is the
  engine's memory). An engine restart therefore does not re-scan, a fresh install
  scans at the first tick instead of waiting an interval, and a clock that moved
  backwards counts as due — the alternative is never running again.
* **It is report-only: a scheduled scan never quarantines.** Nobody chose a file
  while it was running, so moving one would be the program deciding for an absent
  user. Findings land in the job, in the audit trail and in the alert path exactly as
  a manual scan's do — the user decides what to remove, and the app shows it.
* **It needs the engine running**: the logon entry's `--service` mode (D-007's
  `service.install`) or the app itself. When neither is running, nothing scans, and
  that is stated wherever the feature is described rather than implied away.
  `MICS_NO_SCAN_SCHEDULE=1` is the test hook that keeps a probe deterministic.

**What this costs.** One timer that wakes every five minutes (a scan interval is
measured in hours, so the jitter is free), one row in the `meta` table, and the
tick's own logic — `is_due` is a pure function with unit tests, and
`scripts\verify-scan-schedule.ps1` drives a real engine over its own pipe to prove the
three claims (off means off; due means a scan starts over the configured folder and
finds the planted EICAR string; the file is still there afterwards). What it does
**not** close is the half of the register row about watching: a scheduled scan is a
moment, not a monitor, and `و2` stays open with its CPU-cost decision.

## D-028 — The firewall is driven through Windows' own API, not `netsh`

**Status:** decided (2026-11-03); implemented in `engine\src\firewall\mod.rs`, proved
by `scripts\verify-firewall.ps1` (23 checks). The probe grew to **27 checks** on
2026-11-08, when the rule-name defect the acceptance run found was closed without
touching a signature: `owned_rule_name` decides a rule's name in one place (one
`MICS-` prefix, however the caller spelled it), and the new cycle in part 3 creates a
rule under the *prefixed* spelling, proves Windows has no `MICS-MICS-<rule>`, and
removes it by the *unprefixed* spelling.

**Context.** Every firewall change went through `netsh advfirewall` and every read
came back as English console text the engine parsed — with a 20 s deadline per call,
because a child process can hang and the firewall service can restart. The register's
MED row named it: *"Firewall uses `netsh`, not FirewallAPI COM"*. The cost was never
one specific bug (there were two: a policy argument shape that made Default-Deny
impossible to turn on, and a `show rule verbose` dump large enough to fill a pipe);
it was that a security control's truth lived in a stranger's formatting, in whatever
locale that stranger was set to.

**Decision.** The engine speaks `INetFwPolicy2` / `INetFwRules` / `INetFwRule` — the
same COM surface `wf.msc` drives — through the `windows` crate the engine already
depended on. Three properties make this a replacement rather than a rewrite:

* **The public shape is unchanged.** `set_default_deny_now`, `add_rule_now`,
  `remove_rule_now`, `list_rules`, `block_country` keep their signatures and their
  privilege split: an elevated process calls them directly, an unelevated one goes to
  the helper (D-007) over the same `Op` payloads, so the helper's protocol, its audit
  trail and its refusals are untouched.
* **Values are typed, so the words are ours.** The `Any` that `netsh` printed is now a
  deliberate normalisation of `""`/`*` → `Any`, and `In`/`Out`/`Allow`/`Block` come
  from the enums instead of being matched in the output. A rule that names a port but
  no protocol is refused with a sentence that says what to add (`netsh` answered "The
  number of arguments provided is not valid" for the same mistake).
* **Every rule covers every profile, explicitly.** `INetFwRule::Profiles` defaults to
  *no* profile — a rule that exists and never fires. The mask is set to
  `NET_FW_PROFILE2_ALL` for all of them, and each rule is grouped under "MI CS" so the
  Windows UI shows what we added as one block (`netsh` left them ungrouped).

**What this cost, and the two traps that cost the most.** One COM apartment per call,
opened and closed around the interfaces — and *field order in the guard struct is
load-bearing*: Rust drops fields in declaration order, and releasing a policy
interface after `CoUninitialize` on that thread is an access violation (`0xc0000005`
in the drop, measured on every `fw.rules.list`). The interface is declared before the
apartment guard for that reason. The other trap: `INetFwRules::_NewEnum` hands out
`VT_DISPATCH` variants, not `VT_UNKNOWN` (measured: `vt = 9`), so the enumeration
converts through `IDispatch` and keeps the `IUnknown` path as a fallback.

**What this does not claim.** The probe never flips a profile policy — a default-deny
toggle would cut the network of whatever else is running, so
`set_default_deny_outbound` is read and compared with `Get-NetFirewallProfile`, not
written. A country-sized `RemoteAddresses` string has no documented ceiling and was
not measured (changing the firewall needs administrator rights, which the probe has
through the helper but chooses not to spend on a guess): it stays one rule per
country, exactly as before, and the open question is in the register.

---

## D-029 — CI and release builds pin their toolchains

**Status:** accepted (2026-11-04)

**Decision.** Every job that compiles or tests MI CS installs a **named** toolchain
instead of whatever `stable` means that day: Flutter **3.47.8** (framework
`737ba8f885`) and Rust **1.99.1**. Moving either is a decision that gets recorded
here, not a side effect of a Wednesday.

**Why.** The first CI run on the public repository failed in `Pipeline (full)` with
**"135 tests passed, 1 failed"** (run 41922021833) while the same 136 Dart cases pass
on this machine - including in a fresh `--depth 1` clone of that very commit and
again with the runner's own environment forced (`CI`, `GITHUB_ACTIONS`,
`USERNAME=runneradmin`, `USERPROFILE`, `TZ=UTC`, `LANG`). One measured difference
between the two runs was the Flutter version: local **3.47.8** against **3.47.9**,
published four days before that run, which the workflow picked up silently because
it asked for `channel: stable` with no version. Two of the Dart cases measure what
Material actually paints (`test/dark_contrast_audit_test.dart`), which is exactly the
kind of assertion a patch release can move. The pin removes that class of
difference. **Measured on the next run** (41926473473, on `4e04757`): the pipeline
fails fast on the first failing step (`break` in `scripts/pipeline.ps1:301`), and that
run failed at `engine.test` 327.1 s into a 9-minute job instead of at `flutter.test`
after 4 minutes - and package:test's GitHub reporter, which emits its `N tests passed,
M failed` annotation only when the Dart suite fails, emitted nothing, where both
earlier runs had carried `135 tests passed, 1 failed`. Two independent readings of the
same run say the Dart suite is green under 3.47.8; neither is the log line itself, and
the pin is what makes that repeatable rather than lucky.

**Commits us to.** A toolchain bump is its own commit with the measurement that
justifies it (the same rule as the opsec ratchet: numbers move with evidence), and
the local developer's versions are the reference - so the pin and the machine that
verifies it agree. It also means a signed release is built by a known compiler,
which matters more once ب5's certificate exists than it does today.

---

## D-030 — The installer account may be a group: BUILTIN\Administrators is matched by membership

**Status:** accepted (2026-11-05)

**Decision.** The privileged helper still records the installer as the owner of
`%PROGRAMDATA%\MICS` and still compares SIDs. What changes is what a *group* record
means:

- a record naming an account SID is satisfied only by that account (unchanged);
- a record naming **BUILTIN\Administrators** (`S-1-5-32-544`) is satisfied by a caller
  whose token carries that group - read out of the token's **group list**, so a
  UAC-filtered token counts (see the second measurement below), and never guessed from
  a name;
- the image check (`mics-engine.exe`, or the path in `MICS_ENGINE_PATH`) is unchanged
  and still runs first.

**Why.** Once the Flutter pin (D-029) let the pipeline reach `engine.test`, run
41926473473 failed three engine tests, and one of them was the *product*, not the test:
`tests::tests::privileged_requests_are_audited_and_refused_when_malformed` panicked
with the engine's own refusal, `this pipe only serves the account MI CS was installed
for`, on a `ping` from its own test client. The cause is a Windows security policy
rather than a wrong comparison: **a server-class Windows gives a directory an
administrator creates to the Administrators group**, not to the account. Measured on
the runner -

```
left:  "S-1-5-32-544"                              (the directory's owner)
right: "S-1-5-21-3077485881-3661871218-4154919024-500"   (the process's token user)
```

That is a real install scenario - any Windows Server, plus any workstation whose
"System objects: default owner for objects created by members of the Administrators
group" policy names the group - and on those machines MI CS would have refused the
person who installed it.

**Measured twice, on 2026-11-05.** The first fix asked `CheckTokenMembership` and the
runner still refused, with its own facts printed by the failing test:

```
facts: installer=Some("S-1-5-32-544")
       caller=Ok((Some("S-1-5-21-3077485881-3661871218-4154919024-500"), false))
```

`false` is the answer that API gives for a **UAC-filtered** token: the group is present
as *deny-only*, and `CheckTokenMembership` reports enabled membership. So the second fix
reads `TokenGroups` and matches the SID whether it is enabled or deny-only. Deny-only
still means the account *is* an administrator, and the pipe ACL - not this check - is
what keeps an unelevated process out of an actual privileged call.

**Why this does not widen F-2.** The risk F-2 closes is *another local user* driving the
LocalSystem helper. A standard user still fails both the account test and the
membership test, and an administrator could already take the directory over, replace the
binary, or answer a UAC prompt - so refusing them protects nothing and breaks a
legitimate install. D-007's trade (no per-action prompts; the install owner is the trust
anchor) is unchanged.

**Commits us to.** Measured assertions instead of ones that only hold on a workstation:
the group record is allowed for a member and refused for the same account without the
group, a user record is never satisfied by an administrator token, the owner test names
both correct answers, and the pipe DACL test tolerates the `LA` alias Windows prints
instead of the built-in Administrator's SID - the same grant written the other way,
which cost the runner's `the_engine_pipe_grants_only_the_owner_system_and_administrators`
(`D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)`). `docs/THREAT-MODEL.md` F-2 carries the
amendment.

---

## D-031 — A release run creates a draft; a human publishes it

**Status:** accepted (2026-11-05)

**Decision.** The `Release` workflow uploads its assets and notes to a **draft** release
(`gh release create --draft`) and prints the tag it made. Publishing - the click that
makes it visible - stays with the owner.

**Why.** Two reasons, one of them measured. The build is **self-signed** (D-016): Windows
still says "Unknown publisher", so a release that appears by itself is a warning
delivered to strangers without anyone reading it first. And the workflow is still being
verified: the first two `Release` runs (41922523593, 41963395561) failed in packaging,
the ARM64 legs are deliberately `continue-on-error`, and a tag push now re-runs the whole
thing. With a draft, verifying a run costs a tag and publishes nothing.

**Commits us to.** Publishing is a human step, and the release page is where the hashes
are read before it happens. When ب5's real certificate exists and the ARM64 legs have a
green history, this can be revisited - as a decision, not as a silent flag flip.

---

## D-032 — A decoy read is a detection with a measured range, not a sensor we assume

**Status:** accepted (2026-11-05)

**Context.** `guard/canary.rs` watched mtime and size, so a write, a rename or a delete
was caught and a **read-only open was invisible** - and the register said so: the
sharpest thing a decoy can catch (something looking at it) was the one thing it could
not see. The thorough fix is a minifilter, which is a driver, an install, a signing
story and a bugcheck; the cheap fix is a field the file already has. NTFS keeps a
**last-access time**, and it was off by default for years, which is why the row said
"not detected" rather than "not attempted".

**Decision.** A read is detected from the last-access time, and **the range of that
detection is measured per volume and reported** instead of assumed:

1. **One pure rule.** `CanaryState` carries `{exists, mtime, size, atime}` and
   `classify(before, after)` answers `None`, `Read` or `Written`. A reader that also
   writes is a writer (the write answers first), and a volume that keeps no atime never
   invents a read.
2. **A read is its own event.** HIGH `canary_read`, rule id `CANARY_READ` - a separate
   id on purpose, so quieting reads cannot quiet the write that means the decoy was
   overwritten. Writes keep CRITICAL `canary_triggered`/`CANARY` unchanged, and both
   reach the same alert gate, correlator (own title) and sound router (warning cue, not
   the critical one).
3. **A fresh decoy settles.** A decoy MI CS has just written is quiet for 90 s
   (`READ_SETTLE`), because the first thing to open a brand-new file on Windows is
   usually Defender or the indexer; the log records `canary settling`, so a settled read
   is a decision on the record and not silence. A decoy that was already on disk has no
   window. `canary.configure`/`canary.deploy` re-arm rather than only deploy, which is
   what keeps that true for a decoy added at runtime - and it removed a latent false
   alarm: a newly configured path used to arrive with no baseline and be reported as
   *modified*.
4. **The verdict travels with the product.** `read_detection()` writes a scratch file,
   reads it back and compares the time - on the **decoys' own folder** - and
   `canary.status`, `guard.status` and the Canaries screen carry
   `{available, probed_on, detail}` with the `fsutil behavior set disablelastaccess 0`
   that turns it on. When the decoys move to another folder the verdict is re-measured:
   caching it per process was a defect the probe caught, because a verdict about the
   previous volume is a *wrong* answer, not a stale one.

**Why.** The row existed because the copy said "modified" about an access it could not
see. The missing variable was not a kernel component, it was a timestamp - and where
that timestamp does not exist, the honest answer is a named limit the user can switch
on, not a claim. It also costs nothing: no driver, no elevation (the unelevated poll
sees it), no new dependency, and the guard's own poll provably cannot trip it (fifty
metadata queries in a row moved no last-access time; four reads in a row did).

**Commits us to.** `scripts\verify-canary.ps1` (20 checks) has to keep passing against a
real engine on a private pipe and a private `USERPROFILE`, `PROTECTION-MATRIX.md` §4.2
carries the measured range instead of the old "invisible" line, and §9 no longer lists a
read-level canary as missing. If a future Windows changes the last-access policy again,
the measured verdict is what tells the user - so nothing here may be re-stated as "reads
are detected" without the volume it was measured on. Naming the *reader* still needs ETW
or a driver and stays out of scope; `pid` is 0 on this event, and the copy says so.

---

## D-033 — A rule that has never matched a file is a claim, not a detection

**Status:** accepted (2026-11-05)

**Context.** The register row said it plainly: `verify-release.ps1` checks that the packs
*load*, not what they catch. Loading is a statement about a loader, and detection content
is the one part of this product whose *content is the feature*. The bill arrived the first
time a rule was asked to match anything: the shipped `Malicious_Macro_AutoOpen` tested
`uint16(0) == 0x504B`. YARA reads `uint16` little-endian, so `0x504B` is the bytes `K`,`P`
in file order - while a zip/OOXML container starts `P`,`K` and reads `0x4B50`. The rule
could not fire on any `.docm` that has ever existed, and no gate could notice, because a
rule that can never match loads perfectly.

**Decision.** Every rule the pack ships is either held to a file that proves it or named,
with its reason, as unreachable by a text vector.

1. `engine\testdata\detection` carries one vector per provable rule plus a clean control.
   The expectation table lives in two places that cannot drift: a unit test
   (`scanner::yara_engine::tests`, fast tier) and `scripts\verify-rules.ps1` (a real
   engine, the pack a package ships).
2. A declared rule that appears in neither table fails: the unit test asserts the counts
   add up, and the probe fails on the rule's own name. Adding a rule therefore means
   writing a vector or writing down why one is impossible.
3. Two rules are named rather than skipped: `EICAR_Test_File` (the string is what Defender
   itself reacts to, so a committed fixture would be quarantined and the gate would fail
   for the wrong reason) and `Tiny_Packed_Pe_Installer` (a PE-shaped fixture has to be
   binary; a malformed one is quarantine bait, a real one is a build artifact).
4. The probe prints the pack's SHA-256 with the verdict, and `verify-release.ps1` calls it
   with `-InPlace`, so the artifact's own `rules\` is what must catch the vectors - not a
   copy staged by the probe and not the pack compiled into the binary.

**Why.** Eight of ten rules are provable with a text file, and nobody had looked. The
ratchet is cheap (4 unit cases, 0.25 s; 35 probe checks, 6 s), it fails for the right
reason, and it makes the pack's coverage a number instead of a claim. It also converts the
"starter pack or real rules" question from taste into arithmetic: 8 of 10 rules are alive,
one of them only sees an uncompressed container, and the remaining two cannot be proven by
a file at all.

**Commits us to.** A new detection rule needs a vector or a named reason, and the fast tier
fails if a shipped rule stops matching. The measured limit stays written down where the
claim is made: a real `.docm` deflates its macro strings - measured, `AutoOpen`,
`CreateObject` and `Shell` are absent from the file's bytes - so the macro rule's reach is
one container shape, not document detection, and closing that is decision (b) (an
OOXML/OLE parser), not another rule edit.

## D-034 — A release discovers its signing identity; the certificate is two secrets, not a code change

**Status:** accepted (2026-11-06)

**Context.** The one purchase this project needs (`docs/COST.md`) is a code-signing
certificate, and the release path treated its absence as a property of the code:
`make-release.ps1 -Sign` had two identities, `-PfxPath` or the self-signed throwaway, and
the `Release` workflow carried a comment telling whoever bought the certificate to add two
repository secrets **and then edit the build step** to pass them. That is the wrong place to
keep a credential. The day the certificate exists, the release job would need a code change
reviewed, built and run before anyone could find out whether the wiring was right - and a
misspelled secret would have cost a ten-minute build before it said so.

**Decision.** The signing identity is decided at the start of the run, printed, and never
guessed.

1. `scripts\sign.ps1` takes exactly one identity - `-SelfSigned`, `-PfxPath` +
   `-PfxPassword`, or `-Thumbprint <sha1>` - and refuses zero of them or two. The thumbprint
   form is the one a hardware token or a cloud signing agent needs: the key never leaves the
   device, so there is no PFX to read and no password to pass. The two production forms
   accept only a signature Windows calls `Valid`.
2. `scripts\make-release.ps1 -Sign` resolves the identity once, before the build:
   `-Thumbprint`, then `-PfxPath`, then `MICS_CERT_THUMBPRINT`, then `MICS_PFX_B64` +
   `MICS_PFX_PASSWORD`, then `MICS_PFX_PATH` + `MICS_PFX_PASSWORD`, and only then the
   self-signed development certificate. A PFX that arrives as base64 is written to a temp
   file, used by `signtool /f`, and deleted before the script returns - a PFX left in the
   tree could be zipped into the package or committed.
3. The `Release` workflow already passes `secrets.MICS_PFX` and
   `secrets.MICS_PFX_PASSWORD` through as those variables, on both legs. An unset secret
   expands to the empty string, so today's runs behave exactly as before and the log says
   which identity was used.
4. `scripts\verify-signing.ps1` holds it: the guard refuses zero, two and an unknown
   thumbprint before signtool runs; a certificate from a store signs a real PE and the
   signature carries that certificate's thumbprint; an untrusted chain is *refused* rather
   than called verified; and the certificate it imported is removed from the store
   afterwards.

**Why.** The measured behaviour, not an intention:

- before this entry the wiring did not exist anywhere but in that comment;
- with `MICS_PFX_B64` and `MICS_PFX_PASSWORD` set, the run prints `signing identity: the CA
  certificate in MICS_PFX_B64` **before the build starts**, so a wrong secret is a
  ten-second failure;
- with `MICS_PFX_B64` set and the password missing, the run stops immediately with
  `RESULT: FAIL - MICS_PFX_B64 is set without MICS_PFX_PASSWORD`, also before the build;
- the honest limit: the local throwaway certificate is trusted in `TrustedPeople` and
  `TrustedPublisher`, not `Root`, so both production modes end their verification with "did
  not verify" and exit 1 on this machine - measured. That refusal is the design: `Valid` is
  what a CA-issued certificate produces, and the certificate row in `docs/ROADMAP.md` is
  what buys it. The positive end of that branch is therefore **unproven until a real
  certificate exists**, and the probe prints that sentence instead of passing quietly;
- end to end through the release script, with `MICS_PFX_B64` + `MICS_PFX_PASSWORD` set: the
  identity line printed before the build, all seven binaries were signed with that
  certificate (`CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`), every one of them came
  back `UnknownError`, and the run ended `RESULT: FAIL - 7 file(s) did not verify` then
  `RESULT: FAIL - signing failed; nothing was published` (exit 1). The temp PFX it decoded
  was gone afterwards and `dist\` was untouched. A self-signed PFX in `MICS_PFX` therefore
  cannot ship - which is the point of putting the certificate there and not the throwaway;
- while in the file: the signature's description URL (`signtool /du`) pointed at
  `github.com/mourad-ibrahim/mi-cs`, a repository that is not this one. Nothing reads that
  field, which is exactly why it survived; it now names the real repository.

**Commits us to.** A certificate is two repository secrets and no code edit, and
`verify-signing.ps1` must stay green while that is true. The thumbprint mode assumes the
runner already has the certificate with its key - a token or a signing agent - which the
workflow does not set up and does not claim to. The self-signed mode stays the default so a
release can always be cut, and its limit (Windows still says "Unknown publisher") stays in
the release notes until step 5 of `docs/COST.md` §5 can be written. This is the **signing**
side only: what the product *accepts* when it verifies an update payload is still the
signer's common name, pinned in `platform\windows\signature.rs` (D-016), and moving that
pin to a thumbprint is decision (c) in `docs/OPEN-DECISIONS.md` - a separate question with
its own cost, not something this entry decides.


---

## D-035 — Nothing is bought: trust is what a reader can verify by themselves

**Status:** accepted (2026-11-07). Supersedes the "trusted certificate later"
assumption in D-002, and closes **ب5** (the OV-class certificate) in
`docs/ROADMAP.md` as *not purchased* rather than *pending*.

**Decision.** MI CS buys nothing — no certificate, no signing service, no tool,
no cloud, no paid tier. The one paid item the plan ever had (the code-signing
certificate researched in `docs/COST.md` §2) is off the plan, and the public half
of "can a stranger trust this download" is answered with evidence that costs
nothing and that the reader can reproduce:

- the **integrity manifest** signed inside `mics-engine.exe` and the start-up
  self-check that re-hashes the folder and reports `ok` /
  `untrusted-certificate` / `unverified` (ج2, ط2);
- the published **`SHA256SUMS`** next to every asset, so a download can be
  checked against something that was not the download;
- a **reproducible build** (F-11) — the honest substitute for "a CA vouched for
  the author", and now required work rather than a nice-to-have;
- the **CI run record** for the release that produced the artifact;
- the **source itself**, which is the only claim here that a certificate never
  made.

The signing wiring stays exactly as D-034 left it, so a **donated** certificate
(no money changes hands) is still a two-secret drop-in with no code change. The
`CN=MI CS Code Signing` pin of D-016 is unaffected in the meantime and *must* be
moved to a thumbprint in the same release that first carries any certificate.

**Why.** The measured, dated research is in `docs/COST.md` §2, and every free
route closed for a reason that is not going to change:

- this is a free, open-source project; the brief promises no cost to the user and
  there is no budget behind it;
- a certificate buys **reputation**, not a security property: it changes what a
  first-run dialog says, and nothing about what the code does;
- Azure Trusted Signing needs a three-year-verifiable organisation and
  US/Canada residency (not available from Egypt); the free SignPath OSS
  programme excludes this product category; and **no CA can issue our CN**
  (CSCBR §9.2.2, an OV certificate must carry the verified legal name of a real
  person or organisation), so the D-016 pin could never fire on a real
  certificate anyway;
- the substitutes above are the ones that survive a hostile reader: hashes,
  a manifest, and a build anyone can repeat.

**Honest limits.** This decision does **not** make the warning go away. A
first-seen, unsigned binary has no reputation to look up, so Windows will keep
showing "Unknown publisher" and SmartScreen may keep asking — measured on this
machine on 2026-10-30 (unsigned, Smart App Control off, SmartScreen policy
default, reputation endpoints reachable, and still "can't be reached right now" /
"Unknown publisher"). That is **permanent**, and the README's troubleshooting row
says permanent, not "waiting for a certificate". The local half is real and stays:
`make-release.ps1 -Sign` with a self-signed certificate trusted in
`CurrentUser\Root` + `TrustedPublisher` makes every binary `Valid` and stops the
prompts **on the machine that trusts it**, which is what the acceptance runs use.

**Commits us to.**

- Not reopening the purchase without a **superseding** entry here (rule 7).
  "Let's just buy one" is a decision, not a chore.
- Keeping `docs/COST.md` §2 as the record of researched routes, dates and prices,
  so no session spends an hour re-finding the same dead ends.
- Not letting "we have no certificate" excuse missing evidence: the manifest,
  `SHA256SUMS` and the reproducible build are now the *load-bearing* trust story,
  so a release that ships without them is worse off than one that ships unsigned.
- Keeping D-034's two-secret path working, documented and probed, so a donated
  certificate (or a future maintainer who buys one for their own fork) needs no
  code change.
- Saying so plainly wherever the product is described: the README, this log and
  the release notes state that nothing is purchased, rather than implying a
  certificate is coming.

---

## D-036 — The signature is free after all: two routes, one of them available now

**Status:** accepted (2026-11-07). **Supersedes** the two claims in D-035 that the
first-run warning is "**permanent**" and that ب5 is closed as *not purchased*.
Keeps D-035's core rule — the project buys nothing — and leaves D-016 and D-034
exactly as they are.

**Decision.** "Nothing is bought" is still true, and it no longer follows that
nothing can be *signed*. The re-research (`docs/SIGNING.md`, every source dated
2026-11-07) found that the earlier pass asked the wrong question. It asked *which CA
will give this project a free certificate* — answer: none. It never asked *who else
can sign for us, for free* — answer: **Microsoft**, and **OSSign**:

- **Route A — the Microsoft Store, available today.** Microsoft's own comparison
  page states that publishing an **MSIX** package through the Store makes code
  signing "free and handled for you automatically — Microsoft re-signs the package
  after certification", with cost **Free**, availability **Worldwide**, SmartScreen
  **"No warnings"**. The developer account is free too: the $19 fee is waived in the
  new flow, verification is a government ID plus a selfie, and it covers "nearly 200
  markets worldwide" — Egypt included, no payment step anywhere in it.
- **Route B — OSSign, from ~2027-04-27.** A free certificate issued to the
  *project* (not to a person), signing keyless over OIDC trusted publishing, so the
  repository carries **no secret at all**. The requirements are an OSI-approved
  license (GPL-3.0-or-later), actively developed, public repository — all met — and
  a project age of at least **6 months**; the repository was created 2026-10-27.
  Their applications were suspended as of 2026-09, so this is a queue, not a form.

**Why this is not a reversal of D-035.** D-035 forbids *buying*. Neither route
spends anything: the Store's certificate is Microsoft's and the OSSign certificate
is OSSign's, and in both cases the publisher identity a stranger sees is the
signing body's verified one — not a CN we invented. The substitutes D-035 made
load-bearing (the in-binary manifest, the published `SHA256SUMS`, the reproducible
build F-11) stay load-bearing, because a signature says who shipped a file and
never that the file is safe.

**Honest limits.**

- **Route A is researched, not proven.** Three things are unverified and are
  written as unverified in `docs/SIGNING.md` §3: that Microsoft approves the two
  restricted capabilities a LocalSystem service needs (`packagedServices` +
  `localSystemServices`), that a packaged service can still write the real `hosts`
  file and drive the Windows Firewall from inside the MSIX container, and that the
  product category passes Store certification. Until a package is built and
  installed, this route is a well-sourced plan, not a result.
- **Route A moves distribution.** The signed copy lives in the Store; the GitHub
  release keeps the portable ZIP and the NSIS installer, self-signed as today. It is
  not "the same download, now signed".
- **Route B is a date, not an action.** Nobody can apply before ~2027-04-27, and
  the queue was closed when this was written.
- **SignPath stays closed**, and now on the record verbatim: their code of conduct
  cannot sign tools that "actively scan for and highlight exploitable
  vulnerabilities, e.g. by identifying unprotected network ports, missing password
  protection" — which is what our audit screen does. Their signed list (Fibratus, a
  Windows EDR; sniffnet, a traffic monitor) shows the line is *breach detection yes,
  posture audit no*, not "security is banned".
- **Nothing changes for a downloader today.** The release page still says the
  binaries are self-signed with no trusted publisher, because that is still true.

**Commits us to.**

- **Building an MSIX package** (`installer/msix/`), with the helper declared as a
  `desktop6:Service` running as `localSystem`, and measuring the three unknowns on a
  real install before promising anyone a warning-free download.
- **Writing the privacy policy** the Store requires (10.5.1 names Win32 products).
  It is short and true — MI CS ships no telemetry (rule 8) — but it must exist at a
  URL before a listing can.
- **Queuing the OSSign application** rather than forgetting it: the row in
  `docs/TODO.md` carries the ~2027-04-27 date and the age condition.
- **Keeping `docs/SIGNING.md` as the single place** where routes, dates, prices and
  the exact wording that closes a route are recorded, so the next session re-reads
  the source instead of re-arguing the question.
- **Correcting the record wherever it says the warning is permanent** — the README,
  `docs/TODO.md` and the release notes — because D-035 wrote that before this
  research existed, and a document that overstates a dead end is as wrong as one
  that overstates a feature.

## D-037 — The Store route gets a real MSIX package, and it is a third packaging, not a replacement

**Status:** accepted (2026-11-07). Depends on D-036 (route A), leaves D-026 (the NSIS
installer folds the helper's elevation in) and D-031 (`v0.1.0` is a draft) untouched.

**Decision.** Route A of D-036 is now implemented as far as it can be without
Microsoft: `installer/msix/AppxManifest.xml` declares the package, and
`scripts/make-msix.ps1` stages `dist\MICS-portable`, generates the logo assets,
substitutes the identity and publisher, packs, and signs when given an identity.
Three things about it are decisions rather than details:

1. **It is an addition to the release, not a new source of truth.** The portable ZIP
   and the per-machine NSIS installer stay the primary distribution; the MSIX exists
   so the Store can re-sign and distribute the same bytes. If the MSIX route dies,
   nothing else changes.
2. **The privileged helper is declared declaratively**, as
   `desktop6:Service Name="MICSHelper" StartupType="auto"
   StartAccount="localSystem" Arguments="helper-service"` — the same name, account
   and arguments the installer creates with `sc create`, but created by the package
   manager. That is the only reason the two restricted capabilities
   (`packagedServices`, `localSystemServices`) are in the manifest, and Microsoft
   approves those **per app**, so route A carries a certification risk that no local
   test can remove.
3. **The package's publisher must equal the signing certificate's subject**, which is
   why `make-msix.ps1` takes the subject from the certificate in `-SelfSigned` mode
   instead of letting a human type it, and why a Store submission must use the
   identity Partner Center assigns.

The manifest also **states its trust level instead of implying it**:
`uap10:TrustLevel="mediumIL"` and `uap10:RuntimeBehavior="packagedClassicApp"`. That is
not decoration — the container's behaviour is defined per trust level, and the
documented model (read 2026-11-07, `docs/SIGNING.md` §3) is what makes the privileged
product viable in a package: writes to system locations such as `C:\Windows\` are
blocked for **AppContainer** apps, while a full-trust package writes them subject to its
own account's permissions, and the write virtualization that remains covers `HKCU` and
`AppData` — neither of which this product's privileged work touches (it writes `HKLM`,
the firewall's own service, and the hosts file). The empirical test still decides it,
and it is written down as one elevated step, with the rule that results are read from
**outside** the container, because a read-back from inside a virtualized process would
prove nothing.

**Evidence, measured 2026-11-07:** makeappx 10.0.26100.0 packed 75 payload files into
22.11 MB in 3.6 s (`sha256 FFA869F7...` unsigned, `D40AAE90...` signed); the ZIP holds
79 entries including `[Content_Types].xml`, `AppxBlockMap.xml` and
`AppxSignature.p7x`; unpacking it proves the manifest kept the identity, the publisher
matching the certificate, the `desktop6:Service` declaration and all three
capabilities; makeappx accepted the service extension and both restricted capabilities
without a warning. The install then hit Windows' two rules rather than any fault in the
package: a signed self-signed package is refused with **0x800B0109** (no trusted root,
and user-level trust does not count, because AppX deployment reads machine trust), and
registering the **unsigned** staged folder in developer mode — a path no signature can
influence — fails with **0x80073D28**, "Administrator privileges required to install
packaged service". So **any package that declares a service needs an administrator to
install** — and the shape this product submits first declares none (D-038). The container
questions (can a packaged
service write the real `hosts` file and drive the firewall) stay **unmeasured**, and
they stay written as unmeasured in `docs/SIGNING.md` §3; the test machine was left with
no package, no service and no extra trusted root.

**Commits us to:** keeping the manifest and the script in step with the payload (a new
top-level file in the portable build must still pack); telling a Store user that an
administrator is needed for the install, rather than discovering it in a review; not
describing the MSIX route as working until a Store-signed build has been installed and
the container behaviour measured; and keeping the two restricted capabilities visible in
the manifest, where a reviewer can see exactly why they are requested.

**Does not commit us to:** a Store-only future, a paid account (the route is free), a
Partner Center identity before one exists, or publishing an MSIX release asset that
nobody has certified.

## D-038 — The Store submission declares no service, so it installs without an administrator

**Context.** D-037 packaged the full product — the helper included, as a
`desktop6:Service` — and measured what Windows does with that: **0x80073D28,
"Administrator privileges required to install packaged service"**, a rule that applies to
any package declaring a service rather than a fault in our manifest. That shape also
carries two restricted capabilities Microsoft approves per app, and the container
questions in `docs/SIGNING.md` §3. Three risks riding on one submission.

**Decision.** `scripts\make-msix.ps1` gains `-ServiceMode Packaged|None` (default
`Packaged`), and **the first Store submission uses `None`**: no `desktop6:Service`, no
`packagedServices`, no `localSystemServices` — `runFullTrust` alone. Privileged work is
then done by a helper installed *outside* the package, which is the arrangement D-026
already chose for the direct download (the NSIS installer's one UAC prompt, or
**Settings → Engine → Install helper**).

**Why.** Measured A/B, same staged folder, same call, minutes apart: `Packaged` →
0x80073D28 refused; `None` → **registered with no elevation at all**, `Status Ok`,
`IsDevelopmentMode True`, one declared capability, removed cleanly with no leftover. That
takes the capability approval and the administrator requirement off the critical path,
and it takes the container out of the hosts write entirely, because the process doing
that write is no longer inside it. It also matches the architecture this project already
chose: the app is the UI, the helper is a separately-consented privileged component
(D-002, D-026).

**What it costs, stated plainly.** A Store-edition user who has never installed the
product gives one UAC prompt before any fix works; until then the app can scan, detect,
guard and report, and must say so rather than fail silently. The package can no longer
guarantee that the service binary is present, so the UI's "helper absent" state stops
being an edge case and becomes the first-run state. The engine was given the other half of
that story on the same day: `helper-status` now reports `stale` and `bin_path`
(`docs/PRIVILEGED-OPS.md`), so a registration pointing into a folder a package update
replaced is named, with the fix that works, instead of being reported as "installed but not
answering". Nothing re-registers on its own, and that stays written as the open half. The
shape was then run for real on 2026-11-07 and the app half works end to end: `mics_app`
started `mics-engine` from the package folder, the engine answered the app's heartbeat, and
its integrity self-check passed from inside the container (`docs/SIGNING.md` §3). The helper
across the container is still unmeasured, because installing one needs an administrator.

**Supersedes** one clause of D-037 — "the Store edition needs an administrator to
install". Any package that *declares a service* needs one, and that measurement stands;
the shape submitted first declares none. The rest of D-037 — a third packaging rather
than a replacement, the declarative service, publisher equal to certificate subject —
stands untouched.

**Does not commit us to:** never shipping the `Packaged` shape (it stays the full-product
shape for a later submission or a direct download), or to installing a helper without the
user's consent, which D-026 forbids.

## D-039 — The engine belongs to the app that started it, and ends when that app does

**Context.** D-006 made the engine one long-lived process per machine, and the product
brief said what that meant for its life: "Closing the UI -> tray; engine keeps
protecting." So the app started `mics-engine service` *detached*, never stopped it, and
hid to the tray on close instead of quitting. Closing MI CS therefore left
`mics-engine.exe` running with no window anywhere that named it, and the only way to end
it was Task Manager — an invisible process watching every new process on the machine,
which is exactly the shape this project's threat model treats as a liability, and one the
user cannot see, stop, or even know about. The user asked for the opposite on
2026-11-08: "when I close the program, the engine should close and exit."

**Decision.** The engine's lifetime is the app's lifetime, in three parts. (1) The app
starts it with `service --parent <its own pid>`; the engine opens a handle to that
process once and exits when the handle signals, so a close, a crash and a Task Manager
kill all take the engine with them. (2) On a deliberate quit the app *asks* first —
`shutdown`, a new whitelisted method, answers `stopping` and only then ends — so the app
can tell "my engine is stopping" from "I lost the engine". (3) Closing the window quits
by default; **Settings -> Protection -> "Keep running in the background"**
(`close_to_tray`, default **false**) restores the previous behaviour by hiding to the
tray.

**Why.** A handle rather than a pid polled on a timer, because Windows does not hand a
pid to another process while a handle to the first one is open — so "signaled" cannot be
a recycled pid, it can only be that process ending. Asking before stopping, because a
clean end is what keeps the engine's own bookkeeping honest; and the parent handle as the
second path, because a process that was killed cannot ask for anything. The app stops the
engine only when it started it: it compares `status.pid` with the pid it spawned, so a
second MI CS that merely attached to a running engine does not end protection somebody
else owns.

**What it costs, stated plainly.** Protection lasts as long as MI CS is open, and no
longer: the process guard, the scan schedule and the alert cards stop with the engine.
The Windows-enforced artefacts — firewall rules, hosts entries — stay, because Windows
enforces them without us. An engine started by something else (the autostart entry
`service.install` writes, a terminal, a verifier) has no parent and keeps running until it
is asked to stop, which is what makes 24/7 an explicit choice instead of an accident.
Measured on this machine on 2026-11-08: no MI CS entry in `HKCU\...\CurrentVersion\Run`
and no MI CS scheduled task exist, so nothing starts an engine behind the user's back
today.

**Measured.** `scripts\verify-lifecycle.ps1`, against a real engine on private pipes and a
stand-in app process: **19 checks, 0 skipped, 0 failures, 9.6 s** — a killed app ends the
engine within seconds with the reason in its log and no crash report; `shutdown` answers
`stopping` before the process ends and files no crash report; an engine whose `--parent`
was already gone ends by itself; a parentless engine keeps running until it is asked to
stop; `service --help` lists `--parent`. Engine unit tests: 6 new cases (4 on the stop
flag, 2 on the parent handle) in 158 passing, 0 failing.

**Supersedes** one line of `MI-CS-Agent-Prompt.md` ("Closing the UI -> tray; engine keeps
protecting") and the comment it produced in `lib\main.dart`. D-006 (one engine per
machine) is untouched, and is what makes ownership checkable at all.

**Does not commit us to:** stopping an engine this app did not start, hiding a running
protection engine from the user, or removing the autostart entry — 24/7 protection stays
one explicit switch away (Settings -> Engine -> Start with Windows).

---

## D-040 — The tray's styled surface is a Flutter panel in the app's own window

**Context.** The tray icon offered two labels — `Open MI CS`, `Quit` — because §0.6 row 15
measured what `tray_manager 0.5.2` can build on Windows: `AppendMenuW`, which draws labels,
separators and check marks and nothing else (read in the plugin's `tray_manager_plugin.cpp`
on 2026-11-08). No icons, no colours, no typography, at any amount of effort. The user asked
for a tray surface that is styled — "شيك … كريتف و احترافي" — so the styled surface had to be
Flutter's, and the native menu had to become the fallback rather than the product.

**Decision.** A left click on the icon opens a **Flutter panel, painted in the app's own
window**: 392×486 logical pixels (360×420 floor), non-resizable, always-on-top, out of the
taskbar, positioned above the notification area, closed by `Escape`, by its ✕, or by
clicking anywhere else. The right click still opens the native menu: D-040 supersedes the
"deliberately small" reading of that menu, not the menu. Three consequences, all deliberate:

1. **One window, not two.** A second window means a second Flutter engine and a second
   Riverpod container, and every number in the panel would have to be synced between them.
   The panel *borrows* the window the app already has and reads the providers the screens
   read (`guardProvider`, `firewallProvider`, `connectionsProvider`, `settingsProvider`), so
   its state is live by construction. `MaterialApp.router`'s `builder` paints the panel over
   the router rather than replacing it, so closing the panel returns to the page the user
   was reading.
2. **Placement is measured, not guessed.** `tray_manager.getBounds()` reports the icon in
   **logical** pixels (the plugin divides its device pixels down) and `screen_retriever`
   reports the work area in the same units, so the panel sits above the icon and is clamped
   into the work area; when neither answers (a stripped build, a test) it falls back to the
   bottom-right corner of the work area — where Windows puts its own tray flyouts.
3. **The panel is a view of the engine, never a second source of truth.** The guard switch
   asks `guard.start`/`guard.stop` and then re-reads `guard.status`; the other two switches
   write the same settings Settings -> Protection writes (`dnd`, `close_to_tray`); `Quit` is
   the D-039 quit — `shutdown`, then the window — from the panel and the native menu alike.
   Every window call is best-effort, so a platform without `window_manager` still leaves the
   panel's content usable instead of throwing out of a tray click.

**What it costs, stated plainly.** While the panel is open it *is* the app window: opening
it resizes and moves the window, and closing it hides the window rather than revealing the
app. A left click therefore shows the app when the app is already on screen and the panel
when it is not. The panel has no title bar to click (the window is `TitleBarStyle.hidden`),
so `Escape` and clicking away are the ways out. `screen_retriever` is now named in
`pubspec.yaml` instead of arriving transitively through `window_manager`: no new code was
fetched for it, and the analyzer requires the name before an import of it is allowed.

**Measured.** `scripts\pipeline.ps1 -Tier fast`: **PASS, 4 of 4, 63.0 s** at `d80d5ee`
(`build\pipeline-fast.json`), `flutter analyze --fatal-infos` clean, `flutter test`
**146 passing, 0 failing** (141 before this pass). Four of the new cases are the panel's
(`test/tray_panel_test.dart`): it asks `guard.status`, `fw.default_deny.status` and
`net.connections` for the state it shows; the guard switch asks the engine *and* re-reads
it; the other switches write `dnd` and `close_to_tray`; `Escape` and `Quit` throw nothing.
The panel is also a **swept surface**, not an exception: `qa/ui/ledger.json` gained
`surfaces.trayPanel` with exactly **6 controls** (Open MI CS, Quit, ✕, three switches), and
`qa/report.md`/`.html` now read **"13 screens, 1 surface and the shell"**, **107 controls**,
**67 methods** — a diff a reviewer reads, which is the point of the ledger. The 19 new i18n
keys exist in both packs (`ar`, `en`), which `test/i18n_parity_test.dart` enforces.

**Supersedes** the comment in `lib\main.dart` that said the tray menu "stays deliberately
small until the tray panel lands", and closes §0.6 row 15. `tray_manager` is untouched: the
native menu keeps working, which is what makes it a fallback rather than a leftover.

**Does not commit us to:** a second window or a second Flutter engine, tray badges or
overlay icons, richer panel content (charts, incident lists), or removing the native menu —
it stays the right-click path for anything the panel does not do.

## D-041 — Explorer's verb hands the path to the window that is already open

**Context.** §0.6 row 16 measured the hole: nothing in the tree could scan a file the user
was looking at. There was no context-menu verb anywhere, and no way for a second launch to
reach the process that already had a window — two MI CS processes would mean two windows
watching one machine, each with its own engine. Windows gives the verb a *fresh process* and
the path as an argument (`--scan "%1"`), so the argument had to travel from a process that
must not stay alive to a window that must not start a second engine.

**Decision.** The **engine is the single instance**, and the handover is one new method.
Three parts:

1. **The verb**, written by the installer and deleted by the uninstaller, under the
   installing user's own hive: `HKCU\Software\Classes\{*,\Directory,\Directory\Background}\
   shell\MICS`, labelled `Scan with MI CS`, carrying the installed app's icon, running
   `"<install>\mics_app.exe" --scan "%1"` — and `--scan "%V"` for
   `Directory\Background`, where the click is on the empty space *inside* a folder and `%V`
   is that folder. `*` covers a file, `Directory` a folder, and all three are needed: a
   user who right-clicks a `.pdf` and a user who right-clicks a folder are the same
   intention. Per-user keys, written even from the per-machine install: NSIS runs the
   elevated half with the invoking user's token still attached, which is the same reason the
   AUMID key has always been HKCU.
2. **`app.activate`**, the 68th method, with an optional `path`. It answers
   `{"delivered": <bool>}`, where delivered means *another transport is attached*
   (`subscriber_count() > 1`: the caller is a client too, so only a second one counts). When
   it is delivered the engine raises `event` `{"type":"activate","data":{"path":...}}` to
   every client; when it is not, nothing is raised at all — a notification nobody could hear
   is noise, not a message.
3. **The app's first act**, in `lib\core\ipc\handoff.dart` (new) and `lib\main.dart`: every
   launch announces itself and reads the answer. `delivered: true` means the window that is
   open has been handed the path, so this process ends through the D-039 quit path — and it
   leaves the engine alone, because attaching first (`tryConnect`) means it never owned one.
   `delivered: false` means this process *is* the window: it raises itself, records the
   handover in `handedScanProvider`, navigates to the scanner, and the scanner starts the
   scan (quarantine on, matching the checkbox the screen shows) and puts the handed path in
   the path field.

**What it costs, stated plainly.** Explorer paints the menu from those keys and no script can
read the menu back, so the verb is proved as far as it can be: the keys exist under this user,
their label, icon and command line are the ones above, and the `--scan` path they invoke is
tested end to end against two real clients. A second launch still creates a process, attaches
to the engine, asks, and only then closes: the window it opens for that moment is the price of
using one pipe instead of a Win32 named mutex — and the pipe is the thing both processes
already trust. Multi-selection is not measured: no `MultiSelectModel` is written, so what
Explorer does with five selected files is Explorer's default and unproven. Another client that
is not a window (a probe, a script holding the pipe) counts as a listener and would swallow a
handover — the count is of transports, not of windows, deliberately, because a probe that can
receive it can also report what it received. The MSIX and the portable package get **no** verb:
they are not installed by this installer.

**Measured.** `scripts\verify-handoff.ps1` (new): **PASS, 10 checks, 5.1 s**, against a real
engine on a private pipe, using two real `NamedPipeClientStream` connections the way two app
processes use two pipe handles — `delivered: true` with a window attached, the `event`/
`activate` notification arriving on *that* window with the path unchanged (spaces and all),
a notification and not a reply, a plain launch carrying a null path, `delivered: false` once
the window closes, and nothing raised for the caller that has nobody to hand over to.
`engine/src/jobs.rs` gained four unit tests (the handover boundary, the payload, the plain
launch, and that the activation is not a `progress` event), and `test/handoff_test.dart`
(new) has twelve: five for `--scan` parsing (`--scan p`, `--scan=p`, no flag, a flag with no
path, extra arguments), six for the two halves of the handshake against `FakeEngine` — "nobody
is here", a plain launch, a window that is handed over and does not act on its own activation,
an engine too old to answer at all (which must still leave the user a window), an activation
that carries a path and one that does not — including the one that matters for the row: a
handover makes the scanner ask for exactly `{"path": ..., "quarantine": true}` and show the
folder it came with. `flutter test` is **158** (146 before). `scripts\
verify-installer.ps1` now asserts the verb on each of the three classes after install
(label, icon, command line), their removal after uninstall, their survival of a refused
uninstall, and refuses to run at all on an account that already has the verb (it must own
what it deletes). `qa/methods.json` carries the 68th method; `qa/report.md`/`.html` were
regenerated and `test/qa_report_test.dart` is byte-identical.

**Environment limit, recorded here.** The live install half of `verify-installer.ps1` could
not run in the session that wrote this: on that machine `Start-Process` on the freshly built
NSIS package never returned (no process appeared, no key was written, the same for a copied
package and for a `WaitForExit(150000)`), so the verb keys are asserted by a probe that runs
where an install can run — a release-tier or user run — and not claimed from this session.
The engine half of the handover *is* measured here, live, as above.

**Closes** §0.6 row 16. **Does not commit us to:** a Win32 single-instance mutex, scanning a
whole multi-selection, a shell extension (`IExplorerCommand`), Windows 11's top-level menu
placement, or an "Open with" entry — the verb is one entry that scans.