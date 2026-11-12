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

**Amendment (2026-11-11, D-051 — the pin is the certificate, not the name).** Points 3 and 4 below
are superseded *as contracts*, and kept as the record of what was decided in 2026-11-03. The pin is
now `signature::Pin`: the **thumbprint of the certificate over the engine itself** whenever this
build has a certificate of its own (or `MICS_UPDATE_SIGNER_THUMBPRINT` says which one), and
`CN=MI CS Code Signing` only where it does not — an unsigned development binary. The name is still
what `scripts/make-release.ps1 -Sign` publishes, and still what an unsigned build checks, so the
release procedure below is unchanged; what changed is that a CA-signed release no longer refuses
itself, and a certificate with the same CN issued by somebody else is no longer accepted. Read D-051
before touching the pin.

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

## D-042 — MI CS gets its own layer in the filtering engine, not a driver

**Context.** §0.6 row 17 measured what existed on 2026-11-08: `MICS-*` blocks live in the
**Windows Firewall's rule table** (`INetFwPolicy2`/`INetFwRule`), which the engine stops
owning the moment it stops — the rules persist and Windows enforces them, but they are
Windows' objects, in Windows' namespace, indistinguishable from a rule a user or another
product wrote (`MICS-` is a naming convention, not a boundary). The row asked for MI CS' own
enforcement layer: WFP persistent filters under a **provider and sublayer MI CS owns**, the
way `netsh wfp` and every filtering product describe them. The alternatives the register
weighed — WinDivert/Mullvad-Lib or a driver of our own, and the legacy `netfilter2.sys` —
mean shipping kernel code and a WHQL-signed binary: more to sign, more to get wrong, and a
known-bad driver in the family tree. WFP is the supported path, and it needs no driver.

**Decision.** Slice (a): a **provider, a sublayer and persistent filters owned by MI CS**,
written only through the helper (D-007), with the same prefix and the same undo story as the
firewall rules. Five parts:

1. **The objects** (`engine\src\firewall\wfp.rs`, new). A provider keyed
   `{6D494353-0001-4D49-9B43-534355425331}` named `MI CS` and a sublayer keyed
   `{6D494353-0002-…}` named `MI CS real-time filter`, both persistent in the BFE store and
   stable forever, so a second install finds the same objects instead of a parallel set.
   Filters are added with `FWPM_FILTER_FLAG_PERSISTENT` at the ALE connect layers
   (`FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `_V6` — connection time, both address families),
   action `FWP_ACTION_BLOCK`, under our sublayer (weight `0x7fff`, the highest value the
   API's own examples use for a sublayer that has to be consulted first), with one
   condition: the application id and/or the remote port.
2. **The key is derived from the spec**, not rolled: `sha256` over the canonical fields, with
   the RFC 4122 version/variant bits set, and the V6 filter's key differs by one bit. Asking
   for the same block twice edits the same filter instead of adding a second one, and
   removing it needs no state we could lose between runs.
3. **Four ops, no more** (D-007 amendment): `firewall.wfp.status`, `firewall.wfp.block`,
   `firewall.wfp.unblock`, `firewall.wfp.reset`. The set is still a closed enum and the
   payload is still data — a spec — that the helper validates, not a command it interprets.
   `reset` names **our provider key**, never a filter name, so it cannot delete an object
   Windows or another product owns.
4. **A block is verified before it is reported.** `block_now` reads the filter list back from
   the BFE and fails unless the new filter is in it; the helper reports `added`, `key` and
   the resulting filter count, and the audit line carries the filter's display name and key —
   never the directory the application sits in.
5. **Four methods on the dispatcher**: `fw.wfp.status`, `fw.wfp.block`, `fw.wfp.unblock`,
   `fw.wfp.reset` (72 registered now), routed through `WfpManager`, which writes directly
   when the process is elevated and through the helper when it is not — the same split as
   `FirewallManager`.

**What it costs, stated plainly.** A persistent filter is enforced by the BFE with MI CS not
running at all, which is the point of the row; it is also **not a kernel driver** and does not
pretend to be one. Traffic that never reaches the ALE layers for a named application — kernel
mode, raw sockets, a filter in a higher-weight sublayer, a callout that terminates a
connection before ours sees it — is outside what this slice covers. Blocking *by application*
still means the path the user gave us, exactly like a firewall rule: the same binary reached
through a renamed copy is a different filter. And the unelevated engine cannot read the
BFE at all, so `fw.wfp.status` answers `needs_elevation: true` **with the reason** rather
than showing an empty list — "0 filters" and "cannot look" are different facts and the UI
must not confuse them.

**Measured.** Twelve new unit tests: eight in `engine\src\firewall\wfp.rs` — the canonical
name keeps its prefix and says what it covers, a spec with nothing in it is refused, a
protocol without a port is refused, a path that cannot be a path is refused, the same block
has the same key, a known spec keeps its measured key
(`B051BA44-F5BF-454C-8D09-B8F1F8D5680E`, so a key cannot move between versions), the two
layers get two keys and a well-formed GUID (RFC 4122 version 4, variant `10`), and — on this
machine, unelevated — **the BFE opens and refuses the write**: `FwpmEngineOpen0` succeeds,
`FwpmProviderAdd0` answers `0x80070005 Access is denied`, and the code names that as
`needs_elevation`. Four more in `engine\src\tests.rs` — the four ops are in the closed set
and a made-up one is not, a spec with no target and a note with a newline or 41 characters
are refused before the wire, the audit line carries the filter name and key but not the
folder, and the RPC params become a spec or a refusal with the same gate. `cargo test` is
**174** (162 before). `scripts\verify-wfp.ps1` (new) measured the live surface on this
machine, unelevated, against the debug engine: **PASS, 7 checks, 3 skips, 0 failures** —
`fw.wfp.status` answered `sublayer=false filters=0 needs_elevation=true` with the helper's
own refusal as `detail`, `fw.wfp.block` was refused **with the reason**
(`unknown variant firewall.wfp.block, expected one of ping, version, …, hardening.rollback`)
instead of the generic "method failed", and the three write checks skipped: this shell is
unelevated but a `MICSHelper` service *is* running on this machine, and the **installed
helper predates this decision** — reinstalling it from Settings → Engine is what makes the
write path reachable. The RPC contract ran against the same binary: **86 cases, 0 failed**,
with the four new methods answering in their documented shape (`status` an object, the three
writes a refusal error), and `qa/methods.json` carries them; `qa/report.md`/`.html` were
regenerated (72 methods, 107 controls).

**Measured against the real Base Filtering Engine on 2026-11-09** — the elevated run §0 item 7
asked for, with `engine\target\debug\mics-engine.exe` (the build that carries D-045):
`scripts\verify-wfp.ps1` **16 checks passed, 2 skipped, 0 failed, 5 s**. `fw.wfp.status` answered
`needs_elevation=false` before and after, `fw.wfp.block` reported `block` with
`added=true` and the key `77C31A7A-8BE6-4277-BDCC-6045151EE243`, the filter count went from 0 to
2 (one per address family), and the name MI CS reports is the one Windows reports:
`MICS-mics-engine.exe port 65001 protocol 6 probe`. Windows' own `netsh wfp show filters` carried
the same object — `FWPM_FILTER_FLAG_PERSISTENT`, `FWPM_FILTER_FLAG_INDEXED`, provider
`{6d494353-0001-...}`, sublayer `{6d494353-0002-...}`, layer `FWPM_LAYER_ALE_AUTH_CONNECT_V4`,
conditions `FWPM_CONDITION_ALE_APP_ID` (a `FWP_BYTE_BLOB` holding the debug exe's path),
`FWPM_CONDITION_IP_REMOTE_PORT` 65001 and `FWPM_CONDITION_IP_PROTOCOL` 6, action
`FWP_ACTION_BLOCK` — and the probe checked it is **not** a Permit filter. The undo removed it:
gone from our list and from Windows' filtering state. The two skips are honest: the
`netsh wfp show state` comparison produced no XML here (`show filters` carried the same evidence),
and part 5's refusal path is unreachable in a shell that can write (measured unelevated instead).
The first elevated run of the same probe (2026-11-08) is what produced D-045: every call failed
`0x80320004`.

**Not measured, and the row keeps these three open.** No connection was opened through the filter
to watch it be **refused**, so the enforcement effect is not composed into evidence; no **reboot**
was performed, so survival is the `FWPM_FILTER_FLAG_PERSISTENT` flag Windows prints rather than an
observed reload; and no **permit rule with a higher precedence** was created, so whether our
sublayer weight (`0x7fff`) really outranks the built-in firewall's permit is still unproven. What
the run does prove is the layer MI CS claims: MI CS' own provider, sublayer and persistent block
exist in the BFE, Windows names and enforces them with MI CS free to stop, and `reset`/`unblock`
address only our provider key.

**Advances** §0.6 row 17 (slice a), which is closed for what it states — the firewall is Windows'
rule list, and MI CS writes real rules into it — with the three claims above named as the honest
limit. **Does not commit us to:** a kernel driver, WinDivert or Mullvad-Lib, DNS or name
resolution interception, stateful callouts or the stream layer, per-connection state, blocking
by package SID, or any UI surface of its own — this slice is the enforcement layer the rest of
the product can now build on.

---

## D-043 — The connection list offers one block, and the engine writes the filter it implies

**Status:** accepted (2026-11-08)

**Context.** §0.6 row 17 slice (b) asked for the half of a real-time firewall a user actually
touches: the live connection list, and a way to block one line of it. `net.connections`
existed and was **IPv4 TCP only** — `GetExtendedTcpTable`/`GetExtendedUdpTable` for
`AF_INET` alone, no IPv6 at all, so a block on `[2001:db8::1]:443` was not expressible and a
machine whose traffic had moved to IPv6 could be watched and then not acted on. The walk lived
in `platform\windows\collectors.rs`, in an `unsafe` block that no unit test can reach, next to
`format_ipv4_port` and `tcp_state_name` which are pure and were testable but untested. And the
UI had no action on a row: `fw.wfp.block` (D-042) existed with no caller.

The tempting shortcut is for the UI to build the spec: the row already *shows* a peer
`address:port` and a process name, so `{app: row.processName, port: <parsed>, ...}` looks like
enough. It is not. `fw.wfp.block` matches an **image path**, not a process name — a name is
spoofable and a path is what the filter compares — and the displayed port is a *string in a
column*, which can be a listener's local port, a UDP socket's local port, or `*:*`. A UI-side
parser would be a second, weaker copy of the engine's own knowledge, and its mistakes would be
silent: a filter that blocks the wrong thing still reports success.

**Decision.** Slice (b): the walk and the block decision move into a module of their own, and
the **engine** derives the filter spec a row implies.

1. **`platform\windows\conns.rs` (new; `collectors.rs` keeps only the trait wiring).** All four
   tables — `TCP_TABLE_OWNER_PID_ALL` and `UDP_TABLE_OWNER_PID` for `AF_INET` **and**
   `AF_INET6` — are walked, so both address families are in the list. A row is IPv6 when the
   table it came from is, and its addresses are formatted the way Windows writes them
   (`[2001:db8::1]:443`, `[::]:135`), not as bare hex. The process name comes from one
   `sysinfo` refresh; the **image path** comes from one `OpenProcess` +
   `QueryFullProcessImageNameW` per pid, cached across all four tables for the call, and
   `OpenProcess` failing is a `None` path rather than an error or a guessed name. `tcp_state_name`,
   the two address formatters and the peer-port rule are `pub` and unit-tested in this module.

2. **The spec is derived, once, in the engine** (`block_for`). A row becomes
   `NetworkBlock { app, port, protocol, note }` — the row's own `process_path` as the filter's
   application, its `remote_port`, its protocol number, and a note built by `note_for`, which is
   filtered to the character set, and the 40-character ceiling, the helper's validator accepts.
   It is `None` when the filter would not mean what a click implies: **no peer port** (a UDP
   socket — Windows keeps no peer for it — or a TCP listener), **no image path** (a kernel
   connection, or a process this token may not query), or a protocol we do not filter. The field
   is serialised either way — a row that cannot be blocked arrives with `block: null`, which is a
   statement in itself — and the UI offers the button only when it is there.

3. **The UI forwards, it does not assemble.** `NetworkConnection` carries `process_path`,
   `protocol_number`, `remote_port` and the `NetworkBlock?`, and the block button sends
   `block.toJson()` — the engine's own object — to `fw.wfp.block`. One click is confirmed first,
   and the confirmation names the program and the port and says the filter outlives MI CS,
   because a persistent block is a deliberate act and not a view setting. The screen fetches a
   snapshot when it opens (it previously listed nothing until Refresh was pressed), and the
   engine's own refusal is shown as its sentence: unelevated, "needs an administrator" is a real
   answer, not a failed click.

4. **What it is not.** The list is a snapshot of the kernel's tables, not a push feed: a
   connection that opens and closes between two reads is never seen, and a row can be seconds
   stale by the time it is clicked. There is no per-row traffic counter, no reverse DNS, no
   process tree, and no un-block from the row itself. UDP rows still have no peer, because
   Windows has none to give.

**Measured on this machine, 2026-11-08** (unelevated, against `engine\target\debug\mics-engine.exe`):

- `cargo test` **180** (174 before): 6 new in `conns` — a spec is offered only with a peer port
  and an image path, the note fits the helper's validator, both families format the way Windows
  writes them, and the running process resolves to a real image path — plus the moved
  `format_ipv4_port` case. `cargo clippy --release -- -D warnings` clean, and the fast tier as
  one run: **green, 4 of 4, 66.4 s warm** — which is where the analyzer's `--fatal-infos` and the
  control ledger's ratchet were both seen turning over.
- `scripts\verify-connections.ps1` (new) against a real engine on a private pipe: **PASS, 23
  checks, 0 skipped, 0 failed**. It found what a unit test cannot: **490 rows**, every one
  carrying path, protocol number, peer port and a block decision; **139** offering a spec whose
  application path, peer port and protocol match the row it came from *and* whose file exists;
  no row with an empty peer port offering one; IPv6 rows present on a machine that has IPv6
  connections; UDP rows present with `*:*` instead of an invented peer; **0** rows naming an
  owner Windows disagrees with, out of the 147 whose socket was still in `Get-NetTCPConnection`
  / `Get-NetUDPEndpoint` when the probe looked (343 had already vanished — a snapshot ages, and
  the probe counts that rather than failing). Two behaviours this probe had to learn from the
  machine, and now encodes: Windows reports pid 0 for a socket that is closing while MI CS still
  has the owner (D-042's table read), and the two Windows APIs name *different* binders for the
  same shared wildcard UDP socket (WS-Discovery, mDNS, SSDP), so those rows are counted as
  ambiguous instead of being called wrong.
- The write path: the spec a row offers was handed to `fw.wfp.block` as the UI sends it, refused
  **with a reason** (`unknown variant firewall.wfp.block, expected one of ping, version, ...`) —
  the installed `MICSHelper` predates the WFP ops, exactly as D-042 recorded — and
  `fw.wfp.status` was unchanged after the refusal, so nothing was left behind (D-007).
- App side: `flutter analyze` clean, 2 new widget tests (the click sends the engine's own spec
  and reports the refusal; cancelling writes nothing), `qa\ui\fixtures.json` moved to the real
  engine shape with the blockable and unblockable rows both present, the control ledger
  regenerated (**+2 controls, 109**), and the RPC contract re-run against the same binary:
  **86 cases, 0 failed**, with `net.connections` answering in the new shape.

**Measured elevated on 2026-11-09** (same run, fixed debug build):
`scripts\verify-connections.ps1` **24 checks passed, 0 skipped, 0 failed, 6 s**, with part 3 taking
the write branch for a **real row's own spec** instead of the refusal path — the spec
`fw.wfp.block` accepted, the BFE holding one more filter, `fw.wfp.unblock` removing it, and the
probe's closing check that the machine is back where it started. The list itself: 462 rows, every
one carrying address, protocol, state, pid, name, path, protocol number, remote port and a block
decision; 143 rows still present in Windows' own table when compared, 319 already gone, 38 shared
UDP sockets not comparable; 147 rows offering a block and 315 not; IPv6 and UDP rows present, with
a UDP row saying it has no peer instead of inventing one.

**Not measured, and the row keeps this open.** Nothing watched a blocked row's connection actually
die: the probe proves the filter a row offers is exact, accepted and really in the BFE, not that
the connection it names is then refused (that would need the probe to open a connection through
the filter, and the click's own effect on screen is the same claim a step further out). So the
sentence "the spec a row offers, once accepted, blocks exactly that row's connection" is now
written, reasoned and **half measured**: the rule is real and Windows-owned, its enforcement on a
live socket is not observed. The UI's own click is proved up to the wire, plus 2 widget tests.

**Advances** §0.6 row 17 (slice b), which is closed for what it states — there is a live feed and
a one-click block. **Does not commit us to:** a packet-level view, per-connection
state or byte counters, reverse DNS, a process tree in the list, blocking by process *name*,
automatic blocking from a heuristic or a feed (the click is the human's), or an un-block from the
row — removal stays the Firewall tab's rule list, where the filter's own name is shown.

## D-044 — The filtering layer watches itself, and an administrator's deletion is an incident

**Status:** accepted (2026-11-09)

**Context.** §0.6 row 17 slice (c) asked for the last piece of a real-time firewall: MI CS should
notice when what it wrote is taken away. D-042's objects are **persistent** in the Base Filtering
Engine on purpose — that is what makes a block outlive the app — and the same property makes them
deletable by anything holding an administrator token, with the result that MI CS would go on
reporting `fw.wfp.status` for a machine whose protection is gone. Nothing watched it: the guard's
events were process starts and canaries, and the status call was a request the UI made when it felt
like it, not a poll with memory.

The obvious design — a subscription — is not available to us. `FwpmFilterSubscribeChanges0` needs
the same access the write path needs, and the write path is the wall D-042 and D-043 both hit: an
unelevated engine can only ask the helper, and the helper reads the BFE for it. A kernel callout
driver would see the deletion immediately and is exactly what `SECURITY.md` forbids (usermode
only). So the feature is a **record plus a poll**, and its honesty depends on saying what a poll
cannot see rather than on pretending it is a subscription.

**Decision.**

1. **A record beside the objects, never a second source of truth.** `meta` row `wfp_baseline`
   holds the filter names MI CS wrote and whether it created the sublayer. `WfpManager::block`
   writes it after the outcome is known — on both privilege paths, so it is the engine's own
   bookkeeping rather than the helper's — `unblock` removes that one name, and `reset` clears the
   record, because a cleanup MI CS performed itself must never come back as a tamper. A **refused**
   write records nothing: memory of a filter that was never created would be a tamper alarm on the
   next poll.

2. **The judgement is pure and has five answers.** `verdict(baseline, live)` returns
   `WatchReport { state, recorded, live, missing, extra, sublayer, needs_elevation, detail, at }`:
   `clear` (nothing recorded, and the machine agrees it holds nothing of ours), `unrecorded` (our
   filters are on the machine with no record beside them — the state before D-044's first write, or
   after a data-directory wipe), `guarded`, `tampered` (a recorded filter or the sublayer is gone,
   named in `missing` and in the sentence a user reads), and `unknown`. `needs_elevation` **wins
   over every other answer** — an administrator is the difference between "nothing is there" and
   "I may not look", and a detector that guessed would either cry wolf or claim protection it
   cannot see. Every branch is a unit test, including the two that must never be a tamper.

3. **One alert per change, into the surfaces that already exist.** `should_alert` compares a
   signature (the missing names plus the sublayer) against the last one alerted, so the 30 s poll
   is silent while the state stands and speaks again only when something *else* disappears; a
   `Tampered` report after an `unknown` one is new information and alerts, an `unknown` never
   alerts. The event rides the guard bus as `wfp_tamper`/HIGH with rule id `wfp.tamper`, so it
   lands in the incidents list (title: "MI CS' filtering layer was tampered with: <detail>"), the
   correlator's timeline, and a desktop card with its own copy and its own icon and route — the
   connection list, which is where a block is written and the engine's filtering status is read.
   The alert is the **whole** feature: it never re-creates the object, because silently fighting
   the machine's owner is a worse failure than reporting them.

4. **The poll lives in the guard thread, on its own counter.** `watch::poll()` runs on the guard
   loop's own `watch_ticks` (every 15th 2 s tick, ≈30 s) in **both** the ETW and the poll loop —
   the loop `continue`s early when ETW is live, so a counter at the top is the only place that
   works for both. It is also `fw.wfp.watch`, so a person (or a probe) can ask now. The guard
   thread has no tokio reactor, so `WfpManager::status` was split: `status_blocking()` is the same
   helper-or-BFE decision without a runtime, and both callers share it.

5. **Detect, do not restore, and say what the poll cannot see.** The window is the poll interval:
   a delete-and-re-add inside it is invisible. `unknown` is not "fine" — an unelevated engine with
   no helper genuinely cannot read the BFE (D-042), and the watch reports that rather than an empty
   machine as `guarded`. The record is best-effort by construction: a crash between a successful
   write and its record leaves one filter of ours listed as `extra`, and `extra` is never a tamper.
   A deliberate administrator cleanup and an attacker read as the same sentence; the alert names
   *what* is gone, not *who* removed it.

6. **Two test hooks, both labelled where they can be read.** `MICS_WFP_WATCH_SEED` fills the record
   **only when none exists**, so a machine's real history is never overwritten by a test, and
   `MICS_WFP_WATCH_LIVE` supplies the status to compare against. An injected status appends a note
   naming the hook to the report's `detail` and logs it, so a test's answer can never be mistaken
   for a measurement of the machine — the same discipline D-042's probe follows when it reports
   `needs_elevation` instead of a number.

**Measured on this machine, 2026-11-09** (unelevated, against `engine\target\debug\mics-engine.exe`):

- `cargo test` **190** (180 before): 10 new in `watch` — the five states, the unreadable machine
  that must never be a tamper, the sublayer lost with every filter present, a filter nobody
  recorded counted as `extra`, the once-per-change rule (including "a different loss alerts
  again"), the seed hook filling only an empty record, and the injected status being labelled.
  `cargo clippy --release -- -D warnings` clean, fast tier as one run: **green, 4 of 4, 113.6 s**.
- `scripts\verify-wfp-watch.ps1` (new), five engines on private pipes over their own data
  directories: **PASS, 38 checks, 1 skipped, 0 failed, 4 s**. Part 1 asked the real machine with an
  empty record and got `unknown`, `recorded=0`, `needs_elevation=true` and the running helper's own
  refusal quoted in `detail` (`unknown variant firewall.wfp.status, expected one of ping, version,
  …`) — the installed `MICSHelper` predates D-042, exactly as D-042/D-043 recorded, so the probe
  **skips** its "an elevated shell should have read this" check loud instead of passing it. Part 2
  seeded two names and injected a status holding one: state `tampered`, `missing=["MICS-probe-beta"]`,
  the sentence naming it, `alerted_at` stamped, **an `incident.list` entry titled "filtering layer
  was tampered with" with severity HIGH carrying the filter's name**, and a `WFP tamper:` line in
  the engine's own log marked as injected; a second poll left the state and `alerted_at` identical
  and filed no second incident. Part 3 judged a filter nobody recorded as `guarded` with it listed
  as `extra`, and a missing sublayer as `tampered` with `missing` empty and the sublayer named.
  Part 4 refused a block (no administrator, no helper) and proved the record stayed empty and could
  not turn into a tamper.
- App and harness side: `flutter analyze` clean, **162 tests** (160 before) — 2 new in
  `test\alert_card_test.dart`, that the card's `firewall` kind wears its own icon rather than the
  catch-all bell and opens `/network`; `qa\methods.json` gained `fw.wfp.watch` and the report was
  regenerated (**73 methods, 109 controls**) with the RPC contract re-run against the same binary:
  **87 cases, 0 failed**.

**Measured elevated on 2026-11-09** (same run, fixed debug build):
`scripts\verify-wfp-watch.ps1` **34 checks passed, 1 skipped, 0 failed, 4 s**. Part 1 read the
**real** BFE for the first time — `state=clear recorded=0 live=0 needs_elevation=false`, and
`live=0` is also the independent proof that the four stray filters the 2026-11-08 run left behind
were gone (they were: `scripts\reset-wfp.ps1` removed 4 filters, the sublayer and the provider, see
D-045). Parts 2 and 3 still drive the detector and the alert over an injected status, now in a
shell that can write, and part 4 is skipped there for the same reason (its refusal path is measured
unelevated). The alert path is unchanged and measured: one HIGH incident titled "filtering layer
was tampered with", naming the missing filter, once per change, with the engine's log line and the
injected status labelled as injected.

**Not measured, and this is the experiment that stays open.** No **real** deletion was performed
behind the engine's back: what part 2 proves is the detector, the alert and the once-per-change rule
against an injected status, not a measurement of the machine. The guard thread's own 30 s poll was
not observed firing either — the probe and the contract call `fw.wfp.watch` directly, which is the
same function on a timer. The missing experiment is a **real** removal while the engine watches:
create one filter (the connection list's block button, or `fw.wfp.block`), then take it out of the
BFE **behind the engine's back**, which the engine's own ops cannot do without also clearing the
record — the available route is the helper's `firewall.wfp.unblock`, called on the helper pipe
directly so the engine's bookkeeping is untouched. `scripts\verify-wfp.ps1 -Keep` is *not* that
filter: it keeps the scratch directory, and its teardown unblocks what it created either way, which
is why this experiment still needs its own script or a WFP-API tool.

**Advances** §0.6 row 17 (slice c), which is closed for what it states — a lost filter or sublayer
becomes an incident. **Does not commit us to:** a WFP change subscription, a kernel
callout driver, self-healing re-creation of a deleted filter, attribution of the deletion, watching
anything other than MI CS' own objects, or treating `unknown` as a healthy state anywhere in the
UI.

## D-045 — A filter enumeration names its layer; "every layer" is not a zero GUID

**Status:** accepted (2026-11-09)

**Context.** Everything in D-042 and D-043 was measured from an unelevated shell, where the engine
answers `needs_elevation` and never reaches the Base Filtering Engine. The first **elevated** run of
`scripts\verify-wfp.ps1` (2026-11-08) reached the BFE and found the write path broken:

- `fw.wfp.status` failed with `enumerating MI CS' filters: layer does not exist. (0x80320004)` —
  `FWP_E_LAYER_NOT_FOUND`;
- `fw.wfp.block` failed with the same sentence **after** its filter had been added, because the
  read-back that makes "blocked" a state that was *seen* rather than a call that returned zero
  (D-042) is the step that failed.

The cause is one line. `for_each_ours` built its `FWPM_FILTER_ENUM_TEMPLATE0` as
`providerKey: ours, actionMask: u32::MAX, ..Default::default()`, so `layerKey` stayed the zero GUID.
With the default `FWP_FILTER_ENUM_FULLY_CONTAINED` the BFE resolves that layer *before* it looks at
the provider: a zero GUID is not "every layer of this provider", it is a layer that does not exist.
The type made the mistake invisible — `Default` is legally zeroed, and the intent the line reads as
("the filters of our provider") is not what the API does with it. The same template is used by
`reset`, so before this fix the undo for a stray filter could not run either: `fw.wfp.reset` failed
with the identical sentence (reproduced unelevated through the installed helper on 2026-11-09).

Three instruments read that failure as something other than a failure, which is why it survived a
green `cargo test` and a green unelevated probe run:

1. `verify-wfp.ps1` printed `PASS a refused block carries a reason the UI can show` for a refusal
   that happened in a shell which *could* write, and then skipped the write path — a broken engine
   reading as a working one;
2. `verify-connections.ps1` computed `$writable = -not $statusBefore.result.needs_elevation`; with a
   failed status, `$null.needs_elevation` is `$null` and `-not $null` is `$true`, so it went down the
   write path and then compared `$null -eq $null` as `PASS ... the machine is back where it started`;
3. `verify-wfp-watch.ps1` printed "the block was refused here (no administrator, no helper)" — in an
   elevated shell, asserting the reason instead of printing the one it was given.

**Decision.**

1. **One enumeration per layer, and the layer comes from the list this product installs into.**
   `filter_enum_template(layer)` builds the template — provider, `FWP_FILTER_ENUM_FULLY_CONTAINED`,
   `actionMask: u32::MAX`, and a **real** `layerKey` — and `for_each_ours` calls it once per entry of
   `LAYERS`. Enumerating across layers would need `FWP_FILTER_ENUM_FLAT`, which the `windows` crate
   does not expose; one call per real layer is the same answer with the layers MI CS writes to as the
   only input, so the engine can still only ever report a filter it wrote (D-042).
2. **A provider that is not on the machine yet is an empty answer; a layer that is not on the
   machine is a failure.** `FWP_E_PROVIDER_NOT_FOUND` (and the other "it is not there" codes) remains
   `is_missing`, so a first-time status is `filters=0` rather than an error. `FWP_E_LAYER_NOT_FOUND`
   is deliberately **not** in that set, and a test says so: collapsing the two is how a broken read
   starts looking like a clean machine, which is the exact state the D-044 watch exists to tell apart
   from a healthy one.
3. **The template is a pure function and a test holds the invariant.** The test
   `every_enumeration_template_names_a_real_layer` asserts, for every layer in `LAYERS`, that the
   built template's `layerKey` is that layer, is not zero, carries our provider key and does not mask
   any action. Nothing in it touches the BFE, which is the point: the mistake is in the template, and
   the template is pure.
4. **The instruments say what happened.** `verify-wfp.ps1` now *fails* a refusal in a shell that can
   write, with the reason printed; `verify-connections.ps1` treats an unreadable status as
   "not exercised" and skips instead of passing on two nulls; `verify-wfp-watch.ps1` prints the
   refusal it was given and fails it when the shell could write. A probe that reports a broken write
   path as a passing refusal is worse than no probe.
5. **Cleanup is a state a crashed run can need, so it has a script.**
   `scripts\reset-wfp.ps1` starts an engine against the app's own data directory, removes MI CS' own
   filters, sublayer and provider through `fw.wfp.reset`, and reads the machine back — including
   that the reset cleared the D-044 record, so a cleanup cannot read as a tamper. It is deliberately
   honest about an unreadable machine: `filters=0` from a shell that could not read the BFE is
   reported as *unmeasured*, not as "nothing is left".

**Measured on this machine, 2026-11-09.** `cargo test` **192** (190 before): the two new tests above.
`cargo clippy --release -- -D warnings` clean, and the fast tier as one run: **green, 4 of 4,
68.8 s** (the QA report is byte-gated by `test\qa_report_test.dart` and declares the engine test
count, so it had to be regenerated to say 192 — the one place a test count is a checked artifact).
The debug build now carries the fix
(`engine\target\debug\mics-engine.exe`). `scripts\reset-wfp.ps1` end to end, unelevated, against the
**installed** helper (a release build that predates the fix): `fw.wfp.reset` is refused with
`enumerating MI CS' filters: The layer does not exist. (0x80320004)` — the bug reproduced through a
second caller — while the script's own path is exercised: `fw.wfp.status` answered, the machine
reported unreadable and the cleanup **unmeasured** rather than "clean", and `fw.wfp.watch` answered
`unknown`, `recorded=0`.

**Verified against the real Base Filtering Engine the same day.** The elevated re-run §0 item 7
asked for happened on 2026-11-09 with the fixed debug build, and the bug is gone: `fw.wfp.status`,
`fw.wfp.block` and `fw.wfp.reset` all answered from the BFE. The numbers, in the order the run
prescribes: `scripts\reset-wfp.ps1` **7 checks passed, 0 skipped, 0 failed, 1 s** — and it found what
it exists for: `before: sublayer=True filters=4` naming four of our own filters
(`MICS-mics-engine.exe port 65001 protocol 6 probe` twice and the same at port 65002), so the
2026-11-08 teardown had indeed left the machine dirty; `removed: 6` (four filters, the sublayer and
the provider), `after: filters=0 sublayer=False`, and `watch: state=clear recorded=0` — the cleanup
did not leave a tamper behind. Then `verify-wfp.ps1` **16 passed, 2 skipped, 0 failed, 5 s**,
`verify-connections.ps1` **24 passed, 0 skipped, 0 failed, 6 s** and `verify-wfp-watch.ps1`
**34 passed, 1 skipped, 0 failed, 4 s**, whose part 1 read the real BFE
(`state=clear recorded=0 live=0`) — `live=0` being the second proof that no filter of ours was left
anywhere. The three checks the 2026-11-08 run reported as PASS while nothing could be written now
report the reason they are skipped, and the one that was a FAIL was a FAIL for the right reason.

**Not measured.** The D-045 fix itself is now measured (above); what stays open belongs to the
slices, not to this bug: the *enforcement effect* of a filter on a live connection, its survival
across a reboot, our sublayer's weight against a built-in permit rule (D-042), and a **real**
deletion behind the engine's back (D-044). One instrument limit is recorded rather than fixed:
`netsh wfp show state` produced no XML on this machine, so the `show filters` comparison is what
carried the action evidence — the skip now quotes netsh's own exit code and answer (commit
`4709011`), which is why the next run will say *why* instead of only *that*. A second one: the
installed `MICSHelper` is still a release build from before this fix, so the **app's own unelevated**
write path still answers `0x80320004` until the helper is reinstalled from a fixed build
(`engine\target\debug\mics-engine.exe install-helper` in an elevated shell, which also unlocks the
release exe for the next `cargo build --release`).

**Advances** §0.6 row 17 (slice a's elevated path, and the honesty of its probes), which is closed
with the slices. **Does not commit
us to:** enumerating layers MI CS does not write to, `FWP_FILTER_ENUM_FLAT` (unavailable in the
bindings), treating a failed read as an empty machine anywhere, or a probe that reports a broken
write path as a passing refusal.

## D-046 — The update feed has a compiled-in default, one implementation, and an answer that names it

**Status:** accepted (2026-11-09)

**Context.** `update.check` read `settings.update_manifest_url`, which starts empty, and answered
`disabled` — so the Updates section of Settings shipped a *Check now* button that could not do
anything until its owner found, typed and trusted a URL, and `update.download` / `update.apply`
behind it were unreachable the same way. §0.6 row 5 (هـ1) is the self-update path; a check that only
works after hand-configuration is not one. Three facts shaped what follows:

- the engine already parses exactly the manifest `scripts\make-release.ps1`'s contract names
  (`{version, url, sha256, size, notes_en, notes_ar}`) and refuses a download whose SHA-256 does not
  match before it stages anything (`engine/src/update.rs`), so there was no fetcher to design — only a
  URL to choose;
- **nothing polls it.** `update.check` is reached from one dispatcher arm and from
  `download_and_verify`, and the auto-sync scheduler's `run_due` covers the intel sources only. So
  *when* traffic happens is the user's button and nothing else;
- the channel (`stable`/`beta`) was already a real setting that nothing read.

**Decision.**

1. **The channel carries a URL.** `DEFAULT_UPDATE_MANIFEST_URL_STABLE` is
   `https://github.com/ibraimfarag/MIF/releases/latest/download/update.json`; the beta feed is
   `…/releases/download/beta/update.json` — the rolling `beta` tag's release, the one place a
   newer-than-stable build can live without becoming "latest". `default_update_manifest_url(channel)`
   maps everything but `beta` to stable, the same rule `settings.set` applies to the channel.
2. **Resolution is ordered and pure.** `resolve_update_url(env, setting, channel)`:
   `MICS_UPDATE_MANIFEST_URL` wins when the environment sets it, then a URL the user saved, then the
   channel's default. Keeping that order in a function that does not read the environment itself is
   what lets the tests be about the order instead of about the machine they run on.
3. **"Do not check" is `off`, not empty.** `MICS_UPDATE_MANIFEST_URL=off` (any case) is the single
   explicit do-not-check value (`update_checks_disabled`); an empty environment value counts too where
   a platform can carry one — Windows *deletes* a variable set to `""`, which is why a word is the
   sentinel. It is deliberately environment-only: `check_url` keeps refusing anything that is not a
   URL, so a typo in the field can never switch updates off quietly.
4. **One implementation.** `SyncManager::check_update` is deleted; `update.check` calls
   `crate::update::check()`, the same function `download_and_verify` already used, so the screen, the
   downloader and the prober cannot disagree about what "latest" means.
5. **The answer names the feed.** `check()` reports `manifest_url`, and the Updates panel prints it
   under the button in mono. An update answer that does not say who gave it cannot be checked by the
   person reading it.
6. **The release lane publishes the manifest the default reads.** `scripts\update-manifest.ps1` writes
   `dist\update.json` from the archive *after* the zip and `SHA256SUMS` exist (step 9 of
   `make-release.ps1`): the asset URL is built from version and arch rather than discovered, the file
   is UTF-8 without a BOM, and the script re-reads its own output field by field to prove it describes
   that zip. The Release workflow uploads it with the other assets, so the stable default begins to
   answer the moment the v0.1.0 draft is published (§0.6 row 1) — and answers 404, in the UI's own
   error text, until then.

**Measured** (2026-11-09, unelevated shell, debug engine built from this commit):

- `scripts\verify-update.ps1` **18 passed, 0 skipped, 0 failed, 4 s**, run twice — once with no
  arguments, so the probe picked its own binary, and once with `-EngineExe
  engine\target\debug\mics-engine.exe`. The manifest is served by the
  probe itself on `127.0.0.1` over a raw `TcpListener`, so the run needs no network: `=off` answers
  `disabled` with a reason and names no feed; a saved loopback feed is fetched and answers `available`
  with `latest=9.9.9` and `manifest_url`, `sha256` and `download_url` carried through; the download the
  manifest names is really fetched, is staged under the data directory and hashes to what the manifest
  promised; a manifest whose `sha256` is 64 zeros is refused with `SHA256 mismatch: expected 000…,
  got 0f69…` and leaves no `update.zip`; `http://example.com/update.json` is refused by `settings.set`
  with "must use https:// (http:// is only accepted for loopback: 127.0.0.1, ::1 or localhost)", and
  the refused patch leaves the previous feed in place.
  Running it is also how two false readings were caught, and both are now guards rather than notes: the
  probe used to take the first binary that *exists*, and a leftover `release` build answered as if the
  feature were missing — **14 passed, 2 failed**, both failures being "switched off" and "echoes the
  feed that answered". It now picks the **newest** of the two outputs, and refuses to run at all when
  the one it has predates `engine\src` (**measured**: passing the stale release binary exits 1 with
  `RESULT: FAIL - ... predates engine\src\settings.rs; build the engine or pass -EngineExe`). A stale
  binary reads exactly like a defect, which is D-045's lesson.
- `scripts\update-manifest.ps1` — the happy path plus three refusals, measured against the real
  `dist\MICS-portable-0.1.0-x64.zip`: it wrote `size 22552651` and `sha256
  8f27ad587efa450eae3f428c0641b8a16ea4616d77e31b5ae0106a43054fb37a` with the asset URL **built** from
  version and arch (`.../releases/download/v0.1.0/MICS-portable-0.1.0-x64.zip`), re-read the file and
  compared `version`/`url`/`sha256`/`size`, and left it UTF-8 with no BOM (`{`, LF, space as the first
  three bytes). Each of these was refused with exit 1 and nothing written: an archive named for another
  arch (`probe-MICS-portable-9.9.9-x64.zip`), `-Version beta`, and a missing archive.
- `scripts\pipeline.ps1` gained the step `update.verify` (**full** tier — 13 steps across 3 tiers now),
  so the probe runs in the same tier and the same shape as the other live probes instead of only when a
  human remembers it; it passes `-EngineExe` from `CARGO_TARGET_DIR` the way `engine.lifecycle` does.
- `cargo test settings::` **10 passed**, including the two new cases: the compiled-in defaults pass the
  same gate a typed URL does (https, not loopback, `check_url` accepts them, the two channels differ),
  and the resolution order — environment over setting over default — with `off` and `""` disabling and
  `"  https://mirror.test/u.json  "` trimmed.
- The four gates, all four green in this working tree: `cargo test` **194 passed, 0 failed** (192
  before), `cargo clippy --release -- -D warnings` exit 0, `flutter analyze --no-pub` "No issues
  found!", `flutter test --no-pub` **162 passed**. Two gates were regenerated to keep their ratchets
  honest: `qa/report.md`/`.html` (192 → 194 engine cases in 25 modules, and the new pipeline step) and
  `qa/ui/ledger.json` (the settings field whose hint became a translated key — same one control, new
  signature `TextField(empty = MI CS' own release feed)`).

**Not measured, and open.** No run in this repository fetches the compiled-in default: `releases/latest`
serves **published** releases, v0.1.0 is still a draft, and a probe that reached github.com would make
its result depend on the network and on a release that does not exist yet. What the measurements above
support is the wiring, the refusals and the staging — not "the feed answered". What that leaves:

- **nothing verifies a signature over the manifest.** The `sha256` in a manifest describes the file the
  same manifest points at, so it catches a truncated or corrupted transfer, not a hostile feed; today
  the only thing standing behind a manifest is the TLS connection that carried it. That is هـ1's second
  half (a detached signature beside `update.json`, checked against a key shipped in the engine), and it
  wants the thumbprint pin that arrives with any certificate (D-016);
- `notes_ar` is carried and never shown: the Updates panel reads `notes_en` only, and the app has no
  locale accessor (`languageCode` appears nowhere in `lib\`). The release lane ships no Arabic notes
  either — scripts here are ASCII — so the honest fix is the existing translation-debt row, not a
  machine translation;
- `update.apply` still ends in a restart the *app* performs, and the extraction of a **real** signed zip
  is exercised by the release gate (`verify-release.ps1`), which this decision does not touch.

**Advances** §0.6 row 5 (slice 1: the compiled-in default, the single implementation and the named
feed) and §7's هـ1. **Does not commit us to:** an update that installs itself, an automatic poll of any
kind, a beta release that does not exist yet (the beta feed answers 404, and the panel says so until a
release is published under that tag), trusting a manifest because it arrived over https, or a second
manifest format for the installer — `update.apply` replaces a portable folder, so the manifest
describes the zip and nothing else.

## D-047 — The update manifest is signed, and the engine refuses one that is not

**Status:** accepted (2026-11-09)

**Context.** D-046 gave the update path a compiled-in feed and closed with its own honest gap: "nothing
verifies a signature over the manifest. The `sha256` in a manifest describes the file the same manifest
points at, so it catches a truncated or corrupted transfer, not a hostile feed; today the only thing
standing behind a manifest is the TLS connection that carried it." That is §0.6 row 5's second half
(هـ1), and it is not a small gap: `releases/latest/download/update.json` is served to every install
from a GitHub release, and a manifest is a *version, a URL and a hash* — whoever controls those bytes
decides what a machine downloads and, through `update.apply`, what it unpacks over its own folder. Four
facts shaped this entry:

- **there is already a signing identity with a rule about it.** D-016 signs the engine and refuses to
  call a self-signed result verified; `engine/src/platform/windows/signature.rs` already verifies an
  Authenticode signature and reads the signer (`verify_embedded`, `SignerInfo`). What was missing was a
  *detached* signature — a document is not a PE, and signtool will not sign one;
- **the pin D-046 deferred to is the one D-016 already uses**: the certificate the project signs with,
  which the shipped engine carries as its own signature. So `MICS_UPDATE_SIGNER_THUMBPRINT` is the test
  hook for the same check, not a second trust model;
- **the engine must not trust a chain it cannot check.** A self-signed development certificate is what
  this project has today (§0.6 row 3, ب5): `CryptVerifyDetachedMessageSignature` with
  `X509_ASN_ENCODING | PKCS_7_ASN_ENCODING` verifies the *signature* and hands back the signer, while
  `WinVerifyTrust`-style chain building would refuse it — measured below;
- **a feed that cannot be checked is worse than no feed**, because the compiled-in default points at it
  and the failure would be silent.

**Decision.**

1. **The signature is detached and beside the manifest**: `update.json.sig`, the manifest's own URL plus
   `.sig`, with a query string or fragment left where it is. The manifest format does not change — it
   still carries only `{version, url, sha256, size, notes_en, notes_ar}` — and a feed that publishes
   `update.json` says nothing about its own signature. `<file>.sig` is also what the release lane
   already writes for data (`scripts\sign.ps1 -DataFile`), so one naming rule covers both ends.
2. **PKCS#7 detached, SHA-256, certificate included (`EndCertOnly`), no chain trust.** Exactly what
   `SignedCms.ComputeSignature` produces with a `CmsSigner`, which is the same shape OSSign and the
   Authenticode lane produce; `verify_detached` in `signature.rs` calls
   `CryptVerifyDetachedMessageSignature` with the message withdrawn (detached), so nothing has to
   re-encode the bytes that were signed.
3. **Verified before parsing, and the reason is specific.** `crate::update::check()` fetches the
   manifest's bytes (`SyncManager::fetch_bytes`, new), fetches the signature, verifies it over those
   bytes, and only then runs `serde_json::from_slice`. A missing signature, a signature by another key,
   or a signature that does not verify are three different refusals with their own text; "the fetch
   returned 404" is kept as the cause of the first, so an unpublished feed is readable as itself.
4. **The signer is pinned, and the answer says which check happened.** `pinned_update_thumbprint()` is
   `MICS_UPDATE_SIGNER_THUMBPRINT` if the environment sets it (the only way a probe can test a
   certificate it minted seconds ago, AGENTS.md rule 5), else the thumbprint of the certificate over the
   running engine, else `None`. With a pin, the signer's thumbprint must equal it. With no pin — a
   `cargo build` has none — the signature must still verify *and* the signer's name must be the release
   name, and the answer reports `pinned: false` rather than the same `true` a release would report.
   `update.check` now answers with `signature`, `signer`, `signer_thumbprint` and `pinned` beside the
   fields it already carried: an update answer has to be checkable by the person reading it (D-046).
5. **The release lane signs with the identity that signed the binaries, and reads its own signature
   back.** `scripts\sign.ps1` gained `-DataFile`/`-DataSignature` — the same script, so there is one
   place that decides what "the release key" means — and `make-release.ps1` step 9b signs
   `dist\update.json` with the `@signArgs` identity resolved at the top of the run, then proves the
   bytes on disk decode, verify, and carry that identity's thumbprint. A build with no signing identity
   prints that its feed is unsigned and why a shipped engine would refuse it, instead of shipping a
   manifest that only looks publishable. The Release workflow uploads `dist/update.json.sig` with the
   other assets (`if-no-files-found: error`), and the release notes name it.
6. **Three corrections from checking, not from assuming.**
   - The `Release` workflow handed `secrets.MICS_PFX` to `env: MICS_PFX`, but `make-release.ps1` reads
     `MICS_PFX_B64` (D-034's order: `MICS_CERT_THUMBPRINT`, then `MICS_PFX_B64` + `MICS_PFX_PASSWORD`,
     then `MICS_PFX_PATH` + `MICS_PFX_PASSWORD`, then self-signed). A donated certificate would have
     been ignored and the release silently self-signed — which this decision makes more expensive,
     because the *feed* would then be pinned to a self-signed key. Both legs now pass the secret's value
     to the variable the script reads; the secret keeps its name.
   - `scripts\verify-update.ps1` grew the four refusals *and* the two acceptances around them, and its
     part 8 is a `SKIP` with a reason on a signed engine rather than a silent pass: the name fallback
     can only be reached by an engine that carries no signature of its own.
   - `docs/THREAT-MODEL.md` said twice that `update.apply` "never calls `WinVerifyTrust` on the extracted
     binary" and that the payload half of F-3 was therefore open. It does call it: `apply()` runs
     `signature::require_signed_by` over each extracted `mics-engine.exe` / `mics_app.exe`, which is
     `WinVerifyTrust` plus `CN=MI CS Code Signing` (D-016). The claim had been stale since that check
     landed. So F-3's remaining payload gap is narrower and different in kind — the check is a *subject
     name*, not a thumbprint, so a certificate bearing that CN from any trusted CA would pass. That is
     what this entry's pin does not fix, and the row and §B6/§B7 now say so.

**Measured** (2026-11-09, unelevated shell, debug engine built from this commit, no network):

- `scripts\verify-update.ps1` **45 passed, 0 skipped, 0 failed, 8 s** (was 18 checks for slice 1; a run
  against a *signed* engine reports part 8's five checks as one `SKIP` with its reason instead, because
  that branch needs an engine carrying no signature of its own to reach the name fallback). The
  feed is served by the probe on `127.0.0.1`; both signing identities are minted in memory by the probe
  (`CertificateRequest.CreateSelfSigned`) and never touch a certificate store. Proven accepted: a
  manifest with `update.json.sig` beside it loads, answers `available`, `signature: verified`,
  `signer: MI CS Code Signing`, `signer_thumbprint` equal to the pin, `pinned: true`, and the download
  it names is staged and hashes to what the manifest promised. Proven refused, each with nothing staged:
  no signature at all ("publishes no signature at ... refuses an update manifest nothing signed"),
  another key's signature (naming both the signer's thumbprint and the pin), a body changed after
  signing ("the manifest ... was refused: the detached signature over it does not verify"), the honest
  feed under the wrong pin, and — in the branch the probe runs only on an unsigned engine — a signature
  under another *name* with no pin. A correctly signed manifest whose `sha256` is 64 zeros is still read
  and still refused by the hash check ("SHA256 mismatch"), which is the point: the signature did not
  replace the hash. The skip is part 8 on a signed engine, with the reason printed.
- **The engine accepts what the release lane actually produces.** One throwaway run (not committed) fed
  the engine an `update.json` that `scripts\sign.ps1 -SelfSigned -DataFile` had just signed, with
  `MICS_UPDATE_SIGNER_THUMBPRINT` set to that certificate: `update.check` answered
  `signature: verified`, `signer: MI CS Code Signing`, `pinned: true`, thumbprint `9488d80e…`. This is
  the join the row asks for — the same key that signs the binaries signs the feed, and the engine
  verifies that signature — proved without minting a certificate into a store.
- `cargo test` **6 new cases**: 3 in `update.rs` (the `.sig` URL rule including query and
  fragment, the pin deciding and refusing with both thumbprints named, the no-pin fallback
  accepting the release name and refusing a stranger's) and 3 in `signature.rs`
  (`a_real_detached_signature_verifies_over_exactly_those_bytes` — a committed fixture,
  `engine/tests/data/`, signed with a throwaway key whose private half was not kept, so
  the success path is covered by the gate that always runs rather than only by the probe;
  a blob that is not a signature at all, an empty one, and a PKCS#7 header with nothing
  behind it; and the thumbprint pin's normalisation and refusal). A changed byte and a
  wrong pin are refusals with their own text, not a generic error.
- The four gates, all four green in this working tree: `cargo test` **200 passed, 0 failed**
  (194 before), `cargo clippy --release -- -D warnings` exit 0, `flutter analyze --no-pub`
  "No issues found!", `flutter test --no-pub` **162 passed**.

**Not measured, and open.** Nothing here fetches the published feed: `releases/latest` serves
*published* releases, v0.1.0 is a draft, and a probe that reached github.com would depend on the
network (D-046's limit, unchanged). Concretely:

- **the pin is only as trustworthy as the release it came from, and a self-signed release pins a
  self-signed feed.** `pinned_update_thumbprint` reads the certificate over the running engine, so a
  build signed with the throwaway development certificate pins *that* certificate — it proves the feed
  came from whoever built this engine, which is the honest claim, not "a stranger can verify it". A real
  CA certificate (§0.6 row 3, ب5) is what makes the same sentence checkable by someone else, and the
  feed's own signature is what makes a *donation* of that certificate reach the update path;
- **an attacker who can replace the engine binary can replace the pin with it.** This is Authenticode's
  own limit, not a new one: the manifest signature is checked by a process that trusts its own file, and
  `verify-tamper.ps1` plus D-016's refusal to call a self-signed result verified are what stand in front
  of that;
- **nothing verifies `update.json.sig` at publish time in CI** beyond `make-release.ps1` reading its own
  bytes back on the runner that wrote them: the workflow uploads the asset and the release gate
  (`verify-release.ps1`) does not reach into a downloaded feed, because doing so would need the
  certificate this run used;
- **keyless signing (OSSign, D-036 route B) has no detached-CMS story here.** OSSign signs over OIDC
  with a transparency log, so its signature would be verified by `cosign`/`sigstore`, not by
  `CryptVerifyDetachedMessageSignature` — a different verifier and a different pin, and one to design
  when that route is actually eligible (~2027-04-27) rather than guessed at now.

**Advances** §0.6 row 5 (slice 2: a signature over the manifest, verified before parsing, with the D-016
thumbprint pin) and §7's هـ1, and closes the "nothing verifies a signature over the manifest" bullet
D-046 left open. **Does not commit us to:** a second trust store, trusting a signature because it
verified (the pin decides), a revocation check, a timestamp authority for the manifest, signing the
*installer* with the same lane (it publishes no feed), or verifying the feed from CI.

## D-048 — The guard says what it does not check, and the surface carries the fact

**Status:** accepted (2026-11-10)

**Context.** `guard::etw::start` opened the store, read `dump_ioc_hashes()` into a `HashMap` on every
guard start, and then discarded it (`let _ = ioc_hashes;`) — and the comment that justified the waste
was **false**: "There is no scan scheduler yet, so this is not a safety net." A scan scheduler landed
with **D-027** on 2026-11-03. The limit itself is real and deliberate (hashing every process creation
was judged too hot), but it lived in two places that disagreed — a comment a reader could not trust,
and `PROTECTION-MATRIX.md` §4.1, which stated it correctly — so the *documentation* had drifted from
the code in the direction that hides coverage rather than the direction that invents it. D-032 set the
precedent for the canary half of the same subsystem: a limit that matters gets a verdict on the
surface, not an implication of coverage.

**Decision.** The process-start path does **not** hash the image, and that is a **fact in one
function** the surface reports:

1. **One fact, one place.** `guard::ioc_hash_coverage()` answers
   `{hash_checked_at_process_start: false, reason: "hashing every process image at start was judged
   too hot; the scan job checks file hashes (D-027)"}`. It is the only place in the code that states
   the limit; the ETW callback's comment points at it rather than restating it, so the two cannot
   drift apart again.
2. **The surface carries it.** `guard.status` returns it under `ioc`, beside `canaries`, in the idiom
   D-032 established. The guard screen reads only `running` and `rules`, so this is additive and
   breaks no client; `guard.status`'s registered result is `object`, so the contract is unchanged.
3. **The dead load and the false sentence are deleted.** The callback no longer opens the store for a
   list it does not use, `Storage` is no longer imported there, and "there is no scan scheduler yet" is
   removed rather than reworded — the scan job owns the hash dimension, scheduled or manual.
4. **A test pins it.** `engine/src/tests.rs::the_guard_status_states_that_process_start_does_not_hash`
   fails if the fact flips or if the reason stops naming where the hash dimension actually lives, so
   turning hashing on at start means changing this fact, the test and §4.1 — not just a comment.

**Measured** (2026-11-10, unelevated shell, no network, no machine changes): `scripts\pipeline.ps1
-Tier fast` **green, 4 of 4** — **74.7 s** on the first green run (`flutter.analyze` 17.3 s,
`flutter.test` 37.3 s, `engine.test` 8.3 s, `engine.clippy` 11.8 s) and **57.6 s** on the re-run of
the frozen tree, with `engine.clippy` cached (2.3 s) — and `cargo test` at **201 passed / 0 failed**.
The first
attempt failed `qa_report_test`, which is the gate doing its job rather than a defect: one new engine
case moves the report's per-file count (`engine/src/tests.rs` 55 → 56, total 200 → 201), and the
regenerated `qa/report.md`/`qa/report.html` are in this commit. Nothing here is a probe: no elevation,
no firewall, no file outside the repository.

**Not measured, and open.** The cost of hashing a process image at start is still a **judgement, not a
number** — nothing here measures it against a real process-start rate, which is why the reason string
states the judgement instead of quoting a figure. A machine that wants hash-at-start would have to
measure that first, and the measurement needs an elevated ETW session to see real process starts, so
it is out of reach of this unelevated run. The row stays *closed* because its actual defect was the
dead load and the untrue comment, not the deliberate limit.

**Advances** §7's LOW row (the guard's ETW callback loads the IOC hash list and never uses it) and
`PROTECTION-MATRIX.md` §4.1. **Does not commit us to:** hashing at process start, a second or key-free
hash feed (that row stays open and needs an external source), a minifilter for file events, feeding
the guard's rules from the IOC list, or any change to the poll fallback — unelevated, that path is
unchanged.

## D-049 — A language tag no pack can render falls back to English, and says which tag

**Status:** accepted (2026-11-10)

**Context.** `settings.set lang=de` is accepted and persisted **on purpose** — the engine must not need
a release per language, so `lang` is a validated language tag and not a name checked against a list —
and the UI turned that tag into a language with `AppLang.byCode(code) ?? AppLang.ar`. That fallback is
the one language the frame must not be in: `lookup` already falls back to **English per key**, so `de`
produced an Arabic layout — right-to-left, Arabic labels — with every key that pack is missing left in
English, and nothing on screen said a word about it. The picker cannot produce such a tag (it offers
`AppLang.all`), but a hand-edited `settings.json` and an external RPC caller both can, and both are
supported ways in. §7 carried it as a LOW row naming exactly that expression.

**Decision.** The chain ends where the key-level chain already ends, and the fact is shown:

1. **One resolver decides, and it ends in English.** `AppLang.resolve(code)` returns the bundled pack
   for a bundled tag (regional tags through their primary subtag, as `byCode` always did), **Arabic** for
   an absent or empty code — the engine's own default, not a guess — and **English** for a tag no pack
   answers to, because that is the language a missing *key* already falls back to. `AppSettings.lang` is
   a *rendering* fact now rather than a copy of the stored string, so the frame is one language.
2. **The stored tag is carried instead of lost.** `AppSettings` keeps it (`storedLangTag`; `null` in the
   constructor means "same as `lang`", which keeps a hand-built object coherent) and `toEngineJson`
   writes **it**, not `lang.code`. Without that, the next settings write — a theme change, anything —
   would replace a hand-edited tag with the fallback's code: silent data loss in the one direction that
   cannot be undone.
3. **The screen says which tag.** When no pack answers to it, Settings prints one line under the
   language picker naming the tag (`settings.languageMissing`, `{tag}` substituted), so the user is told
   why the product is not in the language the file asks for, and that the picker is the way out. That
   line is English in practice — an unrenderable tag is exactly the case that renders English — and the
   key still exists in every pack, because the parity test requires it and a pack that *can* render the
   tag is the only thing that makes the notice unnecessary rather than missing.
4. **Tests pin all three.** Four cases in `test/settings_model_test.dart` (a tag with no pack renders
   English and reports the tag; `ar`/`en`/`en-GB`/`EN` are not "missing"; an absent tag is the engine's
   Arabic and *not* a missing pack; a write sends the stored tag back) and one in
   `test/ui_screens_test.dart` that mounts Settings against a fake engine holding `de` — the new
   `FakeEngine(initialLang:)` exists for this, because the interesting tag is the one the picker cannot
   offer — asserts the English pack, the tag named on screen and `rtlProvider` false, then picks العربية
   and watches both the notice and the tag go.

**Measured** (2026-11-10, unelevated shell, no network, no machine changes): `scripts\pipeline.ps1
-Tier fast` **green, 4 of 4 — 69.6 s** on the first green run (`flutter.analyze` 17.8 s,
`flutter.test` 40.5 s, `engine.test` 8.8 s, `engine.clippy` 2.5 s) and **59.2 s** on the re-run of the
frozen tree, with `flutter test` at **172 passed** (5 of them new) and the engine at
**201 passed / 0 failed**. The first attempt failed `qa_report_test`, which is the gate doing its job
rather than a defect: five new Dart cases move the report's counts (137 → **142** declared cases,
`test/settings_model_test.dart` 6 → 10 and `test/ui_screens_test.dart` 10 → 11), and the regenerated
`qa/report.md`/`qa/report.html` are in this commit. The two cases that assert the *rendering* were also
run with the resolver put back to the pre-D-049 fallback: exactly those two fail, which is what makes
them a pin rather than a description.

**Not measured, and open.** Nothing here runs against a real `%PROGRAMDATA%\MICS\settings.json` edited
by hand: the widget test drives the fake engine and the model cases drive `fromEngineJson` directly,
which is the code path the settings notifier uses but not the file on disk. The wording is also a guess
at the reader's situation — no user has been watched reading it. What is decided is where the chain
ends, that the stored tag survives, and that the tag is named.

**Advances** §7's LOW row (the engine stores a language tag the UI cannot render) — closed.
**Does not commit us to:** validating `lang` in the engine against a list of shipped languages (the
engine must not need a release per language), a second or third bundled pack, packaging languages so one
can be installed at run time, or translating the notice into the language that is missing.

---

## D-050 — A pack that did not load is a fact: one line in the log, and the language named in Settings

**Status:** accepted (2026-11-10)

**Context.** §7's LOW row: a language folder `pubspec.yaml` does not declare renders every key raw, and
silently. `I18nLoader` catches every failed asset read on purpose — a module nobody has translated yet
must not break the app — and a *whole* folder takes the same path: a language the picker offers, whose
pack loads as an empty table, is indistinguishable from a language nobody has translated, because
`lookup` falls back per key and never complains. The repository cannot ship one
(`test/lang_registry_test.dart` fails and `lib/main.dart` gates the first frame on the packs ever having
a value, so a build that lost a folder never starts), but a *built* app has no such gate: it degrades
quietly, `dashboard.title` on screen, with nothing anywhere to explain it.
What the row left open was therefore the **report** rather than the failure, and the reason it left it
open is the reason it cannot be a failure: throwing would replace a degraded UI with none at all,
because that same first-frame gate would then wait forever.

**Decision.** The swallow is classified instead of silent, and the fact reaches both places it can.

- `I18nLoader.build` collects one `PackLoad(code, modules, failed, firstFailure)` per language, and
  `i18nPackLoadNote` turns it into **one** line — or `null` when that language loaded completely, so a
  correct build stays quiet. One line per language that lost anything, never one per module.
- The two cases are worded apart, because only one of them is a defect: a folder the asset list does not
  carry says `no pack loaded for "en" - assets/i18n/en/ is not in the asset list (see pubspec.yaml
  "assets:")`, an unread module says `N of M module(s) did not load ... (first: <path>)`, and the
  tolerance stays for that second kind.
- The reader and the sink are both injectable
  (`I18nLoader({PackReader? read, void Function(String)? log})`, defaults `rootBundle.loadString` and
  `stderr.writeln`), so a test can refuse an asset exactly the way the bundle does and read the line
  back rather than scrape a process's `stderr`. `I18nLoader.loads` keeps the classification visible for
  the same reason.
- The screen reads the *fact*, not the log: this is a Windows GUI app, and `stderr` exists only when a
  console is attached (`windows/runner/main.cpp` attaches to a parent console; a Start-menu launch has
  none). `packLoaded(tables, code)` therefore feeds one line under the language picker
  (`settings.languagePackMissing`, `{language}` filled from `AppLang.nativeName` — the same script-safe
  choice D-049 made in the picker). It sits beside D-049's notice and answers a different question: that
  one is about the stored **tag**, this one about the **build**.
- `i18nModules` gained the check it never had: every entry is a file every language ships, in **both**
  directions (`test/lang_registry_test.dart`). The list carried a stale `about` entry, so every start of
  every language read a file that was not there — the entry is gone (the About surface's copy lives with
  `settings`) and the first run of the new tests is what found it. `assets/i18n/README.md` now names the
  `pubspec.yaml` step it used to leave implicit, which is how the defect was reachable at all.

**Why.** Reporting beats failing for one mechanical reason: `lib/main.dart` gates the first frame on
`i18nProvider` ever having a value, so an exception in the loader is a splash that never ends — a broken
language would take the whole app with it. Reporting beats *not* reporting for the row's reason: a user
reading `dashboard.title` had nothing to read and a developer had nothing to grep. `stderr` alone is not
enough either, hence the screen: the log is for whoever is looking, the sentence for whoever is not.

**Measured** (2026-11-10, unelevated shell, no network, no machine changes): `scripts\pipeline.ps1
-Tier fast` **green, 4 of 4 — 65.0 s** (`flutter.analyze` 17.9 s, `flutter.test` 32.2 s,
`engine.test` 12.3 s, `engine.clippy` 2.6 s), with `flutter test` at **178 passed, 6 of them new**, and
the engine untouched at **201 passed / 0 failed**. The new cases: four in `test/i18n_pack_load_test.dart`
— the first reads the **real** bundle through the loader the app builds, and a correct build must load a
pack for every bundled language and log *nothing* — one in `test/ui_screens_test.dart`, and one in
`test/lang_registry_test.dart`. The first attempt failed `qa_report_test`, the gate doing its job rather
than a defect: six Dart cases move the report's counts (142 → **148** declared cases, 29 → 30 files), and
the regenerated `qa/report.md`/`qa/report.html` are in this commit. Both halves were then re-run with the
fix reverted: with the log call silenced exactly the two log cases fail, and with the screen line removed
the widget case fails (`Found 0 widgets`) — the difference between a pin and a description.

**Not measured, and open.** No real broken build was run: the demonstration is the loader reading the
real bundle *inside* `flutter test` with a reader that refuses one folder, which is the same code path
the app runs but not the same artifact, and nothing checks that the shipped installer's asset list
carries both folders (`scripts\verify-installer.ps1` counts files; it does not ask the loader). No user
has been watched reading the Settings sentence, so its wording is a guess at their situation. A module
that fails to load still reaches no screen at all, deliberately — the log is the only place a partial
pack is visible.

**Advances** §7's LOW row (a language folder `pubspec.yaml` does not declare) — closed, and the
`i18nModules` drift it was hiding with it. **Does not commit us to:** making a failed pack a startup
error, disabling the picker for a language whose pack is empty, a second source of truth about which
languages are reachable, or a pack loader that can reload without a restart.

---

## D-051 — The pin is a certificate, not a name: the thumbprint of the engine's own signer, and the release CN only where there is no signature of its own

**Status:** accepted (2026-11-11).

**Context.** §7's LOW row ("the update pin is the signer's subject name, not its thumbprint") is
D-016's residual, and `docs/OPEN-DECISIONS.md` item 3 had already been asking the same question with
the same recommendation. Two measurements turn it from a preference into a defect:

- **No CA will ever issue the CN the pin compares.** CA/B CSCBR §9.2.2 requires
  `subject:commonName` to be the verified legal name, measured 2026-11-06 (the row and item 3 carry
  the finding). `MI CS Code Signing` exists only in the certificate
  `scripts\codesign-cert.ps1` creates locally, so the day ب5's certificate exists the name check
  stops matching — and the place it breaks is the worst one: `update.rs`'s payload check, run over
  the two binaries of an update archive, would refuse the release **it is part of** ("signed by X,
  not MI CS Code Signing") and the package self-check would report the engine as a foreign signer on
  its own machine.
- **A thumbprint alone is the mirror-image fault.** The local certificate is re-issued whenever
  `codesign-cert.ps1` runs, and a re-issued certificate is a new thumbprint; every acceptance run
  after that would refuse its own engine.

Which is why the row wrote its own fix down: **thumbprint when there is one to pin, the release CN
otherwise**, and every check that used to compare a name compares the pin instead.

**Decision.** One value, `signature::Pin` — `Pin::Thumbprint(hex)` or `Pin::Name(cn)` — with one
place that builds it and one comparison that decides, so no caller can pick the weaker half by
accident:

- **`update_pin()` builds it**, in order: `MICS_UPDATE_SIGNER_THUMBPRINT` when the environment sets
  one (D-047's operator hook, and a value that is not 40 hex digits is an **error** rather than a
  silent fallback), else the thumbprint of the certificate inside **this engine's own** Authenticode
  blob — read out of the certificate table with no chain built, so it answers the same on a machine
  that has not trusted the root yet — else `Pin::Name(EXPECTED_SIGNER_CN)`. That last branch is the
  development build and only the development build: an unsigned `cargo build`/`cargo test` binary
  has no certificate of its own to pin, so every configuration that ships pins a certificate.
- **`require_signed_by_pin(path, &pin)` replaces `require_signed_by(path, cn)`** — one path, not two.
  Windows still has to accept the signature (a changed byte never reaches the comparison), and then
  the pin decides the identity: a `Thumbprint` pin compares the file's own certificate thumbprint, a
  `Name` pin the display name, case-insensitively as before. The update path's payload check calls it
  for both binaries in the archive, which is the half that was actually broken.
- **`judge(&pin, signer, url)`** is the same policy one level up, over the detached PKCS#7 that signs
  `update.json` (D-047), and it still reports *which* pin decided — `pinned: true` only for a
  thumbprint comparison — so the update screen never calls the weaker check a pin.
- **`trust(path)`** classifies a file against the pin, keeping D-025's table exactly as it was
  (`Ours` / `UntrustedRoot` / `NotOurs`), and the package self-check's refusal line now **names the
  certificate it found** (subject and thumbprint) instead of asserting the release CN, which on a
  CA-signed build would have been a false sentence in the log.
- **`scripts\verify-manifest.ps1` moves with it, or the claim is only half true.** The release gate
  refuses a package whose engine is not signed by us, and it asked that question by name
  (`$script:MicsSignerCn` in `manifest-resource.ps1`, kept in step with `EXPECTED_SIGNER_CN` by
  `test/package_integrity_test.dart`) — so the first CA-signed release would have passed the engine's
  own check and failed the gate that runs before publishing, which is the same defect one file over.
  The gate now reads the **same hook the engine reads**: `MICS_UPDATE_SIGNER_THUMBPRINT` when it is
  set (and a value that is not 40 hex digits is a refusal, not a fallback), the release CN otherwise.
  Nothing new to configure, and the constant that used to be the whole check is now its fallback.

**What this closes, and what it does not.** Closed: the half that would have broken the day a real
certificate exists — a CA-signed release recognises itself, and a *different* certificate carrying
the very same CN is refused, which is D-016's residual and AP-4's scenario for a forged feed.

Still open, and now stated in `docs/THREAT-MODEL.md` F-3's fix line rather than implied: the pin is
read **out of the file under question**, so an engine copy that somebody re-signed pins its *own*
certificate and `trust()` still answers `Ours` — an engine cannot authenticate itself, and what
answers for a hand-delivered copy remains the file hashes the signed manifest lists and the publisher
name Windows shows. On the **update** path the same pin is a real comparison, because the payload is
a different file from the engine holding it — that is the direction a forged update arrives from, and
that is the direction the pin now has teeth in.

**One precondition this pin places on the release lane — measured 2026-11-11, not met yet.** A
thumbprint pin only means something if what it will judge is signed by the **same** certificate, and
the lane mints one per build: `make-release.ps1` says so in its own closing line ("the throwaway
signing key does not outlive the build it signed") while `scripts\codesign-cert.ps1` keeps the
certificate as a PFX in the job's TEMP. Counted on the day the published release was verified, this
machine's user stores held **12 distinct certificates** with the identical subject
`CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)` (24 store entries across
`Cert:\CurrentUser\TrustedPublisher`, `TrustedPeople` and `My`), and the published `v0.1.0` adds a
thirteenth on the artifact itself — the pile that made D-016's CN pin look reasonable is exactly what
a thumbprint pin must not be aimed across releases. So the next release, signed by a fresh
certificate, would be refused by the engine inside the published one: fail-closed (no update, never a
wrong accept), impossible to hit yet because nothing carrying this decision is published, and
repairable without code — one certificate kept in the `MICS_PFX` and `MICS_PFX_PASSWORD` secrets
(D-034's wiring, load-bearing now for a second reason), with `MICS_UPDATE_SIGNER_THUMBPRINT` as the
operator's override. Recorded as the register's new MED row and `docs/TODO.md` §0.6 row 18 (**ب7**),
whose only deadline is the next publish.

**Measured.** `cargo test` **206 passed, 0 failed** (five new cases around the pin and two renamed so
the counts stay honest — `signature.rs` 10 → 14 declared, `update.rs` 3 → 4: a `Thumbprint` pin
accepts the pinned certificate and refuses a same-name certificate, each half is decided by the half
it names, an unsigned file is refused by either pin, an engine with no signature of its own falls
back to the release name, the manifest is judged by the thumbprint, and the right release name does
not save the wrong thumbprint); `cargo clippy --all-targets` **clean**, which cost the deletion of the
now-unused `require_signed_by` rather than leaving a second, weaker entry point in place. The
file-level cases ran against a **real signed artifact** rather than a fixture — `dist\MICS-portable\mics-engine.exe`, status `Valid`,
subject `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`, thumbprint `1F08A3EF6CDF5E93394DAC3CBCB5276381CC47E0` — so "the
right thumbprint is accepted" and "the wrong thumbprint is refused while the name is identical"
compare real certificate bytes. `scripts\verify-update.ps1` was then re-run against an engine built
from this source, deliberately **unsigned** so that both halves of the pin are exercised rather than
one: **45 passed, 0 failed, 0 skipped** in 9 s — part 7 refuses a correctly signed feed under a pin
that is not its signer, naming both thumbprints in the refusal ("signed by … `f250975f…`, and this
engine pins the certificate with thumbprint `11fbddbb…`"), and part 8 is the fallback itself, where
an engine with no signature of its own reports `pinned: false` and requires the release name instead
of claiming a pin. The manifest-level policy, its refusals and their wording therefore all hold with
a `Pin` where the CN used to be.

The release gate was then measured the same way, on the signed package that is in the tree
(`dist\MICS-portable`, 68 files, engine `Valid`, thumbprint `1F08A3EF...`), three pins and three
exit codes: **no hook set** → `RESULT: PASS` (the CN fallback, exactly as before) **exit 0**; the
hook set to **the engine's own thumbprint** → `RESULT: PASS` **exit 0**; the hook set to **another
certificate** → refused **exit 1** with `mics-engine.exe is not signed by thumbprint FFFF... (status
Valid, signer CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS) (thumbprint 1F08A3EF...))`, and a hook
that is not a thumbprint refused **exit 1** before any file is read. `scripts\verify-tamper.ps1`,
which drives that gate through its callers and the engine's own reporting, stays green on the changed
script: **41 checks, 0 failures, 100.8 s** — the same counts as its 2026-11-03 run.

**Not measured, and open.** No certificate that a CA issued exists to try, so "a real certificate
recognises itself" rests on the same code path a re-signed copy would take, not on such an artifact;
and the `Ours`-on-a-re-signed-copy hole is stated, not demonstrated (proving it means minting a
second certificate and re-signing a copy, which is a waiver-maker rather than a test).

**Advances** §7's LOW row (the update pin is the signer's subject name) — closed; and
`docs/OPEN-DECISIONS.md` item 3 stops waiting, since its own recommended answer — "both, in order" —
is what landed. The decisions still waiting on the owner are **three**, not four. **Does not commit
us to:** buying, donating or configuring a certificate; a Settings field for the thumbprint (the
environment hook is the operator's way in, as with the feed in D-046/D-047); pinning a CN in the
binary for a certificate that does not exist yet; a key (SPKI) pin that would survive re-issuance; or
putting the app's own signature under the same pin.

**Amendment (2026-11-12 — the identity half is built, and the release report says it out loud).** The
precondition above ends on "repairable without code", which is true and was not enough: a repair
nobody performs is the defect staying. Two things landed for it, neither of them in the engine.
`scripts\verify-signer-identity.ps1` is new and measures the mechanism in seconds with **no engine,
no build, no store write and no Windows SDK** (`sign.ps1 -DataFile` is managed code): one PFX signs
two scratch manifests and both detached signatures carry one thumbprint, equal to the certificate
inside that PFX; a second PFX signs a third and carries a different one — the identity the engine
refuses, recorded here and measured there (`verify-update.ps1` part 4, a manifest signed by another
key, and part 7, the honest feed under the wrong pin). **18 checks, 0 failed, 5.1 s.** It also holds
the *names* end to end, which is where this area has actually broken before: the workflow's
`secrets.MICS_PFX` → `MICS_PFX_B64` → the lane's `-PfxPath` (D-047's wiring bug, now a check rather
than a memory), one `@signArgs` for the staged binaries and for `dist\update.json`, both refusals of a
PFX that arrives without its password, the lane's throwaway fallback and the `Remove-Item` on the
folder its key lives in, and the four readers of `MICS_UPDATE_SIGNER_THUMBPRINT` (`signature.rs`,
`verify-manifest.ps1`, `verify-update.ps1`, this probe). And `make-release.ps1`'s closing report now
names the identity instead of leaving it in a signing step's log: `pinned : <thumbprint>` — the
certificate the engine over *that* build will trust when it judges the next release — plus a `WARN`
when the identity is the one whose key the script deletes before it returns, because a release that
pins a deleted key is a release no later build can update, and the difference between the two is one
repository secret. One correction to the sentence above: `MICS_UPDATE_SIGNER_THUMBPRINT` is *not* this
repair, it is a probe and an operator override — it has to name the certificate of the **next**
release, which is knowable only once an identity is being kept, so the variable cannot stand in for
keeping one. **Measured end to end** by a lane run (below). The remaining act is the owner's and takes
a minute: `docs/SIGNING.md` section 7 item 6 is the copy-paste recipe, and the deadline is unchanged —
before the next publish.
