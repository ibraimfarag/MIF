# ROADMAP — what is left, in order

This is the one-page answer to "what remains before this project is done?".
It is derived from `docs/TODO.md` (§0.2 blocked-on-you, §0.3 the plan, §6 the
backlog, §7 the risk register) and it must stay in sync with it: **when a step
lands, its row here moves to `[x]` in the same commit.** The step IDs (`ب3`, `ج2`,
`د1` …) are the same ones used there — do not invent new ones.

**Estimates are agent working hours** (what one session of focused work costs,
including its commit and the four checks), not calendar time. A "small step" is
20–45 minutes; the numbers below are the honest ranges, with the uncertainty
stated where it is real.

## Where we are

`main`, 2026-11-02. Everything that needed neither elevation nor money is
implemented **and** measured: the eight small steps of §0.5 are closed (dead
VirusTotal client deleted, names frozen, both contrast modes audited at 29 of 29
pairs, four light-theme renders, icon set verified, `PROTECTION-MATRIX.md` given
the product's layer numbers, the two cheap register rows written up), and **the
release is hardened** (ج1, D-021): Control Flow Guard on both binaries — which was
*not* on before, measured from the PE — the engine LTO'd and stripped
(35.7 → 24.0 MB), the Dart snapshot obfuscated, and `scripts\verify-hardening.ps1`
gating the release on what the file says rather than on the build flags.

The installer is **finished and measured** (ب3 steps 1–3, 2026-11-01): it installs
and removes the whole product, tags both shortcuts' `System.AppUserModel.ID` through
`IPropertyStore`, refuses to remove a copy its privileged helper still points at, and
`scripts\verify-installer.ps1` proves all of it end to end in about two minutes.
What is left is **release engineering, integrity, QA, and the two things that need
a human** (one UAC-acceptance session and a signing certificate).

On 2026-11-01 the user approved the QA and reliability track (§3), and eight of its
slices have landed: the pipeline entry point (ز0), the contract harness over all
**65** JSON-RPC methods (د1), every screen and control swept against the same
fixtures (د2), the language moved into Settings as a table (ز1), crash capture
with a bug id and a local bundle (ز2-أ), the runtime hang detector (ز2-ب: a
`std::thread` watchdog that files one `hang` report when the heartbeat stops), the
bug-id surface (ز2-ج: Settings → Diagnostics lists, opens, copies and deletes
those reports, with the bug id as the first line of the pasted text), and the
in-app cards (ز3: the same alert gate now has a second destination, a card in the
window's bottom corner - right in LTR, left in RTL - for every severity including
LOW, with the crash card carrying its bug id). What
is open on that track is cut into commit-sized slices in `docs/TODO.md`
§0.3b/§0.3c. The opsec work starts from a measured baseline rather than a guess —
the 2026-11-01 package shipped **1241** `cargo` strings and the build user's home
path **1238** times, which was a privacy leak as much as a fingerprint; **ط1**
remapped that path to `/build` (0 hits, measured on the rebuilt engine) and put
the remaining counts, with a reason per row, under a ratchet that may only fall.

## 1. Phases

| Phase | What it contains | Status | Priority | Est. | Blocked on |
|---|---|---|---|--:|---|
| **ب — P4 release engineering** | NSIS installer, helper install folded in, ARM64 leg, real signature, public release | **partial** — portable ZIP + local signing work | 🔴 **HIGH** (the register's only HIGH row: "no installer") | 8–16 h | certificate + release hosting: **you**; the rest: nothing |
| **ج — P5 trust & integrity** | build hardening, signed file manifest + startup self-check, README rewrite | **partial** — build hardening landed (ج1, D-021); threat model and protection matrix exist; ج2's design settled (D-025) | 🟠 MED | 4–7 h | nothing |
| **د — P6 QA** | pipeline entry point **[done]** (ز0), `qa/` contract harness over every JSON-RPC method **[done]** (د1), every screen and control **[done]** (د2), the committed QA report with coverage gates **[done]** (د5), E2E on the built artifact (د3) | **almost done** — ز0, د1, د2 landed 2026-11-01 and د5 landed 2026-11-02; only د3 (E2E on the installer) is left | 🟠 MED | 4–7 h | the system-tier contract runs on this machine, not CI |
| **ز — P8 interface & reliability** | language off the title bar into a Settings dropdown (multi-language + direction) **[done, 2026-11-01]**, crash/hang detection with a bug ID **[capture + hang detector done, and the bug-id surface in Settings done, 2026-11-02; delivery next]**, in-app cards in the bottom corner per direction **[done, 2026-11-02, D-024]**, opt-in delivery (webhook/SMTP/**Open WhatsApp bridge**) | **partly done** (ز1, ز2-أ, ز2-ب, ز2-ج, ز3) — only delivery is left | 🟠 MED | 6–10 h | ز2-د needs D-023 + the bridge endpoint |
| **ط — P9 opsec** | fingerprint sweep over the shipped files, `--remap-path-prefix`, an allowlist with a written reason per entry, tamper tests (byte flip, DLL swap, manifest edit) | **mostly done** — ط1 and ط3 landed 2026-11-02 (the account name is gone, the counts ratchet, `-Tier release` refuses a bad package); ط2 (tamper) waits for ج2 | 🟠 MED | 6–10 h | nothing |
| **هـ — P3 remainder** | compiled-in update manifest URL + signature check on the manifest | **partial** — check/download/apply work, manifest is user-supplied | 🟡 LOW | 2–3 h | nothing |
| **و — the register** | rows in §7 that are real work rather than accepted gaps | **19 open rows** (2 HIGH, 5 MED, 12 LOW) | 🟡 LOW–MED, per row | 6–12 h | some rows need a decision from you |
| **P1.5** | helper acceptance: three privileged operations with **zero** prompts | the first attempt (2026-11-01) found **two engine bugs instead of a helper problem** — both fixed that day (netsh policy argument shape, PowerShell quoting in the hardening snapshots); the helper itself was installed, running and reachable | 🔴 **HIGH** — this is the product's core promise | **15 min of your time** | **you** — and MI CS must be started *unelevated* for the helper path to be exercised |

Total: **~35–62 h of work** plus the certificate (money + procurement time).

## 2. Tasks

| ID | Task | Priority | Est. | Notes / first commit |
|---|---|--:|--:|---|
| ~~**ج1**~~ | ~~**Build hardening**: Rust LTO/strip/`panic=abort`, PE mitigations, Dart `--obfuscate --split-debug-info`~~ — **done** (D-021): CFG on both binaries (measured from the PE, and it was absent before), engine 35.7 → 24.0 MB, obfuscated Dart with symbols kept out of the package, and `verify-hardening.ps1` gating the release | ✅ | 2–3 h | Landed 2026-10-31; the installer now packs hardened binaries. |
| ~~**ب3**~~ | ~~**NSIS installer**: engine + `rules` + offline intel, shortcuts, AUMID, one UAC, uninstaller, upgrade path, `scripts\verify-installer.ps1`~~ — **done** (steps 1–3, 2026-11-01): `installer\mics.nsi` + `scripts\make-installer.ps1` produce `dist\MICS-setup-0.1.0-x64.exe` (15.8 MB, NSIS 3.11); the per-user variant installs 70 files with the hardened, signed engine (`E64A6FDE...`, `Valid`) and removes everything (exit 0); both shortcuts carry `System.AppUserModel.ID` through `IPropertyStore` (`Get-StartApps` shows no exe-path entry); the uninstaller refuses a copy the helper still points at (`/S _?=$INSTDIR` → 5); and `scripts\verify-installer.ps1` proves all of it in 126 s, restoring the machine afterwards | ✅ | — | Left for a human: one **per-machine** run (one UAC click, §0.2). |
| **ب4** | Fold the privileged-helper install into the installer (removes the separate UAC step) | 🟠 | 1–2 h | After ب3. |
| **ج2** | **Signed SHA-256 manifest** of shipped files + startup self-check + "unofficial build" banner | 🟠 | 3–5 h | Closes F-11; reuses the local self-signed certificate. **Design settled 2026-11-03 (D-025)**: the manifest is an `RT_RCDATA` resource inside `mics-engine.exe`, so its authenticity is the engine's existing Authenticode signature and `EXPECTED_SIGNER_CN` pin; `make-release.ps1` builds it after signing and re-signs the engine after the injection, and `verify-manifest.ps1` gates the package. `status.integrity` has three states (`ok`, `untrusted-certificate` = our CN with an untrusted chain → a neutral About line, `unverified` → notice + card), so only a real mismatch raises the banner. 2 commits: producer, then reader. |
| ~~**د0**~~ | ~~**Pipeline entry point**: `scripts/pipeline.ps1` with tiers, fail-fast, a JSON report, and the CI workflow calling it instead of repeating the four checks~~ — **done** (ز0, 2026-11-01): `fast` = the four checks (measured 16.3 + 13.8 + 7.4 + 2.4 s), `full` adds both release builds and the engine smoke, `release` is where the artifact verifiers land; CI caches `engine/target` and uploads the report | ✅ | — | `scripts/pipeline.ps1`, `.github/workflows/ci.yml` |
| ~~**د1**~~ | ~~`qa/` contract harness: every method × (happy path, invalid params, unknown method, result schema), registry generated from `dispatcher.rs` and freshness-checked~~ — **done** (2026-11-01): `qa/methods.json` documents all **62** methods, `qa/contract.dart` runs the surface against a real engine in a `%TEMP%` sandbox (**64 cases, 0 failed, 15 classified not-to-run with a reason, 18.4 s** on the release binary), and `test/qa_registry_test.dart` fails if the registry and the dispatcher's match table ever disagree | ✅ | — | `qa/README.md` carries the rules; `engine.contract` is a `full`-tier pipeline step, so CI runs it. |
| ~~**د2**~~ | ~~Every screen, every interactive control: the same fixtures drive a `FakeEngine`, ar/RTL + en/LTR, empty/loading/error states, and a ledger that fails when a control was never exercised~~ — **done** (2026-11-01): `qa/ui/` holds the fake engine (shapes from `qa/methods.json`, content from `qa/ui/fixtures.json`), the mounting harness and the sweep; **13 screens + the shell, 93 controls in a committed ledger**, 99 Dart tests in 13 s, and four unnamed icon buttons (canaries add/delete, IDS and firewall row delete) got the tooltips they were missing. RTL/LTR in the same sweep is **not** done — the sweep normalises to English so labels are comparable, and the direction switch moves with **ز1** | ✅ | — | `test/ui_screens_test.dart`, `test/ui_shell_test.dart`; the limits are in the Done log entry. |
| **د3** | E2E against the built artifact (the ب3 installer) | 🟡 | 2–3 h | After the harness and the per-machine run. |
| ~~**د5**~~ | ~~Coverage gates, `qa/report.html` + `.md`, and CI fails when a feature is not registered~~ — **done 2026-11-02**: `qa/report.md` + `qa/report.html` are committed and generated by `qa/report.dart` from the committed registries only (no clock, machine path or run timing), so `test/qa_report_test.dart` compares both byte for byte and fails the fast tier - and CI, which runs the fast tier inside `-Tier full` - when a surface moves without the report. The gates: 65 dispatcher methods = 65 registry rows, every language directory listed under `assets:`, every `skip` reason at least 20 characters, no degenerate surface, no machine value in either file. The measured run stays in `build/qa-contract.json` and `build/pipeline-<tier>.json`, which CI now uploads next to it | ✅ | 2–4 h | `qa/report.dart`, `qa/registry.dart`, `qa/report.md`, `qa/report.html`, `test/qa_report_test.dart` |
| ~~**ز1**~~ | ~~Language off the title bar into a Settings dropdown; `AppLang` → language code + direction table; `settings.rs` accepts the bundled set~~ — **done** (2026-11-01): `AppLang` is a table (`code`, native name, English name, `direction`) and `AppLang.all` is the only list of languages in the app — the title bar's language button is gone, Settings owns a labelled dropdown that shows each language in its own script, `lib/main.dart` takes `locale`/`supportedLocales` from the table, and every `== AppLang.ar` comparison became `isRtl`. The engine now checks the *shape* of a language tag instead of a fixed `ar`/`en` list (`is_language_tag`), so a language added next month needs no engine release; `test/lang_registry_test.dart` (10 tests) keeps `AppLang.all`, `assets/i18n/` and `pubspec.yaml` in step, and a Settings behaviour test proves one dropdown pick changes the pack, the tree direction and the engine at once | ✅ | — | `lib/core/i18n/app_i18n.dart`, `engine/src/settings.rs`, `qa/methods.json`. |
| **ز2** | Crash/hang: session marker, panic/error capture, `MICS-<date>-<hash>` bug id, local bundle, delivery through `mics-engine report` (webhook / SMTP / WhatsApp), dedupe and deadlines — **first half + hang detector done** (ز2-أ 2026-11-01, ز2-ب 2026-11-02): the engine detects a panic and a run that was killed, names it `MICS-<date>-<6 hex>` (hash of the failure, not of the moment, so a repeat is counted instead of re-filed), and writes a JSON bundle plus a readable `.txt` under `<data dir>\crashes\` with the last 60 log lines and any key-shaped values redacted; `crash.list` / `crash.get` / `crash.delete` read them, and the contract harness proves the whole loop across two real processes (kill one engine, start another, one report, right pid). **ز2-ب adds the hang half that only an OS thread can report**: a `std::thread` watchdog started with the session watches a heartbeat the runtime bumps (a 5 s timer task plus every request), and after a 20 s silence files one `hang` report saying how long the runtime was stuck and what the last request was — measured 2026-11-02 with 106 engine tests, including a deliberately frozen heartbeat and a proved absence of false reports; a hang that takes the whole process stays invisible by design. **Left: delivery (ز2-د)** — and **ز2-ج landed 2026-11-02**: Settings → Diagnostics lists those reports (`crash.list`), opens one (`crash.get`), copies the paste text whose **first line is the bug id**, and deletes one (`crash.delete`) by re-reading the list afterwards; measured with 114 Dart tests and exactly four new controls in the committed ledger. Delivery is blocked on **D-023**, and the WhatsApp path is now specified as an Open WhatsApp bridge rather than WhatsApp itself. **Left: delivery only (ز2-د)** | 🟠 | 12–16 h | No third binary (the names are frozen by D-020); nothing in `crash.rs` names a URL. |
| **ز3** | In-app cards: bottom corner, right for LTR and left for RTL, fed by the existing alert gate (`LOW` finally has the in-app home `alert.rs` already describes) — **done 2026-11-02 (D-024)**: the gate gained `decide_in_app` (every severity, DND the only switch, `toast_enabled` is the desktop's), cards leave as an `alert` push and are parked in a 5-card queue when no UI is attached, the shell paints at most three in a `PositionedDirectional` inside its own `Stack` (measured: `right = 1682` in LTR, `left = 18` in RTL, two new controls in the ledger), and a filed crash report raises a card carrying its bug id and saying delivery is off | 🟡 | 2–3 h | No state a report does not have: until ز2-د lands, a card may only say delivery is off. |
| ~~**ط1**~~ | ~~Fingerprint sweep + ratchet~~ — **done 2026-11-02**: the Rust build compiles with `--remap-path-prefix=$env:USERPROFILE=/build` in `make-release.ps1` and `engine.build`, so the account name that appeared **1238** times in `mics-engine.exe` is now **0** (and `/build` replaced it in every crate path); `scripts/verify-opsec.ps1` measures the package against `qa/opsec-baseline.json` (9 binaries; totals **2301** `flutter`, **915** `dart`, **1242** `cargo`, **97** `rustc`, **1** `pubspec`, each row with a written reason), fails when a count rises or a binary is unlisted, and runs inside `make-release.ps1`; `test/opsec_baseline_test.dart` keeps the file honest in the fast tier. The framework strings are the allowlist and may only fall. The remap is *appended* to the crate's own flags by `scripts/engine-rustflags.ps1` rather than replacing them (`CARGO_ENCODED_RUSTFLAGS` overrides `.cargo\config.toml`; doing it by hand cost the engine its CFG table, and the hardening gate in `make-release.ps1` caught it the same day). | ✅ | 3–5 h | `scripts/verify-opsec.ps1`, `scripts/engine-rustflags.ps1`, `qa/opsec-baseline.json` |
| **ط2** | Tamper tests: a byte flip per binary, a swapped DLL, an edited manifest, a copied install — each must be refused or reported | 🟠 | 2–3 h | Sits on ج2's signed manifest. |
| ~~**ط3**~~ | ~~the `-Tier release` wiring~~ — **done 2026-11-02**: `scripts\pipeline.ps1` gained its first `release`-tier step, `opsec.verify`, which runs `verify-opsec.ps1` against `dist\MICS-portable` (the packaged artifact, not the build folder); `-Tier release -List` shows it last and `-Tier release -Only opsec.verify` passes on the published package and fails on a stale one. The tier's help text now says the verifiers land one per slice. | ✅ | 1–2 h | `scripts\pipeline.ps1` |
| **هـ1** | Default update-manifest URL compiled in + signature check on the manifest before applying | 🟡 | 2–3 h | Shares the key handling with ج2. |
| **ب2** | ARM64 leg: Flutter target + `aarch64-pc-windows-msvc` engine, `verify-release.ps1` aware of the arch | 🟡 | 3–5 h | ⚠️ No ARM64 machine here: build + compile-verified only, and say so. |
| **و1** | **Scheduled scan** (closes half of the MED row "no scheduled scan and no real-time watching") | 🟠 | 2–3 h | Cheapest MED row with user-visible value. |
| **و2** | Real-time file watching (`ReadDirectoryChangesW`/USN) | 🟠 | 6–10 h | **Architectural decision** (CPU cost, product behaviour) — bring it to the user first. |
| **و3** | `netsh` → **FirewallAPI COM** | 🟡 | 3–4 h | Removes the external-process dependency for firewall changes. |
| **و4** | Executable LOW rows (GeoIP lists, detection-pack size, guard cost, plaintext keys, method gaps) | 🟡 | 6–10 h | 1–3 h each. |
| **ب5** | Real OV/EV (or Azure Trusted Signing) certificate → sign the release | 🔴 | 1–2 h **+ procurement** | Code is ready (`scripts\sign.ps1` `/sha1`); see `docs/COST.md`. **Needs you.** |
| **ب6** | Public release: signed ZIP + installer, version bump, README updated | 🔴 | 1–2 h | Needs ب5 and somewhere to publish (GitHub Releases?). |

## 3. The order to work in

**The approved track (2026-11-01) runs first, one commit per step:**
**ز0** *(done)* → **د1** *(done)* → **د2** *(done)* → **ز1** *(done)* → **ز2-أ** *(done)* → **ز2-ب** *(done)* → **ز2-ج** *(done)* → **ز2-د** (delivery, blocked on D-023) → **ز3** *(done)* → **ط1** *(done)* → **ط3** *(done)* → **د5** *(done)* → **ج2** (next; closes F-11 and unblocks ط2).
It is what the user picked over the release lane; the list below is the release lane
the project returns to afterwards.

**What each open slice has to prove before it is committed** is written down in
`docs/TODO.md` §0.3c, so a session that starts cold does not re-derive it — and
`docs/TODO.md` §0.0 carries the prompt to paste into a new session.

1. ~~**ج1 build hardening**~~ — **done** (D-021): the binaries are hardened before
   anything packages them.
2. ~~**ب3 installer**~~ — **done** (steps 1–3): the project goes from a ZIP to a
   product with hardened binaries, tagged shortcuts, a guarded uninstaller and a
   script that proves all of it. Left for a human: one per-machine run.
3. **ب4 helper fold-in** — removes the extra UAC step.
4. **ج2 signed manifest + self-check** — completes the integrity story on top of ب3's
   file list.
5. **د1 + د2 QA** — the biggest real gap: every feature is verified by hand, not by a
   harness that proves all of them at once.
6. **هـ1 + و1** — cheap, visible.
7. **ب2 ARM64, د3, د4** — finish the release and the QA report.
8. **ب5 → ب6** the moment the certificate exists.

## 4. Blocked on the user (do not plan around these)

1. **The 15-minute helper acceptance** (`docs/TODO.md` §0.2, `PRIVILEGED-OPS.md`):
   Settings → Engine → Install helper is already installed and reachable; what is
   left is enabling Default-Deny, turning SMBv1 off and importing a hosts list in one
   session and confirming **zero** further prompts plus one `phase=start`/`phase=done`
   pair per operation in `%PROGRAMDATA%\MICS\logs\priv.log`.
2. **A signing certificate** (ب5): OV (~$200–400/yr, days of validation) or Azure
   Trusted Signing (~$10/month, faster). Costs and constraints: `docs/COST.md`.

## 5. Out of scope by design (not "remaining work")

No kernel driver, no pre-execution blocking, no inline network filtering, no
Suricata/ET-Open, no ClamAV/CAPA, no detection of a pure read on a canary, no
anti-tamper watchdog. Each is written down with its reason in
`docs/THREAT-MODEL.md` (§6 residual risks) and `docs/PROTECTION-MATRIX.md` (§9).
They are product decisions, not backlog items — reopening one needs a new entry in
`docs/DECISIONS.md`.

## 6. How every step ends

One conventional commit, `docs/TODO.md` updated in the same commit (the finished item
moves to the Done log, it is not just ticked), this file's row updated, and the four
checks green: `cargo test`, `cargo clippy --release -- -D warnings`,
`flutter analyze --no-pub`, `flutter test --no-pub`. Say what was **measured**, not
just what changed.
