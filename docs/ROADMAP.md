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

`main`, 2026-10-31. Everything that needed neither elevation nor money is
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

## 1. Phases

| Phase | What it contains | Status | Priority | Est. | Blocked on |
|---|---|---|---|--:|---|
| **ب — P4 release engineering** | NSIS installer, helper install folded in, ARM64 leg, real signature, public release | **partial** — portable ZIP + local signing work | 🔴 **HIGH** (the register's only HIGH row: "no installer") | 8–16 h | certificate + release hosting: **you**; the rest: nothing |
| **ج — P5 trust & integrity** | build hardening, signed file manifest + startup self-check, README rewrite | **partial** — build hardening landed (ج1, D-021); threat model and protection matrix exist | 🟠 MED | 4–7 h | nothing |
| **د — P6 QA** | `qa/` harness over every JSON-RPC method, per-screen widget tests, E2E on the built artifact, report + CI gate | **not started** — `tool/` has two smoke probes, no harness | 🟠 MED (largest block of work) | 13–21 h | E2E after ب3; the rest: nothing |
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
| **ج2** | **Signed SHA-256 manifest** of shipped files + startup self-check + "unofficial build" banner | 🟠 | 3–5 h | Closes F-11; reuses the local self-signed certificate. 2 commits. |
| **د1** | `qa/` harness: every JSON-RPC method × (happy path, invalid params, permission failure, schema) | 🟠 | 6–10 h | Longest single item; build it from the dispatcher's method table so it cannot go stale. |
| **د2** | Per-screen widget tests (13 screens) | 🟠 | 4–6 h | `test/widget_test.dart` already has `FakeIpc`; the Settings screen had **no** test and hid a real bug. |
| **د3** | E2E against the built artifact (the ب3 installer) | 🟡 | 2–3 h | After ب3. |
| **د4** | `qa/report.html` + `.md`, and CI fails when a feature is not registered | 🟡 | 1–2 h | After د1. |
| **هـ1** | Default update-manifest URL compiled in + signature check on the manifest before applying | 🟡 | 2–3 h | Shares the key handling with ج2. |
| **ب2** | ARM64 leg: Flutter target + `aarch64-pc-windows-msvc` engine, `verify-release.ps1` aware of the arch | 🟡 | 3–5 h | ⚠️ No ARM64 machine here: build + compile-verified only, and say so. |
| **و1** | **Scheduled scan** (closes half of the MED row "no scheduled scan and no real-time watching") | 🟠 | 2–3 h | Cheapest MED row with user-visible value. |
| **و2** | Real-time file watching (`ReadDirectoryChangesW`/USN) | 🟠 | 6–10 h | **Architectural decision** (CPU cost, product behaviour) — bring it to the user first. |
| **و3** | `netsh` → **FirewallAPI COM** | 🟡 | 3–4 h | Removes the external-process dependency for firewall changes. |
| **و4** | Executable LOW rows (GeoIP lists, detection-pack size, guard cost, plaintext keys, method gaps) | 🟡 | 6–10 h | 1–3 h each. |
| **ب5** | Real OV/EV (or Azure Trusted Signing) certificate → sign the release | 🔴 | 1–2 h **+ procurement** | Code is ready (`scripts\sign.ps1` `/sha1`); see `docs/COST.md`. **Needs you.** |
| **ب6** | Public release: signed ZIP + installer, version bump, README updated | 🔴 | 1–2 h | Needs ب5 and somewhere to publish (GitHub Releases?). |

## 3. The order to work in

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
