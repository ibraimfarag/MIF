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

`main`, **2026-11-10**. Everything
that needed neither elevation nor money is implemented **and** measured: the nine small
steps of §0.5 are closed (dead
VirusTotal client deleted, names frozen, both contrast modes audited at 29 of 29
pairs, four light-theme renders, icon set verified, `PROTECTION-MATRIX.md` given
the product's layer numbers, the two cheap register rows written up, the register's
"engine missing and no reason given" row closed with §0.6 row 10's two
documentation debts), the **reproducible
build landed** (F-11, §0.6 row 4 — two from-scratch builds of the whole app tree agree
file for file, and `scripts\verify-reproducible.ps1`, run end to end, rebuilt a
published archive and matched 60 files byte for byte, 7 on content and 2 explained;
[`REPRODUCIBLE.md`](REPRODUCIBLE.md)), **the firewall's one open MED defect is closed**
(2026-11-08: a rule name that already carried the `MICS-` prefix was prefixed twice and
could then never be removed by the name that was given — one function now decides a rule
name, and the probe creates a rule under the prefixed spelling, proves Windows has no
doubly-prefixed rule and removes it by the unprefixed one: 27 checks, 0 skipped, 0
failures), **the engine's life is now the app's** (2026-11-08, D-039: the app starts it
with `service --parent <pid>` so a close, a crash or a Task Manager kill all end it, a
deliberate quit asks through the new `shutdown` method and gets its answer before the
process goes, closing the window quits unless *Keep running in the background* is on,
and the whole engine half is 19 measured checks in `scripts\verify-lifecycle.ps1`, now
a pipeline step — reversal of the brief's "closing the UI → tray; engine keeps
protecting"), and **the real-time firewall is measured against the real Base Filtering Engine**
(2026-11-09, D-042/D-043/D-044/D-045: a persistent `FWP_ACTION_BLOCK` Windows' own
`netsh wfp show filters` reads back at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, a real connection row's
spec accepted and undone, and the tamper watch reading the real machine —
`scripts\verify-wfp.ps1` 16/2/0, `scripts\verify-connections.ps1` 24/0/0,
`scripts\verify-wfp-watch.ps1` 34/1/0, `scripts\reset-wfp.ps1` 7/0/0, which also removed the four
filters the 2026-11-08 run had left behind), and **the
release is hardened** (ج1, D-021): Control Flow Guard on both binaries — which was
*not* on before, measured from the PE — the engine LTO'd and stripped
(35.7 → 24.0 MB), the Dart snapshot obfuscated, and `scripts\verify-hardening.ps1`
gating the release on what the file says rather than on the build flags.

The installer is **finished and measured** (ب3 steps 1–3, 2026-11-01): it installs
and removes the whole product, tags both shortcuts' `System.AppUserModel.ID` through
`IPropertyStore`, and `scripts\verify-installer.ps1` proves all of it end to end in
about two minutes. **ب4 landed 2026-11-03 (D-026)** and made it one prompt: the same
elevated run now creates the privileged helper — through the shipped engine's own
`install-helper` — and the uninstaller stops and deletes that service again, only
after proving its binPath is the folder being removed and only the service name that
`HELPER_SVC_KEY` names. The run also fixed a defect it uncovered: the refusal dialogs
awaited a click even under `/S`, so the documented exit level 5 never arrived for a
scripted uninstall (measured at 532 s on the pre-change build too) — both are now
`${IfNot} ${Silent}` and the verifier's 141 s run proves it.
**What is left is one table — `docs/TODO.md` §0.6** — and it is short: **ب6 is published**
(the owner's one click landed on 2026-11-10, and the verification of that download on
2026-11-11 is in the Done log — four assets, all three hashes re-checked against the
published `SHA256SUMS`, the portable package `PASS` against its own signed manifest — which
also produced the row that is now first in the engineering list: **ب7**, one signing identity
per release, because `v0.1.0` was signed by a certificate minted for that build and D-051's
pin would have each engine refuse the next release's payload), free engineering (**هـ1** — both its
halves landed, the default update feed on 2026-11-09 (D-046) and the manifest **signature**
with the D-016 thumbprint pin on the same day (D-047) —
the §7
rows — one of which is a real defect the acceptance run found — and §0.6 row 13, the
engine's manifest covering signatures instead of content), one item that is **free but
not yet built** — a publicly trusted signature,
which is no longer "not purchasable": **D-036** found two free routes and
[`docs/SIGNING.md`](SIGNING.md) records both with their sources (route A, the Microsoft
Store re-signing an MSIX, is available today and is packaging work; route B, OSSign's
project certificate, is a calendar row at ~2027-04-27) — and two items that are **blocked
rather than pending**: an ARM64 **app** (Flutter publishes no Windows ARM64 SDK) and
**ز2-د** (D-023 + the bridge endpoint). **Nothing in the plan needs money, and nothing
needs your hands: the one click that was waiting on you happened on 2026-11-10.**

The integrity manifest is **done end to end** (ج2, both commits, and ط2, 2026-11-03,
D-025 and its three amendments): `make-release.ps1` signs every staged file except the
engine, builds `MICS_MANIFEST` from those final bytes, injects it into
`mics-engine.exe` as an `RT_RCDATA` resource, and signs the engine **once, after**
the injection; `scripts\verify-manifest.ps1` re-reads the resource out of the
package and re-hashes the **68** files it lists. The engine then reads its own
document at start-up, re-hashes the folder it runs from, classifies its own
signature (ours and trusted / ours with a root this Windows has not trusted yet /
anything else) and answers `status.integrity` — `ok`, `untrusted-certificate` or
`unverified`, which Settings → About renders as one green line, one neutral line or
the notice, with a card naming the files that moved. **ط2 landed on top of it** — see
below — and the lane is closed.

**ط2, the tamper tests, landed the same day** (`scripts\verify-tamper.ps1`, also the
`tamper.verify` release step): one thing is tampered with at a time in a private copy
of the published package and both halves are asked - a byte flipped in each of the
nine shipped binaries, a same-size swapped DLL, an edited manifest, the manifest
copied into an unsigned engine, and a copied install. The gate must refuse each and
the packaged engine must report each (`unverified`, naming the file in its log and in
the card), while the pristine package is the control and must pass: **41 checks, 0
failures, 108.5 s**. The probe also found a hole in the gate it was testing - an
engine whose signature had been *stripped* passed `verify-manifest.ps1`, because only
`HashMismatch` failed - so the gate now requires the pinned `MI CS Code Signing`
signer and the CN lives in one PowerShell constant pinned to the engine's
`EXPECTED_SIGNER_CN` by a Dart test. **D-051 (2026-11-11)** moved that pin's
engine half to the certificate over the engine, and the gate reads the same
`MICS_UPDATE_SIGNER_THUMBPRINT` hook the engine reads: the constant is now the
fallback for a build with no signature of its own rather than the whole check.

**ج3, the README rewrite, closed that lane on the same day.** The file already had a
"what it does / what it does not do" pair; what it needed was for both halves to stop
lying. The *does* table gained **"Is this copy the published one?"** (the 68 files, the
document inside the engine's own signature, the three verdicts, the About line, the
card and the gate), the *does not* list replaced the stale "there is still no integrity
manifest" with the real limit — a changed copy is made **visible**, not impossible, a
rebuild signed by somebody else is reported and not blocked, and there was no
reproducible build yet — and the install steps, troubleshooting, testing numbers and
the whole Arabic half were brought to the same measured truth. Every number in it is
one a pipeline step prints. (The "no reproducible build yet" half of that list was
the last thing to go stale: it was replaced on 2026-11-08, in the same pass as the
build it described.)

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
| **ب — P4 release engineering** | NSIS installer, helper install folded in, ARM64 leg, real signature, public release | **published 2026-11-10; only the signature is left** — portable ZIP + installer + local signing work, the signing wiring waits for nothing (**D-034**: a certificate is two repository secrets), and the **certificate is not purchased** (**D-035**) but is no longer *closed*: **D-036** (2026-11-07) found two free routes in [`docs/SIGNING.md`](SIGNING.md) — the Store re-signing an MSIX, available today, and OSSign at ~2027-04-27 — while the free substitutes (the manifest, the hashes, a reproducible build) stay load-bearing; `v0.1.0` is **published**, and verifying it against its own release page on 2026-11-11 left one free engineering row behind it (**ب7**, one signing identity per release — P4 below, whose engineering half landed 2026-11-12: a probe that measures one PFX = one identity, and a release report that names the identity and warns when it cannot outlive the build). **2026-11-13: the whole pipeline is green on the `0.1.1` cut, and the release tier depends on *which* identity signed it** — a `dist\` signed by the throwaway certificate the lane mints when it is handed no PFX leaves **4** of `engine.test`'s signature cases red, while the same tier over a `dist\` signed by a kept store certificate is **14/14**, so ب7's one secret is now the difference between a green lane and a red one rather than a formality; that cut also closed a gap of its own, since the two files that declare the version (`engine\Cargo.toml`, `pubspec.yaml`) had nothing comparing them until `test\version_agreement_test.dart`. | 🔴 **HIGH**, but only its signature half — the download half closed 2026-11-10 | 1–2 h for ب7; the certificate is free | **one secret**: keep a certificate in `MICS_PFX`/`MICS_PFX_PASSWORD`, and the next publish stops waiting on ب7 |
| **ج — P5 trust & integrity** | build hardening, signed file manifest + startup self-check, README rewrite | **done** — build hardening (ج1, D-021), the integrity manifest end to end (ج2, 2026-11-03), the tamper proof (ط2, 2026-11-03), the threat model and protection matrix, and the README rewrite (**ج3**, 2026-11-03); **verified on the installed artifact 2026-11-07**: the engine in `C:\Program Files\MI CS` re-hashed **68 of 68** listed files at start-up and reported our signer as `untrusted-certificate` (the honest middle state). **F-11's reproducible build landed 2026-11-08** — the phase's last open piece, and the **substitute** for a certificate (D-035) rather than a nicety: `make-release.ps1 -Reproducible` takes the build time from the revision, asks both linkers for `/Brepro` and writes the archive without the clock, `scripts\verify-reproducible.ps1 -Reference <zip>` rebuilds and compares every file (PE files on their signature-independent content hash), and [`docs/REPRODUCIBLE.md`](REPRODUCIBLE.md) is the recipe. Run end to end on the same day: a rebuild signed with its own self-signed key matched **60 of 69 files byte for byte, 7 on content, and left 2 explained** — the engine and the `VERSION` line that repeats its content hash — with 0 unexpected differences. Unchanged by it: `mics-engine.exe` alone is not byte-comparable, because `MICS_MANIFEST` records the other files' hashes *as signed* — TODO §0.6 row 13 | ✅ | — | nothing |
| **د — P6 QA** | pipeline entry point **[done]** (ز0), `qa/` contract harness over every JSON-RPC method **[done]** (د1), every screen and control **[done]** (د2), the committed QA report with coverage gates **[done]** (د4/د5), E2E on the built artifact **[done 2026-11-07]** (د3) | **done** — see the د3 row for the measured install/uninstall/privileged-op run | ✅ | — | nothing |
| **ز — P8 interface & reliability** | language off the title bar into a Settings dropdown (multi-language + direction) **[done, 2026-11-01]**, crash/hang detection with a bug ID **[capture + hang detector done, and the bug-id surface in Settings done, 2026-11-02; delivery next]**, in-app cards in the bottom corner per direction **[done, 2026-11-02, D-024]**, opt-in delivery (webhook/SMTP/**Open WhatsApp bridge**) | **partly done** (ز1, ز2-أ, ز2-ب, ز2-ج, ز3) — only delivery is left | 🟠 MED | 6–10 h | ز2-د needs D-023 + the bridge endpoint |
| **ط — P9 opsec** | fingerprint sweep over the shipped files, `--remap-path-prefix`, an allowlist with a written reason per entry, tamper tests (byte flip, DLL swap, manifest edit) | **done** — ط1 and ط3 landed 2026-11-02 (the account name is gone, the counts ratchet, `-Tier release` refuses a bad package) and **ط2 landed 2026-11-03** (`scripts\verify-tamper.ps1`, the `tamper.verify` release step), which also closed a hole in the manifest gate it was written to test | ✅ | — | nothing |
| **هـ — P3 remainder** | compiled-in update manifest URL + signature check on the manifest | **done 2026-11-09 (D-046, D-047)** — the channel carries the project's own release feed (`stable` = `releases/latest`, `beta` = the rolling `beta` tag), `resolve_update_url` orders environment → saved URL → channel default, `update.check` runs the one implementation the downloader uses and reports **which feed answered**, `MICS_UPDATE_MANIFEST_URL=off` is the explicit do-not-check, `make-release.ps1` step 9 publishes the `update.json` that feed reads (`scripts\update-manifest.ps1`) and step 9b signs it with the identity that signed the binaries (`update.json.sig`), the engine verifies that detached signature over the exact bytes **before** it parses the manifest and pins the signer to the certificate over its own engine (or to `MICS_UPDATE_SIGNER_THUMBPRINT`), and a manifest that is unsigned, signed by another key, changed after signing, or describing other bytes is refused with the signature as the reason; measured by `scripts\verify-update.ps1` (**18 passed, 0 failed, 4 s** for slice 1 on 2026-11-09, **45 passed, 0 failed, 8 s** after slice 2 — against a signed engine part 8's five checks are one `SKIP` with its reason). **The lane is not the same thing as a published feed, measured 2026-11-12:** `v0.1.0` was created 2026-11-05 and its four assets were frozen that day, before step 9 existed, so the one published release carries no `update.json` and the compiled-in URL answers 404 until a release built by today's lane is published (`docs/TODO.md` 0.6 row 5) | ✅ | — | nothing |
| **F-12 — the app's lifetime and its surfaces** | the engine tied to the app that started it (**D-039**) **[done 2026-11-08]**, a designed tray menu (**D-040**) **[done 2026-11-08]**, "Scan with MI CS" in Explorer's context menu (**D-041**) **[done 2026-11-08]**, a real-time firewall (WFP) **[all three slices done 2026-11-09 (D-042/D-043/D-044/D-045) — §0.6 row 17 closed]** | **4 of 4 done** — D-039 closes §0.6 row 14 with 19 measured checks (`scripts\verify-lifecycle.ps1`, now the `engine.lifecycle` pipeline step) and a `close_to_tray` setting; D-040 closes row 15 with a Flutter panel inside the app's own window (live guard/firewall/connection state, 6 ledgered controls); D-041 closes row 16 with the per-user verb (`*`, `Directory`, `Directory\Background`), the `app.activate` handover (68th method, 10 live checks in `scripts\verify-handoff.ps1`, 11 app tests) and the handed path shown in the scanner; row 17 (WFP) is closed on the elevated run of 2026-11-09, which measured all three slices against the real Base Filtering Engine: **slice (a)** — MI CS' own provider, sublayer and persistent filters through the helper (12 unit tests, 4 methods) — `scripts\verify-wfp.ps1` **16 passed, 2 skipped, 0 failed**, with Windows' own `netsh wfp show filters` reporting the filter as `FWP_ACTION_BLOCK`, `FWPM_FILTER_FLAG_PERSISTENT`, at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` with the app path, port 65001 and protocol 6 as conditions, and gone after the undo; **slice (b)** — live connections with a one-click block (D-043: the four-table walk with IPv6 in `windows\conns.rs`, the spec derived on the engine side, a per-row block button with its confirmation, 6 engine tests + 2 app tests) — `scripts\verify-connections.ps1` **24 passed, 0 skipped, 0 failed**, part 3 in its write branch at last: a real row's own spec accepted, the BFE one filter heavier, `fw.wfp.unblock` back to zero; **slice (c)** — the tamper alert on our sublayer and filters (D-044: a record beside the objects compared by `fw.wfp.watch` into `guarded`/`tampered`/`clear`/`unrecorded`/`unknown`, one HIGH incident and card per change, polled by the guard thread about every 30 s, 10 engine tests + 2 app tests) — `scripts\verify-wfp-watch.ps1` **34 passed, 1 skipped, 0 failed**, its first part reading the real machine (`state=clear recorded=0 live=0`). The 2026-11-08 run before it is what produced **D-045** (every enumeration named a zero `layerKey`, so `fw.wfp.status`, `fw.wfp.block` — after it had added its filter — and `fw.wfp.reset` failed at the BFE with `layer does not exist. (0x80320004)`, and three probes read that as a pass or as a privilege boundary); the fix, its two tests, the honest probes and `scripts\reset-wfp.ps1` are in, and the reset found the four stray filters that run had left. Four claims are named in row 17 as uncomposed rather than disproven (a filter's effect on a live connection, a reboot, our sublayer's weight against a built-in permit rule, a real deletion behind the engine's back), and the installed `MICSHelper` is still a pre-D-045 release build until it is reinstalled | 🟠 MED | 1-3 days, one row at a time | nothing; the Explorer context menu is the one the user asked for by name |
| **و — the register** | rows in §7 that are real work rather than accepted gaps | **7 open rows** (1 HIGH, 3 MED, 3 LOW) out of 24 — recounted 2026-11-11 by walking the table in `docs/TODO.md` §7 with a script; it was 13 (1 HIGH, **4** MED, 8 LOW) earlier on 2026-11-10, and the row that closed is the MED one the acceptance run found (a firewall rule name that already carried the `MICS-` prefix was prefixed twice and could then never be removed by the name that was given) — it closed with its measurements. The newest LOW row — what a user sees when the engine refuses to start — closed in small step 9 (`a4856d5`), the LOW row after it — the guard's ETW callback loading the IOC hash list and dropping it — closed 2026-11-10 (dead load removed, the coverage fact moved into `guard::ioc_hash_coverage`, one engine test, fast tier green at 201 engine tests), **D-049** closed the LOW row about a stored language tag no pack can render (the chain ends in English, the stored tag is carried and named in Settings, five Dart cases, fast tier green at 172 Flutter tests), **D-050** closed the LOW row about a language folder `pubspec.yaml` does not declare (the loader classifies every language's load and writes one line per language that lost anything, Settings names the language whose own pack is empty, six Dart cases — and the first run of them found the `about` entry the module list carried with no file anywhere — fast tier green at 178 Flutter tests and an untouched engine at 201), and **D-051** closed the LOW row about the update pin comparing a subject name (the pin is the certificate over the engine itself, the CN is the fallback for a build with no signature of its own, `update.rs`'s payload check and the manifest judge use the one value, five new engine cases and two renamed — 206 engine tests — `verify-update.ps1` 45/0/0, `verify-manifest.ps1` measured under three pins, `verify-tamper.ps1` 41/0, fast tier green) | 🟡 LOW–MED, per row | 4–10 h | some rows need a decision from you |
| **P1.5** | helper acceptance: privileged operations with **zero** prompts | **done, measured 2026-11-07** — against the **real** LocalSystem service (not `helper-console`): `helper-status` reported `installed/running/reachable/elevated`, `fw.rules.add` created `MICS-MICS-e2e-acceptance` in **37 ms** and `fw.rules.remove` removed it in **36–44 ms**, each a `phase=start`/`phase=done ok=true` pair in `%PROGRAMDATA%\MICS\logs\priv.log`, and **no UAC prompt appeared for any of it**. Proved by the 2026-11-01 attempts fixing two engine bugs first (netsh argument shape, PowerShell quoting) | ✅ | — | nothing |

Total: the rows still open in §2 come to **~11–22 h of free work** (the register + ز2-د), plus the correctness work of the new register row and §0.6 row 13 (the engine's manifest covering content instead of signatures), plus F-12's three remaining rows (the tray panel, Explorer's context menu, the WFP firewall — §0.6 rows 15–17), none of which is estimated yet — and **no money at all**: the certificate this line used to name is off the plan (D-035), and since D-036 it is off the plan *and* reachable for free — two routes, one of them available today (`docs/SIGNING.md`).

## 2. Tasks

| ID | Task | Priority | Est. | Notes / first commit |
|---|---|--:|--:|---|
| ~~**ج1**~~ | ~~**Build hardening**: Rust LTO/strip/`panic=abort`, PE mitigations, Dart `--obfuscate --split-debug-info`~~ — **done** (D-021): CFG on both binaries (measured from the PE, and it was absent before), engine 35.7 → 24.0 MB, obfuscated Dart with symbols kept out of the package, and `verify-hardening.ps1` gating the release | ✅ | 2–3 h | Landed 2026-10-31; the installer now packs hardened binaries. |
| ~~**ب3**~~ | ~~**NSIS installer**: engine + `rules` + offline intel, shortcuts, AUMID, one UAC, uninstaller, upgrade path, `scripts\verify-installer.ps1`~~ — **done** (steps 1–3, 2026-11-01): `installer\mics.nsi` + `scripts\make-installer.ps1` produce `dist\MICS-setup-0.1.0-x64.exe` (15.8 MB, NSIS 3.11); the per-user variant installs 70 files with the hardened, signed engine (`E64A6FDE...`, `Valid`) and removes everything (exit 0); both shortcuts carry `System.AppUserModel.ID` through `IPropertyStore` (`Get-StartApps` shows no exe-path entry); the uninstaller refuses a copy the helper still points at (`/S _?=$INSTDIR` → 5); and `scripts\verify-installer.ps1` proves all of it in 126 s, restoring the machine afterwards | ✅ | — | **The per-machine run happened 2026-11-07** (§0.2 item 1). |
| ~~**ب4**~~ | ~~Fold the privileged-helper install into the installer (removes the separate UAC step)~~ — **done 2026-11-03 (D-026)**: the per-machine section runs the shipped engine's own `install-helper` under the installer's elevation, so one prompt installs the product *and* the service (a failure warns and leaves the app's repair path), and the uninstaller asks `check-helper-ownership.ps1 -Remove` to stop and delete exactly the service whose binPath is `$INSTDIR`, scoped to `HELPER_SVC_KEY`'s leaf so a probe cannot touch a real one; refusal with error level 5 is kept for the cases it cannot remove. Both variants compile and `verify-installer.ps1` passes end to end in **141 s** — which also proved a defect: the refusal dialogs blocked `/S` forever (532 s on the pre-change build too), so the documented exit code was never reachable without a click; they are now `${IfNot} ${Silent}`. **The per-machine run happened 2026-11-07** and proved both halves on the real thing: the installer created `MICSHelper` (`"C:\Program Files\MI CS\mics-engine.exe" helper-service`, LocalSystem, AUTO_START, running) inside its one prompt, and the uninstaller stopped and deleted it in its own one prompt | ✅ | 1–2 h | After ب3. |
| ~~**ج2**~~ | ~~**Signed SHA-256 manifest** of shipped files + startup self-check + "unofficial build" banner~~ — **done 2026-11-03, both commits** | ✅ | 3–5 h | Closes F-11's detection half; reuses the local self-signed certificate. **Design settled 2026-11-03 (D-025) and amended twice the same day**: the manifest is an `RT_RCDATA` resource inside `mics-engine.exe`, so its authenticity is the engine's existing Authenticode signature and `EXPECTED_SIGNER_CN` pin. **The producer**: `make-release.ps1` signs every staged file except the engine, builds the manifest from those final bytes, injects it, signs the engine once (injecting into an already-signed PE breaks it for signtool, `0x800700C1`, measured), and `scripts\verify-manifest.ps1` re-reads the resource out of the package and re-hashes the 68 files it lists — plus a `manifest.verify` release-tier step. **The reader**: `engine\src\selfcheck.rs` re-reads the resource at start-up, re-hashes the folder it runs from, and separates "our certificate, this Windows has not trusted the root yet" (`CERT_E_UNTRUSTEDROOT` + the embedded signer read without a chain) from "the bytes changed" (`TRUST_E_BAD_DIGEST`, which must never be quiet); `status.integrity` answers `ok` / `untrusted-certificate` / `unverified`, Settings → About shows one line or the notice, and only a copy that *carries* a disagreeing manifest raises a card. |
| ~~**د0**~~ | ~~**Pipeline entry point**: `scripts/pipeline.ps1` with tiers, fail-fast, a JSON report, and the CI workflow calling it instead of repeating the four checks~~ — **done** (ز0, 2026-11-01): `fast` = the four checks (measured 16.3 + 13.8 + 7.4 + 2.4 s), `full` adds both release builds and the engine smoke, `release` is where the artifact verifiers land; CI caches `engine/target` and uploads the report. **2026-11-05 (the first two runs on the public repository)**: CI used an unpinned Flutter (`stable` = 3.47.9 against the 3.47.8 this machine verifies with) and the runner is a server-class Windows where an administrator's new directory belongs to `BUILTIN\Administrators` — the first was fixed by pinning the toolchains (D-029) and the second exposed a real install-breaking refusal in the helper's account check (D-030) | ✅ | — | `scripts/pipeline.ps1`, `.github/workflows/ci.yml` |
| ~~**د1**~~ | ~~`qa/` contract harness: every method × (happy path, invalid params, unknown method, result schema), registry generated from `dispatcher.rs` and freshness-checked~~ — **done** (2026-11-01): `qa/methods.json` documents all **66** methods (`62` when this row was written; the surface grew with the scan/crash/i18n work), `qa/contract.dart` runs the surface against a real engine in a `%TEMP%` sandbox (a case per method plus the harness's own scenarios, **0 failed, 14 classified not-to-run, 9.4–18.4 s** on the release binary), and `test/qa_registry_test.dart` fails if the registry and the dispatcher's match table ever disagree | ✅ | — | `qa/README.md` carries the rules; `engine.contract` is a `full`-tier pipeline step, so CI runs it. |
| ~~**د2**~~ | ~~Every screen, every interactive control: the same fixtures drive a `FakeEngine`, ar/RTL + en/LTR, empty/loading/error states, and a ledger that fails when a control was never exercised~~ — **done** (2026-11-01): `qa/ui/` holds the fake engine (shapes from `qa/methods.json`, content from `qa/ui/fixtures.json`), the mounting harness and the sweep; **13 screens + the shell, 100 controls in a committed ledger** (93 when this row was written), 99 Dart tests in 13 s, and four unnamed icon buttons (canaries add/delete, IDS and firewall row delete) got the tooltips they were missing. RTL/LTR in the same sweep is **not** done — the sweep normalises to English so labels are comparable, and the direction switch moves with **ز1** | ✅ | — | `test/ui_screens_test.dart`, `test/ui_shell_test.dart`; the limits are in the Done log entry. |
| ~~**د3**~~ | ~~E2E against the built artifact (the ب3 installer)~~ — **done 2026-11-07**, measured on the artifact built from `main` (ب4, D-026): `dist\MICS-setup-0.1.0-x64.exe`, **16,730,142 bytes**, `sha256 8984C194…`. **Install, one UAC prompt** (installs all users): 72 files under `C:\Program Files\MI CS`, the per-machine Start-Menu group (`MI CS.lnk` + `Uninstall MI CS.lnk`) and the `HKLM\…\Uninstall\MICS` row, and — folded into the same prompt — `MICSHelper` created as `"C:\Program Files\MI CS\mics-engine.exe" helper-service`, LocalSystem, AUTO_START, **running**, with `priv.log` carrying `phase=note install requested` → `phase=note service starting (pid=50128) version=0.1.0 pipe=mics_helper` → `phase=start version`/`phase=done ok=true` → `phase=note install finished, helper state=running`. Starting the installed engine **unelevated** then reported `package integrity: 68 listed file(s) match, signed by "MI CS Code Signing"` classified `untrusted-certificate` — the ج2/ط2 self-check, on the installed tree, with the honest middle state. **Privileged ops, no further prompts**: `fw.rules.add` created a rule in **37 ms** and `fw.rules.remove` removed it in **36–44 ms**, both `ok=true` in `priv.log` (P1.5). **Uninstall, one UAC prompt**: product folder, the service (`sc qc` → 1060), the uninstaller's Start-Menu group, the registry row and the shortcuts it made are all gone, exit 0 (so the helper removal did **not** take the refusal path), and `%LOCALAPPDATA%\MI CS` — the user's own copy — was never touched. `%PROGRAMDATA%\MICS` (database + audit logs) is **kept on purpose**, as `mics.nsi` says | ✅ | — | Found a real defect on the way — a firewall rule whose name already carried the `MICS-` prefix was prefixed twice and could then never be removed by the name that was given — and it was **closed 2026-11-08** (one function decides a rule name; `verify-firewall.ps1` grew to 27 checks, 0 skipped, 0 failures). |
| ~~**د5**~~ | ~~Coverage gates, `qa/report.html` + `.md`, and CI fails when a feature is not registered~~ — **done 2026-11-02**: `qa/report.md` + `qa/report.html` are committed and generated by `qa/report.dart` from the committed registries only (no clock, machine path or run timing), so `test/qa_report_test.dart` compares both byte for byte and fails the fast tier - and CI, which runs the fast tier inside `-Tier full` - when a surface moves without the report. The gates: dispatcher methods = registry rows (65 then, 66 after و1), every language directory listed under `assets:`, every `skip` reason at least 20 characters, no degenerate surface, no machine value in either file. The measured run stays in `build/qa-contract.json` and `build/pipeline-<tier>.json`, which CI now uploads next to it | ✅ | 2–4 h | `qa/report.dart`, `qa/registry.dart`, `qa/report.md`, `qa/report.html`, `test/qa_report_test.dart` |
| ~~**ز1**~~ | ~~Language off the title bar into a Settings dropdown; `AppLang` → language code + direction table; `settings.rs` accepts the bundled set~~ — **done** (2026-11-01): `AppLang` is a table (`code`, native name, English name, `direction`) and `AppLang.all` is the only list of languages in the app — the title bar's language button is gone, Settings owns a labelled dropdown that shows each language in its own script, `lib/main.dart` takes `locale`/`supportedLocales` from the table, and every `== AppLang.ar` comparison became `isRtl`. The engine now checks the *shape* of a language tag instead of a fixed `ar`/`en` list (`is_language_tag`), so a language added next month needs no engine release; `test/lang_registry_test.dart` (10 tests) keeps `AppLang.all`, `assets/i18n/` and `pubspec.yaml` in step, and a Settings behaviour test proves one dropdown pick changes the pack, the tree direction and the engine at once | ✅ | — | `lib/core/i18n/app_i18n.dart`, `engine/src/settings.rs`, `qa/methods.json`. |
| **ز2** | Crash/hang: session marker, panic/error capture, `MICS-<date>-<hash>` bug id, local bundle, delivery through `mics-engine report` (webhook / SMTP / WhatsApp), dedupe and deadlines — **first half + hang detector done** (ز2-أ 2026-11-01, ز2-ب 2026-11-02): the engine detects a panic and a run that was killed, names it `MICS-<date>-<6 hex>` (hash of the failure, not of the moment, so a repeat is counted instead of re-filed), and writes a JSON bundle plus a readable `.txt` under `<data dir>\crashes\` with the last 60 log lines and any key-shaped values redacted; `crash.list` / `crash.get` / `crash.delete` read them, and the contract harness proves the whole loop across two real processes (kill one engine, start another, one report, right pid). **ز2-ب adds the hang half that only an OS thread can report**: a `std::thread` watchdog started with the session watches a heartbeat the runtime bumps (a 5 s timer task plus every request), and after a 20 s silence files one `hang` report saying how long the runtime was stuck and what the last request was — measured 2026-11-02 with 106 engine tests, including a deliberately frozen heartbeat and a proved absence of false reports; a hang that takes the whole process stays invisible by design. **Left: delivery (ز2-د)** — and **ز2-ج landed 2026-11-02**: Settings → Diagnostics lists those reports (`crash.list`), opens one (`crash.get`), copies the paste text whose **first line is the bug id**, and deletes one (`crash.delete`) by re-reading the list afterwards; measured with 114 Dart tests and exactly four new controls in the committed ledger. Delivery is blocked on **D-023**, and the WhatsApp path is now specified as an Open WhatsApp bridge rather than WhatsApp itself. **Left: delivery only (ز2-د)** | 🟠 | 12–16 h | No third binary (the names are frozen by D-020); nothing in `crash.rs` names a URL. |
| **ز3** | In-app cards: bottom corner, right for LTR and left for RTL, fed by the existing alert gate (`LOW` finally has the in-app home `alert.rs` already describes) — **done 2026-11-02 (D-024)**: the gate gained `decide_in_app` (every severity, DND the only switch, `toast_enabled` is the desktop's), cards leave as an `alert` push and are parked in a 5-card queue when no UI is attached, the shell paints at most three in a `PositionedDirectional` inside its own `Stack` (measured: `right = 1682` in LTR, `left = 18` in RTL, two new controls in the ledger), and a filed crash report raises a card carrying its bug id and saying delivery is off | 🟡 | 2–3 h | No state a report does not have: until ز2-د lands, a card may only say delivery is off. |
| ~~**ط1**~~ | ~~Fingerprint sweep + ratchet~~ — **done 2026-11-02**: the Rust build compiles with `--remap-path-prefix=$env:USERPROFILE=/build` in `make-release.ps1` and `engine.build`, so the account name that appeared **1238** times in `mics-engine.exe` is now **0** (and `/build` replaced it in every crate path); `scripts/verify-opsec.ps1` measures the package against `qa/opsec-baseline.json` (9 binaries; totals **2301** `flutter`, **915** `dart`, **1242** `cargo`, **97** `rustc`, **1** `pubspec`, each row with a written reason), fails when a count rises or a binary is unlisted, and runs inside `make-release.ps1`; `test/opsec_baseline_test.dart` keeps the file honest in the fast tier. The framework strings are the allowlist and may only fall. The remap is *appended* to the crate's own flags by `scripts/engine-rustflags.ps1` rather than replacing them (`CARGO_ENCODED_RUSTFLAGS` overrides `.cargo\config.toml`; doing it by hand cost the engine its CFG table, and the hardening gate in `make-release.ps1` caught it the same day). | ✅ | 3–5 h | `scripts/verify-opsec.ps1`, `scripts/engine-rustflags.ps1`, `qa/opsec-baseline.json` |
| ~~**ط2**~~ | ~~Tamper tests: a byte flip per binary, a swapped DLL, an edited manifest, a copied install — each must be refused or reported~~ — **done 2026-11-03** | ✅ | 2–3 h | `scripts\verify-tamper.ps1` tampers one thing at a time in a private copy under `%TEMP%` and asks both halves (the release gate must refuse, the packaged engine must answer `unverified`, name the file and push the card); the published package is the control. 41 checks, 0 failures, 108.5 s, and `tamper.verify` is the third release step. It also found that a **stripped signature** used to pass `verify-manifest.ps1`, which now requires the pinned `MI CS Code Signing`. |
| ~~**ط3**~~ | ~~the `-Tier release` wiring~~ — **done 2026-11-02**: `scripts\pipeline.ps1` gained its first `release`-tier step, `opsec.verify`, which runs `verify-opsec.ps1` against `dist\MICS-portable` (the packaged artifact, not the build folder); `-Tier release -List` shows it last and `-Tier release -Only opsec.verify` passes on the published package and fails on a stale one. The tier's help text now says the verifiers land one per slice. | ✅ | 1–2 h | `scripts\pipeline.ps1` |
| ~~**هـ1**~~ | ~~Default update-manifest URL compiled in + signature check on the manifest before applying~~ — **done 2026-11-09 (D-046 for the feed, D-047 for the signature)**: the channel carries the project's own feed, `resolve_update_url` orders environment → saved URL → channel default, `update.check` uses the downloader's one implementation and names the feed that answered, `MICS_UPDATE_MANIFEST_URL=off` disables explicitly, and the release lane publishes `update.json` (`scripts\update-manifest.ps1`, `make-release.ps1` step 9). The signature is a detached PKCS#7 beside the manifest (`sign.ps1 -DataFile`, step 9b) that the engine verifies over the exact bytes **before** parsing, pinning the signer to the certificate over the engine or to `MICS_UPDATE_SIGNER_THUMBPRINT`; unsigned, other-key, tampered and wrongly-pinned feeds are refused with the signature as the reason and stage nothing, measured by `scripts\verify-update.ps1`. | ✅ | — | `engine\src\update.rs`, `engine\src\platform\windows\signature.rs`, `scripts\verify-update.ps1` |
| ~~**ب2**~~ | ~~ARM64 leg: Flutter target + `aarch64-pc-windows-msvc` engine, `verify-release.ps1` aware of the arch~~ — **done 2026-11-03 as far as this machine allows**: `scripts\build-engine-arm64.ps1` builds the engine **and** its test binaries for `aarch64-pc-windows-msvc` (measured: engine 19,994,112 bytes, PE `machine 0xAA64`, CFG/ASLR/DEP, stripped, `verify-hardening.ps1 -Arch arm64` PASS; test binaries linked too), `make-release.ps1` gained `-Arch` + `-CheckToolchain` (7 prerequisites, **NOT READY 2/7** here), `verify-release.ps1` takes the arch from the artifact's name and `VERSION` line, and `engine-rustflags.ps1` picks the flags by triple. The Flutter half has no Windows ARM64 path on this machine (no cross-compile flag; the SDK ships `windows-x64*` only); on CI an ARM64 host is available (`windows-11-arm`, which this entry wrongly called public-only - corrected 2026-11-04 in D-003), and `.github/workflows/release.yml` now carries the two ARM64 jobs, marked informational until they have a green run - that is where the "nothing was executed" gap can finally be closed. **No ARM64 hardware here: nothing was executed on this machine.** **Correction 2026-11-04, measured on the first CI run:** Flutter publishes no Windows ARM64 SDK (0 of the 747 archives in `releases_windows.json` mention arm64), so the packaging job's `Setup Flutter` died with `Unable to determine Flutter version for channel: stable version: any architecture: arm64` (run 41922523593, job 126898444291). The job now asks for the **x64** SDK (run under emulation) and for `targets: aarch64-pc-windows-msvc` - the target `make-release.ps1 -Arch arm64` checks for - and stays informational: a green run would be the first real ARM64 app, a red one means Flutter's Windows tooling cannot produce it yet, while the engine half is already real (the ARM64 job runs the engine's tests natively). | ✅ | 3–5 h | `scripts\build-engine-arm64.ps1`, D-003 addendum |
| ~~**و1**~~ | ~~**Scheduled scan** (closes half of the MED row "no scheduled scan and no real-time watching")~~ — **done 2026-11-03 (D-027, two commits)**: `scan_interval_hours` (0 = off, default) + `scan_target` (empty = profile), a five-minute tick in both `--serve` and `--service` that calls the same `start_scan` with `quarantine: false`, the engine's own record of the last start in a new `meta` table, `scan.schedule` for the UI/QA, and the Settings switch + folder field with ar/en copy. Proved by 6 unit tests on the pure `is_due` rule, 2 on the settings, a behaviour test that the pick reaches the engine, `scripts\verify-scan-schedule.ps1` (18 checks, 11.6 s) against a real release engine, and a 98 → 100 control ledger (adding the section exposed a sweep hole: controls below the fold were tapped where they were and the tap missed silently — the harness now scrolls them into view and pages through lazily built lists). The register's MED row is now only about real-time watching (و2) | ✅ | — | Cheapest MED row with user-visible value. |
| **و2** | Real-time file watching (`ReadDirectoryChangesW`/USN) | 🟠 | 6–10 h | **Architectural decision** (CPU cost, product behaviour) — bring it to the user first. |
| ~~**و3**~~ | ~~`netsh` → **FirewallAPI COM**~~ — **done 2026-11-03 (D-028)**: `engine\src\firewall\mod.rs` speaks `INetFwPolicy2`/`INetFwRules`/`INetFwRule` in-process instead of spawning `netsh advfirewall` and parsing its English text, with the same public shape and the same helper payloads (so D-007's audit trail and refusals are untouched). Typed values replace matched strings, every rule sets an explicit all-profiles mask (the API's default is *no* profile, i.e. a rule that never fires) and the "MI CS" group, and a port without a protocol is refused with the fix named. Two measured traps are recorded in the decision: a COM interface released after `CoUninitialize` is an access violation (field order in the guard struct), and the rule enumerator hands out `VT_DISPATCH`, not `VT_UNKNOWN`. Proved by `scripts\verify-firewall.ps1` (23 checks, 8.7 s against the release engine): reads compared field by field with `Get-NetFirewallProfile`/`Get-NetFirewallRule`, one rule created/read back/removed, and a fake `netsh.exe` on PATH that proves the dependency is gone. Deliberately not measured: the default-deny write (it would cut the machine's network) and a country-sized `RemoteAddresses` ceiling | ✅ | — | Removes the external-process dependency for firewall changes. |
| ~~**و4**~~ | ~~Executable LOW rows (GeoIP lists, detection-pack size, guard cost, plaintext keys, method gaps)~~ — **done 2026-11-03, five commits (a–e)**: keys DPAPI-protected, blocking `vuln.scan` deleted, merged-audit ages shown, guard cost re-measured; three rows closed by evidence (incomplete package refused with exit 1, portable caller check measured in `verify-helper.ps1`, AUMID attribution as a documented limit). See the Done log in `docs/TODO.md` | ✅ | 6–10 h | 1–3 h each. |
| **ب5** | **A publicly trusted signature — free, after D-036 (2026-11-07) reopened what D-035 had closed — and route A's artifact now exists (D-037).** Nothing is bought; the signature comes from somebody who signs for free, and [`docs/SIGNING.md`](SIGNING.md) is the record of every route with its source and date. **Route A — the Microsoft Store**: publishing an MSIX package makes signing "free and handled for you automatically — Microsoft re-signs the package after certification" (their words), the developer account is free (the $19 fee is waived; ID + selfie; "nearly 200 markets worldwide"), and SmartScreen shows **no warnings**. `installer/msix/AppxManifest.xml` + `scripts\make-msix.ps1` now build that package — measured 2026-11-07: 75 payload files, **22.11 MB**, **3.6–4.3 s**, makeappx accepting the `desktop6:Service` declaration and both restricted capabilities. The install is blocked by two measured facts, not by our manifest: a self-signed chain has no trusted root (**0x800B0109**, and user-level trust is not enough), and Windows requires an administrator for any packaged service (**0x80073D28**). So what is left here is the free account and Microsoft's answers — **not an administrator**: the shape submitted first declares no service and registers with no elevation at all, measured as an A/B against the same staged folder (**D-038**), which also drops the two restricted capabilities from the submission. **That shape's app half was then run for real on 2026-11-07**: the packaged app started its own engine from the package folder, `\\.\pipe\mics_engine` came up, the guard started, the integrity self-check reported `ok — 68 file(s) hash as the manifest says` from inside the container, and state went to the real `%LOCALAPPDATA%\MICS` rather than a package-private store; what no unelevated session can measure is the helper reached *across* the container, because installing one needs an administrator. **The acceptance check for this row now exists**: `scripts\verify-trust.ps1` exits 0 only for an artifact a stranger's Windows would trust — judged by issuer, chain and root store rather than by `Status`, which reports `Valid` for our own self-signed engine on this machine — and `-SelfTest` proves the instrument against both a self-signed control and `kernel32.dll` (`docs/SIGNING.md` §1). **Route B — OSSign**: a certificate issued to the *project*, signed keyless over OIDC so the repository holds no secret, once the repo is 6 months old — created 2026-10-27, so ~**2027-04-27**; their queue was closed in 2026-09. | ✅ **free, not yet done** | route A: the free account (packaging is done, and the shape submitted first needs no administrator, D-038); route B is a date | Closed on the record: **SignPath** cannot sign "security diagnosis tools that actively scan for and highlight exploitable vulnerabilities, e.g. by identifying unprotected network ports" (verbatim, and their signed list — Fibratus, sniffnet — shows the line is *breach detection yes, posture audit no*); **Azure Artifact Signing** is paid *and* Egypt is not in its Public Trust geography; the Store's **MSI/EXE path** still wants our own CA certificate; **Sigstore** means nothing to Windows. The paid research stays in `docs/COST.md` §2 (Certum Open Source €49 in the cloud — the one product that prints the maintainer's name), and `scripts\sign.ps1 -Thumbprint` plus D-034's two secrets keep a **donated** certificate a drop-in. **No CA can issue `CN=MI CS Code Signing`** (CSCBR §9.2.2), so the D-016 pin still moves to a thumbprint in the release that first carries any certificate. |
| **ب6** | Public release: ZIP + installer, version bump, README updated | ✅ **done 2026-11-10** | 1–2 h | **Published, and verified against its own release page the next day; the "signed" half is free but not built yet** (D-035 + D-036: the Store route re-signs an MSIX for free and needs packaging work, the OSSign route is a calendar row — [`docs/SIGNING.md`](SIGNING.md)). Measured 2026-11-05: the repository is public, the tag `v0.1.0` is on `da77bb3`, and Release run **42040718389** was green end to end — `Package (x64)` built, signed, installed, verified and uploaded, and `Publish` created the release as a **draft**, and the workflow said so itself (`draft v0.1.0 created - publish it from the Releases page when the hashes read right`). **The owner published it on 2026-11-10** (D-031), and the download was verified on 2026-11-11: `MICS-setup-0.1.0-x64.exe` **16,642,682 bytes** `sha256 5cd206db...`, `MICS-portable-0.1.0-x64.zip` **23,111,206 bytes** `sha256 1eafe3ee...`, `SHA256SUMS` and `report.md`; all three published hashes re-hashed and matched, and the unpacked portable package reports `PASS - all 67 listed file(s) hash as the signed manifest says`. The sizes this row carried before that check (16,730,142 and 22,552,651 bytes) turned out to be the **2026-11-07 local rebuild's**, not the draft's own bytes — the lesson the register keeps teaching: a number in a document is a claim until something measures it. Two facts the check added are rows of their own: the setup EXE is `NotSigned`, and the certificate that signed the package is minted per build (**ب7** below). |

## 3. The order to work in

**The approved track (2026-11-01) runs first, one commit per step:**
**ز0** *(done)* → **د1** *(done)* → **د2** *(done)* → **ز1** *(done)* → **ز2-أ** *(done)* → **ز2-ب** *(done)* → **ز2-ج** *(done)* → **ز2-د** (delivery, blocked on D-023) → **ز3** *(done)* → **ط1** *(done)* → **ط3** *(done)* → **د5** *(done)* → **ج2** *(done 2026-11-03, both commits)* → **ط2** *(done 2026-11-03)* → **ج3** *(done 2026-11-03)* → the release lane: **ب4** *(done 2026-11-03)* and **د3**
(E2E on the built installer), which needs one UAC click from a human, then **هـ1** *(done
2026-11-09: the feed by D-046, the manifest signature and its pin by D-047)* and
**و1** *(done 2026-11-03)*, then **و3** *(done 2026-11-03)* and **و4** *(done
2026-11-03, five commits)*, then **ب2** *(done 2026-11-03: the ARM64 engine builds
and is checked, nothing was run)*.
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
3. ~~**ب4 helper fold-in**~~ — **done 2026-11-03** (D-026): the installer creates the
   privileged helper inside its one prompt and removes it on uninstall, so an installed
   copy never asks for administrator rights twice — see the installer note at the top of
   this file. Left for a human: the same per-machine run.
4. ~~**ج2 signed manifest + self-check**~~ — **done 2026-11-03** (both commits): the
   package describes itself inside the engine's own signature, the engine checks that
   at start-up and Settings → About answers with one line — see the phase note at the
   top of this file. **ط2 followed it the same day** (the tamper probe, and the third
   release-tier step): `scripts\verify-tamper.ps1` proves both halves catch a flipped
   byte, a same-size swapped DLL, an edited manifest, a repack into an unsigned engine
   and a copied install — and it found a stripped signature slipping past the gate.
5. ~~**د1 + د2 QA**~~ — **done 2026-11-01**: the contract harness over every method,
   every screen and control swept against the same fixtures. The QA phase's last row,
   **د3**, ran on 2026-11-07 (item 7).
6. ~~**هـ1 + و1**~~ — **both done**: و1 on 2026-11-03; هـ1's update feed on 2026-11-09
   (D-046) and the signature over the manifest, with the thumbprint pin, the same day
   (D-047). Nothing is left here; the certificate that would make the pin checkable by
   a stranger is ب5, a free account and a click.
7. ~~**ب2 ARM64, د4**~~ — **done 2026-11-03** (ب2: the engine leg builds and is
   checked, nothing run; د4: the QA report was already generated, byte-gated and
   uploaded). **Item 7 is closed**: د3 ran on 2026-11-07 — install, helper creation,
   unelevated privileged ops and uninstall, all measured; see the د3 row in §2.
8. ~~**ب6** — publish the draft~~ — **done 2026-11-10 and verified 2026-11-11**, so the row that
   takes its place here is **ب7: one signing identity per release, before the next publish.**
   `make-release.ps1` mints a certificate for each build, and D-051's pin is the identity of that
   build — so a second release signed by a second certificate would be refused by the first
   (fail-closed, but a defect). Free, and nothing left that code can do: the lane keeps one
   certificate once it is given one, and both halves of "given one" are now built and measured —
   `scripts\verify-signer-identity.ps1` (new, **18 checks**) signs scratch manifests with one PFX
   twice and with a second PFX once, and shows the first pair carrying one thumbprint (equal to the
   certificate inside the PFX) while the second carries another one, which is what the engine refuses
   (`scripts\verify-update.ps1`, cases 4 and 7); the same probe holds the names end to end — the
   workflow's `secrets.MICS_PFX` → `MICS_PFX_B64` → the lane's `-PfxPath`, one `@signArgs` for the
   binaries and the feed, and the four readers of `MICS_UPDATE_SIGNER_THUMBPRINT`. A release report
   now prints `pinned : <thumbprint>` (the certificate the engine over that build will trust when it
   judges the *next* release) and, when the identity is the throwaway one, a `WARN` saying the key is
   deleted before the script returns and no later release can be signed by it. **So what remains is
   one secret, not one commit**: keep a certificate in `MICS_PFX`/`MICS_PFX_PASSWORD`
   (`docs/SIGNING.md` section 7 item 6 has the copy-paste recipe), and the environment hook
   `MICS_UPDATE_SIGNER_THUMBPRINT` is *not* a substitute — it has to name the next release's
   certificate, which is only knowable once an identity is kept. **ب5 is no longer a prerequisite**
   for anything — nothing is bought (D-035) and the signature has two free routes (D-036,
   `docs/SIGNING.md`), neither of which blocks a download: the Store route is packaging work and the
   OSSign route is a calendar row.

9. ~~**The register's "engine missing and no reason given" row, with §0.6 row 10**~~ —
   **done 2026-11-10** (small step 9): a failed start re-runs the engine once with
   stderr piped, keeps the last twelve lines it printed and shows them in Settings →
   Engine under *Why it would not start*, so the refusal a Low-integrity folder
   produces is readable instead of a retry that cannot succeed; the two documentation
   debts behind it are closed in the same commit.

## 4. Blocked on the user (do not plan around these)

Recounted **2026-11-07**; the long form with the measured state is `docs/TODO.md` §0.2.

**Neither acceptance item is waiting on you any more** — both ran on 2026-11-07, the publish click
was made on 2026-11-10, and what is left is **one secret and a minute of your time** (ب7: mint one
release certificate, keep it as `MICS_PFX` + `MICS_PFX_PASSWORD` — the recipe is
`docs/SIGNING.md` section 7 item 6) plus the four decisions in item 3 that still wait on you (of six briefs, (c) is settled and (f) is answered).

1. **د3 — done, measured 2026-11-07.** The per-machine setup rebuilt from `main`
   (`dist\MICS-setup-0.1.0-x64.exe`, 16,730,142 bytes, `sha256 8984C194…`) installed all
   users in **one** UAC prompt: 72 files under `C:\Program Files\MI CS`, the
   `HKLM\…\Uninstall\MICS` row, the per-machine Start-Menu group, and — folded into the
   same elevation — `MICSHelper` created as
   `"C:\Program Files\MI CS\mics-engine.exe" helper-service`, LocalSystem, AUTO_START and
   **running**. The uninstaller then removed the product, the service (`sc qc MICSHelper`
   → 1060), its shortcuts and the registry row in its own **one** prompt, exit 0 — so the
   helper removal did not take the refusal path — and `%LOCALAPPDATA%\MI CS` (the user's
   own copy) was never touched. `%PROGRAMDATA%\MICS` is kept on purpose.
   The "zero further prompts" half was proven against the **real** service, not
   `helper-console`: driving the installed engine **unelevated**, `fw.rules.add` created
   a rule in **37 ms** and `fw.rules.remove` removed it in **36–44 ms**, each a
   `phase=start`/`phase=done ok=true` pair in `%PROGRAMDATA%\MICS\logs\priv.log`, with no
   prompt. Also verified on the installed tree: the start-up self-check re-hashed **68 of
   68** listed files and classified our own signer as `untrusted-certificate`.
   **What was deliberately not exercised:** *Default deny outbound* would cut this
   machine's own network path mid-run, so it was left alone rather than measured; the
   SMBv1 toggle and the hosts write were skipped for the same class of reason (the hosts
   file already carries a `# BEGIN MICS-IDS` section). The د3 row in §2 has the detail.
2. **~~A signing certificate (ب5).~~** **Closed 2026-11-07 as not-purchased (D-035)** —
   not waiting for you, and no longer on the plan. This is a free, open-source project
   with no budget, so nothing is bought. `docs\COST.md` §2 stays as the record of routes
   that are all either paid or closed to this product category (Certum Open Source
   €49/year in their cloud — the only route that prints the maintainer's name and the
   only one matching D-034's plain `signtool /sha1` call; SSL.com IV $129/year plus
   eSigner; SignPath's free programme excludes tools that scan for vulnerabilities and
   wants an already-released project with reputation; Azure Artifact Signing is not
   purchasable from Egypt). The subject can never stay `CN=MI CS Code Signing`
   (CSCBR §9.2.2), so the D-016 pin must move to a thumbprint in the same release that
   first carries any certificate. The certificate's job is done instead by the manifest
   self-check, the published `SHA256SUMS` and F-11's reproducible build (**landed
   2026-11-08**: `scripts\verify-reproducible.ps1` rebuilds the published archive and
   compares it, `docs/REPRODUCIBLE.md` is the recipe); and if one is
   ever **donated**, D-034's two secrets install it with no code change. And those two secrets are now also the answer to **ب7**, the row the
   publish verification created — one signing identity kept across releases, because D-051's pin makes each engine refuse a payload signed by a different certificate. **What this item used to lead to, ب6 — publish the draft — is done: 2026-11-10.**
3. **Four decisions that each stop ready work** (six briefs, of which (c) is settled by D-035 and (f) is answered and implemented by D-049) - one-page briefs, with the cost of every
   option and a recommendation, are in `docs/OPEN-DECISIONS.md`: whether licensed GeoIP
   lists may be
   bundled; starter pack vs real detection rules (measured 2026-11-05, D-033: 8 of the
   10 shipped rules are now held to a file, one of those only sees an uncompressed
   container because a real `.docm` deflates its macro strings, and 2 cannot be proven
   by a text file at all); thumbprint pin vs CN (D-016);
   IDS beyond DNS; real-time watching (و2); and the language-tag policy (measured:
   the engine accepts any BCP-47-shaped tag by design, the UI resolves exact code then
   the primary subtag and then falls back to Arabic while missing keys fall back to
   English). The
   publishing destination was the seventh and is answered (GitHub Releases).
4. **D-023 and the bridge endpoint** - what holds ز2-د (crash-report delivery), and a
   choice no code can make for you (AGENTS.md 8 forbids inventing a destination).
5. **A Windows on ARM machine** (optional): the engine builds and is checked for
   ARM64, and CI now supplies a host where it genuinely *runs* - the release
   workflow's `windows-11-arm` engine job executes the engine's tests natively
   (informational until it has a green run). The **app** half cannot follow it
   today: Flutter publishes no Windows ARM64 SDK (0 of 747 archives, measured
   2026-11-04), so the packaging job runs the x64 SDK under emulation and stays
   informational until a run says what that produces.
6. **~~Public or private repository~~** - **decided and prepared 2026-11-04: this
   repository goes public.** The history was rewritten in place first (git-filter-repo:
   `dist/` build artefacts dropped, the machine account name scrubbed from old
   revisions) - 147 → 145 commits, no `dist/` path and no account name left in any
   commit, HEAD's tree identical, `.git` 106.4 MB → 7.1 MB - and **one version
   number: 0.1.0**. What remains is the force-push and the visibility switch (both
   in `docs/TODO.md` §0.2a) and the نسخة bundle of the old history, which is the only
   copy left of it.

## 5. Out of scope by design (not "remaining work")

No kernel driver, no pre-execution blocking, no inline network filtering, no
Suricata/ET-Open, no ClamAV/CAPA, no anti-tamper watchdog. Each is written down
with its reason in `docs/THREAT-MODEL.md` (§6 residual risks) and
`docs/PROTECTION-MATRIX.md` (§9). They are product decisions, not backlog items —
reopening one needs a new entry in `docs/DECISIONS.md`. (**A read-level canary left
this list on 2026-11-05**, D-032: it is a snapshot field, not a driver, and what it
costs is that it only works on a volume that keeps last-access times — which the
copy now measures per volume and reports instead of assuming.)

## 6. How every step ends

One conventional commit, `docs/TODO.md` updated in the same commit (the finished item
moves to the Done log, it is not just ticked), this file's row updated, and the four
checks green: `cargo test`, `cargo clippy --release -- -D warnings`,
`flutter analyze --no-pub`, `flutter test --no-pub`. Say what was **measured**, not
just what changed.
