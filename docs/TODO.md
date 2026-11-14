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
> Last updated: 2026-11-08 · **the documents were audited against the code on 2026-11-07 and then
> re-planned around a hard constraint the project had not written down: it is
> open source with no budget, so nothing can be bought** — no certificate, no tool,
> no service. Two consequences. *(a)* **The documents were wrong in places, and are
> fixed**: the JSON-RPC surface is **73** methods (measured 2026-11-09; the recount of
> 2026-11-07 found 66 where the docs said 65, and the ROADMAP said 62 in
> one row); i18n is **19 module files per language / 307 keys** (measured
> 2026-11-13 with D-054; the 2026-11-13 count of 303 was right when taken and four
> keys have landed since, all on the Explorer entry — the file and folder labels,
> the Settings switch and its hint — before which the 2026-11-10 count of 301 was
> right when taken and two keys have
> landed since, both on the tray's exit — its full-exit label and its hint,
> D-053 — before which the 2026-11-09 count of 299 was right when taken and two
> keys landed with the engine-refusal line and the unrenderable-tag notice), not
> 16/169; the
> README's canary claim ("a read-only open is not noticed") was true until **D-032**
> landed and is now the opposite — a read is a HIGH `canary_read` event, with the
> volume's atime range probed and reported; the README presented `v0.1.0` as a
> **download** while the release is a **draft** and the public page says "There aren't
> any releases here"; the README quoted `~11 MB` idle RAM (measured **12.5 MB**) and
> `~150 MB` of disk (measured **51.9 MB** — the 150 was the engine's RAM *budget*
> read as a disk figure); test counts were two generations old; and **`LICENSE` was a
> 5-line placeholder** ("Full GPL-3.0 text would be here") in a repository that
> advertises GPL-3.0-or-later — it now holds the verbatim GPL-3.0 text (35,149 bytes,
> `sha256 3972DC97…`, from `gnu.org/licenses/gpl-3.0.txt`). *(b)* **The paid step is
> off the plan and replaced by a free trust story** — see **D-035**, §0.2 item 2 and
> the new **§0.6**, which is the one-table answer to "what is actually left".
> *(c)* **The one acceptance run that needed your hands ran, and it closed two items
> and found a defect** — on **2026-11-07** the per-machine installer was rebuilt from
> `main` and taken through install → helper creation → privilege-without-a-prompt →
> uninstall, one UAC prompt each: 72 files under `C:\Program Files\MI CS`, `MICSHelper`
> created by the installer and running as LocalSystem, `fw.rules.add` and
> `fw.rules.remove` executed by that service in **37 ms** and **36–44 ms** with **no**
> prompt, uninstall exit 0 leaving only the state folder that `mics.nsi` keeps on
> purpose, and the user's own `%LOCALAPPDATA%\MI CS` untouched throughout. **د3 and
> P1.5 are done, not pending** — and the run paid for itself by finding a real defect
> the register had never suspected: a firewall rule whose name already begins with
> `MICS-` is prefixed twice and can never be removed by the name that was passed (§7,
> MED). What it deliberately did **not** exercise, and says so: *Default deny outbound*
> (it would cut the machine's own network mid-run), the SMBv1 toggle and the hosts
> write.
> **The certificate question has prices, and two of its old assumptions are dead**
> (research pass: Microsoft's own comparison gives public
> trust to organizations in the USA/Canada/EU/UK and to individuals in the **USA and
> Canada only** — so Azure Artifact Signing cannot be bought from Egypt; EV **stopped
> buying a SmartScreen bypass in 2024**; CA/B ballot CSC-31 capped a code-signing
> certificate at **460 days** from 2026-03-01; and CSCBR §9.2.2 requires the subject CN
> to be the verified legal name, so **no CA can ever issue `CN=MI CS Code Signing`** —
> the D-016 pin moves to a thumbprint in the same release as the purchase, or
> `update.rs:128` refuses our own update. The routes for an individual with no company:
> Certum Open Source €49/year in their cloud (their CN becomes "Open Source Developer
> <name>", and their cloud signs only while a logged-in SimplySign session holds the
> virtual card, so it wants a persistent/self-hosted runner), or SSL.com IV $129/year +
> eSigner $180/year whose own action signs on GitHub-hosted runners. **The free route is
> closed, not merely awkward**: SignPath Foundation's code of conduct excludes "security
> diagnosis tools that actively scan for and highlight exploitable vulnerabilities, e.g.
> by identifying unprotected network ports" — this product's audit half — and
> independently requires an already-released project with a verifiable reputation (this
> repository: 0 releases, created 2026-10-27). `docs\COST.md` §2 has
> the sources and the date each figure was read) ·
> **the certificate is two secrets, not a code change** (D-034:
> `scripts\sign.ps1` takes exactly one identity — self-signed, a PFX, or a certificate
> already in a store by SHA-1 thumbprint, which is what a token or a cloud agent needs —
> and `make-release.ps1 -Sign` resolves the identity in one documented order and prints it
> *before* the build, so a misspelled secret costs ten seconds instead of ten minutes;
> `scripts\verify-signing.ps1` — 18 checks, PASS — measures every refusal it makes. The
> honest limit is written where the claim is: with no CA certificate the two production
> modes end in "did not verify" and exit 1, because `Valid` is what a CA-issued certificate
> produces, so that half stays unproven until the certificate row is bought) ·
> **the signature is free after all** (D-036, 2026-11-07: the earlier research asked
> *which CA gives this project a free certificate* — none does — and never asked *who
> else can sign for us for free*. **Microsoft** can: publishing an MSIX through the
> Store makes signing "free and handled for you automatically", with a free developer
> account in ~200 markets and no SmartScreen warnings. **OSSign** can: a project-level
> certificate once the repository is six months old (~2027-04-27), signed keyless over
> OIDC so the repository stores no secret. SignPath stays closed in their own words —
> they cannot sign tools that "actively scan for and highlight exploitable
> vulnerabilities, e.g. by identifying unprotected network ports", which is our audit
> screen. Every route, source and date is in **`docs/SIGNING.md`**; route A needs
> packaging work, not money) ·
> **the shipped detection pack is measured by what it catches,
> and the first rule that could never fire is fixed** (D-033: one vector per rule in
> `engine\testdata\detection`, a unit test in the fast tier, `scripts\verify-rules.ps1` —
> 35 checks, PASS — and `verify-release.ps1` now runs it against the packaged `rules\`;
> `Malicious_Macro_AutoOpen` compared the zip magic against `"KP"`, so it could never
> match a real `.docm`) · **a decoy read is detected, and the coverage behind it is
> measured** (D-032: HIGH `canary_read` read off the file's last-access time, its own
> rule id so reads can be quieted alone, a 90 s settle window for a decoy MI CS has just
> written, and `scripts\verify-canary.ps1` — 20 checks, PASS — against a real engine; the
> probe caught the verdict naming the *previous* decoy folder, which the register row
> never would have) · **the release pipeline is green end to end and the first
> release exists as a draft** (run 42040718389: x64 packaged, verified, uploaded, and
> `Publish` created `v0.1.0` as a draft for your click - D-031), after three fixes that
> each had a measurement behind them: the certificate dialog that stalled two runs, the
> tamper test's third answer (`untrusted-certificate`), and the elevated runner token that
> made a refusal probe fail a release. · Earlier: · P1, P2 (settings/i18n/sounds/theme), P3 (badge +
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
> `Command::new`) plus **a fix re-checks one audit section and still reports the
> whole machine's score** (D-014), **`docs/THREAT-MODEL.md` exists with the two
> pipe ACLs measured and eight residual risks filed**, and **the engine pipe now
> refuses every caller but its owner, SYSTEM and administrators** (F-1 closed,
> D-015) and **`docs/PROTECTION-MATRIX.md` says per layer what detects, what
> blocks and what is missed** (with the starter-pack and no-real-time-watch limits
> written down instead of implied) and **the light-mode palette measured against
> WCAG 2.2 and then fixed** (أ2: 36 pairs, 25 failing · أ3: 29 pairs, **29
> passing**, every ratio pinned by a test — `docs/CONTRAST.md`) and **the AUMID is
> registered** (`scripts\register-aumid.ps1`: `DisplayName "MI CS"` under
> `HKCU\Software\Classes\AppUserModelId\MICS`, plus `System.AppUserModel.ID` on both
> shortcuts, so the Shell files the app under `MICS` instead of under the exe path;
> `scripts\verify-aumid.ps1` reads all of it back, and `-Remove` reverses it) and
> **what is inside the package is now written down**: `tool\sbom.dart` generates a
> CycloneDX 1.6 `sbom.cdx.json` + `THIRD-PARTY-NOTICES` from the lockfiles (579
> components, 8 licenses, 0 copyleft, 0 unclassified, every text present), the pair
> is committed, shipped in the ZIP and freshness-checked before every release
> (ب1a, D-018) and **the release binaries are hardened with the PE to prove it**
> (ج1, D-021: Control Flow Guard on both binaries, LTO + `panic=abort` + stripped
> engine, obfuscated Dart snapshot whose symbols never enter the package, and
> `scripts\verify-hardening.ps1` gates the release on what the file says rather than
> on the flags) ·
> **next: the repository is public and its first CI run is on the record**
> (`Release` 41922523593, `CI` 41922021833 on `5eb956a`): `Package (x64)` failed at
> the step that is green on this machine (`make-release.ps1 -Sign`, re-run here:
> `RESULT: PASS`), `CI` failed inside `Pipeline (full)` with **"135 tests passed, 1
> failed"** — the Dart suite is 136 cases and passes here even in a fresh clone and
> with the runner's environment forced, so the failing test's name has to come from
> the run's log (it needs a signed-in browser; the public API answers 403). The
> **ARM64 diagnosis is done and fixed**: Flutter publishes no Windows ARM64 SDK
> (0 of 747 archives), so the job now asks for the x64 SDK and for
> `targets: aarch64-pc-windows-msvc`, and both ARM64 jobs stay informational.
> **2026-11-14: the red `package-arm64` job was the gate reading the wrong two
> things.** In `Release` 43588227581 the ARM64 engine job built, linked and ran its
> suite **natively on the same `windows-11-arm` image** (green, 22m41s) while the
> packaging job refused with `NOT READY - 2 of 7` — which is proof the runner has
> the SDK's ARM64 import libraries, so that row was the check and not the machine:
> it looked at `Windows Kits\10\Lib\<newest version>` only, while
> `build-engine-arm64.ps1` keeps whichever version actually *has*
> `um\arm64\kernel32.lib` (a newer SDK for another architecture can sit beside an
> older one that has them), and it looked under `Program Files (x86)` only. The
> second row is a state, not a capability: nothing downloads the host's Flutter
> engine artifacts until something asks, and the gate runs before the build, so on
> a buildable host it was guaranteed missing — the CI job now runs
> `flutter precache --windows` first and prints `PROCESSOR_ARCHITECTURE`,
> `dart --version` and the artifact directory, so a MISSING there now means the
> precache could not fetch one. Locally `-CheckToolchain` still reports the same
> two missing (Flutter engine, ARM64 host). Both ARM64 jobs keep
> `continue-on-error`: the answer is the next run's, not this commit's. The
> release lane is otherwise in place: `.github/workflows/release.yml` (`version`,
> `package-x64` 10 steps, `engine-arm64`, `package-arm64`, `publish`),
> `make-installer.ps1 -Arch` and the arch-aware NSIS guard (built and checked for
> x64, refused for arm64 on an x64 package). The last release-lane
> item that needed you at the machine was **د3**
> (E2E on the built installer) — **it ran on 2026-11-07 and is closed**: one
> per-machine run, one prompt each way, and with that click the whole product has now
> been measured as a user meets it (§0.2 item 1). **Nothing in the release lane waits
> on you any more: the publish click was made on 2026-11-10, and again on 2026-11-14
> for `0.1.2`, which is the live release as this is written — `0.1.3` is cut on top of
> it to carry the ARM64 measurement.** The
> download it produced was verified on 2026-11-11 — four assets, three hashes
> re-checked against the published `SHA256SUMS`, and the portable package
> `PASS` against its own signed manifest — which closed §0.6 row 1 and left
> **ب7 (one signing identity per release)** as the first engineering item, since
> `v0.1.0` was signed by a certificate minted for that build. **Its engineering half
> landed 2026-11-12**: `scripts\verify-signer-identity.ps1` (18 checks) measures that
> one PFX gives every build one identity and a second PFX a different one, and
> `make-release.ps1`'s report now names the identity (`pinned : <thumbprint>`) and
> warns when that identity is one whose key the script deletes before returning. What
> is left is not work: keep a certificate in `MICS_PFX`/`MICS_PFX_PASSWORD`
> (`docs/SIGNING.md` §7 item 6), before the next publish. ز2-د stays blocked on D-023
> and the
> bridge endpoint; the autonomous alternatives meanwhile are the §0.6 row 13 remainder
> (the engine's manifest covering content instead of signatures) or a §7 register row —
> **هـ1 (the default update-manifest URL + a signature check before applying) was the
> third and landed 2026-11-09** (D-046 for the feed, D-047 for the signature and its
> thumbprint pin). The
> ARM64 engine is built and checked but **has never been run here** — no ARM64
> machine exists — and ARM64 CI jobs now exist for that (marked informational until
> they have a green run) while the ARM64 *app* still needs an ARM64 host, which CI
> can supply.
> **2026-11-12, later that day: a `-Tier full` run found one red case, and it was not
> the new code.** `engine.contract`'s `update.check` row was classed `read` and the
> case fetched github.com: `resolve_update_url`'s third input is the channel's
> compiled-in feed (D-046), so a sandbox with an empty data dir is not an offline
> sandbox. The row is `network` now, like `sync.now`, with the reason in it. Chasing
> it turned up what the release check had not asked: the published `v0.1.0` carries
> **no** `update.json` or `update.json.sig` — that release object was created
> 2026-11-05 and its assets were frozen at 14:20Z that day, while the manifest upload
> landed 2026-11-09 — so the compiled-in feed answers **404** for every installed copy
> until a release built by today's lane is published (§0.6 row 5 carries the
> measurements). The locally packaged `dist\` from that release is gone too: it held
> one Dart symbol table and nothing else, so `0.1.1` is cut from `48116d4` and what
> gets published after it is the first release whose update feed answers.
> **2026-11-13: that cut is built and the whole lane is green on it.** `0.1.1` moved
> in both files that declare it — `engine\Cargo.toml` and `pubspec.yaml` — and in
> `engine\src\main.rs`, whose start-up banner had the version typed into it and now
> reads it. Two commits of that day-move had touched no doc at all (rule 2), which is
> why this paragraph carries it now. The package: `MICS-portable-0.1.1-x64.zip`
> 22,715,750 bytes `sha256 f5fce883…`, `MICS-setup-0.1.1-x64.exe` 16,836,715 bytes
> `sha256 291ddf32…`, `update.json` + `update.json.sig` (330 + 1,293 bytes, the hash
> and size in the manifest equal to the ZIP on disk), and a `VERSION` line naming
> revision `48116d4`. `engine.test`, `opsec`, `manifest` and `tamper` all pass on
> that `dist\` (**14/14** in `-Tier release`), `verify-release.ps1` passes its 35
> checks with 0 skipped, and both binaries carry the kept store certificate: the engine
> verifies `Valid` as `ABB0FF3D8FFAFDF2E0C52A6D3C239580D1945756`, the app as the same
> one, and that thumbprint is what the engine pins for the update feed (the release
> report's `pinned :` line) — **not** the throwaway identity the lane mints when it is
> handed no PFX, which is the difference row 18 measures.
> The version declarations had **no gate at all** before this cut: `make-release.ps1`
> and `make-installer.ps1` read `engine\Cargo.toml`, Flutter stamps `pubspec.yaml`
> into the app (measured: `mics_app.exe` `FileVersion 0.1.1+2` against the engine's
> `0.1.1`), and nothing compared them, so a one-sided bump would have shipped a
> `0.1.2` package holding an app that still called itself 0.1.1 with every step
> green. `test\version_agreement_test.dart` is that gate now (2 cases, proved to
> fail on a hand-made `0.1.2`-against-`0.1.1+2` tree before it was committed).
> **2026-11-13: `0.1.2` is cut from `bda619e`.** The bump itself is three
> declarations and two generated files: `engine/Cargo.toml` and `pubspec.yaml`
> (`0.1.2+3`, the pair `test/version_agreement_test.dart` holds together),
> `engine/Cargo.lock` following its crate, and `sbom.cdx.json` +
> `THIRD-PARTY-NOTICES` rewritten by `dart run tool/sbom.dart` (579 components,
> 8 licences, no copyleft, no missing texts) — the first attempt edited the SBOM
> by hand, left the `serialNumber` on the old value and the notices headed
> `0.1.1`, and the lane's staleness gate refused the package with exactly that
> diff. What the batch carries over `0.1.1`: the engine's refusal reason reaching
> the card (D-050), the AI surface gone whole (D-052), an Arabic tray whose Quit
> ends the engine rather than the window (D-053), the Explorer entry per user in
> HKCU plus the key that enables it (D-054), and the فصحى pass with the gate that
> keeps it (D-055).
> The package: `MICS-portable-0.1.2-x64.zip` **22,689,130 bytes**
> `sha256 a4894bdb21d297b1ae2bb884393c669224aa1475f9a6ec441cf95756d4883abf`, engine
> `5b32b31f…`, app `8584afe2…`, `VERSION` built 2026-11-13 19:43:19 +02:00 (rebuilt after D-056; no -BuildTime pinned, so the app hash moved), signed
> by the same certificate `0.1.1` pinned (`ABB0FF3D…`), so an installed `0.1.1`
> engine accepts the `0.1.2` feed. **No installer was built for this cut** —
> `make-installer.ps1` was not run, so there is no `MICS-setup-0.1.2-x64.exe`
> beside the zip. `update.json` keeps `notes_ar` empty because
> `update-manifest.ps1` documents the release page as the place notes are
> explained.
> **2026-11-14: `0.1.3` is cut, and it exists to carry the ARM64 measurement.** The
> bump is the same five files as last time and nothing else — the declarations in
> `engine/Cargo.toml` and `pubspec.yaml` (`0.1.3+4`, the pair
> `test/version_agreement_test.dart` holds together), `engine/Cargo.lock` following
> its crate, and `sbom.cdx.json` + `THIRD-PARTY-NOTICES` rewritten by
> `dart run tool/sbom.dart` through the one command, not by hand (579 components, 8
> licences, no copyleft, no gaps; the `serialNumber` moved with the component set).
> It sits on top of `349cb55` so that the release run which measures the ARM64 legs
> measures that gate fix in the same tree, and it is a new version rather than a
> re-run of `0.1.2` because `0.1.2`'s release is already published: `gh release
> create --draft` on a live tag fails instead of re-uploading, which would have
> turned the run red for a reason that says nothing about ARM64. **This paragraph is
> written before the run** — the package size, the hashes, the ARM64 verdict and the
> publish click are measurements, and they belong here when the run has them.
> **Measured, run `43593726650` (2026-11-14, `windows-11-vs2026-arm64`).** `Package
> (x64)` and `Publish` are green and a **draft** `v0.1.3` exists with six assets -
> `MICS-portable-0.1.3-x64.zip` 23,244,662 bytes, `MICS-setup-0.1.3-x64.exe`
> 16,827,724, `report.md`, `SHA256SUMS`, `update.json` and its `.sig`. It is a draft
> because the lane makes drafts; the publish click is not a measurement and has not
> been made. `Package (arm64)` is red and now for exactly one reason: `NOT READY - 1
> of 7`, with the Windows SDK row present (`...\10.0.26100.0\um\arm64`) and the
> host row present (`PROCESSOR_ARCHITECTURE=ARM64`), so the `349cb55` row fix did
> what it was for. The engine job is green on that runner, natively, again.
> **The one row that is left is the Flutter engine artifacts, and the precache step
> added with that fix printed the cause rather than leaving it to be guessed:**
> `dart --version` on that ARM64 runner answers `on "windows_x64"` - the action can
> only install the x64 SDK, since no Windows ARM64 SDK is published - so `precache`
> fetched `windows-x64`, and the engine directory listed `windows-x64` and no
> `windows-arm64`. Flutter's tool reads the platform of the process it is, not the
> machine it is on. **The correction to what this file believed:** the ARM64
> artifacts are published; what is missing is the SDK. For engine revision
> `cf636b1dfb`, `windows-arm64/artifacts.zip` is 34,257,934 bytes and
> `dart-sdk-windows-arm64.zip` is 161,631,589 bytes (its `version` file says
> `3.13.7`, the same Dart the x64 SDK carries, and `bin/dart.exe`'s PE machine is
> `0xaa64`) - while `releases_windows.json` mentions arm64 in **0 of 749**
> archives. An earlier reading of this row ("an ARM64 host gets `windows-arm64`, an
> x64 one only `windows-x64`") is what the run falsified: the host was ARM64 and it
> still got x64. So the job now puts that ARM64 Dart SDK in `bin/cache/dart-sdk`
> before `precache` runs, which is the precondition for the row to be reached - not
> proof that `flutter build windows` then produces an ARM64 app (its target comes
> from the host platform, which is why the tool has to be native first). **That
> build is the next measurement, and it is not written down here because it has not
> run yet.**
> **`0.1.4` is cut on top of that, the same day, to carry the swap.** The version
> moves because `v0.1.3` already has a draft release and `gh release create` refuses
> a tag that already has one - the same collision that made `0.1.3` a cut rather than
> a re-run of `0.1.2`. The bump is the same five files as both cuts before it, and
> the only thing that differs is the intent: this one is a measurement vehicle, and
> its draft is disposable.
> **The lane is not green on this machine, and the reasons are written down
> rather than smoothed over.** `-Tier release` ends `RESULT: FAIL -
> engine.contract` with **85 cases, 3 failed** — `fw.wfp.block`, `fw.wfp.unblock`,
> `fw.wfp.reset` — and `-Tier full` ends the same way; the run does report `PASS`
> for the 19-check app/engine lifetime suite ("the engine ends with the app that
> started it") and the 18-check signing-identity suite ("one PFX gives every build
> the same identity"). Measured with the privileged helper service removed, an
> unelevated standard-user shell (`admin_member=False`, `elevated_token=False`) and
> an engine whose Authenticode status is `NotSigned`, the engine's WFP calls
> nevertheless succeed (`status: blocked`, 2 filters) while the contract expects
> the refusal an unsigned, unelevated caller gets. The same three were red in this
> machine's first run of the day, before any commit in this batch, and
> `make-release.ps1` passes end to end on the same tree. One more defect the run
> paid for: **a failing `engine.contract` leaves its engine alive**; the leaked
> process keeps `engine\target\release\mics-engine.exe` locked and the next
> `cargo build` in the repo dies with `Access is denied (os error 5)` — the
> packaging run above was completed by pointing `CARGO_TARGET_DIR` outside the
> tree, which is a workaround, not a fix.
> ب4 landed 2026-11-03 (D-026): the installer now creates the privileged helper inside
> the one UAC prompt it already asks for — by calling the shipped engine's own
> `install-helper` — and its uninstaller stops and deletes that service again through
> `check-helper-ownership.ps1 -Remove`, scoped to the service name in
> `HELPER_SVC_KEY` so a probe can never delete a real one. Both variants compile,
> `verify-installer.ps1` passes end to end in 141 s, and the run turned up a real
> defect: the refusal dialogs were **not** silent-mode aware, so an uninstaller run
> with `/S` (which is how the verifier, and any script, runs it) hung on a MessageBox
> forever and the documented exit code 5 never arrived — measured at 532 s before the
> dialog was killed, now guarded by `${IfNot} ${Silent}`. ج3 landed 2026-11-03: the
> README now says what MI CS does and does not do, with
> the manifest, the start-up self-check and their honest limits in it, and every
> number in it is one the pipeline measured. ط2 landed 2026-11-03
> (`scripts\verify-tamper.ps1`: a byte flip per shipped binary, a same-size swapped
> DLL, an edited manifest, a repack into an unsigned engine and a copied install -
> each refused by the release gate and reported by the app; 41 checks, 108.5 s, and
> it found a hole in that gate, recorded below), and ج2 landed the same day in its
> two commits (the producer: `make-release.ps1` injects `MICS_MANIFEST` from the
> final bytes and `verify-manifest.ps1` proves the package against it; the reader:
> the engine re-reads its own resource, re-hashes the files and reports
> `status.integrity` in three states, with the About line and the card) (ز2-أ,
> ز2-ب, ز2-ج, ز3, ط1, ط3 and د5 are done and proved: a panic and a killed run each
> become one
> `MICS-<date>-<hash>` report with a JSON+text bundle under `<data dir>\crashes\`,
> readable over `crash.list`/`crash.get`; a `std::thread` watchdog — started with
> the session — files a `hang` report naming the stuck duration and the last
> request when the runtime's heartbeat stops; Settings → Diagnostics lists those
> reports, shows the id and the readable message, copies the paste text whose
> first line is the id, and deletes one; the alert gate has a second destination,
> in-app cards in the window's bottom corner — every severity including LOW, the
> crash card carrying its bug id, right in LTR and left in RTL; the shipped engine
> no longer names the account that built it (`--remap-path-prefix` took the 1238
> hits to 0) and the remaining fingerprints are a written, ratcheted allowance;
> and `-Tier release` now refuses a package whose bytes carry an account name, a
> fingerprint above that allowance, or a binary that lost its CFG table — the last
> one caught a real regression on 2026-11-02, the day it was introduced; and every
> QA surface now has a committed report — `qa/report.md` and its HTML twin, built
> from the registries and refused by the fast tier the moment it drifts).
> 124 engine tests, contract 78 cases / 0 failed, 133 Dart tests, shell ledger 21
> controls). The rest of the track is cut
> into commit-sized slices in §0.3b, and §0.3c says what each one has to prove.
> Delivery off the machine (ز2-د) needs **D-023** + the Open WhatsApp bridge
> endpoint and is the only blocked slice. The user
> approved the
> QA/reliability track on 2026-11-01; §0.3b carries it, and
> `scripts/pipeline.ps1` is where every check now runs, including
> `engine.contract`. ب4 (folding the helper
> install into the installer) stays the release-engineering lane. ب3 is
> finished and measured (all three steps, 2026-11-01): the installer builds around
> the hardened package, installs and removes the whole product (70 files), tags
> **both** shortcuts with `System.AppUserModel.ID` through `IPropertyStore`, refuses
> to uninstall a copy its privileged helper still points at (`/S _?=$INSTDIR` →
> **5**, nothing removed), and `scripts\verify-installer.ps1` proves all of it
> end to end in **126 s** (install, measure, uninstall, refuse, restore itself). The
> per-machine run, the helper acceptance and the uninstall all ran on **2026-11-07**
> (§0.2 item 1, closed — including the three privileged toggles it deliberately did not run
> live, which nothing waits on). The publish click was made on **2026-11-10** and the download it
> produced was verified the next day (§0.6 row 1, closed), so what still needs you is the answers in
> §0.2 items 3–5 plus one secret — keep a release certificate in `MICS_PFX`/`MICS_PFX_PASSWORD`
> (§0.6 row 18, **ب7**; recipe in `docs/SIGNING.md` §7 item 6). The signing certificate is closed as
> not-purchased.
> README is written; the app runs unelevated and was verified end-to-end on a real
> machine.
>
> **New session? Read §0 "Resume here" first** — current state, the next
> ordered steps, what is blocked on a human, and the environment must-knows.

---

> **2026-11-08 — what changed since that audit, and where the next session starts.** The
> certificate question is answered and **closed rather than open**: two free routes are on
> record with their sources and dates ([`docs/SIGNING.md`](SIGNING.md), D-036), the Store-shaped
> package exists, installs without an administrator and was **run for real** — its app half
> reaches its engine inside the container — the submission playbook is
> [`docs/STORE.md`](STORE.md), and the acceptance check now exists: `scripts\verify-trust.ps1`
> exits 0 only for an artifact a stranger's Windows would trust (its `-SelfTest` proves the
> instrument against a self-signed control and `kernel32.dll`). What waits on the owner is **the
> answers and one secret** — the publish click was made on 2026-11-10 (§0.6 row 1), and the release
> identity is the secret (§0.6 row 18) — not a purchase. §0.2 and the register count were reconciled on
> 2026-11-08 with what actually ran; the register is **8 open rows (1 HIGH, 4 MED, 3 LOW) out of
> 24** (recounted from the table on 2026-11-11, after small step 9 closed the engine-refusal row, the same day closed the guard's ETW IOC-hash row, the same day closed the unrenderable language tag (D-049), D-050 closed the undeclared-language-folder row and D-051 the update pin that compared a subject name; not carried over), and no page any longer describes a *run* as waiting on a human.

## 0. Resume here — a new session starts with this section

### 0.0 How to start the next session

Open a fresh session and paste exactly this:

> اقرأ docs/TODO.md §0 (وبالخصوص **§0.6** و§0.3c) و docs/ROADMAP.md. جدول §0.6 هو
> قائمة الناقص كاملة — خُد **صف واحد** في المرة. **الخطوات الصغيرة التسعة (§0.5) خلصت**،
> آخرها الخطوة 9 (`a4856d5`: رفض المحرك بقى يوصل للشاشة بسببه) وبعدها **D-048**
> (`2726214`: صف الـETW اللي بيحمّل قائمة الـIOC ويرميها اتقفل — حمولة ميتة اتشالت،
> والحقيقة بقت دالة واحدة `ioc_hash_coverage` واختبار بيثبّتها)، واللي فاضل هو **المتوسط
> والكبير**. أقربهم **صف 9** — صفوف السجل في §7: **7 صفوف مفتوحة (1 HIGH، 3 MED، 3 LOW)
> من 24** بعد عدّ 2026-11-11، خُد أرخصهم واحد واحد وبنفس نمط الخطوات 8 و9 وD-048 وD-049 وD-050 وD-051:
> إصلاح + اختبار يثبته + قياس حقيقي + كوميت واحد فيه التوثيق كمان. آخرها **D-051**
> (الكوميت اللي كتب السطر ده: صف «دبوس التحديث CN مش thumbprint» اتقفل — الدبوس بقى **الشهادة**
> اللي المحرك نفسه شايلها (بصمتها، مقروءة من صورته بدون سلسلة)، والاسم بس هو الاحتياطي لبناء
> من غير توقيع، و`update_pin()` بتبنيه مرة واحدة والفحص والمانيفست و`trust()` كلهم بيقارنوا القيمة
> دي؛ يعني إصدار موقّع من CA حقيقي هيعرف **نفسه** مش يرفضها، وشهادة بنفس الـCN من حد تاني بقت
> مرفوضة).
> **قبلها D-050** (صف «مجلد لغة `pubspec.yaml` مش مُعلنه» اتقفل — الـloader بقى يصنّف
> القراءة ويكتب **سطر واحد** لكل لغة ضاع منها حاجة (والسكوت باقي في البناء السليم)، والإعدادات بقت
> تسمّي اللغة اللي حزمتها فاضية؛ وأول تشغيل للاختبارات الجديدة كشف كمان إن `i18nModules` كان فيه
> مدخل `about` مش موجود في أي حزمة — اتشال، والاختبار بقى يمشي في الاتجاهين).
> **مفيش صف LOW رخيص تاني** (واقرأ الصف بنفسك في §7 قبل ما تكتب كود، زي ما العادة بتقول): الفاضل
> إما **محتوى** (starter pack — شغل كتابة قواعد، D-033)، أو **موقوف على ترخيص** (قوائم الدول،
> قرار (a))، أو **موقوف على مفتاح من برّه** (abuse.ch محتاج Auth-Key) — فالتالي إما صف MED
> (**المراقبة اللحظية**، و2) أو صف **ب7** (هوية توقيع واحدة لكل إصدار). و**القرارات اللي مستنياك تلاتة** مش ستة (تلاتة
> اتحلّوا: (c) بـD-035 واتنفّذت بـD-051، و(f) بـD-049، وشوف §0.2 item 3).
> بعده **صف 13**
> (نصف F-11 الباقي:
> مانيفست المحرك متجمّد على الهاشات الموقّعة، فإعادة بناء بتوقيع تاني مش بتطابق).
> و**نشر `v0.1.0`** اتعمل خلاص — نشره صاحبه 2026-11-10 والتحميل اتحقّق منه 2026-11-11. **صفوف 14–17 اللي طلبتها قفلت بقياسات**
> (D-039…D-045، ودليل الجدار اللحظي في صف 17) — متعيدهاش. أي صف تاني إما مقفول بقياس أو
> موقوف على حاجة مش موجودة: شهادة موثوقة (D-035، **مفيش شراء في المشروع خالص**)، تطبيق
> ARM64 (مفيش Flutter Windows ARM64 SDK)، رنر `windows-11-arm`، أو **ز2-د** (D-023 +
> endpoint الجسر). متكتبش أرقام من غير قياس، وشغّل
> `scripts\pipeline.ps1 -Tier fast` قبل الكوميت.

**Resume point (2026-11-11, after D-051).** The last committed step is
**D-051** — the update pin is a certificate rather than a subject name: `signature::Pin` carries either
the thumbprint of the certificate **over the engine itself** (read out of its own image, no chain
needed) or the release CN as the fallback a build with no signature of its own gets, `update_pin()`
builds it once, and the payload check, the manifest's `judge()` and `trust()` all compare that one
value — so a CA-signed release recognises itself instead of refusing itself, and a certificate with
the same CN from somebody else is refused; before it **D-050** — a language pack that did not load is
now a fact rather than silence: the loader classifies
every language's load and writes one line per language that lost anything, Settings names the language
whose own pack is empty, and the `about` entry `i18nModules` carried with no file anywhere went with
it; before it **D-049** — a stored language tag no pack can render
renders English with the tag named on screen
instead of Arabic with English gaps; before that,
**D-048** — the guard's ETW callback stopped loading the IOC hash list it dropped and `guard.status`
carries the coverage fact; before that,
**D-046/D-047** (`5a9949b`, `f621a3d` — the compiled-in update feed and the signature over the
manifest) and **small step 9** (`a4856d5` — the engine's refusal reaching the screen); before them,
the **WFP slices** ((a) `9c353e5`, (b) and (c) on the commits above it), then **D-045** (`52b69d3`, the
bug the first elevated run found) and its probe instruments (`4709011`).
The register is **8 open rows** (1 HIGH, 4 MED, 3 LOW, recounted from §7 on 2026-11-11 and again after the publish was verified the same day — small step
9 closed the LOW row about an engine that cannot say why it would not start, the same day closed
the LOW row about the guard's ETW callback loading the IOC hash list and dropping it, the same
day closed the LOW row about a language tag the UI cannot render, **D-050** closed the LOW row
about a language folder `pubspec.yaml` does not declare, and **D-051** closed the LOW row about the
update pin matching a subject name); §0.6 rows
14, 15, 16 **and now 17** are
**closed with measurements** (D-039, D-040, D-041, D-042/D-043/D-044/D-045). Row 17's close is the
2026-11-09 elevated run: `scripts\reset-wfp.ps1` **7 passed, 0 skipped, 0 failed** (and it found the
four filters the 2026-11-08 teardown had left behind), `scripts\verify-wfp.ps1` **16/2/0**,
`scripts\verify-connections.ps1` **24/0/0**, `scripts\verify-wfp-watch.ps1` **34/1/0**. Everything the
row names is measured — MI CS owns a real provider, sublayer and persistent Block filter in the BFE
with Windows' own tool reading it back, the connection list is all four tables with IPv6 and the
exact spec a click would write, and the filtering layer watches itself with one HIGH incident and
card per change. What the run left **uncomposed** (not disproven) is named in the row itself and in
D-042/D-043/D-044: the enforcement effect on a live connection, a real reboot, the sublayer's weight
against a built-in permit rule, and a real deletion behind the engine's back; plus the two limits
that are design, not debt — a prompt per new connection needs a kernel driver, and the poll window
hides a delete-and-re-add. The 2026-11-08 run before it is what produced **D-045** (every enumeration
named a zero layer, so `fw.wfp.status`, `fw.wfp.block` — after it had already added its filter — and
`fw.wfp.reset` failed `layer does not exist. (0x80320004)`, and three of the probes read that as a
pass or as a privilege boundary); the fix, its two tests, the honest probes and
`scripts\reset-wfp.ps1` are in, and one machine is still on the old build: the installed
`MICSHelper` is a release binary from before D-045, so the app's own unelevated write path answers
`0x80320004` until it is reinstalled from a fixed build.
**162**, `cargo test` is **200** (D-047's six cases; the snapshot this line was written from read 192),
the QA ledger is **109 controls** over **73 methods** (the
panel still swept as `surfaces.trayPanel`, 6 controls), and the fast tier is green as one run:
**4 of 4, 65.2 s** (re-run after the docs commit; D-045's own run measured 68.8 s)
(`git rev-list --count '@{u}..HEAD'` names how many commits are unpushed).

That means: read §0 (especially **§0.6** and §0.3c) and `docs/ROADMAP.md`; **§0.6 is
the complete list of what is left**, and a session takes one row at a time. The order
the user set on 2026-11-08 was **rows 15–17** — the designed tray panel, "Scan with MI CS"
in Explorer's context menu, then the real-time firewall (WFP) — and **all of them are now
closed**: 15 by D-040, 16 by D-041, and 17 on 2026-11-09 by the elevated run above, which took
the three slices from "written and unit-tested" to measured against the real Base Filtering
Engine (a persistent Block filter Windows' own tool reports, the connection list's spec accepted
and undone, the watch reading the real machine and clearing it). Row 17's honest limit is
already written down: a per-connection allow/block *prompt* needs a kernel callout driver,
and `SECURITY.md` says usermode only. Independently: the §0.6 row 13 remainder, a §7 register row, or
the one secret behind **ب7** (row 18) — each with the proof its row names. (`v0.1.0` was published on
2026-11-10 and verified the next day, so the publish click is behind us.) **هـ1 landed on 2026-11-09 in two slices** — the compiled-in feed (D-046) and the signed
manifest with the thumbprint pin (D-047, `cargo test` **200**, the probe **45/0/0**) — so what is
left of the signing story is the certificate itself (ب5), which is a free account and a click, not
code. **Nothing in this project is
purchased** (D-035), so a row that says "certificate" is **closed, not pending**. When work
touches signing, **do not re-research the routes** — they are closed, with sources and dates, in
`docs/SIGNING.md` (D-036); judge artifacts with `scripts\verify-trust.ps1` (exit 0 means a
stranger's Windows trusts the file, and `-SelfTest` proves the instrument) and follow
`docs/STORE.md` for the Store submission itself.
**و4, د4 and ب2 are done (2026-11-03)** — see the Done log: the register's
executable LOW rows closed (keys in `secrets.dat`, one scanning path, audit-section
ages, guard cost re-measured) plus three rows closed by evidence; the QA report was
already generated, byte-gated and uploaded, so د4 was only a stale checkbox; and the
ARM64 leg builds the engine **and its test binaries** for
`aarch64-pc-windows-msvc`, with the PE read back as a hardened ARM64 image, while
the Flutter app needs an ARM64 host — **no ARM64 binary has ever been run here**.
§0.3c says what "done" means for every remaining slice, so a new session does not
have to re-derive it. §0.5 is **finished** and so are the tracks behind it:
**ج2, ط2, ج3 and ب4 are done (2026-11-03)** — the package describes itself inside the
engine's signature, the engine reports `status.integrity`, `scripts\verify-tamper.ps1`
proves a tampered copy is refused by the gate and reported by the app, the README says
exactly that, and the installer now creates and removes the privileged helper inside
its own single UAC prompt (D-026) — and **و1 (D-027, both commits)** and **و3 (D-028)**
are done too: the engine schedules the scan and Settings has the switch
(`scripts\verify-scan-schedule.ps1`), and the firewall now speaks the Windows Firewall
API instead of `netsh` (`scripts\verify-firewall.ps1`, 23 checks). **و4 is done too
(2026-11-03, five commits)** — the plaintext keys are DPAPI-protected, the blocking
`vuln.scan` is gone, a merged audit shows each section's age, the guard's cost is
re-measured with the shipped pack, and the three evidence rows are closed with a probe
result each — and **د4 is done** (the QA report was generated, byte-gated and uploaded
all along; only its checkbox was stale), and **ب2 is done as far as this machine
allows** (the ARM64 engine and its test binaries build and are checked; the app
needs an ARM64 host and nothing ARM64 was ever run). **What is left is §0.6** — read
that table, not this history; its shape is the answers to §0.2 items 3–5, one secret (the release
identity, row 18) and free engineering (§7 rows and §0.6 row 13 —
the reproducible build landed 2026-11-08). **The certificate is no longer "waiting on a human"**: it is closed as
not-purchased (D-035, §0.2 item 2), and the helper acceptance — which used to be the single
UAC-click item — **ran on 2026-11-07** (§0.2 item 1, closed; the installer creates the
service, not the app, D-026). The rules that session must keep, all from `AGENTS.md`:

- **one small step per turn** — the user asked for work split until a single reply is
  cheap in time and tokens; do not bundle steps;
- **one step = one conventional commit**, with `docs/TODO.md` **and** `docs/ROADMAP.md`
  updated in the same commit (move the finished item into the Done log, not just tick
  it);
- the **four checks must be green before every commit**: `cargo test`,
  `cargo clippy --release -- -D warnings`, `flutter analyze --no-pub`,
  `flutter test --no-pub`. Run cargo from `engine\` with
  `$env:YRX_REGENERATE_MODULES_RS="false"` (and `CARGO_TARGET_DIR` if it complains,
  see §8);
- **reply in Egyptian Arabic**; code, comments, docs, identifiers and commit messages
  in English;
- no live probe without the isolation env vars (`MICS_NO_SINGLETON`, an isolated
  `MICS_PIPE_NAME`/`MICS_DATA_DIR`, `MICS_NO_GUARD` when the guard is not the subject)
  — a real MI CS runs on this machine;
- when a step is finished, say what was measured or verified, not just what changed.

**Where the project stands** (2026-11-01, `main`). The whole
*unelevated* half of the product is implemented and verified on a real Windows 11
machine: audit + one-click fixes, file scanner (YARA + IOC cache), encrypted
quarantine, process guard + canaries, firewall/hosts through the privileged
helper, intel sync (D-012), resumable jobs, desktop notification cards, bilingual
UI with full RTL, sounds, the 8-section Settings screen, a portable ZIP +
`SHA256SUMS`, an **NSIS installer** (`dist\MICS-setup-<version>-x64.exe`, ب3 steps
1–3: installs and uninstalls cleanly, tags both shortcuts, refuses to remove a copy
the helper points at, and `scripts\verify-installer.ps1` proves all of it, D-022),
and Authenticode signing that works on
this machine. The engine now
also refuses to serve from a Low-integrity folder and names the cause (trap 21).
Both themes are **measured** now (29 of 29 contrast pairs each, asserted in
`test/{light,dark}_contrast_audit_test.dart`), and the README carries four
light-theme renders that regenerate from the UI itself. The release is **hardened
and the PE proves it**: Control Flow Guard on both binaries (it was absent before
ج1), the engine LTO'd and stripped (35.7 → 24.0 MB), the Dart snapshot obfuscated
with its symbol table kept out of the package, and `make-release.ps1` refuses an
unhardened or unobfuscated build (D-021). The names and icons are
settled and a probe now fails the release if they drift:

| Surface | Name |
|---|---|
| Task Manager / Properties — the app (`mics_app.exe`) | `MI Cyber Security` |
| Task Manager / Properties — the engine (`mics-engine.exe`) | `MiShild Background` |
| Inside the product (window title, title bar, tray, card headers) | `MI CS` |
| Windows' own notification settings / Action Center — the source label | `MI CS` |
| Desktop shortcut — icon taken from `mics_app.exe` | `MICS` |
| Start Menu shortcut | `MI CS` |

Both executables carry the **same icon**; the engine embeds
`windows/runner/resources/app_icon.ico` at build time. The table is the decision,
not a description: **D-020** freezes it, and `verify-aumid.ps1` (the registered
source label) plus `verify-release.ps1` (both `FileDescription` values) fail when
one of them drifts.

**Artifacts on this machine.** `dist\MICS-portable\` + the signed
`dist\MICS-portable-0.1.0-x64.zip` + `dist\SHA256SUMS` (all gitignored — the
scripts are the versioned part; `scripts\make-release.ps1 -Sign` re-creates and
re-hashes them), and the runnable install in `%LOCALAPPDATA%\MI CS` (69 files,
both binaries `Valid`).

> **Run the copy in `%LOCALAPPDATA%\MI CS`, never the one under `dist`.**
> `dist` sits in a low-integrity web root (`H:\FlyEnv\...\server\www\`): Windows
> refuses notification cards to a process launched from there
> (`0x80073D54 ... confined folder`), and that folder has already been emptied once
> by host tooling outside this repo (trap 16). Everything started from there also
> runs at Low integrity, which is what trap 21 and `mics-engine`'s startup guard
> are about.

### 0.1 Do this next — needs no elevation and no money (in this order)

1. ~~**أ2 — Light-mode contrast audit**~~ — done: 36 pairs measured against WCAG 2.2
   (4.5:1 body text, 3:1 large text and boundaries), **25 below their bar**. The
   table, the cause behind each group of failures and the reproduce command are in
   `docs/CONTRAST.md`; `test/light_contrast_audit_test.dart` prints it and fails if
   a palette token or a severity colour stops being measured.
2. ~~**أ3 — fix the colours that fail أ2**~~ — done: the light palette was
   repainted so **29 of 29** measured pairs clear their bar (tightest row is now
   `medium-severity text on the page` at 4.67:1 against 4.5; the invisible
   snackbar went 1.00:1 → 21.00:1), `audit_models.dart`/`cvssColor` read the
   palette instead of dark-mode literals, the palette gained a `yellow` token, and
   every ratio is an assertion in `test/light_contrast_audit_test.dart`.
   Before/after numbers: `docs/CONTRAST.md`. Dark mode was measured in small step 4
   (7 of 29 pairs failed, all fixed) — **both** modes now assert 29 of 29.
3. ~~**أ4 — AUMID registration (LOW)**~~ — done: `scripts\register-aumid.ps1` writes
   `HKCU\Software\Classes\AppUserModelId\MICS` (`DisplayName "MI CS"`, `IconUri` =
   the app's own exe: no elevation, no new file) and tags both shortcuts with
   `System.AppUserModel.ID = MICS`. `scripts\verify-aumid.ps1` reported **4
   problems** before and **5 of 5** after, including `Get-StartApps` filing the app
   under `MICS` instead of under the exe path; `-Remove` reverses both, and a real
   card still reached the desktop afterwards (`verify-toast.ps1` PASS). It **moved
   into the installer with ب3 step 2**, which tags both shortcuts it creates.
4. ~~**Guard CPU**~~ — done, see the log below: 3.52 % → 1.56 % → **0.156 % of one
   core (0.0028 % of this 56-thread machine)** with one inert rule, now under the
   `< 1 %` budget under either definition — **re-measured with the shipped pack
   in و4 (2026-11-03): 0.156–0.521 % of one core over four windows, median
   0.417 %; §7 carries the configuration.**

**This section is empty now**, and so is the rest of §0.5: **all nine small steps are
done**. What is left is no longer "small steps" — it is counted in **§0.6** (the one
table) with the order and estimates in **`docs/ROADMAP.md`**. Short version, as of
2026-11-11: **و1, و3, و4, ب2, ج1–ج3, ط2, د1, د2 and د4** are done and measured, and so is
**هـ1** — the compiled-in feed (D-046) *and* the signature over the manifest with its
thumbprint pin (D-047), measured by `scripts\verify-update.ps1`, now the `update.verify`
step of `-Tier full`. What
remains is the answers in §0.2 items 3–5, the
§7 rows, §0.6 row
13 (the reproducible build
itself landed 2026-11-08 and left only the engine's manifest behind), and three things that are *blocked* rather
than pending: a publicly trusted signature (not purchased — D-035), an ARM64 **app**
(no Flutter Windows ARM64 SDK) and **ز2-د** (D-023 + the bridge endpoint).
**No item in §0.2 is a click away any more** — the helper acceptance ran on 2026-11-07
(§0.2 item 1, closed) and the certificate is closed as not-purchased. What waits on you are
answers, not runs (§0.2 items 3–5) — and as of 2026-11-11 not even a click: the publish click in
§0.6 row 1 was made on 2026-11-10, the download it produced was verified the next day, and what
that verification left behind is engineering (ب7), not a question — **and since 2026-11-12 not even
engineering**: the probe and the release report are in, so the row's remaining act is the owner
keeping one certificate in two repository secrets (`docs/SIGNING.md` section 7 item 6) before the
next publish.

### 0.2 Blocked on the user

Everything below waits on a human, and nothing else in the plan does. It was
recounted on **2026-11-07** and reconciled with what actually ran on **2026-11-08**; if an
item is not here, it is not waiting on you. **Item 1 is struck through on purpose**: it is
the record of a run that happened, kept where the run used to be requested, not a request.

1. ~~**د3: three clicks, and the helper acceptance in the same session.**~~ — **closed
   2026-11-07.** Its own record follows, including the slice it deliberately left
   unexercised; nothing in it waits on you.
   The machine was measured clean on 2026-11-07: `MICSHelper` **does not exist at all**
   (`sc qc MICSHelper` → error 1060, where the 2026-11-04 note still expected a leftover
   pointing at `engine\target\debug\mics-engine.exe`), no `MICS` entry is in
   `HKLM\...\Uninstall`, and the only thing left under `C:\Program Files\MI CS` is a
   stray `mics-engine_IObitDel.exe` (a file an anti-malware tool renamed, not an
   install). Nothing needs manual cleanup before the run.
   Run the setup built from `main` on **2026-11-07** —
   `dist\MICS-setup-0.1.0-x64.exe`, **16,730,142 bytes (16.0 MB)**,
   `sha256 8984C19406169DE99374762FB8C4F8DCAD78DF1350EF5718040A0BBFB2F18BBD`
   (this replaces the previously documented `CB6F912F…` build; the local `dist` setup had
   drifted from HEAD, so it was rebuilt).
   - **click 1** - run the setup, UAC yes, Next/Install/Finish. It shows "Unknown
     publisher" (the certificate is not purchased — D-035) and installs **all users**
     with **one** prompt, including the helper. If it warns that the helper was not
     installed, stop and report that instead of continuing.
   - **click 2** - in the installed app, in **one** session: Network → *Default deny
     outbound* on; Hardening → *Disable SMBv1*; IDS → add one domain (that is the
     hosts write). Expect **zero** further prompts; a prompt means D-007's promise is
     broken and the operation's name is what matters.
   - **click 3** - uninstall from Apps & features; the uninstaller must remove the
     product **and** the helper in that one prompt, and a "could not remove its
     privileged helper" box means D-026 is broken.
   **Ran on 2026-11-07 — item 1 is closed.** What was done, and what was measured
   instead of the literal three clicks:
   - **click 1 (install)** — ran, **one** UAC prompt, all users: 72 files under
     `C:\Program Files\MI CS`, the per-machine Start-Menu group (`MI CS.lnk` +
     `Uninstall MI CS.lnk`), the `HKLM\…\Uninstall\MICS` row, and `MICSHelper` created
     **by the installer** inside that same prompt with binPath
     `"C:\Program Files\MI CS\mics-engine.exe" helper-service` — LocalSystem,
     AUTO_START, **running**. `priv.log` holds the whole story
     (`phase=note install requested` → `service starting (pid=50128) version=0.1.0
     pipe=mics_helper` → `phase=start version`/`phase=done ok=true` → `install
     finished, helper state=running`).
   - **click 2 (the privileged operations)** — done **without the GUI and without a
     single prompt**, which is a *stricter* test of D-007 than clicking the screen
     would have been: the installed engine was started unelevated, driven over a
     private pipe, and the LocalSystem helper executed `fw.rules.add` (**37 ms**) and
     `fw.rules.remove` (**36–44 ms**), each one a `phase=start`/`phase=done ok=true`
     pair. `helper.status` reported `installed/running/reachable/elevated=true`.
     **Deliberately not exercised:** *Default deny outbound* (it would have cut this
     machine's own network path mid-run, including the session that was writing these
     docs), the SMBv1 toggle, and the hosts write. So that slice of the promise is
     still proven only by `verify-helper.ps1`'s protocol probe, not by a live toggle —
     said here rather than glossed over. That slice is available to take during any future
     human session; it is **not** a request, and no row in §0.6 waits on it.
   - **click 3 (uninstall)** — ran, **one** UAC prompt, exit 0: product folder, the
     service (`sc qc MICSHelper` → 1060), the Start-Menu group, the registry row and
     the shortcuts all gone — so the helper was really removed, not refused — while
     `%LOCALAPPDATA%\MI CS` (your own copy) was never touched.
   - **Correction to the sentence that used to close this item**: the uninstall does
     **not** leave "nothing" behind. It keeps `%PROGRAMDATA%\MICS` (database + audit
     trail) **on purpose**, and `mics.nsi` says so on screen. The old wording would
     have made correct behaviour look like a defect.
   - **Also verified on the installed tree:** the start-up self-check re-hashed
     **68 of 68** listed files and reported our signer as `untrusted-certificate` —
     the honest middle state, on a real install rather than in a test.
   - **And it found one real defect**, now a MED row in §7: a firewall rule whose name
     already starts with `MICS-` is prefixed a second time and can then never be
     removed by the name that was passed.
2. **The signing certificate (ب5) — answered by constraint, and then answered again for
   free (D-035, D-036).** This is a free, open-source project with no budget, so **no
   certificate, tool or service will be purchased**. What that changes, and what it does
   not:
   - **Off the plan: the purchase.** `docs\COST.md` §2 keeps the researched routes and
     their dated prices on record so nobody re-researches the dead ends (Certum Open
     Source €49/year in their cloud; SSL.com IV $129/year plus eSigner; Azure Artifact
     Signing unavailable to an individual outside the USA/Canada; **the free SignPath
     route closed** — their code of conduct excludes "security diagnosis tools that
     actively scan for and highlight exploitable vulnerabilities", and it independently
     wants an already-released project with a reputation). EV is not a route either: it
     stopped buying a faster SmartScreen verdict in 2024.
   - **Not off the plan: being signed.** D-035 forbids *buying*, and the re-research of
     2026-11-07 (**D-036**, all sources and dates in **`docs/SIGNING.md`**) found two
     routes that cost nothing: **(A) the Microsoft Store re-signs an MSIX package** after
     certification — Microsoft's own words — with a free developer account (the $19 fee is
     waived, verification is a government ID and a selfie, "nearly 200 markets worldwide")
     and **no SmartScreen warnings**; and **(B) OSSign** issues the *project* a
     certificate once the repository is six months old (~**2027-04-27**), signing keyless
     over OIDC so no secret is stored. Route A is available today and is **packaging
     work**, plus three unknowns written as unknowns in `SIGNING.md` §3; route B is a
     date. A **donated** certificate remains a drop-in either way.
   - **Still ready, still free to take: the wiring.** Adding a certificate is two
     repository secrets - `MICS_PFX` + `MICS_PFX_PASSWORD`, or `MICS_CERT_THUMBPRINT`
     for one a token or a cloud agent holds - which the `Release` workflow already passes
     through and `make-release.ps1` resolves in one documented order, printing the
     identity it chose before the build starts (D-034). A **donated** certificate, or a
     free route that opens later, lands with **no code change**.
   - **The subject can never be `CN=MI CS Code Signing`**: CSCBR §9.2.2 requires the
     subject CN to be the verified legal name, so no CA can issue that string - the pin
     moves to a **thumbprint** (decision (c), `docs/OPEN-DECISIONS.md` item 3) in the
     same release that first carries a certificate, or `update.rs` refuses our own
     update — **done ahead of time on 2026-11-11 (D-051)**: the pin is the certificate the
     engine itself carries, read out of its own image, and the CN is only what a build
     with no signature of its own falls back to (and says so). Buying or being donated a
     certificate is now a settings-free drop-in; `docs/COST.md` keeps the paid routes and
     the "nothing is purchased" line.
   - **What replaces the certificate is free — and for this product, stronger:** a
     **reproducible build** (F-11, row 4 of §0.6 — **landed 2026-11-08**,
     `docs/REPRODUCIBLE.md`), the published `SHA256SUMS`, the
     manifest the engine re-hashes at start-up, and GitHub's own record of the run that
     produced the bytes. A signature says "a CA checked a name"; those say "here is the
     source, here is the recipe, here are the bytes - check them".
   - **ب6 is free, and it is the next step: publish `v0.1.0`.** It is built, verified and
     sitting in GitHub Releases as a **draft**, and the version bump, the signed zip and
     installer, the destination (**GitHub Releases**, item 6 below) and
     `.github/workflows/release.yml` are all done. One click (D-031).
3. **Six decisions, one line each — and three of the six still wait on you** ((c) is
   settled by D-035 and now implemented by D-051, and (f) is answered and implemented by
   D-049, all struck in place
   below rather than deleted). Every one of them stops work that is otherwise
   ready - **[`docs/OPEN-DECISIONS.md`](OPEN-DECISIONS.md) has a one-page brief for each,
   with what the code does today measured, the cost of every option, and a
   recommendation**; answering in one line per item is enough. *(a)* whether licensed
   **GeoIP**
   country lists may be bundled, since the licensing is unclear; *(b)* whether the
   detection content stays the **starter pack** or real rules are written — measured
   on 2026-11-05 so the answer is arithmetic rather than taste: the shipped pack holds
   **8 of its 10 rules to a file**, one of those (`Malicious_Macro_AutoOpen`) can only
   see an uncompressed container and a real `.docm` deflates its strings out of reach,
   and 2 rules cannot be proven by a text file at all (see D-033 and the row in §7);
   *(c)* ~~whether the update pin moves to the certificate **thumbprint** (D-016) once a
   certificate exists~~ — **settled by D-035**: it must, in the same release as any
   certificate, because no CA can issue `CN=MI CS Code Signing` at all (§0.2 item 2) —
   and **done early, 2026-11-11 (D-051)**: the pin is the thumbprint of the certificate
   over the engine itself whenever that build has one, so the same-release condition is
   already met and buying or donating a certificate needs no code change; the release CN
   survives only as the fallback for a build with no signature of its own, which reports
   itself as unpinned;
   *(d)* whether **IDS** grows past the DNS blocklist
   (Suricata/ET-Open is out of scope today, so this reopens a decision); *(e)*
   whether **real-time watching** (و2, 6-10 h) is wanted, because it costs CPU
   continuously; *(f)* ~~the **language-tag policy** (which tags the engine accepts and
   the UI can render) — measured on 2026-11-05: the engine accepts any BCP-47-shaped
   tag (deliberately not a closed list) and the UI resolves exact code, then the
   primary subtag, then falls back to **Arabic** while missing *keys* fall back to
   English, which is the incoherence the decision has to settle~~ — **answered and
   implemented 2026-11-10 (D-049)**: the engine still accepts any BCP-47-shaped tag
   (that half was never the problem), and the UI's chain now ends in **English** — the
   language missing *keys* already fall back to — with the stored tag carried through a
   settings write and named in one line of Settings when no pack answers to it. The
   publishing
   destination used to be the seventh and is
   answered: **GitHub Releases** (2026-11-04).
4. **D-023 and the bridge endpoint, which is what holds ز2-د (delivery).** A
   deliberate choice about where crash reports go, and an endpoint for the Open
   WhatsApp bridge. No code can be written before the answer, and inventing one would
   break the no-telemetry rule (AGENTS.md 8).
5. **A Windows on ARM machine (optional, and it is the last ARM64 step).** The engine
   builds and is checked for `aarch64-pc-windows-msvc` (ب2), but the Flutter app has
   no Windows cross-compile, so an ARM64 download needs an ARM64 host - and it is
   also the only way any ARM64 binary will ever be *run* **on your own hardware**.
   Since 2026-11-04 CI supplies that host: `.github/workflows/release.yml` carries
   two `windows-11-arm` jobs (the engine's tests run natively there), marked
   informational until they have a green run.
6. **Whether the repository goes public - DECIDED 2026-11-04: yes, this repository,
   after rewriting its own history (and the version becomes 0.1.0).** SignPath signs
   qualifying
   open-source projects for free, and the runner reference gives public repositories
   4 vCPU Windows runners with free, unlimited minutes (private repositories get
   2 vCPU drawing on included minutes). MI CS is GPL-3.0 (D-001) either way.
   **Corrected 2026-11-04:** ARM64 runners (`windows-11-arm`) are *not* public-repo
   only — see the D-003 correction. The rewrite is measured in §0.2a item 2; all that
   is left is the force-push and the visibility switch.
7. ~~**One elevated shell for the filtering engine (D-042 slice a, D-043 slice b, D-044 slice c and
   the D-045 fix, §0.6 row 17)**~~ — **done 2026-11-09, and it closed row 17.** The run was, in
   this order, against the **debug** build (the one that carries D-045's fix):
   `scripts\reset-wfp.ps1` → `scripts\verify-wfp.ps1` → `scripts\verify-connections.ps1` →
   `scripts\verify-wfp-watch.ps1`, all with `-EngineExe engine\target\debug\mics-engine.exe`.
   Results: **7 / 0 / 0**, **16 passed 2 skipped 0 failed**, **24 / 0 / 0**, **34 passed 1 skipped
   0 failed**; the reset also answered the question it exists for, finding `sublayer=True filters=4`
   (four of our own probe filters the 2026-11-08 teardown had left) and removing 6 objects. Keep the
   order: the reset is what makes the first probe's "added, not found already present" check
   meaningful. Two notes survive the close — the **installed** `MICSHelper` is still a release build
   from before D-045, so the app's own unelevated write path answers
   `enumerating MI CS' filters: The layer does not exist. (0x80320004)` until it is reinstalled from
   a fixed build (`install-helper` run by `engine\target\debug\mics-engine.exe` in an elevated shell,
   which also unlocks the release exe for the next `cargo build --release`); and
   `netsh wfp show state` produced no XML here, so the action evidence came from
   `netsh wfp show filters` (the skip now quotes netsh's own answer, commit `4709011`). The four
   claims the run did *not* compose are named in row 17 and in D-042/D-043/D-044.

### 0.2a Before the repository is flipped to public (measured 2026-11-04)

The user decided on 2026-11-04 to take the repository public. What that decision
needs first, all of it measured rather than assumed:

1. **The published tree is clean of the machine's account name.** A search for the
   account name at HEAD returned **4** hits (an example repo path in
   `MI-CS-Agent-Prompt.md`, a measured OneDrive desktop path and a real
   `net localgroup` line in this file, and a widget-test startup-entry fixture in
   `tool/`). All four now read `<account>` / `<repo root>`, and the same search
   returns nothing at HEAD (commit 8a54e69) - including in this section, which
   deliberately does not spell the name out.
2. **The history was NOT clean, and it has been rewritten in place - DONE 2026-11-04.**
   `.git` was **106.4 MB** and the history carried (a) a **34,000,312-byte**
   `mics-engine.exe` committed under `dist/MICS-v1.0.0-windows-portable/`, a build
   from *before* the ط1 fingerprint sweep (so it holds the account's `.cargo` paths
   in binary form - `git log -S` matched the name inside it) plus `app.so` copies,
   and (b) the account name in **13** textual places. The user first chose a fresh
   snapshot repository and then changed the decision the same day: **work stays in
   one place, so this repository is the one that goes public**, which means the
   history had to be rewritten. Measured, before and after:
   - `git filter-repo --path dist --invert-paths --replace-text ...` (git-filter-repo
     a40bce5), with a verified `git bundle` of the old history taken first
     (`MIF-prepublic-backup.bundle`, 29.3 MB, outside the repository).
   - **145 commits** (was 147; two commits contained nothing but `dist/` and were
     pruned), **no `dist/` path in any commit**, **no commit contains the account
     name** (`git log --all -S` returns nothing), and the author/committer identity
     is deliberately unchanged (`ibrahim ahmed <ib.farag@gmail.com>` - the user's
     decision, and the address never appeared in any file's content, only in commit
     metadata).
   - **The tree at HEAD is byte-identical**: tree `2c0b83a9c3986f7000c02cc497a6d8739f
     78b01e` before and after, working tree clean, 267 tracked files. `.git` is
     **7.1 MB** now.
   - Every commit hash changed, so hashes cited in this file from before 2026-11-04
     (and the `8a54e69` above) name commits of the **pre-public** history. The
     documents, not the hashes, are the record that travels with the code.
   - Residual, stated rather than hidden: GitHub can keep the now-unreachable old
     objects in internal storage for a while (a support request can force their
     removal), and **any other clone or worktree of this repository still holds the
     old history** and must be re-cloned instead of pulled.
3. **What the checkout contains that must never be published**: the VM lab's
   malware samples, `%LOCALAPPDATA%\MICS` state (`mics.db`, `secrets.dat`), and
   `dist/` (already ignored). The working tree is otherwise free of credentials:
   the history scan for private keys, AWS/GitHub/OpenAI/Google key shapes and
   `Authorization: Bearer` returned **zero** hits, and the only two
   `api_key = "..."` matches are test fixtures (`"nvd-KEY-123456"`,
   `"nvd-PROTECTED"`) in the engine's own tests.
4. **A first public version should not ship the internal brief as-is**:
   `MI-CS-Agent-Prompt.md` is a build prompt written for an agent, mojibake-encoded
   in places, and names the author. Keeping it is defensible (it is the project's
   origin story) but it is a deliberate choice, not an oversight. The same goes for
   `docs/TODO.md` itself: it is 340 KB of internal handoff notes, and publishing it
   is what makes the project's claims checkable - but it is a choice.
   **Resolved 2026-11-13 (D-052):** the brief is **deleted** — removing the
   assistant took its last live claim (the L5 local-LLM wording) with it, so the
   file no longer had a job to do. `docs/TODO.md` stays, deliberately.
5. **The version is one number again: 0.1.0.** `pubspec.yaml` said `1.0.0+1` while
   `engine/Cargo.toml` and every shipped artefact said `0.1.0`, so the app's own
   version resource disagreed with the installer that carried it. Decided
   2026-11-04: **0.1.0 wins** (`pubspec.yaml` → `0.1.0+1`, and `sbom.cdx.json` +
   `THIRD-PARTY-NOTICES` regenerated at that version, `dart run tool\sbom.dart
   --check` PASS).

**What is left, and what is already done** (the visibility switch is the only step
that needs your GitHub account; `gh` is not installed):

```powershell
# DONE 2026-11-04: the rewritten history is on the remote.
#   remote main = 1ae33a4, 147 commits, .git 6.2 MB (was 106.4 MB), and neither
#   `dist/` nor the account name appears in any revision or commit message.
#   The branch tracks origin/main again (filter-repo drops the remote each run).

# 1. YOUR STEP: Settings -> General -> Danger Zone -> Change visibility -> Public.
# 2. If you have any other clone or worktree of this repository, re-clone it. It
#    still holds the old history, and pulling will not clean it.
# 3. Optional, and the only way to hurry GitHub along: a support request asking them
#    to remove the now-unreachable objects. They can stay in internal storage for a
#    while; their SHAs are not published anywhere, which is what keeps that residual
#    small.
```

Keep `MIF-prepublic-backup.bundle` (29.3 MB, one directory above the repository)
until you are sure the rewrite was right - it is the only copy of the pre-rewrite
history that exists anywhere.

### 0.3 The plan, in order — what a new session works through

**`docs/ROADMAP.md` is the authoritative order and carries the estimates.** The tables
below remain the per-phase detail it was built from, with the step IDs the ROADMAP
uses. The chosen order is:

> **ج1** build hardening → **ب3** installer → **ب4** helper fold-in → **ج2** signed
> manifest → **د1 + د2** QA → **هـ1 + و1** *(both done)* → **ب2 / د3 / د4** → **و3 + و4**
> → **ب5 → ب6** once the certificate exists.

Every row is one commit-sized step unless it says otherwise; **§0.5 carries the
order the user picked (small → medium → large), and it is finished**
(§0.0). "Needs you" is the list that cannot move without the user.

**أ — close §0 (no elevation, no money)**

| Step | What | Notes |
|---|---|---|
| ~~**أ2**~~ | ~~Light-mode contrast audit~~ — **done**: 36 pairs measured against WCAG 2.2, 25 below their bar (`docs/CONTRAST.md`) | measured 2026-10-30 |
| ~~**أ3**~~ | ~~Fix the colours that fail أ2~~ — **done**: 29 of 29 pairs now clear their bar, every ratio asserted in `test/light_contrast_audit_test.dart` (`docs/CONTRAST.md`) | measured 2026-10-31 |
| ~~**أ4**~~ | ~~AUMID registration script + docs~~ — **done**: `scripts\register-aumid.ps1` writes `HKCU\Software\Classes\AppUserModelId\MICS` (`DisplayName "MI CS"`, `IconUri`) and the shortcut property, `scripts\verify-aumid.ps1` reads 5 of 5 back | measured 2026-10-31; folds into the installer with ب3 |

**ب — P4 release engineering (the largest remaining piece; the register's HIGH row
"no installer")**

| Step | What | Needs you |
|---|---|---|
| ~~**ب1a**~~ | ~~SBOM (CycloneDX) + `THIRD-PARTY-NOTICES`~~ — **done**: `tool\sbom.dart` generates both from the lockfiles (579 components, 8 licenses, 0 copyleft), commits them, and `--check` fails when they go stale; the release ships and re-reads them (D-018) | measured 2026-10-31 |
| ~~**ب1b**~~ | ~~`docs\COST.md`: the real costs (signing certificate) and what stays free~~ — **done**: `docs\COST.md` names the one purchase (a CA-issued certificate), the four constraints that decide *how* it can be used (hardware key since June 2023 → `-PfxPath` stops working; the `/sha1` path this row claimed already existed was in fact added later, by D-034 on 2026-11-06), the options, what is deliberately not bought, and the ب5 checklist — and the purchase section was re-researched on 2026-11-06 with dated prices and per-route publisher names | written 2026-10-31, prices 2026-11-06 |
| **ب2** | ARM64 leg: Flutter target + `aarch64-pc-windows-msvc` engine, per D-003 | no |
| ~~**ب3**~~ | ~~NSIS installer: bundled engine + `rules` + offline intel, shortcut, AUMID, one UAC prompt~~ — **done** (steps 1–3, 2026-11-01): `installer\mics.nsi` + `scripts\make-installer.ps1` build `dist\MICS-setup-0.1.0-x64.exe` (15.8 MB); the per-user variant installs 70 files and removes everything (exit 0); both shortcuts carry `System.AppUserModel.ID` through `IPropertyStore`; the uninstaller refuses a copy its helper still points at (`/S _?=$INSTDIR` → 5); and `scripts\verify-installer.ps1` proves all of it in 126 s. Left for a human: one **per-machine** run (one UAC click) | done |
| ~~**ب4**~~ | ~~Fold the privileged-helper install into the installer (replaces the separate UAC step)~~ — **done** (2026-11-03, D-026): the per-machine section runs the shipped engine's own `install-helper` under the installer's elevation, so one prompt installs the product *and* the service, and the uninstaller asks `check-helper-ownership.ps1 -Remove` to stop and delete exactly the service whose binPath points at `$INSTDIR` (scoped to `HELPER_SVC_KEY`'s leaf, so a probe cannot touch the real `MICSHelper`); both variants compile and `verify-installer.ps1` passes end to end. Left for a human: the same one **per-machine** run | done |
| **ب5** | Real OV-class certificate → sign the release, which prints a real publisher and *starts* a SmartScreen reputation (it does not switch warnings off on day one — measured against Microsoft's own comparison, 2026-11-06). Routes priced in `docs\COST.md` §2: Certum Open Source **€49/year** (cloud, CN "Open Source Developer <name>", but it signs only with a logged-in SimplySign session → persistent/self-hosted runner) or SSL.com IV **$129/year + eSigner $180/year** (their action runs on GitHub-hosted runners). The free SignPath route is closed to this product category (their code of conduct, verbatim in `docs\SIGNING.md` §6); Azure is not purchasable from Egypt. **Re-researched 2026-11-07 (D-036): the row no longer needs money** — `docs\SIGNING.md` records the two free routes (the Microsoft Store re-signing an MSIX; OSSign's project certificate at ~2027-04-27), so this row is now *packaging and a date*, not a purchase | **yes, and free** |
| **ب6** | Public release: signed ZIP + installer, version, README updated | **yes** (needs ب5) |

**ج — P5 trust and integrity**

| Step | What | Needs you |
|---|---|---|
| ~~**ج1**~~ | ~~Build hardening~~ — **done**: Control Flow Guard on both binaries (read back from the PE: `GUARD_CF` + a real guard function table), the engine built with `lto="fat"`/`codegen-units=1`/`panic=abort`/`strip=symbols` (**35.7 → 24.0 MB**), the Dart release obfuscated with its symbol table kept out of the package, and a release gate that refuses an unhardened or unobfuscated build (D-021) | measured 2026-10-31 |
| ~~**ج2**~~ | ~~Signed SHA-256 manifest of shipped files + startup self-check + "unofficial build" banner~~ — **done 2026-11-03, two commits**, design settled the same day (**D-025** + its two dated amendments): the manifest is an `RT_RCDATA` resource inside `mics-engine.exe`, built after signing and injected before the engine's single signature. **The producer**: `make-release.ps1` signs every staged file except the engine, builds `MICS_MANIFEST` from those final bytes, injects it, signs the engine, and `scripts\verify-manifest.ps1` re-reads it out of the staged package and re-hashes every listed file. **The reader**: `engine\src\selfcheck.rs` reads its own resource at start-up, re-hashes the files beside the image, classifies its own signature (ours and trusted / ours with a root this Windows has not trusted yet / anything else) and reports `status.integrity` — `ok`, `untrusted-certificate` (one neutral line in About, no banner: a self-signed build is not a fault) or `unverified` (the About notice plus a card naming the files that moved) | no |
| ~~**ج3**~~ | ~~Deliberate README rewrite ("what it does / does not do") once the above is real~~ — **done 2026-11-03**: the does table gained **"Is this copy the published one?"** (68 files, the document inside the engine's own signature, three verdicts, the About line, the card and the gate), the does-not list replaced the stale "there is still no integrity manifest" bullet with the honest limit (a changed copy is made *visible*, not impossible, and there is no reproducible build yet — F-11), the install steps end with "read the integrity line" plus the headless `verify-manifest.ps1`, **Testing** was rebuilt around `scripts\pipeline.ps1` (4 fast / 4 full / 3 release = 11 steps, 133 Dart, 124 engine, 65 methods / 78 contract cases, the three release gates including the 41 tamper checks), troubleshooting gained a row per verdict, and the Arabic half was brought to the same truth. Every number in it is one the pipeline measured — no new claims | no |

**د — P6 QA**

| Step | What |
|---|---|
| **د1** | `qa/` harness driving every JSON-RPC method: happy path, invalid params, permission failure, schema |
| **د2** | Per-screen widget tests |
| **د3** | E2E run against the built artifact (the installer from ب3) |
| ~~**د4**~~ | ~~`qa/report.html` + `.md`, and CI fails when a feature is not registered~~ — **done** (the checkbox was the only thing stale): `qa/report.dart` generates both files from the committed registries only, `test/qa_report_test.dart` byte-compares them in the fast tier, and `.github/workflows/ci.yml` runs `-Tier full` and uploads `qa/report.md`, `qa/report.html`, `build/qa-contract.json` and `build/pipeline-full.json` next to the binaries, so a feature that lands without a registry row turns the tier red before CI can pass it |

**هـ — the P3 remainder**

| Step | What |
|---|---|
| ~~**هـ1 (the URL)**~~ | ~~A default update-manifest URL compiled in~~ — **done 2026-11-09** (D-046): the channel carries the project's own release feed, a pure `resolve_update_url` orders environment → saved URL → channel default, `update.check` uses the one implementation the downloader uses and now reports **which feed answered**, `MICS_UPDATE_MANIFEST_URL=off` is the explicit do-not-check, `scripts\verify-update.ps1` measures all of it without a network (18 checks), and `make-release.ps1` publishes the `update.json` that feed serves (D-046) |
| ~~**هـ1 (the signature)**~~ | ~~A signature check on the manifest before applying, and the **thumbprint** pin it needs the moment any certificate exists (D-016)~~ — **done 2026-11-09** (D-047): a detached PKCS#7 beside the manifest (`sign.ps1 -DataFile`, `make-release.ps1` step 9b), verified over the exact bytes before a field is parsed, the signer pinned to the certificate over the engine or to `MICS_UPDATE_SIGNER_THUMBPRINT`, and every refusal (unsigned, another key, tampered, wrong pin) staging nothing. Measured: `scripts\verify-update.ps1` **45 checks, 0 failed** and six new engine cases including one against a committed signed fixture |

**و — the register (parallel, not a phase)**

`docs/TODO.md` §7 carries **8 open rows (1 HIGH, 4 MED, 3 LOW)** out of 25 —
recounted from the table itself on 2026-11-11. و4 had closed six of them (the
incomplete package, the merged-audit ages, the blocking `vuln.scan`, the plaintext
keys, the guard cost, the portable caller check, the AUMID attribution) and the
dark-mode and `netsh` firewall rows closed earlier, and small step 9 closed the LOW
row about an engine that cannot say why it would not start, the guard's ETW
IOC-hash row closed right after it, D-049 closed the LOW row about a stored
language tag no pack can render, D-050 the LOW row about a language folder
`pubspec.yaml` does not declare, and D-051 the LOW row about the update pin matching
a subject name. The LOW ones left need content, a licence answer or a key from
outside (the starter pack, the country lists, the hash feed), so the honest next pull
forward is a MED: **no real-time file watching**
(the scheduled half landed with و1, D-027), the canary checker being poll-based, and
Defender tamper protection.
The HIGH one left is the signing certificate and a published download (ب5 → ب6); the
incomplete-package HIGH row is **closed** — `verify-release.ps1` refuses a package
whose `rules\` went missing, measured with exit code 1.

**Blocked on the user (listed in §0.2, do not plan around them):** the answers in §0.2
items 3–5 and one secret in §0.6 row 18 (a release certificate in `MICS_PFX`/`MICS_PFX_PASSWORD`;
the publish click in row 1 was made on 2026-11-10). The signing certificate is closed as
not-purchased (D-035, D-036), and the three-operation helper acceptance is **measured** —
it ran against the installed service on 2026-11-07 (§0.2 item 1, closed; the 2026-10-31
prompt and the ROADMAP P1.5 row are its earlier half).

### 0.3b The approved QA and reliability track (2026-11-01)

The user approved this order, one commit-sized step at a time. It runs **before**
the release-engineering lane (ب4, ج2, ب5, ب6) and does not replace it.
`scripts/pipeline.ps1` is the entry point every step below plugs into.

| ID | Step | Status |
|---|---|---|
| ~~**ز0**~~ | ~~`scripts/pipeline.ps1` (tiers + JSON report) and the CI workflow calls it instead of repeating the checks~~ — **done** | measured 2026-11-01 |
| ~~**د1**~~ | ~~`qa/` contract harness: every JSON-RPC method x (happy path, invalid params, unknown method, schema)~~ — **done**, and the registry is checked against `dispatcher.rs` by `test/qa_registry_test.dart` | measured 2026-11-01: 64 cases, 15 skipped with reasons, 18.4 s |
| ~~**د2**~~ | ~~Every screen, every interactive control: those fixtures drive a `FakeEngine`, so the UI and the engine are exercised from one surface~~ — **done** | measured 2026-11-01: 13 screens + the shell, 63 controls in a committed ledger, 99 Dart tests in 13 s |
| ~~**ز1**~~ | ~~Language off the title bar, into Settings as a dropdown; `AppLang` enum -> language-code table with direction, engine accepts the bundled set~~ — **done** | measured 2026-11-01: 10 new registry tests, 110 Dart tests, contract 65 cases / 0 failed |
| ~~**ز2-أ**~~ | ~~Crash capture: session marker, panic hook, `MICS-<date>-<hash>` bug id, JSON + text bundle under `<data dir>\crashes\`, `crash.list` / `crash.get` / `crash.delete`~~ — **done** | measured 2026-11-01: 100 engine tests, contract 78 cases / 0 failed, a killed engine is reported once with its pid |
| ~~**ز2-ب**~~ | ~~**Hang detector**: a watchdog thread the runtime cannot block names a hang (`hang` report from the engine itself, so nothing off the machine and no UI filesystem access). Details and the honest limits are in §0.3c~~ — **done** | measured 2026-11-02: 106 engine tests (+6), one report per frozen heartbeat with the stuck time and the last request, no false report from a runtime that keeps beating |
| ~~**ز2-ج**~~ | ~~**The bug-id surface**: Settings gets a Diagnostics section that lists reports (`crash.list`), shows the id and the readable message, copies it, and deletes it (`crash.delete`); the fake engine gets fixtures and the UI ledger absorbs the new controls~~ — **done** | measured 2026-11-02: 114 Dart tests (+4), the ledger gained exactly the four Diagnostics controls and nothing else, and the id on screen is the id sent to `crash.get`/`crash.delete` and the id the pasted text starts with |
| ~~**ز3**~~ | ~~In-app notification cards in the window's bottom corner, right for LTR and left for RTL, fed by the existing alert gate; the crash card carries the bug id~~ — **done** | measured 2026-11-02: 111 engine tests (+5), 115 Dart tests (+1) and exactly two new controls in the shell ledger; the card measures `right = 1682` in LTR and `left = 18` in RTL inside the 1700-wide window |
| **ز2-د** | **Delivery** (webhook / SMTP / **Open WhatsApp bridge**): blocked on **D-023**, and on the endpoint shape of the Open WhatsApp bridge | blocked on you |
| ~~**ط**~~ | ~~Fingerprint sweep + tamper tests~~ — **done 2026-11-03**: ط1 and ط3 landed 2026-11-02 (the account name is gone, the counts ratchet, `-Tier release` refuses a bad package) and **ط2 landed 2026-11-03** (`scripts\verify-tamper.ps1`: a byte flip per shipped binary, a same-size swapped DLL, an edited manifest, a repack into an unsigned engine and a copied install - each refused by the gate and reported by the app; it is also the `tamper.verify` release step) | done |
| ~~**د5**~~ | ~~Coverage gates, `qa/report`, docs~~ — **done** (2026-11-02): `qa/report.md` + `qa/report.html` are committed, built from the registries by `qa/report.dart`, and byte-gated by `test/qa_report_test.dart` in the fast tier | measured on the registries: 65 methods / 65 dispatched, 98 controls over 13 screens + the shell, 2 languages / 38 packs, 9 shipped binaries with a reason each, 97 declared Dart cases in 21 files, 111 declared engine cases in 14 modules, 9 pipeline steps across 3 tiers |

### 0.3c How each remaining slice is done (so a new session can start cold)

Every slice below is **one commit**, ends with the four checks green through
`scripts\pipeline.ps1 -Tier fast`, and moves its row up into the Done log with
what was measured. Do not bundle two slices because one "looks small".

| Slice | Done means |
|---|---|
| **tray exit slice** — **done 2026-11-13 (D-053)** | The native tray menu's two labels come from the language packs and are re-drawn when Settings changes language (a listener on `settingsProvider`/`i18nProvider`, not a boot-time literal), and the tray surface's Arabic is rewritten in فصحى (`شغّال`/`مقفول`/`الفايروول`/`بيتصل` → `مفعّل`/`معطّل`/`الجدار الناري`/`جارٍ الاتصال`). `Quit` is now a labelled **full exit**: `shell.tray.quit` reads "Quit MI CS completely" (ar: "إغلاق MI CS بالكامل") with a `shell.tray.quitHint` tooltip, `TrayPanelController.quit()` stops the owned engine and then always destroys the window (both best-effort, so neither can strand the other), and `stopOwnEngine` cancels the reconnect timers before the ownership test. Proved by a new case in `test/tray_panel_test.dart` that taps Quit and asserts the fake engine's stop ran and `window_manager` received `destroy`; by the regenerated `qa/ui/ledger.json` line (`OutlinedButton(Quit MI CS completely)`) and `qa/report.md` (157 declared Dart cases); and by `scripts\pipeline.ps1 -Tier fast` green (analyze, 187 Flutter tests, engine tests, clippy, signer). **Honest limit:** that case proves the app *asks* for both halves, in order — it is not a process-tree proof. On Windows the engine is additionally ended by the synchronize handle it holds on this process (`engine/src/platform/windows/parent.rs` waits on it), so a real quit should leave no engine, but confirming an empty `tasklist` needs a built package and was not run in this slice. |
| **Explorer verb slice** — **done 2026-11-13 (D-054)** | The right-click entry a portable or Store copy never had: **Settings → Protection → Add to the Explorer right-click menu** writes the same three per-user verbs `installer/mics.nsi` has written since D-041 (`HKCU\Software\Classes\*\shell\MICS`, `Directory`, `Directory\Background`; command `"<mics_app.exe>" --scan "%1"`, `%V` on the empty space), and turning it off deletes exactly those three trees. The engine owns the write — one `mutating` method, `explorer.menu.set` = `{enabled: true\|false}` — key paths and command lines come from pure functions (`entries`, `scan_command`, and `command_exe` for reading back what Explorer would run) over a `UserRegistry` seam, and **`HKCU` only, never `HKLM`**: no elevation, so a portable copy gets the same feature as an installed one. **Off by default** (`explorer_menu: false`), the flag being the app's memory of what *it* registered, which is what lets the surviving window call `syncExplorerMenu()` at start and refresh a stale path after the folder moved. Labels are the app's own pack text (`scanner.menuFile`/`scanner.menuFolder`, ar: "فحص هذا الملف/هذا المجلد باستخدام MI CS"). Proved by the engine's six new cases in `engine/src/tests.rs` (a path with spaces and non-ASCII, the enable/disable key sets compared for equality, `command_exe` read-back against `scan_command`), by `test/ui_screens_test.dart` and `test/settings_model_test.dart`, and by the regenerated registry: `qa/methods.json` 72 rows, ledger 103 controls (`SwitchListTile(Add to the Explorer right-click menu)`), report 158 declared Dart / 209 engine cases — with `scripts\pipeline.ps1 -Tier fast` green (analyze, 188 Flutter tests, engine tests, **clippy after a `chunks_exact` → `as_chunks` fix**, signer). **Honest limits:** an installed copy still gets its entry from the installer at install time, with the fixed English label, while the app's flag starts `false` — so on that copy the switch can read off while the entry is present; turning it on adopts the pack's language and turning it off removes it. And the stored `command` value can be rewritten by any same-user process, exactly as before D-054: the entry starts MI CS, which validates the path it is handed like any other. |
| ~~**ز2-ب** hang detector~~ — **done** (2026-11-02) | A `std::thread` watchdog started with the session marks a heartbeat the tokio runtime bumps; if the heartbeat stops for the deadline the watchdog writes a `hang` report itself (a plain OS thread still runs when the runtime is wedged) and logs it. The report says how long the runtime was stuck and what the last request was. Tested by freezing the heartbeat on purpose; the honest limit (a hang that takes the whole process, e.g. a deadlock inside the allocator, is invisible) goes in the code and the Done log. |
| ~~**ز2-ج** bug-id surface~~ — **done** (2026-11-02) | Settings → Diagnostics lists `crash.list`, opens one report with `crash.get`, offers copy and `crash.delete`; the text the user pastes contains the bug id first. `qa/ui/fixtures.json` gains reports, the sweep taps the new controls, `qa/ui/ledger.json` is regenerated and the diff reviewed, and a behaviour test proves the id on screen is the id the engine reported. |
| **ز2-د** delivery | Not before **D-023** (opt-in, user-configured destination only, rule 8) and not before the user names the Open WhatsApp bridge endpoint. The engine gains `mics-engine report <bug-id> --to <configured destination>`; nothing is sent unless the user configured it and switched it on. |
| ~~**ز3** cards~~ — **done** (2026-11-02) | Bottom corner: right in LTR, left in RTL (read `rtlProvider`, never a language name), fed by the existing `alert.rs` gate; a crash card carries the bug id and says delivery is off (no report has a delivery state until ز2-د, D-024). The engine pushes the card as its own `alert` notification, parks it when no UI is attached, and the shell paints it as a widget the sweep can tap. |
| ~~**ط1** fingerprint~~ — **done** (2026-11-02) | The Rust build compiles with `--remap-path-prefix=$env:USERPROFILE=/build` (in `make-release.ps1` and the `engine.build` step), and the shipped engine went from **1238** hits of the account name to **0**. `scripts/verify-opsec.ps1` counts the markers and compares them with `qa/opsec-baseline.json`: a forbidden string (the profile path and its leaf, computed on the machine running the probe) must be absent, a counted marker (`flutter`/`dart`/`cargo`/`rustc`/`pubspec`) may only fall, a binary missing from the baseline fails until a human adds it with a reason, and an entry with no reason fails. `test/opsec_baseline_test.dart` guards the file in the fast tier. Run by `make-release.ps1` on the staging folder, so a leaking build is never packaged. |
| ~~**ط3** wiring~~ — **done** (2026-11-02) | `scripts\pipeline.ps1` gained its first `release`-tier step, `opsec.verify`, which runs `verify-opsec.ps1` against `dist\MICS-portable` - the packaged artifact, not the build folder - so `-Tier release` refuses a package that names the build account or grew a counted fingerprint. `verify-tamper.ps1` joins it with ط2. |
| ~~**ج2** manifest + self-check~~ — **done 2026-11-03, both commits** | **The design is `D-025` plus its two dated amendments.** *The producer*: `make-release.ps1` signs every staged file except the engine, builds `MICS_MANIFEST` (`format`, `version`, `files[{path, bytes, sha256}]`, sorted by path) from those final bytes, injects it as an `RT_RCDATA` resource into the staged `mics-engine.exe`, and signs the engine **once, after** the injection — an injection into an already-signed engine cannot be signed again (`0x800700C1`, measured; the amendment in `D-025` records it). `scripts\manifest-resource.ps1` is the one place the format lives (build, inject, read, validate: ordinal order, no duplicates, no `..` path); `scripts\verify-manifest.ps1` re-reads the resource out of the package and re-hashes every listed file, so a package whose manifest does not describe it never leaves the staging folder, and `manifest.verify` runs it from `-Tier release` too. *The reader*: `engine\src\selfcheck.rs` reads the resource out of its own image with `LOAD_LIBRARY_AS_DATAFILE`, refuses a document that is not the shape this build writes (format, a version, no duplicate, no path that walks out of the package, a 64-hex hash per entry), re-hashes every listed file against the folder it runs from, and classifies its own signature through `platform\windows\signature.rs` — which now separates "our certificate and Windows trusts it" from "our certificate and this Windows has not trusted the root yet" (`CERT_E_UNTRUSTEDROOT` plus the embedded signer read through `CryptQueryObject`) from everything else, because a changed byte reports `TRUST_E_BAD_DIGEST` and must never be the quiet state. `status.integrity` carries `ok` / `untrusted-certificate` / `unverified`; the verdict is computed once at start-up and cached, so the UI's 15 s heartbeat never re-hashes 30 MB. Settings → About shows one green line, one neutral line or the notice, and only `unverified` **with a manifest present** raises the alert card — a developer build has no resource and is not an alarm. The engine is not in its own manifest; its integrity is the signature. Measured, not assumed: the manifest's file names enter the engine's strings, so its `flutter` count rose 0 → 55 and its `dart` count 0 → 1 — a written reason per row in `qa\opsec-baseline.json`, and the QA report regenerated in each commit. |
| ~~**ط2** tamper~~ — **done 2026-11-03** | `scripts\verify-tamper.ps1` tampers one thing at a time in a private copy under `%TEMP%` and asks both halves - the release gate (must refuse) and the packaged engine, started on a private pipe (must answer `unverified`, name the file in its log and in the card it pushes). Cases: **a byte flipped in each of the nine shipped binaries** (the eight listed ones refused and reported by name; the engine refused by the gate with `HashMismatch`, never run after a code edit), **a same-size swapped DLL** (a system DLL padded to `dartjni.dll`'s exact length, and one of our own plugins cut to it - refused **by hash**, so a signed-but-wrong DLL is no more welcome), **an edited manifest** (one hash zeroed inside the resource: refused, and reported, with the engine `NotSigned` afterwards as D-025 measured), **a repack** (the published document injected into the unsigned release engine: refused and reported), and **a copied install** (accepted while it is byte-identical, reported as soon as one file changes; a copy used as a *client* is the caller rule's business, D-015). The pristine copy is the control. **Measured: 41 checks, 0 failures, 108.5 s**; the release tier gained `tamper.verify` (11 steps across 3 tiers). **It also found a hole**: a stripped Authenticode signature used to pass `verify-manifest.ps1` because only `HashMismatch` failed - the gate now requires the pinned `MI CS Code Signing` and refuses no signer, another subject and a changed byte alike, with the CN in one PowerShell constant (`MicsSignerCn`) pinned to the engine's `EXPECTED_SIGNER_CN` by a Dart test. |
| ~~**د5** report~~ — **done** (2026-11-02) | `qa/report.md` + `qa/report.html`, generated by `qa/report.dart` from the committed registries only (no clock, no  | machine path, no run timing) and byte-compared by `test/qa_report_test.dart`, so a method/screen/control/language/binary/test-file/pipeline-step that lands without the report lands with a red fast tier - the same ratchet as the UI ledger. The gates it carries: the dispatcher and `qa/methods.json` agree; every language directory is listed under `assets:`; every `skip` reason is at least 20 characters; the surface is not degenerate; the report names no machine. What it deliberately is not: a run - `build/qa-contract.json` and `build/pipeline-<tier>.json` stay the measured half, and CI uploads them next to it. |

| ~~**و4** the executable LOW rows~~ — **done 2026-11-03, five commits** (a–e in the Done log), each closing its register row with the proof that row names | (a) the API keys left `settings.json` for a DPAPI-protected `secrets.dat` with a one-way migration, proved by five engine tests that search both files for the values that went in; (b) the blocking `vuln.scan` was **deleted** after the callers were checked — the natural-language command bar was the one caller the register did not know about, and its intent now starts the job, so there is exactly one scanning path (65 methods); (c) every audit section carries the time it was collected, a merge keeps the old time for what it did not re-read, and the screen prints "Not re-checked now — read at HH:MM" on those findings and inventory headers (engine + widget test); (d) the guard's cost re-measured with the **shipped** pack: 0.156–0.521 % of one core over four 60 s windows, median 0.417 %, and the old "0.234 % with the starter pack" explanation is written down as refuted. Closing **by evidence**: the incomplete-package HIGH row (a package with `rules\` removed and its sums corrected → `verify-release.ps1` **exit 1**, four FAILs naming the missing packs and the fallback the engine logged), the portable caller check (`verify-helper.ps1` now runs the F-2 layout: non-engine caller refused, `no installer account recorded` logged, the same probe served only with the `MICS_ENGINE_PATH` pin — PASS, 15 checks), and the AUMID attribution row (closed as a documented limit, `THREAT-MODEL` §B10 unchanged). Rows left open **for your decision**: GeoIP list licensing, the detection pack's content, the thumbprint-vs-CN update pin (D-016), the language-tag policy, and IDS beyond DNS. |
| ~~**ب2** the ARM64 leg~~ — **done 2026-11-03, as far as this machine allows, and it says where it stops** | The engine **builds** for `aarch64-pc-windows-msvc` here and the artifact is checked: `scripts\build-engine-arm64.ps1` (new) resolves the toolchain, builds with the same CFG + path-remap flags as x64, compiles the **test binaries** too (`-WithTests`), and `verify-hardening.ps1 -Arch arm64` reads the PE back — `machine arm64 (0xAA64)`, `GUARD_CF`, `CF_INSTRUMENTED`, `CF_FUNCTION_TABLE_PRESENT`, stripped (engine 19,994,112 bytes). `make-release.ps1` gained `-Arch x64\|arm64` (engine `--target`, `build\windows\<arch>`, `-<arch>.zip`, `VERSION` line, `SHA256SUMS`) and refuses ARM64 with a measured prerequisite list (`-CheckToolchain`, seven rows, **2/7 missing here**). `verify-release.ps1` takes the arch **from the artifact's name and `VERSION` line** and fails a package whose PE does not match; `verify-hardening.ps1` infers or enforces the arch instead of assuming x64. The Flutter half has **no** windows-arm64 path on this machine: `flutter build windows` has no cross-compile flag and the SDK's cache holds `windows-x64*` only, so a portable ARM64 package still needs an ARM64 host (7th prerequisite row). **No ARM64 hardware exists here: nothing produced was ever executed**, no probe result is copied from the x64 run, and the Done log says exactly that. |
| ~~**د3** E2E on the built installer~~ — **done and measured 2026-11-07** | The automatable half already ran in the probe (a silent `-TestUser` install into `%TEMP%`, the shortcuts' `System.AppUserModel.ID`, the AUMID key, the Apps-&-features entry, the uninstaller removing exactly what it created, and the refusal against a synthetic service key — all in `verify-installer.ps1`). **The per-machine half ran for real on 2026-11-07** with one UAC prompt per action: 72 files under `%ProgramFiles%\MI CS` (the 70-file package + `uninstall.exe` + one stray `mics-engine_IObitDel.exe` that was already in that folder), the per-machine Start-Menu group, the `HKLM\…\Uninstall\MICS` entry, the **installer** creating the helper (D-026: `"C:\Program Files\MI CS\mics-engine.exe" helper-service`, LocalSystem, AUTO_START, running) with its `phase=note`/`phase=start`/`phase=done` trail in `priv.log`, privileged ops driven from an **unelevated** engine with **zero** further prompts (`fw.rules.add` 37 ms, `fw.rules.remove` 36–44 ms, both `ok=true`), the installed tree's start-up self-check reporting **68/68** files in the `untrusted-certificate` state, and the uninstaller removing the product, the service (`sc qc` → 1060), the Start-Menu group and the registry row (exit 0) while the user's own `%LOCALAPPDATA%\MI CS` copy stayed untouched. `%PROGRAMDATA%\MICS` is kept on purpose. **Not exercised, and named:** *Default deny outbound*, the SMBv1 toggle and the hosts write. |
| **Row 17 slice (a)** (the WFP layer) | **Written 2026-11-08 (D-042), evidence incomplete on purpose.** The machine is not this session's to elevate, so the pickup is two commands: (1) reinstall `MICSHelper` — in the installed app, Settings → Engine → *Install helper*, or `mics-engine.exe helper-install` from an elevated shell — because the helper already running on this machine only knows the eight pre-D-042 ops, which is why every write is refused today; (2) run `scripts\verify-wfp.ps1 -EngineExe engine\target\debug\mics-engine.exe` in an elevated shell and paste its numbers (checks, the created filter's key as `netsh wfp show filters` shows it, and whether `fw.wfp.status` then reports `sublayer=true filters=1`) into `D-042` and the §0.6 row. Do **not** mark slice (a) closed on the unit tests alone: what is unmeasured is exactly what a unit test cannot see — a real connection to the blocked port failing, the filter outliving a reboot, and the sublayer's weight beating the built-in firewall's permit. |
| **Row 17 slice (b)** (live connections + one-click block) | **Written 2026-11-08 (D-043), the same elevated run outstanding as (a).** It turned out not to need a new method: `net.connections` already existed and was the thing to fix — it was IPv4 TCP only, so the walk moved to `engine\src\platform\windows\conns.rs` over all four tables with the owner's **image path** resolved through a handle, and the row now carries the spec a click would send (`block`) or `null` with the reason why not. The UI forwards that spec to the existing `fw.wfp.block`, so a click writes a persistent filter rather than a session rule. Measured unelevated: `scripts\verify-connections.ps1` **23 checks, 0 skipped, 0 failed** (490 rows; 139 with a spec that matches the row and whose file exists; 0 owner contradictions with Windows' own cmdlets; IPv6 and UDP rows present; the write refused with a reason and nothing left behind). **What is still unproven** is the same sentence (a) is waiting on: that an accepted spec blocks that row's connection — run the probe elevated (after reinstalling the helper) and its part 3 takes the write branch instead of the refusal branch. The honest limit stays in the matrix: this is a snapshot, not a push, and there is no un-block from a row. |
| **Row 17 slice (c)** (tamper alert) | **Written 2026-11-09 (D-044), with the detector measured and the machine-reading half still needing an administrator.** The record of what MI CS wrote lives beside the objects (`meta` row `wfp_baseline`, written after a successful `fw.wfp.block`, removed by `unblock`, cleared by `reset`), and `fw.wfp.watch` compares it against the filtering engine: `guarded`, `tampered` (naming the sublayer and each missing filter), `clear`, `unrecorded`, or `unknown` when neither this process nor the helper may read the BFE. A tamper raises one HIGH guard event per change — an incident titled "MI CS' filtering layer was tampered with", a card with its own copy and icon, the correlator timeline — and the guard thread polls it about every 30 s. Measured unelevated: `scripts\verify-wfp-watch.ps1` **38 checks, 1 skipped, 0 failed** (the detector, the alert, the once-per-change rule, and `unknown` instead of a false alarm), and 10 unit tests on the pure comparison. **What is still unproven** needs an administrator, exactly like (a) and (b): deleting a *real* filter (or the sublayer) behind the engine's back and watching this notice, and the guard thread's own 30 s poll firing rather than the method being called directly. **It is deliberately not a self-healing watchdog**: re-adding a filter an administrator deleted would fight the machine's owner, so the alert is the whole feature. |
| ~~**Row 5 slice 2** (a signature over `update.json`)~~ | **Done 2026-11-09 (D-047).** `make-release.ps1` step 9b writes a detached PKCS#7 beside the manifest (`sign.ps1 -DataFile`, the same identity that signs the binaries, verified by reading its own bytes back), and the engine verifies it **before** it parses a field: `update.rs` fetches `<manifest>.sig` with the new `SyncManager::fetch_bytes`, `signature.rs` gained `verify_detached` (`CryptVerifyDetachedMessageSignature`, signature only - no chain trust, so a self-signed development build works) and `pinned_update_thumbprint` (the D-016 pin: `MICS_UPDATE_SIGNER_THUMBPRINT`, else the certificate over the running engine), and `update.check` answers with `signature`, `signer`, `signer_thumbprint` and `pinned` so the screen can print who signed the feed and whether that was checked against a pin. Unsigned, other-key, tampered, and wrongly-pinned feeds are refused with the signature as the reason and stage nothing; a manifest that is signed but lies is still refused by the SHA-256 check, so the signature did not replace it. Measured: `scripts\verify-update.ps1` **45 checks, 0 failed, 0 skipped, 8 s** against the unsigned debug engine (on a *signed* engine, part 8's five checks are recorded as one `SKIP` with the reason that the name fallback needs an engine with no signature of its own), 6 new engine cases (**200 in total**: 3 in `update.rs`, 3 in `signature.rs` including one against a committed signed fixture), and one throwaway end-to-end run proving the engine accepts a signature `sign.ps1 -DataFile -SelfSigned` produced (pin `9488d80e…`, `pinned: true`). Two corrections are recorded in D-047 — the `Release` workflow handed `secrets.MICS_PFX` to a variable `make-release.ps1` does not read (it reads `MICS_PFX_B64`), so a donated certificate would have been ignored; and the probe's part 8 exists because "no certificate exists yet" is a reason for the check to say *which* check it managed, not a reason to skip it — plus a third: `docs/THREAT-MODEL.md` had claimed (twice, since it went stale) that `update.apply` never calls `WinVerifyTrust` on the extracted payload, which it does (`require_signed_by`), so F-3's payload gap is a subject name rather than a thumbprint, not an absent check. |

**Still open for the user** (asked 2026-11-01): approval of **D-023** (opt-in,
user-configured crash reports — rule 8 of `AGENTS.md` forbids any other outbound
destination) and the endpoint shape of the **Open WhatsApp bridge** (the user
chose an Open WhatsApp integration, *not* WhatsApp itself, so no Meta Cloud API
work is needed). Neither is needed for ز3, which reads the existing alert gate and
only has to say that delivery is off.

### 0.4 Environment must-knows (the short version of §8)

- **Before every commit**: `powershell -NoProfile -ExecutionPolicy Bypass -File
  scripts\pipeline.ps1 -Tier fast -CargoTargetDir "$env:TEMP\mics-target"`. That is
  the same four checks `AGENTS.md` names (`cargo test`, `cargo clippy --release --
  -D warnings`, `flutter analyze --no-pub`, `flutter test --no-pub`), in order, with
  the environment (`YRX_REGENERATE_MODULES_RS=false`, `CARGO_TARGET_DIR`) already
  set - do not retype them, or the local run and CI drift apart again. `-List`
  prints the steps, `-Only 'engine.*'` runs a subset, and `-Tier full` adds the
  release builds plus the engine smoke.
- **One phase = one conventional commit**, and this file is updated in the same
  commit. Commit messages are written to a file under `.git\` and passed with
  `git commit -F` (the write tool cannot expand `$env:TEMP`).
- **Proof is textual, never visual**: engine logs, Windows' own toast history
  (`scripts\verify-toast.ps1 -HistoryOnly`), `Get-AuthenticodeSignature`,
  `VersionInfo.FileDescription`, the Shell API, `verify-*.ps1` `RESULT:` lines.
- **The release is hardened and the script enforces it** (ج1, D-021): the first
  `make-release.ps1` after a clean target dir spends **~12 minutes** in the engine's
  fat-LTO codegen (cached afterwards), and it refuses to package an app that was not
  built with `--obfuscate` or a binary that fails `scripts\verify-hardening.ps1`.
  The Dart symbol table lands in `dist\symbols\<version>\` — gitignored, never in
  the ZIP, and the only thing that can symbolicate a crash.
- **PowerShell 5.1 traps** (§8): native stderr + `$ErrorActionPreference = "Stop"`
  turns progress output into a terminating error; `Copy-Item -Recurse` nests;
  never delete the live package folder; UTF-8 must be written with
  `[System.IO.File]::WriteAllLines(..., UTF8Encoding($false))` to avoid the
  double-encoded README that happened once. Scripts stay ASCII-only.
- **The installer needs NSIS, but not on `PATH`** (ب3): `make-installer.ps1` also
  looks in `%LOCALAPPDATA%\mics-tools\nsis-<ver>\makensis.exe`, so an unzipped
  portable copy is enough — *building* needs no elevation, only running the
  per-machine installer does. **Never run a setup or a verifier from `dist\`**:
  that folder is Low-integrity (trap 21), so the process cannot even create its own
  `%TEMP%` target and a silent install exits **0 having done nothing**. Copy the exe
  to `%TEMP%` first (step 3 turns exactly that into `scripts\verify-installer.ps1`).
  Also: a GUI installer does not block `&` in PowerShell — use
  `Start-Process -Wait` or you measure nothing.
- **The installer writes the two things NSIS cannot** (ب3 step 2, every trap
  measured): the shortcuts' `System.AppUserModel.ID` (a Shell property — `WriteRegStr`
  covers only the registry half) and the answer to "does the helper point at this
  copy", both through scripts it unpacks into `$PLUGINSDIR`, never into `$INSTDIR`.
  Traps: a native command line binds only the **first** value to a PowerShell array
  parameter (`-Shortcut "a" "b"` tags `a` and silently drops `b` — one call per
  shortcut); an uninstaller **always answers 0** to its caller because NSIS copies it
  to `%TEMP%` and runs it there (appendix D.1), so read a refusal with
  `uninstall.exe /S _?=$INSTDIR`, and put `_?=` **last** or NSIS swallows the rest of
  the command line into `$INSTDIR`.
- **`make-release.ps1` needs `-EnginePath` in this checkout** (measured 2026-11-01):
  `engine\target\release\mics-engine.exe` is a **stale pre-ج1** build (35.7 MB, no
  `GUARD_CF`), so the default run is refused by its own hardening gate. The real
  engine lives where `CARGO_TARGET_DIR` pointed:
  `-EnginePath "$env:TEMP\mics-target\release\mics-engine.exe"`. The gate catching
  this is the system working — do not "fix" it by relaxing the gate.
- **Reply to the user in Egyptian Arabic**; code, comments, docs and commit
  messages in English. Never add telemetry or cloud calls; the UI never touches OS
  APIs — everything goes through the engine over JSON-RPC (`lib/core/ipc/`).

### 0.5 The order the user asked for: small → medium → large

On 2026-10-31 the user set the sequence for what is left: finish whatever is
waiting on a human **first**, then the small tasks, then the medium ones, then the
large ones. Two of the three human items are settled (the VirusTotal client is
deleted — D-019, small step 2; the shortcut name stays «MI CS» — D-020, small
step 3, no code change) and the helper's install prompt was answered the same
day, so what
remains human is the answers in §0.2 items 3–5 — the certificate is closed as
not-purchased and the three-operation helper acceptance ran on 2026-11-07 (§0.2 item 1).
The steps below are the same work as §0.3, split by size so a session always knows
what "next" means.

**Small — one sitting each, no elevation, no money, no new subsystem**

| # | Step | Note |
|---|---|---|
| 1 | ~~`docs\COST.md` (ب1b)~~ | **done** — this commit |
| 2 | ~~Delete the dead VirusTotal client (`engine/src/scanner/vt.rs` + its wiring and tests) and say in the README that hash lookups are gone~~ | **done** — D-019; the register MED row closed with it |
| 3 | ~~Close the Start-Menu shortcut name decision (keep «MI CS»)~~ | **done** — recorded as D-020; the name already matched |
| 4 | ~~Dark-mode contrast audit → fix, mirroring أ2/أ3~~ | **done** — 7 of 29 dark pairs failed, all fixed; both modes now assert 29 of 29 (`docs/CONTRAST.md`, `test/dark_contrast_audit_test.dart`) |
| 5 | ~~Light-theme screenshots for the README (the same proof-is-textual rules apply: the images illustrate, the text proves)~~ | **done** (small step 5) — four 1600×1000 light-theme renders of the real UI, Arabic RTL, from `tool/write_screenshots_test.dart`; each one is asserted non-empty and the fonts are proved loaded |
| 6 | ~~Icon pass: `test/icon_test.dart` + `app_icon.ico` sizes, per §"Icon sizes required"~~ | **done** (verified in small step 6) — the test pins the ten sizes on all three `.ico` files and 6 assertions pass |
| 7 | ~~`docs/PROTECTION-MATRIX.md` as a standalone sheet a stranger can read~~ | **done** (verified in small step 7) — 10 sections, per-layer sees/detects/blocks, evidence table; README links it |
| 8 | ~~Remaining LOW register rows that are cheap: obfuscation/manifest text, the caller check's `%PROGRAMDATA%` fallback note, and any row whose fix is one file~~ | **done** (small step 8) — the two notes are written into `THREAT-MODEL.md` (F-11 new, F-2 extended) and the README; the register rows now point at them |
| 9 | ~~The register's *when the engine cannot start at all, the UI cannot say why* row, and §0.6 row 10's two documentation debts~~ | **done** (small step 9) — a start that fails re-runs the engine once with stderr piped, keeps the last twelve lines it printed and shows them in Settings → Engine under *Why it would not start* (`test/engine_refusal_test.dart` for the tail and its bound, the two `settings:` cases in `test/ui_screens_test.dart` for the sentence reaching the screen); the i18n diagram lists all 19 modules; and `verify-installer.ps1` asserts the 70 files the per-user variant installs |

**Medium — a subsystem or a build leg**

- ~~**و1** scheduled scan~~ — **done 2026-11-03** (D-027, both commits): opt-in
  `scan_interval_hours` (0 = off, default), `scan_target` (empty = profile), the
  engine's own record of the last start, report-only, the Settings switch and folder
  with ar/en copy, and `scripts\verify-scan-schedule.ps1` (18 checks) proves all three
  claims; the register's MED row now points at real-time watching (و2) only
- ~~**و3** `netsh` → FirewallAPI COM~~ — **done 2026-11-03** (D-028): the firewall is
  `INetFwPolicy2`/`INetFwRules`/`INetFwRule` in-process, same public shape and same
  helper payloads, every rule carries an explicit all-profiles mask and the "MI CS"
  group, and `scripts\verify-firewall.ps1` (23 checks) proves the reads match Windows
  and a created rule is the rule Windows enforces — with a fake `netsh` on PATH to
  prove the dependency is gone
- ~~**ب2** ARM64 (Flutter target + `aarch64-pc-windows-msvc` engine, D-003)~~ —
  **done as far as this machine allows**: the engine builds with the same CFG and
  path-remap flags, its **test binaries** compile, the PE is read back as a hardened
  ARM64 image and CI runs the tests natively on `windows-11-arm`; the ARM64 **app**
  still needs an SDK Flutter does not publish (§0.6 row 6)
- ~~**ج1** build hardening (Rust LTO/strip/`panic=abort`, PE mitigations, Dart
  `--obfuscate --split-debug-info`)~~ — **done** (D-021), with the numbers in §0.3
- ~~**ج2** signed manifest + startup self-check + "unofficial build" banner~~ —
  **done** 2026-11-03 (D-025, with ط2's tamper probe)
- ~~**ب4** the helper install folded into the installer (removes the UAC step)~~ —
  **done** 2026-11-03 (D-026), and **the per-machine run happened 2026-11-07** — one
  prompt installed product + service, one prompt removed both (§0.2 item 1)
- ~~**د1** `qa/` JSON-RPC harness, **د2** per-screen widget tests~~ — **done
  2026-11-01**, with **د3** (E2E on the built installer) following on 2026-11-07
- ~~**هـ1** a default update-manifest URL + signature check~~ — **done 2026-11-09**
  (D-046 the feed, D-047 the signature and the thumbprint pin)
- ~~**canary read-only** (the register's MED row)~~ — **done 2026-11-05 (D-032)**: the
  variable the row was missing is the last-access time, not a driver, so a read-only
  open is a HIGH `canary_read` event of its own (`CANARY_READ`), a write stays
  CRITICAL, a decoy MI CS has just written is settled for 90 s and says so in the log,
  and `scripts\verify-canary.ps1` (20 checks, PASS) measures all of it against a real
  engine — plus that the volume's read coverage is measured and reported rather than
  assumed. See the Done log for the defect the probe found on the way
- the register's open MED rows: Defender tamper protection, real-time watching

**Large — where a human used to be required (and no longer money)**

- ~~**د4** `qa/report.html` + CI gate~~ — **done** (the checkbox was stale; see §0.3)
- ~~**د3** E2E against the built installer~~ — **done and measured 2026-11-07** (§0.2 item 1,
  closed); the unexercised three toggles are noted there and nothing waits on them
- **ب5** the certificate — **not bought, and free to obtain**: nothing is purchased
  (D-035), and the re-research of 2026-11-07 (**D-036**, `docs/SIGNING.md`) found two
  routes that sign for free — the Microsoft Store re-signing an MSIX (available today,
  and it is **packaging work** plus the three unknowns in `SIGNING.md` §3) and OSSign's
  project certificate (a date: ~2027-04-27). The wiring stays (two secrets, D-034), so a
  **donated** certificate still lands with **no code change**
- ~~**ب6** publish `v0.1.0`~~ — **done 2026-11-10**: the draft became a published release and the
  download was verified against its own release page on 2026-11-11 (§0.6 row 1). Its successor is
  **ب7**, one signing identity per release, whose engineering half landed 2026-11-12 (row 18)
- real-time file watching as a real subsystem

---

### 0.6 What is missing, at a glance (recounted 2026-11-11)

**The baseline this is counted against:** `main` at `173224a`, where
`scripts\pipeline.ps1 -Tier fast` is **green — 4 of 4 steps, 181 s** (`flutter analyze`
clean, `flutter test`, `cargo test`, `cargo clippy`), recorded in
`build\pipeline-fast.json`. Everything *not* in the table below is done and measured;
§0.3 and §7 carry the detail, `docs/ROADMAP.md` carries the order and the estimates.
The gate was run again at the end of this documentation pass — **green, 4 of 4,
76.9 s, 150 engine tests** (warm caches; the earlier 181 s was the cold one) — after
the acceptance run and after the certificate-store fix in §8. **Re-run 2026-11-08**
for row 4 (the reproducible build): **green, 4 of 4, 402.8 s, 151 engine tests** —
cold, because the reproducibility measurement had just cleaned `engine\target`, so
that number is a from-scratch one and not comparable with the 76.9 s beside it —
and once more when the work was finished, **green, 4 of 4, 385.3 s, 151 tests** —
the report `build\pipeline-fast.json` holds (its `head` is the commit before the
last documentation-only amend). **Re-run 2026-11-08 for the firewall rule-name fix:
green, 4 of 4, 91.3 s, 152 engine tests** — warm, with the release profile and the
Flutter caches already built, which is why it is not comparable with the cold runs
above.
**Re-run 2026-11-08 for the engine's lifetime (D-039, §0.6 row 14): green, 4 of 4,
60.9 s warm, then **94.6 s** once the last source edit forced the engine to be rebuilt,
158 engine tests.**
**Re-run 2026-11-08 for Explorer's verb (D-041, §0.6 row 16): green, 4 of 4, 66.4 s —
warm, with `flutter test` at 158 and 162 engine tests — and separately
`scripts\verify-handoff.ps1`, which is not part of the tier, PASS **10 checks, 0
failures, 5.1 s** against a real engine on a private pipe.**
**Re-run 2026-11-08 for the WFP slice (D-042, §0.6 row 17 slice a): green, 4 of 4,
154.4 s — 174 engine tests, `engine.clippy` clean, `head` `9b72d0b`** (the first attempt
failed on two `collapsible_if` warnings in the new `wfp.rs`, which is the gate doing its
job; the fix is in the commit). Separately, and outside the tier: the RPC contract against
the same binary **86 cases, 0 failed**, and `scripts\verify-wfp.ps1` unelevated **7 checks
passed, 3 skipped, 0 failed**.
**Re-run in pieces for the live connection list (D-043, §0.6 row 17 slice b) on
2026-11-08: `cargo test` 180, `cargo clippy --release -- -D warnings` clean,
`flutter analyze --no-pub` clean, `flutter test --no-pub` 160 passing, and the pipeline's
own steps were not repeated end to end — the change touched no other step.** Separately,
and outside the tier: `scripts\verify-connections.ps1` (new) unelevated **23 checks
passed, 0 skipped, 0 failed**, and the RPC contract against the same debug binary
**86 cases, 0 failed**.
**Re-run 2026-11-09 for the tamper watch (D-044, §0.6 row 17 slice c): green, 4 of 4,
113.6 s — 190 engine tests, `flutter test` 162, `engine.clippy` clean.** The first attempt
failed on `collapsible_if` in the new `watch.rs` and, separately, on
`qa_report_test` because the report's test-file count moved when
`test\alert_card_test.dart` was added — both were the gates catching the change, and the
regenerated report is in the commit. Separately, and outside the tier:
`scripts\verify-wfp-watch.ps1` (new) unelevated **38 checks passed, 1 skipped, 0 failed,
4 s**, and the RPC contract against the same debug binary **87 cases, 0 failed**
(73 methods, 109 controls).

**Re-run 2026-11-10 for the engine-refusal row (small step 9): green, 4 of 4, 66.1 s — 200 engine tests, `flutter test` 167, `engine.clippy` clean.** The first attempt failed `qa_report_test`: adding a Dart test file moves the report's own count (28 → 29 files, 132 → 137 declared cases), which is the gate catching the change rather than a defect — `qa/report.md`/`.html` are regenerated in this commit and the counts above are the regenerated ones.

**Re-run 2026-11-10 for the guard's ETW IOC-hash row (§7 register, the cheapest open LOW): green, 4 of 4, 74.7 s warm, then 57.6 s on the frozen tree — `cargo test` 201 passed / 0 failed, `engine.clippy` clean, `flutter.analyze` and `flutter.test` untouched by the change.** The first attempt failed `qa_report_test` for the same reason as the run above: one new engine case moves the report's per-file count (`engine/src/tests.rs` 55 → 56, total 200 → 201), and the regenerated report is in this commit. Nothing in the tier is a probe yet — what that row closes with is a dead load removed, one coverage fact moved into one function, and a unit test that pins it.

**Re-run 2026-11-10 for the unrenderable-language-tag row (D-049, §7 register, the cheapest open LOW left): green, 4 of 4, 69.6 s, then 59.2 s on the re-run of the frozen tree (`engine.clippy` cached at 2.5 s) — `flutter analyze` clean, `flutter test` 172 passed (5 of them new), `engine.test` 201 passed, `engine.clippy` clean.** The first attempt failed `qa_report_test` once more, and the gate is right to: five new Dart cases move the report's counts (137 → **142** declared cases, `test/settings_model_test.dart` 6 → 10 and `test/ui_screens_test.dart` 10 → 11), and the regenerated `qa/report.md`/`.html` are in this commit. The engine is untouched by the change — its 201 tests and clippy time are the same work as the run above. The two new cases were also run against the **pre-D-049** fallback (Arabic) before the commit: exactly those two fail, which is what makes them a pin rather than a description.

**Re-run 2026-11-11 for the publish-verification rows (§0.6 row 1 closed, plus the MED row and row 18 it created): green, 4 of 4, 63.7 s — `flutter.analyze`, `flutter.test`, `engine.test` and `engine.clippy` all pass, engine **206 passed / 0 failed** after D-051's five new cases, clippy with zero warnings allowed.** Documentation only, so nothing in this change can move those numbers: the evidence this commit adds is *outside* the tier and is a real artifact rather than a build — the published `SHA256SUMS` re-hashed on this machine, `scripts\verify-manifest.ps1` reporting `PASS - all 67 listed file(s) hash as the signed manifest says`, `Get-AuthenticodeSignature` on the published setup EXE and on the engine inside the archive, and a count of the certificates the release lane has scattered through this user's stores.

**The constraint that shapes every row:** this is a free, open-source project with **no
budget** — nothing can be bought, not a certificate, not a tool, not a service. Every
row that used to say "buy" now either has a free substitute or is written down as out
of reach instead of pending. Re-researched on 2026-11-07 (`docs/SIGNING.md`, D-036):
"no budget" does **not** mean "no signature" — it means the signature has to come from
somebody who signs for free.

| # | What is missing | Free? | Blocked on | How it closes |
|---|---|---|---|---|
| 1 | ~~**A published download** — `v0.1.0` is built, verified and **draft**; the public Releases page says "There aren't any releases here"~~ | ✅ | — | **closed 2026-11-10 by the owner's one click, and verified 2026-11-11**: four assets on the releases page — `MICS-setup-0.1.0-x64.exe` 16,642,682 bytes `sha256 5cd206db...`, `MICS-portable-0.1.0-x64.zip` 23,111,206 bytes `sha256 1eafe3ee...`, `SHA256SUMS` and `report.md`; all three published hashes re-hashed and matched, and the unpacked portable package reports `PASS - all 67 listed file(s) hash as the signed manifest says`. Two things that check found are rows of their own rather than footnotes: the installer is `NotSigned`, and the signing identity is per build (**row 18**). **This check gains one line for the next publish, added 2026-11-12: `releases/latest/download/update.json` must answer, and its `.sig` must verify against the certificate over the published engine** — `v0.1.0`'s four assets froze on 2026-11-05, four days before the manifest upload landed, so the compiled-in feed answers **404** for every installed copy until then (measurements in **row 5**) |
| 2 | ~~**د3 — the E2E acceptance on the per-machine installer**, plus the helper acceptance (D-007/D-026)~~ | ✅ | — | **closed and measured 2026-11-07** — the numbers are in the block below, and in the د3 row of `docs/ROADMAP.md` §2 |
| 3 | **A publicly trusted signature** (ب5) — Windows still shows "Unknown publisher" and SmartScreen may still warn today | ✅ **two free routes, no purchase** | **route A: the free Store account, then Microsoft's certification — no administrator needed for the shape submitted first (D-038)**; route B: the calendar (~2027-04-27) | **D-036** replaces D-035's "not purchasable": **A** the Microsoft Store re-signs an MSIX for free (free account, ID + selfie, worldwide), **B** OSSign issues the project a certificate once the repo is 6 months old (needs `id-token: write`, no secrets). The route A artifact exists and is measured (**D-037**): `installer/msix/AppxManifest.xml` + `scripts\make-msix.ps1` pack 75 files into 22.11 MB in 3.6–4.3 s, makeappx accepts the LocalSystem service and both restricted capabilities (`packagedServices`, `localSystemServices`), and the install stops on two measured OS rules — **0x800B0109** (a self-signed chain has no trusted root, and user-level trust does not count) and **0x80073D28** (Windows requires an administrator for any packaged service). The container questions now belong to the `Packaged` shape only, and stay unmeasured until an administrator installs a trusted build of it (§8 traps 29 and 30); `-ServiceMode None` is the shape submitted first, measured on 2026-11-07 to register with no elevation at all (D-038). The app half of that shape was then **run for real** the same day: launched from a developer-mode registration it started `mics-engine` by itself, brought `\\.\pipe\mics_engine` up, answered the app's 15-second `ping` and `sync.status`, reported `package integrity: ok - 68 file(s) hash as the manifest says` from inside the container, and wrote its state to the real `%LOCALAPPDATA%\MICS` (`SIGNING.md` §3) — what remains unmeasured is the helper across the container, which needs an administrator. **The acceptance check for this row now exists**: `scripts\verify-trust.ps1` exits 0 only for an artifact a stranger's Windows would trust, with `-SelfTest` proving the instrument against both controls (`SIGNING.md` §1) — so the day the Store signs the package, "ب5 is done" is one command instead of an opinion |
| 4 | ~~**Reproducible builds** (threat-model F-11)~~ | ✅ | — | **closed and measured 2026-11-08.** `make-release.ps1 -Reproducible` takes the build time from the revision (`SOURCE_DATE_EPOCH`), asks both linkers for `/Brepro`, writes the archive with one fixed timestamp and puts the signature-independent content hashes in `VERSION`; `scripts\verify-reproducible.ps1 -Reference <zip-or-folder>` rebuilds from source (signed with a locally minted self-signed identity, so no certificate is needed) and compares (file hash exactly, PE files on their content hash, and the two rows the signature legitimately moves — `mics-engine.exe` and the `VERSION` line that records its hash — proved rather than waved through), and **`docs/REPRODUCIBLE.md`** is the recipe a stranger follows. Measured: two from-scratch app builds matched byte for byte after `/Brepro` over the whole 63-file output tree (`mics_app.exe` `4d5cafba…` both times — before it `604152af…` then `03bcfac2…`, and every plugin DLL moved too), the obfuscated Dart snapshot matched all along (`51c2ab76…`), the same 70-file tree zipped twice by the new writer gave one hash where `Compress-Archive` stored per-file times, and `-SelfTest` is **17** checks. The one file a rebuild cannot match byte for byte is `mics-engine.exe`, and **row 13** is that remainder |
| 5 | **A default update-manifest URL and a signature check before applying** | ✅ engineering only | nothing | **done 2026-11-09**: the URL is compiled in per channel, resolved in one pure function, and reported back by `update.check` (D-046, measured by `scripts\verify-update.ps1`), and the release lane publishes the `update.json` the default reads. **Measured 2026-11-12, and the lane is not the gap: the one *published* release is.** `.github/workflows/release.yml` uploads `dist/update.json` and `dist/update.json.sig` with the rest of the assets, but `v0.1.0` does not carry either: that release object was **created 2026-11-05T13:59Z**, its four assets were uploaded at **14:20Z the same day**, and the owner's click **published it 2026-11-10T20:25Z** - while the manifest upload landed **2026-11-09**, four days after those assets froze. So `releases/latest/download/update.json` answers **404** (checked against the API and by fetching the URL) and *Check now* on every installed copy fails, until a release built by today's lane is published. This is what the contract harness hit: `update.check` was classed `read` in `qa/methods.json` on the belief that an unconfigured engine answers `disabled` with no traffic, but `resolve_update_url`'s third input is the channel's compiled-in default (D-046), so the case fetched github.com for real and was the single red case of a `-Tier full` run. The row is `network` now, like `sync.now`, with the reason written in the row. The second half landed the same day (D-047): `make-release.ps1` step 9b writes a detached PKCS#7 beside the manifest with the identity that signed the binaries, and the engine verifies it **before** it parses a field and pins the signer's thumbprint to the certificate over its own engine (D-016) or to `MICS_UPDATE_SIGNER_THUMBPRINT`; an unsigned, re-signed, tampered or wrongly-pinned feed is refused with the signature as the reason and stages nothing. Measured: 45 checks in `scripts\verify-update.ps1`, 6 new engine cases (200 in total, including one against a committed signed-manifest fixture), and one end-to-end run of a signature `sign.ps1 -DataFile` produced. **2026-11-13:** the locally cut `0.1.1` `dist\` carries the pair this check needs — `update.json` 330 bytes and `update.json.sig` 1,293 bytes, signed by the certificate the engine pins (`ABB0FF3D…`) — so row 1's added line has something to check as soon as that release is published |
| 6 | **A Windows-on-ARM app download** — the engine builds, links and is PE-checked for `aarch64-pc-windows-msvc`, and CI runs its tests on real ARM64; the **app** has no SDK | ✅ | **Flutter** (no Windows ARM64 SDK: 0 of 747 archives, measured 2026-11-04) | upstream; the packaging job runs the x64 SDK under emulation until then |
| 7 | **ز2-د — crash-report delivery** | ✅ engineering only | **D-023** (where reports may go) + the Open WA bridge endpoint | your destination answer first, then the sender |
| 8 | **The three decisions that still wait on you** — of the six one-page briefs in `docs/OPEN-DECISIONS.md`, (c) was settled by D-035 and implemented ahead of time by D-051, and (f) is answered and implemented by D-049 | ✅ | **your answers**, one line each | each one has a recommendation; none of them blocks the rest |
| 9 | **8 open rows in the §7 register** — **1 HIGH, 4 MED, 3 LOW** out of 25 (recounted 2026-11-11; the eighth is the row the publish verification created — one signing identity per release — and the HIGH row lost its download half when the draft went live; small step 9 closed the row about an engine that cannot say why it would not start, then the guard's ETW IOC-hash row closed the same day, the same day closed the row about a stored language tag no pack can render, D-050 closed the row about a language folder `pubspec.yaml` does not declare, and D-051 the row about the update pin matching a subject name) — and the one the 2026-11-07 acceptance run found as a real defect (a firewall rule whose name already starts with `MICS-` was prefixed twice and could then never be removed by the name that was given) is **closed 2026-11-08** with its measurements in the register row | ✅ | nobody, or one measurement each | work the rows one at a time; a closed row is one function that decides a rule name in one place (`owned_rule_name`), a unit test over five spellings, two new refusal cases in `qa\methods.json` and four new checks in `scripts\verify-firewall.ps1` that ran against this machine's firewall — for the ETW row, one dead load removed, one coverage fact in one function (`ioc_hash_coverage`), a unit test and a green fast tier — for the language-tag row, a resolution that ends in English, the stored tag carried on the settings object and named in one line of Settings, four unit cases, one widget case and a green fast tier (D-049) — for the language-folder row, a classified pack load that logs one line per language that lost anything and one Settings line naming the language whose own pack is empty, five new cases plus the `about` drift the first run of them found, and a green fast tier (D-050) — or, for the pin row, one type that holds either identity (`signature::Pin`), a thumbprint read out of the engine's own PE, the payload check, the manifest judge and `trust()` all comparing it, five new engine cases, a clean clippy, `verify-update.ps1` **45/0/0** against an engine built from the change, and a green fast tier (D-051) |
| 10 | ~~**Residual documentation debt**: `assets\i18n\README.md`'s diagram lists 16 of the 19 modules, and `scripts\verify-installer.ps1` still asserts `-ge 60` files against the 70 that ship~~ | ✅ | — | **closed (small step 9)**: the diagram lists all 19 modules, and the check asserts the 70 files the per-user variant installs — the count `docs/ROADMAP.md` §2 already records for **ب3** |
| 11 | **The two ARM64 CI legs are informational** (`continue-on-error`) | ✅ | a green run on `windows-11-arm` | watch them until a run says what they produce; they are not gates yet |
| 12 | ~~**`LICENSE` was a 5-line placeholder**~~ | ✅ | — | **closed in this pass**: the verbatim GPL-3.0 text, 35,149 bytes / 553 lines |
| 13 | **The engine is the one file a rebuild cannot match** — `MICS_MANIFEST` records the SHA-256 of every other shipped file *as signed*, so a rebuild signed with another key changes that document and therefore `mics-engine.exe` (this is F-11's remaining half, and `verify-reproducible.ps1` accepts it only after proving the difference is the signature) | ✅ engineering only | a **D-025 revision** + the work | make the document cover **content** instead of signatures: inject the payload hash `Get-MicsUnsignedHash` already computes, make the engine's start-up self-check hash the same way (the certificate table, the optional-header checksum and the security directory are not the code), record in D-025 why, and then delete the "explained" verdict from `verify-reproducible.ps1` because the engine matches too |
| 14 | ~~**The engine is not tied to the app's lifetime**~~ | ✅ | nobody | **closed 2026-11-08 (D-039)**: the app starts it as `service --parent <its own pid>`, and the engine holds a handle to that process — so a close, a crash and a Task Manager kill all end it, with the reason in its log and no crash report. A deliberate quit asks first: the new `shutdown` method answers `stopping` and only then ends, and the client does not treat that disconnect as a reason to reconnect. Closing the window quits by default; **Settings -> Protection -> "Keep running in the background"** (`close_to_tray`, off by default) is the opt-in for the old hide-to-tray behaviour. The app stops an engine only when it started it (`status.pid` against the pid it spawned), so a second MI CS that merely attached does not end protection somebody else owns. Measured: `scripts\verify-lifecycle.ps1` **19 checks, 0 skipped, 0 failures, 9.6 s** (now the pipeline's `engine.lifecycle` step), +6 engine tests (**158** total, 0 failed), the fast tier is **4 of 4, 94.6 s, 158 engine tests**, and the README's "protection survives the window" claims rewritten to what still holds |
| 15 | ~~**The tray menu is two labels** (`Open MI CS`, `Quit`) — `tray_manager 0.5.2` builds it with `AppendMenuW`, which renders labels, separators and check marks only: no icons, no styling (measured 2026-11-08 in the plugin's `windows\tray_manager_plugin.cpp`)~~ | ✅ | nobody | **closed 2026-11-08 (D-040)**: a left click opens a Flutter panel inside the app's own window — 392×486, non-resizable, always-on-top and out of the taskbar, anchored above the notification area, closed by `Escape`/click-away/✕ — carrying live state (engine, guard, firewall default-deny, connection count) and quick actions (Open MI CS, Quit, and switches that write the same settings Settings → Protection writes); the native menu stays on the right click as the fallback. Evidence: `flutter test` **146**, `test/tray_panel_test.dart` (4 cases), and the sweep treats the panel as a surface — `surfaces.trayPanel` = **6 controls** in `qa/ui/ledger.json` |
| 16 | ~~**Nothing scans a file from Explorer** — there is no context-menu verb anywhere in the tree, and the app has no single-instance mutex to receive a path with~~ | ✅ | nobody | **closed 2026-11-08 (D-041)**: `HKCU\Software\Classes\{*,\Directory,Directory\Background}\shell\MICS` is written by the installer (label `Scan with MI CS`, this copy's icon, `"<install>\mics_app.exe" --scan "%1"`, `%V` for the empty space inside a folder) and deleted by the uninstaller; the new `app.activate` method (68th) answers whether another transport is attached and, when it is, raises `event`/`activate` with the handed path — so a second launch hands over and ends instead of opening a second window, and the launch that finds nobody is the window: it raises itself, navigates to the scanner, and starts the scan with the handed path shown in the path field. Measured: `scripts\verify-handoff.ps1` **10 checks, 0 failures, 5.1 s** against a real engine with two real pipe clients, +4 engine tests, `test\handoff_test.dart` **11 tests**, `verify-installer.ps1` extended with the verb keys (install, uninstall, refused uninstall). Honest limits: Explorer's rendered menu cannot be read by a script, the live install half could not run in the writing session (see D-041), multi-selection is unproven, and MSIX/portable copies get no verb |
| 17 | ~~**The firewall is Windows' rule list, not an enforcement engine of ours** — blocking is real and Windows-enforced, but there are no per-connection decisions, no live feed and no one-click block, and the brief's "ETW + WFP usermode" is unimplemented~~ | âœ… | nobody | **closed and measured 2026-11-09 (D-042/D-043/D-044/D-045)** — the missing half was always the elevated run, and it happened, in the order Â§0 item 7 prescribes: `scripts\reset-wfp.ps1` **7 passed, 0 skipped, 0 failed, 1 s** (it found what it exists for — `before: sublayer=True filters=4`, four of our own `MICS-mics-engine.exe … probe` filters left behind by the 2026-11-08 teardown — and removed 6 objects, ending at `filters=0 sublayer=False` with `watch: state=clear`); `scripts\verify-wfp.ps1` **16 passed, 2 skipped, 0 failed, 5 s** — a real persistent `FWP_ACTION_BLOCK` in `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, read back by Windows' own `netsh wfp show filters` with the application path, remote port 65001 and protocol 6 as conditions, explicitly not a permit, and gone from both our list and Windows' state after the undo; `scripts\verify-connections.ps1` **24 passed, 0 skipped, 0 failed, 6 s** — 462 rows, 147 offering a block, a **real row's own spec** accepted, the BFE one filter heavier, `fw.wfp.unblock` taking the machine back to where it started; `scripts\verify-wfp-watch.ps1` **34 passed, 1 skipped, 0 failed, 4 s** — part 1 read the **real** BFE (`state=clear recorded=0 live=0`, `live=0` being the second proof that nothing of ours was left on the machine). The slices themselves: **(a)** MI CS' own provider, sublayer and persistent filters through the helper, 4 ops and 4 methods, 12 unit tests; **(b)** the four connection tables walked with IPv6 (`windows\conns.rs`), the block spec derived on the engine side from the row's own image path, peer port and protocol, a per-row block button behind a confirmation, 6 engine tests + 2 app tests; **(c)** a record beside the objects (`meta` row `wfp_baseline`) compared against the machine by `fw.wfp.watch` into `guarded`/`tampered`/`clear`/`unrecorded`/`unknown`, one HIGH guard event per change into the incidents list and a card of its own, polled by the guard thread about every 30 s, 10 engine tests + 2 app tests. 73 methods, 109 controls, `cargo test` **192**, `flutter test` **162**. **The honest limits, none of them a row:** an allow/block *prompt* per new connection needs a kernel callout driver and `SECURITY.md` says usermode only; the run left four claims uncomposed rather than disproven — the *enforcement effect* (no connection was opened through a filter to watch it be refused), a **reboot** (persistence is the flag Windows prints, `FWPM_FILTER_FLAG_PERSISTENT`, not a reload we observed), whether our sublayer weight (`0x7fff`) outranks a built-in permit rule, and a **real** filter deleted behind the engine's back (the watch's detector is measured over an injected status); the list is a snapshot with no push feed, so a delete-and-re-add inside the 30 s poll window is invisible; and the installed `MICSHelper` is still a release build from before D-045, so the app's **own unelevated** write path answers `0x80320004` until it is reinstalled from a fixed build (`engine\target\debug\mics-engine.exe install-helper` in an elevated shell) |
| 18 | **One signing identity per release** (ب7) — `make-release.ps1` mints a certificate for each build, so D-051's pin makes every engine refuse the *next* release's payload (the MED row in §7) | 🟡 **the engineering half is done and measured 2026-11-12; one secret is left** | nothing to build — a certificate kept in `MICS_PFX` and `MICS_PFX_PASSWORD` | `scripts\verify-signer-identity.ps1` (new, **18 checks, 0 failed, 5.1 s**) proves the mechanism with no engine, no build, **no store write** and no SDK: one PFX signs two scratch manifests and both detached signatures carry one thumbprint, equal to the certificate inside that PFX, while a second PFX signs a third and carries a different one — the identity the engine refuses (`verify-update.ps1` parts 4 and 7). The same probe holds the *names* end to end, which is where this failed once already (D-047): the workflow's `secrets.MICS_PFX` → `MICS_PFX_B64` → the lane's `-PfxPath`, one `@signArgs` for the staged binaries and `dist\update.json`, both refusals of a PFX without its password, the throwaway fallback and the `Remove-Item` on its key folder, and the four readers of `MICS_UPDATE_SIGNER_THUMBPRINT` (`signature.rs`, `verify-manifest.ps1`, `verify-update.ps1`, the probe) — so it is now the `signer.verify` step of `scripts\pipeline.ps1 -Tier fast`. The release report is where a reader meets the decision: `pinned : <thumbprint>`, and a `WARN` when the identity is the one whose key the script deletes before it returns. **Measured 2026-11-12, end to end**: a full lane run printed `pinned : 7FB05790C8CBCF876BF3CC429CA5FAE93129F4B8` and the WARN and returned `RESULT: PASS`; an identity passed as `-PfxPath` whose chain this machine does not trust never reaches that report — the lane's own `Get-AuthenticodeSignature` pass refuses the 7 signed files (`UnknownError`) and publishes nothing. **Measured 2026-11-13: the `WARN` state and a green release tier cannot coexist.** Against a `dist\` the throwaway identity had signed, `-Tier release`'s `engine.test` failed **4** cases — `a_signed_release_binary_is_accepted` (`mics-engine.exe is signed by make-release.ps1 -Sign and must pass`), `the_name_pin_accepts_our_certificate_and_refuses_another`, `the_thumbprint_pin_accepts_our_binary_and_refuses_a_name_alike`, `a_tampered_copy_of_a_signed_binary_is_refused` — while the same tier over a `dist\` signed by a kept store certificate is **14/14**. So `-Sign` with no PFX is a state to diagnose in, not to publish from. **What is left is a minute of the owner's time** — the copy-paste recipe is `docs/SIGNING.md` §7 item 6 — and the only deadline is the next publish |

**What the 2026-11-07 acceptance run measured** (the evidence behind row 2, on the
artifact rebuilt from `main`: `MICS-setup-0.1.0-x64.exe`, 16,730,142 bytes,
`sha256 8984C194…`):

- **install, one UAC prompt, all users** — 72 files under `C:\Program Files\MI CS`
  (the 70-file package, the uninstaller, and one stray `mics-engine_IObitDel.exe`
  that already lived in that folder); the per-machine Start-Menu group
  (`MI CS.lnk` + `Uninstall MI CS.lnk`); the `HKLM\…\Uninstall\MICS` row;
- **the helper created by the installer, inside that same prompt** — `MICSHelper`
  with binPath `"C:\Program Files\MI CS\mics-engine.exe" helper-service`,
  LocalSystem, AUTO_START, **running**, and `priv.log` carrying
  `phase=note install requested` → `phase=note service starting (pid=50128)
  version=0.1.0 pipe=mics_helper` → `phase=start version` / `phase=done ok=true` →
  `phase=note install finished, helper state=running`;
- **the installed engine's self-check** — started unelevated from the installed
  folder, it logged `package integrity: 0.1.0, 68 listed file(s) match and the
  engine is signed by "MI CS Code Signing", but this Windows does not trust that
  certificate yet (self-signed build)`: the ج2/ط2 check, on the installed tree, in
  its honest `untrusted-certificate` state. *(The certificate was trusted in
  `CurrentUser\Root` later the same day — see the new §8 entry — so that exact line now
  reads `ok` instead; the quote is what was true during the run.)*
- **privileged ops with zero further prompts** — driving that engine **unelevated**
  over a private pipe, `helper.status` reported `installed/running/reachable/
  elevated=true`, `fw.rules.add` created a rule in **37 ms** and `fw.rules.remove`
  removed it in **36–44 ms**, each one a `phase=start`/`phase=done ok=true` pair in
  `%PROGRAMDATA%\MICS\logs\priv.log`. **Deliberately not measured:** *Default deny
  outbound* would have cut this machine's own network path mid-run, so it was left
  alone rather than "tested"; the SMBv1 toggle and the hosts write were skipped for
  the same class of reason (the hosts file already carries a `# BEGIN MICS-IDS`
  section). That is the one part of D-007's promise still proven only by the
  protocol probe (`verify-helper.ps1`), not by a live toggle;
- **uninstall, one UAC prompt** — exit 0, with the product folder, `MICSHelper`
  (`sc qc` → 1060), the Start-Menu group, the registry row and the shortcuts all
  gone, so the helper **was** removed rather than refused; and the user's own copy in
  `%LOCALAPPDATA%\MI CS` untouched. `%PROGRAMDATA%\MICS` (database + audit logs) is
  **kept on purpose**, which `mics.nsi` states on screen;
- **the defect it found** — the register's new MED row: an already-prefixed rule name
  gets a second `MICS-` and can no longer be removed by the name that was passed.

After the run the machine is back to how it started: no per-machine install, no
service, no MI CS firewall rule of mine (the registry, the group and the rule were all
removed), and only the user's own `%LOCALAPPDATA%\MI CS` copy left in place.

**Not in this table on purpose:** anything in §5 (out of scope by design) and
`docs/ROADMAP.md` §5 — a kernel driver, an inline IDS engine, ClamAV/CAPA/Suricata, a
32-bit build, and VirusTotal remain *decisions taken*, not work owed. A row that needs
money is not "blocked"; it is **closed as not happening** (D-035).

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
| `MICS_PIPE_NAME` | Serve a different pipe (isolated dev/test engine) — a bare name or a full `\\.\pipe\...` path, both mean the same pipe |
| `MICS_NO_SINGLETON=1` | Allow an engine next to the real one (with `MICS_PIPE_NAME`) |
| `MICS_NO_GUARD=1` | Do not arm the guard in service mode (tests: no canary files) |
| `MICS_NO_AUTO_RESUME=1` | Do not resume interrupted jobs at startup |
| `MICS_NO_SCAN_SCHEDULE=1` | Do not start the scan timer (D-027); the setting is off by default anyway, so this is for a probe that must not double up |
| `PROGRAMDATA` | Relocate all state (`mics.db`, `logs/`, `Quarantine/`) — used by tests |
| `MICS_ENGINE_PATH` | Force the UI to use a specific engine binary |
| `MICS_WFP_WATCH_SEED` | Fill the tamper watch's record (`fw.wfp.watch`, D-044) only when none exists: `;`-separated filter names, a leading `!sublayer` for "no sublayer was created". Never overwrites a real record, so the detector is measurable on a machine where MI CS never wrote a filter |
| `MICS_WFP_WATCH_LIVE` | Give the watch a `WfpStatus` (JSON) to compare that record against instead of reading the filtering engine. The report's `detail` and the engine log both say the status was injected, so a test answer can never be mistaken for a measurement of the machine |

Data lives in `%PROGRAMDATA%\MICS\` (`mics.db`, `logs/engine.log`,
`Quarantine/`, `blocklists/`, `canaries.json`, `settings.json` — the last one is
written by the engine and read by **both** sides, which is what D-008 landed in P2a).

### Verification tools

| Tool | Proves |
|---|---|
| `dart run tool/pipe_smoke.dart` | The **production** `PipeConnection` talks to the engine (ping/status/job.list) |
| `dart run tool/pipe_probe.dart <dir>` | Raw protocol: request/response + `progress` + `job_finished` push |
| `mics-engine.exe benchmark` | RAM/CPU against the §15 budgets |
| `scripts\verify-toast.ps1` | A real notification card reached the desktop: clears the AUMID's history, triggers a card, reads the history back (text + actions). `-HistoryOnly` reads cards an already-running engine produced |
| `scripts\register-aumid.ps1` | Windows labels a card's source `MI CS`: writes `HKCU\Software\Classes\AppUserModelId\MICS` (`DisplayName`, `IconUri`) and tags the shortcuts' `System.AppUserModel.ID` through `IPropertyStore` (WScript.Shell cannot set it). No elevation, no new file; `-Remove` puts both back |
| `scripts\verify-aumid.ps1` | The registration is really there and Windows agrees: reads the registry key, the shortcut property and the Shell's own `Get-StartApps` AppID. Read-only; exits 1 with the list of what did not hold |
| `scripts\verify-helper.ps1` | The privileged helper's protocol **unelevated**: ping/version answer, a privileged op is refused without an elevated token, an unmarked hosts document and a malformed firewall rule are refused, an op outside the closed set is refused, the audit log keeps intent/outcome but never the payload, `helper-status` sees it |
| `scripts\verify-pipe-acl.ps1` | Both pipe ACLs are what `docs/THREAT-MODEL.md` says: reads each live DACL back with `GetSecurityInfo` (engine pipe protected to the owner/SYSTEM/Administrators, helper pipe `INTERACTIVE`), and drives a real JSON-RPC `status` call over the hardened engine pipe so the ACL cannot pass by locking the UI's own user out. Isolated pipe names + data dir, so a running MI CS is untouched |
| `scripts\verify-low-integrity.ps1` | A launch from a Low-labelled folder (D-058): labels a scratch folder `icacls <dir> /setintegritylevel (OI)(CI)L`, copies `mics-engine.exe` in, and runs it there — beside an ordinary copy as the positive control, so a refusal cannot be a missing binary in disguise. The Low copy reports itself Low, is refused by name (folder, both symptoms, the installed copy, the hatch) and ends non-zero; `MICS_ALLOW_LOW_INTEGRITY=1` runs it with the settings warning intact; `helper-status` answers without the hatch, which is the point of the exemption. **6 checks passed, 0 failed** (2026-11-14). Needs no administrator; touches neither the real `%LOCALAPPDATA%\MICS` nor a running MI CS |
| `scripts\verify-single-instance.ps1` | The window the user sees during a handover (D-059): starts the app twice on a private pipe and asks Windows itself about the second process's top-level windows (`EnumWindows` + `IsWindowVisible`, per process id) — the first launch's window is the positive control, the second launch's are all `hidden`, it ends by itself and **cleanly** — `exit code 0`, where the build before D-060 died with `0xC000041D` and left Windows Error Reporting entries (trap 34) — and one window is left. Fails against the pre-fix runner, which shows `visible|mics_app` + `visible|MI CS` |
| `scripts\verify-wfp.ps1` | MI CS' own filtering engine (D-042): starts an isolated engine, asks `fw.wfp.status`, creates a persistent block, reads it back out of the BFE with `netsh wfp show state`/`show filters`, checks the action is Block, removes it and asks Windows again, proves a refusal writes nothing, and greps the engine's log for a `netsh` fallback. **The write half needs an administrator** (or a reinstalled helper): unelevated it PASSes the reads and skips the writes loud, so an unelevated run is honest and not a green claim. Since D-045 a refusal in a shell that *can* write is a **FAIL** with its reason, not a passing "carries a reason the UI can show". **Measured elevated 2026-11-09: 16 passed, 2 skipped, 0 failed (5 s)** — the filter read back out of Windows' own `netsh wfp show filters` as a persistent Block in `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, and the two skips are the `show state` comparison (no XML on this machine, now with netsh's own answer quoted) and part 5's refusal path, which needs a shell that may not write |
| `scripts\verify-connections.ps1` | The live connection list is Windows' own table and what a row offers to block is exact (D-043): starts an isolated engine, asks `net.connections`, checks every row's local socket and owner against `Get-NetTCPConnection`/`Get-NetUDPEndpoint` (counting the rows that had already vanished), requires IPv6 rows when the machine has IPv6 traffic and UDP rows with `*:*` when it has UDP endpoints, requires every offered spec to match its row and name a file that exists, and hands that spec to `fw.wfp.block` — accepted, or refused with a reason and nothing left in the BFE. **The accepted branch needs an administrator** (or a reinstalled helper) like the probe above, and says so. **Measured elevated 2026-11-09: 24 passed, 0 skipped, 0 failed (6 s)** — 462 rows, 147 offering a block, and the accepted branch taken for a real row's own spec: the BFE one filter heavier, `fw.wfp.unblock` removing it, machine back where it started |
| `scripts\verify-wfp-watch.ps1` | The tamper watch (D-044) notices our sublayer or a filter of ours leaving the BFE, and says `unknown` rather than guessing when it may not look: one engine per scenario over its own data directory, the machine path first (an empty record can never be a tamper), then the detector against a seeded record and an injected `WfpStatus` — a lost filter, a lost sublayer and a filter nobody recorded each judged, the alert proven to be a real `incident.list` entry (HIGH, naming the filter) plus a `WFP tamper:` line in the engine's log, and a repeat poll filing nothing. The injected status is labelled as injected everywhere, including in the log. **Measured elevated 2026-11-09: 34 passed, 1 skipped, 0 failed (4 s)**, its first part reading the real engine (`state=clear recorded=0 live=0`). Unelevated it is **38 checks** with 1 skipped, 0 failed while the write path is genuinely unreachable; on this machine the installed helper *can* answer the write path and gets it wrong (it predates D-045), so the same unelevated run now ends **36 passed, 1 skipped, 1 failed** with that failure as its reason — which is exactly what D-045's rule is for |
| `scripts\reset-wfp.ps1` | The undo for a run that died between adding a filter and cleaning it up (D-045), which is what the 2026-11-08 elevated run did: starts an engine against the app's own data directory, reads `fw.wfp.status`, removes MI CS' own filters, sublayer and provider through `fw.wfp.reset`, reads the machine back (`filters=0`, `sublayer=False`), and checks that the reset cleared the D-044 record with them instead of leaving a tamper behind. It names no filter, so it can only remove objects carrying MI CS' provider key, and an unreadable machine is reported as **unmeasured**, never as clean. Needs an administrator or the helper. **Measured elevated 2026-11-09: 7 passed, 0 skipped, 0 failed (1 s)** — and it found what it exists for, `before: sublayer=True filters=4` (four of our own probe filters left by the crashed run) and `removed: 6` |
| `mics-engine.exe helper-status --json` | The status chain the UI renders (`installed/running/state/reachable/version/elevated/pipe`) |
| `mics-engine.exe helper-console` | Serves the privileged protocol in the foreground on `MICS_HELPER_PIPE` without the SCM (diagnostics, `verify-helper.ps1`) |
| `scripts\verify-hardening.ps1` | The binaries are hardened as claimed, read out of the **PE** rather than from the build flags: `DllCharacteristics` (`GUARD_CF`, `DYNAMICBASE`, `NXCOMPAT`, `HIGH_ENTROPY_VA`), the load-config `GuardFlags` (`CF_INSTRUMENTED`, `CF_FUNCTION_TABLE_PRESENT`, `CF_LONGJUMP_TABLE_PRESENT`), the CET marker when present, and a debug directory with no PDB. Pass a folder (judges `mics_app.exe` + `mics-engine.exe`, reports `flutter_windows.dll` but never fails on it) or a single file; `make-release.ps1` refuses to package what it fails |
| `scripts\make-release.ps1` | Builds the published artifact: clean `dist\MICS-portable` (engine + `rules` + app + `sbom.cdx.json` + `THIRD-PARTY-NOTICES`), `VERSION`, `MICS-portable-<version>-x64.zip`, `dist\SHA256SUMS`; fails instead of shipping an incomplete folder, refuses to start when the committed inventory no longer describes the lockfiles, refuses an un-obfuscated app or an unhardened binary, swaps the folder by renaming the old one aside instead of deleting it, and — after signing — builds the `MICS_MANIFEST` document from the final bytes, injects it into the staged engine, signs the engine and refuses to publish a package `verify-manifest.ps1` does not accept |
| `scripts\update-manifest.ps1` | The feed the compiled-in default reads describes the archive beside it (D-046): writes `dist\update.json` (`version`, `url`, `sha256`, `size`, `notes_en`, `notes_ar`) from the zip, **builds** the asset URL from version + arch instead of discovering it, writes UTF-8 **without** a BOM, and then re-reads the file and compares every field against the archive. An archive named for another arch, a version that is not one, or a missing archive is a FAIL; ASCII, no network, no elevation |
| `scripts\verify-update.ps1` | The update feed's wiring and its refusals (D-046), **without a network**: `MICS_UPDATE_MANIFEST_URL=off` answers `disabled` and names no feed; a manifest the probe serves itself on `127.0.0.1` is fetched and answers `available`, carrying `manifest_url`/`sha256`/`download_url`; the download it names is really fetched, staged under the data directory and hashes to what the manifest promised; a manifest whose `sha256` is 64 zeros is refused with `SHA256 mismatch` and stages nothing; `http://example.com/...` is refused by `settings.set` with "must use https://" and the previous feed survives the refusal. **Measured 2026-11-09: 18 passed, 0 skipped, 0 failed (4 s)**, unelevated, and now the `update.verify` step of `-Tier full`. It picks the newest of the two engine builds and refuses to run when that binary predates `engine\src` (D-045's lesson: a stale binary reads like a defect). It does **not** fetch the compiled-in default — v0.1.0 is a draft, so that URL is a 404 until §0.6 row 1's click |
| `scripts\verify-release.ps1` | The artifact is what it claims: every checksum matches, the zip has every required file and exactly 2 rule packs (no `rules\rules`), the inventory parses and names a license for every component, the notices report a clean audit, the **extracted** copy answers the helper protocol, puts a real card on the desktop, loads its own `rules\guard` + `rules\yara` rather than the built-in fallback, and its binaries pass `verify-hardening.ps1` while `data\app.so` carries no Dart class names and no symbol table ships in the zip |
| `scripts\verify-manifest.ps1` | The package describes itself: reads the `MICS_MANIFEST` resource back out of the packaged `mics-engine.exe` (through `scripts\manifest-resource.ps1`, the one place the format lives), validates the envelope (format `1`, a version, sorted duplicate-free relative paths, nothing that walks out of the package), re-hashes every file it lists, and fails on a missing file, a size or hash mismatch, or an engine whose signature broke after signing (`HashMismatch`). It prints what the package carries that the document does not list, which is `VERSION` by design. `-Measure` prints the document instead of the verdict. `make-release.ps1` runs it on the staging folder, and `-Tier release` runs it on `dist\MICS-portable` (`manifest.verify`) |
| `scripts\verify-signer-identity.ps1` | A release *can* be signed by **one** identity across builds, and the certificate the lane mints per build cannot (0.6 row 18, **ب7**): signs three scratch manifests through `sign.ps1 -DataFile` — the same call `dist\update.json.sig` comes from — with one PFX twice and with a second PFX once, reads each signature back out of its own bytes, and requires the first two to carry one thumbprint (equal to the certificate inside that PFX) and the third a different one, which is the identity the engine refuses (`verify-update.ps1` parts 4 and 7, cited rather than re-run); then holds the *names* end to end, which is where this area has broken before (D-047): the workflow's `secrets.MICS_PFX` → `MICS_PFX_B64` → the lane's `-PfxPath`, both refusals of a PFX that arrives without its password, one `@signArgs` for the binaries and the feed, the lane's throwaway fallback and the `Remove-Item` on its key folder, and the four readers of `MICS_UPDATE_SIGNER_THUMBPRINT` (`signature.rs`, `verify-manifest.ps1`, `verify-update.ps1`, this probe). No engine, no build, no **store write**, no Windows SDK, no elevation, no network — and it counts the certificate pile (12 distinct certificates with one subject on this machine) without adding to it. Measured 2026-11-12: **18 checks, 0 failed, 5.1 s** |
| `dart run tool\sbom.dart` | What is inside the package, generated from what is pinned: `sbom.cdx.json` (CycloneDX 1.6) + `THIRD-PARTY-NOTICES` from `cargo metadata`/`Cargo.lock`, `pubspec.lock`/`dart pub deps --json`, the Flutter SDK's `LICENSE` and the two shipped fonts. `--check` exits 1 and prints `RESULT: FAIL` instead of writing when the committed pair is stale (`--verbose` lists what is excluded, and which components ship no text of their own); `make-release.ps1` runs it before it builds and `test\sbom_test.dart` re-derives the same inventory from the lockfiles |
| `cargo run --example toast_probe` | Which WinRT step of the toast path fails, with the HRESULT (diagnoses "no card at all") |
| `scripts\make-installer.ps1` | Wraps the assembled package in the NSIS installer: re-runs `verify-hardening.ps1` on the binaries first (an installer can never ship what the ZIP gate refused), finds NSIS without needing it on `PATH`, and prints the exe, its SHA-256 and the scope. `-TestUser` builds the same script as a per-user, no-UAC variant, which is how the install/uninstall path gets verified without a human clicking a prompt; `-HelperServiceKey` (verification only) points the uninstaller's helper check at another registry key, so the refusal path can be measured without touching a real service |
| `scripts\check-helper-ownership.ps1` | Whether the installed `MICSHelper` service points at one install folder: prints `RESULT: SAFE` / `OWNED` / `UNKNOWN` and exits 0 / 2 / 1. The uninstaller asks it before deleting anything, so a service is never left aiming at a deleted `mics-engine.exe`; read-only, no elevation |
| `installer\mics.nsi` | The installer itself: the package, a Start-Menu folder and a desktop icon, both halves of the AUMID the toast source needs (the registry key, and the shortcuts' `System.AppUserModel.ID` written by `register-aumid.ps1` through `IPropertyStore`), an Apps-&-features entry whose uninstaller refuses to remove a copy the privileged helper still points at, and an upgrade that reuses the previous install location instead of asking twice |
| `scripts\verify-installer.ps1` | The installer's promises, measured on a real install: a silent per-user install into `%TEMP%`, the app, engine and rule packs landing, both shortcuts' `System.AppUserModel.ID`, the AUMID key and Apps-&-features entry pointing at that copy, `Get-StartApps` filing "MI CS" under `MICS` with nothing under the exe path, the checker's answers, the uninstaller removing all of it while the machine's helper and the user's own copy stay untouched, and the refusal (error level 5, everything left in place) against a synthetic service key. Exports and re-imports the AUMID key, deletes everything it created, no elevation, ~2 min |
| `scripts\verify-signing.ps1` | Which identity a release is signed with, and the refusals around it (D-034): `sign.ps1` refuses zero identities, two, or an unknown thumbprint before signtool runs; a certificate from a store signs a real PE and the signature carries that certificate's thumbprint; an untrusted chain is refused, not called verified; the imported certificate is removed from the store afterwards. 18 checks, PASS. What it states it cannot prove: the `Valid` half needs a CA-issued certificate, so with the local throwaway certificate the two production modes end in "did not verify" and exit 1 - the refusal is the design, and the certificate row is what changes it. Signs a copy under `%TEMP%\mics-signtest`, needs no elevation, ~4 s |
| `scripts\verify-scan-schedule.ps1` | The scan schedule (D-027), measured against a real engine over its own pipe and an isolated data directory: with `scan_interval_hours = 0` nothing starts and `scan.schedule` says off; with an interval and a configured folder the first tick starts a scan by itself, the job's root is that folder, it finds the planted ransom-note string, and the file is **still there** afterwards (report-only); and the start is recorded, so a restart does not scan again. No elevation, ~20 s |
| `scripts\verify-firewall.ps1` | The firewall is Windows' API, not `netsh` (D-028), measured against this machine: a fake `netsh.exe` is put first on the engine's PATH (and a direct `netsh` is shown to stop working under it, so the trap is proved to be a trap); `fw.default_deny.status` and `fw.rules.list` are compared with `Get-NetFirewallProfile`/`Get-NetFirewallRule -PolicyStore ActiveStore` field by field; one rule is created through the engine, read back from Windows with the exact direction, action, port, program, profile and group that were asked for, then removed and Windows is asked again. A profile policy is never flipped: a default-deny toggle would cut the network of whatever else is running. Writes go through the running `MICSHelper` (or need an elevated shell - the probe records a skip, never a pass). Cleans up after a failed run; ~8 s |
| `scripts\verify-canary.ps1` | A decoy **read** is detected and the coverage behind it is measured, not assumed (D-032), against a real engine on a private pipe, a private `USERPROFILE` (so the default decoy paths cannot touch the real Documents folder) and a private data directory: a decoy MI CS had just written is settled silently inside the 90 s window and the engine's log says `canary settling`; a decoy that was already on disk raises `canary_read`/HIGH under rule id `CANARY_READ` with its size and **SHA-256 unchanged**; one appended byte raises `canary_triggered`/CRITICAL under `CANARY`; fifty metadata queries in a row move no last-access time and raise nothing, so the guard's own poll cannot trip its trap; and the engine's `read_detection` verdict equals the same measurement taken independently in PowerShell, on the folder the decoys are actually in. With no elevation (the unelevated poll is the path that has to see it) and no ETW; on a volume that keeps no last-access time it reports part 2 as **SKIP** with the reason instead of a pass. No elevation, ~35 s |
| `scripts\verify-rules.ps1` | The shipped detection pack is measured by **what it catches**, not by whether it loads (D-033): 8 vectors in `engine\testdata\detection` (one per rule, plus a clean control that must stay silent) are scanned by a real engine, each must be caught under the rule it was written for, every rule the pack declares must either be caught by one of them or be named as unreachable with its reason, and the engine must say it loaded that pack rather than the copy compiled into the binary. Prints the pack's SHA-256. Fails by construction when it should — an inverted magic loses `pk-macro.txt`, an unproven new rule fails on its own name (both measured, exit 1). `-InPlace` measures the pack beside the engine (what `verify-release.ps1` does with an extracted package); without it, `-RulesBase` points a dev binary at a tree. Isolated data directory with `{"dnd": true}` so it does not put a card on the desktop per finding (measured 7 without, 0 with). No elevation, ~6 s |

Both tools need an engine to talk to; start one with an isolated pipe first
(`MICS_PIPE_NAME`, `MICS_NO_SINGLETON`, `MICS_NO_GUARD`, `PROGRAMDATA`).

---

## 3. Where we are

**Start here if you are new:** run the four checks in section 2, launch
`build\windows\x64\runner\Release\mics_app.exe`, and read the Done log below.
Everything that can be verified without administrator rights is done, and so is
everything that needed money — **because nothing is bought** (D-035; that is a
constraint, not a saving). What remains is in **§0.6**, and the shape of it is: the
answers to §0.2 items 3–5, one secret (the release signing identity, row 18 — the
publish click in row 1 was made on 2026-11-10), and engineering that is free
(the §7 rows, and §0.6 row 13 — reproducible builds landed
2026-11-08).

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
| P4 | Code signing (real cert), x64+ARM64, NSIS installer, SBOM/notices | **done except the certificate, which is no longer planned (D-035)**: SBOM + notices shipped (ب1a), the cost researched and kept (ب1b), the NSIS installer built and verified (ب3 + ب4, helper folded in), the ARM64 **engine** leg built and PE-checked (ب2), and signing wired so a certificate is two secrets and no code change (D-034). Left = **ب6** (publish the draft, one free click) and the free trust stack (§0.6 rows 3–4) |
| P5 | Threat model, integrity/anti-tamper, protection-matrix doc | **done 2026-11-03**: `docs/THREAT-MODEL.md` + `docs/PROTECTION-MATRIX.md` exist and F-1…F-4 are closed with measured evidence; the integrity story closed 2026-11-03 with **ج2** (the signed manifest inside the engine, the start-up self-check and the About line/notice), **ط2** proved both halves catch a tampered copy, build hardening (**ج1**) landed with the PE measured, and the README now says what it does and does not do (**ج3**). Left: nothing — **F-11's reproducible build landed 2026-11-08** (the toolchain decision it waited on was `SOURCE_DATE_EPOCH` + `/Brepro` + a clock-free ZIP writer), leaving only the engine's manifest to make content-based (§0.6 row 13) |
| P6 | Full QA harness + HTML report, malware lab (later) | **the harness is done**: **د1** (the `qa/` contract harness over all 67 methods (row 14 added `shutdown`)), **د2** (every screen and control swept, ledger committed — and since D-040 the tray panel is swept the same way, as a *surface* rather than a screen) and **د4** (the generated `qa/report.md` + `report.html`, byte-gated so the fast tier fails when it drifts) all landed; **د3** (the E2E acceptance on the per-machine installer) **ran on 2026-11-07 and is closed** — §0.6 row 2, §0.2 item 1. The malware lab stays "later" by design |

### Done log (append only)

- **A release says which certificate it pinned — and the lane could not finish until the opsec ratchet recorded today's tree (ب7 / §0.6 row 18, ط1's baseline) — 2026-11-12**
  - **What was built.** `scripts\verify-signer-identity.ps1` (new) measures D-051's pin with **no engine, no build, no store write and no SDK**: 18 checks, 0 failed, one PFX signs two scratch manifests and both detached signatures carry one thumbprint equal to the certificate inside that PFX, a second PFX signs a third and carries a different one — the identity the engine refuses (`verify-update.ps1` parts 4 and 7). It also holds the *names* end to end, which is where D-047 failed once (the workflow's `secrets.MICS_PFX` → `MICS_PFX_B64` → the lane's `-PfxPath`, one `@signArgs` for the staged binaries and `dist\update.json`, both refusals of a PFX without its password, the throwaway fallback and its `Remove-Item`, the four readers of `MICS_UPDATE_SIGNER_THUMBPRINT`), so it is now the `signer.verify` step of `scripts\pipeline.ps1 -Tier fast`.
  - **What the lane now says.** The release report prints `pinned : <thumbprint> (the update path in this engine trusts this certificate and no other)`, and a `WARN` when the identity is the one minted for this build whose key the script deletes before it returns. Measured on a full lane run: `pinned : 7FB05790C8CBCF876BF3CC429CA5FAE93129F4B8`, the WARN, `RESULT: PASS`.
  - **Three refusals on the way there, each the gate working.** A clean build into a foreign `CARGO_TARGET_DIR` is refused (the baseline was measured from `engine\target`); an untrusted scratch CA passed as `-PfxPath` is refused by the lane's own signature pass — 7 files, `UnknownError`, nothing published — which is why `docs/SIGNING.md` §7 item 6 now says the donated certificate must be one this machine already trusts; and the tree itself was refused by the marker ratchet until the counts below were recorded.
  - **The ratchet, measured and not bumped.** `mics-engine.exe` `cargo` **1243 → 1244** and `data\app.so` `flutter` **50 → 54**, `pubspec` **1 → 2**; every other number matched the current package unchanged, and the forbidden-path check stayed green in the same run (zero hits). The engine's one new *distinct* cargo-bearing string is the **remapped** form of a path the 2026-11-09 build still carried un-remapped (`C:\Users\<account>\.cargo\registry\...\serde_json-1.0.154\src\error.rs` → `/build\.cargo\registry\...`); the snapshot's four new `flutter` strings are platform-channel names the newer window and tray UI opens (`flutter/keyboard`, `flutter/mousecursor`, `flutter/restoration`, …); its second `pubspec` is this project's own asset-gate message ending in `pubspec.yaml "assets:"`. `qa/report.md`/`.html` are regenerated in the same commit, as D-025's producer commit requires.
  - **The machine.** Left as found — 24 entries / 12 distinct `CN=MI CS Code Signing` certificates in the user stores, this run's throwaway removed from `TrustedPublisher` and `TrustedPeople` and its PFX deleted. Two traps recorded in §8 with the same date: a foreign target directory has to be *fresh* (a reused one dies on `os error 3`), and a freshly built engine cannot replace one a process under another account is holding (`Access is denied`, renaming works).

- **The published `v0.1.0` was verified against its own release page — and the check found two things no document said (§7 register: HIGH row (a) closed, one new MED row; §0.6 rows 1 and 18) — 2026-11-11**
  - **What was checked.** The owner published the draft on 2026-11-10, so for the first time there was a *download* to verify instead of a build to describe. The release page carries 4 assets; every published hash was recomputed on this machine against the published `SHA256SUMS`, and `scripts\verify-manifest.ps1` was pointed at the unpacked portable package.
  - **What it measured.** `MICS-setup-0.1.0-x64.exe` **16,642,682 bytes**, `sha256 5cd206db3b44cc68d1f7822593efcf834956c15d47aac21bd6116c84d47f84f5`; `MICS-portable-0.1.0-x64.zip` **23,111,206 bytes**, `sha256 1eafe3ee618aae963a2c52811ae442fca85ade9f90ecbb7c87f6d737cd2fe6b0`; `report.md`, `sha256 8bc5fab281e4ea35f5c617572639f3eab5314d577288a3d7bfcf0dd603846a16`. All three hashes in `SHA256SUMS` matched, and the unpacked tree reported `PASS - all 67 listed file(s) hash as the signed manifest says` — so the signed-manifest chain a user can check works on the artifact a user actually downloads. The release was created `2026-11-05T14:18:45Z`, which is why it predates D-046, D-047, D-049, D-050 and D-051.
  - **Finding 1 — the installer is unsigned.** `Get-AuthenticodeSignature` on the published setup EXE returns `NotSigned`; the engine *inside* the package is signed `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)` with thumbprint `E04CE19746C83DB2DAAD532D04C8C607531C3CF5`, self-issued (`Issuer` = `Subject`) and therefore reported `UnknownError` on a Windows that does not trust that certificate's root. So the README's download tape had been saying the download carries the project's signature; it now names the one file that carries anything and states that the published `SHA256SUMS` is the installer's only anchor.
  - **Finding 2 — the signing identity is minted per build, and D-051's pin assumes it is not.** `make-release.ps1` says so itself ("the throwaway signing key does not outlive the build it signed"; `scripts\codesign-cert.ps1` keeps the certificate as a PFX in the job's TEMP). Counted 2026-11-11, this machine's user stores held **24 entries / 12 distinct certificates** with the identical subject `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)` — `ABB0FF3D...` (2026-10-28) and eleven more from 2026-11-04 onward, including `731A6520...`, `ED58002F...`, `AB9A9616...`, `59A150FD...` and `1F08A3EF...` — one per signing run, with the published release adding a thirteenth on the artifact. The CN therefore identifies nothing, which is exactly why D-051 replaced it with a thumbprint; but pinning the thumbprint of the engine's own image, as D-051 does, means the next release signed by the next throwaway certificate is refused by the previous release's engine. **Fail-closed — no update, never a wrong accept — and no user can hit it yet**: no build carrying D-051 has been published. Recorded as the register's new **MED** row and §0.6 **row 18** (**ب7**), with the only deadline it has: before the next publish. The fix needs no code — mint one certificate and keep it as the `MICS_PFX` and `MICS_PFX_PASSWORD` secrets (D-034's wiring, now load-bearing for a second reason), or set `MICS_UPDATE_SIGNER_THUMBPRINT`.
  - **What was written.** `README.md` (the download tape, and the "what is left" list under it), `docs/ROADMAP.md` (the ب-lane row, the ب6 row — whose asset sizes turned out to describe the **2026-11-07 local rebuild** rather than the draft's own bytes, so they are replaced with the measured ones — ordered item 8, and the closing paragraph), this file's §0.6 rows 1, 9 and 18, §7's HIGH row (a) and the new MED row. Nine mojibake characters in this file (the `ΓÇö`-family sequences from an earlier PowerShell round-trip — the exact trap §8.9 warns about) were repaired in the same pass, with the deliberate example inside §8.9 left as the example it is.
  - **Gate.** `scripts\pipeline.ps1 -Tier fast` — **PASS, 4 of 4 steps, 63.7 s** (`flutter.analyze`, `flutter.test`, `engine.test`, `engine.clippy`), engine **206 passed / 0 failed**, clippy clean. The change is documentation only, and the numbers it reports come from outside the tier: published hashes re-hashed, the manifest check run over the unpacked package, signature status read off both the installer and the engine, and the certificate pile counted.
  - **Next.** Nothing here changes what waits on you: the four decisions in `docs/OPEN-DECISIONS.md` item 2 (item 3 is settled and implemented) and the ARM64 app. The engineering list now starts with **ب7** (one signing identity per release, before the next publish), then هـ1's §7 rows.
- **The update pin is a certificate, not a name: the engine's own signer, with the release CN only where a build has no signature of its own (§7 register, the update-pin LOW row, D-051) — 2026-11-11**
  - **What was wrong.** The pin was `EXPECTED_SIGNER_CN = "MI CS Code Signing"` compared against a file's signer display name, and the two halves were wrong in opposite directions. It was **too strict in the way that would have broken the product**: no CA can issue that CN at all (CSCBR §9.2.2 requires `subject:commonName` to be the verified legal name, measured 2026-11-06), so the day ب5's certificate exists, `update.rs`'s payload check - the one place that decides whether the two binaries of an update may replace the running install - would have refused the release **it is part of** ("signed by X, not MI CS Code Signing"), and `selfcheck` would have reported the engine as a foreign signer on its own machine. And it was **too loose where it looked like a check**: a CN is free text, so any certificate that chains to something this Windows trusts and carries the same CN passed. The row's own fix line said what to do - thumbprint when there is one to pin, the name only where there is not - and `docs/OPEN-DECISIONS.md` item 3 had recommended the same for a month.
  - **What was done.** One value carries both, and one comparison decides. `signature::Pin` is `Thumbprint(hex)` or `Name(cn)`; `update_pin()` builds it once, in order: `MICS_UPDATE_SIGNER_THUMBPRINT` when the environment sets it (D-047's operator hook, and a value that is not 40 hex digits is an **error**, not a silent fallback), else the thumbprint **of the certificate inside this engine's own image** - read out of the PE certificate table with no chain built, so it answers the same on a Windows that has not trusted the root yet - else `Pin::Name(EXPECTED_SIGNER_CN)`. That last branch is a development build and only that: an unsigned `cargo build` has nothing of its own to pin, and it **says so** (`pinned: false`) instead of calling the weaker check a pin. `require_signed_by_pin(path, &pin)` replaces `require_signed_by(path, cn)` - Windows still has to accept the signature, then the pin decides the identity - and the update path calls it for **both** binaries in the archive, which is the call that was actually broken. `judge(&pin, signer, url)` is the same policy over `update.json.sig`, `trust()` classifies a file against the pin while keeping D-025's three states, and the package self-check's refusal line now **names the certificate it found** instead of asserting the release CN, which on a CA-signed build would have been a false sentence in the log. The release gate moved with it, because otherwise the claim is half true: `scripts\verify-manifest.ps1` used to ask "is the engine signed by us" by name, so a CA-signed release would have passed the engine and failed the gate that runs before publishing - it now reads the same `MICS_UPDATE_SIGNER_THUMBPRINT` hook (a value that is not a thumbprint is a refusal) with the release CN as its fallback.
  - **What was measured.** `cargo test` **206 passed, 0 failed**, five of them new (`signature.rs` 10 → 14 declared cases, `update.rs` 3 → 4, with two cases renamed rather than duplicated) and two of those over the **real** signed artifact (`dist\MICS-portable\mics-engine.exe`, `Valid`, `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`, thumbprint `1F08A3EF...`): a `Thumbprint` pin accepts the file signed by the pinned certificate and refuses a pin that is another certificate while the name still matches, and a file with **no signature at all** is refused by either half (`no valid Authenticode signature`), so the payload check's first question did not move. The rest pin the halves: each identity is decided by the half it names, and a build with no signature of its own falls back to the release name. `cargo clippy --all-targets` **clean** - the unused `require_signed_by` had to go rather than stay as a second, weaker entry point. `scripts\verify-update.ps1` re-run against an engine built from this source (deliberately **unsigned**, so both halves of the pin run rather than one): **45 passed, 0 failed, 0 skipped** in 9 s - part 7 refuses a correctly signed feed under the wrong thumbprint and names both ("signed by \"MI CS Code Signing\" (thumbprint f250975f...), and this engine pins the certificate with thumbprint 11fbddbb..."), part 8 is the name fallback itself, reporting the name check instead of a pin. The release gate was measured the same way on the signed package in the tree (`dist\MICS-portable`, 68 files, engine `Valid`, thumbprint `1F08A3EF6CDF5E93394DAC3CBCB5276381CC47E0`), three pins and three exit codes: no hook set → **PASS, exit 0** (the CN fallback, exactly as before); the hook set to the engine's own thumbprint → **PASS, exit 0**; the hook set to another certificate → **refused, exit 1** naming both thumbprints; a hook that is not a thumbprint → **refused, exit 1** before a file is read. `scripts\verify-tamper.ps1`, which drives that gate through its callers and the engine's own reporting, stays green on the changed script: **41 checks, 0 failures, 100.8 s**, the same counts as its 2026-11-03 run. `scripts\pipeline.ps1 -Tier fast` **green, 4 of 4 — 92.0 s**, with the engine at **206 passed / 0 failed** (the QA report test failed first and was right to: the report's engine-case counts moved 201 → 206, so the regenerated `qa/report.md`/`.html` are in this commit).
  - **Next.** The register stands at **7 open rows (1 HIGH, 3 MED, 3 LOW)** out of 24 - the LOW ones left need content (the starter pack), a licence answer (the country lists) or a key from outside (the hash feed), so the next pull forward is a MED row (real-time watching) unless publishing `v0.1.0` comes first. What F-3 still carries is **not** a pinning gap and is written as such in the threat model: the pin is read out of the file under question, so a *copy* somebody re-signed pins its own certificate - on the update path the payload is a different file from the engine judging it, and there the pin has teeth.
- **A pack that did not load is a fact, not silence: the loader names it and Settings names the language (§7 register, the cheapest open LOW row left, D-050) — 2026-11-10**
  - **What was wrong.** `I18nLoader` reads the modules of `assets/i18n/<code>/` and catches every read failure with `catch (_)` — deliberately, because a module nobody has translated yet must not break the app. A *whole* folder is the same code path: a language in `bundledLangs` whose folder `pubspec.yaml` does not declare loads as an **empty table**, and nothing anywhere says so. Every key of it falls back to English, and where English is missing too, to the key's own name — `dashboard.title` on screen, no line in the log, no failed step. A *correct* build cannot ship it (`test/lang_registry_test.dart` fails, and `lib/main.dart` gates the first frame on the packs ever having a value, so a folder-less build never starts), but a built app has no such gate: it degrades quietly, which is exactly what the row recorded. The row's own honest bound was that the fix had to **report**, not fail.
  - **What was done.** The silent swallow became a classified one, and the fact reaches both places it can. `I18nLoader.build` collects a `PackLoad(code, modules, failed, firstFailure)` per language and `i18nPackLoadNote` turns it into **one** line — or `null` when that language loaded completely, so a correct build is quiet — through an injectable sink (`I18nLoader({PackReader? read, void Function(String)? log})`, defaults `rootBundle.loadString` and `stderr.writeln`; `I18nLoader.loads` keeps the classification for tests). The two cases are worded apart because only one of them is a defect: `no pack loaded for "en" - assets/i18n/en/ is not in the asset list (see pubspec.yaml "assets:")` against `N of M module(s) did not load ... (first: <path>)`. The screen reads the fact rather than the log — this is a Windows GUI app and `stderr` exists only with a console attached — so `packLoaded(tables, code)` feeds one line under the language picker (`settings.languagePackMissing`, `{language}` = the language's own native name), beside D-049's line: that one is about the stored *tag*, this one about the *build*, and a user who sees neither is the steady state. The About surface's copy lives with `settings`. The first run of the new tests then found the other half of the same defect for free: `i18nModules` listed **`about`, which no pack ships**, so every start of every language read a file that was not there — the entry is gone, `test/lang_registry_test.dart` now checks the module list and the shipped files in **both** directions, and `assets/i18n/README.md` names the `pubspec.yaml` step it used to leave implicit.
  - **What was measured.** `scripts\pipeline.ps1 -Tier fast` **green, 4 of 4 — 65.0 s** (`flutter.analyze` 17.9 s, `flutter.test` 32.2 s, `engine.test` 12.3 s, `engine.clippy` 2.6 s), with **`flutter test` 178 passed, 6 of them new, and the engine untouched at 201 passed / 0 failed**. The new cases: four in `test/i18n_pack_load_test.dart` — the **real** bundle, read through the loader the app builds, loads a pack for every bundled language and logs **nothing**; a reader that refuses one folder leaves that language empty, names it in one line, and keeps the other language and `lookup` working; one unread module is logged as a gap and not as a missing pack; the note is `null` exactly when every module loaded — and one in `test/ui_screens_test.dart` that mounts Settings with `ar`'s pack emptied (the stored tag is fine, so D-049's line must *not* appear), finds the sentence naming العربية, picks English and watches it go. The first attempt failed `qa_report_test`, the gate doing its job: six Dart cases move the report's counts (142 → **148** declared, 29 → 30 files), and the regenerated `qa/report.md`/`.html` are in this commit. Both halves were then re-run with the fix reverted — silencing the log call fails exactly the two log cases, removing the screen line fails the widget case with "Found 0 widgets" — which is the difference between a pin and a description. Nothing here is a probe: no elevation, no network, no machine change.
  - **Next.** The register stands at **8 open rows (1 HIGH, 3 MED, 4 LOW)** out of 24, and the cheapest one left is the **update pin**: `update.rs:128` refuses a release pinned by *name* when the running binary is signed, so the first CA-signed release would refuse itself, and the fix is written in the row. Beyond the register, §0.6 row 1 is still **one publish click by you**, and it is the only HIGH row in the product.
- **The next-session block and the ROADMAP cited a commit that is not in `main` (docs only) — 2026-11-10**
  - **What was wrong.** §0.0 — the block a fresh session is told to paste verbatim — and the ROADMAP's و row both named `ed3e219` as "small step 9". That object exists in this working copy but on no branch and in no commit's history: it is the **discarded first version** of step 9 (same parent `f621a3d`, same subject, same author date, **different tree** — the only difference is `docs/ROADMAP.md` and `docs/TODO.md`), and `a4856d5` is the version `main` carries, code-identical. A reader who follows the citation asks for a hash no clone can show, and the block that exists to orient a cold session was pointing at a commit nobody can read. `6737760` rewrote this same block and carried the stale hash through, which is why it survived.
  - **What was done.** Both citations name `a4856d5`. The check that found it now covers every hex string in `README.md` and `docs/*.md`: **15 commit objects are cited and all 15 are in `main`**, this was the only dangling one, and the remaining strings are artifact hashes and build stamps rather than commit references — `docs/REPRODUCIBLE.md`'s `revision 238da10` is what `make-release.ps1` printed on 2026-11-08, quoted as a measurement, and it is left alone because the rule here is append, not rewrite. Also in this commit: the paste block now names the **two cheapest rows to take next** and what is left in each — the undeclared-language-folder LOW row (the failing test and the first-frame gate already landed; what remains is that the pack loader swallows a failed asset read with no log and no failure) and the update-pin LOW row (an hour, the fix is written in the row, and the real defect is that the first CA-signed release would refuse *itself* at `update.rs:128`) — so a cold session does not re-derive the ordering. No code, no test and no gate reads these files; the register count, the row pointer and the resume point are unchanged and still read 9 open rows (1 HIGH, 3 MED, 5 LOW) out of 24.

- **A language tag no pack can render falls back to English, and the screen says which tag (§7 register, the cheapest open LOW row left, D-049) — 2026-11-10**
  - **What was wrong.** The engine accepts and persists any well-formed language tag **on purpose** — `settings.set lang=de` works, its shape check takes `zh-hant` and refuses `EN` and `abcd`, because a pack shipping next month must not need an engine release. The UI then resolved that tag with `AppLang.byCode(code) ?? AppLang.ar`, and Arabic is the one language the frame must not be in when the tag is unrenderable: `lookup` already falls back to **English per key**, so a hand-edited `settings.json` (or an external RPC caller — the picker cannot offer such a tag) produced an Arabic frame, right-to-left, with its missing keys in English, and not one word on screen about it. §7 carried it as a LOW row naming that exact expression.
  - **What was done.** The chain ends where the key-level chain already ends, and the fact is shown. `AppLang.resolve(code)` resolves a bundled tag to its pack (regional tags through their primary subtag, as before), an absent or empty code to **Arabic** (the engine's own default, not a guess), and a tag no pack answers to to **English**; `AppSettings.lang` is a *rendering* fact now, and `AppSettings` carries the stored tag beside it (`storedLangTag`, `null` = "same as `lang`, so a hand-built object stays coherent"), which `toEngineJson` writes back instead of `lang.code` — without that, the next settings write, a theme change, would silently replace a hand-edited tag with the fallback's code. When no pack answers to it, Settings prints one line naming the tag under the picker (`settings.languageMissing`, `{tag}` substituted), so the user is told why the product is not in the language the file asks for and that the picker replaces it. New key in both packs, so the parity test is satisfied and no pack can be missing the sentence that explains a missing pack. `assets/i18n/README.md` says the same thing for whoever adds a language next.
  - **What was measured.** `scripts\pipeline.ps1 -Tier fast` **green, 4 of 4** — **69.6 s** on the first green run (`flutter.analyze` 17.8 s, `flutter.test` 40.5 s, `engine.test` 8.8 s, `engine.clippy` 2.5 s) and **59.2 s** on the re-run of the frozen tree — with **`flutter test` 172 passed, 5 of them new, and the engine untouched at 201 passed**, which is what the row's close is: five cases, four in `test/settings_model_test.dart` (a tag with no pack renders English and reports the tag; `ar`/`en`/`en-GB`/`EN` are not "missing"; an absent tag is Arabic and not a missing pack; a write sends the stored tag back) and one in `test/ui_screens_test.dart` that mounts Settings against a fake engine holding `de` — the new `FakeEngine(initialLang:)`, because the interesting tag is exactly the one the picker cannot offer — finds the English pack, the tag named on screen and `rtlProvider` false, then picks العربية and watches the notice and the tag both go. The first attempt failed `qa_report_test`, the gate doing its job rather than a defect: five Dart cases move the report's counts (137 → **142** declared, `test/settings_model_test.dart` 6 → 10, `test/ui_screens_test.dart` 10 → 11), and the regenerated `qa/report.md`/`.html` are in this commit. Both new cases were then run against the **pre-D-049** fallback (Arabic) with the fix reverted, and exactly those two fail — the difference between a test that pins this and a test that merely describes it. Nothing here is a probe — no elevation, no network, no machine change.
  - **Next.** The sibling LOW row this pointed at **closed in the entry above** (D-050, 2026-11-10): a language folder `pubspec.yaml` does not declare is now named once in the log and once in Settings, and the `i18nModules` drift it was hiding (`about`, a module no pack ships) went with it. The register stands at **8 open rows (1 HIGH, 3 MED, 4 LOW)**, and the cheapest one left is the **update pin** — `update.rs:128` refuses a release pinned by *name* when the running binary is signed, so the first CA-signed release would refuse itself, and the fix is written in the row. Beyond the register, §0.6 row 1 is still **one publish click by you**, and it is the only HIGH row in the product.

- **The guard stops loading an IOC list it drops, and says out loud that a process start is not hash-checked (§7 register, the cheapest open LOW row) — 2026-11-10**
  - **What was wrong.** `guard::etw::start` opened the store, read `dump_ioc_hashes()` into a `HashMap`, and then threw it away with `let _ = ioc_hashes;`. Worse than the waste was the sentence sitting next to it: *"There is no scan scheduler yet, so this is not a safety net."* A scan scheduler landed with **D-027** on 2026-11-03, so a reader learning the guard's limits from that file was being told something false — and the true reason (the scan job owns the hash dimension) was nowhere in the code.
  - **What was done.** The load and the unused `Storage` import are gone; the comment now states the deliberate limit and points at `PROTECTION-MATRIX.md` §4.1. The limit itself did not move — hashing every process creation is still judged too hot — but it is now *one fact in one function* instead of a comment: `guard::ioc_hash_coverage()` in `guard/mod.rs` answers `{hash_checked_at_process_start: false, reason: "…the scan job checks file hashes (D-027)"}`, `guard.status` returns it under `ioc` beside the canary block (same idiom: a measured verdict, not an implication of coverage), and the engine test `the_guard_status_states_that_process_start_does_not_hash` pins it so turning hashing on later cannot pass by editing only a comment. `PROTECTION-MATRIX.md` §4.1, the §7 register row and `docs/ROADMAP.md` (و) say the same thing.
  - **What was measured.** `scripts\pipeline.ps1 -Tier fast` **green, 4 of 4** — **74.7 s** on the first green run (`flutter.analyze` 17.3 s, `flutter.test` 37.3 s, `engine.test` 8.3 s, `engine.clippy` 11.8 s) and **57.6 s** on the re-run of the frozen tree, `engine.clippy` cached — with `cargo test` at **201 passed / 0 failed**. The first attempt failed `qa_report_test`, which is the gate doing its job: one new engine case moves the report's per-file count (`engine/src/tests.rs` 55 → 56, total 200 → 201), and the regenerated `qa/report.md`/`.html` are in this commit. No probe is involved — nothing here is elevated and nothing touches the machine — so the tier is the whole measurement.

- **The update feed has a compiled-in default, one implementation, and an answer that names it (D-046, §0.6 row 5 — the first half of هـ1) — 2026-11-09**
  - **What was wrong.** `update.check` answered `disabled` until its owner found, typed and trusted a manifest URL, so the Updates section shipped a *Check now* button that could not work out of the box and `update.download`/`update.apply` sat behind it, unreachable the same way. The `stable`/`beta` channel was a setting nothing read, and the check existed twice: `SyncManager::check_update` for the UI and `update::check` for the downloader.
  - **What was done.** The channel now carries the project's own feed (`DEFAULT_UPDATE_MANIFEST_URL_STABLE` = `releases/latest/download/update.json`, beta = the rolling `beta` tag), and `resolve_update_url(env, setting, channel)` orders environment → saved URL → channel default in one pure function; `MICS_UPDATE_MANIFEST_URL=off` is the one explicit do-not-check value (`update_checks_disabled`), environment-only because `check_url` still refuses anything that is not a URL. `SyncManager::check_update` is deleted — `update.check` calls `crate::update::check()`, the same function the downloader uses — and the answer now carries `manifest_url`, which the Updates panel prints in mono under the button. The Settings copy says what an empty field means now, `settings.manifestHint` was reworded and one key added per language (`settings.manifestUrlDefault`), and the release lane grew `scripts\update-manifest.ps1` (step 9 of `make-release.ps1`, uploaded with the other assets) so the default resolves to a manifest that describes the zip beside it.
  - **What was measured.** `scripts\verify-update.ps1` **18 passed, 0 skipped, 0 failed (4 s)**, unelevated, with the feed served by the probe itself on `127.0.0.1` over a raw listener — so the run needs no network: `=off` answers `disabled` with a reason and names no feed; a saved loopback feed answers `available` with `latest=9.9.9` and `manifest_url`/`sha256`/`download_url` carried through; the download it names is really fetched, staged under the data directory and hashes to what the manifest promised; a manifest whose `sha256` is 64 zeros is refused with `SHA256 mismatch` and leaves no `update.zip`; `http://example.com/update.json` is refused by `settings.set` with "must use https://" and the previous feed survives the refusal. The probe is now the `update.verify` step of `-Tier full` (13 steps), so it runs with the other live probes. `scripts\update-manifest.ps1` against the real `dist\MICS-portable-0.1.0-x64.zip`: `size 22552651`, `sha256 8f27ad58…b37a`, the asset URL built from version + arch, the file re-read and compared field by field, no BOM; refused with exit 1 and nothing written for a foreign archive name, `-Version beta`, and a missing archive. The four gates: `cargo test` **194 passed, 0 failed** (192 before — two new cases in `settings::`), `cargo clippy --release -- -D warnings` exit 0, `flutter analyze --no-pub` "No issues found!", `flutter test --no-pub` **162 passed** — with `qa/report.md` (192 → 194 cases, plus the new step) and `qa/ui/ledger.json` regenerated so their ratchets stayed honest. Two false readings were caught by running it for real, and both became guards: the probe used to take the first binary that *exists*, so a stale `release` build answered as if the feature were missing (14 passed, 2 failed — every failure the change under test), and it now picks the newest output and refuses to measure a binary older than `engine\src` (measured: the stale release binary exits 1 naming `engine\src\settings.rs`).
  - **What it does not claim.** Nothing in this run fetched the compiled-in default: `releases/latest` serves **published** releases and v0.1.0 is still a draft (§0.6 row 1), so that URL is a 404 until the click, and reaching github.com from a probe would make the probe's result depend on the network. A manifest is also still trusted because https carried it — the `sha256` inside it describes the file it points at, so it catches a truncated transfer rather than a hostile feed. `notes_ar` is carried and never shown (`notes_en` is what the panel reads), and the release lane ships no Arabic notes because scripts here are ASCII.
  - **Next.** The second half of §0.6 row 5: a detached signature over `update.json` checked against a key shipped in the engine, with the D-016 thumbprint pin the moment any certificate exists. Then the §7 rows.

- **The elevated run happened and closed §0.6 row 17 (D-042/D-043/D-044/D-045) — 2026-11-09**
  - **What was done.** The one thing the row was missing: a shell with an administrator token, and the four scripts run in the order §0 item 7 set — `scripts\reset-wfp.ps1` first (the 2026-11-08 teardown never ran), then `scripts\verify-wfp.ps1`, `scripts\verify-connections.ps1` and `scripts\verify-wfp-watch.ps1`, all against `engine\target\debug\mics-engine.exe`, the build that carries D-045. The reset found exactly what it was written for: `before: sublayer=True filters=4` — four of MI CS' own `MICS-mics-engine.exe … probe` filters (two at port 65001, two at 65002) left on the machine by the crashed run — and removed 6 objects (four filters, the sublayer, the provider), ending at `filters=0 sublayer=False` with `watch: state=clear recorded=0`, so the cleanup did not leave a tamper behind. Then `verify-wfp.ps1` **16 passed, 2 skipped, 0 failed (5 s)**: `fw.wfp.block` reported `added=true` with the key `77C31A7A-8BE6-4277-BDCC-6045151EE243`, the count went 0 → 2 (one per address family), and Windows' own `netsh wfp show filters` carried the object — `FWPM_FILTER_FLAG_PERSISTENT`, provider `{6d494353-0001-…}`, sublayer `{6d494353-0002-…}`, layer `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, conditions `ALE_APP_ID` (the debug exe's path), `IP_REMOTE_PORT` 65001 and `IP_PROTOCOL` 6, action `FWP_ACTION_BLOCK` and **not** a permit — and the undo took it out of both our list and Windows' state. Then `verify-connections.ps1` **24 passed, 0 skipped, 0 failed (6 s)**: 462 rows, 143 still present when compared with Windows' own table and 319 already gone, 38 shared UDP sockets not comparable, 147 rows offering a block and 315 not, and part 3 in its write branch at last — a **real row's own spec** accepted, the BFE one filter heavier, `fw.wfp.unblock` removing it, machine back where it started. Finally `verify-wfp-watch.ps1` **34 passed, 1 skipped, 0 failed (4 s)**: part 1 read the **real** BFE for the first time (`state=clear recorded=0 live=0 needs_elevation=false` — `live=0` being an independent second proof that nothing of ours was left on the machine), with the detector, the once-per-change rule and the HIGH incident still driven by an injected status.
  - **What was measured.** The four runs above, and §0.6 row 17 closed on them. Two limits recorded rather than papered over: the installed `MICSHelper` is still a pre-D-045 release build (the app's own unelevated write path answers `0x80320004` until it is reinstalled: `engine\target\debug\mics-engine.exe install-helper` in an elevated shell), and `netsh wfp show state` produced no XML here, so `show filters` carried the action evidence — the skip now quotes netsh's exit code and answer (`4709011`). During the same pass a relative `-EngineExe` was found to break the *helper* path (`0x80070003`: the service runs as SYSTEM with its own working directory), so all four probes now resolve the path once; with that fixed the unelevated run names the real reason instead. **Four claims remain uncomposed** and are named in row 17 and in D-042/D-043/D-044: a filter's effect on a live connection, survival across a reboot, our sublayer's weight against a built-in permit rule, and a real deletion behind the engine's back.
  - **Next.** Nothing in the tree depends on those four; they are experiments a session can pick up with the scripts that already exist (`verify-wfp.ps1` could open a connection through its own filter, and the behind-the-back deletion needs the helper pipe's `firewall.wfp.unblock`). The project's own next rows are unchanged: publish `v0.1.0`, هـ1, row 13's remainder, or a §7 row.

- **A filter enumeration names its layer, and three probes stop reading a broken write as a pass (D-045, §0.6 row 17 slice a's elevated path) — 2026-11-09**
  - **What was done.** The elevated run of 2026-11-08 reached the BFE for the first time and found `fw.wfp.status`, `fw.wfp.block` and `fw.wfp.reset` all failing with `enumerating MI CS' filters: layer does not exist. (0x80320004)` (`FWP_E_LAYER_NOT_FOUND`) — `fw.wfp.block` failing **after** it had added its filter, because the read-back that makes "blocked" a seen state is the step that failed. The cause was one line: `for_each_ours` built its `FWPM_FILTER_ENUM_TEMPLATE0` with `..Default::default()`, leaving `layerKey` the zero GUID, which the API resolves as a layer that does not exist rather than "every layer of this provider". `filter_enum_template(layer)` now builds the template for a real layer and `for_each_ours` walks `LAYERS`; `FWP_E_LAYER_NOT_FOUND` is deliberately **not** in `is_missing` (a provider that is not there yet is an empty answer, a layer that is not there is a failure), and the crate has no such constant, so the test carries the code. Three instruments were reading that failure as something else and no longer do: `verify-wfp.ps1` **fails** a refusal in a shell that can write, with the reason; `verify-connections.ps1` treats an unreadable status as not-exercised instead of letting `-not $null` run down the write path and passing `$null -eq $null` as "back where it started"; `verify-wfp-watch.ps1` prints the refusal it was given rather than asserting "no administrator, no helper" in an elevated shell. `scripts\reset-wfp.ps1` (new) is the cleanup such a run needs: it removes MI CS' own filters, sublayer and provider through `fw.wfp.reset`, clears the D-044 record with them, reads the machine back, and reports an unreadable machine as **unmeasured** rather than clean.
  - **What was measured.** `cargo test` **192** (190 before: the template names a real, non-zero layer for every entry of `LAYERS`, and `FWP_E_LAYER_NOT_FOUND` is not `is_missing`), `cargo clippy --release -- -D warnings` clean, `flutter analyze --no-pub` clean, `flutter test --no-pub` **162 passing** (the QA report regenerated — it declares the engine test count, so it was stale until it said 192), fast tier as one run: **green, 4 of 4, 68.8 s**. `scripts\reset-wfp.ps1` end to end, unelevated, against the **installed** helper (a release build from before the fix): it reproduced the bug through a second caller — `fw.wfp.reset failed: enumerating MI CS' filters: The layer does not exist. (0x80320004)`, the same sentence in the status `detail` — and reported the cleanup **unmeasured** rather than done, which is the whole point of the script. `engine\target\debug\mics-engine.exe` now carries the fix.
  - **Next.** The four scripts in order in an elevated shell against the debug binary (§0 item 7), `reset-wfp.ps1` first: the 2026-11-08 run's teardown never ran, so a filter of ours may be on the machine. That run is what turns row 17's three slices into evidence — **done the next day; see the entry above, which also records the four strays the reset found**.

- **The filtering layer watches itself, and a deletion becomes an incident (D-044, §0.6 row 17 slice c) — 2026-11-09**
  - **What was wrong.** D-042's objects are persistent in the BFE *on purpose* — that is what makes a block outlive the app — and the same property means anything with an administrator token can delete the sublayer or a filter while MI CS goes on answering `fw.wfp.status` as if the protection were there. Nothing watched it: the guard's page had process starts and canaries, and the status call was a request the UI made when it felt like it, with no memory to compare against. The obvious design, a change subscription (`FwpmFilterSubscribeChanges0`), needs the very access the write path needs, and a kernel callout that would see it instantly is what `SECURITY.md` forbids.
  - **What was done.** A record beside the objects, and a pure judgement over it. `engine\src\firewall\watch.rs` (new): `meta` row `wfp_baseline` holds the filter names MI CS wrote plus whether it created the sublayer; `WfpManager::block` writes it on both privilege paths after the outcome is known, `unblock` drops one name, `reset` clears it (so our own cleanup is never read as a tamper), and a **refused** write records nothing. `verdict` is pure and answers `clear` / `unrecorded` / `guarded` / `tampered` (naming the sublayer and every lost filter) / `unknown`, with `needs_elevation` beating every other answer — the difference between "nothing is there" and "I may not look". One HIGH guard event per change (`should_alert` dedupes on the missing names plus the sublayer) rides the existing bus: an incident titled "MI CS' filtering layer was tampered with", the correlator's timeline, and a desktop card with its own copy, icon and route (`/network`, where the block and the status both live). The guard thread polls it on its own 2 s-loop counter (every 15th tick, ~30 s, in **both** the ETW and the poll loop, because the ETW branch `continue`s early), and `fw.wfp.watch` is the same look on demand; `WfpManager::status` was split so the guard thread's `status_blocking()` shares the helper-or-BFE decision without a tokio runtime. It never re-creates what was removed: re-adding a filter an administrator deleted would fight the machine's owner.
  - **What was measured.** `cargo test` **190** (180 before; 10 new in `watch` — the five states, the unreadable machine that must never be a tamper, the sublayer lost with every filter present, a filter nobody recorded as `extra`, the once-per-change rule including "a different loss alerts again", the seed hook filling only an empty record, and the injected status being labelled), `cargo clippy --release -- -D warnings` clean, `flutter analyze --no-pub` clean, `flutter test --no-pub` **162 passing** (2 new in `test\alert_card_test.dart`: the card's `firewall` kind wears its own icon rather than the catch-all bell, and opens `/network`), and the fast tier as one run: **green, 4 of 4, 113.6 s**. `scripts\verify-wfp-watch.ps1` (new), five engines on private pipes over their own data directories: **PASS, 38 checks, 1 skipped, 0 failed, 4 s** — part 1 asked the real machine with an empty record and got `unknown`, `recorded=0`, `needs_elevation=true` and the running helper's refusal in `detail` (`unknown variant firewall.wfp.status, ...`, the installed helper predating D-042), which is why the probe **skips** its "an elevated shell should have read this" check instead of passing it; part 2 seeded two names and injected a status holding one — `tampered`, `missing=["MICS-probe-beta"]`, an `incident.list` entry **HIGH** titled "filtering layer was tampered with" carrying the filter's name, a `WFP tamper:` line in the engine's own log marked as injected, and a second poll that moved neither the state nor `alerted_at` and filed no second incident; part 3 judged a filter nobody recorded as `guarded` with it listed as `extra` and a missing sublayer as `tampered` with `missing` empty; part 4 refused a block and proved the record stayed empty. The RPC contract against the same debug binary: **87 cases, 0 failed**. QA: `qa\methods.json` gained `fw.wfp.watch`, `qa\report.*` regenerated (**73 methods, 109 controls**).
  - **What it does not claim.** No **real** deletion was performed behind the engine's back — that needs an administrator, so what part 2 measures is the detector, the alert and the once-per-change rule against an injected status, not the machine. The guard thread's own 30 s poll was not observed firing either: the probe and the contract call `fw.wfp.watch` directly, which is the same function on a timer. Elevated (or with the helper reinstalled from Settings → Engine) part 1 reads the real BFE, and deleting one of MI CS' own filters while it runs is the missing experiment. The watch is a **poll**, so a delete-and-re-add inside one interval is invisible; `unknown` is not "fine"; and the record is best-effort — a crash between a write and its record leaves one filter listed as `extra`, which is never a tamper.
- **The connection list offers one block, and the engine writes the filter it implies (D-043, §0.6 row 17 slice b) — 2026-11-08**
  - **What was wrong.** `net.connections` was **IPv4 TCP only** — the walk lived in one `unsafe` block in `collectors.rs` over `GetExtendedTcpTable`/`GetExtendedUdpTable` with `AF_INET`, so a machine whose traffic had moved to IPv6 could be watched and then not acted on, and the pure helpers beside it (`format_ipv4_port`, `tcp_state_name`) had no tests. The list also showed nothing until Refresh was pressed, and `fw.wfp.block` (D-042) had **no caller at all**: the UI had no action on a row. The tempting shortcut — let the UI build the spec out of the row's displayed name and address — is wrong twice over: the filter matches an **image path**, not a spoofable process name, and the displayed port can be a listener's local port or `*:*`.
  - **What was done.** `engine\src\platform\windows\conns.rs` (new; `collectors.rs` keeps the trait wiring): all **four** tables (`TCP_TABLE_OWNER_PID_ALL`, `UDP_TABLE_OWNER_PID`, `AF_INET` **and** `AF_INET6`), the owning process's image path from one `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` per pid cached across the walk, IPv6 written the way Windows writes it (`[2001:db8::1]:443`, `[::]:135`), and `block_for` deriving the spec — `{app, port, protocol, note}` with the note sanitised to the helper validator's 40-character `[A-Za-z0-9 _-]` set — or `None` when a click would not mean what it says: **no peer port** (UDP, or a TCP listener), **no image path** (kernel connection, or a process this token may not query), or a protocol that is not TCP/UDP. A row that cannot be blocked arrives as `block: null` and the UI shows the reason instead of a button. In the app, `NetworkConnection` carries `process_path`/`protocol_number`/`remote_port`/`block`, the block button sends `block.toJson()` **untouched** (one unit test pins those four names to `FilterSpec`), a confirmation names the program, the port and the fact that the filter outlives MI CS, and the screen fetches a snapshot on open. Six new i18n keys in both languages plus `common.cancel`.
  - **What was measured.** `cargo test` **180** (174 before; 6 new in `conns`, including one asserting the derived spec passes `wfp::validate` *and* `Op::FirewallWfpBlock::validate`, and one resolving the running process to a real `.exe`), `cargo clippy --release -- -D warnings` clean, `flutter analyze --no-pub` clean, `flutter test --no-pub` **160 passing** (2 new in `test\network_connections_test.dart`: the click sends the engine's own spec and shows the engine's refusal; Cancel writes nothing), and the fast tier as one run: **green, 4 of 4, 66.4 s warm**. `scripts\verify-connections.ps1` (new) against a real engine on a private pipe: **PASS, 23 checks, 0 skipped, 0 failed** — 490 rows, every row carrying path/protocol/peer port and a block decision, **139** offering a spec whose app path, peer port and protocol match the row *and* whose file exists, no empty-peer row offering one, IPv6 and UDP rows present, **0** owner contradictions with `Get-NetTCPConnection`/`Get-NetUDPEndpoint` out of the 147 sockets still present (343 had already vanished — a snapshot ages, and the probe counts that), and the spec handed to `fw.wfp.block` refused **with a reason** with `fw.wfp.status` unchanged after. The RPC contract against the same debug binary: **86 cases, 0 failed**. QA: `qa\methods.json`'s note for the method rewritten, the fixtures moved to the real engine shape, the ledger regenerated (**+2 controls, 109**), `qa\report.*` regenerated (72 methods, 109 controls, 27 Dart test files, 24 engine modules).
  - **What this probe taught the tree.** Two Windows behaviours the first version of the probe called failures and now encodes: Windows reports **pid 0** for a socket that is closing while MI CS still holds the owner, and `Get-NetUDPEndpoint` and `GetExtendedUdpTable` name **different binders** for the same shared wildcard UDP socket (WS-Discovery, mDNS, SSDP) — so those rows are counted as ambiguous rather than called wrong.
  - **What it does not claim.** No click blocked anything on this machine: that needs an administrator or a helper that knows the WFP ops, and the installed `MICSHelper` predates them (the same wall D-042 hit). So "this spec, once accepted, blocks exactly this row" is **written and reasoned but unproven** — run `scripts\verify-connections.ps1` elevated and its last three checks take the write branch instead of the refusal branch. Also honest: the list is a snapshot, not a feed; there is no per-row traffic counter, no reverse DNS, no process tree, and no un-block from a row (removal is the Firewall tab's rule list).
- **MI CS gets its own layer in the filtering engine (D-042, §0.6 row 17 slice a) — 2026-11-08**
  - **What was wrong.** Every `MICS-*` block was a **Windows Firewall rule**: Windows enforced it, and it outlived the engine — but it was Windows' object in Windows' namespace, with `MICS-` a naming convention rather than a boundary. The row asked for MI CS' own enforcement layer, and the register had already refused the driver routes (WinDivert/Mullvad-Lib, or the legacy `netfilter2.sys`) as more signing for less truth.
  - **What was done.** `engine\src\firewall\wfp.rs` (new): a **provider** `{6D494353-0001-…}` named `MI CS` and a **sublayer** `{6D494353-0002-…}` weight `0x7fff`, both persistent and stable forever, plus persistent `FWP_ACTION_BLOCK` filters at `ALE_AUTH_CONNECT_V4`/`_V6` under our sublayer — one condition (application id and/or remote port). The filter key is **derived from the spec** (`sha256` over the canonical fields, RFC 4122 bits, one bit flipped for V6), so the same block twice is one filter and the undo needs no saved state. Four ops (`firewall.wfp.status/block/unblock/reset`; `reset` addresses our own provider key and can delete nothing else) and four dispatcher methods (`fw.wfp.*`, 72 registered), each write through the helper (D-007) and each verified by reading the filter list back from the BFE before it is reported. The `validate` both sides share refuses a spec with no target, a port of 0, a protocol that is not TCP/UDP, a path with a quote/newline/NUL, and a note longer than 40 characters — the note ends up in the filter's display name, which the BFE stores and `netsh` prints.
  - **What was measured.** `cargo test` **174** (162 before): 8 in `wfp.rs` — the canonical name, four refusals, the same spec → the same key, a known spec → the measured key `B051BA44-F5BF-454C-8D09-B8F1F8D5680E`, two layers → two well-formed version-4 GUIDs, and on this machine **the BFE opens unelevated and refuses the write** (`FwpmEngineOpen0` succeeds, `FwpmProviderAdd0` answers `0x80070005`, named as `needs_elevation`) — and 4 in `tests.rs` (the closed set still refuses a made-up op, the spec gate, an audit line that names the filter and key but not the folder, and the RPC params → spec-or-refusal path). The fast tier is **green, 4 of 4, 154.4 s, 174 engine tests, clippy clean** (the first attempt failed on two `collapsible_if` warnings in the new file — the gate working). `scripts\verify-wfp.ps1` (new) ran live unelevated: **PASS, 7 checks, 3 skipped, 0 failed** — `fw.wfp.status` answered `sublayer=false filters=0 needs_elevation=true` with the running helper's own refusal as `detail` (the installed helper predates D-042, so it lists the old eight ops), and the refused `fw.wfp.block` now carries the reason instead of "method failed internally". The RPC contract against the same binary: **86 cases, 0 failed**, the four new methods answering in their documented shape. `qa/methods.json` + `qa/report.*`: **72 methods, 107 controls**.
  - **What is NOT measured (so the row is not closed).** No filter was actually persisted here: that needs an administrator. Unproven until `scripts\verify-wfp.ps1` runs elevated (or with the helper reinstalled from Settings → Engine): a real block, its effect on a connection, its survival of a reboot, and whether `0x7fff` really puts our sublayer in front of the built-in firewall's permit. The probe skips those loud rather than passing.
  - **Next.** Run the probe in an elevated shell and paste the numbers into D-042 and this row. Slice (b) followed the same day — see the entry above it (D-043) — and is waiting on the same elevated run.

- **Explorer's verb hands the path to the window that is already open (D-041, §0.6 row 16) — 2026-11-08**
  - **What was wrong.** Nothing in the tree could scan the file the user was looking at: no context-menu verb anywhere, and no way for a second MI CS process to reach the window that was already open — two processes would have meant two windows and two engines watching one machine.
  - **What was done.** Three parts, one handover. **The verb:** `installer\mics.nsi` writes `HKCU\Software\Classes\{*,\Directory,\Directory\Background}\shell\MICS` — labelled `Scan with MI CS`, carrying this copy's icon, running `"$INSTDIR\mics_app.exe" --scan "%1"` (`%V` for `Directory\Background`, where the click is the empty space *inside* a folder) — and the uninstaller deletes all three; HKCU because NSIS keeps the invoking user's token even in the elevated half. **The method:** `app.activate` (the 68th) takes an optional `path`, answers `{"delivered": subscriber_count() > 1}` — the caller is a client itself, so only a *second* transport counts — and raises `event` `{"type":"activate","data":{"path":...}}` only when it is delivered, so the caller never reads back its own message. **The app:** `lib\core\ipc\handoff.dart` (new: `AppHandoff`, `HandedScan`, `handedScanProvider`) + `lib\main.dart` — `main(List<String> args)` now reads the arguments Windows already passed (`GetCommandLineArguments` → `set_dart_entrypoint_arguments`) for `--scan <path>`; every launch announces, `delivered: true` ends the process through the D-039 quit path (it never owned the engine — attaching first leaves `_ownsEngine == false`), and `delivered: false` means it *is* the window: raise, `appRouter.go('/scanner')`, hand the path to the scanner's notifier, which starts the scan (quarantine on, matching the checkbox) and shows the folder in the path field.
  - **What was measured.** `scripts\verify-handoff.ps1` (new): **PASS, 10 checks, 0 failures, 5.1 s** against a real engine on a private pipe with two real `NamedPipeClientStream` clients — delivered with a window attached, the `event`/`activate` notification arriving on that window with the path unchanged, a notification and not a reply, a plain launch carrying a null path, `delivered: false` once the window closes, and nothing raised for a caller with nobody to hand over to. Engine: `cargo test jobs::` **4 of 4** new tests in `engine\src\jobs.rs`. App: `flutter analyze --fatal-infos` clean, `flutter test` **158 passing, 0 failing** (146 before), `test\handoff_test.dart` (new) **12 tests** — five for the command line, six for the handshake against `FakeEngine` (including an engine too old to answer, which must still leave the user a window) and one for the scanner asking for exactly `{"path": ..., "quarantine": true}` and showing the handed folder. QA: `qa\methods.json` row 68, `qa\report.md`/`.html` regenerated (68 methods, 107 controls), `test\qa_registry_test.dart` and `test\qa_report_test.dart` green. `scripts\verify-installer.ps1` extended: the verb on each class after install (label, icon, command line), gone after uninstall, still there after a refused uninstall, and the probe refuses to run on an account that already has the verb.
  - **Honest limits.** Explorer paints the menu from those keys and a script cannot read the menu back, so the evidence is the keys plus the `--scan` path they invoke; the live install half of `verify-installer.ps1` could not run in this session (`Start-Process` on the NSIS package never returned on that machine — no process, no key, also for a copy and for an explicit `WaitForExit`), so the registry claims are asserted by a release-tier/user run of that probe, not from this session; multi-selection is unproven (no `MultiSelectModel` written); another pipe client that is not a window (a probe) counts as a listener and would take the handover; a second launch does create a process that briefly has no window, which is the price of using the engine as the single instance instead of a Win32 mutex; MSIX and portable copies get no verb.

- **The tray's styled surface is a Flutter panel in the app's own window (D-040, §0.6 row 15) — 2026-11-08**
  - **What was wrong.** The tray icon offered two labels, `Open MI CS` and `Quit`, because `tray_manager 0.5.2` builds its menu with `AppendMenuW` — labels, separators and check marks, read in the plugin's `windows\tray_manager_plugin.cpp` — so no amount of work makes that menu "designed". The user asked for a tray surface that looks styled; the only surface that can be is Flutter's.
  - **What was done.** `lib\core\window\tray_panel.dart` (new): a left click opens a **panel painted over the running app** — 392×486, non-resizable, always-on-top, out of the taskbar, anchored above the notification area and clamped into the work area, closed by `Escape`, by ✕, or by clicking away. It is the *same* window and the *same* Riverpod container, reached through `MaterialApp.router`'s `builder`, so its numbers are the screens' numbers: `guardProvider`, `firewallProvider`, `connectionsProvider`, `settingsProvider`. The guard switch asks `guard.start`/`guard.stop` and then re-reads `guard.status`; the other two switches write the same settings Settings → Protection writes (`dnd`, `close_to_tray`); `Quit` and the native menu's `Quit` are the same D-039 quit. The right click keeps the native menu as the fallback, and every `window_manager` call is best-effort so a platform without the plugin still paints the panel. 19 new i18n keys in both packs.
  - **What was measured.** `scripts\pipeline.ps1 -Tier fast`: **PASS, 4 of 4, 63.0 s** (`build\pipeline-fast.json`, `head` `d80d5ee`); `flutter analyze --fatal-infos` clean; `flutter test` **146 passing, 0 failing** (141 before), four of them new in `test\tray_panel_test.dart` — the panel *asks the engine* for the guard, the firewall mode and the connections it displays, the guard switch asks **and** re-reads, the other switches write `dnd` and `close_to_tray`, and `Escape`/`Quit` throw nothing. The QA harness treats it as a first-class surface: `test\ui_screens_test.dart` gained a `surfaces` map and a second sweep loop, `qa\ui\ledger.json` gained `surfaces.trayPanel` with **6 controls**, and `qa\report.md`/`.html` were regenerated to **"13 screens, 1 surface and the shell"**, **107 controls**, **67 methods** (the report's generator now separates screens from surfaces instead of calling a panel a screen).
  - **What it does not claim.** The panel's *placement* is not measured end to end: `tray_manager.getBounds()` and `screen_retriever` are logical pixels in the plugin source, and the anchor arithmetic is unit-tested nowhere because a widget test has no tray icon — what is documented is the arithmetic, the clamping, and the bottom-right fallback. Nor is a second window: the panel resizes the window the app already has, so opening it while the app is visible is a mode switch, not a popup over it. It does not touch `tray_manager`, and it does not remove the native menu — that is what a fallback means.
- **The engine lives and dies with the app that started it (D-039, §0.6 row 14) — 2026-11-08**
  - **What was wrong.** `mics-engine service` was started `detached` and nothing ever stopped it: closing MI CS hid the window to the tray, so the engine kept running with no window anywhere that said so, and the only way to end it was Task Manager. That is an invisible process watching every new process on the machine, invisible *and* unkillable from the product, which is the shape this project's own threat model treats as a liability. The brief asked for it ("Closing the UI -> tray; engine keeps protecting"); the user asked for the opposite, and chose the setting as the way to keep both.
  - **What was done.** Three parts. (a) **The app's process is the engine's lifetime**: the client starts `service --parent <its own pid>`, and `platform\windows\parent.rs` opens a **handle** to that process once and waits on it — a handle, not a pid polled on a timer, because Windows does not re-use the pid while a handle to it is open, so "signaled" can only mean that process ended. A close, a crash and a Task Manager kill all end the engine, and the end is *clean* (`crash::end_session("clean")`), so a killed app is not filed as an engine crash. (b) **`shutdown`**: a new whitelisted method that answers `stopping` and only then ends — the pipe server holds the connection open 250 ms for that answer, and the client suppresses its reconnect logic while it is deliberately stopping, so a quit is not mistaken for a lost engine. The UI asks only when it *owns* the engine: it compares `status.pid` with the pid it spawned, so a second MI CS that merely attached to a running engine leaves it alone. (c) **`close_to_tray`** (default **false**): closing the window quits, and Settings -> Protection -> "Keep running in the background" restores hide-to-tray. An engine nobody owns — the autostart entry, a terminal, a verifier — has no parent and runs until it is asked to stop, which is what keeps 24/7 an explicit choice.
  - **What was measured.** `scripts\verify-lifecycle.ps1` (new, and now the pipeline's `engine.lifecycle` step): **19 checks, 0 skipped, 0 failures, 9.6 s** against a real engine on private pipes and a stand-in app process. It proves a killed app ends the engine within seconds with the pid in its log and **no crash report**; that `shutdown` answers `stopping` *before* the process ends and also files no crash report; that an engine whose `--parent` was already gone ends by itself; that a **parentless** engine keeps running until it is asked (the autostart case); and that `service --help` lists `--parent`. Engine tests: 6 new cases (4 on the stop flag, 2 on the parent handle) in **158 passing, 0 failed**; `cargo clippy --release -- -D warnings` clean; `qa\report.md` + `.html` regenerated (**67 methods**, 69 contract cases, 15 classified not to run, Dart cases 110 -> **111**, QA control ledger 100 -> **101** with the new `SwitchListTile(Keep running in the background)`, and the QA report's `full`-tier table now lists the `engine.lifecycle` step) with the new `mutating` row for `shutdown` skipped by reason.
  - **What it does not claim.** The UI's half is not measured end to end — a widget test cannot own a pipe — so what is documented is the exact decision it makes (`status.pid == spawned pid`) and that `stopOwnEngine()` is a no-op when that is false; the engine's half, which is the part that cannot be worked around, is what the 19 checks measure. Nothing here stops an engine this app did not start, and nothing removes the autostart entry.
  - **Also fixed in the same pass, because the change made them false:** `README.md`'s "the logon entry keeps it running" and "cards fire even when the window is closed" now say what the code does (and the `HKCU\...\Run` entry was measured absent on this machine, as was any MI CS scheduled task); the `guardAutostart`, `scanHours` and Settings hints in both languages; and the engine's own comments that promised 24/7 (`main.rs`) now name the engine's real lifetime.
- **One name, one rule: the firewall cannot be told to remove something it created under another name (§7 register, MED — found by the 2026-11-07 acceptance run) — 2026-11-08**
  - **What was wrong.** `add_rule_now` prefixed the name unconditionally while `remove_rule_now` stripped an *optional* prefix first, so `fw.rules.add {name:"MICS-foo"}` created `MICS-MICS-foo` and `fw.rules.remove {name:"MICS-foo"}` then looked for `MICS-foo`, found nothing and **reported success** - removing a missing rule is deliberately idempotent - leaving a stray *blocking* rule. The acceptance run had to pass the doubly-prefixed name to clean up after itself, and the same class of leftover is on this machine: `MICS-TEST-BLOCK-EXAMPLE`, an outbound block on `203.0.113.0/24` with no MI CS group and no description.
  - **What was done.** One function decides a rule name. `owned_rule_name` strips *every* leading `MICS-` (repeated, ASCII-case-insensitive, surrounding space trimmed) and re-adds exactly one, so `foo`, `MICS-foo` and `MICS-MICS-foo` all name the rule `MICS-foo`; a name that is only the prefix is refused with a sentence that quotes the prefix; `add_rule_now` and `remove_rule_now` both go through it, so a name an older build doubled is removable by either spelling; and `FirewallManager::add_rule`/`remove_rule` validate it *in front of* the privilege split, so an unelevated caller gets the name refusal instead of "no helper" - which is also what makes the new contract case meaningful on any machine. D-028 holds: no signature changed.
  - **What was measured.** `cargo test`: **152 passed, 0 failed** (the new test walks five spellings of one name and four non-names through the pure function, so it touches no firewall). `qa\report.md` + `.html` regenerated: **69 declared contract cases** (67 + the two new refusal cases - `fw.rules.add` and `fw.rules.remove`, each with `name: "MICS-"`), and `test/qa_report_test.dart` is green. `scripts\verify-firewall.ps1`: **27 checks, 0 skipped, 0 failures, 29.9 s** against the running `MICSHelper` - part 3's new cycle creates a rule under the *prefixed* spelling, asserts the engine reports it as `MICS-<rule>`, asserts Windows has **no** `MICS-MICS-<rule>`, then removes it by the *unprefixed* spelling and asks Windows to confirm it is gone (23 checks before; the four new ones are the ones the register asked for). No probe rule was left behind - `MICS-*` on this machine is still only the old `MICS-TEST-BLOCK-EXAMPLE`.
  - **What it does not claim.** The stray `MICS-TEST-BLOCK-EXAMPLE` is not removed: one call fixes it now, but that is a change to a user's firewall and this phase is a code fix. And the *real-time* firewall (WFP filters, live connections, one-click block) is **§0.6 row 17**, not this: this phase only stops the rule list from lying about what MI CS owns.
- **A reproducible build, and the check a stranger runs on it (F-11, §0.6 row 4) — 2026-11-08**
  - **What was wrong.** With no certificate purchased (D-035) the trust story rests on
    "the published bytes can be re-derived from this source", and nothing measured that.
    Two from-scratch app builds differed (`mics_app.exe` `604152af…` then `03bcfac2…`, and
    every plugin DLL with it); two from-scratch engine builds differed (`e5c1ef1d…` then
    `118084ae…`); `Compress-Archive` stored each file's own timestamp, so the same tree
    zipped twice differed; and the shipped engine's PE header carried its own link time
    (`1794050817` = 2026-11-07T11:26:57Z).
  - **What was done.** The build time comes from the revision, not the clock
    (`SOURCE_DATE_EPOCH`, the revision's committer date in UTC at an even second, which a
    ZIP entry can store); `/Brepro` is set for both linkers (`windows\CMakeLists.txt`
    before the Profile copies, so Release and Profile and the plugin subdirectories inherit
    it, and both MSVC target sections of `engine\.cargo\config.toml`);
    `New-MicsDeterministicZip` replaces `Compress-Archive` (ordinal paths, forward slashes,
    no directory entries, one fixed timestamp); `make-release.ps1 -Reproducible` refuses a
    tree with uncommitted changes and writes the *content* hashes into `VERSION`;
    `Get-MicsUnsignedHash` is the PE hash with the signature taken out; and
    `scripts\verify-reproducible.ps1` rebuilds a published archive - signed with a
    locally minted self-signed identity, which needs no certificate - and compares it
    file by file, with `-SelfTest` covering the primitives and
    `docs\REPRODUCIBLE.md` as the recipe.
  - **What was measured.** With `/Brepro`, two from-scratch `flutter clean` builds produced
    an identical **63-file output tree**, `mics_app.exe` = `4d5cafba…` both times; two
    `cargo clean` + release builds of the engine produced one file
    (`6afc16b7…`, 24,184,832 bytes, 742 s and 696 s, `TimeDateStamp` `3544384635` =
    `0xD343047B` in both — a hash-derived value, not a clock, where the pre-change pair had
    differed); `data\app.so` was `51c2ab76…` throughout; the same 70-file tree zipped twice
    gave `266B627B…`; and `-SelfTest` is **17** checks. The pipeline is green — 4 of 4,
    **402.8 s**, 151 engine tests (cold, because the measurement had just cleaned
    `engine\target`).
  - **And the check itself ran end to end.** A reference package was built the way a
    release is built (`make-release.ps1 -Reproducible -Sign -Version 0.1.0-repro`,
    295 s), and `verify-reproducible.ps1 -Reference` then rebuilt it from the same
    source with its own self-signed key in 239 s: **60 files byte for byte identical,
    7 identical on their content hash, 2 explained, 0 unexpected** — exit 0. The
    explanation is the one in §3, and the two explained rows are the engine and the
    `VERSION` line that repeats its content hash. Comparing the two package file
    lists afterwards also explained `69` versus the published archive's `70`: the one
    differing name is `native_assets.json`, which Flutter's native-assets step wrote
    for the 2026-11-06 CI build and does not write after a local `flutter clean`
    (recorded in `docs\REPRODUCIBLE.md` §6).
  - **What it does not claim.** The Authenticode blobs themselves are not reproducible (a
    timestamp and a random RSA value), and the engine carries `MICS_MANIFEST`, which
    records the other files' hashes *as signed* - so `mics-engine.exe` and the one `VERSION`
    line that repeats its content hash are **proved** different rather than required
    equal, and a rebuild re-signed with another key is still indistinguishable to a local
    check. Making the manifest content-based is its own slice, **§0.6 row 13**.

- **§0.2 reconciled with what actually ran, and the register count corrected (2026-11-08)**
  - The first item in "Blocked on the user" still read *"د3: three clicks, and the helper
    acceptance happens in the same session"* a day after §0.6 row 2 and the ROADMAP recorded it
    closed and measured, so the section contradicted itself: it opens by promising that
    everything below waits on a human. The item is now struck through and kept as **the record
    where the request used to be** — install with one prompt, `MICSHelper` created by the
    installer inside it, `fw.rules.add`/`fw.rules.remove` over a private pipe with no GUI, the
    uninstall with one prompt, and the installed tree's 68-of-68 self-check reporting
    `untrusted-certificate`. The slice it deliberately did **not** run live (*Default deny
    outbound*, the SMBv1 toggle, the hosts write — said so at the time rather than glossed over)
    is now labelled as **not a request**: nothing in §0.6 waits on it.
  - The register count is one number in all three places that state it (`TODO` §0.3, §0.6 row 9,
    `ROADMAP` و): **13 open rows — 1 HIGH, 4 MED, 8 LOW — out of 24**, counted on 2026-11-08 by
    walking §7. Three copies had drifted to 12/23, 12/22 and 12/23; the eighth LOW row is the one
    this session added — what a user sees when the engine refuses to start at all.
    **Later the same day the count became 12 — 1 HIGH, 3 MED, 8 LOW** — when the MED row about a
    doubly-prefixed `MICS-` rule name closed (the paragraph above); the number was corrected in
    every place that states it, and it was re-derived from §7 with a script rather than adjusted
    by hand.
  - Every pointer that still described د3 as pending was swept: the release-lane blockquote, both
    "what is left" summaries (§0.1 and §0.3), the P6 phase row, the 21-point list row 13, and the
    §0.2 item 1 references in §0.5. No page now says a *run* waits on you; what waits are answers
    (§0.2 items 3–5) and the one publish click (§0.6 row 1).

- **"Trusted by a stranger's Windows" became a command with an exit code (2026-11-07, later
  again)**
  - `scripts\verify-trust.ps1` judges one artifact and exits **0 only when the answer is yes**:
    the signer was issued by a CA and the chain ends in a root in `LocalMachine\Root` — the store
    AppX and installers actually read. Unsigned, self-signed, a chain that stops at an untrusted
    root, and a file that no longer matches its own signature all exit non-zero with the reason
    printed, and the certificate's EKU, its timestamp and (for certificates issued on or after
    2026-03-01) the CA/Browser Forum 460-day validity limit are reported next to the verdict.
  - **Why it was needed:** the obvious check lies. On this machine `Get-AuthenticodeSignature`
    reports **`Valid`** for the engine signed with our own self-signed certificate, because the
    certificate is in the user's trust stores. The tool tells the two apart by issuer, chain and
    root store, and says explicitly when a locally-`Valid` file is judged untrusted.
  - **Both controls are built in (`-SelfTest`), and both pass:** the repository's own engine is
    judged `self-signed` while its raw status on this machine is `Valid` — the trap working — and
    `C:\Windows\System32\kernel32.dll` is judged `public-ca`, chain of 3 to `Microsoft Root
    Certificate Authority 2010`, timestamped, 364-day validity. Judged by hand too: the unsigned
    `dist\MICS-0.1.0.0-x64-noservice.msix` → `unsigned`; the same package signed with the test
    certificate (`make-msix.ps1 -SelfSigned`) → `self-signed`, although that script's own output
    says `trusted for install (CurrentUser\TrustedPeople): True`.
  - **Honest limits, in the header and in `SIGNING.md` §1:** revocation is not checked (no
    network), the private key's location cannot be seen (so the hardware-module rule is out of
    reach), and an AppX/MSIX is read through `signtool verify /pa /v` because .NET's `SignedCms`
    refuses the encoding AppX uses (`ASN1 bad tag value met`, measured) — without the SDK a
    package is reported **unjudged**, never trusted.
  - The probes were removed and the machine left as found; `build\msix-stage` and
    `dist\MICS-signature-probe.msix` are deleted.

- **The Store-shaped package was run for real, and the app half works (2026-11-07, later
  again)**
  - The `None` shape had been *registered* before but never *run*. Run: staged with
    `-StageDir "$env:LOCALAPPDATA\mics-msix-stage"`, registered in developer mode, launched
    through the shell. `mics_app` started `mics-engine` **from the package folder**, the pipe
    `\\.\pipe\mics_engine` came up, the engine answered the app's 15-second `ping` heartbeat and
    `sync.status`, the guard started (6 rules, 3 canaries armed) with `ETW unavailable (Access is
    denied)` falling back as an unelevated process should, and the self-check reported **`ok — 68
    file(s) hash as the manifest says (package 0.1.0)`** from inside the container.
  - **State landed in the real `%LOCALAPPDATA%\MICS`** (`data=C:\Users\…\AppData\Local\MICS`), not
    in a package-private store, and `%PROGRAMDATA%\MICS` was not touched. Honest limit: this was a
    developer-mode **loose** registration, so it describes the shape's behaviour and not a promise
    about a Store-signed install — which is why `docs/STORE.md` §6 has it re-measured after
    certification.
  - **The hour it cost is written down as trap 33:** staged in this workspace (`H:\`, which carries
    `Mandatory Label\Low Mandatory Level`), the same package launched, sat there and never started
    its engine. The portable copy failed identically, which identified the folder rather than the
    package as the cause: Windows gives a process the label of the folder its image is in, and the
    engine refuses to serve below Medium. A new §7 row records what that costs a user — the engine's
    explanation goes to a stderr that `ProcessStartMode.detached` discards, so the UI shows "engine
    missing" and retries forever.
  - Still unmeasured, and only an administrator can: the helper reached across the container. The
    machine was left as found — package removed, stage deleted, no process and no pipe behind.

- **Route B's date is not only a calendar question (2026-11-07, later again)**
  - Re-read the OSSign CLI repository instead of trusting the earlier note: the roadmap marks
    PE/COFF, MSI and PowerShell signable (JAR/APK/DMG still open) and `verify` is documented
    for PE/COFF, MSI, CAB, **APPX/MSIX** and PowerShell — so the artifacts this project would
    hand it are exactly the ones it was built for, which also means an OSSign-signed MSIX is
    on their roadmap even though route A does not need it.
  - The half that changes the plan: the **OSSign Server** — the free, keyless,
    trusted-publishing path — is still marked **TBA** for signing together with the GitHub
    Action, the example configuration uses `trustedSigningKey: test-certificate`, and their
    own `verify` exits 2 for a file signed with an "OSSign Server **test-mode** certificate".
    So route B waits on **two** things: this repository reaching six months (~2027-04-27) and
    OSSign putting the production server into service. That is consistent with the suspended
    applications, and only the first half is under this project's control — which is why the
    README and the ROADMAP keep route A as the one that is open today.
  - Recorded with the date in `docs/SIGNING.md` §4 and its source row.

- **The Store submission has a playbook, so the free account is the only thing left
  (2026-11-07, later again)**
  - [`docs/STORE.md`](STORE.md) is the operational half of route A, kept separate from
    `SIGNING.md` (which records *why* each route is what it is): what only the owner can do
    (the free account, the name reservation, and the four values Partner Center assigns — two
    of which go straight into the manifest, with the Publisher DN required to equal the signing
    certificate's subject), the exact `make-msix.ps1 -ServiceMode None -Identity … -Publisher …`
    invocation for that identity, and the warning that **the submitted package must not be
    self-signed**, because Microsoft signs it.
  - The copy that would otherwise be improvised at submission time is in the file: short
    description, description, "what's new", the two links (the privacy policy Store policy
    10.5.1 requires — the document `PRIVACY.md` was written for), a four-screenshot list, the
    IARC answers that are true for this build, and a certification note that states what the
    app does, what it never does (no driver, no trust-store change, no telemetry, no account)
    and how a reviewer can check it for themselves (`priv.log` is written before every
    privileged op).
  - It also writes down the part that only starts after certification: the clean-VM
    measurement — install as a standard user and expect **no UAC prompt** (D-038), install the
    helper with one prompt, verify the hosts/firewall change from outside the app, then update
    the package and watch `helper-status` report `stale` (the engine change from this same
    round is what makes that observable) — and the two refusals worth telling apart, product
    policy versus the package itself.
  - README's docs table and `SIGNING.md` §3 both point at it, so the playbook is reachable from
    the two places a reader arrives from.

- **The engine names a helper registration that points at nothing (2026-11-07, later
  again)**
  - `helper-status --json` gained `bin_path` (the program `sc qc MICSHelper` says the
    service runs) and `stale` (true when that program is not on disk). Both are read from
    Windows, never guessed: parsing is a pure function, `parse_qc`, with a test over the
    two real shapes — the quoted form this project installs
    (`"C:\Program Files\MI CS\mics-engine.exe" helper-service`) and the unquoted one
    (`sc qc Spooler` was the measurement) — and an absent or unreadable answer is `None`,
    because a config query this caller may not read must not become a false "stale".
  - **Why.** A service whose program is gone reports the same `stopped` as a healthy one
    that is merely not started; only the file system tells them apart. Two ordinary routes
    there: the user moved or replaced the MI CS folder, and a package update replacing the
    versioned folder inside `WindowsApps` (D-038). The "installed but not answering" message
    no longer gives that case the integrity advice — it names the path that is gone and the
    fix that works, installing the helper again, which rewrites `binPath` from the folder
    the running copy is in.
  - **Measured** on this machine with the new build: `helper-status --json` with no service
    reports `bin_path: null, stale: false` — the fields exist and do not invent a problem.
    Engine tests **151 passed**, clippy clean with `-D warnings`. **Not observed:** `stale:
    true` itself, which needs an installed helper whose folder then moves.
  - **Left open, written down:** nothing re-registers on its own and the UI shows no
    `stale` badge (`state` is unchanged, so the actionable text arrives when a fix fails);
    the stable-install-location alternative in `docs/SIGNING.md` §3 is still just an
    option.

- **The throwaway certificate stops leaving private keys in the trust stores
  (2026-11-07, later again)**
  - `scripts\codesign-cert.ps1` promises in its own header that only the public half of
    the certificate it mints goes into a store. It was adding the `X509Certificate2` it
    had just signed with, and that object carries its private key, so `X509Store.Add`
    persisted the key association. Measured before the fix: **17 MI CS Code Signing
    entries across `CurrentUser\TrustedPeople` and `CurrentUser\TrustedPublisher`, 16 of
    them `HasPrivateKey = True`** — the exact opposite of what the file promises.
  - Fixed by adding the certificate read back from the exported `.cer`, with a throw if
    that export ever carries a key. Measured after: a fresh run adds its two entries and
    the key-bearing count does **not** move (16 → 16), and a second run reuses the same
    thumbprint and adds nothing at all.
  - **Signing was verified, not assumed.** The self-signed path hands signtool the pfx
    with `/f`, and the `/sha1` path reads the MY store, where a real certificate's key
    lives, so neither depends on what the trust stores hold. The service-free package was
    re-signed with the fixed certificate: signer thumbprint matches, the script's own
    `trusted for install (CurrentUser\TrustedPeople): True`, and `UnknownError` from
    `Get-AuthenticodeSignature` — the documented answer for a correct MSIX signature.
  - The script now says how many earlier certificates are still trusted, because losing
    `%TEMP%\mics-signing` is precisely what makes it mint a new one and nothing else in
    the project notices the pile. Removing them stays a human decision, with the command
    in trap 31; the 16 old entries were left as found.

- **The Store submission stops needing an administrator, and the reason is measured
  (2026-11-07, later again)**
  - **Two shapes, one switch.** `scripts\make-msix.ps1` gained
    `-ServiceMode Packaged|None` (default `Packaged`), and the two shapes get different
    file names — `MICS-0.1.0.0-x64.msix` and `MICS-0.1.0.0-x64-noservice.msix` — so neither
    can silently overwrite the other. `None` removes the `<Extensions>` block and the two
    restricted capabilities from the generated manifest and refuses to continue if any of
    them survives, if `runFullTrust` disappears with them, or if a token is left behind
    (the first version of that guard tripped on the manifest's own header comment, which
    *names* `desktop6:Service` while explaining it — the check now matches elements, not
    text).
  - **The A/B, same machine, same staged folder, minutes apart.** `Packaged` →
    **0x80073D28** ("Administrator privileges required to install packaged service"),
    refused. `None` → **registered with no elevation at all**: `MICS.Desktop 0.1.0.0`,
    `Status Ok`, `IsDevelopmentMode True`, one declared capability (`runFullTrust`), then
    removed cleanly — no package, no `MICSHelper` service, no stage directory left behind.
    So this was never a property of our manifest: it is a property of declaring a service.
  - **What the service-free package is, in numbers:** 75 files, 22.11 MB, 3.7 s,
    `sha256 CF3E1BC4...`, 76 entries inside, `uap10:TrustLevel="mediumIL"` and
    `uap10:RuntimeBehavior="packagedClassicApp"` intact, and exactly one capability.
  - **Decision: D-038** — the first Store submission uses `None`. It supersedes one clause
    of D-037 ("the Store edition needs an administrator to install") while keeping the rest
    of it: any package that declares a service still needs one, and the `Packaged` shape
    stays the full-product shape for a later submission or the direct download. The cost is
    written down rather than discovered later — one UAC prompt before the first fix, and
    "helper absent" becomes the first-run state instead of an edge case.
  - **Two of the three unknowns leave the critical path**: no restricted capability for
    Microsoft to approve, and no administrator needed to install. What remains on route A
    is the free developer account and the product-category question. The container
    questions survive only for the shape we are not submitting first — in `None` the
    privileged writes happen outside any container, and the single cross-container question
    left is whether a packaged app can reach the helper's pipe.
  - **What the service-free shape still owes**, written down now instead of found later: the
    helper's `binPath` is the engine's own path (`install-helper` rewrites it) and a
    package's install folder carries its version, so a Store-edition helper points into a
    folder the next update does not keep — re-registration after an update, or a stable
    install location like the NSIS installer's, is an **open design item** (`docs/SIGNING.md`
    §3), and the UI's helper-status check has to notice a stale `binPath`.
  - **`-AllowUnsigned` is not a way around a missing certificate**: measured **0x80073D2C**,
    "its publisher is not in the unsigned namespace", for both our real subject and a bare
    `CN=MI CS (dev)`. Developer-mode *registration* of the staged folder is the unelevated
    test path that does work, and it is what the A/B used (trap 32).
  - Docs swept in the same commit: `docs/SIGNING.md` §3 (the two-shapes table, the A/B, and
    the qualified unknown list) and §7, `docs/DECISIONS.md` (D-037's clause and D-038),
    `docs/TODO.md` §7 register and trap 30, and the README status block.

- **The free-route search is closed by independent sources, and the container risk is
  answered by Microsoft's own model (2026-11-07)**
  - **"No free CA certificate" is now confirmed from the outside.** Two independent
    surveys read this round — My-SSL's guide (published 2026-07-23, last updated
    2026-10-22) and comparecheapssl.com's (updated 2026) — both state that no public CA
    issues a free code-signing certificate, and both list exactly the routes already in
    `docs/SIGNING.md`. The one programme that looked like a fourth route, **GlobalSign's
    open-source programme, is SSL**: the page is titled *"Free SSL Certificates for Open
    Source Projects"*, its requirements include passing their SSL Checker, and the
    certificate is for a website — not for signing a binary. All four sources are in §8.
  - **A new rule changes what a donated certificate is** (CSBR **v3.11.0**, 2026-06-16,
    §6.3.2 / §6.2.7.4.2, ballots CSC-31 and CSC-32): a publicly trusted code-signing
    certificate issued from 2026-03-01 is valid for at most **460 days**, its
    subscriber key must live in a **hardware crypto module** (since 2023-06-01), and
    from 2026-09-15 it carries exactly one reserved policy OID. So a donation is a
    **~15-month renewable commitment**, and a publicly trusted certificate can no longer
    arrive as a software `.pfx` at all — which makes `MICS_CERT_THUMBPRINT` (a token, a
    cloud agent, or OSSign's keyless service) the path that matters, not the PFX one.
    That is written in `docs/SIGNING.md` §5 as a clarification, not a reversal of D-034.
  - **The container question is now documentation, not guesswork.** Reading
    Microsoft's containerization overview (updated 2026-04-15), the full-trust packaged
    app guide (updated 2026-09-30) and the flexible-virtualization page gave the exact
    model: writes to system locations such as `C:\Windows\` are blocked **for
    AppContainer apps**, while a full-trust package writes them subject to its own
    account's permissions; the write virtualization that remains covers `HKCU` and
    `AppData`; and the escape hatch can only exclude locations *inside* those two. So
    the hosts file (a system-location write by a full-trust LocalSystem service) is
    **not** redirected by the documented model, and the hardening ops' `reg add HKLM`
    is **not** in the virtualized scope either — the classic "silently virtualized
    registry write" trap does not apply to where this product works.
  - **The manifest now says its trust level instead of implying it.**
    `uap10:TrustLevel="mediumIL"` and `uap10:RuntimeBehavior="packagedClassicApp"` were
    added to the Application element, with the `uap10` namespace. Re-packed and verified
    **inside the package**: 75 files, 22.11 MB, 3.9 s, `sha256 5088D937...`, the
    `desktop6:Service` declaration and all three capabilities intact. That also settles
    the argument for the review: this package is deliberately *not* sandboxed, and the
    manifest states the level it runs at.
  - **The remaining test is written down as one elevated step** (§3): install with a
    machine-trusted self-signed certificate, confirm the service as `LocalSystem`/`auto`
    with its binary inside `C:\Program Files\WindowsApps\...`, drive `fw.rules.add`
    (with a name that does **not** start with `MICS-`, because of the double-prefix
    defect in §7) and one `hosts.write` probe line, then read the results **from outside
    the container** — `netsh advfirewall firewall show rule` and the real hosts file —
    because a read-back from inside a virtualized process would prove nothing. A
    hand-rolled pipe client would prove even less: the helper identifies its caller
    (`engine/src/privileged/server.rs`), so the op has to travel the product's own path.
  - **Nothing was installed this round**, so the machine is untouched; `make-msix.ps1`'s
    closing message was corrected — it used to call the container question "not
    answerable locally" and now says what is documented and what one elevated test
    settles.

- **The Store's other prerequisites are written: a privacy policy, and a contact that
  exists (2026-11-07)**
  - **Why now.** D-036 committed the project to the Store listing's prerequisites, and
    the two that are documents rather than clicks were both missing. Store policy
    **10.5.1** requires a privacy policy at a URL for Desktop Bridge and Win32
    products; `SECURITY.md` said "report privately to the maintainers" with **no
    channel**, which nobody outside the repository can use.
  - **`docs/PRIVACY.md` is written from the threat model, not from marketing.** It
    names the four things MI CS never does (no telemetry, no account, no
    reputation upload — there is no VirusTotal client at all, D-019 — and no cloud),
    the complete outbound table, what is stored on the machine and where, the honest
    F-5 limit on `secrets.dat` (machine-scope DPAPI, so any local account can decrypt
    it), the deletion story, and the rule that a new destination changes this file in
    the same commit as the code.
  - **Two corrections came out of writing it, both against my first draft.** The intel
    feeds are **not** opt-in: `engine/src/sync/mod.rs` carries the StevenBlack hosts
    URL and the CISA KEV URL as built-in defaults, and `sync_interval_hours` defaults
    to **6**, so a fresh install does fetch both every six hours — the policy says so
    in the row itself. And the UI has **no settings screen** for those switches
    (grepped: `lib/` contains no feed or NVD string at all), so the draft's "the
    settings screen shows what each switch does" was false and was replaced with where
    the interval and the addresses actually live.
  - **`SECURITY.md` now carries the private advisory link**, what to include in a
    report, what to expect from a single-maintainer project, and the same commitments
    as before plus the audit-log line: every privileged operation is written before it
    runs.
  - **Where it is written down.** The privacy-policy and support-contact rows of
    `docs/SIGNING.md` §3 (which is the Store checklist), and the `docs/` table in the
    README. The public URL to paste into Partner Center is
    <https://github.com/ibraimfarag/MIF/blob/main/docs/PRIVACY.md>.

- **The Store route's artifact exists, and Windows' two install rules are now measured
  rather than guessed (2026-11-07, D-037)**
  - **What was built.** `installer/msix/AppxManifest.xml` (a template whose tokens the
    script must replace, with a hard failure if one survives) and
    `scripts\make-msix.ps1`, which stages `dist\MICS-portable`, generates the four MSIX
    logo assets from `assets\icons\Desktop.png` at the exact sizes the manifest names
    (aspect ratio kept, never stretched), substitutes identity/publisher/version, packs
    with makeappx, and signs with signtool when given an identity — the project's own
    self-signed one for local tests, or a thumbprint for a Store/donated certificate.
    The script refuses a version that is not four numeric parts, refuses a source that
    is not a portable build, and refuses to use the repository, its parent or the source
    as a scratch directory.
  - **Measured, not asserted.** 75 payload files became **22.11 MB** in **3.6 s**
    (pack only) / **4.3 s** (pack + sign): `sha256 FFA869F7...` unsigned and
    `D40AAE90...` signed. The ZIP holds **79 entries**, including `[Content_Types].xml`,
    `AppxBlockMap.xml` and `AppxSignature.p7x`. Unpacking it back proves the manifest
    survived with no token left, `Identity Name="MICS.Desktop"`, the publisher equal to
    the certificate subject, `Version="0.1.0.0"`, x64,
    `TargetDeviceFamily MinVersion="10.0.19044.0"`, the
    `desktop6:Service Name="MICSHelper" StartupType="auto" StartAccount="localSystem"
    Arguments="helper-service"` declaration, all three capabilities, and four logos at
    exactly 150x150, 44x44, 50x50 and 310x150.
  - **Unknown 1's local half is closed.** makeappx 10.0.26100.0 validated and packed a
    manifest that declares a LocalSystem service and the restricted capabilities
    `packagedServices` + `localSystemServices`, with no warning — the declaration is
    legal and buildable. Whether Microsoft *approves* those capabilities for a
    defensive security tool during certification stays open, and nothing here can
    measure it.
  - **Two OS rules, both hit and both reported verbatim.** (a) A signed but self-signed
    package is refused by `Add-AppxPackage` with **0x800B0109** ("the root certificate
    of the signature in the app package or bundle must be trusted"), and adding the test
    certificate to `CurrentUser\Root` does **not** clear it — AppX deployment reads
    machine trust. (b) Registering the **unsigned** staged folder in developer mode
    (`AllowDevelopmentWithoutDevLicense` was already 1, measured) fails with
    **0x80073D28 — "Administrator privileges required to install packaged service"**,
    which is Windows' rule for *any* package that declares a service, not a property of
    our manifest. **The counterpart was measured the next round: the same call against
    the same staged folder, with the service declaration and its two restricted
    capabilities removed, registers with no elevation at all** (`MICS.Desktop 0.1.0.0`,
    `Status Ok`, one declared capability, removed cleanly). That A/B is D-038, and it
    makes the service-free shape the one to submit to the Store first.
  - **What was deliberately not measured.** Whether the packaged service can still write
    the real `hosts` file and drive the Windows Firewall — the container question —
    because that needs a trusted package installed by an administrator. It stays written
    as unmeasured in `docs/SIGNING.md` §3 instead of being assumed either way.
  - **The machine was left as it was found.** No package registered, no `MICSHelper`
    service, the test certificate removed from `CurrentUser\Root` again (its
    `TrustedPeople` entry stays, because `sign.ps1` needs it), both scratch directories
    deleted. Two environment traps came out of it and are now §8 entries 29 and 30: the
    .NET root-store call raises a modal "Security Warning" that `certutil` does not, and
    an MSIX with a service cannot be installed by a non-administrator.
  - **Where it is written down.** `docs/SIGNING.md` §3 (the measurement block and the
    corrected unknowns) and §7, **D-037** ("a third packaging, not a replacement"),
    the **ب5** row in `docs/ROADMAP.md`, and row 3 of §0.6 above.

- **The signature stopped being impossible: two free routes, researched to the source
  (2026-11-07, D-036)**
  - **What was wrong in the previous conclusion.** D-035, earlier the same day, sent the
    certificate to "not purchasable" after asking *which CA will give this project a free
    certificate*. The answer to that is none — and it is the wrong question. The question
    that has an answer is *who else can sign for us, for free*, and two organisations do.
  - **Route A — the Microsoft Store, available today.** Microsoft's own comparison page
    states that publishing an **MSIX** package makes code signing "free and handled for
    you automatically — Microsoft re-signs the package after certification", with cost
    **free**, availability **worldwide** and SmartScreen **"No warnings"**. The developer
    account is free in the new flow: the $19 fee is waived, verification is a government
    ID plus a selfie, and it covers "nearly 200 markets worldwide". What is missing is
    ours, not theirs — an MSIX package — and `docs/SIGNING.md` §3 writes the three
    unverified things *as unverified*: that Microsoft approves the two restricted
    capabilities a LocalSystem service needs (`packagedServices` +
    `localSystemServices`), that a packaged service can still write the real `hosts` file
    and drive the Windows Firewall from inside the container, and that the product
    category passes certification.
  - **Route B — OSSign, from ~2027-04-27.** A certificate issued to the *project*, not to
    a person, signed keyless over OIDC trusted publishing, so the repository stores **no
    secret at all**: a workflow needs only `permissions: id-token: write`. The
    requirements — OSI-approved license, actively developed, public repository — are met;
    the one that is not is a project age of six months, and this repository was created
    2026-10-27. Their applications were suspended as of 2026-09.
  - **The closed routes now have their own words on record.** SignPath Foundation cannot
    sign tools that "actively scan for and highlight exploitable vulnerabilities, e.g. by
    identifying unprotected network ports, missing password protection" — which is what
    the audit screen does — while their signed list (Fibratus, a Windows EDR with a
    kernel driver; sniffnet, a traffic monitor) shows the line they draw is *breach
    detection yes, posture audit no*, not "security is banned". Azure Artifact Signing is
    paid, and its Public Trust geography lists neither Egypt nor any individual outside
    the USA and Canada. The Store's MSI/EXE path still requires a certificate of our own
    that chains to a Microsoft Trusted Root Program CA, and Sigstore means nothing to
    Windows.
  - **Where it is written down.** `docs/SIGNING.md` is the new single place for the
    routes, their sources and dates, and the wording that closes each one. **D-036**
    supersedes D-035's "the warning is permanent" under rule 7 and keeps D-035's core
    rule that nothing is bought; §0.6 row 3 flips from ❌ to ✅ with both routes named;
    the ROADMAP's **ب5** row reopens as free work and **ب6** stops saying the signed half
    "is not coming"; `COST.md`'s "in one line" is corrected where it called the
    certificate "the one purchase"; and the README, its Arabic mirror and the
    troubleshooting row name both routes instead of calling the warning permanent. What
    has **not** changed is today's download: still self-signed, and the release notes
    still say so.
- **The documents were audited against the code, and the acceptance run that needed a
  human ran (2026-11-07)**
  - **The audit.** Every count and claim in `README.md`, `docs/TODO.md`,
    `docs/ROADMAP.md` and `docs/DECISIONS.md` was re-derived from the code and the
    generated reports instead of from the previous document. What was wrong, in the
    order it matters: `LICENSE` was a **5-line placeholder** in a repository that
    advertises GPL-3.0-or-later (now the verbatim text, 35,149 bytes,
    `sha256 3972DC97…`); the JSON-RPC surface is **66** methods, not 65 (one ROADMAP row
    said 62); i18n is **19 module files per language / 270 keys**, not 16/169; the
    README's canary claim was inverted by D-032 (a read **is** a HIGH `canary_read`
    with the volume's atime range probed and reported); the README offered a **draft**
    as a download while the public page says "There aren't any releases here"; idle RAM
    read `~11 MB` against a measured **12.5 MB**, and disk read `~150 MB` against a
    measured **51.9 MB** — the 150 was the engine's RAM *budget* mistaken for a disk
    figure; the test counts were two generations old (110 Dart cases in 24 files, 150
    engine cases in 19 modules, 100 controls over 13 screens); and the register's own
    counts were wrong because two rows closed by evidence still carried an open
    severity cell.
  - **The plan changed, and rule 7 was honoured.** The project is open source with **no
    budget**, which had never been written down, so the one paid item — the
    code-signing certificate — is now **closed as not-purchased** rather than pending
    (the *buying* half of that conclusion stands; the free-routes half is superseded by
    the D-036 entry above) — **D-035** (with an amendment recorded in D-002, whose
    "trusted certificate later" assumption it supersedes). The free substitutes are named
    in D-035: the manifest the
    engine re-hashes at start-up, the published `SHA256SUMS`, a **reproducible build**
    (F-11 — **landed 2026-11-08**, `docs/REPRODUCIBLE.md`) and the CI run record — plus D-034's
    two secrets, so a **donated** certificate is a drop-in with no code change.
  - **The acceptance run (2026-11-07, both UAC clicks provided by the user).** The
    per-machine setup was rebuilt from `main` (`dist\MICS-setup-0.1.0-x64.exe`,
    16,730,142 bytes, `sha256 8984C194…` — the previously documented build had drifted
    six commits behind HEAD) and taken end to end: install in **one** prompt (72 files,
    the per-machine Start-Menu group, the `HKLM\…\Uninstall\MICS` row, and `MICSHelper`
    created **by the installer** with `priv.log` recording
    `install requested` → `service starting (pid=50128) version=0.1.0 pipe=mics_helper`
    → `phase=start version`/`phase=done ok=true` → `install finished, helper
    state=running`); the installed engine started **unelevated** reporting
    `package integrity: 68 listed file(s) match, signed by "MI CS Code Signing"` in the
    honest `untrusted-certificate` state; the LocalSystem helper executing
    `fw.rules.add` in **37 ms** and `fw.rules.remove` in **36–44 ms** with **zero**
    prompts (P1.5 — the product's core promise, now measured against the real service
    rather than `helper-console`); and uninstall in **one** prompt, exit 0, with the
    product, the service (`sc qc` → 1060), the Start-Menu group, the registry row and
    the shortcuts all gone while the user's own `%LOCALAPPDATA%\MI CS` copy was never
    touched. **د3 and P1.5 are closed.** **Deliberately not exercised, and said so in
    both files:** *Default deny outbound* (it would cut this machine's own network path
    mid-run), the SMBv1 toggle and the hosts write — so that slice is still proven only
    by `verify-helper.ps1`'s protocol probe. A second correction from the run: the
    uninstall does **not** leave "nothing" behind — it keeps `%PROGRAMDATA%\MICS`
    (database + audit trail) on purpose, which `mics.nsi` states on screen.
  - **A defect the run found (new MED row in §7).** `add_rule_now` prefixes
    unconditionally (`firewall\mod.rs:239`) while `remove_rule_now` strips an *optional*
    prefix first (`:317`), so a rule added as `MICS-foo` becomes `MICS-MICS-foo`, and
    removing `MICS-foo` then strips to `foo`, finds nothing and **reports success** —
    a silent failure that can leave a **blocking** rule behind. The run hit it and had
    to pass the doubly-prefixed name to clean up. The same machine carries an older
    leftover of that class, `MICS-TEST-BLOCK-EXAMPLE` (outbound block on TEST-NET-3
    `203.0.113.0/24`, no MI CS group or description). Fix: normalize in one place, and a
    harness case for both spellings. **Closed 2026-11-08** (Done log): `owned_rule_name`
    decides the name in one place, `cargo test` is 152 passed / 0 failed, and
    `scripts\verify-firewall.ps1` is 27 checks, 0 skipped, 0 failures — part 3 creates the
    rule under the prefixed spelling, proves Windows has no `MICS-MICS-<rule>` and removes
    it by the unprefixed one.
- **The certificate question got prices, and two of its premises died (2026-11-06, research pass)**
  - **The gap.** `docs\COST.md` named the one purchase and refused to quote a price
    ("they move, they are bundled with a token or a cloud subscription"), which left the
    project's only HIGH row as "buy a certificate" with no route, no figure, and no way to
    tell whether the free open-source programme even applied. Two of its premises were
    also wrong: that EV is the shortest path to SmartScreen trust, and that
    `CN=MI CS Code Signing` is a string a CA can be asked for.
  - **What the research found (everything read 2026-11-06; sources and dates are in the
    file).** Microsoft's own comparison gives public trust to organizations in the
    USA/Canada/EU/UK and to **individuals in the USA and Canada only**, so Azure Artifact
    Signing is not purchasable from Egypt at all — its `/dlib` integration is closed as
    "not our route" rather than left as planned work. **EV stopped buying a SmartScreen
    bypass in 2024**, so the $400+/year premium is off the table. CA/B ballot CSC-31
    (adopted 2025-11-17) capped a code-signing certificate at **460 days** from
    2026-03-01. And CSCBR §9.2.2 requires `subject:commonName` to be the **verified legal
    name**, so no CA can issue `CN=MI CS Code Signing` — measured consequence:
    `update.rs:128` would refuse our own signed release and `signature.rs:184` would
    report it as a foreign signer.
  - **The routes that exist for an individual with no company, priced.** **Certum Open
    Source €49/year** (their own shop; the CN becomes "Open Source Developer <name>",
    individual-only, non-commercial, 459-day cap, ≤5,000 signatures/month; Egypt is in
    their checkout country list, their shipping table delivers hardware there, and
    Egyptian passports are in IDnow's supported-document list) — but their cloud signs
    only while a logged-in SimplySign desktop session holds the virtual card, and Certum
    publishes no headless agent, so it wants a persistent runner. **SSL.com IV $129/year
    + eSigner $180/year**, whose own GitHub action signs on GitHub-hosted runners, i.e.
    inside the workflow this repository already has. Standard OV $99–300/year; Certum's
    own OV for an individual is €209/year.
  - **The free route is closed, not merely awkward.** SignPath Foundation's code of
    conduct excludes *"security diagnosis tools that actively scan for and highlight
    exploitable vulnerabilities, e.g. by identifying unprotected network ports, missing
    password protection etc."* — the audit half of this product — with a carve-out only
    for malware and breach **detection**; and it independently requires an already
    released project with a verifiable reputation, which a repository created 2026-10-27
    with 0 releases does not have. Their published certificate reads
    `CN=SignPath Foundation, O=SignPath Foundation, ...`, so even acceptance would print
    their name and not ours. Reframing the product to slip past that policy is not on the
    table.
  - **What changed in the repo.** `docs\COST.md` §2 carries the dated table, the two
    retracted premises and the CI question that actually decides the purchase; §4 now says
    what buying does *not* do (SmartScreen warnings fade with downloads, not on day one);
    `docs\OPEN-DECISIONS.md` item 3 records that moving the pin is part of buying the
    certificate rather than a follow-up; and the register's HIGH row, the LOW pin row, the
    ب5 row and `docs\ROADMAP.md` §4 item 2 all carry the figures.
  - **Method note.** None of this is from memory: the searches went through the Exa MCP
    endpoint (the deployed `web_search` has no API key), vendor pages were read live,
    `shop.certum.eu` product pages and SSL.com's WordPress REST API supplied the prices,
    the CA/B Forum published the ballot, and a project SignPath actually signed was
    downloaded and its Authenticode subject read off the binary.
  - **Not verified, and written as such.** Whether Certum accepts an Egyptian order
    end to end (the evidence is positive; no order was placed); whether their €49 cloud
    product can be driven unattended at all (a third-party tool exists and is
    unsupported); SSL.com's "High Risk Region" clause; and the one behind all of them —
    **no certificate has been bought, so every signature path in this repository is still
    unproven against a real CA certificate.**

- **The certificate is two secrets now, and a release discovers its own signing identity (2026-11-06, D-034)**
  - **The gap.** `make-release.ps1 -Sign` had two ways to sign - `-PfxPath`, or the
    self-signed throwaway - and the `Release` workflow's own comment told whoever bought the
    certificate to add two repository secrets **and then edit the build step** to pass them.
    A credential wired that way cannot be tested until it is bought, and a typo in it would
    have cost a ten-minute build before the run said anything at all.
  - **What landed.** `scripts\sign.ps1` takes exactly one identity and refuses zero or two:
    `-SelfSigned`, `-PfxPath` + `-PfxPassword`, or `-Thumbprint <sha1>` - the last is what a
    hardware token or a cloud signing agent needs, because the key never leaves the device.
    The two production modes accept only a signature Windows calls `Valid`.
    `scripts\make-release.ps1 -Sign` resolves the identity once, **before the build**:
    `-Thumbprint`, then `-PfxPath`, then `MICS_CERT_THUMBPRINT`, then `MICS_PFX_B64` +
    `MICS_PFX_PASSWORD`, then `MICS_PFX_PATH` + `MICS_PFX_PASSWORD`, and only then the
    self-signed certificate - printing which one it chose. The workflow already passes
    `secrets.MICS_PFX` and `secrets.MICS_PFX_PASSWORD` through on both legs, and an unset
    secret expands to the empty string, so today's runs behave exactly as before.
  - **Measured.** `scripts\verify-signing.ps1` - **18 checks, PASS** (`RESULT: PASS - 18
    check(s)`, exit 0): the guard refuses no identity, two identities and an unknown
    thumbprint *before* signtool is invoked; a certificate imported from
    `%TEMP%\mics-signing\codesign.pfx` signs a real PE and the signature carries that
    certificate's SHA-1 (`99FAFE73...`); the run then refuses to call it verified and exits
    1; `-PfxPath` still signs (regression); and the imported certificate is gone from
    `CurrentUser\My` afterwards. With `MICS_PFX_B64` and its password set, a release run
    prints `signing identity: the CA certificate in MICS_PFX_B64` before it builds
    anything; with the password missing it stops there with `RESULT: FAIL - MICS_PFX_B64 is
    set without MICS_PFX_PASSWORD` (exit 1, measured).
  - **Written limit, not a silent pass.** The throwaway certificate is trusted in
    `TrustedPeople`, not `Root`, so both production modes end in "did not verify" on this
    machine - that refusal is the design, and `Valid` is what a CA-issued certificate
    produces. The positive half therefore stays **unproven until the certificate exists**,
    and the probe prints that sentence instead of passing quietly.
  - **Measured end to end too.** A full `make-release.ps1 -Sign` run with `MICS_PFX_B64`
    and its password set printed the identity line before the build, signed all seven
    binaries with that certificate, then failed every one of them (`UnknownError`):
    `RESULT: FAIL - 7 file(s) did not verify; SmartScreen will still warn` →
    `RESULT: FAIL - signing failed; nothing was published`, exit 1. The PFX decoded out of
    the environment was gone afterwards (0 `mics-sign-*.pfx` left in TEMP) and `dist\` was
    untouched, so "nothing was published" is literally true. A self-signed PFX dropped into
    `MICS_PFX` therefore cannot ship - which is exactly what that variable is for.
  - **Side finding.** `signtool /du` pointed at `github.com/mourad-ibrahim/mi-cs`, a
    repository that is not this one. Nothing reads that field, which is exactly why it
    survived; it now names `github.com/ibraimfarag/MIF`.

- **The shipped rules are held to files now, and the first one that could never fire is fixed (2026-11-05, D-033)**
  - **The gap.** `verify-release.ps1` proved that a package's `rules\` is the one the
    engine loads — a statement about packaging. Nothing ever asked a rule to *match*
    anything, and the bill arrived the moment one was asked: the shipped
    `Malicious_Macro_AutoOpen` tested `uint16(0) == 0x504B`. YARA reads `uint16`
    little-endian, so that constant is the bytes `K`,`P` in file order, while a
    zip/OOXML container starts `P`,`K` and reads `0x4B50`. **The rule could not fire on
    any `.docm` that has ever existed**, and a gate that counts loaded rules cannot
    notice a rule that loads perfectly.
  - **Measured before and after.** A file whose first two bytes are `KP` plus
    `AutoOpen`/`Shell` *was* caught (`yara:Malicious_Macro_AutoOpen`) while a real
    container built with `Compress-Archive` (`50 4B 03 04`) was not; after the fix the
    `KP` file is silent and a `PK`-shaped file with the same strings is caught.
    Re-measured through a real engine on an isolated data directory, the pack now holds
    **8 of its 10 rules to a file**: `Suspicious_HTA_Exec`,
    `Suspicious_BAT_Certutil_Download`, `Suspicious_Cmd_PowerShell_Download`,
    `Suspicious_VBS_Dropper`, `Malicious_Macro_AutoOpen`, `Double_Extension_Emailer`,
    `Ransom_Note_Names`, `Suspicious_Scheduled_Task_Creator` — with the 2 it cannot
    reach named and reasoned (`EICAR_Test_File`: the string is what Defender
    quarantines; `Tiny_Packed_Pe_Installer`: needs a binary PE).
  - **What holds it now.** `engine\testdata\detection` carries one vector per rule plus
    a clean control; `scanner::yara_engine::tests` runs the table in the fast tier (4
    cases, 0.25 s) and `scripts\verify-rules.ps1` runs the same table through the
    shipped engine and the packaged pack (**35 checks, PASS**), while
    `verify-release.ps1` now calls the probe with `-InPlace` so a release proves its own
    `rules\` *detects* rather than merely loads. The probe fails by construction when it
    should, both measured at exit 1: the inverted constant loses `pk-macro.txt`, and a
    rule nobody has a vector for fails on its own name. The pack's SHA-256 is printed
    with the verdict, because which bytes were measured is part of the measurement.
  - **The honest remainder.** The fix removes the impossibility, not the weakness. A real
    `.docm` deflates its macro strings, and the probe measured that `AutoOpen`,
    `CreateObject` and `Shell` are **absent** from such a file's bytes — so the rule
    still cannot see a real document, and catching one needs an OOXML/OLE parser.
    That is decision (b), and it has numbers behind it now instead of adjectives.
  - **Two side measurements.** A detection probe must not spam the desktop: with the
    staged data directory's `{"dnd": true}` the scan logged 0 `alert shown` lines where
    the same scan without it logged 7. And 9 vectors cost 6 s, so this runs anywhere.

- **A decoy read is an event now, and the coverage behind it is measured (2026-11-05, D-032)**
  - **What changed.** `guard/canary.rs`'s snapshot carries the decoy's last-access
    time beside its mtime and size, and the whole detection rule is one pure function
    (`classify`) with six test cases: identical state → nothing, atime-only → **Read**,
    size/mtime/deleted → **Written**, and a volume that keeps no atime → never invents
    a read. A read emits HIGH `canary_read` under its own rule id (`CANARY_READ`) so a
    user can quiet reads without losing the write that means the decoy was
    overwritten; a write keeps CRITICAL `canary_triggered`/`CANARY` unchanged. Both
    flow to the alert card (one producer), the incident correlator (its own title) and
    the sound router (a warning cue, not the critical one).
  - **The settle window, and why it is not a cover-up.** The first program to open a
    brand-new file on Windows is usually Defender or the indexer, so a decoy MI CS has
    just written is left quiet for 90 s (`READ_SETTLE`) — and the log says `canary
    settling` when that happens, so "nobody read it" and "somebody read it and we
    chose not to shout" stay different answers. A decoy that was already on disk gets
    no window. `canary.configure`/`canary.deploy` now **re-arm** rather than only
    deploy, which is what keeps that distinction true for a decoy added at runtime —
    and fixed a latent false alarm on the same lines: a newly configured path used to
    reach the watcher with no baseline and be reported as *modified*.
  - **The honesty half.** `read_detection()` measures whether the decoys' volume keeps
    a last-access time (write a scratch file, read it back, compare), `guard.status`
    and the new `canary.status` carry `{available, probed_on, detail}`, and the
    Canaries screen prints the verdict — including the `fsutil behavior set
    disablelastaccess 0` that turns it on — instead of implying coverage. **The probe
    caught a real defect here**: the verdict was cached per process rather than per
    folder, so after `canary.configure` moved the decoys it still named the previous
    folder's volume; where the decoys live on another disk that is a wrong answer, not
    a stale one. It re-measures when the folder changes now, and the probe asserts
    `probed_on` is the decoys' own folder.
  - **Measured, not asserted.** `scripts\verify-canary.ps1` — **20 checks, PASS** —
    runs a real engine on a private pipe with a private `USERPROFILE` (so the default
    decoy paths can never touch the real Documents folder) and measures: a decoy MI CS
    had just written is settled and the log says so, a pre-existing decoy opened
    read-only raises `canary_read`/HIGH with its size and **SHA-256 unchanged**, one
    appended byte raises `canary_triggered`/critical, fifty metadata queries in a row
    move no atime and raise nothing, and the engine's verdict equals the same
    measurement taken independently in PowerShell. The probe's own readiness check also
    learned something worth keeping: `Test-Path \\.\pipe\x` *opens a connection*, so
    asking it twice in a row races the server's accept loop and the second answer is a
    false negative — readiness is a real `ping` now.
  - **Machine figures** (`fsutil behavior query disablelastaccess` = `2, System
    Managed, Last Access Time Updates ENABLED`): four reads in a row moved the atime
    (0.4–1.3 s lag), a read from a *different* process moved it, fifty metadata queries
    in a row moved nothing. Engine tests 146 (was 140; six new), the QA surface moved
    **65 → 66 methods** with `qa/report.md` regenerated, and the register row closed.

- **The CI logs arrived: both failures diagnosed, one of them was the product (2026-11-05)**
  - **The engine refused its own client, and that is a real install scenario (D-030).**
    `engine.test` failed three cases on the runner (job log: `test result: FAILED. 136
    passed; 3 failed`), and the interesting one is
    `tests::tests::privileged_requests_are_audited_and_refused_when_malformed`, which
    panicked with the engine's own words - `ping answers: this pipe only serves the
    account MI CS was installed for`. The cause is a Windows policy, not a wrong
    comparison: on a **server-class** Windows a directory an administrator creates is
    owned by **`BUILTIN\Administrators`**, not by the account. Measured on the runner:
    the directory the test created was owned by `S-1-5-32-544` while the process's own
    token user was `S-1-5-21-3077485881-3661871218-4154919024-500`. So MI CS would have
    refused the person who installed it on any Windows Server (and on any workstation
    whose "default owner for objects created by members of the Administrators group"
    policy names the group). Fixed in `engine\src\platform\windows\caller.rs`: a record
    that names that group is satisfied by a caller whose token carries it
    (`CheckTokenMembership`, asked of the SID - never guessed from a name), while an
    account record still demands that account. **140 engine cases pass here, 0 failed**
    (was 139 - one new case), including four new/rewritten assertions: the group record
    allowed for a member, refused for the same account without the group, a user record
    never satisfied by an administrator token, and the pipe DACL test tolerating the
    `LA` alias Windows prints for the built-in Administrator
    (`D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)` - the same grant written the other way,
    which is what `the_engine_pipe_grants_only_the_owner_system_and_administrators`
    actually hit). F-2 in `docs\THREAT-MODEL.md` carries the amendment: a standard user
    is still refused by both tests, and an administrator could take the directory over
    anyway, so nothing was widened.
  - **The one Dart failure was the Flutter version, and the pin proved it (D-029).**
    `scripts\pipeline.ps1:301` fails fast on the first failing step, so the pre-pin runs
    stopped at `flutter.test` (**"135 tests passed, 1 failed."**) after ~4 minutes,
    while run **41926473473** (the pinned `4e04757`) failed at `engine.test` **327.1 s**
    into a 9-minute job - the Dart suite was no longer where it failed. The second
    reading is package:test's GitHub reporter: it emits its `N tests passed, M failed`
    annotation only when the Dart suite fails, and that run had none, where both earlier
    runs did. Neither reading is the log line, and both say the same thing.
  - **The `Package (x64)` failure is the same class of problem, and the pin should close
    it - unverified.** The step died at
    `RESULT: FAIL - sbom.cdx.json or THIRD-PARTY-NOTICES is stale; run 'dart run
    tool\sbom.dart' and commit both`, and the reason is visible in that log's own
    environment: `FLUTTER_ROOT: ...\stable-3.47.9-x64\flutter`. `tool\sbom.dart` reads
    `dart pub deps --json` for **the SDK versions** (its header says so: the lockfile
    does not carry them), so the committed pair describes 3.47.8 and the runner was
    building with 3.47.9. With `flutter-version: 3.47.8` pinned it should match - and
    that is a prediction, not a result: the next `Release` run is what settles it.
  - **The CI now names its own failure.** Job logs need a signed-in browser (the public
    API answers 403 on `actions/jobs/{id}/logs`), which is why every diagnosis above
    cost a round trip with the user. The `Pipeline (full)` step tees its output to
    `build/pipeline-log.txt` and, on failure, prints the last matching lines as
    `::error::` annotations - the same public surface the Dart reporter already used.
    Verified locally with the exact snippet: `-Tier fast` through `Tee-Object` still
    returns **exit 0** on PASS and the log holds all 388 lines.
  - **The instrumented run then named the last fact, and it was a filtered token.** With
    the failure emitting its own log tail, run **41938235816** printed
    `facts: installer=Some("S-1-5-32-544") caller=Ok((Some("S-1-5-21-...-500"), false))`:
    the record was the Administrators group (as measured), and
    `CheckTokenMembership` still answered **false** because the runner's token is
    **UAC-filtered** - the group is there as deny-only, which that API does not report.
    The check now reads `TokenGroups` and matches the SID whether enabled or deny-only
    (D-030 carries both measurements), and the count went **3 failures -> 1 -> 0** as each
    assumption was replaced by a measurement: 139/1, then the same run with two of the
    three assertions fixed, then the group list.
  - **The runner is green where it counts, and the last failure is a missing component.**
    Run **41940095160** (on `d17122d`) printed `test result: ok. 140 passed; 0 failed`
    and `PASS (362.0s)` for `engine.test` - **all three original engine failures are
    gone**, D-030's group-list check is what the runner needed. The same run also shows
    `flutter.analyze` and `flutter.test` passing (the pipeline failed at step **4/8**), so
    the Flutter pin holds too. What is left is my own rust pin being incomplete: a *named*
    toolchain arrives without the components the hosted image has for its stable, so
    `cargo-clippy.exe is not installed for the toolchain 1.99.1-x86_64-pc-windows-msvc`
    failed `engine.clippy` in **1.2 s**. `Setup Rust` now asks for
    `components: clippy`. Steps 5-8 of the full tier (`engine.build`, `engine.smoke`,
    `engine.contract`, `app.build`) have still never run on that runner.
  - **The last failure was my own harness, not the engine.** With the emit naming cases,
    run **41947091678** (on `6475568`) reported `FAIL  scan job finished state=queued`
    and, downstream of it, `FAIL  a finished job is not cancellable`. `qa/contract.dart`
    waited for the scan job with `if (state != 'running') break;` - and **`queued` is not
    `running`**, so the first poll before a worker picked the job up was read as
    "finished". On this machine the job is already `done` by the first poll, which is why
    79 cases pass here; on the runner the poll landed in the queued window. The loop now
    waits for the terminal states (`done`/`failed`/`cancelled`) with the same 120 s
    deadline. Re-measured locally against the release engine: `79 case(s), 0 failed, 14
    method(s) classified not-to-run`, `PASS  scan job finished state=done`, `PASS  a
    finished job is not cancellable`.
  - **Where the pipeline now stands on the runner** (run 41947091678): steps 1-3 pass
    (`flutter.analyze`, `flutter.test`, `engine.test` - 140 passed), 4 passes
    (`engine.clippy`, once the component is asked for), **5 and 6 ran for the first time
    and passed** (`engine.build`, `engine.smoke`), 7 (`engine.contract`) is the harness
    bug above, and **8 (`app.build`) has still never run there**.
  - **The Release run failed in all three packaging jobs; the CI is green (2026-11-05).**
    Run **41951427102** (on `6fee0ce`) is the first **green CI**: all 8 full-tier steps,
    including `app.build`, which had never run on a runner before.
    `workflow_dispatch` run **41963395561** then showed the release side: `Resolve the
    version and tag` PASS, and three failures - `Package (x64)` step 7
    ("Build, sign, hash and zip"), `Package (arm64)` step 6 and the informational
    `ARM64 engine, run natively` step 6 ("The result has to be a hardened ARM64 PE").
    `Publish` was **skipped**, which is the dependency doing its job. **x64 is green on
    this machine, end to end** - `make-release.ps1 -Sign -Arch x64 -Version 0.1.0`
    printed `RESULT: PASS` with the SBOM check passing (579 components) and 41 checks /
    0 failures / 154.6 s - so the runner's x64 failure is environmental and the log has
    to name it. Because the Release workflow had no self-annotating step, three steps
    now tee their output and call `scripts/annotate-failure.ps1` (extracted from the CI
    step, one owner for the format), and the release is created as a **draft** (D-031) so
    verifying a run costs a tag and publishes nothing.
  - **All three Release failures are named, and two are fixed (2026-11-05).** The
    self-annotating steps paid for themselves on the first run (tag `v0.1.0` on
    `1a6d871`, run **41966869643**):
  - **ARM64 prerequisites, measured for the first time in full.** `Package (arm64)`
    printed `RESULT: NOT READY - 2 of 7 prerequisite(s) missing: Windows SDK arm64 libs,
    Flutter windows-arm64 engine`, with the five that *are* there named (rust target
    `aarch64-pc-windows-msvc`, MSVC ARM64 `cl.exe`, MSVC ARM64 CRT libs, LLVM
    `clang.exe` for ring's assembly, and an ARM64 host). That is ب2's answer in one
    line: the runner is wired for ARM64, and the two things Flutter's Windows tooling
    does not ship are exactly what is missing. The job stays informational.
  - **The ARM64 engine check was looking for a file nobody built.** `verify-hardening.ps1
    -Arch arm64` reported `no mics_app.exe or mics-engine.exe under
    engine/target/release`: `cargo test --release` builds a test harness under
    `target/release/deps`, not the bin. The job now runs `cargo build --release` before
    the check.
  - **x64 is still the SBOM, and now it says which line.** The runner printed the same
    `sbom.cdx.json or THIRD-PARTY-NOTICES is stale` message as the first run, so the
    Flutter pin was *not* the whole story: `tool/sbom.dart --check` printed whether it
    was stale and nothing else. It now prints the first differing line of each file
    (`<label> differs at line N`, committed vs generated), and
    `scripts/annotate-failure.ps1` picks that up, so the next run names the component
    instead of the file. Locally the same check passes on a tree with no
    `.dart_tool/package_config.json` (dart regenerates it), so the difference is
    something the runner's SDK reports.
  - **The release is a draft (D-031).** It made this verification possible: a tag push
    re-runs everything and publishes nothing.
- **The x64 packaging failure was never a stale inventory (2026-11-05).** Run
    **41974398428** (tag on `0c86ac7`) finally carried the check's own output, and it
    said: `cargo metadata failed (101)` / `error: no matching package named aes-gcm
    found` / `note: offline mode (via --offline)`. `tool/sbom.dart` reads the crate graph
    and deliberately keeps it offline; on a developer machine the crates are already in
    `~/.cargo/registry`, and on a fresh runner **nothing has fetched them yet** - the
    release workflow's first cargo-touching step was the inventory check itself. So the
    check died (exit 2) and three releases reported it as files that needed
    regenerating. Both packaging jobs now run `cargo fetch --locked` before it (which the
    build would have done anyway), the check's failure is a separate message from
    "stale", and the raw tail is printed. Same run: the ARM64 engine leg is **green**
    (`cargo build --release` before the verifier was the whole difference), and
    `Package (arm64)` still reports its measured `2 of 7` prerequisites.
- **`make-release.ps1` could not cut a release from a clean checkout (2026-11-05).** With
    the inventory check fixed, run **41976679343** moved one step deeper and stopped at
    `RESULT: FAIL - no engine build found for x64; run 'cargo build --release' in engine\`.
    The script insisted on an existing engine binary *before* the step that builds it
    (`cargo build --release`, then "prefer the binary we just built over whatever the
    earlier lookup found") - so the one place it had to work, a runner that has just
    fetched the crates and built nothing, was the one place it refused. It now treats a
    missing build as something to produce, keeps the refusal for `-SkipBuild` and for an
    `-EnginePath` that does not exist, and says so when cargo succeeds but no
    `mics-engine.exe` is where it expected.
  - **Measured on the fix**: `CARGO_TARGET_DIR` pointed at an **empty** directory, so the
    lookup had nothing to find and the script had to build everything itself -
    `make-release.ps1 -Sign -Arch x64 -Version 0.1.0` ended in `RESULT: PASS` (68 files
    hashed against the signed manifest, tamper checks included). That is the same shape as
    the release runner, and it is the first time this path was measured from nothing.
  - **The runner's x64 release now gets further than it ever has**: `sbom: up to date (579
    components)` with `RESULT: PASS` for the inventory, which is what the Flutter pin plus
    `cargo fetch --locked` bought. The ARM64 engine leg is green; `Package (arm64)` still
    reports its measured `2 of 7`.
  - **The README now says where the release is (2026-11-05, ب6's publishing half).** A
    `## Download` section sits under the status block: `v0.1.0` on the Releases page, the two
    artefacts and what each one is, `SHA256SUMS` + `report.md`, a `Get-FileHash` check to run
    before anything is executed, and the honest note that Windows will say "Unknown
    publisher" because the build has no publicly trusted certificate yet (ب5) - the app's own
    manifest check is what is available. The Arabic overview got the same line, and
    `docs/ROADMAP.md`'s ب6 row now records the measured state: tag `v0.1.0` on `da77bb3`,
    run **42040718389** green end to end, and the release created as a **draft** that is
    still a draft at this commit - publishing it is the one click D-031 reserved for you.
- **The first release is built, verified and sitting as a draft (2026-11-05, run
    **42040718389** on `da77bb3`).** Every job that has to pass passed: `Resolve the
    version and tag`, **`Package (x64)`** (probe, build, signing, manifest, NSIS installer,
    `verify-release.ps1 -Arch x64 -SkipToast`, artifact upload, QA report) and **`Publish`**,
    whose notice reads `draft v0.1.0 created - publish it from the Releases page when the
    hashes read right`. `Package (arm64, informational)` is still a failure by design -
    measured `NOT READY - 2 of 7 prerequisite(s) missing: Windows SDK arm64 libs, Flutter
    windows-arm64 engine` - and `continue-on-error` keeps it from failing the run. Nothing
    is public until the publish button is pressed (D-031).
  - **Four things stood between the first run and this one, each one measured.** (1) The
    root-store dialog (next entry). (2) The tamper test demanding `ok` from a self-signed
    build that correctly reports `untrusted-certificate`. (3) `verify-release.ps1` failing
    on `verify-helper.ps1` while filtering the reason out of its own output - on failure it
    prints the helper's whole answer now, and `annotate-failure.ps1` recognises `[FAIL]`
    and `  - ` markers. (4) That reason: **a runner's token is elevated** - the helper's own
    `version` answer said `{"elevated":true}` (run 42036237342) - so accepting
    `hardening.run` is the correct behaviour there, and `verify-helper.ps1` skips that one
    refusal when the token says elevated, printing
    `[SKIP] hardening.run unelevated - this token is elevated ...` and naming it in the
    summary instead of changing SMBv1 on a machine nobody asked it to harden. Unelevated
    (this machine: `{"elevated":false}`) the refusal is still required and still checked.
  - **Measured while fixing, not assumed**: `verify-release.ps1 -Arch x64 -SkipToast` PASS
    locally twice (17 s, and again after the helper change); `annotate-failure.ps1` naming a
    synthetic helper failure case for case; `-Tier fast` green at 55.9-66.5 s; and the
    signing probe PASS on the runner in seconds, twice.
- **The x64 release got all the way to its last check (2026-11-05, run 42022830468).** The
    signing probe passed on the runner for the first time (step 8, seconds), the build,
    signing, manifest injection, NSIS installer and the download verification all
    succeeded, and the run stopped at `verify-tamper.ps1`: **39 of 41 checks passed**, and
    the two that did not were the same expectation written twice -
    `control: the app says ok` and `a copy of the published bytes: the app says ok`. The
    engine was right and the probe was wrong: `D-025` has **three** answers, and a build
    signed with our certificate on a machine that has not trusted its root reports
    `untrusted-certificate` (every listed file hashes as published; only the chain is
    missing) - which is exactly a release runner, where `scripts/codesign-cert.ps1`
    deliberately never writes the root store. Measured from the code that decides it:
    `trust()` returns `Trust::UntrustedRoot` when the signature verifies and the embedded
    CN is `EXPECTED_SIGNER_CN` = `MI CS Code Signing`, and the new certificate's CN is that
    string. `verify-tamper.ps1` now accepts `ok` **or** `untrusted-certificate` for those
    two checks and still fails on `unverified`, which is what tampering, a repack or
    another signer report (`integrity=unverified ... data\app.so: changed` still passes as
    a *detection*, and still fails as a control).
  - **The probe's own failure was PowerShell, not signing** (run 42021515566). The probe
    step failed in seconds with nothing to say because `$code = Invoke-SigningProbe`
    captured every `Write-Output` the function produced - the log held only the
    certificate script's `Write-Host` lines, and `exit $code` received an array of
    strings. Its messages go to the host now, the function returns a number, and anything
    that throws is printed as `RESULT: FAIL - <type>: <message>`. Measured here after the
    fix: **RESULT: PASS in 5 s**, signing a copy of `mics-engine.exe`, `signtool:
    UnknownError - CN=MI CS Code Signing`.
  - **`sign.ps1` on the whole package, with the new certificate:** 8 binaries signed and
    verified in **7 s**, every one `UnknownError` with our signer, `RESULT: PASS`.
- **The hang was a certificate dialog, and it was never the build (2026-11-05).** Run
    **42010747061** finished the engine in **13m 08s**, passed the hardening check
    (`0xC160`, `CF_INSTRUMENTED`) and the opsec table (9 binaries, `mics-engine.exe` at
    1243 `cargo` markers = the baseline, none of this machine's account) - and then stopped
    at `Creating self-signed code-signing certificate...` until the 50-minute cap. The
    same line stopped run 41980725064 for three hours before that. It is not the
    certificate API: it is **adding a certificate authority to `CurrentUser\Root`**, which
    Windows answers with a confirmation dialog nobody can click on a runner. Reproduced
    here in seconds - `certutil -user -addstore Root` printed
    `Root "Trusted Root Certification Authorities"`, then sat until killed, and
    `X509Store.Add` on Root did exactly the same. The earlier runs only passed because the
    then-current certificate was already in Root, so the add was a no-op.
  - **What signing does now.** `scripts/codesign-cert.ps1` builds the certificate in
    memory, keeps it as a PFX in the job's TEMP (signing key never in a store), and trusts
    the public half only in `TrustedPeople` + `TrustedPublisher` - the two stores that take
    an entry without asking. `sign.ps1` signs with `signtool /f`, and because a self-signed
    signature cannot reach `Valid` without its root trusted, the check accepts
    `UnknownError` **with our own signer certificate**: that status means the chain is not
    publicly trusted, not that the file was touched (tampering reports
    `HashMismatch`/`NotSigned`). A real certificate still has to be `Valid`.
  - **`scripts/signing-probe.ps1` runs before the build** (5-minute cap, added to
    `package-x64`): create the certificate, trust it, sign a copy of a real PE, verify the
    signer. Measured here: **4 s**, `RESULT: PASS`, `signtool: UnknownError - CN=MI CS Code
    Signing`. That is the step that would have saved both runs.
  - **The throwaway key is deleted** at the end of `make-release.ps1`; nothing after it
    needs it.
  - **What this says about the workflow.** Every "green locally, red in CI" here has been
    the *environment*, not the code: an unpinned channel, a server-class default-owner
    policy, an SDDL alias. That is why D-029 pins the toolchains and D-030 documents the
    policy instead of skipping the test on such machines.

- **First CI run on the public repository: what failed, and what was fixed (2026-11-04)**
  - **The run itself is on the record.** `Release` run **41922523593** (`main` =
    `5eb956a`) and `CI` run **41922021833** on the same commit. `Release`:
    `Resolve the version and tag` PASS, **`Package (x64)` FAIL** at step 6
    ("Build, sign, hash and zip", i.e. `make-release.ps1 -Sign -Arch x64`),
    **`Package (arm64)` FAIL** at step 2 ("Setup Flutter"),
    `ARM64 engine, run natively` running, `Publish` **skipped** - which is the
    dependency working as intended: nothing was published from a run that failed.
    `CI`: `pipeline` FAIL inside `Pipeline (full)`, annotated
    **"135 tests passed, 1 failed."**
  - **That annotation is a Dart count, not a Rust one.** `flutter test` here runs
    **136** cases (measured: `+136 All tests passed`), so 135 + 1 is that suite; the
    Rust harness prints `test result: FAILED. N passed; M failed` with semicolons,
    so it is not the engine's. Which test fails on the runner is **not known yet**:
    job logs need authentication (the public API answers **403**) and the HTML page
    is a shell, so the text has to come from the user's browser.
  - **The environment is not the difference I could reproduce here.** The suite
    passes locally in a **fresh `--depth 1` clone** of the published commit (no
    tags, no `dist/`, no build outputs - 0 tags, 1 commit) and passes again with the
    runner's own conditions forced (`CI=true`, `GITHUB_ACTIONS=true`,
    `USERNAME=runneradmin`, `USERPROFILE=C:\Users\runneradmin`, `TZ=UTC`,
    `LANG=en_US.UTF-8`). So it is either something only that image has or a flaky
    timing test - the log decides.
  - **`Package (x64)` is green on this machine, end to end**: re-ran the exact step
    (`make-release.ps1 -Sign -Arch x64 -Version 0.1.0`) and read it to the end -
    hardening PASS, opsec PASS, signing PASS (`Valid - CN=MI CS Code Signing,
    O=Mourad Ibrahim (MI CS)`), manifest 68 files, tamper PASS, `RESULT: PASS`. So
    the runner's failure is one of that script's own gates behaving differently
    there, and again the log names which.
  - **The ARM64 failure is diagnosed and fixed.** `Setup Flutter` failed because
    Flutter publishes **no Windows ARM64 SDK**: **0** of the **747** archives in
    `releases_windows.json` mention arm64, and the action says so itself -
    `Unable to determine Flutter version for channel: stable version: any
    architecture: arm64` (job 126898444291). `.github/workflows/release.yml` now
    asks that runner for the **x64** SDK (Windows runs it under emulation) and for
    `targets: aarch64-pc-windows-msvc`, which `make-release.ps1 -Arch arm64` checks
    for before it packages - a prerequisite the job never satisfied. Both ARM64
    jobs stay `continue-on-error` and informational: a green packaging run would be
    the first real ARM64 app (the host-derived target in
    `commands\build_windows.dart` plus `verify-hardening.ps1 -Arch arm64` refusing an
    x64 package is what makes that claim checkable), and a red one means Flutter's
    Windows tooling cannot produce it yet. The engine half needs no such
    qualification - it runs natively on that runner.
  - **The workflow is still only YAML-verified where it matters.** The ARM64 job's
    step list was re-read after the edit (7 steps, `Install NSIS` and
    `Build, sign, hash and zip` restored - the first edit had dropped them) and both
    workflows were parsed with PyYAML: `ci` = 1 job / 6 steps, `release` = 5 jobs
    (`version`, `package-x64` 10 steps, `engine-arm64` 5, `package-arm64` 7,
    `publish` 6).
  - **One measured difference between the two machines is now closed (D-029).** The
    runner installed **Flutter 3.47.9** (newest stable, published 2026-10-29) while
    this machine verifies with **3.47.8** (framework `737ba8f885`) - the workflow
    asked for `channel: stable` and no version, so it followed the channel. Every
    job now pins `flutter-version: 3.47.8` and `toolchain: 1.99.1` (the local rustc),
    and D-029 records that moving either is a decision with its own measurement. That
    is a candidate cause for the one Dart failure (two of the cases measure what
    Material paints), not a proven one: the run's log still has to name the test.

- **The history was rewritten so the repository can go public (2026-11-04)**
  - **Why.** The user wanted the work to stay in one place, so the repository itself
    is the one going public - which means its own history had to stop carrying two
    things: a **34,000,312-byte** `mics-engine.exe` from *before* the ط1 fingerprint
    sweep (committed under `dist/MICS-v1.0.0-windows-portable/`, and `git log -S`
    finds the machine account name **inside the binary**), and the account name in
    **13** textual places across old revisions.
  - **Safety first.** `git bundle create MIF-prepublic-backup.bundle --all` (29.3 MB,
    written one directory above the repository) and `git bundle verify` said "The
    bundle records a complete history". It is now the only copy of the pre-rewrite
    history: filter-repo repacks and prunes the old objects when it finishes.
  - **The rewrite.** `git filter-repo --path dist --invert-paths --replace-text
    <expressions>` (git-filter-repo a40bce5), where the one expression maps the
    machine's account name to `<account>`. A stale
    `.git/filter-repo/already_ran` from **2026-10-27** made the first attempt stop at
    an interactive prompt (`EOFError` in a non-interactive shell, before touching
    anything - HEAD and tree were verified unchanged afterwards), so the marker was
    removed and the run repeated. Took 6.9 s.
  - **Verified, not assumed.** 147 → **145** commits (two commits held nothing but
    `dist/` and were pruned); `git log --all --name-only -- dist/` returns nothing;
    a history-wide search for the account name returns nothing; HEAD's tree is
    **byte-identical** (`2c0b83a9c3986f7000c02cc497a6d8739f78b01e` before and after,
    267 tracked files, clean working tree); the author/committer identity is
    unchanged on purpose (the user chose to keep `ib.farag@gmail.com`, which never
    appeared in file content, only in commit metadata); `.git` went from **106.4 MB**
    to **7.1 MB**. filter-repo removed the `origin` remote as designed, so it is
    re-added before the force-push.
  - **What is not provable from here, and is written down instead**: GitHub can keep
    the unreachable old objects in internal storage for a while (a support request
    can force their removal), and every other clone of this repository still holds
    the old history and must be re-cloned rather than pulled.
  - **A second pass, because the first commit after the rewrite put the string back.**
    The Done-log entry spelled the account name out twice - inside the filter-repo
    expression and inside the search command that proves it is gone - and the commit
    message carried it too. Found by running the search *after* committing. Fixed in
    two steps: the entry now describes the mechanism without quoting the string, and
    a second filter-repo pass (`--replace-text` + `--replace-message`) took it out of
    the two commit messages and the one revision that still had it. Verified
    afterwards across every revision, not just HEAD: no blob in any of the 147
    commits and no commit message contains it. Then the branch was force-pushed again
    (remote main = `1ae33a4`, matching local), the upstream was restored -
    filter-repo drops the `origin` remote on every run - and the local `reflog` and
    unreachable objects were pruned, leaving the bundle as the only copy of the
    pre-rewrite history.

- **The README's ARM64 claim matches the corrected one (2026-11-04)**
  - The public face said "an ARM64 download needs an ARM64 build host; until then an
    ARM64 package does not exist (D-003 appendix)" in the status note and in the
    Requirements row, which was true but stopped being the whole truth once the
    release workflow gained the two `windows-11-arm` jobs. Both now name GitHub's
    ARM64 runner as that host, say the workflow builds and tests ARM64 there, and
    keep the honest part - the jobs are **informational until they have a green
    run** - so nothing in the public repo promises a download that does not exist.
    No Arabic mirror: the README's Arabic section never mentioned ARM64.

- **One version number: 0.1.0 (2026-11-04)**
  - `pubspec.yaml` said `1.0.0+1` while `engine/Cargo.toml` said `0.1.0` and every
    shipped artefact was named `0.1.0`, so `mics_app.exe`'s own version resource
    disagreed with the installer carrying it. Decided by the user: **0.1.0 wins**
    (it is what the downloads are called and what `mics-engine --version` reports),
    so `pubspec.yaml` → `0.1.0+1` (`windows/runner/Runner.rc` keeps Flutter's
    template fallbacks `1,0,0,0`, which only apply to a raw MSBuild build with no
    `FLUTTER_VERSION*` macros - the Flutter build overrides them from pubspec).
  - The inventory is regenerated at that version rather than edited by hand:
    `dart run tool\sbom.dart --version 0.1.0` rewrote `sbom.cdx.json` and
    `THIRD-PARTY-NOTICES`. Measured diff: 4 lines - the app component moves from
    `pkg:generic/mi-cs@1.0.0` to `0.1.0`, the CycloneDX serial number is derived from
    it, and the notices header follows. `dart run tool\sbom.dart --check` PASS
    (exit 0) against the tree, which is the same check `make-release.ps1` runs before
    it ships either file.

- **Pre-public preparation, and a release workflow that has never run (2026-11-04,
  commit 8a54e69 and this one)**
  - **A claim this project made was wrong, and it is corrected rather than
    quietly dropped.** D-003 said GitHub's ARM64 Windows runners were public-repo
    only and that a `windows-11-arm` job "would queue forever". The runner
    reference lists `windows-11-arm` for **private** repositories too (2 vCPU /
    8 GB, drawing on included minutes) and for public ones (4 vCPU / 16 GB, free
    and unlimited), and `flutter build windows` derives `windows-arm64` from the
    host (`commands\build_windows.dart`), so an ARM64 runner can build the app as
    well as the engine. D-003, the ب2 row and this file now say "no ARM64 job has
    been written or run yet" instead. What CI still cannot do is reproduce P1.5's
    human half: a Windows runner is an administrator with UAC disabled, so it
    proves the operations and the audit pairs, never "one prompt, then silence".
  - **The account name is out of the published tree and now out of the history**: 4
    hits at HEAD → 0, with the measured facts (two administrators, one of them the
    user) unchanged, and the rewrite that followed took it out of every old revision
    together with the 34,000,312-byte pre-ط1 engine binary (§0.2a item 2).
  - **`make-installer.ps1` is arch-aware** (`-Arch x64|arm64`, D-003): it names the
    output `MICS-setup-<version>-<arch>.exe`, passes `MICS_ARCH` to NSIS, checks
    the package's own binaries with `verify-hardening.ps1 -Arch` **before** wrapping
    it, and the installer refuses the wrong machine at `.onInit` (silent mode gets
    exit code 2 instead of a dialog). Measured: the x64 installer rebuilt green
    (`MICS-setup-0.1.0-x64.exe`, 15.9 MB, sha256
    `F18B47ED1B19C403E3990BDC970348DD6A199F45C58E504E565F1DDC1133966A`), and
    `-Arch arm64` against that same package **fails on purpose** with
    "`mics_app.exe`: built for x64 (0x8664) but this package is arm64" — the
    mistake this whole change exists to prevent.
  - **`.github/workflows/release.yml` is written and validated as YAML, and has
    never been executed** (no push from here; `gh` is not installed). Five jobs:
    resolve the version and refuse a tag that disagrees with `engine/Cargo.toml`,
    package x64 on `windows-latest` (`make-release.ps1 -Sign` → `make-installer.ps1
    -Arch x64` → `verify-release.ps1 -Arch x64 -SkipToast`), two informational
    ARM64 jobs on `windows-11-arm` (the engine's tests **run** there natively, plus
    a packaging attempt), and publish to GitHub Releases with `gh release create`
    and `contents: write`. The ARM64 jobs are `continue-on-error` and gate nothing
    until they have a green run; the notes it publishes say the builds are not
    signed by a publicly trusted publisher, because that is ب5 and no workflow
    change can fix it.
  - **Found while writing the version gate**: `pubspec.yaml` says **1.0.0+1** and
    `engine/Cargo.toml` says **0.1.0**, and the artifacts that ship are named
    0.1.0 — so the app's own version resource and the installer's disagree. The
    workflow warns instead of failing (it must not block a release on an unrelated
    fix), but one number has to win; that is a decision in §0.2.

- **ب2 (f) — the ARM64 leg: the engine builds and is checked, the app cannot be
  built here, and nothing was run**
  - **What built.** `scripts\build-engine-arm64.ps1` (new) compiles the engine for
    `aarch64-pc-windows-msvc` and then reads the PE back, because "cargo finished"
    and "the file is an ARM64 image" are different claims. Measured on this
    56-logical-processor x64 machine, with the release flags (`-C
    control-flow-guard=yes` + the path remap, so the build account does not appear
    in the binary): `cargo build --release --target aarch64-pc-windows-msvc`
    finished in **11m 41s** and produced an engine of **19,994,112 bytes**
    (`sha256 639ed862…`), `machine arm64 (0xAA64)`, `DllCharacteristics 0xC160`
    (HIGH_ENTROPY_VA|DYNAMICBASE|NXCOMPAT|GUARD_CF), `GuardFlags 0x00017500`
    (CF_INSTRUMENTED|CF_FUNCTION_TABLE_PRESENT|CF_LONGJUMP_TABLE_PRESENT), no PDB
    path — and `verify-hardening.ps1 -Arch arm64` returns **RESULT: PASS**. With
    `-WithTests`, `cargo test --release --no-run --target aarch64-pc-windows-msvc`
    also **compiles and links the test binaries** (`Finished release profile in
    15m 20s`, `Executable unittests src\main.rs`,
    `mics_engine-968c89ed026ea79a.exe`, **25,749,504 bytes**) — the whole tree
    type-checks and links for ARM64, and not one of those executables was run.
  - **The three toolchain pieces this machine has in odd places**, all measured
    rather than assumed: the **MSVC ARM64 build tools** are *not* in the 2022 Build
    Tools (`VC\Tools\MSVC\14.44.35207\bin\Hostx64` holds only x64 and x86, and its
    `lib` has no arm64) but *are* in Visual Studio 18 Community
    (`…\18\Community\VC\Tools\MSVC\14.50.35717\bin\Hostx64\arm64\cl.exe`); the
    **C compiler** for `ring`'s assembly is not clang-from-VS (that component ships
    only `clang-format`/`clang-tidy`) and not on PATH, so the build uses the LLVM
    inside the **Android NDK** (`clang 19.0.1`, AArch64 backend, `llvm-lib.exe`) as
    a *build-time* tool — no LLVM code is in the output; and the **Windows SDK
    10.0.26100.0** already carries `um\arm64` and `ucrt\arm64`. The first attempt
    failed exactly where the row predicted it would, and the failure is the finding:
    `error: failed to run custom build command for ring v0.17.14` →
    `failed to find tool "clang"`.
  - **What cannot be built here, with the measurement.** The Flutter half has no
    Windows ARM64 path on this machine: `flutter build windows --help` offers no
    `--target-platform` for Windows, and the SDK's cache holds
    `windows-x64`, `windows-x64-profile`, `windows-x64-release` and **no**
    `windows-arm64` — so an ARM64 app needs an ARM64 host and its own SDK download.
    `make-release.ps1 -CheckToolchain` prints the seven prerequisites and says
    **NOT READY (2 of 7)**: MSVC ARM64 tools ✔, ARM64 CRT ✔, SDK arm64 libs ✔, Rust
    target ✔, clang ✔ (the NDK one), Flutter windows-arm64 ✘, ARM64 host ✘ (this
    host is AMD64). So a portable ARM64 *package* is still not producible here,
    while its engine is — that is the exact boundary, written in the script's own
    output and in D-003's addendum.
  - **What was made arch-aware, so an ARM64 package is verified as one.**
    `verify-hardening.ps1` gained `-Arch auto|x64|arm64`: it reads the PE `Machine`
    of every judged binary, lets the first one decide under `auto`, fails a package
    that mixes arches, and requires `CF_LONGJUMP_TABLE_PRESENT` only on x64 (it is
    an x64 construct in the linker's terms; the ARM64 build happens to carry it
    too). `verify-release.ps1` derives the arch from the zip's name **and** the
    `VERSION` line inside it and refuses a mismatch, then hands `-Arch` to the
    hardening gate. `make-release.ps1` gained `-Arch`, the `--target` build, the
    per-arch Flutter folder, `-<arch>.zip`, `PORTABLE, <arch>` in `VERSION`, and
    `-CheckToolchain`. `engine-rustflags.ps1` now selects the rustflags **by target
    triple** (and refuses when there is no section, instead of silently building
    without CFG), and `engine/.cargo/config.toml` gained the
    `[target.aarch64-pc-windows-msvc]` section with the same
    `-C control-flow-guard=yes`.
  - **No ARM64 hardware, so: nothing was run.** Not the engine, not the tests, not
    the app; no timing, no memory figure and no behaviour is claimed for ARM64, and
    nothing measured on x64 was copied over. The claim is exactly "compiled and
    linked for `aarch64-pc-windows-msvc`, and the artifact is a hardened ARM64 PE".
  - **CI, and why there is no ARM64 job in it yet (corrected 2026-11-04).** D-003
    commits the project to "adding an ARM64 build leg to CI when ARM64 hardware or
    runners are available". Measured at the time: `https://api.github.com/repos/
    ibraimfarag/MIF` answers **404**, i.e. the repository is private, and this entry
    then concluded the ARM64 runners were public-repo only. **That conclusion was
    wrong**: GitHub's runner reference lists `windows-11-arm` for private
    repositories too (2 vCPU/8 GB, drawing on the account's included minutes) and
    for public ones (4 vCPU/16 GB, free and unlimited), and `flutter build windows`
    picks `windows-arm64` from the host, so an ARM64 runner can build the app as
    well as the engine. The honest status is therefore: **no ARM64 job has been
    written or run yet** - it is planned work in `docs/TODO.md` §0.1, and the leg
    lives in `build-engine-arm64.ps1` until a workflow calls it. What CI cannot do
    is reproduce P1.5's human half: a Windows runner is an administrator with UAC
    disabled, so it proves the operations and the audit pairs, never "one prompt,
    then silence". The SBOM stays arch-independent on purpose: it
    describes the dependency set, which is the same for both legs, and the artifact
    itself (`-<arch>.zip`, `VERSION`, PE machine) is what names the arch.
  - Measured: `-Tier fast` green; the ARM64 numbers above come from the two cargo
    runs and from `verify-hardening.ps1`'s own output.

- **و4 (e) — the three rows that close by evidence: the incomplete package, the
  portable caller check and the AUMID attribution**
  - **The incomplete-package HIGH row, closed with a refusal.** The row said a
    hand-copied package can lose `rules\` and silently fall back to the
    compiled-in starter pack. A package was built for the test with `rules\`
    removed **and its own `SHA256SUMS` corrected**, so nothing but the missing
    folder could fail, and `verify-release.ps1` returned **exit 1** with four
    FAILs: `missing from the zip: rules\yara\starter.yar,
    rules\guard\starter.json`, `rules folder holds 0 file(s)` (the layout check,
    not just the names), `the guard did not use the packaged rules: guard:
    6 rule(s) from the built-in starter pack (rules/guard not found)` and
    `the scan did not use the packaged YARA rules (log line: YARA rules from the
    built-in starter pack (no rules\yara\starter.yar found))`. A degraded copy
    cannot pass the gate, and the engine names the source it used.
  - **The portable caller check, closed by making the claim measurable.**
    `verify-helper.ps1` now starts the helper in the portable layout F-2 describes
    — an empty `PROGRAMDATA` plus a separate `MICS_DATA_DIR`, so no install account
    exists — and measures both halves: a client that is not the engine image is
    refused (`this pipe only serves the MI CS engine`) and the helper's log carries
    `no installer account recorded`, then the same probe is served once the
    documented `MICS_ENGINE_PATH` pin names it. The first version of the check
    reused one helper process and the "pinned client" expectation failed, because
    the helper reads that pin from its own environment at startup — two helper
    processes, and the behavior is now visible instead of assumed. `RESULT: PASS`,
    exit 0, **15 checks** (was 13). The probe also reads the helper's stderr with
    `FileShare.ReadWrite`, because a plain read of a file a live process holds
    fails.
  - **The AUMID row, closed as a documented limit rather than a defect.**
    `verify-aumid.ps1` passes: `DisplayName` is `MI CS`, its `IconUri` names a file
    that exists, both shortcuts carry `System.AppUserModel.ID = MICS`, and the
    Shell files `MI CS` under AppID `MICS` — which is what the AUMID was for. The
    row's substance is not fixable in the app, and
    `docs/THREAT-MODEL.md` §B10 already states it in one sentence: Windows lets any
    same-token process raise a card under that AUMID, so **a card is UI, not
    proof** (the record is the engine's DB and `priv.log`, and a forged card cannot
    make the engine act). F-2's row in the same file now carries the measured
    fallback next to its text.
  - Measured: `verify-helper.ps1` PASS / exit 0 / 15 checks; `verify-aumid.ps1`
    PASS / exit 0 / 5 checks; `verify-release.ps1 -DistDir <incomplete> -SkipToast`
    FAIL / **exit 1** with the four FAILs above. `-Tier fast` green.

- **و4 (d) — the guard's idle cost re-measured with the shipped pack, and the
  register's number replaced**
  - **The stale claim.** The register carried "0.156 % of one core with one inert
    rule in force; with the shipped starter pack the earlier runs measured
    0.234 % — the difference is one-time startup matching". Both halves were
    unverified in the configuration the product ships.
  - **What was run.** `scripts\measure-guard-cpu.ps1 -RealRules` — the probe that
    exists for this — four times, 60 s per mode each, on this 56-logical-processor
    machine, with the release engine copied out of `%TEMP%` (the starter pack's
    GR-002 kills a script host whose command line contains `\temp\`, so the probe
    would have killed its own measuring shell). The engine was unelevated, and its
    own log proves what loaded and what ran: `guard: 6 rule(s) from the built-in
    starter pack (rules/guard not found)` and
    `ETW unavailable ... falling back to poll loop` — so the number is the 2 s poll
    loop with the shipped rules, not the ETW path.
  - **The measured numbers.** Guard-on minus `MICS_NO_GUARD=1`:
    **0.156 / 0.521 / 0.339 / 0.495 % of one core (median 0.417 %)** =
    **0.0028 / 0.0093 / 0.0060 / 0.0088 % of the machine (median 0.0074 %)**. The
    guard-off half measured 0.000 % in all four windows — below the 15.6 ms process
    timer resolution, i.e. < 0.03 % of one core. The `< 1 %` budget holds by a wide
    margin under both readings.
  - **What the measurement refuted, and it is written down as refuted.** The spread
    is run-to-run noise on a busy machine, not a rule-count effect: the **lowest
    shipped-pack window equals the inert-rule figure exactly (0.156 %)**, so
    "the difference is one-time startup matching" was a story about two numbers that
    are the same number. The register row, `PROTECTION-MATRIX.md` §8,
    `THREAT-MODEL.md` §7 and the README's budget claim all carry the range, the
    median and the configuration instead of one clean-looking figure.
  - Measured: `-Tier fast` green; the probe's own output (four result tables) is the
    evidence, and no code changed in this row.

- **و4 (c) — a merged audit now says how old every section it did not re-read is**
  - **The gap.** A fix re-reads one section on top of the last full audit, which is
    what keeps the score comparable — but the report then looked uniformly fresh to
    the user, including the seven sections that were hours old. The register said
    the UI never shows that age.
  - **What moved.** Each audit section carries the unix time it finished
    (`AuditPass::stamps`, filled by `collect_audit`), `report()` emits
    `section_times: {id: seconds}`, and `AuditCache::merge` keeps the base's stamp
    for every section it did not re-read while taking the re-read's own time for
    the ones it did. A section whose collector failed on the re-read loses its
    stamp — it is not reported as run, so it must not look fresh either. Every
    finding also carries its **section id** now, because the display name is not
    unique (`rdp` and `remote_tools` both read "Remote Access") and the age is
    resolved through the id.
  - **The UI says it, in both languages.** The audit screen prints
    "Not re-checked now — read at HH:MM" (`audit.sectionAge`, Arabic mirrored) on
    every finding and on the two inventory headers whose section this report did
    not re-read, formatted through `TimeOfDay.format` so it follows the locale.
    Nothing appears on a full audit, or on the section the fix just re-read.
  - **Proved.** Engine: 139 tests, including a merge whose base section is stamped
    at a fixed old time (so "it moved" cannot be a same-second coincidence), the
    refreshed section's stamp proven newer, the untouched one proven unchanged,
    every finding proven to carry a known section id, and the failing-collector
    case proven to drop its stamp. Dart: 106 declared cases, with a widget test
    that mounts the screen on a merged report and finds **3** stale lines (the
    untouched finding plus the two inventory headers) and a time in each, and the
    QA audit fixture rewritten to the new shape so the sweep renders it.
  - Measured: `-Tier fast` green, `flutter analyze` clean, QA report regenerated
    (65 methods, 100 controls, 106 Dart / 139 engine cases) with the ledger
    unchanged — the line is text, not a new control.

- **و4 (b) — one scanning path: the blocking `vuln.scan` is gone, and the command
  bar stops pinning a request for minutes**
  - **What the register got wrong, found by checking first.** The row said the
    blocking variant was "kept for probes and scripts", so the slice allowed
    deleting it. Nothing in the UI called it — but the natural-language command
    bar did: the `vuln_scan` intent (`ثغرات`/`vulnerab`/`cve`) dispatched
    `vuln.scan`, and `nl.command` executes the sub-request **inline**, so asking
    the bar for a vulnerability scan held the pipe for one NVD lookup plus the
    rate-limit pause per application (the P3e sweep measured the same shape at
    minutes) with no progress event and no way to cancel.
  - **What moved.** The intent points at `vuln.scan.start`, which returns a
    `job_id` at once and reports through `progress`/`job_finished` — the same job
    the Vulnerability screen starts. With the last caller re-pointed, the
    blocking method was deleted along with `VulnScanner::scan` (the only thing
    that used it), its `qa/methods.json` row and its registry entry. There is
    exactly one scanning path now: the durable, cancellable job.
  - **Proved by the ratchet that already exists**: `test/qa_registry_test.dart`
    compares the registry with the dispatcher's match table, so the deleted arm
    and the deleted row fail the fast tier if only one of them moves; the QA
    report regenerated to **65 methods** (was 66 after و1), and the release engine
    rebuilt clean with `cargo build --release`.
  - Measured: `-Tier fast` green, QA report regenerated (65 methods, 100 controls),
    no contract case lost (the row was a classified skip, never a run).

- **و4 (a) — the two API keys leave `settings.json` and get DPAPI, with a migration**
  - **What moved.** `nvd_api_key` and `ioc_feed_key` were the only credentials in
    the settings document, which is the one file every backup, every shared folder
    and every pasted log snippet carries. They now live in
    `<data dir>\secrets.dat`: a four-byte `MS1\0` header plus
    `CryptProtectData` (machine scope) of a tiny JSON document — the same
    primitive the quarantine master key already uses. `settings.json` holds
    neither field, and the write order is deliberate: secrets first, document
    second, both atomic, so a crash between them cannot lose a credential.
  - **The migration is one-way and idempotent.** A file an older build wrote is
    read, the plaintext keys are moved into the protected store and the document
    is rewritten without them, once; a second start finds nothing to move. A
    plaintext value never overwrites a protected one (that path drops the stale
    copy instead), and a *failed* rewrite leaves the plaintext in place so the next
    start retries rather than losing the key — which is exactly the bug the first
    version of the test caught.
  - **`settings.get` still returns the values**: the UI prefills the two inputs and
    it is the same interactive user, so this commit changes what is at rest, not
    the RPC contract. The environment hooks (`NVD_API_KEY`,
    `MICS_IOC_FEED_KEY`) still win, as everywhere else.
  - **Proved by five tests** (`engine/src/secrets.rs`): the protected file is not
    what went in (both values absent from both files, and a damaged blob refuses
    to decode), a written document reads back both keys, a legacy plaintext file
    is migrated, cleaned and re-read as the same answer, a protected value survives
    a stale plaintext one, and a foreign file is treated as "no keys" instead of
    being decrypted. **Honest limit**: machine-scope DPAPI binds the blob to the
    computer, not the user, so another local account can still ask Windows to
    decrypt it (`THREAT-MODEL.md` F-5) — what it removes is the plaintext copy.
  - Measured: `-Tier fast` green in 156.1 s, engine tests 133 → **138** (5 new),
    QA report regenerated (17 modules, 138 declared engine cases).

- **و3 — the firewall speaks Windows' own API instead of parsing `netsh` (D-028)**
  - **What moved.** `engine\src\firewall\mod.rs` went from shelling out to
    `netsh advfirewall` (a 20 s deadline on a child process, and every read parsed
    out of English console text) to `INetFwPolicy2` / `INetFwRules` / `INetFwRule`
    in-process, through the `windows` crate the engine already depended on — two
    features added (`Win32_System_Ole`, `Win32_System_Variant`), no new dependency.
    The public shape is unchanged (`set_default_deny_now`, `add_rule_now`,
    `remove_rule_now`, `list_rules`, `block_country`), so the helper's op set, its
    audit trail and its refusals are untouched: an elevated process calls the API
    directly, an unelevated one still goes through the helper (D-007).
  - **What is genuinely better, not just newer.** Values are typed, so the words are
    ours: `Any` is now a deliberate normalisation of `""`/`*`, and
    `In`/`Out`/`Allow`/`Block` come from the enums. Every rule sets an explicit
    all-profiles mask (`NET_FW_PROFILE2_ALL`) because the API's default is *no*
    profile — a rule that exists and never fires — and a group ("MI CS") so our
    rules appear as one block in the Windows UI, which `netsh` never did. A rule
    that names a port without a protocol is refused with a sentence that says what
    to add, at both boundaries: the helper payload's `validate()` and the API path.
  - **The two traps, both measured the hard way.** (1) *Field order in the guard
    struct is load-bearing*: Rust drops fields in declaration order, and releasing a
    policy interface after `CoUninitialize` on that thread is an access violation —
    `0xc0000005` in the drop, on **every** `fw.rules.list`, which is what the first
    live run did. The interface is now declared before the apartment guard. (2) The
    rule enumerator hands out `VT_DISPATCH` variants, not `VT_UNKNOWN` (measured:
    `vt = 9`), so `as_rule` converts through `IDispatch` and keeps the `IUnknown`
    path as a fallback; the first version asked for `IUnknown` and got
    `TYPE_E_TYPEMISMATCH` for every rule.
  - **Proved by the new probe.** `scripts\verify-firewall.ps1` — 23 checks, 0
    skipped, 0 failures, 8.7 s against the shipped release engine: a fake `netsh.exe` first on
    PATH (with a control check that a direct `netsh` stops working under it, so the
    trap is proved to be a trap), the policy and the rule list compared field by
    field with `Get-NetFirewallProfile` and `Get-NetFirewallRule -PolicyStore
    ActiveStore`, one rule created through the engine and read back from Windows with
    the exact direction, action, port, program, profile and group, then removed and
    asked for again (gone, and a second removal is a no-op). It cleans up after a
    failed run and never touches a profile policy.
  - **What it deliberately does not claim.** The default-deny *write* is not
    exercised: flipping a machine's outbound policy — even for a second — would cut
    the network of whatever else is running, so the probe reads it and compares it
    with Windows instead. And a country-sized `RemoteAddresses` string has no
    documented ceiling and was not measured (the probe has privilege through the
    helper but will not spend it on a guess): `block_country` still sends one rule
    per country, and the register says so.
  - **Measured.** 133 engine tests green (the `netsh`-dump parser test is replaced by
    two API tests: the word/number translation, and the port-without-protocol
    refusal), `cargo clippy --release -- -D warnings` clean, the full fast tier green.
    The trap that took the longest was not the API: it was that `target\debug\
    mics-engine.exe` is a *different artifact* from what `cargo test` builds, so the
    first "still crashing" run was measuring a stale binary.

- **و1 — the engine runs a scan by itself, and Settings has the switch: opt-in,
  report-only, and it needs nobody watching (D-027)** *(two commits: the engine half
  and the control below)*
  - **What moved.** `scan_interval_hours` (0 = off, and 0 is the default) and
    `scan_target` (empty = the current user's profile folder) joined the settings,
    validated like the rest: 0 or 1..168 hours, and an absolute path or empty. The
    engine starts a timer in both long-lived modes (`--serve` and `--service`, so a
    closed window does not stop it) that looks at the clock every five minutes, and
    when the interval has passed since the last start it calls the same `start_scan`
    the UI calls — with `quarantine: false`, because nobody chose a file while it was
    running: findings are recorded, alerted and left in place for the user to act on.
  - **The engine remembers what it did, in the state database rather than in
    `settings.json`**: a new `meta` table (`scan.last_scheduled`) answers "when did I
    last start one", so an engine restart does not scan again, a fresh install scans
    at the first tick instead of waiting a whole interval, and a clock that moved
    backwards counts as due instead of never running again. `scan.schedule` exposes
    the whole picture (enabled, interval, target, last start, next due) for the UI and
    for the QA harness, and `MICS_NO_SCAN_SCHEDULE=1` is the test hook.
  - **Proved, not assumed.** `is_due` is a pure function with unit tests (off, never
    ran, exactly the interval, one second short, and a future timestamp), the settings
    validation has its own, and `scripts\verify-scan-schedule.ps1` drives a real
    release engine over its own pipe and an isolated data directory: with the schedule
    off nothing starts and the answer says so; with an interval and a configured
    folder the first tick starts a scan by itself, the job's root is that folder, it
    examines the planted file and records the finding as `yara:Ransom_Note_Names`; and
    the file is **still there** afterwards. 18 checks, 0 failures, 11.6 s, no
    elevation. The fixture is a ransom-note-shaped text file rather than an EICAR
    sample on purpose: the first version of the probe planted EICAR, Defender
    quarantined it mid-scan, the engine recorded a skip and the probe was measuring
    the wrong program.
  - **The control, and the harness fix it forced.** Settings → Protection gained the
    switch (off / 6 / 12 / 24 / 72 / 168 hours) and the folder field, with Arabic and
    English copy in the same commit (`settings.scanHours`, `…Hint`, `settings.scanOff`,
    `settings.scanTarget`, `…Hint`), the typed `AppSettings` view carries
    `scan_interval_hours`/`scan_target` in both directions, and
    `test/ui_screens_test.dart` proves the pick reaches the engine
    (`{'scan_interval_hours': 24}`), that the dropdown keeps the value it stored, and
    that the folder field is on screen. Adding the section exposed a real hole in the
    UI sweep: it collected every *mounted* control but tapped the ones below the fold
    where they were, so the tap missed silently — and the two buttons inside a
    collapsed report row dropped out of the ledger while the sweep still passed. The
    harness now brings a control into view before tapping it (`ensureVisible`, ignored
    when the tree cannot scroll to it) and pages one viewport at a time through a
    lazily built list until it stops moving, so the ledger covers a long screen instead
    of its first page. Ledger 98 → 100 controls, and the diff is two pure additions.
  - **Measured.** 104 declared Dart cases (23 files) with the new behaviour test, the
    report regenerated (66 methods, 100 controls), `flutter analyze` clean, and the
    fast tier green in 62 s. Engine: 6 unit tests on `is_due`, 2 on the settings, the
    new registry row, and the probe above.
  - **What is still missing, and said plainly:** real-time watching (the other half of
    the register's MED row) is untouched — a schedule is a moment, not a monitor, and
    the README and `docs/PROTECTION-MATRIX.md` §2 now say exactly that.

- **ب4 — the installer owns the helper's whole life, so the product asks for UAC once
  (D-026), and a silent install can no longer hang on a dialog**
  - **What moved.** D-022 kept the installer out of the service on purpose: the
    product asked once to install itself, then again at the first fix that needs
    administrator rights. The per-machine section now runs the shipped engine's own
    `install-helper` under the elevation the installer already holds — the *same*
    command the app's button runs, so the service definition (quoted binPath, the
    `helper-service` argument, description, start type) still lives only in
    `engine\src\privileged\service.rs` — and reports a failure instead of aborting:
    an install that cannot create the service still gives a working app that asks
    once, later, exactly like a portable copy.
  - **The other half, because install and uninstall must be symmetric.**
    `check-helper-ownership.ps1` gained `-Remove`: it deletes only after proving the
    service's `binPath` points at `$INSTDIR`, it stops and deletes only the service
    named by the `-ServiceKey` it read (so a probe aimed at a synthetic key cannot
    touch the real `MICSHelper`), it needs elevation, and if the SCM does not drop
    the key it answers `OWNED` again. The uninstaller calls it when the checker first
    says `OWNED`, proceeds on `0`, and still refuses with error level 5 when the
    removal cannot happen — naming `Settings → Engine → Remove helper` as the manual
    way out. Whatever the installer created it takes away; whatever it did not, it
    leaves alone. Portable copies are untouched: nothing creates the service for
    them, so D-007's one-prompt path through the app is still how they get one.
  - **The defect the run turned up.** The refusal dialog was not silent-mode aware, so
    `uninstall.exe /S _?=$INSTDIR` — the form the verifier uses, and the only one that
    reports an error level at all — sat on a MessageBox forever and the documented
    exit code 5 never arrived. Measured twice: 532 s until the dialog was killed, and
    the *pre-change* build compiled from `HEAD` behaved identically, so this was not
    new: the "refuses with 5" claim had never been true without a human clicking OK.
    Both MessageBoxes are now `${IfNot} ${Silent}` (the error level is the answer a
    scripted caller asked for), and the assertion is real.
  - **Measured.** Both variants compile (per-machine and `-TestUser`), and
    `scripts\verify-installer.ps1` passes end to end in **141 s** — install, AUMID on
    both shortcuts, the checker's three answers, a clean uninstall, and the refusal
    with exit 5 which now arrives without a click. The one thing left for a human is
    the per-machine run itself: compiling `RequestExecutionLevel admin` and boxing a
    real `sc create` is not something an agent here can do.
  - `installer\mics.nsi`, `scripts\check-helper-ownership.ps1`,
    `scripts\verify-installer.ps1` (its header and part 4), `docs\DECISIONS.md`
    (D-026), `docs\PRIVILEGED-OPS.md`, `README.md` (install, uninstall, requirements,
    status — both halves), `docs\TODO.md`, `docs\ROADMAP.md`.

- **ج3 — the README now says what MI CS does and does not do, and every number in it
  was measured**
  - The file already had that shape; what made this a rewrite is that half of it had
    stopped being true. The status box still said packaging and the helper were "in
    progress" (both are built and verified), and the *does not do* list claimed
    **"there is still no integrity manifest, so a repackaged copy cannot be told from
    ours"** — which ج2 and ط2 made false. Recomposed around the pair it is named for:
    - the *does* table gained a row, **"Is this copy the published one?"**: the **68**
      files, the document carried **inside the engine's own signature**, the three
      verdicts (`ok` / `untrusted-certificate` / `unverified`), the About line, the
      card, and the release gate that refuses a changed folder.
    - the *does not* list replaced that stale bullet with the honest limit: the
      manifest makes a changed copy **visible, not impossible** — a rebuild signed
      with somebody else's certificate is reported as `unverified`, and the app cannot
      refuse to run because it is the thing running — and there is still no
      **reproducible build**, so a stranger cannot re-derive our bytes from this
      source (F-11's open half). The other limits stayed as they were: no kernel
      driver, no ClamAV/CAPA/Suricata, polling canaries, no VirusTotal, and the update
      pin is the signer's **name**, not its thumbprint.
    - **Install and first run** ends with the check a user can actually make: read the
      integrity line in Settings → About, and the same check headless with
      `verify-manifest.ps1 -Path <folder>` (which refuses the folder and names the
      file). **Troubleshooting** gained a row per verdict — `unverified` names the
      file, says to re-extract and compare with `SHA256SUMS`, and explains why a
      development build shows it; `untrusted-certificate` is neutral and why (D-002).
    - **Testing** was rebuilt around the single entry point: `pipeline.ps1` and its
      three tiers with their real contents (4 fast / 4 full / 3 release = **11**
      steps, **133** Dart tests, **124** engine tests, **65** methods and **78**
      contract cases, and the three release gates including the **41** tamper checks),
      replacing the stale "82 / 72" counts — and every probe it lists now has its
      command.
    - The build section says how signing and the manifest interleave (every file
      first, the engine **last**, so its signature covers the document — D-025), the
      layout table gained `qa/` and the new probes, and the **Arabic half** mirrors all
      of it: the self-check paragraph, the honest limits, the pipeline and the counts,
      and a current-status line that no longer calls the installer "planned".
  - No code and no new tests: the four checks are unchanged (`-Tier fast` 4/4, 133 /
    124), and every claim in the README is a number a pipeline step already produces,
    so a reader can re-run `-Tier release` and get the same sentences back.

- **ط2 — the tamper tests: nothing gets to lie about these bytes quietly**
  - `scripts\verify-tamper.ps1` tampers with one thing at a time in a private copy of
    the published package and asks **both** halves what they think: the release gate
    (`scripts\verify-manifest.ps1`, run as a child process - its exit code is the
    verdict) must refuse the copy, and the packaged engine - started from the copy on a
    private pipe with a private data directory, and **without** the
    `MICS_ALLOW_LOW_INTEGRITY` hook, because the copy is Medium-integrity under `%TEMP%`
    (trap 21) - must answer `unverified`, name what changed in its log, and push the
    card that names it. The published package is the control and must be accepted by
    both halves: without that, "every tampered copy is refused" would also be true of a
    probe that refuses everything. **41 checks, 0 failures, 108.5 s**, the release tier
    gained the `tamper.verify` step (11 steps across 3 tiers now), and
    `make-release.ps1` runs the same probe as its last gate - a release build that
    cannot prove the refusal does not publish.
  - What each case proved, measured on the 2026-11-03 package:
    - **a byte flipped in each shipped binary** (offset 1024, the length untouched): the
      eight the manifest lists are each refused by the gate - naming the sha256 on disk
      and the one the manifest records - and each reported by the app as
      `unverified - <path>: changed`, with the card naming the file. `mics-engine.exe`
      is never listed in its own manifest, so a code edit of it is refused by the gate
      with `HashMismatch`, and the app is not asked to run bytes that were edited in
      code (case 3 changes the engine's bytes too, in its resource, which is safe to run
      and still breaks the signature that covered them).
    - **a same-size swapped DLL**, twice: `System32\version.dll` padded to
      `dartjni.dll`'s exact 65,592 bytes, and one of our own signed plugins cut to that
      same length. Both are refused **by hash** (not by size, which is what a careful
      repackager would defeat) and both are reported as `dartjni.dll: changed`: the
      manifest covers the DLLs by digest, so a DLL that is signed by us is no more
      welcome than a foreign one.
    - **an edited manifest**: one listed file's hash replaced with 64 zeroes inside the
      resource. The gate refuses it with the file hash *and* the signature it just lost
      (a resource rewrite leaves the engine `NotSigned`, the measured consequence of
      `EndUpdateResource` that D-025 recorded), and the app reports it and raises the
      card.
    - **a repack**: the published document injected into the *unsigned* release build of
      the engine, which is what copying the manifest into a rebuild looks like. The gate
      refuses it ("is not signed by 'MI CS Code Signing' ... no signer") and the app
      reports it (`the engine is not signed by "MI CS Code Signing"`).
    - **a copied install**: accepted by both halves - a copy of the published bytes *is*
      the published bytes, because the manifest is about bytes and not paths - and
      reported the moment one file in the copy changes. What refuses a copy used as a
      *client* is the caller rule (D-015, `verify-pipe-acl.ps1` and `caller::tests`), not
      the manifest, and the probe prints that note instead of claiming the case.
  - **The probe found a real hole in the gate it was written to test.** Point 4 of
    `verify-manifest.ps1` only failed on `HashMismatch`, so an engine whose Authenticode
    signature had been **stripped** while it kept its manifest passed the release gate -
    measured on a copy: status `NotSigned`, and `RESULT: PASS - all 68 listed file(s)
    hash as the signed manifest says`. A repackager could therefore publish a re-packed
    folder with no signature at all and clear the gate, while the app - which asks
    `signature::trust()` - would report `unverified`: the two halves disagreed about who
    signs MI CS. The gate now requires the pinned `MI CS Code Signing`, and refuses no
    signer at all, another subject, and `HashMismatch` alike. The CN lives in one place
    for PowerShell (`$script:MicsSignerCn` in `scripts\manifest-resource.ps1`) and
    `test\package_integrity_test.dart` fails if that constant and the engine's
    `EXPECTED_SIGNER_CN` ever drift apart; D-025 carries the rule in its third
    amendment.
  - Docs: `THREAT-MODEL.md` F-11 now says what the tamper probe proves and what it still
    cannot (a rebuild signed by somebody else stays *visible*, never preventable),
    `qa/README.md` lists the new release step, and the QA report was regenerated
    (11 pipeline steps, 103 declared Dart cases).
  - The four checks are green through `scripts\pipeline.ps1 -Tier fast` (flutter.analyze
    13.9 s, flutter.test 29.5 s / **133 tests**, engine.test 6.7 s / **124 tests**,
    engine.clippy 2.0 s = **52.1 s**), and `-Tier release` is green end to end on
    `dist\MICS-portable` - **11 of 11 steps in 821.9 s**, with the new `tamper.verify`
    itself at 114.0 s / 41 checks: `opsec.verify`, `manifest.verify` and
    `tamper.verify` all pass.

- **ج2 commit 2 of 2 — the reader: the app now says whether its own files are the published ones**
  - `engine\src\selfcheck.rs` reads the manifest out of the engine's own image
    (`LoadLibraryExW(..., LOAD_LIBRARY_AS_DATAFILE)` + `FindResourceW`, so nothing is
    executed), refuses a document this build did not write (`format` not 1, no version,
    no files, a duplicate path, a path that walks out of the package, a digest that is
    not 64 hex), re-hashes every listed file against the folder the engine runs from
    (streamed 256 KB chunks) and reports the result through `status.integrity`: `ok`,
    `untrusted-certificate` or `unverified`. Ten unit tests, one of which drives
    `Dispatcher::handle_request` and asserts the field the UI reads is the cached
    verdict.
  - **The signature has to be read without a chain, and that is the decision this
    commit turned on.** A failed `WinVerifyTrust` returns no provider state at all, so
    `platform\windows\signature.rs` gained `Trust::{Ours, UntrustedRoot, NotOurs}` and
    `embedded_signer_name` — `CryptQueryObject` → `CryptMsgGetParam` →
    `CertFindCertificateInStore` → `CertGetNameStringW` — and returns `UntrustedRoot`
    **only** when the status is exactly `CERT_E_UNTRUSTEDROOT` *and* the embedded
    certificate is ours. A changed byte reports `TRUST_E_BAD_DIGEST` and still leaves
    our certificate in the file: treating "negative status, our certificate" as the
    quiet state would have made a patched engine quiet, which is exactly the attack
    F-11 names. Three new tests pin it, one of them flipping a byte of the release
    binary and asserting the verdict is *not* `untrusted-certificate`.
  - The verdict is computed once at start-up and cached (`OnceLock`), because `status`
    answers the UI's 15 s heartbeat and re-hashing ~30 MB per beat would be a tax, not a
    check. `main.rs` calls `selfcheck::start(...)` for `serve`/`service` only, logging
    the verdict always and raising `alert::package_changed` only when the copy
    **carries** a manifest that disagrees: a development build has no resource, so it is
    `unverified` in About and does not put a card on every `flutter run`. D-025 carries
    a second dated amendment for both points.
  - UI: `lib\core\ipc\package_integrity.dart` (`PackageIntegrity` plus a provider that
    falls back to `unknown` when the engine does not answer), one line in Settings →
    About for each verdict (green / muted / the notice), `alert_card.dart` learned the
    `integrity` kind and routes it to `/settings`, and the three strings exist in both
    languages. `test\package_integrity_test.dart` reads the three wire words **out of
    `selfcheck.rs`**, so a rename on either side fails the fast tier instead of leaving
    an About line that never appears, and `test\settings_integrity_test.dart` mounts the
    real Settings screen and asserts the right line for each verdict — and silence when
    the engine sent none.
  - **Measured on the real package, not on the build folder** (`make-release.ps1 -Sign`,
    2026-11-03, engine `88439F0B...`): the published copy answers
    `{"state":"running","version":"0.1.0","platform":"windows-x86_64","pid":...,"integrity":"ok"}`
    and logs `package integrity: ok - 68 file(s) hash as the manifest says (package
    0.1.0)`. Negative control, one byte flipped in `data\app.so` of a copy: `status`
    answers `"integrity":"unverified"`, the log names the file (`unverified -
    data\app.so: changed`), and Windows' **own notification history**, cleared first,
    holds the card — title *"🚨 MI CS — الملفات دي مش النسخة اللي اتنشرت"*, body
    *"data\app.so: changed — …"* — read back with `verify-toast.ps1`, so the card is
    proof the platform displayed it and not proof that a call returned `Ok`.
  - `scripts\verify-manifest.ps1` and `-Tier release` are unchanged and still pass on
    the published folder; the reader added no counted opsec string (the engine's
    `flutter` 55 and `dart` 1 rows are the ones commit 1 measured). `qa/report.md` /
    `qa/report.html` were regenerated in this commit: engine **111 → 124** declared
    cases in **14 → 15** modules, Dart **97 → 102** in **21 → 23** files, and the
    `status` row in `qa\methods.json` now names the integrity field it answers with.
  - The four checks are green through `scripts\pipeline.ps1 -Tier fast` (flutter.analyze
    63.3 s, flutter.test 52.9 s / **132 tests**, engine.test 33.3 s / **124 tests**,
    engine.clippy 2.3 s = **151.8 s** on HEAD `891957d` plus this work), and the signed
    release above was rebuilt and re-verified end to end by that same tree — the one
    clippy finding this commit did have (`field_reassign_with_default` in the new
    `CERT_INFO` lookup) was fixed and the package rebuilt after it, so the published
    folder is the committed source, not the one before the fix.

- **ج2 commit 1 of 2 — the producer: a manifest the package carries about itself**
  - `scripts\manifest-resource.ps1` is the one place the format lives: it lists a
    folder's files (relative path, bytes, SHA-256), sorts them ordinally, builds the
    `{"format":1,"version":...,"files":[{"path","bytes","sha256"}]}` document,
    injects it into an exe as the `RT_RCDATA` resource `MICS_MANIFEST` and reads it
    back. The engine is never listed in its own manifest — its integrity is its
    signature (D-025 point 3) — and a path that walks out of the package (`..`, a
    leading separator) is refused on the write **and** the read side, so neither can
    hash outside the package. The same file validates on read: envelope `format: 1`,
    a version, a sorted duplicate-free list, a whole byte count and a 64-hex digest.
  - `make-release.ps1` runs it after signing: every staged binary except the engine
    is signed (`sign.ps1 -Except`), the manifest is built from those final bytes,
    injected, the engine is signed (`sign.ps1 -Only`), and the resource is read back
    out of the staged package and every file it lists re-hashed — a package that
    does not describe itself never leaves the staging folder. A second
    `verify-opsec.ps1` call after the injection catches the strings the manifest
    adds, and `manifest.verify` runs the same probe from `-Tier release` against
    `dist\MICS-portable`.
  - **Measured, and it moved one step of the order D-025 recorded**: injecting into
    an already-signed engine and signing it again fails — Windows' resource API
    leaves the certificate table inconsistent with the rewritten PE and signtool
    refuses the file (`SignedCode::Sign returned error: 0x800700C1`), where the same
    injection into a never-signed engine is then signed `Valid`. So the engine is
    signed **once, after** the injection; D-025 carries a dated amendment and both
    properties it wanted (the manifest covers the signatures of every file it lists,
    the engine's signature covers the manifest bytes) are re-proved by
    `verify-manifest.ps1` on the staged package.
  - Measured on the built package (2026-11-03, `make-release.ps1 -Sign` end to end):
    the staged manifest describes **68 file(s)** — everything except
    `mics-engine.exe`; `VERSION` is written after it by design and is printed as
    "not listed" — and `verify-manifest.ps1` re-hashed all 68 out of the package and
    found every one matching, with the engine's signature `Valid`. Both negative
    controls, run by hand on a copy: one flipped byte of `data\app.so` fails with
    that file's sha256 named, and an engine with no injected resource is refused
    ("carries no MICS_MANIFEST resource").
  - The manifest's own file names enter the engine's strings, measured rather than
    waved through: `flutter` **0 → 55** (54 `data\flutter_assets\...` paths plus
    `flutter_windows.dll`) and `dart` **0 → 1** (`dartjni.dll`), each with a written
    reason in `qa\opsec-baseline.json`, and `qa/report.md` / `qa/report.html` were
    regenerated in this commit (they also gained the "Integrity manifest" gate row
    and the tenth pipeline step).
  - The four checks are green through `scripts\pipeline.ps1 -Tier fast`
    (flutter.analyze 53.3 s, flutter.test 46.5 s, engine.test 185.3 s,
    engine.clippy 117.8 s = **402.9 s**; the Rust half was the cold
    `%TEMP%\mics-target`, so that is the slow case, not the usual one), and
    `-Tier release -Only '*.verify'` passes both artifact verifiers on
    `dist\MICS-portable`: `opsec.verify` 3.4 s and **`manifest.verify` 2.6 s** on
    the published folder.
  - Left for commit 2, which landed the same day (the entry above): the reader —
    `status.integrity` in three states (`ok`, `untrusted-certificate`, `unverified`)
    and the About notice/banner.

- **د5 - the QA report and the coverage gates**
  - `qa/report.md` + `qa/report.html` are committed, generated by
    `qa/report.dart` from the committed registries only: no clock, no machine
    path, no run timing, no hash. That is what lets `test/qa_report_test.dart`
    compare both files byte for byte and fail the fast tier (and so CI, which runs
    the fast tier inside `-Tier full`) when the surface moved and the report did
    not - the same ratchet `qa/ui/ledger.json` applies to controls.
  - `qa/registry.dart` is the one reader for the registries (`methods.json`, the
    UI ledger, `fixtures.json`, the opsec baseline, and the dispatcher's match
    table); `test/qa_registry_test.dart` was moved onto it, so the report and the
    registry gate cannot disagree about what "registered" means.
  - The gates the report states, and where each is enforced: the dispatcher and
    `qa/methods.json` (65 = 65) by the registry test; every language directory
    listed under `assets:` in `pubspec.yaml` by the report test; every `skip`
    reason at least 20 characters by the report test (a reason exists to be read,
    so "n/a" is not one); the surface not degenerate (floors on methods, controls,
    screens, languages, test files, shipped files, pipeline steps) by the report
    test; and no machine value in either file (no `C:\`, no account name, ASCII
    only) by the report test.
  - Measured 2026-11-02 from the registries: **65** methods, all 65 dispatched,
    **65** declared cases and **15** classified not to run with a reason each;
    **98** controls over **13** screens + the shell; **2** languages, **38** packs;
    **9** shipped binaries (**1339** `cargo`+`rustc` hits in the engine, the rest
    framework strings); **97** declared Dart cases in **21** files and **111**
    declared engine cases in **14** modules (the same 111 the run reports); **9**
    pipeline steps across 3 tiers. Negative controls, both run: appending a line to
    `qa/report.md` fails with `qa/report.md is stale ... read the diff`, and
    setting one `skip` reason to `n/a` fails with `canary.deploy: the recorded
    reason is too short to say why this method is not exercised here`.
  - Honest limits, written into the files: the counts are declarations, so a test
    that failed still counts as declared - the gates on results are
    `engine.contract` and the two test steps; the parsed pipeline table is a regex
    over `scripts/pipeline.ps1`, so a reformat changes the report (loudly, via the
    staleness gate) rather than drifting silently; and coverage of a registry is
    not correctness of the product.
  - Also fixed: `engine.contract`'s description in `scripts/pipeline.ps1` said
    "All 62 JSON-RPC methods", which the report showed was stale (65); it now says
    "Every registered method", so it cannot rot again.

- **ط3 - the opsec probe runs from the release tier**
  - `scripts\pipeline.ps1` gained its first `release`-tier step, `opsec.verify`:
    it runs `verify-opsec.ps1` against `dist\MICS-portable` - the packaged
    artifact, not the build folder - so the tier refuses a package whose bytes
    name the account that built it or grew a counted fingerprint.
  - Nothing else is wired there yet, on purpose: `verify-tamper.ps1` lands with
    ط2 (it needs ج2's signed manifest), and the hardening/release/installer
    verifiers already run inside `make-release.ps1` and `verify-release.ps1`. The
    tier's help text now says the verifiers land one per slice instead of listing
    them as if they were all there.
  - Measured 2026-11-02, on the package `make-release.ps1` published the same day
    (engine hash `B78E05B3...`, 70 files): `-Tier release -List` ends with
    `opsec.verify release The packaged files carry no build fingerprint the
    baseline forbids`; `-Tier release -Only opsec.verify` prints `RESULT: PASS -
    9 binaries, no shipped file names this machine's account, and no counted
    string above the baseline` in **3.3 s** (report
    `build/pipeline-release.json`). Negative control: the same probe against the
    2026-11-01 package fails with
    `this machine's account is named in the package: mics-engine.exe: 1238 x
    'C:\Users\<account>'`.

- **fix - the path remap replaced the engine's own rustflags instead of adding to them**
  - ط1 set `CARGO_ENCODED_RUSTFLAGS` to `--remap-path-prefix=...` and nothing else.
    That variable (like `RUSTFLAGS`) **overrides** `engine\.cargo\config.toml`
    rather than adding to it, so `-C control-flow-guard=yes` (ج1, D-021) stopped
    being passed and the release engine came out without a CFG table. The fast tier
    cannot see this: only the release lane reads the PE.
  - Caught the day it was introduced, by the gate that exists for exactly this:
    `make-release.ps1` refused to package the build -
    `mics-engine.exe (23,898,624 bytes) DllCharacteristics 0x8160` (no GUARD_CF)
    and `GuardFlags 0x00000100` (no function table, no longjump table), while
    `mics_app.exe` in the same staging folder still measured `0xC160`.
  - `scripts\engine-rustflags.ps1` reads `engine\.cargo\config.toml` the way cargo
    reads it (host target section first, then `[build]`; a multi-line array is
    fine; a config it cannot parse throws instead of building quietly), appends the
    remap, and hands back a unit-separator-joined string. `make-release.ps1` and
    the `engine.build` step both call it, so the flag list stays in one file.
  - Measured 2026-11-02: `powershell -File scripts\engine-rustflags.ps1` prints
    `-C | control-flow-guard=yes | --remap-path-prefix=<profile>=/build`; the
    rebuilt engine measures `DllCharacteristics 0xC160` with
    `GuardFlags 0x00017500` (CF_INSTRUMENTED + function table + longjump table),
    keeps **0** hits for the account name, and the counted rows did not move
    (1242 `cargo`, 97 `rustc`), so the baseline needed no rewrite.

- **ط1 - the shipped engine no longer names the account that built it**
  - `rustc` records the source directory of every crate it compiles, so the
    release engine carried `C:\Users\<account>\.cargo\registry\src\...` — and the
    account name, **1238 times**, measured on the 2026-11-01 package. A file every
    user runs was saying who built it and which registry the crates came from.
  - Both paths that build the engine now compile with
    `--remap-path-prefix=$env:USERPROFILE=/build`, set as
    `CARGO_ENCODED_RUSTFLAGS` (not `RUSTFLAGS`: it is split on the unit
    separator, so a profile path with a space cannot break the flag):
    `scripts/make-release.ps1` and the `engine.build` step of
    `scripts/pipeline.ps1 -Tier full`. Measured on the rebuilt binary: **0** hits
    for the profile path and **0** for the account name (the 2026-11-01 package
    had 1238 of each; 34 other `C:\Users\` strings remain and belong to crate
    documentation that names other people's folders); a dependency panic now
    reports `/build\.cargo\registry\src\...` instead of the build machine's
    layout.
  - What was *not* leaking, measured rather than assumed: the workspace path is
    absent (0 hits for `H:\FlyEnv`), and `data\app.so`'s only two
    `C:\Users\` strings are product copy (a `Downloads` example and the canary
    path), so the Dart side needed no toolchain work.
  - `scripts/verify-opsec.ps1` reads the shipped bytes and compares them with
    `qa/opsec-baseline.json`: **forbidden** = the profile path of the account that
    runs the probe and its leaf directory, so the baseline never stores the path
    it forbids; **counted** = `flutter`/`dart`/`cargo`/`rustc`/`pubspec`,
    case-insensitive substring counts over ISO-8859-1 bytes — the same definition
    as the 2026-11-01 baseline, which `-Measure` reproduces exactly (1891 + 748,
    39, 1241 + 97). `-Measure` only prints; it never edits the allowlist.
  - The ratchet: a count above the baseline fails; a count below it is reported so
    the baseline can be tightened; a binary the baseline does not list fails until
    a human adds it with a reason; an entry whose reason is shorter than a
    sentence fails. `make-release.ps1` runs the probe against the **staging**
    folder next to the hardening check, so a leaking build is never published.
    Negative control run 2026-11-02: the old package fails with
    `this machine's account is named in the package: mics-engine.exe: 1238 x
    'C:\Users\<account>'`.
  - `test/opsec_baseline_test.dart` (5 tests, fast tier) guards the file: every
    marker has a reason of at least 20 characters, the file's marker list is the
    probe's own `$Counted` list read out of the script, the file is sorted, and it
    never contains a Windows user path or the account that measured it.
  - Honest limits: the counts are a **budget, not a guarantee** — `cargo` is 1242
    where the 2026-11-01 package measured 1241, because the crate paths still say
    `.cargo` (only their prefix is synthetic), and the toolchain's own name cannot
    be removed from a Rust binary; the framework strings in `flutter_windows.dll`
    (1891 + 748) are a prebuilt third-party DLL we do not compile. The measurement
    above is a **staging copy** of the 2026-11-01 package with the freshly built
    engine dropped in: the other eight files are byte-identical, so their counts
    are the shipped ones, and the next `make-release.ps1` re-measures the real
    package before it can publish.
  - Measured 2026-11-02: 111 engine tests (unchanged: no engine source touched),
    **120 Dart tests** (+5), the same shell ledger (21 controls), and
    `verify-opsec.ps1` PASS on the staged package (`9 binaries, no shipped file
    names this machine's account`) with the four fast checks green.

- **ز3 - the alert gate has a second destination: in-app cards in the window**
  - `engine/src/notify/alert.rs` keeps D-013's desktop policy untouched and adds
    `decide_in_app(severity, dnd)`: **every severity reaches the app**, `low`
    included, DND is the only switch that silences it (below CRITICAL), and
    `toast_enabled` is not consulted at all because it is the *desktop's* switch.
    Producers were already calling `alert::*`, so no call site grew a policy — they
    only pass a class now (`guard`, `canary`, `scan`, `quarantine`, `protection`,
    `crash`) and the UI uses it to pick the icon and the screen a tap opens.
  - A card leaves the gate as a JSON-RPC **push** named `alert` —
    `{kind, severity, title, body, bug_id?, report_kind?}` — through the same
    `jobs::notify` channel as `event`/`progress`, so both transports (pipe and
    stdio) carry it with no new request method: `qa/methods.json` stays at **65**
    rows and `test/qa_registry_test.dart` needed nothing.
  - `crash.rs::note_keyed` raises a card for every report it writes (panic, unclean
    exit, hang) **after** both files are on disk, carrying the bug id as its own
    field and the report kind for the icon. That is how a user who is looking at the
    window learns a bundle exists; ز2-ج's Diagnostics list is still where it is read.
  - A card raised before a UI exists is **parked, not lost**: `jobs::has_subscribers()`
    is false while the engine is starting, so the `unclean-exit` report filed at
    startup waits in a queue capped at **5** (oldest dropped) and is handed to the
    first transport that subscribes (`pipe.rs::handle_client`, and the stdio loop in
    `main.rs`). Subscribe-then-drain, so a card is never delivered twice.
  - The UI side: `ipc_client.dart` grew an `alertStream` (a third branch in the
    demux, next to `event` and `progress`), `lib/models/alert_card.dart` reads the
    push, `lib/core/notify/alert_cards.dart` holds at most **3** cards (newest first,
    one card per bug id) and drops the oldest, and `AppShell` paints them in a
    `PositionedDirectional(end, bottom)` inside its `Stack` - so `end` is the right
    corner in LTR and the left in RTL, from `rtlProvider`, with no language name in
    sight. Each card: icon by class, severity colour from the palette (the contrast
    audit measures it), the bug id in mono when there is one, a body clipped to three
    lines, a line saying **delivery is off** on a crash card, a close button, and a
    tappable body that opens the screen explaining that class (`crash` → Settings).
    Nothing auto-hides: the Guard screen, the incident list and `crash.list` are the
    record, the corner is a nudge.
  - Measured 2026-11-02: **111 engine tests** (was 106: five for the in-app policy,
    the waiting list and the card shape), **115 Dart tests** (was 114: the new shell
    behaviour test), `clippy -D warnings` clean, `flutter analyze` clean, and the four
    checks green through `scripts\pipeline.ps1 -Tier fast` (**128 s**). The shell
    ledger gained **exactly two** controls - `InkWell(🧯 MI CS — the engine filed a
    crash report)` and `IconButton(Dismiss notification)` - and no other entry moved.
  - The behaviour test is the receipt for the two things the slice promises: after
    the fake files a report the card is on screen with its bug id, its box measures
    `right = 1682` (1700 − 18) in LTR and `left = 18` in RTL, and closing it removes
    both the box and the id. The sweep also taps the card body, which navigates to
    the stub `/settings` route and comes back - so the ledger proves it is a real
    control, not decoration.
  - End to end on a real engine, isolated (`MICS_DATA_DIR` under `%TEMP%`,
    `MICS_NO_SINGLETON`, `MICS_NO_GUARD`), with a session marker left behind by a run
    that never said goodbye: `mics-engine serve` filed `MICS-20261102-e09798` while
    starting - before any client could exist - and the first line on its stdout was
    `{"jsonrpc":"2.0","method":"alert","params":{...,"bug_id":"MICS-20261102-e09798",
    "report_kind":"unclean-exit"}}`, i.e. the parked card delivered on connect. The
    title came out Arabic (المحرك سجّل تقرير انهيار) because the isolated data dir has
    no settings document and `ar` is the shipped default - the copy follows
    `settings.lang`, not the build.
  - **Honest limits, in the code and here**: (1) the panic path's card is best
    effort - the process is aborting, and the bundle on disk, not the card, is the
    record there; (2) a card says nothing about delivery because nothing is
    delivered - that is ز2-د (D-023), and D-024 fixes that no card may invent a
    delivery state; (3) `notify.test` (the Settings button) still proves the desktop
    card only, because routing it through the gate would change what that method
    answers, which is its own slice; (4) up to three cards are visible and older ones
    are dropped, so a flood of LOW events shows the newest three - the guard list
    keeps all 100.

- **ز2, third slice (ج) - the bug id now has a surface a user can act on**
  - `lib/models/crash_models.dart` reads the two shapes the engine sends
    (`crash.list` summaries and `crash.get` full reports) and composes the text a
    user pastes. **The bug id is the first line on its own**, because that is the
    one thing a paste into a message, a ticket or a search box has to start with;
    the field names under it are the ones the engine's own `.txt` uses (`kind`,
    `when`, `version`, `where`, `session`, `what happened`, the log tail), and
    they stay English like it - this text is read next to the engine's bundle
    rather than as UI copy.
  - `lib/core/ipc/crash_reports.dart` is the only door to the reports: an
    `AsyncNotifierProvider` over `crash.list` (newest first, the newest 20),
    `crash.get` for the row that was opened, and `crash.delete` followed by a
    **re-read of the list**, so what stays on screen is what the engine still has
    rather than what the UI hoped it deleted. The UI still opens no file and
    writes none (rule 4) - the reports directory belongs to the engine.
  - Settings → Diagnostics (between Engine and About) lists each report with its
    kind icon, the readable message, the engine's own kind, the repeat count and
    the last-seen time; opening one shows the whole paste text in a
    `SelectableText` with **Copy report** and **Delete report**. Copy goes to the
    OS clipboard: the UI itself still sends nothing anywhere (rule 8), and the
    text exists only on the user's own clipboard.
  - Measured 2026-11-02: **114 Dart tests** (was 110 - three for the paste-text
    model and one behaviour test), `flutter analyze --fatal-infos` clean, 106
    engine tests unchanged, `clippy -D warnings` clean, and the four checks green
    through `scripts\pipeline.ps1 -Tier fast` (**86 s**). The control ledger for
    `screens.settings` gained **exactly four** controls and no other screen
    changed: `ListTile(MICS-20261101-a1b2c3)`, `ListTile(MICS-20261102-0d9743)`,
    `IconButton(Copy report)`, `IconButton(Delete report)`.
  - The behaviour test is the receipt that the id on screen is the id the engine
    reported: it reads the row's own id, asserts it is the one that went out with
    `crash.get` and `crash.delete` (`{'bug_id': ...}`), and asserts that what
    reached the clipboard starts with that exact id and still carries the log
    tail. It also proves the deleted row is gone **because the list was re-read**
    and that deleting one report did not remove the other one.
  - **Honest limits, in the code and here**: (1) the list is read when the section
    builds, so a report written while Settings is open shows up after leaving the
    screen and coming back - there is no refresh button, because a "reporting"
    screen that polls would add a second state machine on top of the engine's and
    the id is what matters, not the seconds; (2) the newest **20** are shown while
    the engine keeps all of them; (3) the paste text is composed in Dart from the
    JSON, so it can drift from the engine's `.txt` - the engine's file stays the
    canonical artifact, and the UI still never opens it; (4) nothing on this
    surface delivers a report anywhere, and no report carries a delivery state:
    that is ز2-د, blocked on **D-023**.
  - No pipe surface changed (still 65 methods), so `qa/methods.json` and
    `test/qa_registry_test.dart` needed no new row. Only `qa/ui/fixtures.json`
    (two reports and one full-report template), `qa/ui/fake_engine.dart`
    (`crash.list` / `crash.get` / `crash.delete` are now stateful, so a deleted
    report stays deleted and a malformed id is refused exactly like the
    dispatcher refuses it) and the ledger moved.

- **ز2, second half (ب) - a runtime that stops answering now files its own hang
  report**
  - `engine/src/watchdog.rs` is a `std::thread` (deliberately **not** a tokio
    task), started where the session marker is written (`serve` and `service`),
    that watches a heartbeat the runtime bumps: a timer task every **5 s** plus
    every JSON-RPC request that enters the dispatcher. If the heartbeat stays
    silent for the **20 s** deadline - four beats, so a busy machine or one slow
    tick is not a hang - the thread writes the report itself through
    `crash.rs`, which is why it can report a wedged runtime at all: the process
    is alive, only the scheduler stopped.
  - The report is a new kind (`hang`) in the existing bundle: the same
    `MICS-<date>-<hash>` id shape and the same JSON + text pair under
    `<data dir>\crashes\`, readable over `crash.list` / `crash.get`. The message
    says **how long the heartbeat was silent** and **which request the
    dispatcher saw last** (`last request: scan.start`), so a support case does
    not have to guess. The id is hashed from the *last request*, not from the
    measured duration or the moment: the same hang keeps one id and a repeat is
    counted, while a hang during a different request is a different report.
  - One stall is one report: the first poll past the deadline files it, every
    later poll skips until a heartbeat returns, and a later stall gets its own
    (the same id again, so `occurrences` is the honest count). Nothing is sent
    anywhere - still no URL, no socket, no HTTP client in `crash.rs`, and the UI
    writes no files: it reads over the pipe, and its surface is ز2-ج.
  - Measured 2026-11-02: **106 engine tests** (was 100), `clippy -D warnings`
    clean, and a real `serve` engine started with the isolation hooks answered
    `ping`, closed its session cleanly and filed **zero** reports. The new tests
    freeze the heartbeat on purpose and read the file the thread wrote: exactly
    one report, its `occurrences` 1, a duration at least the deadline, the last
    request named, nothing when there was no request, nothing at all while the
    heartbeat keeps beating, and a stopped watchdog joins its thread.
  - **Honest limits, in the code and here**: (1) a hang that takes the whole
    process with it - a deadlock inside the allocator, a driver call stuck
    before the thread starts, a killed process - is **invisible**, because the
    watchdog is a thread of that process and dies with it; that case is what the
    session marker and the next start's `unclean-exit` report are for (ز2-أ);
    (2) one request that is merely slow is **not** a hang on purpose - a long
    `audit.run` or a Defender scan must never be filed as one, and on the
    multi-threaded runtime the timer keeps beating while one worker sits in a
    blocking Windows call, so the detector covers a runtime that stopped
    scheduling tasks at all, not a single stuck request; (3) the UI's own
    unanswered `ping` is still not a *detector* here - the engine reports the
    hang it can see, and the UI-side half stays with ز2-ج.
  - No pipe surface changed (still 65 methods), so `qa/methods.json` and
    `test/qa_registry_test.dart` needed no new row; the contract harness's crash
    scenario is unaffected (its engines are killed, not wedged).

- **ز2, first half - a crash now has a name and a file, and nothing leaves the
  machine**
  - `engine/src/crash.rs` detects two failures that a user experiences as "it
    just stopped": **a panic** (a hook runs before `panic = "abort"` ends the
    process, which is why the report is written first) and **a run that never
    said goodbye** (a session marker is written at startup, closed at the end,
    and an unclosed one at the next start is a kill, a power cut, or a death
    that left no panic behind). A hung process is the third case and cannot be
    detected from inside itself - the UI's unanswered `ping` is the next step.
  - The **bug id** is `MICS-<yyyymmdd>-<6 hex>`, and the hex is a SHA-256 of
    `version + kind + message + location` - the *failure*, not the moment. So the
    same crash has the same id on every machine running the same build, "send me
    the bug id" is a sentence that means something, and a repeat bumps
    `occurrences`/`last_seen` on the existing report instead of filing a second
    one. Two different call sites in the same function are two ids.
  - Each report is two files under `<data dir>\crashes\`: `MICS-….json` (what the
    UI and any future delivery reads) and `MICS-….txt` (what a human can paste
    into a message: what happened, where, which session, and the last **60** log
    lines). The log tail is capped at 64 KB, cut on a line boundary, and every
    key-shaped value is replaced with `<redacted>` - the engine does not log
    secrets today, and the redactor is there so it still cannot happen after
    someone adds one.
  - `crash.list` / `crash.get` / `crash.delete` are the pipe surface (62 -> 65
    methods). `bug_id` is validated character by character *before* it becomes a
    path, so `..\..\settings.json` is refused instead of read; a well-formed id
    that is not there is idempotent for `delete` and an error for `get`.
  - The contract harness gained a scenario that only exists across processes:
    start an engine (no reports), **kill it**, start another on the same data
    dir, and assert exactly one `unclean-exit` report, the documented id shape,
    the dead pid inside the report, the traversal refusal, and removal. Measured
    2026-11-01: **78 cases, 0 failed, 15 classified not-to-run**; 6 of the new
    cases are that scenario.
  - The panic hook's messy half is testable without a global hook (which would
    fire on every other test's deliberate panic): the payload reader is a
    function with three shapes (`&str`, `String`, anything else) and the recorder
    takes the payload, so `cargo test` covers "a panic produces a panic report
    with its location, and the same panic twice is one report".
  - Measured: **100 engine tests** (was 87), `clippy -D warnings` clean, 110 Dart
    tests, `flutter analyze` clean.
  - Deliberately not here: **delivery**. There is no URL, socket or HTTP client in
    `crash.rs`; that half needs **D-023** (rule 8), and the user has now said the
    WhatsApp path will be an **Open WhatsApp bridge**, not WhatsApp itself - so
    the integration is a local/bridge endpoint, not the Meta Cloud API. Nothing
    was built against a channel that is still being chosen.

- **ز1 - the language is a table, not a button in the title bar**
  - `AppLang` stopped being an enum. It is now a value with four facts:
    `code` (which is the asset folder *and* the string the engine stores, so the
    three cannot disagree), `nativeName` (what the picker shows, in its own
    script), `englishName` (logs and tests) and `direction`. `AppLang.all` is the
    only list of languages in the app, and adding one is: a folder with the same
    module files, one line in that list, one line in `pubspec.yaml`.
  - The title bar lost its language button entirely (`_TitleBar` no longer takes
    a `lang`), and Settings owns a labelled dropdown
    (`settings.language` + `Icons.translate`) that lists every bundled language
    by its native name - which is the only way a user who cannot read the
    current language can find theirs. It replaced a two-segment button, which
    does not survive a third language.
  - Direction is now read from the language instead of compared against Arabic:
    `isRtl`, `lang.locale`, and `supportedLocales` built from the table. Every
    comparison that was really a direction check is gone. One `== AppLang.ar`
    survives on purpose - the hardening screen picks between the two action
    names the engine ships (`name` / `nameAr`), which is a language choice and
    not a layout one - and it now compares `AppLang` values that are equal by
    code, so it keeps working when the list grows.
  - The engine stopped keeping a list: `settings.set lang` is validated as a
    **language tag** (`is_language_tag`: lower-case primary subtag, optional
    region) instead of `ar`/`en`, so shipping a language needs no engine release
    - and a typo is still refused (`english` is an error, `de` is stored). This
    is a *loosening* of a validated field, so it is recorded where it is tested:
    `qa/methods.json`'s `settings.set` invalid case changed from `xx` (now legal)
    to `english`, plus a new `de` case, and the hand-written round-trip scenario
    in `qa/contract.dart` changed the same way - it was the only thing that
    still assumed `xx` was invalid.
  - `test/lang_registry_test.dart` (10 tests) is the seam that was missing: the
    registry, `assets/i18n/`, and `pubspec.yaml` must agree, or a bundled
    language renders every key raw; directions must include both RTL and LTR
    (Arabic pinned); `byCode` resolves case-insensitively and falls back to the
    primary subtag, and returns null for a language nobody bundled; `lookup`
    falls back to English and then to the key itself.
  - A Settings behaviour test drives the real thing: pick العربية from the
    dropdown and the screen switches pack (`اللغة` appears, `Language` is gone),
    the tree flips to RTL, `rtlProvider` is true, and the engine received
    `settings.set {"lang": "ar"}`. A dropdown that only changed its own label
    would fail this test.
  - `lang.ar` / `lang.en` were removed from both packs: a language's own name
    lives in the registry now, and two sources of truth for it is how they drift.
  - Measured 2026-11-01: **110 Dart tests** in 13 s (was 99), `flutter analyze`
    clean, **contract 65 cases / 0 failed / 15 skipped** against the release
    engine, `scripts\pipeline.ps1 -Tier fast` green.
  - Correction to the د2 entry above: the "first frame can show raw i18n keys"
    row I added to the risk register was **wrong** - `lib/main.dart` does not
    build the router at all until the settings *and* the packs have values, so
    the harness was emulating the splash, not working around a bug. The row is
    replaced with what is actually true (a language missing from `pubspec.yaml`
    is silent, now caught by the registry test).

- **د2 - every screen and every control, driven by the same fixtures the contract
  harness uses**
  - `qa/ui/fake_engine.dart` answers a screen the way `qa/methods.json` says the
    engine answers: the shape comes from the registry row, the content from
    `qa/ui/fixtures.json` (25 methods), and only the methods whose answer depends
    on what came before are simulated (the language, the job table, the two push
    streams). A method the dispatcher does not have fails the test instead of
    returning `null`.
  - `qa/ui/harness.dart` mounts a screen the way `app_router.dart` does (Riverpod
    overrides for the IPC client and the language packs, a throw-away router with
    a stub for every route a screen can navigate to, a 1700x2400 viewport) and
    then **sweeps**: it walks the rendered tree, taps every control once
    (re-reading the tree between taps, because a tap rebuilds the screen), closes
    any dialog a tap opened, and reports what it touched. Labels are the widget
    type plus the tooltip or text a human would name it by (`IconButton(Restore)`,
    `GestureDetector(Settings)`), with an occurrence suffix so four identical
    icons stay four controls.
  - `qa/ui/ledger.json` is the ratchet: 14 entries, **93 controls** (13 screens +
    the shell), sorted and committed. A control that appears or disappears fails
    the test and prints the diff; regenerating is an explicit
    `$env:UI_LEDGER_WRITE = "1"`, so the diff is the thing a reviewer reads.
  - Two behaviours that a fixture cannot cover are tested directly, because they
    only exist once the engine pushes something: a `job_finished` event pulls the
    completed job and the screen shows its findings, and a `guard.event.dismiss`
    that answers `mute_suggested: true` makes the mute offer appear (and the mute
    button then sends `noise.mute` for the right category).
  - The sweep found and fixed four unnamed controls: the add/delete buttons on
    the canaries screen and the per-row delete on IDS and firewall had no
    tooltip, so they were invisible to a screen reader and unnamed in the ledger.
    `common.add` / `common.remove` now exist in both packs and all four carry one.
  - Measured 2026-11-01: **99 Dart tests in 13 s** (was 81), `flutter analyze`
    clean, `scripts\pipeline.ps1 -Tier fast` green. The shell needs two plugin
    channels mocked (`window_manager`, `tray_manager`) and its green window button
    needs `isMaximized` to answer `false` — answering `null` throws inside the
    title bar.
  - Honest limits, repeated because they will be asked again: this proves every
    control is *reachable and does not throw against a fake engine*, not that it
    does the right thing on a real machine (that is د3/د5 and the manual runs),
    and the screens are mounted without the shell's 13 rail items being part of
    each screen's own count — the shell is swept once, on its own.

- **د1 - every JSON-RPC method now has a case, and a test that keeps the list
  whole**
  - `qa/methods.json` is the surface as a document: one row per method with its
    `class` (`pure`/`read`/`sandbox` run for real; `mutating`/`network`/`desktop`
    only ever carry a refusal case, because this runs on the machine it protects),
    the call to make, the shape to expect, an optional `want` map pinning the
    values that make the shape meaningful, `missing`/`invalid` refusal cases, and
    `extra` named cases for a contract that is more than one call. Every row has a
    `note`; a row that could not produce a case is a test failure, not a comment.
  - `qa/contract.dart` starts a real `mics-engine` in a fresh `%TEMP%` sandbox with
    `MICS_DATA_DIR`/`PROGRAMDATA`/`MICS_PIPE_NAME`/`MICS_NO_*` set, then: an
    unknown method must answer `-32601`; every row runs; then three scenarios the
    single calls cannot express - a scan on an empty folder to `state=done` with
    `job.get`/`job.list`/`job.cancel` agreeing, a settings round trip where `xx`
    is refused and the previous value survives, and a final `ping` that proves the
    engine is still serving. It writes `build/qa-contract.json` and exits non-zero
    on the first summary line that disagrees.
  - `test/qa_registry_test.dart` parses the dispatcher's match table (arms at
    twelve spaces, with a guard against the parse going vacuous) and fails unless
    the two sets are equal, no method is listed twice, every class/expect is from
    the allowed vocabulary, `want` only appears on objects, no skipped row carries
    an `expect` that would silently not run, and every placeholder is
    `@sandbox/...` so the document stays machine-independent.
  - Measured (`-Tier full -Only engine.contract`, release binary): **64 cases, 0
    failed, 15 methods classified not-to-run with a reason each, 18.4 s**. The
    skipped fifteen are the ones that would change this machine (firewall profile,
    Defender scan, helper/service install, canary files, toast) or leave it (NVD,
    the intel feeds, LM Studio, the update manifest) - all still registered, so the
    count stays honest. With the registry test in place the `fast` tier is
    **42.3 s** (analyze 11.8, **81** Dart tests 21.2, 86 Rust tests 7.0, clippy
    2.3), still one command.
  - The harness found three contract mismatches on its first real run, all fixed
    in the registry rather than papered over: `noise.stats` returns an array (one
    row per learned category), `job.resume` of an unknown id answers
    `not_resumable` *unless* another job is active, in which case it is an error -
    so the row moved before any scan starts and `want` pins the answer, and
    `quarantine.delete` is deliberately idempotent where `restore` is not (an
    already-missing blob still answers `deleted`, because the postcondition holds),
    which is what `extra` exists for.
  - One trap worth the paragraph: the first full run reported six timeouts that
    were the harness's own fault. The client polled with `sleep()`, which blocks
    the isolate's event loop, which stops the `process.stdout`/`stderr` listeners
    that drain the engine's stdio; the engine logs every request to stderr
    synchronously, so a full 64 KB pipe parked its reader inside an `info!` call -
    process alive, pipe open, nothing read. Polling with `await Future.delayed`
    keeps the drain alive and the deadline honest. The production path was never
    affected (`ProcessStartMode.detached`, stdio not piped), so this was the
    harness learning the same lesson the UI avoids by construction.

- **ز0 - one pipeline script, so the checks a human runs and the checks CI runs are
  the same checks**
  - `scripts/pipeline.ps1` is now the only place the list lives: tiers `fast` (the
    four checks), `full` (+ the engine and app release builds and the engine smoke)
    and `release` (the artifact verifiers, as they land). Each step is a named
    command with its own working directory, the run is fail-fast, and every run
    writes `build/pipeline-<tier>.json` with per-step seconds and exit codes
    (`build/` is gitignored).
  - `.github/workflows/ci.yml` calls `-Tier full` instead of repeating the steps,
    caches `engine/target` against `engine/Cargo.lock`, cancels superseded runs, and
    uploads the report next to the binaries. The smoke test the workflow used to run
    inline is now the `engine.smoke` step, so the local run covers it too.
  - Measured on this machine (`-Tier fast -CargoTargetDir $env:TEMP\mics-target`):
    `flutter.analyze` 16.3 s (no issues), `flutter.test` 13.8 s (72 tests),
    `engine.test` 7.4 s (86 tests), `engine.clippy` 2.4 s - all PASS, and the report
    was written. The `full` tier was not run for this commit (the engine binary it
    would rebuild is the release one, and this step changed no Rust).
  - Two traps met inside the script instead of around it: PowerShell 5.1 reads a
    UTF-8 em-dash in a double-quoted string as a closing quote, so the script is
    ASCII-only (the existing §8 rule, now enforced by habit); and
    `Measure-Object -Property` cannot read a hashtable key, so the total is summed
    by hand. Native stderr is also no longer allowed to terminate a step
    (`$ErrorActionPreference = 'Continue'` around the call, exit code is the
    verdict) - §8's trap 8, in the runner rather than in a note.

- **fix - every IDS domain add was refused because the hosts file starts with a BOM**
  - Measured by the user's acceptance run, three attempts in a row:
    `ids.block.add failed: hosts line 1 is not an address/host pair: "\u{feff}"`, and
    `priv.log` shows the helper received the document and refused it -
    `phase=done ok=false error=hosts line 1 is not an address/host pair: "\u{feff}"`
    (`bytes=7220 lines=167`). So the transport, the elevation and the marker check
    all worked; only the validator disagreed with the file.
  - Cause: this machine's hosts file begins with a UTF-8 BOM, the document the IDS
    path builds inherits it, and `str::trim` does not remove U+FEFF (Rust does not
    class it as whitespace, unlike what "trim whitespace" suggests), so line 1 was
    the BOM alone and `is_hosts_entry` said no.
  - Fix: `validate_hosts` skips one leading BOM before walking the lines and writes
    the document unchanged - the BOM is the file's encoding marker, not an entry, and
    the file keeps whatever prefix it already had.
  - Test: `hosts_documents_are_shape_checked` now feeds a BOM-prefixed good document
    (accepted) next to a BOM-prefixed hostile one (still refused), so the exception
    cannot turn into leniency. `cargo test` 86 passed, clippy clean.
  - P1.5 state after that run: Default-Deny went on and off through the helper
    (`ok=true`, 1651 ms and 1899 ms) with no prompt; the SMBv1 rollback was pressed
    from the UI at 16:27:56 and answered `ok=true` in 3184 ms with the same script hash
    the end-to-end run used (`de441645d4054b16`); and the IDS add is the only operation
    that failed - on this bug. It has to be retried against the rebuilt engine.

- **fix - the SMBv1 rollback could not run at all (found by the user's acceptance run)**
  - Measured, not reasoned: the user pressed rollback on a real install and got
    `EngineException(-32000) ... Set-SmbServerConfiguration : Cannot process argument
    transformation on parameter 'EnableSMB1Protocol'. Cannot convert value
    "System.String" to type "System.Boolean"`.
  - Cause: `snapshot_script("smbv1_off")` formatted the recorded bool with `-f $s`, and
    a formatted PowerShell bool prints `True`/`False`. In argument position those are
    *strings*, and the CIM cmdlet refuses a string where it declares `[bool]` - the
    rollback died at binding time, before the helper could do anything. The helper's
    allow-list accepts the word, so the shape test written for exactly this class
    (`rollback_scripts_are_allow_listed`) could not catch it either.
  - Fix: the snapshot emits a literal through a branch
    (`$(if($s){'$true'}else{'$false'})`), and it emits neither half when the value it
    would restore is missing - a rollback that guesses is worse than one that refuses.
  - Measured on the same machine, same cmdlet, unelevated:
    `-EnableSMB1Protocol False` -> `ParameterArgumentTransformationError` (the user's
    error, reproduced on demand); `-EnableSMB1Protocol $false` -> `Windows System Error
    5` (**access denied**) - the binding was accepted and elevation is the only gate
    left, which is what the helper is for. The shipped snapshot script, extracted from
    `engine\src\hardening\mod.rs` and run with `-File`, now prints
    `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; reg add
    "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f`.
  - Regression: `snapshots_run_unelevated_and_are_acceptable_rollbacks` asserts the
    SMBv1 rollback carries a boolean *literal*, and the allow-list test now carries the
    literal shape next to the word shape. `cargo test` 86 passed, clippy clean.
  - P1.5 after that run: the helper is installed and running from
    `%LOCALAPPDATA%\MI CS` (`STATE : 4 RUNNING`, `ImagePath "...\MI CS\mics-engine.exe"
    helper-service`), one UAC prompt in total, and `priv.log` shows
    `phase=note install finished, helper state=running` plus three
    `phase=start`/`phase=done ok=true` pairs. Disabling SMBv1 went through; only its
    rollback was broken. Still to press by hand: the rollback, Default-Deny and one IDS
    domain.

- **ب3 step 3 — the installer is verified by a script, not by hand (2026-11-01)**
  - `scripts\verify-installer.ps1` turns the throw-away probe steps 1–2 were measured
    with into the committed gate. It builds a per-user installer (or takes `-Setup`,
    copying it out of `dist\` first because that folder is Low-integrity), installs it
    into `%TEMP%`, measures every promise the installer makes, uninstalls it, and then
    builds a second copy whose helper check points at a synthetic HKCU key so the
    refusal branch runs without touching a real service.
  - Measured end to end on this machine: **126 s**, `RESULT: PASS`, and the run
    restored itself - the AUMID key back to the user's `MI CS` /
    `%LOCALAPPDATA%\MI CS\mics_app.exe`, no stray shortcut or key, the user's 69-file
    copy and its engine hash untouched. The install is the 69-file package plus
    `uninstall.exe`; both shortcuts read `MICS`; `Get-StartApps` files the app under
    `MICS` with nothing under the copy's exe path; the checker answers SAFE/SAFE, and
    OWNED when a helper points at the copy it is asked about; `/S _?=$INSTDIR` answers
    **5** while a plain `/S` answers 0, and the refused copy keeps the program, the
    uninstaller, both shortcuts and its Apps & features entry.
  - It refuses to start when this account already owns an `MI CS` shortcut or a
    per-user Apps-&-features entry: it owns the names it creates, and deleting a real
    install to measure a test one is not a trade this script makes.
  - Checks: `cargo test` **86 passed**, `cargo clippy --release -- -D warnings`
    clean, `flutter analyze --no-pub` no issues, `flutter test --no-pub` **72
    passed**.

- **ب3 step 2 — the shortcuts carry the AUMID, and the uninstaller refuses a copy the helper points at (2026-11-01)**
  - Both items that step 1 recorded as deliberately left out (D-022) are now
    closed, and both were the kind that only a real install could measure.
  - **The shortcut's `System.AppUserModel.ID`.** The installer unpacks
    `register-aumid.ps1` + `aumid-interop.ps1` into its temporary `$PLUGINSDIR`
    (never into `$INSTDIR` — the package stays byte-for-byte the one
    `make-release.ps1` assembled) and tags both shortcuts through `IPropertyStore`,
    which NSIS has no command for. Measured on the per-user build
    (`MICS-setup-test.exe`, 15.8 MB, sha256 `98819F6AC6CDE17E959072B2F53AE4817241286ED60DB87BA74BDE5015A13604`):
    after a silent install, `[MicsAumid]::Read` answers **MICS** on
    `...\Start Menu\Programs\MI CS\MI CS.lnk` *and* on
    `...\OneDrive\Desktop\MI CS.lnk`, and `Get-StartApps` files "MI CS" under AppID
    `MICS` with **no** entry under this copy's exe path. That last number is the
    before/after: the first build passed both shortcuts in one `-Shortcut "a" "b"`
    call, tagged only the first, and the Shell listed the desktop icon as
    `...\mics-verify4\install\mics_app.exe` — a native command line binds only the
    first value to a PowerShell array parameter. The installer now makes one call per
    shortcut, and the trap is written in both files.
  - **The uninstaller and the privileged helper.** The helper service is the app's
    (D-022), so a copy it still points at cannot be taken apart: the uninstaller asks
    the new `scripts\check-helper-ownership.ps1` before it touches anything and, on
    OWNED, says which button removes the helper and aborts. Measured: the checker
    answered **2/OWNED** for `%LOCALAPPDATA%\MI CS` while the machine's service
    pointed at it (**0/SAFE** for the test copy, **0/SAFE** for a service that does
    not exist); a verification build (`-HelperServiceKey`) whose helper points into
    the test copy refuses (`/S _?=$INSTDIR` → **5**) with the program, the
    uninstaller, both shortcuts and the Apps-&-features entry still in place, and the
    same uninstaller exits 0 and removes everything once that key is gone.
  - **Three NSIS/PowerShell facts measured on the way**, all now written where the
    next person will look: an uninstaller **always answers 0** to its caller (NSIS
    copies it to `%TEMP%` and runs it there — appendix D.1), so the refusal's error
    level is only readable the documented way; `_?=` must be **last**, because put
    first it swallows the rest of the command line into `$INSTDIR` and the result was
    a "successful" uninstall that removed the shortcuts and the registry entry and
    left every file; and the machine's own `MICSHelper` was removed **by the app**
    during this step (`helper.uninstall` in `priv.log`, 15:53 local) — the installer
    and its uninstaller only ever read that key, which the log and the before/after
    definition check both show.
  - Checks: `cargo test` **86 passed**, `cargo clippy --release -- -D warnings`
    clean, `flutter analyze --no-pub` no issues, `flutter test --no-pub` **72
    passed**. Deliberately not in this step: `scripts\verify-installer.ps1` (step 3)
    and the per-machine run, which still needs one UAC click.

- **ب3 step 1 — the product has an installer, and it installs and removes cleanly (2026-11-01)**
  - `installer\mics.nsi` + `scripts\make-installer.ps1` compile the assembled package
    into `dist\MICS-setup-0.1.0-x64.exe` — **15.8 MB**, sha256
    `304678D69F11C87B335B8F6947F47DCDDE4D518B4E4A4E77B6EF28FA1BB4CC54`, NSIS 3.11
    (portable copy, no admin to build). The ZIP is no longer the only way to get MI CS.
  - **Measured, not asserted.** The per-user variant (`-TestUser`, same script, no
    UAC) was installed silently into `%TEMP%\mics-verify3\install`: **70 files /
    51.7 MB**, `mics-engine.exe` = the package's `E64A6FDE…` — hardened **and**
    `Valid`-signed, so what ships is the release engine — Start-Menu folder with
    `MI CS.lnk` + `Uninstall MI CS.lnk`, the
    desktop icon, `HKCU\Software\Classes\AppUserModelId\MICS` (`DisplayName=MI CS`,
    `IconUri=<install>\mics_app.exe`) and the Apps-&-features entry
    (`DisplayName=MI CS 0.1.0`, `UninstallString=…\uninstall.exe`). Then
    `uninstall.exe /S` exited 0 and the folder, both shortcuts, the AUMID key and the
    ARP key were **all gone**; the machine's own AUMID registration was restored after
    the test.
  - Three traps measured on the way: PowerShell's `&` does **not** wait for a GUI
    installer (the first check measured an empty folder while the setup was still
    running — use `Start-Process -Wait`); a setup started from `dist\` runs at
    **Low** integrity and cannot create its `%TEMP%` target, so it exits **0 having
    installed nothing** (trap 21 again, now with an installer-shaped symptom); and
    `make-release.ps1` without `-EnginePath` stages the **stale** pre-ج1 engine from
    `engine\target\release` (35.7 MB, no `GUARD_CF`) — the hardening gate refuses to
    publish it, which is also how the three `signature.rs` tests came to fail: the
    package had been rebuilt unsigned. Re-signing it (`-SkipBuild -Sign -EnginePath
    …\mics-target\release\mics-engine.exe`) turned the suite back to 86 passing.
  - Deliberately not in this step (D-022): the shortcut's `System.AppUserModel.ID`,
    uninstall-side helper cleanup (ب4), and `scripts\verify-installer.ps1`. The
    **per-machine** installer has not been run by a human yet — that is the UAC
    prompt in §0.2.

- **The helper acceptance test found two engine bugs, not a missing helper (2026-11-01)**
  - The first real run of the privileged path (Default-Deny, then SMBv1) failed in the
    engine, not in the helper: `fw.default_deny.enable` answered `netsh failed: The
    number of arguments provided is not valid` and `hardening.apply` died as
    `powershell failed: … Unexpected token
    'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\" /v Start …'`. The helper was
    installed, running and reachable the whole time (`helper-status` from the packaged
    copy: `installed:true running:true reachable:true`) and `priv.log` held **no**
    entry for either call — both failures happened before the elevation step, in the
    code that prepares it.
  - **Default-Deny could never have worked.** `netsh advfirewall set <profile>
    firewallpolicy` takes the pair as **one** comma-separated argument, inbound first
    (`BlockInbound,AllowOutbound`); the engine passed `blockoutbound` and
    `allowinbound` as two arguments, so Windows refused every profile. It also,
    separately, (a) hard-coded `AllowInbound` on every write — switching the toggle
    *off* would have opened inbound instead of restoring Windows' default — and (b)
    read the state from `show <profile> state`, which prints no policy line at all, so
    the switch could only ever show "off". All three are fixed: one `show allprofiles`
    read, the inbound half preserved on every write, and `is_default_deny_enabled` true
    only when **all three** profiles block outbound.
  - **The SMBv1 snapshot could not parse.** `\"` is not an escape inside a PowerShell
    double-quoted string, so the script that generates the rollback line closed its own
    string early and PowerShell refused the whole apply — before the helper was ever
    involved. `rdp_off` and `uac_on` carried the identical shape, i.e. the same bug was
    waiting for the next user. The snapshot scripts now live in one place each
    (`snapshot_script`, `pub(crate)`, so a test can see them), build their answer with
    single-quoted format strings, and print nothing for a value that is not there —
    `reg add … /d  /f` used to be the "rollback" when `mrxsmb10` was absent, which is
    the state of a machine that never enabled SMBv1 (this one included).
  - **Four tests, and they have teeth.** `every_powershell_script_we_generate_parses`
    compiles every apply and snapshot script with `[scriptblock]::Create` through the
    production runner (parse only, never executes); the old SMBv1 script was run
    through that harness by hand first and reproduces the user's `Unexpected token`
    verbatim. `snapshots_run_unelevated_and_are_acceptable_rollbacks` runs each
    snapshot and feeds the output to `validate_rollback`;
    `a_quoted_registry_path_survives_the_powershell_runner` proves the `-Command` round
    trip keeps `reg add "HKLM\…"` quotes intact;
    `the_firewall_policy_is_read_from_one_netsh_dump` pins the line `netsh` really
    prints (`BlockInbound,AllowOutbound`) instead of the one we assumed.
  - Checks: `cargo test` **86 passed**, `cargo clippy --release -- -D warnings` clean,
    `flutter analyze --no-pub` no issues, `flutter test --no-pub` **72 passed**.
  - **Still needs the human** (and now for a second reason): the attempt ran with MI CS
    started **elevated**, and an elevated engine runs privileged operations itself
    (`is_elevated()`), so nothing reaches the helper and `priv.log` stays empty. To
    exercise the helper path the app has to run unelevated.

- **ج1 — the release binaries are hardened, and the PE is what proves it (D-021)**
  - The ROADMAP put build hardening before the installer for one reason: everything
    after it packages a binary. So the first measurement was of the binaries that
    were being shipped — and it said the mitigation everybody assumed was **off**.
    `scripts\verify-hardening.ps1` (new) parses the PE: both `mics_app.exe` and
    `mics-engine.exe` had `DYNAMICBASE|NXCOMPAT|HIGH_ENTROPY_VA` but **no
    `GUARD_CF`** and **no guard function table** in the load config, i.e. indirect
    calls were not checked at all. The same probe reports `CF_INSTRUMENTED` for
    `kernel32.dll`/`ntdll.dll` (plus their function tables and CET marker), which is
    how the reader itself was validated before it was trusted.
  - **What changed.** Engine: `[profile.release]` gains `lto = "fat"`,
    `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, and
    `engine\.cargo\config.toml` asks rustc for `-C control-flow-guard=yes` (the
    compiler flag matters: `/guard:cf` at link time alone produces the bit and an
    empty table). App: `windows\runner\CMakeLists.txt` adds `/guard:cf` to both
    compile and link for Release/Profile. Dart: `make-release.ps1` now builds with
    `--obfuscate --split-debug-info=dist\symbols\<version>`, and the symbol table is
    a build artifact that is never in the ZIP (it maps `app.so` back to the source).
  - **Measured after the change** (same probe, on the built files): engine
    `DllCharacteristics 0xC160`, `GuardFlags 0x00017500`
    (`CF_INSTRUMENTED|CF_FUNCTION_TABLE_PRESENT|CF_LONGJUMP_TABLE_PRESENT`), no
    CodeView entry; app `0xC160` / `0x00017500` / stripped; engine size
    **35,731,512 → 24,024,064 bytes (−32.8 %)**; `data\app.so`
    **7,209,864 → 5,751,688 bytes** and the five class names that a readable
    snapshot carries (`SettingsNotifier`, `AuditFinding`, `GuardScreen`,
    `AppSettings`, `_LayerTile`) are **gone** from it.
  - **The gate, not the flags.** `make-release.ps1` refuses to package when the
    staged binaries fail `verify-hardening.ps1` or when no Dart symbol table exists
    for the version (`-SkipBuild` from an un-obfuscated build folder is exactly that
    case), and `VERSION` inside the package now says what was hardened.
    `verify-release.ps1` gained step 6: the extracted copy passes the same probe and
    its `data\app.so` carries none of those names, with **no** `*.symbols` file
    anywhere in the ZIP.
  - **Deliberately not claimed** (D-021): `/guard:ehcont` is refused by `link.exe`
    (LNK2047 — `libstd` has no EH continuation metadata, and
    `/force:guardehcont` would ship an incomplete table), and `/CETCOMPAT` is not
    set because this machine cannot run a process under a shadow stack to prove it.
    Both are written down where the next person will look instead of being silently
    implied by "hardened".
  - Checks: `cargo test` **82 passed**, `cargo clippy --release -- -D warnings`
    clean, `flutter analyze --no-pub` no issues, `flutter test --no-pub` **72
    passed**; the release was rebuilt through the new gates and
    `verify-release.ps1` re-read the hardened package.

- **Small step 5 — four light-theme renders of the real UI, and a real Settings bug found by rendering it**
  - `tool/write_screenshots_test.dart` (new, dev-only) pumps the app's own widgets with
    `engineIpcProvider` replaced by a canned engine, loads the **real fonts** (Cairo,
    JetBrainsMono) through `FontLoader`, pins the light palette and the Arabic RTL
    layout through the app's own `settings.get` path, and writes four 1600×1000 PNGs
    into `docs/images/`: `light-dashboard.png`, `light-audit.png`,
    `light-intel.png`, `light-settings.png`. Regenerate with
    `flutter test --no-pub tool\write_screenshots_test.dart`. It lives in `tool/`, so
    the normal suite never collects it and the count stays 72.
  - **The images are self-proving, because I cannot see them and neither can a reviewer
    of a diff.** Every screen asserts a known string before its PNG is written (the
    dashboard's settled score `78` and the `L1` card, the audit's `SMBv1 Protocol` and
    `3 local accounts`, intel's `76737`/`1766`, the settings screen's
    `SegmentedButton<ThemeMode>` and ≥4 `SwitchListTile`), `takeException()` must be
    null after each navigation, and each image must carry either >2000 distinct colours
    or >2 % non-background pixels **and** a mean luminance above 0.6 (so a dark capture
    fails). A font test measures a known string and requires the width to differ from
    both the Ahem signature (`glyphs × px`) and the default family: Cairo 177.0 px
    versus 400.0, JetBrainsMono 374.4 versus 624.0. The receipt (size, colours,
    luminance, SHA-256) is printed on every run, and the dashboard PNG is byte-identical
    across two independent runs.
  - **Rendering Settings found a real bug, fixed in its own commit**: `_Section`'s
    decorated `Container` was the nearest Material ancestor for every `SwitchListTile`,
    so each switch lost its ink splash and Flutter threw six
    "ListTile ... ink splashes may be invisible" exceptions per render. Wrapping the
    column in `Material(type: MaterialType.transparency)` fixes it with no visual
    change; the screenshots then render with zero exceptions. No test had ever rendered
    Settings with data, which is why it survived.
  - README gained a **Screenshots** section (the four images side by side, one in the
    Arabic section) that says plainly they are renders with sample data — score 78,
    nine findings, three synced sources — and that the text is what proves the product.

- **Small step 8 — the two cheap LOW rows became prose a reader can find**
  - Both gaps were true and already recorded, but only in the register — the one place
    a stranger does not read. This step moved them into the documents that exist for
    exactly this purpose.
  - **No obfuscation, no integrity manifest** → new `THREAT-MODEL.md` row **F-11**:
    what is readable (strings, symbols, the Dart/Rust structure), what an attacker can
    do with it (repackaging), why it is accepted (obfuscation hides the code from the
    auditors this project invites, and it does not stop a reverse engineer), what
    carries the security instead (pipe ACL F-1, update signature F-3), and what closes
    it (P5 ج1–ج3: signed manifest + start-up self-check banner + a reproducible-build
    note). README's "does not" list now says it in one paragraph, next to the
    unsigned-binary bullet it belongs with.
  - **The caller check's portable fallback** → `THREAT-MODEL.md` F-2 now spells out the
    fallback concretely: with no `%PROGRAMDATA%\MICS` there is no account to compare
    against, so the check falls back to the image name and logs `no installer account
    recorded` once — and the pipe ACL is what still keeps other users out. The register
    rows point at both places so the two never drift apart.
  - Also closed the stale §0.1 row 8, which still said "dark mode is not yet measured"
    after step 4 measured it: both palettes now assert 29 of 29.

- **Small step 7 — `PROTECTION-MATRIX.md` verified, linked from the README, and its layer numbers reconciled**
  - The sheet already existed (243 lines, 10 sections); what this step added is the
    check that a stranger can read it, and the two things that were wrong with it.
  - **The layer numbers did not match the product's own naming.** The matrix called
    the scanner `L1` and the firewall `L2`, while the README and the brief call
    network `L1` (Network Gate) and the file engines `L4`. A reader going from one
    document to the other had two numbering schemes for one product. Fixed in the
    matrix: the scanner is **L4**, the firewall **L1**, hosts/name resolution **L2**
    (they already were), guard/canaries/correlation **L3** — and the intro now spells
    the mapping out and says why §2/§3/§4 keep their numbers (other documents,
    including the register, cite them).
  - **Nothing linked to it.** README's five-layers table is the short version; it now
    ends by pointing at the matrix and saying the numbers are the same in both.
  - Re-read for staleness: the only sentence that had drifted was the VirusTotal one,
    already fixed in step 2 (D-019). The rest matches the code — starter pack size
    (6 guard + 10 YARA), an opt-in scheduled scan (D-027), polling canaries, `netsh` firewall, no
    ClamAV/CAPA, and §10's evidence table names a real probe for each claim.

- **Small step 6 — the icon pass was already there; it is now verified and recorded**
  - The step asked for `test/icon_test.dart` plus the `app_icon.ico` size set. Both
    already existed (the test was written with the icon pipeline), so this step is the
    measurement that proves them, not new code: `flutter test --no-pub
    test/icon_test.dart` → **6 assertions pass**.
  - What those assertions actually pin: the ICONDIR table of all three `.ico` files
    must equal exactly **{16, 20, 24, 32, 40, 48, 64, 96, 128, 256}** (a lost frame
    fails; `equals` rather than "contains", so an extra or missing size is a
    failure), `app_icon.ico` and `assets/icons/mics.ico` must be **byte-identical**
    (one task art, no drift), `desktop.ico` must **differ** from it (otherwise
    shipping it is pointless), and the four source/render inputs
    (`task.svg`, `Desktop.svg`, `task.png`, `Desktop.png`) must exist.
  - README's icon section already listed the ten sizes; it now also records the
    measured result and the fact that the test fails the build on drift, so the claim
    and the check sit next to each other.

- **Small step 4 — dark mode is contrast-audited, fixed, and frozen (7 of 29 failed)**
  - Mirroring أ2/أ3 for light: the dark palette was **measured first** with the same
    29 pairs the UI actually paints — palette tokens as text on the page and on a
    card, the card border, the accent fills, `onPrimary`/`onSecondary`/`onError`,
    both snackbar rows read back out of a rendered `SnackBar`, the nav-rail icons,
    and the tinted banners composited with `blendOver`. **7 of 29 were below their
    WCAG bar**, and the card is the binding surface in dark mode (the lighter of the
    two, the mirror of light mode where the page bound).
  - The failures and their ratios: border `#1E293B` 1.32:1 on the page / 1.21:1 on a
    card; secondary text `#64748B` 4.06:1 / 3.73:1; declared `onError` (`#FFFFFF` on
    `#F43F5E`) 3.67:1; the settings error bar (85 % red over the dark page) 3.92:1;
    the block-action badge (red on red 15 %) 4.19:1.
  - The fix, dark tokens only: `border` → `#5C6C80` (3.60 / **3.31** — the dimmest
    slate that clears 3:1 on the card), `muted` → `#788AA0` (5.47 / 5.02), `red` →
    `#FB5F7B` (6.47 / 5.94, and it carries the badge to 4.91 and the translucent bar
    to 4.76), and `colorScheme.onError` takes the page colour in dark mode (6.47:1),
    as `onPrimary`/`onSecondary` already did. `background` was deliberately left at
    `#0A0E14` because `AppTheme.isDark` compares exactly that literal.
  - **Two screens were painting a pair no audit could see** (the same class of bug
    the light audit found): `guard_screen.dart` (Start/Stop Guard) and
    `hardening_screen.dart` (Fix) forced `foregroundColor: Colors.white` over the
    green/red fill — 1.92:1 and 2.99:1 in dark mode. They now use
    `AppColors.background`, the token `filledButtonTheme` already paints on a filled
    button: 10.06:1 / 6.47:1 dark, and light goes 7.68→7.15 / 6.29→5.85 (still
    passing, `#FFFFFF`→`#F4F7FB`).
  - **The two audits now share `test/contrast_audit_harness.dart`** (pair type, bars,
    hex, the finding builder, the real-`SnackBar` painter and the registrars), so
    they cannot drift in what they measure. Equivalence was proved rather than
    assumed: the light table was captured before the refactor and diffed after — 32
    printed lines, byte-identical, so light's frozen numbers did not move.
  - Verified: `flutter test --no-pub` **72 passed** (65 + 7 new dark tests), both
    audits print `29 of 29 pairs clear their bar`, `cargo test` 82 passed,
    `clippy --release -D warnings` clean, `flutter analyze` no issues. README's test
    counts were stale (51/31) and are now 82/72, plus a paragraph per language saying
    contrast is measured in both modes.

- **Small step 3 — the Start-Menu name question is closed (D-020)**
  - The open question was whether the Start-Menu shortcut should be renamed `MICS`
    to match the desktop one. Answer: **no** — it stays `MI CS`, because that is
    both the name the product uses about itself and the source label Windows'
    notification settings show (`scripts\register-aumid.ps1` writes
    `DisplayName "MI CS"`); renaming the shortcut would file the same app under two
    labels in the two places a user looks for it.
  - Written down as **D-020**, which also records the rule behind the split
    (`MI CS` = the product, `MICS` = the search-and-folder token), that nothing in
    `settings.json` names the product, and that the names are held in place by two
    probes rather than by convention: `verify-aumid.ps1` reads the registered label
    back and `verify-release.ps1` fails when either binary's `FileDescription`
    drifts.
  - Documentation only — no code, no build, no new file. `README.md` now says why
    the two shortcuts differ on purpose (both in the naming section and in the icon
    section), and the §0.0 naming table points at D-020.
  - Checked before writing, measured rather than assumed: the real desktop is the
    OneDrive one (`C:\Users\<account>\OneDrive\Desktop`) and holds `MICS.lnk`
    → `%LOCALAPPDATA%\MI CS\mics_app.exe`; the Start Menu holds `MI CS.lnk`; and
    `HKCU\Software\Classes\AppUserModelId\MICS` reads `DisplayName = MI CS` with
    `IconUri` = the same exe. All three already matched the frozen table, so
    nothing was corrected — only recorded. (A leftover `MI CS test.lnk` still
    points at the `%LOCALAPPDATA%\MI CS test` copy used for A/B runs; it is not
    part of the product's naming.)

- **Small step 2 — the dead VirusTotal client is gone, and the product says so (D-019)**
  - What the code lost: `engine\src\scanner\vt.rs` (124 lines), the `vt_api_key`
    setting with the `MICS_VT_API_KEY` test hook, the `sync_queue` table and the
    four storage calls that served it (`queue_op`, `pop_queue_ops`,
    `remove_queue_op`, `queue_len`), the sync pass's queue flush, the
    `vt_queue_len` field of the sync report, the Settings → Integrations field
    with its two i18n entries and the typed mirror — 227 lines deleted, 10 added,
    the largest share of it code that nothing could reach.
  - **Why delete instead of wiring it:** the client was unreachable by
    construction — only the offline queue could call it and nothing filled that
    queue — so what shipped was a settings field, an outbound destination, a table
    and a sync-status column that made the scanner look more capable than it is.
    The user chose deletion on 2026-10-31; D-019 records it, including what would
    have to come back with it (a §B6 destination row, the F-5 masking story and
    the UI field that names the key).
  - **Documents moved with the code, in the same commit:** `README.md` (English
    "does not" list, requirements network row, privacy paragraph; Arabic
    equivalent), `docs\THREAT-MODEL.md` (asset A7 and residual risk F-5 shrink to
    two keys; the §B6 destination table loses its `virustotal.com` row and says
    why nothing can reach one; `MICS_VT_API_KEY` leaves the B9 hook list),
    `docs\COST.md` (§3 now says there is no client and no key at all),
    `docs\PROTECTION-MATRIX.md` (the hash dimension explains the absent client
    instead of a queue nothing fills), `AGENTS.md` rule 8's outbound-traffic list,
    and this file.
  - **Verified:** the four checks are green (cargo test **82 passed** — the deleted
    module carried no tests of its own, and two settings assertions went with the
    field; `flutter test` 65; `flutter analyze` and `clippy --release -D warnings`
    clean), and after the commit a grep for any VirusTotal symbol outside the
    documents that explain its absence returns nothing.

- **`readonly database` and "helper not answering" were one bug: a Low-integrity build**
  - The report: clicking **Settings → Engine → Install/Repair** answered
    `helper.install failed: the privileged helper is installed but not answering
    (state-running, reachable-false)`, and the intelligence button answered
    `sync.now failed: attempt to write a readonly database: Error code 8`. On the
    same machine, from the same shell: `mics.db` accepted `BEGIN IMMEDIATE` and
    `sc query MICSHelper` said `RUNNING`.
  - Cause, measured: the engine the UI was attached to was
    `dist\MICS-portable\mics-engine.exe` (integrity `0x1000`), while the app was
    `0x3000`. The workspace root `MIF` carries
    `Mandatory Label\Low Mandatory Level:(OI)(CI)(NW)`, every folder created under
    it inherits that label, and Windows starts a process at the label of its image
    — so anything launched from `dist\` or `build\windows\...\Release\` runs
    **Low**. A Low process may not write a Medium object: SQLite reports
    `SQLITE_READONLY` ("attempt to write a readonly database") for the state
    directory, and LocalSystem's helper pipe refuses the Low client at its access
    check, which the engine reports as `reachable: false`. Same binary, one second
    apart: `mics-engine.exe helper-status --json` from `dist\` →
    `reachable: false`; from `%LOCALAPPDATA%\MI CS\` → `reachable: true`,
    version `0.1.0`, `elevated: true`.
  - The app made it stick: it attaches to whichever engine owns
    `\\.\pipe\mics_engine`, so one leftover Low engine served every later UI
    session (an elevated app showing a readonly database was the tell). Stopping
    that engine made the app start a healthy one from its own folder, and
    `sync.now` then succeeded (76,737 blocked names, 1,766 KEV CVEs) and
    `helper.status` returned `reachable: true`.
  - Fixed in code, three parts: `platform::windows::integrity` reads the process
    label; the engine **refuses to serve** below Medium and names the folder it
    was started from (`MICS_ALLOW_LOW_INTEGRITY=1` and the helper-inspection
    commands stay usable — that is what `verify-pipe-acl`, `verify-toast` and
    `measure-guard-cpu` need); and the two misleading messages now carry the
    measurement: a `SQLITE_READONLY` RPC error appends the data directory and the
    repair (`storage::sqlite::readonly_hint`, wired into `detailed_error`), and
    `wait_until_reachable` names the integrity level. `cargo test` covers the
    guard's command allow-list and the readonly hint.
  - Why the wording was the real damage: "readonly database" sends the user to the
    database and "not answering" to the service — neither was broken, and the one
    actionable instruction ("run the installed copy, not the folder under
    `www\`") was in the docs only.

- **A from-scratch Windows build works again (found by asking for a clean copy)**
  - Asking for "a complete clean copy" meant `flutter clean` for the first time in
    this tree, and it failed **twice** on things no previous build could show —
    every build so far had reused a configure from before:
  - **The install prefix was unwritable.** CMake's default is
    `C:/Program Files/<project>`, and `windows\CMakeLists.txt` trusted Flutter's
    template guard `CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT` to replace it with
    the bundle next to the exe. **CMake 4 no longer sets that variable** (the
    toolchain here is `cmake version 4.2.3-msvc3`), so on a fresh configure the
    prefix stayed the default and the install step died with
    `MSB3073 ... VCEnd exited with code 1`, whose real text is
    `file cannot create directory: C:/Program Files/mics_app. Maybe need
    administrative privileges`. The guard now compares against the value it wants
    to replace, which works on CMake 3 and 4 and still lets an operator-supplied
    prefix win.
  - **`nuget.exe` was missing from PATH.** Nothing in this repo needs it, but
    `audioplayers_windows` fetches `Microsoft.Windows.ImplementationLibrary` at
    configure time, and CMake's `find_program(nuget)` found nothing, so the
    configure failed with `Failed to install nuget package
    Microsoft.Windows.ImplementationLibrary.1.0.260126.7`. A stale
    `%TEMP%\NuGetScratch\lock` left by an earlier crashed NuGet made the first
    attempt look like a permissions problem. `make-release.ps1` now fetches
    `nuget.exe` into `%TEMP%\mics-tools` and prepends it to PATH when the build
    needs it (nothing is added to the repo, and the package is not shipped).
  - Proof: with a cleaned Flutter tree the release rebuilt end to end — 69 files
    (the old 71 included two leftovers from the unclean build directory, not
    anything missing: `sbom.cdx.json` and `THIRD-PARTY-NOTICES` are both in the
    package at 292,280 and 76,317 bytes), engine `C9FEFDD5...`, every binary
    `Valid`, and `verify-release.ps1` passed **13/13** including reading the
    inventory back out of the zip, the helper protocol from the package, and a real
    desktop card.
  - Why this matters beyond this machine: **a fresh clone could not build**. These
    two files are the difference between "works on my machine" and "works after
    `git clone`".

- **The service's own `binPath` had the same bug — and a test was guarding it (P1.5, second fix)**
  - With the install button fixed, the elevated step got further and **created**
    the service, which then refused to start: `sc start failed: [SC] StartService
    FAILED 1053`. The reason was already written down, by the first fix, in the
    helper's own log (`%PROGRAMDATA%\MICS\logs\engine.log` — where a LocalSystem
    helper resolves its data directory):
    `command line refused: error: unexpected argument '--helper-service' found`.
    `service::bin_path()` was building `binPath` as `"<exe>" --helper-service`: the
    same flag-for-a-subcommand mistake, one layer deeper.
  - **The older test made it worse, not better.** `service_definition_quotes_the_install_path`
    asserted the exact broken string, so it stayed green and every reader saw a
    tick for a definition that could never run. It now asserts the *shape* — the
    built `binPath` contains no `--` at all, and ends with the subcommand constant
    — and it builds its expectation from `privileged::SERVICE_COMMAND` instead of
    a literal, so test and code cannot disagree.
  - `SERVICE_COMMAND` sits next to `INSTALL_COMMAND`/`UNINSTALL_COMMAND`, and both
    CLI tests now cover all three commands: each must be accepted by the real CLI,
    and each flag spelling is proven to be refused as an unknown argument.
  - Measured cost of the whole class: one dead install button, one service that
    could not start, and every privileged operation (firewall, hosts, hardening)
    behind them. What finally surfaced it was the instrumentation added by the
    first fix — the hidden child's refusal now lands in a log file instead of
    being an exit code — and what would have caught it a day earlier is a test
    that asserts shape rather than a literal.

- **The money question is answered on paper (ب1b, `docs\COST.md`)**
  - Today MI CS costs **nothing** to run or ship, and that is written down name by
    name (toolchains, packaging, local self-signing, free RFC 3161 timestamping via
    `scripts\sign.ps1`, our own rule packs, the user's own Defender as the real-time
    layer, the user's own intel keys, static hosting, the SBOM tool). Two of those
    are design decisions that are also cost decisions and are now named as such: no
    telemetry/cloud means no backend bill, and using what Windows already has means
    no AV or EDR licence.
  - **The one purchase** is a CA-issued code-signing certificate, because without it
    a stranger's Windows says "Unknown publisher" (measured: the release probe prints
    `signed : NotSigned - Windows will show 'Unknown publisher'...`).
  - The document earns its keep by recording the four constraints that decide *how*
    that certificate can be used, and two of them change code. Under the CA/Browser
    Forum's baseline (June 2023) the private key must live in hardware (token) or a
    cloud service, so **`-PfxPath`/`-PfxPassword` stops being usable** with a
    compliant certificate: the working path is `scripts\sign.ps1 -Thumbprint <sha1>`
    (added 2026-11-06, D-034 — this summary originally claimed that path "is already
    in the repo", which was false until that commit, and Certum's cloud manual
    documents exactly that call). And the publisher CN is pinned by D-016, which
    **cannot survive a real certificate**: CSCBR §9.2.2 requires the subject CN to be
    the verified legal name, so the pin moves to a thumbprint in the same release
    (`docs\OPEN-DECISIONS.md` item 3). Timestamps keep old releases valid after
    renewal, and the 2026-03-01 change caps a certificate at 460 days.
  - Prices **are** quoted as of 2026-11-06, each with its source and the day it was
    read, because "the price moves" turned out to be a reason to date the figure
    rather than to omit it. The options table is Microsoft's own comparison (OV
    $150–300/year, EV $400+/year and **no longer an instant SmartScreen bypass since
    2024**, Azure ~$9.99/month and **not purchasable by an individual outside the
    USA/Canada**), plus the routes that exist for this maintainer: Certum's Open
    Source certificate at €49/year in their cloud (CN becomes "Open Source
    Developer <name>"; it signs only with a logged-in SimplySign session, so it wants
    a persistent runner) and SSL.com IV at $129/year plus $180/year eSigner (their
    action signs on GitHub-hosted runners). **SignPath Foundation's free route is
    closed to this product category**: their code of conduct excludes "security
    diagnosis tools that actively scan for and highlight exploitable vulnerabilities,
    e.g. by identifying unprotected network ports", with a carve-out only for
    malware/breach *detection*, and independently requires an already-released
    project with a verifiable reputation. Reframing the product to slip past that
    policy is not on the table.
  - `docs\COST.md`'s §5 is the ب5 checklist, and §3 lists what is deliberately not
    bought (no telemetry backend, no AV/EDR licence, no cloud sandbox, no paid rule
    feed, no update server, no CDN).

- **The elevated install called a flag the CLI does not have (P1.5, first fix)**
  - Pressing **Settings → Engine → Install helper** only produced an error. The
    engine's `privileged::install()` launched `run_elevated(&exe, ["--install-helper"])`,
    but the CLI defines `install-helper` as a **subcommand**: clap answered
    `error: unexpected argument '--install-helper' found` and exited **2** before the
    child reached its first log line. Reproduced against the shipped exe:
    `--install-helper` → exit 2; `install-helper` → starts, logs
    `mode=install-helper`, and refuses cleanly when unelevated. The same call is the
    one every privileged operation goes through (`privileged::ensure()`), so
    firewall, hosts and hardening were all dead in D-007's build — while
    `scripts\verify-helper.ps1` stayed green, because it exercises the helper
    *console* path and never this argument. **This is the "still unproven" line in
    D-007's own entry.**
  - Fixed by naming the two commands once (`privileged::INSTALL_COMMAND` /
    `UNINSTALL_COMMAND`, no dashes) and by two tests that parse exactly those strings
    with the real CLI: one requires them to be accepted, the other requires the flag
    spelling to be refused as an unknown argument, so the two cannot drift apart
    again.
  - Second hole, same bug: the elevated child's stderr goes to a console the engine
    hides (`SW_HIDE`), so **nothing at all** was written to
    `%LOCALAPPDATA%\MICS\logs\engine.log` and the UI could only show "the elevated
    step failed (exit code 2)". `main()` now logs whatever a command decided, and a
    refused command line goes through `Cli::try_parse()` and is logged before clap
    exits; exit codes are unchanged.
  - Third: the UI asked for the install with the client's 120 s default while the
    engine allows the child 180 s to let the user read one prompt; the two helper
    calls now pass 240 s explicitly.
  - Evidence in this commit: `cargo test` 78/78 (76 + the two new), the four checks
    green, and the release rebuilt and signed. The end-to-end install with a real
    UAC click ran on **2026-11-07** — the result, including the slice it deliberately left
    unexercised, is the record under §0.2 item 1 and the block after §0.6's table.

- **What is inside the package is written down, generated and checked (ب1a)**
  - The register had a HIGH row for "no SBOM and no third-party notices", so
    `tool\sbom.dart` now builds both from what is already pinned: `sbom.cdx.json`
    (CycloneDX 1.6) and `THIRD-PARTY-NOTICES` (Markdown). Its inputs are
    `cargo metadata --locked --offline` (each crate's *declared* SPDX expression,
    checksum and source directory), `pubspec.lock` plus `dart pub deps --json` (each
    Dart package, its sha256, and whether it is in the runtime closure), the Flutter
    SDK's own `LICENSE`, the two shipped fonts, and four entries no lockfile
    mentions: Cairo, JetBrains Mono, `flutter_windows.dll`, and the Visual C++
    runtime the app needs but does not ship (`scope: excluded`, named rather than
    given an invented SPDX id).
  - **Measured on this machine (2026-10-31): 579 components** — 483 Rust crates, 87
    Dart packages, 6 Flutter SDK packages, 2 fonts, 1 not-shipped runtime — of which
    **541 ship** and 38 are dev- or build-only. **8 licenses** are relied on
    (MIT 444, BSD-3-Clause 73, Apache-2.0 35, Unicode-3.0 18, Zlib 3, ISC 2,
    OFL-1.1 2, CDLA-Permissive-2.0 1) with **0 copyleft, 0 unclassified and 0
    missing texts**. The only copyleft-flavoured expression in the tree is
    `r-efi`'s `MIT OR Apache-2.0 OR LGPL-2.1-or-later`: `OR` offers a named
    permissive option, and the notices say that is the one we take.
  - A deliberate choice is what gets reported, not what a human felt like: an SPDX
    evaluator handles `OR`/`AND`/`WITH`/parentheses and the legacy `MIT/Apache-2.0`
    spelling, and picks the option from a fixed preference list (MIT first) so
    `MIT OR Apache-2.0` and `Apache-2.0 OR MIT` conclude the same id. An id that is
    neither permissive nor copyleft fails the audit, so a dependency with an
    unfamiliar license stops the release (D-018).
  - The two files are committed, are copied into the package by
    `make-release.ps1` (which now
    refuses to start when `dart run tool\sbom.dart --check` says they no longer
    describe the lockfiles) and are read back **out of the zip** by
    `verify-release.ps1`, which also checks that every component names a license
    and that the notices report a clean audit. `test\sbom_test.dart` (22 tests)
    re-derives the component set from `Cargo.lock` + `pubspec.lock` and fails when
    the committed pair drifts, so a dependency bump and its notices travel in one
    commit.
  - `assets\fonts\OFL-1.1.txt` filled a real compliance gap: the two fonts are OFL
    1.1 and shipped no license text at all, and no font binary carries one. Their
    copyright lines were read out of the `.ttf` `name` tables, not guessed.
  - The output carries no timestamp and its BOM serial number is derived from the
    sorted coordinates, so two runs over the same lockfiles are byte-identical: a
    diff in the committed file means a dependency changed and nothing else.
  - Proved end to end, not just in the generator: `make-release.ps1` was run with a
    deliberately corrupted `sbom.cdx.json` and **stopped before building** (exit 1,
    `dist` untouched), then regenerated and run for real — the package came out with
    **71 files** (69 + the two inventory files), and `verify-release.ps1` passed all
    13 of its checks, including reading the inventory back **out of the zip** and
    confirming CycloneDX 1.6, 579 components, a license on each, and a clean audit.
  - One real bug came out of that: `Future<int> main()` does **not** set a Dart
    process's exit code (`dart:io`'s `exitCode` does), so the first version of the
    release gate passed while the tool was reporting a stale file. The tool now sets
    `exitCode`, prints `RESULT: PASS/FAIL`, and `make-release.ps1` reads the line as
    well as the code (trap 18).
- **Windows names the notification source "MI CS" now, and a probe reads it back (أ4)**
  - The engine has always raised cards under AUMID `MICS`; what Windows *calls* that
    source comes from a registration nobody was doing, so the Action Center and
    Settings → Notifications showed the raw id. `scripts\register-aumid.ps1` writes
    `HKCU\Software\Classes\AppUserModelId\MICS` (`DisplayName "MI CS"`, `IconUri` =
    the app's own exe) and tags both shortcuts with `System.AppUserModel.ID = MICS`.
    No elevation and no new file - it is the user's own hive and the user's own
    shortcuts - and `-Remove` puts both back.
  - Measured, not asserted: `scripts\verify-aumid.ps1` reported **4 problems** before
    the change (no key, neither shortcut carrying an id, and `Get-StartApps` filing
    "MI CS" under the *exe path*) and **5 of 5** after, including the Shell's own
    start-menu index reporting AppID `MICS`. `-Remove` was run for real and reversed
    the three checks that depend on it, then the registration was put back. That is
    why it is a script: a registry key and a shortcut property that cannot be undone
    are just another thing to forget.
  - The shortcut property is a Shell property, not a WScript field, so
    `create-shortcuts.ps1` (WScript.Shell) cannot write it: the interop lives in
    `scripts\aumid-interop.ps1` (IPropertyStore) and both scripts dot-source it, so
    the writer and the reader cannot drift apart. Two things the run taught:
    `InitPropVariantFromString` is **not** exported by `propsys.dll` on this build
    (`EntryPointNotFoundException` - the PROPVARIANT is built by hand instead), and
    the start-menu index lags a changed shortcut by about **5 s**, so the probe waits
    for it instead of failing on the cache.
  - Delivery is unchanged, and that was re-proven rather than assumed: with the AUMID
    registered, `scripts\verify-toast.ps1` reports PASS with the card
    "🛡️ MI CS — إشعار تجريبي" in Windows' own notification history. The card was
    rebuilt from the runnable copy in `%LOCALAPPDATA%\MI CS` (medium integrity),
    which is where a card can be raised at all (trap 16).
  - Honest limits: the probe proves the fact Windows *reads* the label from, not the
    pixels of the Settings page - nobody looked at that screen. And registration is
    per-user and per-machine, so a fresh install needs the script again: **ب3** folds
    it into the installer, where NSIS can write the key with `WriteRegStr` but not
    the shortcut property, so the installer will have to call this script (or a
    helper) rather than only touching the registry (done in ب3 step 2: the installer unpacks the script into `$PLUGINSDIR` and calls it once per shortcut).
  - The register's AUMID row is now a smaller, different risk: a *forged* card is
    labelled "MI CS" too. That is written into `docs/THREAT-MODEL.md` §B10 - the
    label was never proof, and it now looks more convincing while proving the same
    nothing.
  - Checks: `cargo test` 76/76, `cargo clippy --release -- -D warnings` clean,
    `flutter analyze --no-pub` clean, `flutter test --no-pub` 43/43 (this step adds no
    Dart and no Rust, so those two are unchanged by it).

- **the light palette now clears WCAG 2.2 on every pair it paints (أ3)**
  - أ2 measured 36 pairs and 25 failed. This step repainted the palette so the
    audit's own table passes — **29 of 29** rows above their bar — and turned each
    ratio into an assertion (`test/light_contrast_audit_test.dart`), so the numbers
    in `docs/CONTRAST.md` are a floor now, not a report.
  - The five changes, worst first: **the invisible message** — `intel_screen.dart`
    overrode only `backgroundColor`, so the success snackbar kept Material's white
    text on a white bar (1.00:1); it now overrides the background only for the
    failure case, and the success bar keeps the theme's colours (21.00:1).
    **Borders became boundaries** — `#DDE4EE` → `#74849B`, 1.19:1 → 3.54:1 on the
    page and 3.81:1 on a card, still lighter than Material 3's own `outline`.
    **The accent hues moved to their 700/800 shades in light mode** (cyan
    `#0E7490`, green `#065F46`, red `#BE123C`, orange `#B23A0B`) because they are
    used as 10–13 px text: the worst went 3.31:1 → 5.58:1, and the filled button
    (`#F4F7FB` on cyan) went 3.43:1 → 4.99:1 as a side effect. **The severity
    colours stopped being literals** — `AuditFinding.statusColor`/`severityColor`
    and `cvssColor` read the palette now, and the palette gained the one token they
    needed (`yellow`: `#B45309` light, `#EAB308` dark), which is why "Secure"
    green went 1.79:1 → 7.15:1. **The tinted banners pass too** (orange on
    `red 8 %` 3.14 → 5.23; the two badges 3.70 → 4.84 and 3.14 → 6.04).
  - Dark mode is deliberately untouched and unchanged: the literals it was getting
    *were* the dark tokens, so its look is identical. It is also still unmeasured —
    the register row now says so with the number that matters (its border is
    1.36:1 against the 3:1 a boundary needs) instead of implying the whole theme is
    now audited.
  - What is asserted, not just measured: the palette pin (a token change forces a
    re-measure), token coverage (a new colour cannot appear unmeasured), "the
    severity getters return palette tokens" (this is what catches a literal
    creeping back), and each of the 29 ratios. The two snackbar rows are still
    read out of the render tree, not out of the framework source.
  - Honest limits: the table shrank 36 → 29 rows because ten literal rows collapsed
    into the palette rows that now cover them; the palette was verified
    numerically, **not** visually (the running copy is the installed one under
    `%LOCALAPPDATA%`, and a screenshot would not prove a ratio anyway) — the
    screenshots item stays open; and the *dark* palette is a separate job.
  - Checks: `cargo test` 76/76, `cargo clippy --release -- -D warnings` clean,
    `flutter analyze --no-pub` clean, `flutter test --no-pub` 43/43 (1 new).

- **the light palette is measured now, and 25 of its 36 pairs fail WCAG (أ2)**
  - The register said the light palette had never been contrast-audited, so it is
    measured rather than eyeballed: the WCAG 2.x formula
    (`lib/core/theme/contrast.dart`) over every colour pair the UI actually paints,
    printed as a table by `test/light_contrast_audit_test.dart` and written down in
    `docs/CONTRAST.md`. **36 pairs, 25 below their bar** (4.5:1 for text, 3:1 for
    large text, boundaries and icons).
  - What the numbers corrected about the assumption behind the task: this is not "the
    light theme is a little washed out". The worst pair is **1.00:1** — the success
    snackbar in `intel_screen.dart` overrides only `backgroundColor`
    (`AppColors.surface`) and leaves Material's default text colour, which is white
    in this theme, so that message is invisible. The rest is systematic: card and
    input borders at 1.19:1/1.28:1 (a boundary needs 3:1), the accent hues as the
    10–13 px text the UI uses them for at 3.31–3.77:1, and the severity colours
    `audit_models.dart` hardcodes at 1.78:1–1.92:1 on the page because they are the
    *dark* tokens returned in both modes. What passes is on the record too: body text
    16.61:1/17.85:1, secondary text 5.07:1/5.45:1, white on the error red 4.70:1,
    red on a white card 4.70:1, and both rail icons over their 3:1 bar.
  - The two rows that could have been paper claims are not. The snackbar row is
    proven by rendering the real `SnackBar` with that screen's own background and
    reading the painted colour back out of the render tree
    (`RenderParagraph.text.style.color`) — that is what makes 1.00:1 a measurement
    instead of a reading of the framework source. Tinted banners are composited
    first (`blendOver`), so `red 8 %`, `red 15 %` and `green 15 %` are measured as
    the colours they really are.
  - Honest scope: this step measures, it does not repaint. The assertions that pin
    each ratio arrive with the palette fix in step **أ3**, so this table is the
    "before" that step has to beat — and the audit already enforces two things: every
    palette token, and every colour `statusColor`/`severityColor`/`cvssColor` can
    return, must appear in a measured pair, so a new colour cannot be added
    unmeasured. Dark mode is **not** audited, and there are still no screenshots.
  - Checks: `cargo test` 76/76, `cargo clippy --release -- -D warnings` clean,
    `flutter analyze --no-pub` clean, `flutter test --no-pub` 42/42 (6 new).

- **The plan for the next sessions is written down, and the stale P5 row fixed**
  - §0.0 tells a fresh session what to paste — `اقرأ docs/TODO.md §0 وابدأ من أ2` — and
    repeats the working rules it must keep: one small step per turn, one conventional
    commit per step with this file updated in the same commit, the four checks green
    before every commit, Egyptian Arabic to the user and English in the artifacts, and
    isolated env vars for any live probe.
  - §0.3 replaces the loose "big phases" bullets with the ordered roadmap: **أ** close
    §0 (contrast audit → fix → AUMID), **ب** P4 (SBOM/notices/cost, ARM64 leg, NSIS
    installer, helper folded into it, certificate, public release), **ج** P5 (build
    hardening, signed SHA-256 manifest + self-check banner, README rewrite), **د** P6
    (QA harness → widget tests → E2E → report), **هـ** the P3 remainder (default update
    manifest + signature check) and **و** the 21-row register, each row marked with
    whether it needs the user. §0.1 now carries the same step names (أ2 first).
  - The phase table said P5 was "planned" while `docs/THREAT-MODEL.md` and
    `docs/PROTECTION-MATRIX.md` exist and F-1…F-4 are closed on measured evidence;
    the row now says partly done and lists what is left (ج1–ج3). The resume header
    points at the real HEAD (`24079de`) instead of a commit from several phases ago.
  - Documentation only, no code: the four checks were run anyway and stayed green
    (`cargo test` 76/76, clippy clean, `flutter analyze` clean, `flutter test` 36/36).
- **The guard's pid diff is one `EnumProcesses` call now, and the cost is 0.156 % of a core**
  - `platform/windows/pids.rs` lists the pids in a single kernel call (with the
    buffer-too-small retry the API asks for), and the guard uses it instead of
    `sysinfo`'s full snapshot: 0.156 % of one core / 0.0028 % of this 56-thread
    machine, down from 1.56 % / 0.03 % and from 3.52 % at the start. `sysinfo` still
    reads command line, image path and parent — for the new pids only — and its map is
    pruned with one full snapshot every 900 ticks (~30 min) because
    `ProcessesToUpdate::Some` only ever adds. If `EnumProcesses` fails the loop warns
    and falls back to the old snapshot for that tick rather than going blind.
  - The differential probe had a bug worth recording: it set `MICS_RULES_DIR` to
    `<scratch>\rules`, but `guard::rules_dir()` appends `rules\guard` to whatever it is
    given, so every earlier run measured the **shipped starter pack** instead of the
    inert rule — six rules, real alerts (one popped a Windows toast at the user) and
    the `kill` action armed. Fixed: the variable points at the scratch root, the header
    says why, and `-RealRules` exists for anyone who wants that configuration on
    purpose. The numbers above are with the inert rule, confirmed in the engine log
    (`1 rule(s) from ...\rules\guard`).
  - With the budget met under both readings (0.156 % of one core, 0.0028 % of the
    machine), §0.1 no longer carries this item; the `benchmark` fix from the previous
    commit is what makes `budget_ok` trustworthy.
- **`benchmark` no longer measures itself (the 2.97 % was an artefact)**
  - `mics-engine benchmark` sampled `sysinfo` while refreshing **every** process six
    times in three seconds, then compared the result against 1 %. Run with
    `MICS_NO_GUARD=1` it reported **9.94 %** for a process that was idle — so a large
    part of the old "2.97 %" was the probe, not the engine. The guard's real cost is
    the differential in `scripts\measure-guard-cpu.ps1`, which is where the 1.56 % /
    0.03 % numbers come from.
  - The measurement is now one idle window (3 s) bracketed by two reads of this
    process's own kernel+user time (`GetProcessTimes` in `platform/windows/timing.rs`),
    with RAM read by refreshing only this process
    (`ProcessRefreshKind::nothing().with_memory()`). Nothing inside the window does
    work that the window would then charge to the engine.
  - Two numbers are reported, because "1 %" without a denominator is meaningless:
    `cpu_percent` (share of one core, the profiler scale) and
    `cpu_percent_of_machine` (Task Manager). **The budget compares the machine
    figure**, and `budgets.idle_cpu_basis` now says so in the JSON, together with
    `guard_measured_by` pointing at the script, because the guard loop lives in the
    long-running service process and not in this one.
  - Measured after the change: `cpu_percent: 0.0`, `cpu_percent_of_machine: 0.0`,
    `ram_mb: 12.5`, `budget_ok: true`, `cores: 56`. A new test
    (`cpu_time_grows_when_this_thread_works`) pins the counter: a busy loop must show
    up in `GetProcessTimes`. `cargo test` 74/74.
- **The guard's CPU cost is measured, not assumed (first step)**
  - `scripts\measure-guard-cpu.ps1` runs the engine twice — guard on, then with
    `MICS_NO_GUARD=1` — in isolated data/pipe/rules dirs, samples
    `TotalProcessorTime` over a wall-clock window and prints both definitions:
    percent of one core and percent of the machine (the Task Manager one).
  - Baseline on this machine (56 logical processors): **3.52 % of one core,
    0.06 % of the machine**. That reframes §0.1's "2.97 % against a < 1 % budget":
    the recorded figure was a per-core number, and on this machine the guard was
    already 0.06 % of total CPU. The budget line needs that definition spelled out.
  - Cheap win found by reading the loop instead of guessing: with ETW live it
    refreshed every process **every second** just to service the canary check, and
    the unelevated path fetched command lines, image paths and parents for all
    processes on every tick even though only *new* pids are matched. Now the sweep
    is skipped entirely once ETW is live (after the one initial sweep that catches
    processes started before MI CS), and the poll refreshes pids cheaply
    (`ProcessRefreshKind::nothing()`) with the expensive reads done only for new
    pids. Re-measured: **1.56 % of one core, 0.03 % of the machine** — a 56 % cut.
  - What is still on the table: the unelevated poll enumerates every process every
    2 s. `EnumProcesses` for the pid diff and a 3 s tick are the next candidates;
    the register entry and §0.1 say so instead of claiming the budget is met.
- **The helper answers only the installer's account, not merely the engine's name (F-2b)**
  - F-2a proved *which program* is calling; it could not tell *which user*, so a
    standard user could copy `mics-engine.exe` and drive SYSTEM. The caller's token
    user SID is now read (`OpenProcessToken` + `GetTokenInformation(TokenUser)`) from
    the same process handle as the image path, and compared with the owner SID of
    `%PROGRAMDATA%\MICS` — the account the elevated installer created it as.
  - `judge()` is the decision table and is unit-tested without any Windows call: image
    + SID match → allowed; image match + other SID → `NotTheInstaller(sid)`; wrong
    image → `NotTheEngine` whatever the SID says; no recorded account → image check
    alone; unreadable SID → not treated as a different user. The helper logs the
    refused pid, image and SID, and answers `this pipe only serves the account MI CS
    was installed for` in-band.
  - Real measurement, not a claim: `the_owner_of_a_directory_is_the_sid_of_this_process`
    creates a temp directory, reads its owner SID with `GetNamedSecurityInfoW`, reads
    this process's token SID, and asserts they are the same `S-1-5-...` string. The
    multi-user negative is unit-tested only — this machine has a single interactive
    account, so there is no second user to log in as.
  - `cargo test` 73/73 (7 caller tests). Live: `scripts\verify-helper.ps1` still
    `RESULT: PASS` (script user == installer account), and an unnamed PowerShell client
    is still refused.
  - Residuals recorded instead of hidden: a process running *as the installing user*
    can drive the helper (D-007's accepted trade — that user can answer UAC himself),
    and a portable run with no `%PROGRAMDATA%\MICS` has no account to compare, so it
    falls back to the image check with a warning (LOW in the register).
- **The helper checks who is calling before it runs anything (F-2a)**
  - The pipe still grants `INTERACTIVE` (D-007), so the helper now asks. On every
    accepted connection it reads the client pid with `GetNamedPipeClientProcessId`,
    opens that process and reads its image path with `QueryFullProcessImageNameW`,
    and keeps the handle open while the path is read so the pid cannot be recycled
    underneath the check (`platform/windows/caller.rs`).
  - Authorised: an image named `mics-engine.exe` (case-insensitive), or a path equal
    to `MICS_ENGINE_PATH` — the hook the installer records and the one the
    verification scripts use to name themselves. Anything else gets
    `{"ok":false,"error":"this pipe only serves the MI CS engine"}` after its request
    line arrives, a `WARN` naming the refused image, and **no** audit entry: it never
    reaches validation.
  - Measured live on this machine: a PowerShell client was refused
    (`privileged helper refused C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
    the in-band JSON came back, and `scripts\verify-helper.ps1` still prints
    `RESULT: PASS` once it names itself through `MICS_ENGINE_PATH` (the recipe in
    `docs/PRIVILEGED-OPS.md` shows both sides).
  - 70/70 `cargo test` (5 new: name matching, the configured path, the refusal of
    pid 0, and the existing in-process protocol test now names itself). The
    unauthorised path is deliberately *not* given the full 300 s request deadline —
    it waits 5 s for the line and closes, so a refused client cannot hold the single
    request slot.
  - Honest limit, in D-017 and the register: this is the image **name**, so a copy of
    the engine still passes, and the caller's **token SID** is not compared with the
    installer's account. That is F-2b.
  - Note while running it: `scripts\verify-helper.ps1` defaults to
    `dist\MICS-portable\mics-engine.exe`, which predates these changes and fails the
    audit-log checks; pass `-EnginePath` a fresh `cargo build --release` binary (or
    rebuild the release) to measure the current source.
- **The update signer must be MI CS, not just someone Windows trusts (F-3c)**
  - F-3b asked "is this signed by anyone Windows trusts?" — a real improvement over
    a bare hash, but a stolen or purchased certificate from any CA would also pass.
    The check now reads the signer's name out of the same verify state
    (`WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` →
    `CertGetNameStringW`) and compares it with `EXPECTED_SIGNER_CN =
    "MI CS Code Signing"`.
  - A valid signature from another certificate is refused with the name it actually
    found, so a support log says why. The CN is now a release contract:
    `make-release.ps1 -Sign` must keep issuing it.
  - The four tests cover the pair: our release binary's CN is measured to be exactly
    `MI CS Code Signing`, `require_signed_by` accepts it, refuses `"Some Other
    Signer"`, and the refusal text carries `MI CS Code Signing`. `cargo test` 66/66
    (1 new). Two extra `windows` features were needed for the WTHelper bindings.
  - Deliberate limit, in D-016 and the register: the pin is the **subject name**,
    not the thumbprint, because a thumbprint breaks on every locally re-issued
    certificate. A same-CN certificate from a CA that failed identity validation is
    the residual, now filed as LOW instead of "any trusted certificate passes".
- **An update payload must be signed, not just hashed (F-3b closed, D-016)**
  - `update.apply` used to trust the manifest's SHA-256 alone, which only proves the
    archive matches what a document said — not who produced it. A mirror (or a URL
    the user was talked into) could describe any payload and the hash would agree.
  - The extracted `mics-engine.exe` and `mics_app.exe` must now pass
    `WinVerifyTrust` (generic verify, no UI, embedded signature, chain built by
    Windows) **before** `copy_over` runs, so a refusal leaves the running install
    untouched. The check is `platform/windows/signature.rs`; `update.rs` calls it
    with the file name in the error so the message names what was refused.
  - Three tests, and the numbers are from this machine rather than guesses: a junk
    file answers `0x800B0003` and is refused, the signed release answers
    `0x00000000` and passes, and a copy with **one byte** flipped in the middle
    answers `0x80096010` (`TRUST_E_BAD_DIGEST`) and is refused. `cargo test` 65/65
    (3 new).
  - Measured along the way: `notepad.exe` is *catalog*-signed and answers
    `0x800B0100` (`TRUST_E_NOSIGNATURE`) to a file-level check — so a Windows
    system binary is not a positive fixture, and the test uses the release artifact
    (skipping with a printed line when `dist\` is absent).
  - D-016 records the decision, including the honest limit: **the signer is not
    pinned**, so any certificate Windows trusts passes. That identity pin is the
    remaining half of F-3 and stays in the register.
- **Cleartext feeds and update manifests are refused (F-3a closed)**
  - `settings.rs` accepted `http://` for `ioc_feed_url`, `lm_url` and
    `update_manifest_url`. For a local LM Studio that is correct; for a feed or an
    update manifest it is a downgrade an on-path attacker can rewrite, and the
    engine would trust what came back (F-3).
  - One rule now: `https://` anywhere, `http://` **only** for loopback
    (`127.0.0.0/8`, `::1`, the literal `localhost`). The host is taken from the
    parser (so `http://0x7f000001/` is seen as `127.0.0.1`) and the decision is
    numeric, so `localhost.evil.test` is not mistaken for loopback.
  - It is enforced twice on purpose: `settings.set` refuses it with a message the
    UI can show, and `load()` clears such a value with a warning, so a hand-edited
    `settings.json` cannot smuggle a cleartext feed past the UI.
  - Live acceptance over JSON-RPC (isolated engine): `http://feeds.example.com/…`
    answers `-32602 ioc_feed_url must use https:// (http:// is only accepted for
    loopback…)`, and `http://127.0.0.1:1234` is accepted. `cargo test` 62/62
    (1 new: five accepted and five refused spellings, times three keys, plus the
    "a refused patch changes nothing" case).
  - Still open: the updater does not verify Authenticode on the extracted binary
    before replacing a running one (F-3b, next step).
- **`AGENTS.md` rule 8 now names the real network calls (F-7 closed)**
  - The rule said "nothing leaves the machine except explicit VT/NVD/LM lookups",
    which was not the list: the engine also fetches the intel sources it shows you
    (StevenBlack hosts, CISA KEV, NVD), runs a 30 s connectivity probe against
    `dns.google`/`1.1.1.1`, and sends to whatever the user configures (LM Studio, an
    IOC hash feed, an update manifest).
  - A rule that a future contributor reads as "we only talk to three hosts" is a
    rule that gets broken by accident, so it now carries the honest list and points
    at `docs/THREAT-MODEL.md` §B6, where every destination has what is sent and what
    triggers it. Any new destination is a decision entry, not a commit detail.
  - The threat model closes F-7 in its "closed since" note and drops the row.
- **One answer to "what is this pipe name" for both test hooks**
  - `MICS_PIPE_NAME` wanted a full `\\.\pipe\...` path and `MICS_HELPER_PIPE` a
    bare name. The forms are not interchangeable by accident: Windows accepts
    `\\.\pipe\\\.\pipe\x` as a name of its own (verified on this machine), so the
    wrong form started a second, differently-named pipe **silently** — the helper
    was up, `helper-status` agreed with itself, and any client asking for the plain
    name found nothing.
  - `platform/windows/pipe.rs` now owns `pipe_path()` and `bare_pipe_name()`, and
    both hooks go through them: either form names the same pipe. A new test pins
    the accepted forms, the whitespace, the mixed case, the idempotence and the
    fact that only the real `\\.\pipe\` prefix is stripped
    (`\\.\pipelines\x` untouched). `cargo test` 61/61 (1 new).
  - Live acceptance on the reference machine: `MICS_HELPER_PIPE` set to a **full
    path** (`\\.\pipe\mics_helper_fullpath_probe`) now yields
    `"reachable": true` from `helper-status --json`, which is the configuration
    that used to be unreachable by name.
  - The hook table in §0 and the `docs/PRIVILEGED-OPS.md` note now say that both
    forms are accepted, and the register row for the disagreement is gone.
- **The canary copy now says what the detector sees (F-4 closed)**
  - The alert read `was accessed/modified — something opened your decoy` while
    `check_touches` compares mtime and size only. A read-only open changes neither,
    so the wording claimed a detector that does not exist.
  - The event detail, the card title (ar + en) and the incident title now say the
    decoy file was **modified** — a write, rename or delete — and `canary.rs`'s
    module doc states the read gap next to the code it belongs to.
  - The detection gap itself is unchanged and stays in the register: catching a
    pure read needs a minifilter or handle auditing, which is kernel work.
- **`docs/PROTECTION-MATRIX.md` — what each layer sees, detects, blocks and misses**
  - Written from the code, not from intent, and it is deliberately unflattering:
    where a claim could not be backed by code or a test it is either labelled an
    assumption or filed in the register.
  - It states the thing the product's own copy should not have to be read twice to
    learn: **MI CS leans on Windows Defender for real-time protection.** It is a
    posture, triage and response tool — nothing in it blocks code before it runs.
  - Per layer: L4 on-demand file scanning (hash + YARA, 50 000 files / 200 MB per
    file, archives ranked but never expanded), L2 name resolution (hosts sinkhole)
    and L1 firewall (`netsh`: default-deny outbound, `MICS-` rules, IPv4-only country
    lists that must already be on disk), L3 process guard (ETW when elevated, a
    2 s poll otherwise; `kill` is `taskkill /T /F` **after** the start), canaries
    (mtime/size only — a pure read is invisible, F-4), the correlator, the
    vulnerability layer (NVD keyword mapping plus KEV, no CPE matching, no
    patching), the audit/hardening posture, Defender orchestration, and delivery.
  - Three limits are now written down rather than implied: the bundled detection
    content is a **starter pack** (6 guard rules, 10 YARA rules) and is a
    demonstration of the mechanism, not a signature database; there is **no scan
    scheduler** and no real-time file watching, so the hash/rule dimensions apply
    only when someone runs a scan; and the guard's ETW callback **loads the IOC
    hash list without using it** (hashing every process start was judged too hot),
    so a known-bad hash that matches no rule is only caught by a scan.
  - The stale comment in `guard/etw.rs` that implied "scheduled scans" covered the
    hash dimension is corrected in the same commit — the documentation and the code
    now say the same thing.
  - New register rows: no scheduled scan (MED), starter-pack content (LOW), the
    guard's unused IOC hashes (LOW).
- **`scripts\verify-pipe-acl.ps1` — the pipe boundaries are now re-measurable
  instead of quoted**
  - `docs/THREAT-MODEL.md` states two security descriptors. Both are now checked
    by a committed probe rather than by a paragraph: it starts a real `service`
    engine and a real `helper-console` on private pipe names with a private data
    directory, reads each DACL back with `GetSecurityInfo` + an SDDL conversion,
    and drives a real JSON-RPC `status` call over the hardened engine pipe — so a
    passing ACL cannot be one that merely locked the UI's own user out.
  - Engine pipe: `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)` — protected, three
    ACEs, no `WD`/`AN`/`IU`. Helper pipe: `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;IU)`
    — the documented `INTERACTIVE` grant, printed with a note that this is open
    risk F-2 and that the probe reports it rather than blessing it.
  - Honest limit written into the script and the threat model: the DACL is the
    evidence that another account is refused; proving it with a second account
    would need a second account's credentials, which a probe must not ask for.
  - `RESULT: PASS` on the reference machine, 18 checks, exit code 0 on success and
    1 when a pipe measures differently, like the other `verify-*.ps1` runbooks
    (ASCII only, both engine streams to files — traps 8.9 and 13).
- **Threat model F-1 closed — the engine pipe now names its callers**
  - `\\.\pipe\mics_engine` used to be created with no security attributes, so it
    carried Windows' default pipe DACL: `(A;;FR;;;WD)(A;;FR;;;AN)` let any local
    account attach to a free instance and read the engine's broadcast stream
    (alerts, scan progress, incident text). Sending was never possible for them;
    it was a confidentiality leak on a multi-user machine.
  - It is now created with `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<user SID>)`, the
    SID read from the engine's own token at startup
    (`platform/windows/pipe.rs`). If that descriptor cannot be built the engine
    logs a warning and serves with the default ACL instead of refusing to start —
    a decision recorded as D-015, together with why the engine and the UI must stay
    in one user session.
  - Two tests read the DACL back from the live pipe object
    (`GetSecurityInfo` + SDDL conversion): exactly three ACEs, `D:P(`, no
    `WD`/`AN`/`IU` in the result. `GA` is stored by Windows as the mapped `FA`,
    which is what the measurement shows.
  - Live acceptance (real `service` engine, isolated pipe and data dir, nine
    checks, `RESULT: PASS`): `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)`, and a
    same-user JSON-RPC round trip still answers
    `{"state":"running","version":"0.1.0","platform":"windows-x86_64","pid":…}` —
    the hardening did not cost the UI its transport.
  - `cargo test` 60/60 (2 new), clippy clean, `flutter analyze` clean,
    `flutter test` 36/36. F-2 (the helper pipe's `INTERACTIVE` scope) is untouched
    and still open.
- **`docs/THREAT-MODEL.md` — assets, adversaries, boundaries, and what we do not
  defend (measured, not assumed)**
  - Written from the code and from two live measurements, not from intent: the
    engine pipe and the helper pipe were both started in isolation (real `service`
    engine, real `helper-console`) and their security descriptors read back with
    `GetSecurityInfo` + SDDL conversion.
  - Engine pipe `\\.\pipe\mics_engine` carries Windows' default DACL:
    `(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)(A;;FR;;;WD)(A;;FR;;;AN)` — the
    owner, SYSTEM and Administrators can *send*, but `Everyone` and
    `ANONYMOUS LOGON` have read access, so on a multi-user machine another local
    account can attach to a free instance and read the broadcast stream (alerts,
    progress). Fix filed as F-1 with the exact mitigation (explicit SDDL,
    `create_with_security_attributes_raw`).
  - Helper pipe measured as documented: `(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;IU)`.
    `IU` is INTERACTIVE, so a **standard** local user can ask the LocalSystem
    helper for the closed op set — a real, bounded multi-user risk, filed as F-2
    with the caller-identity check as the mitigation; keeping D-007's single
    prompt is why it is accepted for now.
  - Eight residual risks recorded (F-1…F-10 range), each with why it is accepted
    and what closing it would cost: pipe ACLs, updater provenance (SHA-256 from
    the manifest, no `WinVerifyTrust`, `http://` accepted), plaintext API keys,
    machine-scope DPAPI for quarantine, canaries that see writes but not reads
    (the alert copy overstates this), no self-defense, and the usermode-only
    detection limits.
  - Corrected an honesty gap found while writing it: `AGENTS.md` rule 8 says
    "nothing leaves the machine except explicit VT/NVD/LM lookups", while B6's
    table is the accurate list (intel sources + a `dns.google`/`1.1.1.1`
    connectivity probe cached for 30 s) — filed as F-7.

- **audit — a fix re-checks one section, and the score still means the whole
  machine (D-014)**
  - `audit.run {sections:[...], merge:true}` re-reads those sections and merges
    them into the last full audit the engine remembers, so the client pays for
    one collector and still gets a **complete** report: `partial:false`, every
    section listed, one score computed by the same code over every finding
    (`merged:true` + `refreshed:[ids]` say what was just re-read). The base is a
    full audit only: a merge with nothing remembered is refused (`-32000`, "run
    the full audit first") and the UI falls back to the sweep.
  - The merge is keyed by **section id**, never by a finding's display `section`:
    `rdp` and `remote_tools` both report under "Remote Access", so a
    display-name merge would have deleted one of them and flattered the score.
    A section whose collector fails on the re-read is dropped, not left stale.
  - **Both fix buttons use it.** The audit screen used to leave the fixed card
    claiming the machine was still vulnerable (it never refreshed at all); the
    hardening screen re-ran every collector to move one number. Each now calls
    `refreshAfterFix(action)`, which names the section via one table
    (`auditSectionForHardeningAction`, `lib/models/audit_models.dart`) and does
    the full audit for an action the engine has no section for.
  - `cargo test` 58/58 (4 new: the merged report keeps every section and score,
    the "Remote Access" collision, a failed re-read leaving no stale finding, and
    the `merge` parameter validation), clippy clean, `flutter analyze` clean,
    `flutter test` 36/36 (5 new in `test/audit_merge_test.dart`: the request
    shape, the mapping table, the no-mapping fallback, the refused-merge
    fallback, and a plain full audit).
  - Live on this machine (throwaway `serve` engine, isolated `MICS_DATA_DIR`):
    full audit `score 70, 12 findings, 10 sections, partial false`; then
    `{sections:["hosts"], merge:true}` → `score 70, 12 findings, 10 sections,
    partial false, merged true, refreshed [hosts]`. A lone `{sections:["hosts"]}`
    returns `score 85, 1 finding, partial true` — exactly the uncomparable number
    the merge exists to avoid. `{sections:[], merge:true}` → `-32602` ("merge
    needs sections"), `{sections:["nope"], merge:true}` → `-32602` (unknown
    section), and a merge on a fresh engine → `-32000` ("no full audit to merge
    into"). Nine of nine checks PASS.

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
    same `mics-engine.exe helper-service`, plus the engine's client
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
    *(Measured again 2026-11-10: **19 modules / 301 keys** per language — the pack
    grew after this entry was written, and the same two gates below hold it; the
    2026-11-07 footnote in this entry said 270 and the 2026-11-09 count 299 (29 keys
    landed with the slices between those two counts, then one key with the
    engine-refusal line and one with the unrenderable-tag notice).)*
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
    with 16 module files each *(19 as of 2026-11-07)*.
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
| 2 | Translation as separate files with keys | **done** — **19** module files × 2 languages, **301** keys each (measured 2026-11-10; the 2026-11-09 count of 299 was stale by two keys — one with the engine-refusal line, one with the unrenderable-tag notice), parity + no-hardcoded-copy tests | D-009 |
| 3 | Code signing | **not bought, and free to obtain (D-035 + D-036)** — the self-signed script works and names the publisher locally (`CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`), and the release takes a real certificate as two secrets with **no code change** (D-034). Nothing is purchased (D-035); `docs/SIGNING.md` records the two free routes that sign for us instead — the Microsoft Store re-signing an MSIX after certification (available today; packaging work plus the three unknowns in its §3) and OSSign's project certificate (~2027-04-27) — while the public half is carried meanwhile by reproducible builds + published hashes | D-002, D-034, D-035, D-036, `scripts/sign.ps1` |
| 4 | Permissions asked once, publisher name | **code complete; one UAC click left** — the helper, its closed op set, the audit trail and the Settings card are shipped and proven unelevated, and the **installer** now creates the service (ب4, D-026), so one prompt covers product + helper; the per-machine run is §0.6 row 2. Publisher naming is the certificate, and it is not purchased (D-035) | D-007, D-026, `docs/PRIVILEGED-OPS.md` |
| 5 | Complete advanced Settings screen | **done** — 8 sections, every field writes through `settings.set` | D-008 |
| 6 | App update paths | **partial** — the manifest URL + channel are real settings, `update.check`/`download`/`apply` work, and an empty URL now means the channel's own release feed rather than "off" (D-046, measured by `scripts\verify-update.ps1`); left: no rollback screen. The signature check is **done** — the manifest is verified as a detached PKCS#7 before a field of it is parsed (D-047, 2026-11-09) and the pin it is judged against is the certificate over the engine itself rather than a subject name (D-051, 2026-11-11), so this row's "no signature check on the manifest and the thumbprint pin it needs" is spent; what is left of §0.6 row 5 is the rollback screen, which is not written as a row anywhere | P3, P4 |
| 7 | CVE/intel update paths | **done** — per-source scheduled sync with state/backoff (D-012), Intel screen with per-source results and last errors, vulnerability scan as a cancellable job with live progress, KEV badge on exploited CVEs | D-012, P3c1–P3c3 |
| 8 | ~~Dark/light mode~~ | **done** — palette, System mode follows live OS switches; **both** palettes are audited and fixed (**29 of 29** pairs clear WCAG 2.2 each, pinned by a test — `docs/CONTRAST.md`; dark closed in small step 4) | P2, أ2–أ3 |
| 9 | Not hackable / not reverse-engineerable | **partial** — hardening landed (ج1, D-021): CFG on both binaries, LTO/stripped engine, obfuscated Dart snapshot, and `verify-hardening.ps1` gates the release on the PE. The start-up self-check landed with ج2 (2026-11-03): the engine re-hashes the files beside it against the manifest inside its own signed image and says so in About. What no local check can do stays open: a from-source rebuild re-signed with another key is indistinguishable (a stranger can now at least *rebuild ours and compare* — F-11 landed 2026-11-08, `docs/REPRODUCIBLE.md`; the engine is the one file that needs the explanation in §0.6 row 13) | P5 |
| 10 | README: what it does / does not + requirements | **done** — bilingual README with a capability matrix, requirements, data locations, privacy, build and troubleshooting | `README.md` |
| 11 | x64 / x86 / ARM64 | **decided, and half-built** — x64 + ARM64; the 32-bit UI is impossible (Flutter has no 32-bit Windows desktop target); the ARM64 **engine** builds and its PE is checked (ب2), and GitHub's `windows-11-arm` runner runs its tests natively. Pending: the ARM64 **app**, because Flutter publishes no Windows ARM64 SDK — §0.6 row 6 | D-003; §0.6 |
| 12 | Protection types | **done** — `docs/PROTECTION-MATRIX.md`: layer → sees / detects / blocks / misses, plus the evidence table (verified in small step 7) | `docs/PROTECTION-MATRIX.md` |
| 13 | Full test walk-through with a report | **done, including the installer E2E (2026-11-07)** — **د1** the `qa/` contract harness over all 66 methods, **د2** every screen and control swept with a committed ledger, **d4** the generated `qa/report.md`/`report.html` (byte-gated so the fast tier fails when it drifts), and **د3** the per-machine E2E, which ran on 2026-11-07 (§0.6 row 2). Nothing in this row is left | P6, `qa/` |
| 14 | Malware corpus for testing | **deferred** — EICAR only, and only inside a VM lab | P6 (later) |
| 15 | Engine restart must not lose a scan | **done** — durable jobs + auto-resume, verified | `engine/src/jobs.rs` |
| 16 | Interactive sounds + control | **done** — in-house pack, engine cue with the UI closed, UI volume/mute/DND, test button | D-004 |
| 17 | Protect the project from theft | **decided** — GPL + trademark + signing, never secrecy | D-001 |
| 18 | Cheapen the project + licenses | **answered, and it got cheaper than planned** — GPL-3 **text** now really ships (`LICENSE` was a placeholder until 2026-11-07); SBOM + `THIRD-PARTY-NOTICES` generated, committed and shipped (ب1a, D-018); `docs\COST.md` still records the researched prices, but the single purchase it named is **off the plan** (D-035) — the project's running cost is **zero**, which was always the point of this row | D-035, `docs\COST.md` |
| 19 | Professional README | **done** — see row 10 | `README.md` |
| 20 | L5 wording vs reality (LLM) | **closed — the assistant was removed, not reworded**: L5 is incident correlation only, and `llm.explain`/`nl.command` are gone (2026-11-13) | D-005 → **D-052** |
| 21 | Living TODO/handoff file | **done** — this file | — |

---

## 5. Next up — one prompt, then the installer

**The ordered plan lives in §0.3 (steps أ → و); this section is the detail behind
P1.5 and the installer.**

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
- [x] ~~**Acceptance (needs you):** install the helper once from
      **Settings → Engine → Install helper** (one prompt), then enable Default-Deny,
      turn SMBv1 off and import a hosts list in one session: **zero** further
      prompts, and `logs\priv.log` carries one `phase=start`/`phase=done` pair per
      operation.~~ — **done and measured 2026-11-07**, against the **real** service
      rather than `helper-console`, and after the installer (ب4) became the thing that
      creates the helper: one UAC prompt installed product + service, and then three
      privileged operations were driven from an **unelevated** engine over its pipe
      with **zero** prompts — `helper.status` (`installed/running/reachable/elevated`),
      `fw.rules.add` (**37 ms**) and `fw.rules.remove` (**36–44 ms**), each one a
      `phase=start`/`phase=done ok=true` pair in `%PROGRAMDATA%\MICS\logs\priv.log`.
      **Not** exercised, deliberately: *Default deny outbound* (it would have cut this
      machine's own network path mid-run), the SMBv1 toggle and the hosts write — so
      that slice is still proven only by the protocol probe below.
      Everything below that step is already proven unelevated by
      `scripts\verify-helper.ps1`.
- Note: the prompt shows "MI CS" as publisher only with a trusted certificate
  (D-002) — until then it shows the helper's unsigned identity.

### Leftovers from P2 (non-blocking)
- [x] Light-mode contrast audit (text/borders/severity colours): 36 pairs measured
      against WCAG 2.2, 25 below their bar — `docs/CONTRAST.md`, step أ2.
- [x] Screenshots of the light theme in the documentation — done in small step 5, and
      the audit stays numeric on purpose (the record is the ratio table, not a
      picture): the four renders are illustrations, the ratios are the proof.
- [x] `docs/PROTECTION-MATRIX.md` — verified 2026-10-31 (small step 7): the sheet
      exists as a standalone document (10 sections), and README now links it from the
      five-layers section instead of implying the README is the only matrix.

### Cheap wins — no elevation, no money, no new subsystem
These can be done in any order and each is one small commit. They are listed
because P1.5 and P4 both need something only you can supply (a UAC prompt and a
signing certificate respectively), so this is the work that is always available.

- [x] `status` returns the real crate version and platform instead of hardcoded
      `0.1.0` / `windows` (now `windows-x86_64` + pid).
- [x] `audit.run` honours `params.sections` instead of running everything
      (7 ms for one section instead of 1.7 s; unknown names are refused). A fix
      now uses it: `audit.run {sections:[id], merge:true}` re-reads one section
      and merges it into the last full audit (D-014), so the UI pays for one
      collector and still shows the engine-computed score over every check.
- [x] Add timeouts to the `netsh` / elevated-PowerShell calls in `firewall/mod.rs`
      and `ids/mod.rs`, the way hardening was fixed — an unanswered prompt or a
      stalled service must not wedge a request. Done as a shared runner
      (`platform/windows/process.rs`) for every spawn in `firewall` and
      `hardening`; `ids` spawns nothing itself (it goes through the helper).
      Extended to **every** external tool: the audit probes, the update extract,
      the autostart `reg` calls, `icacls`, `taskkill` and `sc.exe` all run through
      `ToolCall`, the async Defender scan carries its own `tokio::time::timeout`,
      and a test fails on any bare `Command::new` outside the runner.
- [x] VirusTotal client's fate decided and executed: the client was dead code (only
      the offline queue could call it, and nothing filled the queue), so it is
      **deleted** — `scanner/vt.rs`, `vt_api_key`/`MICS_VT_API_KEY`, the
      `sync_queue` table and its four storage calls, the Settings → Integrations
      field and `vt_queue_len`. README says so in both languages (D-019). The
      register MED row closed with it.
- [x] Regenerate the portable ZIP + `SHA256SUMS` from the current
      `dist/MICS-portable`, so the published artifact matches the deployed build
      (`scripts\make-release.ps1` + `scripts\verify-release.ps1`; the folder now
      also ships `rules\`, which every previous deploy had dropped).
- [ ] ARM64 build leg (Flutter + `aarch64-pc-windows-msvc` engine), per D-003.
- [x] Guard CPU: 3.52 % → 1.56 % → **0.156 % of one core** (0.0028 % of a 56-thread
      machine), budget met under either definition, and the measuring tool fixed
      (`benchmark` was reporting its own probe) — §0.1, log entries below.
- [x] `docs/PROTECTION-MATRIX.md` + `docs/THREAT-MODEL.md` — both exist and were
      re-read in small step 7 (the protection sheet has 10 sections and a "how these
      claims are checked" table; the threat model carries the assets, adversaries,
      boundaries and F-1...F-10).

---

## 6. Backlog by phase

### P3 — updates & intel
- [x] Update check + channels + download/apply **UI** (`update.check`,
      `update.download`, `update.apply`), with release notes and real errors.
- [x] Default update manifest URL compiled in per channel, one implementation behind
      `update.check` and the downloader, and an answer that names the feed that
      answered (D-046) — measured by `scripts\verify-update.ps1`, and the release lane
      publishes the `update.json` it reads (`scripts\update-manifest.ps1`).
- [x] A signed manifest check before applying, plus the thumbprint pin it needs
      (D-016) — the second half of §0.6 row 5 (هـ1), **done 2026-11-09 (D-047)**:
      `update.json.sig` is verified over the manifest's exact bytes before a field is
      parsed, the signer is pinned to the certificate over the engine (or
      `MICS_UPDATE_SIGNER_THUMBPRINT`), and every refusal stages nothing — measured by
      `scripts\verify-update.ps1` and six new engine cases, one against a committed
      signed fixture.
- [x] OFFLINE badge + "intel last updated Xh ago" in the title bar, tap to sync.
- [x] Intel pipeline hardening: named sources in one scheduled pass, per-source
      state + backoff + `sync_state.next_due`, DNS-blocklist domains, CISA KEV
      catalog (D-012). YARA/IPC packs wait for a signature-delivery mechanism.
- [x] A dedicated sync/intel screen with per-source results and last-error text,
      plus a configurable hash feed (`ioc_feed_url`/`ioc_feed_key`) — P3c3.

### P4 — release engineering
- [x] ~~Authenticode: an OV-class certificate bought as an individual~~ — **closed
      2026-11-07 as not-purchased (D-035)**: this is a free, open-source project with
      no budget, so no certificate is bought. What the row got right and is kept:
      `docs\COST.md` §2 carries the researched routes, dated prices and per-route
      publisher names (Azure Artifact Signing is not purchasable from Egypt; **no CA can
      issue our `CN=MI CS Code Signing`**, CSCBR §9.2.2; the free SignPath route is
      closed to this product category), so nobody re-researches the dead ends. What the
      row wanted is now met by free means: the PE hardening and manifest the release
      already gates on, plus a **reproducible build** (§0.6 row 4, landed 2026-11-08:
      `docs/REPRODUCIBLE.md` + `scripts\verify-reproducible.ps1`) and the published
      `SHA256SUMS`. The signing itself — DLLs then EXEs, timestamping, `signtool verify`
      in CI — is wired (D-034): a certificate is `MICS_PFX` + `MICS_PFX_PASSWORD`, or
      `MICS_CERT_THUMBPRINT` for a token/cloud agent, resolved in one documented order
      and printed before the build, so a **donated** certificate lands with no code
      change. *Reality measured 2026-10-30, still true:* the app is `NotSigned`, Smart
      App Control is off, SmartScreen policy is default, and the reputation endpoints
      are reachable — yet Windows still shows "SmartScreen can't be reached right now" /
      "Unknown publisher", because a first-seen unsigned binary has no reputation to look
      up, and a working lookup would only say "unknown". The **local** half has been
      solved since `make-release.ps1 -Sign` (self-signed certificate trusted in
      `CurrentUser\Root` + `TrustedPublisher`: all binaries `Valid`, `signtool verify /pa`
      passes, prompts stop on this machine).
- [x] ~~Build legs: x64 (primary) + ARM64 (app + `aarch64-pc-windows-msvc` engine);
      optional x86 **CLI** build only (D-003)~~ — **the engine half is done** (ب2,
      2026-11-03): `scripts\build-engine-arm64.ps1` builds the ARM64 engine **and its
      test binaries**, the PE is read back as a hardened ARM64 image, and GitHub's
      `windows-11-arm` runner runs the tests natively. **The app half is blocked
      upstream**: Flutter publishes no Windows ARM64 SDK (0 of 747 archives, measured
      2026-11-04) — §0.6 row 6. The optional x86 CLI stays optional.
- [x] ~~NSIS installer (bundled engine + rules + offline intel) next to the portable
      ZIP; regenerate ZIP + `SHA256SUMS` from the current build~~ — **done** (ب3 steps
      1–3 + ب4, 2026-11-01/03): `installer\mics.nsi` + `scripts\make-installer.ps1`
      build `dist\MICS-setup-<version>-x64.exe` from the same package, per-machine by
      default with the **helper install folded in**, and `scripts\verify-installer.ps1`
      proves install/uninstall, both shortcuts' AUMID and the untagged-helper refusal.
      Rebuilt from `main` on 2026-11-07: 16.0 MB, `sha256 8984C194…`, 70 files shipped,
      68 of them described by the manifest inside the engine.
- [x] ~~SBOM (CycloneDX), `THIRD-PARTY-NOTICES`, dependency-license audit~~ — done
      (ب1a, D-018): `tool\sbom.dart` generates both from the lockfiles, the pair is
      committed, shipped in the package and freshness-checked before a release.
- [x] ~~`docs/COST.md` — the real costs and what stays free~~ — done (ب1b): the only
      purchase is a CA-issued certificate; the sheet also records that its key must
      be in hardware since June 2023, which retires the `-PfxPath` path in favour of
      the `-Thumbprint` one — a mode D-034 added on 2026-11-06, after this row's
      claim that a `/sha1` path already existed turned out to be false. The file was
      re-researched the same day: it now carries dated list prices, per-route
      publisher names, and the two rules that changed (460-day cap, EV's SmartScreen
      bypass retired in 2024).

### P5 — trust & truth
- [x] `docs/THREAT-MODEL.md` (assets, adversaries, trust boundaries, what a
      usermode product cannot do: no kernel driver) — the two pipe ACLs measured
      live rather than assumed; residual risks F-1…F-10 in the register below.
- [x] `docs/PROTECTION-MATRIX.md`: per layer, what is detected/blocked and what is
      not (hosts-based L2, polling canaries, netsh firewall, no ClamAV/CAPA) — done
      and re-verified in small step 7; only its VT sentence needed touching (D-019).
- [x] ~~Integrity: signed SHA256 manifest of shipped files, self-check at startup,
      "unofficial build" banner on mismatch~~ — done (ج2 + ط2, 2026-11-03): the
      document rides inside the engine's signature, the engine answers
      `status.integrity`, About shows the line and the card fires on a mismatch, the
      release gate refuses a changed folder, and `scripts\verify-tamper.ps1` proves
      both halves catch it.
- [x] ~~Build hardening: Dart `--obfuscate --split-debug-info`, Rust LTO/strip/
      `panic=abort`, PE mitigations~~ — done (ج1, D-021): CFG on both binaries,
      LTO/stripped engine, obfuscated Dart, and `scripts\verify-hardening.ps1`
      gates the release on what the PE says.
- [x] ~~README rewrite: what it does / **does not do**, requirements (Win10 21H2+/
      Win11, x64 or ARM64, 4 cores, 8 GB, 52 MB, one UAC at install), privacy,
      data locations, uninstall, screenshots, build instructions, GPL notice~~ —
      done (ج3, 2026-11-03): the does/does-not pair now carries the manifest, the
      start-up self-check and their honest limits, and every number in it is the one
      the pipeline measured. **Re-measured 2026-11-07** after this pass's audit: the
      disk figure is 52 MB unpacked (was written as "~150 MB", which was the engine's
      RAM budget read as disk), the idle figure is 12.5 MB (was 11), the canary claim
      was inverted by D-032, and "Download" now says the release is a draft.
- [x] L5/assistant wording — **resolved by removal, not rewording** (2026-11-13):
      the assistant, the command bar and their settings are gone; README and docs
      now say L5 = incident correlation only (D-052).

### P6 — QA
- [x] Pipeline entry point: `scripts/pipeline.ps1` (ز0) — tiers, JSON report, and
      the CI workflow calls it instead of repeating the checks.
- [x] ~~`qa/` contract harness: every JSON-RPC method (happy path, invalid params,
      unknown method, schema) driven from `dispatcher.rs` so a new method cannot go
      unregistered (د1), then the same fixtures drive a `FakeEngine` for every
      screen and every interactive control (د2)~~ — **done, 2026-11-01**: `qa/methods.json`
      holds **66** rows and `qa/report.md` records **66 dispatched**, so a new method
      cannot go unregistered in either direction; every screen (13) and control (100)
      is swept against the fixtures with a committed ledger.
- [x] ~~CI runs the harness; a feature that is not registered fails the build (د5)~~ —
      **done**: the fast tier fails when the registry and the code disagree
      (`test/qa_registry_test.dart`, `test/ui_screens_test.dart`).
- [x] ~~**د3** — E2E on the built **per-machine** artifact~~ — **done and measured
      2026-11-07**: install (one UAC), the installer-created `MICSHelper`, privileged
      ops driven unelevated with **zero** further prompts, uninstall (one UAC) removing
      product + service + shortcuts, and the installed engine's self-check reporting
      `68/68` files. The full measurements are the د3 row in `docs/ROADMAP.md` §2 and
      §0.2 item 1 here. The report half (~~`qa/report.html` + `.md`~~, د4) was already
      done 2026-11-02: generated from the registries, byte-gated by
      `test/qa_report_test.dart`, uploaded next to the contract log by CI.
- [ ] Malware lab (later): isolated VM + snapshots, EICAR/AMTSO first, samples
      never in the repo, detection-efficacy report.

---

## 7. Known issues / risk register

| Sev | Issue | Where |
|---|---|---|
| HIGH | **No publicly trusted signature** — the download half of this row closed on 2026-11-10 by the owner's click, and was verified the next day. **(a) Published:** `v0.1.0` was built and verified by the Release workflow (run 42040718389) and sat in GitHub Releases as a **draft** (D-031); the public page now carries it — **4 assets**, `MICS-setup-0.1.0-x64.exe` 16,642,682 bytes `sha256 5cd206db3b44cc68d1f7822593efcf834956c15d47aac21bd6116c84d47f84f5` and `MICS-portable-0.1.0-x64.zip` 23,111,206 bytes `sha256 1eafe3ee618aae963a2c52811ae442fca85ade9f90ecbb7c87f6d737cd2fe6b0`, both re-hashed on 2026-11-11 against the published `SHA256SUMS` (all three hashes it lists matched), the unpacked portable package reporting `PASS - all 67 listed file(s) hash as the signed manifest says` under `scripts\verify-manifest.ps1`, and the engine inside it signed `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`, thumbprint `E04CE19746C83DB2DAAD532D04C8C607531C3CF5` (issued 2026-11-04). Three facts about that download are recorded rather than assumed: **the installer carries no signature at all** (`NotSigned`, measured 2026-11-11, so the published hashes are its only anchor — and the README paragraph about "the project's own signature" was made to say which file that covers); the package was built **2026-11-05 14:18:45** (its own `VERSION`), so D-046, D-047, D-049, D-050 and D-051 are in `main` and not in the download; and the certificate that signed it is not the certificate in this tree, which is the MED row below about one identity per release. The old "no installer" half of this row closed long ago: the NSIS installer exists, is per-machine by default, folds the privileged helper into its own elevation (ب4, D-026), ships 70 files of which 68 are described by the manifest inside the engine, refuses to orphan a helper (`/S _?=$INSTDIR` → 5), and `verify-installer.ps1` proves the per-user path in 126 s. Rebuilt from `main` on 2026-11-07: 16.0 MB, `sha256 8984C194…`, and the E2E acceptance on that per-machine artifact is §0.6 row 2. **(b) The signature will not be bought — and no longer needs to be** (D-035, D-036): this is a free, open-source project with no budget, so nothing is purchased; the re-research of 2026-11-07 (`docs/SIGNING.md`) found the two routes that sign for free, so ب5 is **free work plus one date**, not a debt: **the Microsoft Store re-signs an MSIX package** after certification (free account, ID + selfie, worldwide, no SmartScreen warnings — the missing piece is packaging, plus the three unknowns in `SIGNING.md` §3), and **OSSign** issues the *project* a certificate once the repository is six months old (~2027-04-27). `docs/COST.md` §2 keeps the researched *paid* routes, dated prices and each route's publisher name so the dead ends are not re-researched (Azure Artifact Signing is paid and unavailable to an individual outside the USA/Canada; the free SignPath route is closed to this product category in their own words — they cannot sign tools that "actively scan for and highlight exploitable vulnerabilities", e.g. "identifying unprotected network ports"). **No CA can issue `CN=MI CS Code Signing`** — CSCBR §9.2.2 — so the D-016 pin must move to a **thumbprint** in the same release that first carries a certificate, or `update.rs:128` refuses our own update. What carries the claim until one of the free routes lands is free and checkable without trusting anybody: the manifest the engine re-hashes at start-up, the published `SHA256SUMS`, and a **reproducible build** (F-11 — **landed 2026-11-08**, `scripts\verify-reproducible.ps1` + `docs/REPRODUCIBLE.md`, §0.6 row 4). If a certificate is ever **donated**, D-034's two secrets install it with **no code change**. | `dist/`, `installer/`, `scripts/`, P4, D-035 |
| ~~HIGH~~ | ~~A user who copies the package by hand can drop `rules\` and get the compiled-in starter pack silently~~ — **closed 2026-11-03 (و4) by evidence**: a package with `rules\` removed (and its own `SHA256SUMS` corrected, so nothing but the missing folder can fail) is refused by `verify-release.ps1`: 4 FAILs — `missing from the zip: rules\yara\starter.yar, rules\guard\starter.json`, `rules folder holds 0 file(s)` (the layout check, not just the file names), `the guard did not use the packaged rules: guard: 6 rule(s) from the built-in starter pack (rules/guard not found)` and `the scan did not use the packaged YARA rules (log line: YARA rules from the built-in starter pack (no rules\yara\starter.yar found))` — **exit code 1** (`RESULT: FAIL - the release artifact is not what it claims to be`). The silently-degraded copy the row described can no longer pass the gate, and the engine's own log names the source it used | `dist/`, `guard/mod.rs`, `scanner/mod.rs`, `scripts\verify-release.ps1` |
| ~~LOW~~ | ~~A merged re-read keeps the audit complete, but the merged report's non-refreshed sections are only as fresh as the last full audit; the UI never shows that age~~ — **closed 2026-11-03 (و4)**: every section now carries the unix time it was collected (`AuditPass::stamps`), a merge keeps the base's time for the sections it did not re-read and takes the re-read's own time for the ones it did (a section whose collector failed loses its stamp instead of inheriting a fresh one), each finding names its **section id** (the display name is not unique — `rdp` and `remote_tools` both read "Remote Access"), and the audit screen prints "Not re-checked now — read at HH:MM" on every finding and inventory header whose section this report did not re-read. Localised in ar/en; the widget test proves 3 such lines on a merged report and none on the refreshed finding | `traits.rs`, `audit_models.dart`, `audit_screen.dart` |
| MED | Defender **tamper protection** refuses programmatic preference writes, so `Set-MpPreference -PUAProtection` can fail even when the engine is elevated; `hardening.apply` now detects the no-op and points at the Windows Security switch instead of claiming success | `hardening/mod.rs` |
| ~~LOW~~ | ~~`vuln.scan` (the blocking variant) still exists for probes and scripts~~ — **closed 2026-11-03 (و4)**: callers were checked first, and the register's "for probes and scripts" was wrong in one place — the natural-language command bar's `vuln_scan` intent dispatched it, so a spoken "scan for vulnerabilities" blocked the request for minutes with no progress and no cancel. That intent now points at `vuln.scan.start` (the command bar answers at once and the job reports through `progress`/`job_finished`), and with its last caller gone the blocking method, `VulnScanner::scan`, its `qa/methods.json` row and its registry entry are deleted: **one scanning path** — the durable job. The surface is **66** methods since و1 added its own (65 until then) | `vulns/mod.rs`, `dispatcher.rs`, `llm/mod.rs` |
| ~~LOW~~ | ~~A **registered** AUMID still only names the source: any same-token process can raise a card under `MICS` and Windows will attribute it to "MI CS"~~ — **closed 2026-11-03 (و4) by evidence, as a documented limit rather than a defect**: `verify-aumid.ps1` PASSes — `DisplayName` is `MI CS`, its `IconUri` names a file that exists, **both** shortcuts carry `System.AppUserModel.ID = MICS`, and the Shell files `MI CS` under AppID `MICS` — which is exactly what the AUMID was for (the app is filed by name instead of by exe path). The row's *substance* is not fixable in the app and `docs/THREAT-MODEL.md` §B10 already says it: a card is UI, not proof of origin, because the AppUserModelID is not an authenticator. Nothing in the product reads a card as evidence of anything; the register row existed to stop that reading | `notify/toast.rs`, THREAT-MODEL §B10 |
| ~~MED~~ | ~~**A rule added with a name that already starts with `MICS-` gets a second prefix and can never be removed by the name the caller used**~~ — **closed 2026-11-08**: one function decides the name. `owned_rule_name` strips *every* leading `MICS-` (repeated, ASCII-case-insensitive, surrounding space trimmed) and re-adds exactly one, so `foo`, `MICS-foo` and `MICS-MICS-foo` are the one rule `MICS-foo`; a name that is only the prefix is refused with a sentence that quotes the prefix; `add_rule_now` and `remove_rule_now` both go through it, and `FirewallManager::add_rule`/`remove_rule` check it *in front of* the privilege split so an unelevated caller gets the name refusal rather than "no helper" (D-028 kept: no signature changed). Measured 2026-11-08: `cargo test` **152 passed / 0 failed** (the new unit test walks five spellings of one name and four non-names), and `scripts\verify-firewall.ps1` **27 checks, 0 skipped, 0 failures, 29.9 s** against the running `MICSHelper` — part 3 now creates a rule under the *prefixed* spelling, proves `MICS-<rule>` is what Windows got (not `MICS-MICS-<rule>`), that no doubly-prefixed rule exists, and that the unprefixed spelling removes the rule the prefixed spelling created. The stray `MICS-TEST-BLOCK-EXAMPLE` on this machine is now removable by its own spelling; it was left in place, because removing it is a firewall change on the user's machine and not a code fix | `engine\src\firewall\mod.rs`, `qa\methods.json`, `scripts\verify-firewall.ps1` |
| MED | **No real-time file watching**: the hash + YARA dimensions only apply while a scan job is running, so a machine nobody scans has no file-level detection between runs (Windows Defender is the real-time layer, and the audit says so loudly when it is off). **The scheduled half is done** (و1, 2026-11-03, D-027): the engine runs a scan by itself every `scan_interval_hours` (opt-in, off by default) over `scan_target`, report-only, and `scripts\verify-scan-schedule.ps1` proves it starts, finds, and leaves the file in place — but a schedule is a moment, not a monitor: what changed *between* two runs is still only seen by Defender | `scanner/mod.rs`, PROTECTION-MATRIX §2 |
| LOW | The bundled detection content is a **starter pack** (6 guard rules, 10 YARA rules): the mechanism is complete and hot-reloadable, but the shipped rules demonstrate it rather than protect with it. **The "checks that packs load, not what they catch" half closed 2026-11-05 (D-033)**: `scripts\verify-rules.ps1` holds the pack a package ships to files — `engine\testdata\detection`, 8 vectors each written for one rule plus a clean control, **35 checks PASS** — and every rule the pack declares must either be caught by one of them or be named as unreachable with its reason. That ratchet immediately found the pack's one impossible rule: `Malicious_Macro_AutoOpen` compared `uint16(0)` against `0x504B`, which little-endian is `"KP"`, so it could never fire on any container that exists (a real `.docm` starts `50 4B` = `0x4B50`) — fixed, with the measured pair pinned by a test and re-measured through the probe. Measured reach of the 10 rules: **8 held to a file**, 2 named unreachable by a text vector (`EICAR_Test_File` — the string is what Defender quarantines; `Tiny_Packed_Pe_Installer` — needs a binary PE). **What stays open is the content decision, not the mechanism**: the macro rule's container test is two magic bytes plus substrings, and a real `.docm` deflates those substrings out of any pattern's reach (measured: `AutoOpen`, `CreateObject` and `Shell` are absent from the file's bytes), so document-borne malware needs an OOXML/OLE parser rather than another rule — which is decision (b) of the six in §0.2 | `engine/rules/yara/starter.yar`, `engine/testdata/detection/`, `scripts/verify-rules.ps1`, `scripts/verify-release.ps1`, `docs/PROTECTION-MATRIX.md` §2 |
| ~~LOW~~ | ~~The guard's ETW callback loads the IOC hash list and never uses it~~ — **closed 2026-11-10**: the dead load is gone (the callback opened the store and dropped the list on every guard start) and the comment beside it no longer claims flatly that "there is no scan scheduler yet" — one landed with **D-027**, so that was a false statement in a file people read to learn the limit. The deliberate part stays and is now a fact the surface reports instead of a comment: `guard::ioc_hash_coverage()` (`guard/mod.rs`) is the one place that says a process start is **not** hash-checked and why, `guard.status` returns it under `ioc`, and `PROTECTION-MATRIX.md` §4.1 points at it. `engine/src/tests.rs` pins the fact (`the_guard_status_states_that_process_start_does_not_hash`) so turning hashing on later cannot pass by editing only a comment. Measured 2026-11-10: `cargo test` **201 passed / 0 failed**, `scripts\pipeline.ps1 -Tier fast` **green, 4 of 4** (74.7 s, then 57.6 s on the frozen tree; `qa/report.md` engine count **200 → 201**) — decision recorded as **D-048** | `guard/etw.rs`, `guard/mod.rs`, `docs/DECISIONS.md` D-048, PROTECTION-MATRIX §4.1 |
| MED | IDS = hosts-file blocklist (DNS only); no Suricata/ET-Open | `ids/mod.rs` |
| MED | **The release lane signs each build with a certificate minted for that build, and D-051's pin is the identity of *that* build** — so the next release's payload is judged against the previous build's key and refused. It fails closed (no update, never a wrong accept), and the lane says it out loud: `make-release.ps1` ends with "the throwaway signing key does not outlive the build it signed" (`scripts\codesign-cert.ps1` keeps it as a PFX in the job's TEMP). The evidence is a pile rather than a pair: **12 distinct certificates** with the identical subject `CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)` sat in this machine's user stores when it was counted on 2026-11-11 (24 entries across `Cert:\CurrentUser\TrustedPublisher`, `TrustedPeople` and `My` — `ABB0FF3D...` from 2026-10-28, then `731A6520...`, `ED58002F...`, `AB9A9616...`, `59A150FD...`, `1F08A3EF...` and six more from 2026-11-04 onward), one per signing run, and the published release adds a thirteenth on the artifact itself (`E04CE197...531C3CF5`, issued 2026-11-04). So the CN identifies nothing, and a pin on it (D-016's state before D-051) would have matched the wrong certificate — while a pin on the thumbprint, which is what D-051 built, is exactly the wrong instrument for an identity that changes every build. The pile is also the script's own warning coming true: each entry is a trust anchor in somebody's profile and nothing in the build notices them accumulating. What is broken is the release's **identity**, not the code: mint one certificate and keep it as the `MICS_PFX` and `MICS_PFX_PASSWORD` secrets (D-034's wiring, load-bearing now for a second reason) — free, and nothing left that code can do. The `MICS_UPDATE_SIGNER_THUMBPRINT` hook is not that repair (it has to name the *next* release's certificate, which is knowable only once an identity is being kept): it is a probe and an operator override. The engineering half is built and measured — 2026-11-12: `scripts\verify-signer-identity.ps1` (**18 checks, 0 failed, 5.1 s**) shows one PFX giving every build one thumbprint and a second PFX a different one, and `make-release.ps1`'s report now prints `pinned : <thumbprint>` plus a `WARN` when the identity is the one whose key it deletes before returning. **It has to land before the next published release**; nothing carrying D-051 is published yet, so no user is affected. | `scripts/make-release.ps1`, `scripts/verify-signer-identity.ps1`, `engine/src/update.rs` |
| ~~MED~~ | ~~Canaries detect mtime/size changes by polling; a read-only open is not detected~~ — **closed 2026-11-05 (D-032) by evidence**: the snapshot carries the file's last-access time, so a read-only open is its own HIGH `canary_read` event under rule id `CANARY_READ` — a separate id on purpose, so a user can quiet reads without losing the ones that mean their decoy was overwritten — while a write still wins as CRITICAL `canary_triggered`/`CANARY`. `scripts\verify-canary.ps1` (**20 checks, PASS**) drives a real engine over a private pipe with a private `USERPROFILE` and measures: a decoy MI CS had just written is settled silently inside the 90 s window (`READ_SETTLE`, and the engine's log says `canary settling` instead of hiding it), a decoy that was already on disk raises `canary_read` with its size and SHA-256 unchanged, one appended byte raises `canary_triggered`/critical, fifty metadata queries in a row move no last-access time and raise nothing (the poll cannot trip its own trap), and the engine's `read_detection` verdict equals the same measurement taken independently in PowerShell. **Found while measuring:** the verdict had been probed on the *previous* decoy folder, so on a machine whose decoys live on another volume it would have named the wrong disk — the probe now asserts `probed_on` is the decoys' own folder, and the engine re-measures when they move. What remains is honest and named: only a volume that keeps a last-access time can show a read, so `canary.status`/`guard.status` and the Canaries screen report the measured verdict (with the `fsutil behavior set disablelastaccess 0` that turns it on) instead of implying coverage, and the engine still cannot name the reader without the kernel event source | `guard/canary.rs`, `guard/mod.rs`, `dispatcher.rs`, `docs/PROTECTION-MATRIX.md` §4.2, `scripts\verify-canary.ps1` |
| ~~MED~~ | ~~**Firewall uses `netsh`, not FirewallAPI COM**~~ — closed by **و3** (2026-11-03, D-028): the engine speaks `INetFwPolicy2`/`INetFwRules`/`INetFwRule` in-process, so there is no child process to hang, no English console text to parse and no locale to depend on. `scripts\verify-firewall.ps1` (23 checks) compares the reads with `Get-NetFirewallProfile`/`Get-NetFirewallRule`, creates and removes one real rule, and proves the `netsh` dependency is gone by putting a fake `netsh.exe` first on PATH. **What stays open**: a country-sized `RemoteAddresses` string has no documented ceiling and was not measured, so `block_country` still sends one rule per country | `firewall/mod.rs`, PROTECTION-MATRIX §3.2 |
| LOW | Country CIDR lists are read from disk only (public country-list licences are unclear), so GeoIP stays empty on a fresh install until lists are placed in `rules\blocklists` or `%PROGRAMDATA%\MICS\blocklists` | `ids/geoip.rs` |
| ~~LOW~~ | ~~The guard's idle cost is **0.156 % of one core / 0.0028 % of this 56-thread machine** with one inert rule in force; with the shipped starter pack the earlier runs measured 0.234 %~~ — **closed 2026-11-03 (و4)**: re-measured with the **shipped pack** actually loaded (`measure-guard-cpu.ps1 -RealRules`, four 60 s windows, 56 logical cores, guard on minus `MICS_NO_GUARD=1`): **0.156–0.521 % of one core, median 0.417 % = 0.0028–0.0093 % of the machine, median 0.0074 %**. The engine was unelevated, so ETW was denied and the 2 s poll loop is what ran (`on.err` names it); the guard-off half measured 0.000 % in every window — below the 15.6 ms process-timer resolution, i.e. < 0.03 % of one core. The earlier "with the starter pack it is 0.234 %, the difference is one-time startup matching" is **not supported by this measurement**: the lowest shipped-pack window equals the inert-rule number, so the spread is run-to-run noise on a busy 56-thread box, not a rule-count effect. The row's *number* was stale; the `< 1 %` budget holds under either definition | `guard/mod.rs`, `platform/windows/pids.rs`, `scripts/measure-guard-cpu.ps1` |
| LOW | No key-free sha256 hash feed exists any more (abuse.ch needs an Auth-Key), so `ioc_hashes` reports `not_configured` until the user pastes a URL + key in Settings → Intelligence (env hooks `MICS_IOC_FEED_URL`/`MICS_IOC_FEED_KEY` still work) | `sync/mod.rs` |
| ~~LOW~~ | ~~**The helper's caller check has nothing to compare against in a portable run**~~ — **closed 2026-11-03 (و4) by evidence**: `verify-helper.ps1` now starts the helper in exactly that layout (an empty `PROGRAMDATA` plus a separate `MICS_DATA_DIR`, so no install account exists) and measures both halves in one run: a client that is **not** the engine image is refused — `{"ok":false,"error":"this pipe only serves the MI CS engine"}` — while the helper's own log carries `no installer account recorded (no %PROGRAMDATA%\MICS) - the caller image is the only check`; then the same probe, with the documented `MICS_ENGINE_PATH` pin the installer records, is served (`pong:true`). The helper reads that pin from its own environment, which is why the probe uses two helper processes — the first version of this check reused one and the "pinned client" expectation failed, which is what made the behavior visible. `RESULT: PASS`, exit 0, 15 checks; the fallback stays what F-2 says it is (the pipe ACL is what keeps other users out) and is now measured rather than asserted | `platform/windows/caller.rs`, `privileged/server.rs`, `scripts\verify-helper.ps1`, D-017, THREAT-MODEL F-2 |
| ~~LOW~~ | ~~**The update pin is the signer's subject name, not its thumbprint**: a certificate with the same CN (`MI CS Code Signing`) issued by a CA that failed identity validation would pass — and since **no CA can issue that CN at all** (CSCBR §9.2.2 requires the subject CN to be the verified legal name, measured 2026-11-06), the pin stops matching the moment ب5 is bought: without decision (c) the first CA-signed release is refused by `update.rs:128` as "signed by X, not MI CS Code Signing" and reported as foreign by `selfcheck`. A thumbprint pin breaks on every locally re-issued release certificate, which is why the fix is thumbprint-when-configured and the CN otherwise~~ — **closed 2026-11-11 (D-051)**: the pin is a certificate, not a name. `signature::Pin` holds either a thumbprint or the release CN, `update_pin()` builds it once (`MICS_UPDATE_SIGNER_THUMBPRINT` → the thumbprint of the certificate **inside this engine's own image**, read from the PE without building a chain → `Pin::Name(EXPECTED_SIGNER_CN)` only for a build that has no signature of its own), and both the payload check (`require_signed_by_pin`, over **both** binaries of the archive — the call that would have refused a CA-signed release) and the manifest's `judge()` compare that one value; `trust()` classifies against it instead of the CN and the package self-check now names the certificate it found. So a CA-signed release recognises itself, and a same-CN certificate from somebody else is refused. Measured: `cargo test` **206 passed, 0 failed** (five new cases, two of them over the **real** signed `dist/MICS-portable/mics-engine.exe`), `cargo clippy --all-targets` clean, `scripts\verify-update.ps1` **45 passed, 0 failed, 0 skipped** against an engine built from this source — part 7 refusing a correctly signed feed under the wrong thumbprint and naming both, part 8 being the name fallback itself — and the release gate itself, `scripts\verify-manifest.ps1`, run under three pins on the signed package in the tree (no hook = PASS as before, the engine's own thumbprint = PASS, another certificate = refused with both thumbprints named, a hook that is not a thumbprint = refused before a file is read), with `scripts\verify-tamper.ps1` green on the changed script at **41 checks, 0 failures**. What F-3 still carries is the other half, and it is not a pinning gap: the pin comes out of the file under question, so a re-signed **copy** pins its own certificate | `platform/windows/signature.rs`, `scripts\verify-manifest.ps1`, D-051, D-016 (amended), `docs/OPEN-DECISIONS.md` item 3 (settled), THREAT-MODEL F-3 |
| ~~LOW~~ | ~~**A language folder that `pubspec.yaml` does not declare renders every key raw, silently**: the pack loader swallows a failed asset read on purpose ("a module that has not been translated yet must not break the app"), so nothing logs or fails when a whole language is missing from the asset list. `test/lang_registry_test.dart` now fails instead, and the app itself gates its first frame on the settings *and* the packs (`lib/main.dart`), so this cannot reach a user who is running a correct build~~ — **closed 2026-11-10 (D-050)**: the loader *reports* it now instead of only tolerating it. `I18nLoader` classifies every language's load (`PackLoad`, `i18nPackLoadNote`) and writes **one** line per language that lost anything, through an injectable sink (default `stderr.writeln`), worded apart for the two cases: `no pack loaded for "en" ... is not in the asset list (see pubspec.yaml "assets:")` against `1 of 19 module(s) did not load ... (first: assets/i18n/ar/app.json)`. Settings prints one line naming the language whose own pack is empty (`settings.languagePackMissing`, `{language}` = its native name), beside D-049's line — that notice is about the *tag*, this one about the *build*, and the two are told apart on purpose. The tolerance itself stays, because failing is worse than degrading here: `lib/main.dart` gates the first frame on this provider ever having a value, so an exception would hang the splash instead of showing a raw key. Both halves are pinned — `test/i18n_pack_load_test.dart` (the **real** bundle loads a pack for every bundled language and logs *nothing*, so a correct build stays quiet; a folder the asset list does not carry loads empty, is named once, and the app still answers; one unread module is logged as a gap, not as a missing pack) plus one case in `test/ui_screens_test.dart`; with the log call removed exactly the two log cases fail and with the screen line removed the widget case fails. The first run of those tests also found a second defect of the same shape: `i18nModules` carried an **`about` entry no pack ships**, so the loader asked for a file that was not there on every start of every language — entry removed (the About surface's copy lives with `settings`) and `test/lang_registry_test.dart` now checks the module list and the shipped files in **both** directions | `lib/core/i18n/app_i18n.dart`, `lib/features/settings/screens/settings_screen.dart`, `test/i18n_pack_load_test.dart`, `test/lang_registry_test.dart`, `assets/i18n/README.md`, `lib/main.dart`, `pubspec.yaml` |
| ~~LOW~~ | ~~**The engine stores a language tag the UI cannot render**: `settings.set lang=de` is accepted and persisted (deliberately - the engine must not need a release per language), and the UI falls back to Arabic via `AppLang.byCode(...) ?? AppLang.ar`, so a hand-edited settings file shows Arabic rather than the requested language. The picker only ever offers bundled languages~~ — **closed 2026-11-10 (D-049)**: the chain ends in **English** now. `AppLang.resolve(code)` resolves a bundled tag to it, an absent or empty code to the engine's own default Arabic, and a tag with **no pack** to English — the language a missing *key* already fell back to (`lookup`), so the frame is one language instead of Arabic layout over an English key table. The screen is no longer silent about it either: `AppSettings` carries the tag the engine actually holds (`storedLangTag`, deliberately not the language being rendered, which is a fallback) and `toEngineJson` writes that tag back, so a hand-edited one survives an unrelated settings write instead of being replaced by `lang.code` — and when no pack answers to it, Settings prints one line naming the tag beside the picker. Pinned by four cases in `test/settings_model_test.dart` (`{'lang': 'de'}` renders English *and* reports the tag; `ar`/`en`/`en-GB`/`EN` are not "missing"; an absent tag is Arabic and not a missing pack; a write sends the stored tag back) and one in `test/ui_screens_test.dart` that mounts Settings against a fake engine holding `de` (the new `FakeEngine(initialLang:)`), finds the English pack, the tag named on screen and `rtlProvider` false, then picks العربية and watches both the notice and the tag go. Measured in this commit: fast tier **4/4, 69.6 s** on the first green run and **59.2 s** on the re-run of the frozen tree — `flutter analyze` clean, `flutter test` **172 passed** (5 of them new), engine test **201 passed**, `cargo clippy` clean. Reverting the resolver to the pre-D-049 fallback fails exactly the two new cases, so they pin the behaviour rather than describe it | `lib/core/i18n/app_i18n.dart`, `lib/features/settings/screens/settings_screen.dart`, `assets/i18n/{ar,en}/settings.json`, `test/settings_model_test.dart`, `test/ui_screens_test.dart` |
| ~~LOW~~ | ~~`nvd_api_key` / `ioc_feed_key` are plaintext in `settings.json`~~ — **closed 2026-11-03 (و4)**: both keys now live in `<data dir>\secrets.dat`, DPAPI-protected at machine scope (the primitive the quarantine master key uses) behind a `MS1\0` header, written before the document and replaced atomically; `settings.json` no longer holds them at all, a file written by an older build is migrated on the next start (the plaintext is taken out and the document rewritten without it, idempotently), and the proving test asserts that neither the document nor the secrets file contains the value that went in. **Honest limit**: machine-scope DPAPI binds the blob to the computer, not to a user, so another local account can still ask Windows to decrypt it (`THREAT-MODEL.md` F-5) — what it removes is the plaintext copy that travelled in backups, shared folders and pasted logs | `settings.rs`, `secrets.rs`, THREAT-MODEL F-5 |
| ~~LOW~~ | ~~**Dark mode is not contrast-audited**~~ — closed by small step 4: the dark palette was measured with the same 29 pairs (7 below their bar: the border at 1.32/1.21, secondary text at 4.06/3.73, `onError` 3.67, and two composited tints), fixed, and frozen in `test/dark_contrast_audit_test.dart`; both modes now assert 29 of 29 (`docs/CONTRAST.md`) | `app_theme.dart`, `test/dark_contrast_audit_test.dart` |
| ~~LOW~~ | ~~**No signed integrity manifest**, so a repackaged copy is not detectable *by the app itself*~~ — **closed 2026-11-03 (ج2, both commits)**, with its honest limit written down: the shipped engine carries a SHA-256 manifest of every other shipped file inside its own signature, re-reads it at start-up, re-hashes the folder it runs from and reports `ok` / `untrusted-certificate` / `unverified` in `status` — About shows the line, and a manifest that disagrees with the files raises a card naming them. `make-release.ps1` builds and injects it, `verify-manifest.ps1` proves the package against it, and `-Tier release` refuses one it fails. What stays open is in `THREAT-MODEL.md` F-11: a from-source rebuild re-signed with another key, plus the engine's manifest recording signed hashes rather than content (§0.6 row 13) | P5, THREAT-MODEL F-11, `engine/src/selfcheck.rs` |
| ~~LOW~~ | ~~**When the engine cannot start at all, the UI cannot say why.**~~ — **closed 2026-11-10 (small step 9):** a start that fails now re-runs the engine once with stderr piped (the detached spawn throws it away), keeps the **last twelve lines it printed** and shows them in Settings → Engine under *Why it would not start*, so the Low-integrity refusal below reaches the user instead of a retry that cannot work. Proved by `test/engine_refusal_test.dart` (the tail, its 12-line bound, and a line split across two stderr chunks) and by the two `settings:` cases in `test/ui_screens_test.dart` (the sentence is on screen; a running engine shows nothing). The engine's refusal is one excellent sentence — `MI CS was started from a Low-integrity location (…): it cannot write its state database ("attempt to write a readonly database") or reach the privileged helper … run the installed copy in %LOCALAPPDATA%\MI CS, or extract the release ZIP outside a web root or sandbox folder` — and the app spawns it with `ProcessStartMode.detached`, so that text goes to a discarded stderr: the user sees "engine missing" and a retry that cannot succeed. Measured 2026-11-07 by staging the same package in a Low-labelled folder (trap 33), where the portable copy failed identically. ~~**Fix direction:** capture the child's stderr on the first failed connect (normal mode, drain it, then let the process go), or have the engine leave the refusal where the app already reads — the log tail it shows on the crash screen~~ | `lib\core\ipc\ipc_client.dart`, `lib\features\settings\screens\settings_screen.dart`, `engine\src\main.rs:199` |
eatures\settings\screens\settings_screen.dart`, `engine\src\main.rs:199` |

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
- [x] Ensure `test/icon_test.dart` passes for all sizes without loss — **verified
      2026-10-31** (small step 6): `flutter test --no-pub test/icon_test.dart` runs 6
      assertions and passes; the size set is asserted as *equals* the ten sizes, so a
      lost frame fails rather than being tolerated, and the two task icons are
      byte-identical while `desktop.ico` differs.
- [x] Verify `windows/runner/resources/app_icon.ico` includes all sizes — same test:
      it reads the ICONDIR table and requires exactly {16, 20, 24, 32, 40, 48, 64, 96,
      128, 256} for `app_icon.ico`, `assets/icons/mics.ico` and
      `assets/icons/desktop.ico`, and checks the rasterised SVG masters exist.

**Other remaining tasks**
- [x] Light‑mode contrast audit — 36 pairs measured against WCAG 2.2, 25 below their bar
  (`docs/CONTRAST.md`, steps أ2–أ3): 25 of 36 failing when measured, **29 of 29**
  passing after the fix, each ratio pinned by a test.
- [x] AUMID registration — cards were raised under `MICS` without it being
  registered, so Windows' own notification settings labelled the source with the raw
  id (step أ4): `scripts\register-aumid.ps1` writes the key + the shortcut property,
  `scripts\verify-aumid.ps1` reads 5 of 5 back and `-Remove` reverses both.
- [x] Screenshots of the light theme in the documentation — four renders, Arabic UI,
      regenerate with `flutter test --no-pub tool\write_screenshots_test.dart`.
- [x] Complete `docs/PROTECTION-MATRIX.md` as a standalone document — done (small
  step 7 verified it: 10 sections, layers at a glance, per-layer sees/detects/blocks,
  and the evidence table; README links it now).
Resolved during P1/P2a (keep for context): pipe closed after the first client;
blocking read + write on one handle deadlocked (fixed with `PeekNamedPipe`);
`scan.start` blocked the UI for the whole scan; engine had no log file; settings
were UI-only and language/theme changes wiped them; engine options ignored
settings and read environment variables only.

---

## 8. Environment traps (learned the hard way)

1. **`engine/target` may be ACL-locked** → `cargo` fails on
   `.cargo-build-lock`. Use `CARGO_TARGET_DIR` pointed at a **fresh, empty**
   directory; never try to "fix" it by hand. Measured 2026-11-12: the directory
   this trap names as the workaround (`%TEMP%\mics-target`) is a trap itself once
   an earlier session has left a tree there — cargo then failed with
   `error: failed to write ...\Temp\mics-target\release\.fingerprint\...\invoked.timestamp`
   / `The system cannot find the path specified. (os error 3)` while the same
   build into a new empty directory (`C:\mics-mt`) compiled normally.
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
   uses. Measured 2026-11-12: cargo does not do that, so a lane run died on
   `error: failed to remove file ...\engine\target\release\mics-engine.exe` /
   `Access is denied. (os error 5)` three times over, and the holder was a
   `mics-engine.exe` running under **another account** (the helper's — its path and
   command line are unreadable from this shell, trap 6), so retrying or waiting
   never helps. `Rename-Item` succeeding while delete fails is how this is told
   apart from an ACL problem; the way out is trap 1.
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
    - **The "is anyone running from it" test was itself wrong (2026-10-31).** It
      reads `$_.Path`, which is **empty for an elevated process**, so the check
      passed while an elevated MI CS had the folder's DLLs mapped; the delete then
      removed the four unlocked files and died on the rest — the gutted folder this
      trap is about, one layer down. The swap is now a **single rename of the whole
      folder aside** before anything is deleted, so a mapped file makes it fail
      *whole* (`The process cannot access the file because it is being used by
      another process`) and leaves the previous copy intact; the old folder is only
      removed after the new one is in place.

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

17. **A shortcut's AUMID is not a `WScript.Shell` field, and the start-menu index
    lags it.** `System.AppUserModel.ID` lives only in the Shell property store, so
    `$shell.CreateShortcut()` cannot write it — it needs `IPropertyStore`
    (`scripts\aumid-interop.ps1`). Two traps inside that one: **`InitPropVariantFromString`
    is not exported by name from `propsys.dll`** on this Windows build, so the
    P/Invoke throws `EntryPointNotFoundException` and the `PROPVARIANT` has to be
    built by hand (`vt = VT_LPWSTR` + `Marshal.StringToCoTaskMemUni`); and
    `Get-StartApps` keeps reporting the *old* AppID (the exe path) for several
    seconds after the property changes, so a probe that checks it immediately
    reports a false failure (`verify-aumid.ps1` waits ~5 s for it). Removing the
    property again is `SetValue(VT_EMPTY)`, not writing an empty string.
18. **A Dart script's exit code comes from `dart:io`'s `exitCode`, not from what
    `main` returns.** `Future<int> main()` compiles, runs and prints everything
    correctly, and `dart run tool\sbom.dart --check` still hands the shell **0** —
    so a release gate written as `if ($LASTEXITCODE -ne 0) { fail }` passes while
    the tool is reporting a stale file (found while wiring ب1a; the tool now sets
    `exitCode` and prints a `RESULT: PASS/FAIL` line, like the PowerShell probes).
    Check a new Dart tool with `& dart run tool\x.dart; "exit=$LASTEXITCODE"` after
    making it fail on purpose, never by reading its output alone.
19. **A CLI subcommand is not a flag, and a hidden child's error goes nowhere.**
    `mics-engine install-helper` works; `mics-engine --install-helper` is a clap
    usage error that exits **2** *before* the process writes its startup line — and
    since the engine launches it with `SW_HIDE`, stderr reaches no file and the only
    symptom at the caller is "the elevated step failed (exit code 2)". That was
    P1.5's install button, dead for a day while `verify-helper.ps1` stayed green (it
    tests the helper console path, not the argument). **It happened three times**:
    the install call, the uninstall call, and the service `binPath` — the last one
    presenting as `sc start failed: 1053` from the SCM and nothing else. Three rules
    came out of it: keep every command spelling in one constant
    (`privileged::INSTALL_COMMAND`/`UNINSTALL_COMMAND`/`SERVICE_COMMAND`) and parse
    it with the real CLI in a test; assert the **shape** of a generated command line
    (no `--` in `binPath`) rather than a literal string, because a literal test can
    pin the bug; and log the reason for a non-zero exit instead of trusting stderr.
    Diagnosing any "the engine did nothing" case: read
    `%LOCALAPPDATA%\MICS\logs\engine.log` for the UI-side engine, and
    `%PROGRAMDATA%\MICS\logs\engine.log` for the LocalSystem helper (**not**
    `%PROGRAMDATA%` alone — `resolve_base_dir` picks the per-user dir when the
    machine-wide one is not writable, and records the choice in
    `%LOCALAPPDATA%\MICS\.data-dir`).
20. **`flutter clean` is the only way to find out whether the Windows build works
    from scratch — and it needs two things this tree never had.** After
    `flutter clean`, the configure step fails twice: (a) `nuget.exe` is not on PATH,
    so the `audioplayers_windows` plugin cannot fetch
    `Microsoft.Windows.ImplementationLibrary` and CMake reports `Failed to install
    nuget package`; a stale `%TEMP%\NuGetScratch\lock` from a crashed NuGet makes it
    look like a permission error — delete the scratch dir; (b) CMake 4 no longer
    sets `CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT`, so Flutter's prefix guard
    silently goes false and the install step tries `C:/Program Files/mics_app`
    (`MSB3073 ... VCEnd exited with code 1`, real text: `file cannot create
    directory`). `make-release.ps1` now supplies `nuget.exe`, and
    `windows\CMakeLists.txt` decides the prefix by comparing values. Before
    trusting any "it builds" claim, run `flutter clean` once — an incremental build
    hides both.

21. **A Low-integrity *folder* makes the engine unable to write anything, and both
    symptoms point at the wrong component.** Trap 12 covers notification cards; the
    same label also breaks the state database and the privileged helper, and the
    user sees two unrelated errors for one cause. The workspace root `MIF` carries
    `Mandatory Label\Low Mandatory Level:(OI)(CI)(NW)`, so everything created under
    it — `dist\`, `build\windows\...\Release\`, a probe folder — inherits the label,
    and Windows starts a process at the label of its image. A Low process cannot
    write the Medium state directory (SQLite says `attempt to write a readonly
    database`, i.e. `SQLITE_READONLY`, which is a permission refusal and not a
    corrupt file) and cannot open LocalSystem's helper pipe for writing (the probe's
    access check fails, so `helper.status` reports `reachable: false` and
    `helper.install` says "installed but not answering" while the service is
    running). Measured 2026-10-31: the same `helper-status --json` printed
    `reachable: false` from `dist\MICS-portable\mics-engine.exe` (integrity
    `0x1000`) and `reachable: true` from `%LOCALAPPDATA%\MI CS\mics-engine.exe`
    (`0x2000`), one second apart.
    - Worse than the two messages: the app attaches to **whatever** engine owns
      `\\.\pipe\mics_engine`, so one leftover Low engine (started by an earlier
      probe from `dist\`) served every later UI session — an *elevated* app showing
      "readonly database" is the tell. Kill the stray `mics-engine.exe` in Task
      Manager; a normal shell cannot even show an elevated process's path.
    - Standing rules: the engine refuses to serve state below Medium and names the
      folder (`MICS_ALLOW_LOW_INTEGRITY=1` opts out for the diagnostic probes); a
      `SQLITE_READONLY` RPC failure appends the data directory and the repair
      (`storage::sqlite::readonly_hint`); "not answering" names the integrity level
      it measured. Diagnose with `icacls <folder>` (the `Mandatory Label` line) and
      never run MI CS from this tree — the runnable copy lives in
      `%LOCALAPPDATA%\MI CS`.

22. **`\"` is not an escape in PowerShell, and an elevated engine hides a broken
    helper path.** Two lessons from the same failed acceptance run (2026-11-01):
    - Inside a PowerShell **double-quoted** string the backslash is literal and the
      quote closes it; the escape is a backtick (`` `" ``) or a doubled quote. A script
      that builds a rollback line with `\"HKLM\…\"` therefore ends its own string early
      and PowerShell refuses the whole thing with `Unexpected token 'HKLM\…\"'` — which
      reads like a permissions problem but is a parse error, thrown *before* the
      elevated step ever runs. Build the line with a single-quoted format string
      instead, and let a test compile every script (`[scriptblock]::Create`, parse
      only) rather than waiting for a user to find it.
    - `netsh advfirewall set <profile> firewallpolicy` takes **one** comma-separated
      argument, inbound first — `BlockInbound,AllowOutbound` — and the only way to read
      it back is `netsh advfirewall show allprofiles`; `show <profile> state` prints no
      policy line. Passing the halves as two arguments is "The number of arguments
      provided is not valid", and nothing says so until someone flips the toggle.
    - And the reason both went unnoticed: when MI CS runs **elevated**, `is_elevated()`
      sends every privileged operation straight through the local code path, so the
      helper is never called and `priv.log` stays empty while the failure looks like a
      helper problem. An acceptance run must start the app unelevated, or it proves
      nothing about the helper.

23. **`Set-Content -Encoding UTF8` mangles a UTF-8 source file** (PS 5.1 reads it as
    ANSI, then writes the mojibake back as UTF-8 — and a `Get-Content` +
    `Set-Content` round trip also swallowed the first byte of the file). It is the same
    trap that double-encoded the README once (see §0.4). Never rewrite a source file
    with `Set-Content`; use the editor tools, or read with `[System.IO.File]::ReadAllText`
    (which strips a BOM) and write with
    `[System.IO.File]::WriteAllText($p, $text, UTF8Encoding($false))`. Catch it with
    `git diff` before committing: the diff shows `use` as `se` and every em dash as
    three characters.

24. **A bool formatted into a PowerShell command is a string.** `'... {0} ...' -f $s`
    prints `True`, and in argument position PowerShell binds that as the *string*
    "True" - a CIM cmdlet declaring `[bool]` refuses it with
    `ParameterArgumentTransformationError` ("Boolean parameters accept only Boolean
    values and numbers"), so the command never runs. Emit a literal instead
    (`$(if($s){'$true'}else{'$false'})`). This is how the SMBv1 rollback shipped broken
    while every test passed: the shape was allow-listed and the script parsed. Only the
    parameter binder objected. A rollback path needs a test that pins the *literal*,
    not just the shape.

25. **U+FEFF is not whitespace in Rust.** A hosts file that starts with a UTF-8 BOM
    puts the BOM at the head of line 1, and `str::trim` leaves it there - so a
    validator that walks `content.lines()` sees a line that is *only* U+FEFF and
    rejects a document it built itself (`hosts line 1 is not an address/host pair:
    "\u{feff}"`). Strip one leading BOM before validating, and write the document
    back unchanged. The same trap applies to any file we read, edit and re-validate
    (the `.ps1` files in this repo already have a BOM of their own, for the opposite
    reason: PS 5.1 decodes without one as ANSI).

26. **Windows' resource API and Authenticode signatures do not mix: writing a
    resource into an already-signed PE leaves the file unsignable.** `BeginUpdateResource`
    / `EndUpdateResource` rewrites the image but keeps the embedded certificate
    table, so the result no longer parses as a signed image; `signtool` refuses it
    with `SignedCode::Sign returned error: 0x800700C1` (`ERROR_BAD_EXE_FORMAT`) and
    `Get-AuthenticodeSignature` reports `NotSigned` on the wrecked file, so nothing
    warns you until signing fails. Measured 2026-11-03 on `mics-engine.exe` (24 MB,
    CFG + LTO + stripped): the identical injection into a *never-signed* copy,
    signed afterwards, is `Valid`. That is why `make-release.ps1` signs everything
    **except** the engine (`sign.ps1 -Except`), injects the `MICS_MANIFEST` resource
    and signs the engine once (`sign.ps1 -Only`), and why `D-025` carries an
    amendment. Two related facts for the next reader of a PE resource:
    `LoadLibraryEx` with `LOAD_LIBRARY_AS_DATAFILE` (0x2) reads a resource without
    running anything or loading dependencies, and `FindResource` wants the
    `MAKEINTRESOURCE` integer for `RT_RCDATA` (10) but a wide string for the
    resource name (`scripts\manifest-resource.ps1`).
27. **A package signed twice is unreadable to the engine's own signer check.**
    `signtool` appends a second signature to a file that already has one (measured:
    +344 bytes per pass, so re-signing `dist\MICS-portable` grew
    `flutter_windows.dll` from 205,368 to 205,712 bytes). `Get-AuthenticodeSignature`
    and `X509Certificate.CreateFromSignedFile` still read it, but
    `CryptQueryObject(CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED)` returns nothing, so
    `embedded_signer_name()` answers `None` and the three `signature::tests` that read
    `dist\MICS-portable\mics-engine.exe` fail - which is how a local `-Tier fast` run
    turned red on 2026-11-05 while the same tree passed on a runner that has no `dist`.
    Sign once per artifact, and if you re-sign a package by hand, move the artifact
    aside before running the tier (a fresh `make-release.ps1` rebuilds it).
22. **A partially evicted `%TEMP%` cargo cache looks like a broken tree.** On 2026-11-06
    the fast tier failed in `engine.test` (exit 101) with
    `error[E0463]: can't find crate for 'anstyle'` followed by a page of
    `cannot find value None`, `cannot find type Option` and `cannot find trait Into` -
    core prelude items reported missing, which is a cache problem and never a source
    problem. Nothing in the tree had changed: re-running the same step with the same
    `CARGO_TARGET_DIR=%TEMP%\mics-target` passed with **150 tests** (166 s, i.e. it
    rebuilt what was gone). The target directory lives under `%TEMP%`, which Windows is
    free to clean between sessions, so read the *first* error: if it is that cascade,
    re-run before believing anything is broken, and point `CARGO_TARGET_DIR` outside
    `%TEMP%` if it keeps happening.
28. **The fast tier's colour depends on `dist\` — which is gitignored — and on the
    certificate store.** Three `engine` tests in `platform::windows::signature` read
    `dist\MICS-portable\mics-engine.exe` (the artifact `make-release.ps1 -Sign` leaves
    behind) and require its chain to **build**, because `signer_name()` is
    `WinVerifyTrust` and anything but `ERROR_SUCCESS` becomes `None`. Measured
    2026-11-07: the fast tier was green at 12:58 with the older package sitting in
    `dist\`, then went **red** after a `-Sign` run replaced it — because
    `sign.ps1 -SelfSigned` deliberately does **not** add its certificate to
    `CurrentUser\Root` (that import blocks on a dialog a runner cannot answer: the
    2026-11-05 measurement recorded inside `sign.ps1`), so a freshly signed package is
    `UnknownError` and those tests read it as unsigned. Two ways out, and only one of
    them changes bytes: **trust the signer** — export the certificate from
    `CurrentUser\TrustedPeople` and `certutil -user -addstore -f Root <file.cer>` needs
    no elevation, shows no dialog and touches nothing (measured today: the same engine
    went `UnknownError` → `Valid` and all three tests passed) — or delete `dist\`, and
    the tests **skip** with a printed reason instead of failing. Also note that `-Sign`
    mints a **new** certificate on every run and leaves the old ones in the store: this
    machine had accumulated eight `MI CS Code Signing` certificates by the end of the
    day, which is harmless but makes "which one signed this?" a real question — ask the
    **file** (`Get-AuthenticodeSignature`), never the store.
29. **Adding a certificate to `CurrentUser\Root` has exactly one unattended path.**
    Measured 2026-11-07 while packaging the MSIX (D-037): `certutil -user -addstore -f
    Root <file.cer>` completes silently in under a second and prints "added to store",
    while the .NET route — `New-Object X509Store("Root","CurrentUser")` then `.Add()` —
    raises the modal **"Security Warning"** dialog and hangs forever in a session where
    nobody can click it (the dialog's owner had to be killed to get the desktop back).
    So a script that needs user-level root trust must call `certutil`, never the store
    API. Neither one is enough for MSIX deployment, which reads machine trust (trap 30).
30. **An MSIX that declares a service refuses to install without an administrator —
    and the error says so.** Measured 2026-11-07 on the package D-037 adds:
    `Add-AppxPackage -Path <signed.msix>` fails with **0x800B0109** ("the root
    certificate of the signature … must be trusted") because a self-signed chain ends in
    a root nobody trusts, and a *user-level* root does not clear it; signing is not the
    only wall either, because registering the **unsigned** staged folder in developer
    mode (`AllowDevelopmentWithoutDevLicense` was already 1 on this machine) fails with
    **0x80073D28 — "Administrator privileges required to install packaged service"**.
    Two consequences: a sideloaded test of the *service-bearing* shape needs an elevated
    install *and* a machine-trusted signature, and any user who is not an administrator
    cannot install that shape from any source. **The A/B that changes the submission:**
    the same call, same staged folder, with the service declaration and its two restricted
    capabilities removed, **registers with no elevation at all** (`MICS.Desktop 0.1.0.0`,
    `Status Ok`, one declared capability, removed cleanly) — D-038. So the shape a Store
    user receives needs neither an administrator nor a restricted-capability approval.
    Also worth knowing:
    `Get-AuthenticodeSignature` reports `UnknownError` for a **correctly signed** MSIX —
    the AppX signature is not a PE signature — so signtool, not .NET, is the tool that
    answers "is this package signed".
31. **`X509Store.Add` on the object you just signed with puts its private key in the
    store.** `scripts\codesign-cert.ps1` builds the throwaway code-signing certificate in
    memory and says in its own header that only the *public* half goes into a store — but
    it was adding the `X509Certificate2` it had just signed with, and that object carries
    its private key, so the store persisted the key association. Measured 2026-11-07:
    **17 MI CS Code Signing entries across `CurrentUser\TrustedPeople` and
    `CurrentUser\TrustedPublisher`, 16 of them `HasPrivateKey = True`**. Adding the
    certificate read back from the exported `.cer` fixes it, and the fix is measured: a
    fresh run adds two entries while the key-bearing count stays at 16, and a second run
    reuses the same thumbprint and adds nothing. Two consequences to keep in mind: the pfx
    in `%TEMP%\mics-signing` is the only copy of the private key, so losing that folder is
    what makes the script mint a *new* certificate — and a store entry can never be reused
    for signing for the same reason, which is why the pile grows. The script now reports
    how many earlier certificates are still trusted; removing them is a person's decision,
    not a build step, and this keeps only the newest:
    `$all = Get-ChildItem Cert:\CurrentUser\TrustedPeople, Cert:\CurrentUser\TrustedPublisher | Where-Object Subject -like '*MI CS Code Signing*'; $keep = ($all | Sort-Object NotBefore -Descending | Select-Object -First 1).Thumbprint; $all | Where-Object Thumbprint -ne $keep | Remove-Item`.
32. **`Add-AppxPackage -AllowUnsigned` does not mean "any unsigned package".** The
    parameter exists on this machine, and it refuses the service-free package with
    **0x80073D2C — "The package deployment failed because its publisher is not in the
    unsigned namespace"** — measured 2026-11-07 with both our real subject
    (`CN=MI CS Code Signing, O=Mourad Ibrahim (MI CS)`) and a bare `CN=MI CS (dev)`. An
    unsigned package has to carry a publisher OID that marks it unsigned, so this is not a
    way around a missing certificate. What *does* work unelevated, and is what the A/B in
    `docs/SIGNING.md` §3 used, is developer-mode **registration** of the staged folder
    (`Add-AppxPackage -Register build\msix-stage\AppxManifest.xml`): no publisher trick, no
    signature, no administrator — for the shape that declares no service.
33. **A Low-labelled staging folder makes a working package look broken, and it does it
    silently.** This workspace (`H:\…`) carries `Mandatory Label\Low Mandatory Level:(OI)(CI)(NW)`
    — `icacls <dir>` prints the label — and Windows gives a process the label of the folder its
    **image** is in, not of the user who launched it. Staged there, the packaged app started, sat
    there and never spawned its engine; the **portable** copy failed identically, which is how the
    folder was identified as the cause rather than the MSIX. The engine does explain itself —
    `MI CS was started from a Low-integrity location (…): the engine cannot write its state
    database ("attempt to write a readonly database") or reach the privileged helper … run the
    installed copy in %LOCALAPPDATA%\MI CS, or extract the release ZIP outside a web root or
    sandbox folder` — but it prints that to **stderr**, and the app spawns it with
    `ProcessStartMode.detached`, so the text is thrown away and the UI only ever shows "engine
    missing" (§7). Staging under `%LOCALAPPDATA%` fixes it outright, measured 2026-11-07:
    `-StageDir "$env:LOCALAPPDATA\mics-msix-stage"` and the app, the engine, the pipe, the guard
    and the integrity self-check all work. `MICS_ALLOW_LOW_INTEGRITY=1` runs the engine anyway, but
    it is a diagnostic hook, not a fix.
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

34. **A launch that hands itself over exits by crashing, not by ending.** Measured 2026-11-13 with
    `scripts\verify-single-instance.ps1`: the second launch of the app ends with exit code
    **0xC000041D** (`STATUS_FATAL_USER_CALLBACK_EXCEPTION`), and the Application log gets
    Application Error id **1000** for `mics_app.exe` — `0xC0000005` (access violation) and then
    `0xC000041D` — with Windows Error Reporting id 1001 behind each. The **pre-fix** build exits
    with the same code, so this is older than the window flash D-059 fixed and is a second symptom
    of the same branch (`quit()` on the process that hands itself over). A single launch closed
    politely (`CloseMainWindow`) left no such entries, but that app did not exit either — on this
    machine a close hides it to the tray, so the comparison is suggestive, not conclusive. Why it
    matters: every right-click scan writes crash entries into the user's event log, and on a machine
    where WER is set to show a dialog, that dialog is itself a window appearing where none should.
    **Closed 2026-11-14 (D-060).** Three ways of leaving were measured on this path with the same
    probe: `quit()`'s `windowManager.destroy()` — what the branch used to call — dies with
    `0xC000041D` plus both events; Flutter's own
    `ServicesBinding.exitApplication(AppExitType.required)`, whose documentation calls it "always
    preferred over calling `exit`", dies with the same code and the same two events; `dart:io`'s
    `exit(0)` exits **0** with no Application Error and no WER entry. The branch calls the third
    now, and check 3 of the probe asserts the exit code, so this cannot come back unnoticed: it
    reads `FAIL ... (exit code -1073740771)` against either of the first two.
