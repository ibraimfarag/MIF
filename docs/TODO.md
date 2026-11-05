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
> Last updated: 2026-11-05 · **the shipped detection pack is measured by what it catches,
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
> `targets: aarch64-pc-windows-msvc`, and both ARM64 jobs stay informational. The
> release lane is otherwise in place: `.github/workflows/release.yml` (`version`,
> `package-x64` 10 steps, `engine-arm64`, `package-arm64`, `publish`),
> `make-installer.ps1 -Arch` and the arch-aware NSIS guard (built and checked for
> x64, refused for arm64 on an x64 package). The last release-lane
> item that still needs you at the machine is **د3**
> (E2E on the built installer): one per-machine run, and with that click the whole
> product can be measured as a user meets it. ز2-د stays blocked on D-023 and the
> bridge endpoint; the autonomous alternatives meanwhile are هـ1 (the default
> update-manifest URL + a signature check before applying) or a §7 register row. The
> ARM64 engine is built and checked but **has never been run here** — no ARM64
> machine exists — and ARM64 CI jobs now exist for that (marked informational until
> they have a green run) while the ARM64 *app* still needs an ARM64 host, which CI
> can supply.
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
> per-machine run is the one ب3 item left, and it needs one UAC click from you; the
> helper acceptance in §0.2 item 1 and a signing certificate are the other two that
> still need you.
> README is written; the app runs unelevated and was verified end-to-end on a real
> machine.
>
> **New session? Read §0 "Resume here" first** — current state, the next
> ordered steps, what is blocked on a human, and the environment must-knows.

---

## 0. Resume here — a new session starts with this section

### 0.0 How to start the next session

Open a fresh session and paste exactly this:

> اقرأ docs/TODO.md §0 (وبالخصوص §0.3c) و docs/ROADMAP.md، وشوف اللي فاضل:
> **د3** لو الكليكة وصلت (التشغيل E2E على المثبّت per-machine)، وإلا خُد خطوة من
> اللي فاضل — صف من السجل (§7) أو **هـ1** — واحدة في كل مرة، وكل واحدة بدليل
> القياس اللي اسمها في الصف. متكتبش أرقام من غير قياس. وشغّل
> `scripts\pipeline.ps1 -Tier fast` قبل الكوميت.

That means: read §0 (especially §0.3c) and `docs/ROADMAP.md`, then take **د3** if
the UAC click has arrived — it is the E2E run on the built per-machine installer,
which installs the product *and* the helper and removes both; the autonomous half
is already written into `verify-installer.ps1`, and nothing was invented for the
half that needs the click. Without the click, take one row of the register (§7) or
**هـ1** (the default update-manifest URL and a signature check before applying),
one commit at a time, each with the proof its row names.
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
needs an ARM64 host and nothing ARM64 was ever run). What is left is
**د3**, the register (§7) and the things that need the user.
The two things that still need a human are
the certificate in §0.2 and the three-operation helper acceptance (the service itself
is installed, running and reachable). The rules that session must keep, all from
`AGENTS.md`:

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

**This section is empty now**, and so is the rest of §0.5: **all eight small steps are
done** (the register keeps only rows that need elevation, money, a signing certificate
or a decision from you). What is left is no longer "small steps" — it is the release,
integrity and QA work in **`docs/ROADMAP.md`** (phases, tasks, priorities, estimates
and the order to work in). Short version, as of 2026-11-03: **و1 (scheduled scan,
D-027) and و3 (the firewall speaks the Windows Firewall API, D-028) are done → و4**
(the executable LOW rows of §7) **→ ب2** (the ARM64 leg, built and compile-verified
only) **→ د3** (the E2E on the built installer; its automatable half runs today, the
per-machine half needs one UAC click from you). The two things that cannot move
without you are P1.5 (the three-operation helper acceptance, §0.2 item 1) and P4
signing (the certificate, §0.2 item 2).

### 0.2 Blocked on the user

Everything below waits on a human, and nothing else in the plan does. It was
recounted on **2026-11-04**; if an item is not here, it is not waiting on you.

1. **د3: three clicks, and the helper acceptance happens in the same session.**
   The old per-machine install was removed on 2026-11-04 (measured: `C:\Program
   Files\MI CS` and the `HKLM\...\Uninstall\MICS` entry are both gone; the leftover
   `MICSHelper` service still points at `engine\target\debug\mics-engine.exe`, and
   that is expected - the new installer's `install-helper` stops, deletes and
   re-creates the definition, so no manual cleanup is needed).
   The setup to run is the one built from `main` on 2026-11-03 17:20:
   `dist\MICS-setup-0.1.0-x64.exe`, 16,628,250 bytes,
   `sha256 CB6F912FB60C066FE751CFC3C176A696F29CDBA4359E6126E15FF9B2E19E41CA`.
   - **click 1** - run the setup, UAC yes, Next/Install/Finish. It shows "Unknown
     publisher" (ب5 is the fix) and installs **all users** with **one** prompt,
     including the helper. If it warns that the helper was not installed, stop and
     report that instead of continuing.
   - **click 2** - in the installed app, in **one** session: Network → *Default deny
     outbound* on; Hardening → *Disable SMBv1*; IDS → add one domain (that is the
     hosts write). Expect **zero** further prompts; a prompt means D-007's promise is
     broken and the operation's name is what matters.
   - **click 3** - uninstall from Apps & features; the uninstaller must remove the
     product **and** the helper in that one prompt, and a "could not remove its
     privileged helper" box means D-026 is broken.
   What I measure afterwards: the installed tree and shortcuts with their AUMID, the
   `Apps & features` row, that `MICSHelper` now points into `%ProgramFiles%\MI CS`,
   three `phase=start`/`phase=done` pairs in `%PROGRAMDATA%\MICS\logs\priv.log`, the
   firewall/SMB/hosts values read back from the OS itself, that the per-user copy in
   `%LOCALAPPDATA%\MI CS` is never touched, and that the uninstall leaves nothing
   behind.
2. **A real signing certificate (ب5, the only HIGH row in §7).** The local half is
   done and tested: `scripts\make-release.ps1 -Sign` self-signs through
   `CurrentUser\Root` + `TrustedPublisher`, signs DLLs then EXEs before hashing and
   zipping. A public release needs the bought certificate (`-PfxPath`/`-PfxPassword`
   already timestamps). **The subject must be exactly `CN=MI CS Code Signing`**
   (D-016 pins that name; a different one needs a new decision entry), and
   `docs/COST.md` carries the routes and their trade-offs - including the free
   SignPath route for open-source projects, which is only available while the source
   is public. Then **ب6**: a version bump, the signed zip + installer and a place to
   publish - and the place is now decided (**GitHub Releases**, item 6 below), with
   `.github/workflows/release.yml` written for it.
3. **Six decisions, one line each.** Every one of them stops work that is otherwise
   ready: *(a)* whether licensed **GeoIP**
   country lists may be bundled, since the licensing is unclear; *(b)* whether the
   detection content stays the **starter pack** or real rules are written — measured
   on 2026-11-05 so the answer is arithmetic rather than taste: the shipped pack holds
   **8 of its 10 rules to a file**, one of those (`Malicious_Macro_AutoOpen`) can only
   see an uncompressed container and a real `.docm` deflates its strings out of reach,
   and 2 rules cannot be proven by a text file at all (see D-033 and the row in §7);
   *(c)*
   whether the update pin moves to the certificate **thumbprint** (D-016) once a
   certificate exists; *(d)* whether **IDS** grows past the DNS blocklist
   (Suricata/ET-Open is out of scope today, so this reopens a decision); *(e)*
   whether **real-time watching** (و2, 6-10 h) is wanted, because it costs CPU
   continuously; *(f)* the **language-tag policy** (which tags the engine accepts and
   the UI can render) — measured on 2026-11-05: the engine accepts any BCP-47-shaped
   tag (deliberately not a closed list) and the UI resolves exact code, then the
   primary subtag, then falls back to **Arabic** while missing *keys* fall back to
   English, which is the incoherence the decision has to settle. The publishing
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
> manifest → **د1 + د2** QA → **هـ1 + و1** *(و1 done)* → **ب2 / د3 / د4** → **و3 + و4**
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
| ~~**ب1b**~~ | ~~`docs\COST.md`: the real costs (signing certificate) and what stays free~~ — **done**: `docs\COST.md` names the one purchase (a CA-issued certificate), the four constraints that decide *how* it can be used (hardware key since June 2023 → `-PfxPath` stops working, the `/sha1` path already exists), the options, what is deliberately not bought, and the ب5 checklist | written 2026-10-31 |
| **ب2** | ARM64 leg: Flutter target + `aarch64-pc-windows-msvc` engine, per D-003 | no |
| ~~**ب3**~~ | ~~NSIS installer: bundled engine + `rules` + offline intel, shortcut, AUMID, one UAC prompt~~ — **done** (steps 1–3, 2026-11-01): `installer\mics.nsi` + `scripts\make-installer.ps1` build `dist\MICS-setup-0.1.0-x64.exe` (15.8 MB); the per-user variant installs 70 files and removes everything (exit 0); both shortcuts carry `System.AppUserModel.ID` through `IPropertyStore`; the uninstaller refuses a copy its helper still points at (`/S _?=$INSTDIR` → 5); and `scripts\verify-installer.ps1` proves all of it in 126 s. Left for a human: one **per-machine** run (one UAC click) | done |
| ~~**ب4**~~ | ~~Fold the privileged-helper install into the installer (replaces the separate UAC step)~~ — **done** (2026-11-03, D-026): the per-machine section runs the shipped engine's own `install-helper` under the installer's elevation, so one prompt installs the product *and* the service, and the uninstaller asks `check-helper-ownership.ps1 -Remove` to stop and delete exactly the service whose binPath points at `$INSTDIR` (scoped to `HELPER_SVC_KEY`'s leaf, so a probe cannot touch the real `MICSHelper`); both variants compile and `verify-installer.ps1` passes end to end. Left for a human: the same one **per-machine** run | done |
| **ب5** | Real OV/EV certificate → sign the release, SmartScreen stops warning strangers | **yes** |
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
| **هـ1** | A default update-manifest URL compiled in, and a signature check on the manifest before applying (today both are user-supplied) |

**و — the register (parallel, not a phase)**

`docs/TODO.md` §7 carries **12 open rows (1 HIGH, 4 MED, 7 LOW)** out of 22 —
recounted from the table itself on 2026-11-03, after و4 closed six of them (the
incomplete package, the merged-audit ages, the blocking `vuln.scan`, the plaintext
keys, the guard cost, the portable caller check, the AUMID attribution) and the
dark-mode and `netsh` firewall rows closed earlier. The MED ones
worth pulling forward once the phases above allow it: **no real-time file watching**
(the scheduled half landed with و1, D-027), the canary checker being poll-based, and
Defender tamper protection.
The HIGH one left is the signing certificate and a published download (ب5 → ب6); the
incomplete-package HIGH row is **closed** — `verify-release.ps1` refuses a package
whose `rules\` went missing, measured with exit code 1.

**Blocked on the user (listed in §0.2, do not plan around them):** a real signing
certificate (ب5), and the three-operation helper acceptance in §0.2 — its install
prompt was answered on 2026-10-31 (the service is installed, running and reachable).

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
| **د3** E2E on the built installer | The automatable half runs in the probe: a silent `-TestUser` install into `%TEMP%`, the shortcuts' `System.AppUserModel.ID`, the AUMID key, the Apps-&-features entry, the uninstaller removing exactly what it created, and the refusal against a synthetic service key (all in `verify-installer.ps1` today). The per-machine half - **one UAC click from you** - installs for real and asserts: the app + engine + rules land in `%ProgramFiles%`, the shortcuts carry the AUMID, Apps & features has the entry, the **installer** created the helper service (not the app, D-026), `priv.log` has one `phase=start`/`phase=done` pair per operation, and the uninstaller removes all of it *and* the service while the user's own `%LOCALAPPDATA%\MI CS` copy stays untouched. The half that cannot run is skipped with a printed reason, never passed, and no number in the Done log comes from it. |

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
remains human is a certificate (§0.2/ب5) and the three-operation helper acceptance.
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
- **ب2** ARM64 (Flutter target + `aarch64-pc-windows-msvc` engine, D-003)
- ~~**ج1** build hardening (Rust LTO/strip/`panic=abort`, PE mitigations, Dart
  `--obfuscate --split-debug-info`)~~ — **done** (D-021), with the numbers in §0.3
- ~~**ج2** signed manifest + startup self-check + "unofficial build" banner~~ —
  **done** 2026-11-03 (D-025, with ط2's tamper probe)
- ~~**ب4** the helper install folded into the installer (removes the UAC step)~~ —
  **done** 2026-11-03 (D-026; the per-machine run is the one item left for a human)
- **د1** `qa/` JSON-RPC harness, **د2** per-screen widget tests
- **هـ1** a default update-manifest URL + signature check
- ~~**canary read-only** (the register's MED row)~~ — **done 2026-11-05 (D-032)**: the
  variable the row was missing is the last-access time, not a driver, so a read-only
  open is a HIGH `canary_read` event of its own (`CANARY_READ`), a write stays
  CRITICAL, a decoy MI CS has just written is settled for 90 s and says so in the log,
  and `scripts\verify-canary.ps1` (20 checks, PASS) measures all of it against a real
  engine — plus that the volume's read coverage is measured and reported rather than
  assumed. See the Done log for the defect the probe found on the way
- the register's open MED rows: Defender tamper protection, real-time watching

**Large — where a human or money is required**

- ~~**د4** `qa/report.html` + CI gate~~ — **done** (the checkbox was stale; see §0.3)
- **د3** E2E against the built installer (**needs one UAC click from you**)
- **ب5** the certificate → **ب6** public release (both need the user)
- real-time file watching as a real subsystem

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
| `scripts\register-aumid.ps1` | Windows labels a card's source `MI CS`: writes `HKCU\Software\Classes\AppUserModelId\MICS` (`DisplayName`, `IconUri`) and tags the shortcuts' `System.AppUserModel.ID` through `IPropertyStore` (WScript.Shell cannot set it). No elevation, no new file; `-Remove` puts both back |
| `scripts\verify-aumid.ps1` | The registration is really there and Windows agrees: reads the registry key, the shortcut property and the Shell's own `Get-StartApps` AppID. Read-only; exits 1 with the list of what did not hold |
| `scripts\verify-helper.ps1` | The privileged helper's protocol **unelevated**: ping/version answer, a privileged op is refused without an elevated token, an unmarked hosts document and a malformed firewall rule are refused, an op outside the closed set is refused, the audit log keeps intent/outcome but never the payload, `helper-status` sees it |
| `scripts\verify-pipe-acl.ps1` | Both pipe ACLs are what `docs/THREAT-MODEL.md` says: reads each live DACL back with `GetSecurityInfo` (engine pipe protected to the owner/SYSTEM/Administrators, helper pipe `INTERACTIVE`), and drives a real JSON-RPC `status` call over the hardened engine pipe so the ACL cannot pass by locking the UI's own user out. Isolated pipe names + data dir, so a running MI CS is untouched |
| `mics-engine.exe helper-status --json` | The status chain the UI renders (`installed/running/state/reachable/version/elevated/pipe`) |
| `mics-engine.exe helper-console` | Serves the privileged protocol in the foreground on `MICS_HELPER_PIPE` without the SCM (diagnostics, `verify-helper.ps1`) |
| `scripts\verify-hardening.ps1` | The binaries are hardened as claimed, read out of the **PE** rather than from the build flags: `DllCharacteristics` (`GUARD_CF`, `DYNAMICBASE`, `NXCOMPAT`, `HIGH_ENTROPY_VA`), the load-config `GuardFlags` (`CF_INSTRUMENTED`, `CF_FUNCTION_TABLE_PRESENT`, `CF_LONGJUMP_TABLE_PRESENT`), the CET marker when present, and a debug directory with no PDB. Pass a folder (judges `mics_app.exe` + `mics-engine.exe`, reports `flutter_windows.dll` but never fails on it) or a single file; `make-release.ps1` refuses to package what it fails |
| `scripts\make-release.ps1` | Builds the published artifact: clean `dist\MICS-portable` (engine + `rules` + app + `sbom.cdx.json` + `THIRD-PARTY-NOTICES`), `VERSION`, `MICS-portable-<version>-x64.zip`, `dist\SHA256SUMS`; fails instead of shipping an incomplete folder, refuses to start when the committed inventory no longer describes the lockfiles, refuses an un-obfuscated app or an unhardened binary, swaps the folder by renaming the old one aside instead of deleting it, and — after signing — builds the `MICS_MANIFEST` document from the final bytes, injects it into the staged engine, signs the engine and refuses to publish a package `verify-manifest.ps1` does not accept |
| `scripts\verify-release.ps1` | The artifact is what it claims: every checksum matches, the zip has every required file and exactly 2 rule packs (no `rules\rules`), the inventory parses and names a license for every component, the notices report a clean audit, the **extracted** copy answers the helper protocol, puts a real card on the desktop, loads its own `rules\guard` + `rules\yara` rather than the built-in fallback, and its binaries pass `verify-hardening.ps1` while `data\app.so` carries no Dart class names and no symbol table ships in the zip |
| `scripts\verify-manifest.ps1` | The package describes itself: reads the `MICS_MANIFEST` resource back out of the packaged `mics-engine.exe` (through `scripts\manifest-resource.ps1`, the one place the format lives), validates the envelope (format `1`, a version, sorted duplicate-free relative paths, nothing that walks out of the package), re-hashes every file it lists, and fails on a missing file, a size or hash mismatch, or an engine whose signature broke after signing (`HashMismatch`). It prints what the package carries that the document does not list, which is `VERSION` by design. `-Measure` prints the document instead of the verdict. `make-release.ps1` runs it on the staging folder, and `-Tier release` runs it on `dist\MICS-portable` (`manifest.verify`) |
| `dart run tool\sbom.dart` | What is inside the package, generated from what is pinned: `sbom.cdx.json` (CycloneDX 1.6) + `THIRD-PARTY-NOTICES` from `cargo metadata`/`Cargo.lock`, `pubspec.lock`/`dart pub deps --json`, the Flutter SDK's `LICENSE` and the two shipped fonts. `--check` exits 1 and prints `RESULT: FAIL` instead of writing when the committed pair is stale (`--verbose` lists what is excluded, and which components ship no text of their own); `make-release.ps1` runs it before it builds and `test\sbom_test.dart` re-derives the same inventory from the lockfiles |
| `cargo run --example toast_probe` | Which WinRT step of the toast path fails, with the HRESULT (diagnoses "no card at all") |
| `scripts\make-installer.ps1` | Wraps the assembled package in the NSIS installer: re-runs `verify-hardening.ps1` on the binaries first (an installer can never ship what the ZIP gate refused), finds NSIS without needing it on `PATH`, and prints the exe, its SHA-256 and the scope. `-TestUser` builds the same script as a per-user, no-UAC variant, which is how the install/uninstall path gets verified without a human clicking a prompt; `-HelperServiceKey` (verification only) points the uninstaller's helper check at another registry key, so the refusal path can be measured without touching a real service |
| `scripts\check-helper-ownership.ps1` | Whether the installed `MICSHelper` service points at one install folder: prints `RESULT: SAFE` / `OWNED` / `UNKNOWN` and exits 0 / 2 / 1. The uninstaller asks it before deleting anything, so a service is never left aiming at a deleted `mics-engine.exe`; read-only, no elevation |
| `installer\mics.nsi` | The installer itself: the package, a Start-Menu folder and a desktop icon, both halves of the AUMID the toast source needs (the registry key, and the shortcuts' `System.AppUserModel.ID` written by `register-aumid.ps1` through `IPropertyStore`), an Apps-&-features entry whose uninstaller refuses to remove a copy the privileged helper still points at, and an upgrade that reuses the previous install location instead of asking twice |
| `scripts\verify-installer.ps1` | The installer's promises, measured on a real install: a silent per-user install into `%TEMP%`, the app, engine and rule packs landing, both shortcuts' `System.AppUserModel.ID`, the AUMID key and Apps-&-features entry pointing at that copy, `Get-StartApps` filing "MI CS" under `MICS` with nothing under the exe path, the checker's answers, the uninstaller removing all of it while the machine's helper and the user's own copy stay untouched, and the refusal (error level 5, everything left in place) against a synthetic service key. Exports and re-imports the AUMID key, deletes everything it created, no elevation, ~2 min |
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
| P4 | Code signing (real cert), x64+ARM64, NSIS installer, SBOM/notices | **partly done**: the SBOM + notices are generated, committed and shipped (ب1a) and the cost question is answered (ب1b, `docs\COST.md`) — left = steps **ب2–ب6** in §0.3 |
| P5 | Threat model, integrity/anti-tamper, protection-matrix doc | **done 2026-11-03**: `docs/THREAT-MODEL.md` + `docs/PROTECTION-MATRIX.md` exist and F-1…F-4 are closed with measured evidence; the integrity story closed 2026-11-03 with **ج2** (the signed manifest inside the engine, the start-up self-check and the About line/notice), **ط2** proved both halves catch a tampered copy, build hardening (**ج1**) landed with the PE measured, and the README now says what it does and does not do (**ج3**). Left: F-11's reproducible-build note, which needs a toolchain decision rather than a slice |
| P6 | Full QA harness + HTML report, malware lab (later) | planned — steps **د1–د4** in §0.3 |

### Done log (append only)

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
    that certificate can be used, and one of them changes code: under the CA/Browser
    Forum's baseline (June 2023) the private key must live in hardware (token) or a
    cloud service, so **`-PfxPath`/`-PfxPassword` stops being usable** with a
    compliant certificate. The path that works is already in the repo — the
    self-signed branch of `scripts\sign.ps1` signs with `signtool /sha1 <thumbprint>`
    — so ب5 is "add a `-Thumbprint` selector and pass it through", not a rewrite. It
    also notes that the publisher CN is pinned by D-016, that timestamps keep old
    releases valid after renewal, and that EV's current SmartScreen advantage is a
    verify-at-purchase question rather than something this project asserts.
  - Prices are deliberately **not** quoted: they move, they are bundled with tokens
    or cloud subscriptions, and they depend on the validation type; the shape (a
    recurring subscription plus hardware/cloud) is what is fixed. The options table
    covers OV, EV, cloud signing (Microsoft's service is **Artifact Signing** as of
    2026, renamed from Trusted Signing), free OSS signing programmes, and the
    Microsoft Store (which re-signs with Microsoft's own certificate and would need
    the portable folder plus the `LocalSystem` helper repackaged as MSIX).
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
    UAC click is what §0.2 item 1 still asks for; its result gets recorded here when
    it runs.

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
| 8 | ~~Dark/light mode~~ | **done** — palette, System mode follows live OS switches; **both** palettes are audited and fixed (**29 of 29** pairs clear WCAG 2.2 each, pinned by a test — `docs/CONTRAST.md`; dark closed in small step 4) | P2, أ2–أ3 |
| 9 | Not hackable / not reverse-engineerable | **partial** — hardening landed (ج1, D-021): CFG on both binaries, LTO/stripped engine, obfuscated Dart snapshot, and `verify-hardening.ps1` gates the release on the PE. The start-up self-check landed with ج2 (2026-11-03): the engine re-hashes the files beside it against the manifest inside its own signed image and says so in About. What no local check can do stays open: a from-source rebuild re-signed with another key is indistinguishable, and the reproducible-build note is not written | P5 |
| 10 | README: what it does / does not + requirements | **done** — bilingual README with a capability matrix, requirements, data locations, privacy, build and troubleshooting | `README.md` |
| 11 | x64 / x86 / ARM64 | **decided** — x64 + ARM64; 32-bit UI impossible (Flutter), ARM64 build legs pending | D-003; P4 |
| 12 | Protection types | **done** — `docs/PROTECTION-MATRIX.md`: layer → sees / detects / blocks / misses, plus the evidence table (verified in small step 7) | `docs/PROTECTION-MATRIX.md` |
| 13 | Full test walk-through with a report | **todo P6** — two smoke tools exist; no feature-wide harness/report | P6 |
| 14 | Malware corpus for testing | **deferred** — EICAR only, and only inside a VM lab | P6 (later) |
| 15 | Engine restart must not lose a scan | **done** — durable jobs + auto-resume, verified | `engine/src/jobs.rs` |
| 16 | Interactive sounds + control | **done** — in-house pack, engine cue with the UI closed, UI volume/mute/DND, test button | D-004 |
| 17 | Protect the project from theft | **decided** — GPL + trademark + signing, never secrecy | D-001 |
| 18 | Cheapen the project + licenses | **partial** — GPL-3 shipped; SBOM + `THIRD-PARTY-NOTICES` generated, committed and shipped (ب1a, D-018); the cost sheet exists and names the single purchase (ب1b, `docs\COST.md`) | P4 |
| 19 | Professional README | **done** — see row 10 | `README.md` |
| 20 | L5 wording vs reality (LLM) | **decided** — optional local LLM + templates; wording fix in P5 | D-005 |
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
- [ ] **Acceptance (needs you):** install the helper once from
      **Settings → Engine → Install helper** (one prompt), then enable Default-Deny,
      turn SMBv1 off and import a hosts list in one session: **zero** further
      prompts, and `logs\priv.log` carries one `phase=start`/`phase=done` pair per
      operation. Everything below that step is already proven unelevated by
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
- [x] ~~SBOM (CycloneDX), `THIRD-PARTY-NOTICES`, dependency-license audit~~ — done
      (ب1a, D-018): `tool\sbom.dart` generates both from the lockfiles, the pair is
      committed, shipped in the package and freshness-checked before a release.
- [x] ~~`docs/COST.md` — the real costs and what stays free~~ — done (ب1b): the only
      purchase is a CA-issued certificate; the sheet also records that its key must
      be in hardware since June 2023, which retires the `-PfxPath` path in favour of
      the `/sha1` one `scripts\sign.ps1` already has.

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
      Win11, x64 or ARM64, 4 cores, 8 GB, ~500 MB, one UAC at install), privacy,
      data locations, uninstall, screenshots, build instructions, GPL notice~~ —
      done (ج3, 2026-11-03): the does/does-not pair now carries the manifest, the
      start-up self-check and their honest limits, and every number in it is the one
      the pipeline measured.
- [ ] Fix L5/assistant wording everywhere (README, About, brief): "event
      correlation + optional local-LLM explanations", command bar is regex.

### P6 — QA
- [x] Pipeline entry point: `scripts/pipeline.ps1` (ز0) — tiers, JSON report, and
      the CI workflow calls it instead of repeating the checks.
- [ ] `qa/` contract harness: every JSON-RPC method (happy path, invalid params,
      unknown method, schema) driven from `dispatcher.rs` so a new method cannot go
      unregistered (د1), then the same fixtures drive a `FakeEngine` for every
      screen and every interactive control (د2).
- [ ] CI runs the harness; a feature that is not registered fails the build (د5).
- [ ] E2E on the built artifact (د3) and `qa/report.html` + `.md` (د5).
- [ ] Malware lab (later): isolated VM + snapshots, EICAR/AMTSO first, samples
      never in the repo, detection-efficacy report.

---

## 7. Known issues / risk register

| Sev | Issue | Where |
|---|---|---|
| HIGH | **No real signing certificate and no published download**: the NSIS installer exists and is verified (ب3, `dist\MICS-setup-<version>-x64.exe`, 70 files, untagged-helper refusal, `verify-installer.ps1` in 126 s) and is signed with a *locally* issued certificate, but nothing is signed by a CA a stranger's Windows trusts and nothing is published, so the register's original "no installer" half is closed and this row is now about ب5/ب6 | `dist/`, `installer/`, P4 |
| ~~HIGH~~ | ~~A user who copies the package by hand can drop `rules\` and get the compiled-in starter pack silently~~ — **closed 2026-11-03 (و4) by evidence**: a package with `rules\` removed (and its own `SHA256SUMS` corrected, so nothing but the missing folder can fail) is refused by `verify-release.ps1`: 4 FAILs — `missing from the zip: rules\yara\starter.yar, rules\guard\starter.json`, `rules folder holds 0 file(s)` (the layout check, not just the file names), `the guard did not use the packaged rules: guard: 6 rule(s) from the built-in starter pack (rules/guard not found)` and `the scan did not use the packaged YARA rules (log line: YARA rules from the built-in starter pack (no rules\yara\starter.yar found))` — **exit code 1** (`RESULT: FAIL - the release artifact is not what it claims to be`). The silently-degraded copy the row described can no longer pass the gate, and the engine's own log names the source it used | `dist/`, `guard/mod.rs`, `scanner/mod.rs`, `scripts\verify-release.ps1` |
| ~~LOW~~ | ~~A merged re-read keeps the audit complete, but the merged report's non-refreshed sections are only as fresh as the last full audit; the UI never shows that age~~ — **closed 2026-11-03 (و4)**: every section now carries the unix time it was collected (`AuditPass::stamps`), a merge keeps the base's time for the sections it did not re-read and takes the re-read's own time for the ones it did (a section whose collector failed loses its stamp instead of inheriting a fresh one), each finding names its **section id** (the display name is not unique — `rdp` and `remote_tools` both read "Remote Access"), and the audit screen prints "Not re-checked now — read at HH:MM" on every finding and inventory header whose section this report did not re-read. Localised in ar/en; the widget test proves 3 such lines on a merged report and none on the refreshed finding | `traits.rs`, `audit_models.dart`, `audit_screen.dart` |
| MED | Defender **tamper protection** refuses programmatic preference writes, so `Set-MpPreference -PUAProtection` can fail even when the engine is elevated; `hardening.apply` now detects the no-op and points at the Windows Security switch instead of claiming success | `hardening/mod.rs` |
| ~~LOW~~ | ~~`vuln.scan` (the blocking variant) still exists for probes and scripts~~ — **closed 2026-11-03 (و4)**: callers were checked first, and the register's "for probes and scripts" was wrong in one place — the natural-language command bar's `vuln_scan` intent dispatched it, so a spoken "scan for vulnerabilities" blocked the request for minutes with no progress and no cancel. That intent now points at `vuln.scan.start` (the command bar answers at once and the job reports through `progress`/`job_finished`), and with its last caller gone the blocking method, `VulnScanner::scan`, its `qa/methods.json` row and its registry entry are deleted: **one scanning path** — the durable job. The surface is 65 methods again | `vulns/mod.rs`, `dispatcher.rs`, `llm/mod.rs` |
| ~~LOW~~ | ~~A **registered** AUMID still only names the source: any same-token process can raise a card under `MICS` and Windows will attribute it to "MI CS"~~ — **closed 2026-11-03 (و4) by evidence, as a documented limit rather than a defect**: `verify-aumid.ps1` PASSes — `DisplayName` is `MI CS`, its `IconUri` names a file that exists, **both** shortcuts carry `System.AppUserModel.ID = MICS`, and the Shell files `MI CS` under AppID `MICS` — which is exactly what the AUMID was for (the app is filed by name instead of by exe path). The row's *substance* is not fixable in the app and `docs/THREAT-MODEL.md` §B10 already says it: a card is UI, not proof of origin, because the AppUserModelID is not an authenticator. Nothing in the product reads a card as evidence of anything; the register row existed to stop that reading | `notify/toast.rs`, THREAT-MODEL §B10 |
| MED | **No real-time file watching**: the hash + YARA dimensions only apply while a scan job is running, so a machine nobody scans has no file-level detection between runs (Windows Defender is the real-time layer, and the audit says so loudly when it is off). **The scheduled half is done** (و1, 2026-11-03, D-027): the engine runs a scan by itself every `scan_interval_hours` (opt-in, off by default) over `scan_target`, report-only, and `scripts\verify-scan-schedule.ps1` proves it starts, finds, and leaves the file in place — but a schedule is a moment, not a monitor: what changed *between* two runs is still only seen by Defender | `scanner/mod.rs`, PROTECTION-MATRIX §2 |
| LOW | The bundled detection content is a **starter pack** (6 guard rules, 10 YARA rules): the mechanism is complete and hot-reloadable, but the shipped rules demonstrate it rather than protect with it. **The "checks that packs load, not what they catch" half closed 2026-11-05 (D-033)**: `scripts\verify-rules.ps1` holds the pack a package ships to files — `engine\testdata\detection`, 8 vectors each written for one rule plus a clean control, **35 checks PASS** — and every rule the pack declares must either be caught by one of them or be named as unreachable with its reason. That ratchet immediately found the pack's one impossible rule: `Malicious_Macro_AutoOpen` compared `uint16(0)` against `0x504B`, which little-endian is `"KP"`, so it could never fire on any container that exists (a real `.docm` starts `50 4B` = `0x4B50`) — fixed, with the measured pair pinned by a test and re-measured through the probe. Measured reach of the 10 rules: **8 held to a file**, 2 named unreachable by a text vector (`EICAR_Test_File` — the string is what Defender quarantines; `Tiny_Packed_Pe_Installer` — needs a binary PE). **What stays open is the content decision, not the mechanism**: the macro rule's container test is two magic bytes plus substrings, and a real `.docm` deflates those substrings out of any pattern's reach (measured: `AutoOpen`, `CreateObject` and `Shell` are absent from the file's bytes), so document-borne malware needs an OOXML/OLE parser rather than another rule — which is decision (b) of the six in §0.2 | `engine/rules/yara/starter.yar`, `engine/testdata/detection/`, `scripts/verify-rules.ps1`, `scripts/verify-release.ps1`, `docs/PROTECTION-MATRIX.md` §2 |
| LOW | The guard's ETW callback loads the IOC hash list and never uses it (deliberate: hashing every process start was judged too hot), so a known-bad process hash that matches no behavioural rule is not flagged at start | `guard/etw.rs`, PROTECTION-MATRIX §4.1 |
| MED | IDS = hosts-file blocklist (DNS only); no Suricata/ET-Open | `ids/mod.rs` |
| ~~MED~~ | ~~Canaries detect mtime/size changes by polling; a read-only open is not detected~~ — **closed 2026-11-05 (D-032) by evidence**: the snapshot carries the file's last-access time, so a read-only open is its own HIGH `canary_read` event under rule id `CANARY_READ` — a separate id on purpose, so a user can quiet reads without losing the ones that mean their decoy was overwritten — while a write still wins as CRITICAL `canary_triggered`/`CANARY`. `scripts\verify-canary.ps1` (**20 checks, PASS**) drives a real engine over a private pipe with a private `USERPROFILE` and measures: a decoy MI CS had just written is settled silently inside the 90 s window (`READ_SETTLE`, and the engine's log says `canary settling` instead of hiding it), a decoy that was already on disk raises `canary_read` with its size and SHA-256 unchanged, one appended byte raises `canary_triggered`/critical, fifty metadata queries in a row move no last-access time and raise nothing (the poll cannot trip its own trap), and the engine's `read_detection` verdict equals the same measurement taken independently in PowerShell. **Found while measuring:** the verdict had been probed on the *previous* decoy folder, so on a machine whose decoys live on another volume it would have named the wrong disk — the probe now asserts `probed_on` is the decoys' own folder, and the engine re-measures when they move. What remains is honest and named: only a volume that keeps a last-access time can show a read, so `canary.status`/`guard.status` and the Canaries screen report the measured verdict (with the `fsutil behavior set disablelastaccess 0` that turns it on) instead of implying coverage, and the engine still cannot name the reader without the kernel event source | `guard/canary.rs`, `guard/mod.rs`, `dispatcher.rs`, `docs/PROTECTION-MATRIX.md` §4.2, `scripts\verify-canary.ps1` |
| MED | ~~**Firewall uses `netsh`, not FirewallAPI COM**~~ — closed by **و3** (2026-11-03, D-028): the engine speaks `INetFwPolicy2`/`INetFwRules`/`INetFwRule` in-process, so there is no child process to hang, no English console text to parse and no locale to depend on. `scripts\verify-firewall.ps1` (23 checks) compares the reads with `Get-NetFirewallProfile`/`Get-NetFirewallRule`, creates and removes one real rule, and proves the `netsh` dependency is gone by putting a fake `netsh.exe` first on PATH. **What stays open**: a country-sized `RemoteAddresses` string has no documented ceiling and was not measured, so `block_country` still sends one rule per country | `firewall/mod.rs`, PROTECTION-MATRIX §3.2 |
| LOW | Country CIDR lists are read from disk only (public country-list licences are unclear), so GeoIP stays empty on a fresh install until lists are placed in `rules\blocklists` or `%PROGRAMDATA%\MICS\blocklists` | `ids/geoip.rs` |
| ~~LOW~~ | ~~The guard's idle cost is **0.156 % of one core / 0.0028 % of this 56-thread machine** with one inert rule in force; with the shipped starter pack the earlier runs measured 0.234 %~~ — **closed 2026-11-03 (و4)**: re-measured with the **shipped pack** actually loaded (`measure-guard-cpu.ps1 -RealRules`, four 60 s windows, 56 logical cores, guard on minus `MICS_NO_GUARD=1`): **0.156–0.521 % of one core, median 0.417 % = 0.0028–0.0093 % of the machine, median 0.0074 %**. The engine was unelevated, so ETW was denied and the 2 s poll loop is what ran (`on.err` names it); the guard-off half measured 0.000 % in every window — below the 15.6 ms process-timer resolution, i.e. < 0.03 % of one core. The earlier "with the starter pack it is 0.234 %, the difference is one-time startup matching" is **not supported by this measurement**: the lowest shipped-pack window equals the inert-rule number, so the spread is run-to-run noise on a busy 56-thread box, not a rule-count effect. The row's *number* was stale; the `< 1 %` budget holds under either definition | `guard/mod.rs`, `platform/windows/pids.rs`, `scripts/measure-guard-cpu.ps1` |
| LOW | No key-free sha256 hash feed exists any more (abuse.ch needs an Auth-Key), so `ioc_hashes` reports `not_configured` until the user pastes a URL + key in Settings → Intelligence (env hooks `MICS_IOC_FEED_URL`/`MICS_IOC_FEED_KEY` still work) | `sync/mod.rs` |
| ~~LOW~~ | ~~**The helper's caller check has nothing to compare against in a portable run**~~ — **closed 2026-11-03 (و4) by evidence**: `verify-helper.ps1` now starts the helper in exactly that layout (an empty `PROGRAMDATA` plus a separate `MICS_DATA_DIR`, so no install account exists) and measures both halves in one run: a client that is **not** the engine image is refused — `{"ok":false,"error":"this pipe only serves the MI CS engine"}` — while the helper's own log carries `no installer account recorded (no %PROGRAMDATA%\MICS) - the caller image is the only check`; then the same probe, with the documented `MICS_ENGINE_PATH` pin the installer records, is served (`pong:true`). The helper reads that pin from its own environment, which is why the probe uses two helper processes — the first version of this check reused one and the "pinned client" expectation failed, which is what made the behavior visible. `RESULT: PASS`, exit 0, 15 checks; the fallback stays what F-2 says it is (the pipe ACL is what keeps other users out) and is now measured rather than asserted | `platform/windows/caller.rs`, `privileged/server.rs`, `scripts\verify-helper.ps1`, D-017, THREAT-MODEL F-2 |
| LOW | **The update pin is the signer's subject name, not its thumbprint**: a certificate with the same CN (`MI CS Code Signing`) issued by a CA that failed identity validation would pass. A thumbprint pin breaks on every locally re-issued release certificate | `platform/windows/signature.rs`, D-016, THREAT-MODEL F-3 |
| LOW | **A language folder that `pubspec.yaml` does not declare renders every key raw, silently**: the pack loader swallows a failed asset read on purpose ("a module that has not been translated yet must not break the app"), so nothing logs or fails when a whole language is missing from the asset list. `test/lang_registry_test.dart` now fails instead, and the app itself gates its first frame on the settings *and* the packs (`lib/main.dart`), so this cannot reach a user who is running a correct build | `pubspec.yaml`, `test/lang_registry_test.dart`, `lib/main.dart` |
| LOW | **The engine stores a language tag the UI cannot render**: `settings.set lang=de` is accepted and persisted (deliberately - the engine must not need a release per language), and the UI falls back to Arabic via `AppLang.byCode(...) ?? AppLang.ar`, so a hand-edited settings file shows Arabic rather than the requested language. The picker only ever offers bundled languages | `engine/src/settings.rs`, `lib/core/i18n/app_i18n.dart` |
| ~~LOW~~ | ~~`nvd_api_key` / `ioc_feed_key` are plaintext in `settings.json`~~ — **closed 2026-11-03 (و4)**: both keys now live in `<data dir>\secrets.dat`, DPAPI-protected at machine scope (the primitive the quarantine master key uses) behind a `MS1\0` header, written before the document and replaced atomically; `settings.json` no longer holds them at all, a file written by an older build is migrated on the next start (the plaintext is taken out and the document rewritten without it, idempotently), and the proving test asserts that neither the document nor the secrets file contains the value that went in. **Honest limit**: machine-scope DPAPI binds the blob to the computer, not to a user, so another local account can still ask Windows to decrypt it (`THREAT-MODEL.md` F-5) — what it removes is the plaintext copy that travelled in backups, shared folders and pasted logs | `settings.rs`, `secrets.rs`, THREAT-MODEL F-5 |
| LOW | ~~**Dark mode is not contrast-audited**~~ — closed by small step 4: the dark palette was measured with the same 29 pairs (7 below their bar: the border at 1.32/1.21, secondary text at 4.06/3.73, `onError` 3.67, and two composited tints), fixed, and frozen in `test/dark_contrast_audit_test.dart`; both modes now assert 29 of 29 (`docs/CONTRAST.md`) | `app_theme.dart`, `test/dark_contrast_audit_test.dart` |
| ~~LOW~~ | ~~**No signed integrity manifest**, so a repackaged copy is not detectable *by the app itself*~~ — **closed 2026-11-03 (ج2, both commits)**, with its honest limit written down: the shipped engine carries a SHA-256 manifest of every other shipped file inside its own signature, re-reads it at start-up, re-hashes the folder it runs from and reports `ok` / `untrusted-certificate` / `unverified` in `status` — About shows the line, and a manifest that disagrees with the files raises a card naming them. `make-release.ps1` builds and injects it, `verify-manifest.ps1` proves the package against it, and `-Tier release` refuses one it fails. What stays open is in `THREAT-MODEL.md` F-11: a from-source rebuild re-signed with another key, plus the reproducible-build note | P5, THREAT-MODEL F-11, `engine/src/selfcheck.rs` |

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
