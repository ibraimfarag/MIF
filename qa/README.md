# qa — the contract between the app and the engine

The UI never touches the OS: it speaks 65 JSON-RPC methods over
`\\.\pipe\mics_engine` and nothing else ([D-006](../docs/DECISIONS.md)). That
pipe is therefore the product's entire public surface, and `qa/` is what proves
the surface is still there, still shaped the way the UI expects, and still
refuses what it must refuse.

Three files:

| File | What it is |
|---|---|
| `methods.json` | One row per method: what class it is, what call to make, what shape to expect, and why. |
| `contract.dart` | The harness: starts a real `mics-engine` in a throw-away sandbox, runs every row, writes `build/qa-contract.json`. |
| `support/pipe.dart`, `support/engine_host.dart` | A JSON-RPC client with a deadline, and the isolated engine process. |

`registry.dart` is where the committed registries are read (`methods.json`, the
UI ledger, the opsec baseline, and the dispatcher's match table). The report and
`test/qa_registry_test.dart` both go through it, so "registered" has one
definition.

The fourth thing is `test/qa_registry_test.dart`, which fails if `methods.json`
and the dispatcher's match table ever disagree — so a method cannot ship
untested, and a row cannot outlive its method.

## The other half: `ui/`

The contract proves the engine answers. It says nothing about what the app does
with the answer, and a widget test that only checks the first frame says nothing
about the twelve buttons under it. `qa/ui/` closes that gap:

| File | What it is |
|---|---|
| `fake_engine.dart` | An `EngineIpc` that answers from `methods.json` (shape) and `fixtures.json` (content), records every call, and simulates the four things whose answer depends on what came before: the language, the job table, and the two push streams. |
| `fixtures.json` | What each method returns when a screen needs something to show. 25 methods: a finished scan, one blocked domain, one failing feed. |
| `harness.dart` | Mounts a screen the way the router does (Riverpod overrides, a throw-away router with stubs for every route a tap can navigate to, a 1700x2400 viewport) and then **sweeps** it: walk the tree, tap every control once, close what opens, report what happened. |
| `ledger.json` | The controls each screen exposed, sorted and committed. A diff here is a change to what a user can press. |

Two tests use it — `test/ui_screens_test.dart` (13 screens) and
`test/ui_shell_test.dart` (rail, window buttons, command box) — and the sweep
labels a control by its type plus the tooltip or text a human would name it by,
with an occurrence suffix so four identical icons stay four controls.

**Regenerating the ledger** after an intended change:

```powershell
$env:UI_LEDGER_WRITE = "1"; flutter test --no-pub test/ui_screens_test.dart test/ui_shell_test.dart
```

and read the diff. Without the variable the file is read-only, and a control that
appeared or disappeared fails the build in both directions.

What the sweep proves and what it does not: every control is **reachable and does
not throw against a fake engine**, and the set of controls cannot silently
change. It does not prove a button does the right thing on a real machine
(`engine.contract` and the manual runs are what carry that), and it deliberately
normalises to English between taps so labels are comparable — RTL is covered by
`test/i18n_parity_test.dart` and `test/dark_contrast_audit_test.dart`, not here.

## The report: `report.md` and `report.html`

The registries above describe a surface; the report is what a human reads to see
it, and what the build refuses to let drift. Both files are **committed**, built
by `qa/report.dart` from committed inputs only — no clock, no machine path, no run
timing, no hash — which is what makes a byte-for-byte comparison possible:

```powershell
# regenerate, then read the diff (the same ratchet as qa/ui/ledger.json)
$env:QA_REPORT_WRITE = "1"; dart run qa\report.dart

# check mode: exits 1 and names the stale file
dart run qa\report.dart
```

`test/qa_report_test.dart` runs the same comparison in the fast tier, so a method,
screen, control, language, shipped file, test file or pipeline step that lands
without the report lands with a red build. It also holds the other claims: the
surface is not degenerate (a parse that silently stopped matching would be small
and tidy and wrong), every language directory is listed under `assets:` in
`pubspec.yaml`, every `skip` reason is at least 20 characters, and the report
names no machine (no user path, no account name, ASCII only).

What it is not: a run. The numbers are declarations in committed files, so a test
that failed still counts as declared. What actually executed, and how long each
step took, is in `build/qa-contract.json` and `build/pipeline-<tier>.json`; CI
uploads both next to this report.

## Running it

```powershell
# the pipeline does this for you at full tier, after the release build
.\scripts\pipeline.ps1 -Tier full -Only engine.contract

# or directly; --engine defaults to $CARGO_TARGET_DIR / engine/target
dart run qa\contract.dart --engine $env:TEMP\mics-target\debug\mics-engine.exe
```

| Flag | Effect |
|---|---|
| `--engine <path>` | The binary to test. Otherwise `MICS_ENGINE_PATH`, then `release`/`debug` under `CARGO_TARGET_DIR` or `engine/target`. |
| `--only a,b,c` | Run only those methods (plus the unknown-method probe and the final ping). |
| `--keep` | Leave the sandbox on disk for inspection. |

Exit code 0 means every case passed. The report is `build/qa-contract.json`:
`executed`, `skipped`, and one entry per case with its `ok` and the reply it got.

## What a row can say

```json
{
  "method": "job.resume",
  "class": "read",
  "params": { "job_id": "qa-no-such-job" },
  "expect": "object",
  "want": { "status": "not_resumable" },
  "note": "why this case, and what would make it wrong"
}
```

- **class** decides what may run: `pure`/`read`/`sandbox` execute for real
  against an isolated `MICS_DATA_DIR`; `mutating`/`network`/`desktop` never take
  a happy path, because this harness runs on the machine it is protecting.
- **expect** is the shape the result must have (`string`, `object`, `array`,
  `any`) or `error` for a call that is refused by design.
- **want** pins the values that make a shape meaningful.
- **missing** / **invalid** are refusal cases: empty params, or params that must
  not be accepted.
- **extra** is a named extra case for a method whose contract is more than one
  call (e.g. an idempotent delete).
- **skip** is a recorded decision not to run, with the reason. Every skipped row
  still has to exist, so the count stays honest.

## The opsec baseline: `opsec-baseline.json`

One more committed file, and not about the pipe: what the **shipped bytes** are
allowed to say about the machine that built them. `scripts/verify-opsec.ps1`
counts five markers (`flutter`, `dart`, `cargo`, `rustc`, `pubspec`,
case-insensitive, over ISO-8859-1 bytes) in every binary of a package and
compares the result with this file:

- a count **above** the baseline fails; below it is reported so the baseline can
  be tightened, because the ratchet only turns one way;
- a binary the file does not list fails until someone adds it with a reason;
- the build account's profile path (computed on the machine that runs the probe,
  never stored here) must appear **zero** times;
- an entry with no written reason fails.

`-Measure` prints the table and the JSON to paste in, and writes nothing:
raising a count is a decision a human records. `make-release.ps1` runs the probe
against the staging folder - so a leaking build is never published - and
`-Tier release` runs it against `dist\MICS-portable` (ط3). `scripts/engine-rustflags.ps1`
is the other half: it appends the remap to the engine's own rustflags, because
`CARGO_ENCODED_RUSTFLAGS` replaces `.cargo\config.toml` rather than adding to it,
and doing that by hand cost the engine its CFG table on 2026-11-02.

The manifest's own names are part of that measurement: the injected document lists
every shipped file, so `data\flutter_assets\...` and `dartjni.dll` enter the
engine's strings and its `flutter` / `dart` rows carry the written reason for it.

## The integrity manifest: `MICS_MANIFEST`

Not a file under `qa/`, but a surface the report carries a row for: the package's
SHA-256 manifest is an `RT_RCDATA` resource inside the shipped `mics-engine.exe`
(D-025), so its authenticity is that engine's Authenticode signature and no loose
document can be edited. `scripts/verify-manifest.ps1` is the proving half - it
re-reads the resource out of the package and re-hashes every file the document
lists - and it is also the `manifest.verify` step of `-Tier release`.

The app reads the same document about itself: `engine/src/selfcheck.rs` re-hashes
the folder it runs from at start-up and answers `status.integrity` with `ok`,
`untrusted-certificate` (our certificate, a root this Windows has not trusted yet)
or `unverified`, which is what Settings -> About renders and what raises the card
naming the files that moved. `test/package_integrity_test.dart` reads the three
words out of that Rust file, so a rename on either side fails the fast tier instead
of leaving an About line that never appears.

`scripts\verify-tamper.ps1` is the adversarial half and the third release-tier step
(`tamper.verify`): it tampers with one thing at a time in a private copy of the
package - a byte flipped in each shipped binary, a same-size swapped DLL, an edited
manifest, the manifest copied into an unsigned engine, a copied install - and
requires the gate above to refuse each one while the packaged engine reports it in
`status.integrity` and in the card it pushes. The published package is the control,
so a probe that simply refused everything would fail. It is also what keeps the
gate's signer pin honest: an engine whose signature was stripped used to pass the
gate, and is refused now.
`test/opsec_baseline_test.dart` keeps the file
honest (reasons present, markers equal to the probe's own list, no user path).
The `cargo`/`rustc` rows are what is left after ط1's
`--remap-path-prefix=$env:USERPROFILE=/build`.

## Deliberately not covered here

- **Mutations of this machine.** Firewall profile changes, hosts, registry,
  Defender scans, the helper service and UAC: skipped with a reason, or only
  their refusal path runs.
- **Anything that leaves the machine.** The intel feeds, NVD, LM Studio and the
  update manifest are `network` rows.
- **The UI.** This file is about the engine side of the pipe; the screens and
  controls are tested in `test/` and, from د2 on, in `qa/ui/`.

### The scenarios that are not rows

Three behaviours cannot be expressed as "call this, expect that shape", so they
are hand-written in `contract.dart` and print their own `PASS`/`FAIL` lines:

| Scenario | What it proves |
|---|---|
| `scan` | A job runs to `done`, its findings survive a re-read, and a finished job cannot be cancelled. |
| `settings` | A write is readable back, a refused value leaves the old one in place, and a language tag nobody ships yet (`de`) is stored. |
| `crash` | Start an engine (no reports), **kill it**, start another on the same data dir: exactly one `unclean-exit` report, the documented id shape, the dead pid inside it, `..\..\settings.json` refused as an id, and the report removable. |
| `qa.definitely.not.a.method` | An unregistered method answers `-32601`, not a fake result. |

The `crash` scenario starts two extra engines of its own, and both are stopped in
a `finally` — a failed case must not leave a service behind on the machine that
runs it.

## Why the client polls instead of blocking

`ReadFile` on a pipe blocks until the engine writes, which would make a hung
handler look like a hung test. The client peeks first and yields between polls,
so a method that never answers fails its case in 30 s. The yield is also load
bearing: the engine logs every request to stderr synchronously, and a client
that stops draining the child's stdio will fill that pipe and park the engine
inside its own `info!` call — measured, not theoretical. Blocking the isolate
once hid a healthy engine behind six "timeout" failures.