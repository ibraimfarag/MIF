# qa — the contract between the app and the engine

The UI never touches the OS: it speaks 62 JSON-RPC methods over
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

The fourth thing is `test/qa_registry_test.dart`, which fails if `methods.json`
and the dispatcher's match table ever disagree — so a method cannot ship
untested, and a row cannot outlive its method.

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

## Deliberately not covered here

- **Mutations of this machine.** Firewall profile changes, hosts, registry,
  Defender scans, the helper service and UAC: skipped with a reason, or only
  their refusal path runs.
- **Anything that leaves the machine.** The intel feeds, NVD, LM Studio and the
  update manifest are `network` rows.
- **The UI.** This file is about the engine side of the pipe; the screens and
  controls are tested in `test/` and, from د2 on, in `qa/ui/`.

## Why the client polls instead of blocking

`ReadFile` on a pipe blocks until the engine writes, which would make a hung
handler look like a hung test. The client peeks first and yields between polls,
so a method that never answers fails its case in 30 s. The yield is also load
bearing: the engine logs every request to stderr synchronously, and a client
that stops draining the child's stdio will fill that pipe and park the engine
inside its own `info!` call — measured, not theoretical. Blocking the isolate
once hid a healthy engine behind six "timeout" failures.