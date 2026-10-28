# AGENTS.md — read this before touching MI CS

**Start here:** [`docs/TODO.md`](docs/TODO.md) (status, plan, next tasks, known
issues, environment traps) and [`docs/DECISIONS.md`](docs/DECISIONS.md)
(decided architecture, do not silently reverse it).

## Layout

| Path | What |
|---|---|
| `lib/` | Flutter UI (Riverpod). **No OS APIs in the UI** — everything goes through the engine. |
| `engine/` | Rust crate `mics-engine` (JSON-RPC 2.0). |
| `engine/rules/` | Bundled YARA pack + Sigma-like guard rules (hot-reloaded). |
| `docs/` | TODO/handoff, decisions, (later) threat model + protection matrix. |
| `tool/` | Dev-only Dart probes (`pipe_smoke`, `pipe_probe`); not shipped. |
| `dist/` | Portable package (ignored by git). |

## Build & test (all four must pass before a commit)

```powershell
cd engine
$env:YRX_REGENERATE_MODULES_RS = "false"
cargo test
cargo clippy --release -- -D warnings
cd ..
flutter analyze --no-pub
flutter test --no-pub
```

If cargo complains about `.cargo-build-lock` access, set
`CARGO_TARGET_DIR` to a writable directory (see `docs/TODO.md` §8).

## Rules

1. **Reply to the user in Egyptian Arabic.** Code, comments, identifiers, docs,
   commit messages in English.
2. One phase = one conventional commit; update `docs/TODO.md` in the same commit.
3. No placeholders, no TODOs in code, no `unwrap()` in production paths.
4. The engine owns all OS access; the UI only speaks JSON-RPC through
   `lib/core/ipc/`. Whitelisted methods only.
5. Test hooks exist for a reason — use them instead of hacking production code:
   `MICS_PIPE_NAME`, `MICS_NO_SINGLETON`, `MICS_NO_GUARD`, `MICS_NO_AUTO_RESUME`,
   `PROGRAMDATA`, `MICS_ENGINE_PATH`.
6. Anything privileged (firewall, hosts, registry) must stay auditable and
   reversible; hardening snapshots before changes.
7. Never disable or bypass `docs/DECISIONS.md` decisions without recording a new
   decision entry that supersedes the old one.
8. Do not add telemetry, cloud calls, or telemetry-adjacent analytics. Nothing
   leaves the machine except explicit VT/NVD/LM lookups.
