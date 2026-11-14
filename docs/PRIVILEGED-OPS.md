# Privileged operations (D-007)

MI CS runs **unelevated**. Everything that needs an administrator token happens
inside one Windows service, `MICSHelper`, installed once with a single UAC
prompt and never again. This file is the complete list of what that service will
do — the code, the wire format, the validation and the audit trail.

- Engine side: `engine/src/privileged/` (`ops.rs`, `server.rs`, `service.rs`, `mod.rs`)
- Protocol: newline-delimited JSON over the named pipe `\\.\pipe\mics_helper`
- Audit: `%PROGRAMDATA%\MICS\logs\priv.log` (override: `MICS_HELPER_LOG`)
- Test hook: `MICS_HELPER_PIPE` renames the pipe (a bare name or a full
  `\\.\pipe\...` path — the same function decides the name as for the engine's own
  `MICS_PIPE_NAME`); nothing else about the helper moves

## The closed set

`Op` is a **closed enum**. There is no "run this command" variant, no shell, no
script passthrough: a bug or a confused caller can only ask for one of these.

| Op | Payload | Changes | Reversible by |
|---|---|---|---|
| `ping` | — | nothing (liveness only) | — |
| `version` | — | nothing; returns `{version, elevated}` | — |
| `firewall.default_deny` | `{enabled: bool}` | outbound policy of all three firewall profiles | the same op with `false` |
| `firewall.add_rule` | `{rule: {name, direction, action, program?, local_port?, remote_port?, remote_ip?, protocol?}}` | one `MICS-<name>` rule | `firewall.remove_rule` |
| `firewall.remove_rule` | `{name}` | deletes one `MICS-<name>` rule | `firewall.add_rule` |
| `hosts.write` | `{content}` | replaces the managed `# BEGIN MICS-IDS` section (the caller takes the snapshot **before** sending) | restore that snapshot |
| `hardening.run` | `{action}` | one of `pua_protection`, `smbv1_off`, `rdp_off`, `uac_on`, `defender_scan_quick` | `hardening.rollback` with the snapshot |
| `hardening.rollback` | `{snapshot}` | re-applies a previous state | — |
| `firewall.wfp.status` | — | nothing; reads MI CS' WFP provider, sublayer and filters | — |
| `firewall.wfp.block` | `{spec: {app?, port?, protocol?, note?}}` | one persistent `MICS-` filter in the BFE (creates the provider and sublayer on first use) | `firewall.wfp.unblock` with the same spec |
| `firewall.wfp.unblock` | `{spec}` (same shape) | removes that one filter | `firewall.wfp.block` |
| `firewall.wfp.reset` | — | removes **every** `MICS-` filter, then the sublayer and the provider | — |

The four `firewall.wfp.*` ops were added by D-042 (register section 0.6 row 17,
slice a). They are the only ops that name no rule and no path for the machine to
delete: `reset` addresses our own provider key, so it cannot be pointed at
anything Windows or another product owns. A spec needs an application or a
remote port (`validate`), so the set cannot express "block everything".

D-043 (same row, slice b) is the caller: the connection list derives a spec from
the row the user clicked — the row's own image path, its peer port and its
protocol — and the UI confirms it before it is sent, because the filter outlives
MI CS. The engine builds that spec, so the UI never assembles a filter out of
what a row happens to display; a row with no peer port (UDP, a listener) or no
image path carries no spec at all and the UI offers no button for it.

D-044 (same row, slice c) uses **only `firewall.wfp.status`**: the tamper watch
compares a record of what MI CS wrote against that read, so it needs no new
privileged op and never writes. Unelevated with no helper the read is refused,
and the watch reports `unknown` rather than an empty machine — the same
`needs_elevation` answer, used as a third state instead of being flattened into
"nothing is there".

Every op names its effect on the machine; nothing is implicit, nothing is
"best effort and hope".

## Wire format

One request, one response, one connection:

```json
{"op":"hardening.run","action":"smbv1_off"}
{"ok":true,"data":{"action":"smbv1_off"}}
{"ok":false,"error":"the privileged helper is running without an elevated token — uninstall and reinstall it from Settings → Engine"}
```

The client (`privileged::call`) owns blocking pipe I/O on its own thread, retries
the connect up to 20 times (100 ms apart) because the helper re-creates its pipe
instance between clients, and gives up after 300 s so a hung helper cannot wedge
a UI request.

## Validation, before anything runs

`Op::validate` refuses a payload whose shape is wrong, and the helper calls it
**before** executing or logging a start line:

- `firewall.add_rule` — non-empty name, `direction` ∈ {`in`, `out`}, `action` ∈
  {`allow`, `block`}. `MICS-` is added by the helper, so a caller cannot escape
  the namespace it will later remove.
- `hosts.write` — ≤ 4 MiB, must contain the `# BEGIN MICS-IDS` marker, and every
  non-comment line must be an `address host [host…]` pair with a real IPv4/IPv6
  address. A document produced by anything other than the IDS path is rejected
  with the offending line number. This is what stops the pipe from becoming a
  "write any file as SYSTEM" primitive.
- `hardening.run` — the action id must exist in the command table
  (`hardening::validate_action`), so an arbitrary string never reaches PowerShell.
- `hardening.rollback` — at most 8 lines, and every `;`-separated command must
  match a shape this codebase generates: `reg add "HKLM\…" /v … [/t REG_DWORD]
  /d <digits> /f`, `reg delete "HKLM\…" /v … /f`,
  `Set-SmbServerConfiguration -EnableSMB1Protocol true|false [-Force]`,
  `Set-MpPreference -PUAProtection 0|1|2|enabled|disabled`. Keys must be absolute
  `HKLM\` paths and may not walk out of their hive. A snapshot that cannot be
  expressed in those shapes is a bug, not something to run.
- `firewall.wfp.block` / `firewall.wfp.unblock` — the spec must name an
  application or a remote port (so "filter everything" is not expressible), a
  named application must be a path of ≤ 1024 characters without a quote,
  newline or NUL, a port must be above zero, a protocol must be 6 (TCP) or 17
  (UDP) and needs a remote port — those are the only two this product blocks —
  and a `note` is at most 40 characters of letters, digits, spaces, `-` or `_`,
  because it ends up in the filter's display name, which the BFE stores and
  `netsh` prints. The engine applies the same `validate` before the call is put
  on the wire, so both sides refuse the same specs.

The helper also refuses to pretend: run without an elevated token and the
privileged ops answer with *"the privileged helper is running without an
elevated token"* instead of half-applying a change.

## Audit trail

Every request writes at least two lines, in this order, before and after the
work — so a crash mid-op still leaves the intent on disk (`security` rule 6 in
`AGENTS.md`: privileged work must stay auditable):

```
2026-10-30T12:19:51.995+00:00 phase=start hardening.run action=smbv1_off
2026-10-30T12:19:51.996+00:00 phase=done ok=false error=… dur_ms=0 hardening.run action=smbv1_off
```

- Payloads are never logged whole: `hosts.write` records `bytes=`, `lines=` and a
  truncated `sha256=` (`dab82ccbcffeb900`), which proves *what* was sent without
  copying a document that can contain the machine's name resolution.
- `firewall.wfp.block` and `firewall.wfp.unblock` record the filter's display
  name and its key — `filter=MICS-setup.exe port 443 protocol 6 note guard
  key=B051BA44-...` — never the directory the application sits in, so the log
  says what the machine now enforces without copying a user's paths.
- `phase=note` lines record service start/stop and install/uninstall.
- Rotated at 2 MiB to `priv.1.log`.

## Install, upgrade, remove

`install-helper` has two callers and they are the same command: the app's
`Settings -> Engine -> Install helper` on a portable copy (elevated, one UAC
prompt; a privileged operation does *not* start it — that path refuses with the
reason instead, so "one prompt" stays one prompt), and — since ب4/D-026 —
the **installer itself**, which already holds the elevation and runs the same
subcommand while it installs, so an installed copy never sees a second prompt. It is a
CLI **subcommand**, and both callers pass exactly
this spelling: as `--install-helper` clap refuses the argument and exits 2 before
the child can log anything, which is what the first shipped build did:

1. `sc stop` + `sc delete` any previous definition, so an upgraded exe path and
   the current description replace the old service instead of leaving a stale
   one behind. That is also what makes the installer's call idempotent across
   upgrades and repairs.
2. `sc create MICSHelper binPath="<current exe>" helper-service start= auto
   obj= LocalSystem` — the service points at the same executable that needs the
   work, so there is nothing extra to ship. The body is the `helper-service`
   **subcommand**, never `--helper-service`: as a flag, clap refuses it, the
   process exits 2, and the SCM only reports `sc start failed: 1053`.
3. `sc description …` (the audit-file location is in the description).
4. `sc start`, then **poll the pipe for up to 20 s** and only report success when
   the helper actually answers: "sc said Ok" is not the same as "the engine can
   use it".

`uninstall-helper` stops and deletes `MICSHelper`, treating `1060` (service does
not exist) as already done. Removal has a second shape for the installer, because the
installer is what created the service (D-026): its uninstaller asks
`scripts\check-helper-ownership.ps1 -Remove`, which deletes only after proving the
service's `binPath` points at the folder being removed, and only the service named by
the `ServiceKey` it read. Without elevation, or when the definition is not this copy's,
it answers `OWNED`/`UNKNOWN` instead and the uninstaller refuses with error level 5:
nothing is touched and the message points at the app's own button.

The service body is `StartServiceCtrlDispatcherW` → `service_main`:
`SERVICE_START_PENDING` → audit note → `SERVICE_RUNNING` with `STOP|SHUTDOWN`
accepted → the pipe loop. The stop handler sets a flag, connects once to wake the
blocked accept, and reports `SERVICE_STOPPED` when the loop returns.

## Pipe ACL

```
D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)
```

LocalSystem, Administrators and **Interactive Users** — the people who could
answer a UAC prompt themselves. Not `Everyone`, not services, not network
identities: a non-interactive process cannot ask the helper for anything.

## Who may call

The ACL above says "any interactive user", which is why the helper also asks *who*
is on the other end before it does anything (F-2, D-017):

1. `GetNamedPipeClientProcessId` reads the client's pid from the connected pipe.
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW`
   turn that pid into a full image path. Holding the process handle while the path
   is read means the pid cannot be recycled in between.
3. The path is accepted when the image is `mics-engine.exe` (by name), or when it
   matches `MICS_ENGINE_PATH` exactly — the hook the installer records, and the one
   the verification scripts use to name themselves.
4. The caller's **token user SID** must be the account MI CS was installed for, read
   as the *owner of* `%PROGRAMDATA%\MICS` — a directory only the elevated installer
   creates. A different local user who copies the engine is refused here even though
   the image name matches.

A client that fails step 3 or 4 gets

```json
{"ok":false,"error":"this pipe only serves the MI CS engine"}
```

(or `this pipe only serves the account MI CS was installed for`) after its request
line arrives, a `WARN` in the helper log naming the refused pid, image and SID, and
**no** audit entry — an unauthorised caller never reaches validation. Measured on this
machine: a PowerShell client answered the first message and the log said
`privileged helper refused pid 12345 (...\powershell.exe): not the engine it serves`;
`scripts\verify-helper.ps1` still passes end to end, because the script and the
helper's recorded installer account are the same user.

When `%PROGRAMDATA%\MICS` does not exist (portable run, console helper in a fresh
checkout) there is no recorded account: the helper logs
`no installer account recorded (no %PROGRAMDATA%\MICS) - the caller image is the only
check` and falls back to step 3 alone. A console helper already runs with the
caller's own token, so that fallback costs nothing; an installed service always has
the directory.

## Verifying it without a UAC prompt

The service install is the only step that needs elevation. Everything else can be
proven on an unelevated shell, which is what the repository does in
`engine/src/tests.rs` and what this recipe does by hand:

```powershell
# 1) the status chain (no helper installed → not_installed, reachable=false)
.\mics-engine.exe helper-status --json

# 2) serve on the real protocol, unelevated, in the foreground
$env:MICS_HELPER_PIPE = 'mics_helper_probe'
$env:MICS_HELPER_LOG  = "$env:TEMP\mics-helper-audit.log"
# The client below is PowerShell, not the engine, so it has to be named first.
$env:MICS_ENGINE_PATH = (Get-Process -Id $PID).Path
Start-Process .\mics-engine.exe -ArgumentList helper-console

# 3) speak the protocol (one connection per request)
$p = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'mics_helper_probe', 'InOut')
$p.Connect(3000); $w = [System.IO.StreamWriter]::new($p); $w.AutoFlush = $true
$r = [System.IO.StreamReader]::new($p); $w.WriteLine('{"op":"hardening.run","action":"smbv1_off"}'); $r.ReadLine()
```

Without the `MICS_ENGINE_PATH` line, step 3 answers
`{"ok":false,"error":"this pipe only serves the MI CS engine"}` — that is the F-2a
check doing its job, not a broken recipe.

Observed on this machine (unelevated, 2026-10-30):

| Request | Answer |
|---|---|
| `{"op":"ping"}` | `{"ok":true,"data":{"pong":true,"pid":…,"version":"0.1.0"}}` |
| `{"op":"version"}` | `{"ok":true,"data":{"version":"0.1.0","elevated":false}}` |
| `{"op":"hardening.run","action":"smbv1_off"}` | refused: no elevated token |
| `{"op":"hosts.write","content":"no marker here"}` | refused: missing MI CS marker |
| `{"op":"firewall.add_rule","rule":{"name":"x","direction":"sideways","action":"block"}}` | refused: direction must be `in` or `out` |
| `{"op":"firewall.wfp.status"}` against a helper installed before D-042 | refused: `unknown variant firewall.wfp.status, expected one of ping, version, …, hardening.rollback` — the installed helper is older than the engine; reinstall it from Settings → Engine (measured 2026-11-08 on this machine) |
| `{"op":"shell.exec","cmd":"whoami"}` | refused: unknown variant, lists the allowed ops |
| `helper-status --json` while `helper-console` runs | `reachable:true, version:"0.1.0", elevated:false` |

`scripts\verify-helper.ps1` does the same thing automatically and prints
`RESULT: PASS|FAIL`.

### A registration that points at nothing (2026-11-07)

`helper-status --json` gained two fields, both read from Windows rather than guessed:
`bin_path` (the program `sc qc MICSHelper` says the service runs) and `stale` (true when
that program is no longer on disk). The parsing is a pure function with tests over the two
real shapes — the quoted form this project installs (`"C:\Program Files\MI CS\
mics-engine.exe" helper-service`) and the unquoted one (`sc qc Spooler` was the
measurement) — and an absent or unreadable answer is `None`, never a guess, because a
config query this caller may not read must not become a false "stale".

It exists because a service whose program is gone reports the same `stopped` as a healthy
one that is merely not started; only the file system tells them apart. Two ordinary ways
to get there: the user moved or replaced the MI CS folder, and a package update replacing
the versioned folder inside `WindowsApps` (`docs/SIGNING.md` §3, D-038). The engine no
longer answers that case with "start MI CS from its installed folder" — it names the path
that is gone and says the fix is installing the helper again, which rewrites `binPath` from
the folder the running copy is in.

Measured on this machine with the build of 2026-11-07: `helper-status --json` with no
service installed reports `bin_path: null, stale: false` — the fields are there and they do
not invent a problem. **Not observed yet:** `stale: true` itself, which needs an installed
helper whose folder then moves — an administrator's install plus a move, or the same thing
a package update does.

## What is still unproven

The **elevated install itself** has been done once on this machine and it holds:
`helper-status --json` from a normal folder reports `installed:true running:true
reachable:true version:"0.1.0"`, and `priv.log` records `install requested` →
`service starting (pid=…)` → `install finished, helper state=running`. What that run
did *not* prove is the UAC half of D-007: the app was already elevated, so it installed
the service itself instead of raising the prompt.

Still open is the **end-to-end privileged path from the UI**, which has to be done once
with the app running **unelevated** — an elevated engine runs privileged operations in
its own process and never touches the helper, so `priv.log` stays empty and the run
proves nothing. The first attempt (2026-11-01) got that wrong and also found two engine
bugs (a wrong `netsh` policy argument shape and a PowerShell quoting error in the
hardening snapshots), both fixed the same day — see `docs/TODO.md` Done log.

The steps: `Settings → Engine → Install helper` (only if the app asks), then
Default-Deny, SMBv1 off and one IDS domain in the same session — **zero** further
prompts, one `phase=start`/`phase=done` pair per operation.

Publisher attribution in that prompt still needs the trusted certificate from
D-002; until then Windows shows the helper's unsigned identity.