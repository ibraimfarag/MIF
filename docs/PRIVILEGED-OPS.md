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
- `phase=note` lines record service start/stop and install/uninstall.
- Rotated at 2 MiB to `priv.1.log`.

## Install, upgrade, remove

`install-helper` (elevated, started by the engine with one UAC prompt on the
first privileged operation) — a CLI **subcommand**, and the engine passes exactly
this spelling: as `--install-helper` clap refuses the argument and exits 2 before
the child can log anything, which is what the first shipped build did:

1. `sc stop` + `sc delete` any previous definition, so an upgraded exe path and
   the current description replace the old service instead of leaving a stale
   one behind.
2. `sc create MICSHelper binPath="<current exe>" --helper-service start= auto
   obj= LocalSystem` — the service points at the same executable that needs the
   work, so there is nothing extra to ship.
3. `sc description …` (the audit-file location is in the description).
4. `sc start`, then **poll the pipe for up to 20 s** and only report success when
   the helper actually answers: "sc said Ok" is not the same as "the engine can
   use it".

`uninstall-helper` stops and deletes the service, treating `1060` (service does
not exist) as already done.

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
| `{"op":"shell.exec","cmd":"whoami"}` | refused: unknown variant, lists the allowed ops |
| `helper-status --json` while `helper-console` runs | `reachable:true, version:"0.1.0", elevated:false` |

`scripts\verify-helper.ps1` does the same thing automatically and prints
`RESULT: PASS|FAIL`.

## What is still unproven

The **elevated install itself** — `sc create` + the service start + the pipe ACL
in the LocalSystem context — needs one interactive UAC prompt that no automated
run can answer. Until that has been done once on a machine, the honest statement
is "the protocol, the validation, the audit trail, the refusal paths and the
status reporting are proven; the install is not". The acceptance test for that
step is `Settings → Engine → Install helper`, then a default-deny toggle with no
second prompt.

Publisher attribution in that prompt still needs the trusted certificate from
D-002; until then Windows shows the helper's unsigned identity.