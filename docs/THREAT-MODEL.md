# MI CS — Threat Model

What MI CS protects, from whom, where the trust boundaries are, and what it
honestly does **not** defend against. Companion files: [`DECISIONS.md`](DECISIONS.md)
(what was decided and why), [`PRIVILEGED-OPS.md`](PRIVILEGED-OPS.md) (the closed
privileged operation set), and `PROTECTION-MATRIX.md` (per-layer: detects /
blocks / misses).

Every claim below is either **measured** (a probe whose command is in this file,
in `docs/TODO.md`, or in a `scripts/verify-*.ps1` runbook — both pipe ACLs are
measured by `scripts/verify-pipe-acl.ps1`), **proven by a test or a
`scripts/verify-*.ps1` run**, or explicitly labelled **assumed**. A threat model
that mixes the three is a marketing document.

Scope: the shipped Windows 10/11 x64 product — `mics_app.exe` (UI, manifested
`asInvoker`), `mics-engine.exe` (the engine, stdio or the pipe
`\\.\pipe\mics_engine`), the `MICSHelper` LocalSystem service
(`\\.\pipe\mics_helper`), the bundled `rules\` pack, and the data directory.

## 1. Assumptions

1. Windows itself is not already compromised in the kernel. A rootkit, a bootkit
   or a vulnerable signed driver (BYOVD) is out of scope — nothing running in
   usermode can see or stop it.
2. The user is not the adversary. The person running MI CS wants the machine
   protected; a "disable my protection" click is a decision, not an attack.
3. Single interactive user per machine is the design assumption (see F-2).
4. The build and release machine is trusted; the toolchain (`cargo`, `flutter`,
   NSIS) is out of scope. What the *update path* trusts is in section 5.
5. Other operating systems, the dev probes in `tool/`, and the Web GUI in this
   checkout are not part of this model.

## 2. Assets

| # | Asset | Where it lives | What an attacker gains |
|---|---|---|---|
| A1 | The user's files and credentials | Everywhere | The reason the product exists |
| A2 | The settings MI CS manages: firewall policy, the managed hosts section, hardening registry state, parent snapshots | `HKLM`, Windows Firewall, `drivers\etc\hosts` | A weaker machine (open ports, UAC off, SMBv1 back on) that still looks protected |
| A3 | MI CS binaries and rules | install dir (`%LOCALAPPDATA%\MI CS`, portable folder) | Silence or redirect detection; no privilege gain by itself |
| A4 | **The verdict** — the audit score, a finding's state, a scan result | engine memory, DB, UI | Trust misplaced: a false `Secure` retires the user's vigilance (this is why the engine owns the score — D-014) |
| A5 | Quarantine blobs (live malware samples) | `%PROGRAMDATA%\MICS\Quarantine` | Working samples; also evidence destruction if deleted |
| A6 | Engine state and logs (scan history, incidents, canaries, intel state, job queue, `priv.log`) | data dir, `%PROGRAMDATA%\MICS\logs` | Knowledge of what was detected; tamper evidence |
| A7 | Secrets: `vt_api_key`, `nvd_api_key`, `ioc_feed_key` | `settings.json` (plaintext — F-5) | Quota abuse, attribution to the user's key |
| A8 | Reports | `Documents\MICS-Reports` | Findings export (no secrets) |
| A9 | Availability of protection | engine process, guard loop, helper service | Time and quiet to act (F-8) |

## 3. Adversaries

| # | Adversary | Capability | What they try | In scope |
|---|---|---|---|---|
| A-1 | Opportunistic malware | User token, no admin | Persist, evade, disable a security tool it can reach | Yes |
| A-2 | Ransomware | User token, sometimes admin | Mass encrypt, delete shadow copies, kill canaries | Yes (detection + evidence, not prevention) |
| A-3 | Infostealer | User token, reads only | Harvest browsers/wallets/crypto fast, then leave | Partly: a **read** of a decoy is invisible (F-4) |
| A-4 | Fileless / LOLBin abuse | Signed binaries, scripts | Live off the land with no file to hash | Yes, via the guard's behavioural rules; YARA alone misses it |
| A-5 | Another local user | Interactive session, no admin | Use MI CS as a lever on a shared machine (F-2) | Yes |
| A-6 | Administrator-level attacker | Full admin, or the admin's own malware | Turn off Defender/firewall/guard, replace binaries | Evidence only; prevention is impossible by definition |
| A-7 | On-path network attacker | DNS/route/TLS interception | Poison feeds or the update manifest (F-3) | Partly |
| A-8 | Supply chain | Our endpoints, a dependency, a compromised release host | Ship a malicious update or rule pack (F-3) | Partly |
| A-9 | Kernel-level attacker | Drivers, BYOVD, firmware | Total invisibility | **No** — documented, not defended |
| A-10 | The user's own mistake | Downloads and clicks | Get infected on purpose | Yes: reduce damage, never claim prevention |

## 4. Trust boundaries

### B1 — UI process: `mics_app.exe`

Manifested `requestedExecutionLevel level="asInvoker"` (`windows/runner/runner.exe.manifest`,
D-010), so the UI starts unelevated and never holds an admin token. It reaches the
OS only through the engine (`AGENTS.md` rule 4, whitelisted JSON-RPC methods).

### B2 — `\\.\pipe\mics_engine` (UI ↔ engine)

The engine's pipe server passes **no** security attributes
An **explicit** SDDL (`platform/windows/pipe.rs`), measured on the reference
machine with an isolated `service` engine (`scripts/verify-pipe-acl.ps1`):

```
D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user-SID>)
```

- Full control: SYSTEM, Administrators, and the user who started the engine.
  Nobody else: `Everyone` and `ANONYMOUS LOGON` are gone, and `P` marks the DACL
  protected so no inherited ACE can widen it.
- **This was not always so.** Until the fix below, the pipe passed no security
  attributes at all, so it carried Windows' default ACL for a pipe created by
  this process — `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)(A;;FR;;;WD)(A;;FR;;;AN)`.
  The `WD`/`AN` read ACEs meant any local account on a multi-user machine could
  attach to a free instance and read the broadcast stream (`event`, `progress`;
  `jobs::notify`) — the paths, detection names and incident text in alerts and
  scan progress. Such a client could never *send* a request (that needs write
  access), so it was a confidentiality leak, not control. F-1 recorded it; the
  explicit ACL closes it, and two tests read the ACL back from the live pipe
  object so a regression fails the suite instead of shipping.
- Anything running with the user's own token can call every engine method
  (`guard.kill`, `quarantine.delete`, `settings.set`, `update.apply`, the audit,
  the scanner). That is accepted: the same token can also just start the engine
  binary or write to the install dir. The boundary that matters is *other users*
  and *elevation*, not same-token code.

### B3 — `\\.\pipe\mics_helper` (engine ↔ LocalSystem helper)

Set explicitly as `PIPE_SDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)"`
(`privileged/server.rs`) and measured on the reference machine
(`scripts/verify-pipe-acl.ps1`):

```
D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;IU)
```

`IU` is `INTERACTIVE`: **any** interactively logged-on user — including a standard
user who cannot answer a UAC prompt — can ask the LocalSystem helper for the
closed operation set. The set is small, shaped-validated and audited
(`PRIVILEGED-OPS.md`), but a standard user can still, without any prompt, have
SYSTEM open an inbound firewall rule, replace the managed hosts section, or run a
hardening action. Accepted for now for one reason: the alternative is a UAC prompt
per action, which is exactly what D-007 removed. It is a real multi-user risk —
F-2, with the caller-identity check as the mitigation.

### B4 — Helper operations: the closed set

`Op` is a closed enum — no shell, no "run this command", no script passthrough.
Payloads are validated **before** execution and before the audit start line:
`hardening.run` action ids must exist in the command table, `hosts.write` must
carry the `# BEGIN MICS-IDS` marker with every line a real `address host` pair and
≤ 4 MiB, `hardening.rollback` accepts at most 8 lines whose `;`-separated commands
must match shapes this codebase generates and absolute `HKLM\` keys. This is what
stops the pipe from being a "write any file / run anything as SYSTEM" primitive
(AP-1, AP-2). `MICSHelper` refuses to act at all when it is running without an
elevated token.

### B5 — Elevation

One UAC prompt, at helper installation (D-007). The UI stays `asInvoker`; when an
action genuinely needs an admin token and the engine is not elevated, the engine
asks Windows and reports the real failure reason instead of a generic one; the UI
offers an explicit "Relaunch as administrator" (`app.relaunch_elevated`, D-010).
Nothing privileged runs silently in the UI process.

### B6 — The network

Outbound TLS uses `reqwest` with `rustls-tls` (Mozilla root store — an enterprise
TLS-inspecting proxy will break feeds, by design: no corporate CA is trusted).

| Destination | What is sent | Trigger |
|---|---|---|
| `raw.githubusercontent.com` (StevenBlack hosts) | a GET, nothing machine-specific | intel sync, when that source is configured |
| `cisa.gov` KEV feed | a GET | intel sync |
| `services.nvd.nist.gov` | installed product identifiers (CPE/keyword query), key optional | vulnerability scan |
| `virustotal.com/api/v3/files/<sha256>` | **a hash only**, never file content | explicit lookup (`scanner/vt.rs`) |
| `dns.google`, `1.1.1.1` | a HEAD/GET probe with no payload | the "online?" check, cached 30 s (`sync/mod.rs::online`) |
| LM Studio (`lm_url`, default `http://127.0.0.1:1234`) | the finding text to explain | LLM explain, explicit |

`settings.rs` accepts `https://` everywhere and `http://` **only for loopback**
(`127.0.0.0/8`, `::1`, the literal name `localhost`) — that is what a local LM
Studio needs, and it is the one case where the traffic never leaves the machine.
A cleartext feed or update manifest is refused at `settings.set` and cleared again
on load, so a hand-edited file cannot smuggle one in (the half of F-3 that is
closed; `WinVerifyTrust` on the extracted binary is still open).
`AGENTS.md` rule 8 now carries this table's list instead of a shorter one — the
intel sources and the connectivity probe used to be missing from it (F-7, closed).

### B7 — The package directory

The install directory is user-writable (`%LOCALAPPDATA%\MI CS` or an unpacked
portable folder). Two consequences: `rules\` is hot-reloaded from a path the user
(and any same-token process) can write, and the updater replaces binaries there.
Impact is limited to detection quality and availability for the same user; it is
not a privilege boundary. Releases are Authenticode-signed (`scripts/sign.ps1`),
but the *updater* verifies only the SHA-256 recorded in the manifest — it never
calls `WinVerifyTrust` (F-3).

### B8 — The data directory

Resolution order (D-011): `MICS_DATA_DIR` → the sticky pointer in
`%LOCALAPPDATA%\MICS\.data-dir` → `%PROGRAMDATA%\MICS` when proven writable (a real
`BEGIN IMMEDIATE`, not a folder probe) or when the engine is elevated → otherwise
`%LOCALAPPDATA%\MICS`. An elevated engine grants the interactive user modify
rights once, idempotently, with a marker file (`icacls`, `settings.rs`).

Quarantine blobs are AES-256-GCM with a per-machine master key in a sidecar file
protected with **DPAPI machine scope** (`scanner/quarantine.rs`). Machine scope
means any local process on this machine can decrypt it; what it actually buys is
that copying a blob to another machine is useless. It is not protection against
local code (F-6).

### B9 — Test hooks, honoured in release builds

`MICS_DATA_DIR`, `MICS_PIPE_NAME` (full path), `PROGRAMDATA`, `MICS_ENGINE_PATH`,
`MICS_NO_SINGLETON`, `MICS_NO_GUARD`, `MICS_NO_AUTO_RESUME`, `MICS_HELPER_PIPE`
(**bare** name — `privileged/ops.rs` prefixes `\\.\pipe\`, F-8), `MICS_VT_API_KEY`,
`NVD_API_KEY`, `MICS_LM_URL`. Whoever can set the engine's environment decides
where it reads and writes and whether the guard runs. That requires the ability to
create a process as the user, which already implies the same-token power described
in B2 — accepted, and the reason the hooks are documented rather than hidden.

### B10 — Notifications

Cards are raised under the app's AUMID. Windows lets any same-token process raise
a card with that AUMID, so **a card is UI, not proof**: the record is the engine's
DB and `priv.log`. The card's action ids are resolved by the engine's own handler,
so a forged card cannot make the engine do anything the caller could not already
ask the engine to do through the pipe.

## 5. Attack paths we considered

| # | Attempt | Outcome | Evidence |
|---|---|---|---|
| AP-1 | "write any file as SYSTEM through the helper" | Refused: marker + line-shape validation, ≤ 4 MiB, `MICS-` prefix owned by the helper | `Op::validate`, `scripts/verify-helper.ps1` |
| AP-2 | "make the engine run arbitrary PowerShell" | No op takes a command; hardening ids come from a fixed table (`validate_action`) | `hardening/mod.rs`, helper tests |
| AP-3 | "make the audit lie" | The engine computes the score, flags `partial`, and omits a section whose collector failed instead of reporting it secure; a refused Defender query is `Unknown`, never `Secure` | audit tests, D-014 |
| AP-4 | "poison an update" | SHA-256 from the manifest over TLS, `http://` refused outside loopback, and the extracted payload must carry an embedded signature from `CN=MI CS Code Signing` that Windows trusts before it replaces anything (D-016) | F-3 (CN pin, thumbprint gap open) |
| AP-5 | "steal quarantined samples" | AES-256-GCM + machine-scope DPAPI: an off-box copy is useless, local code can decrypt | `scanner/quarantine.rs` (F-6) |
| AP-6 | "hide from the scanner" | Acknowledged: user-mode, hash-IOC + YARA only — no unpacking, emulation, memory scanning. A custom packer wins round one; the guard's behavioural rules are round two | `scanner/`, F-9 |
| AP-7 | "read the decoys and slip through" | A pure **read** changes neither mtime nor size, so it is invisible; the copy says "modified" and never claims otherwise | `guard/canary.rs` (F-4, copy fixed) |
| AP-8 | "starve the engine with a hung tool" | Every external tool call has a deadline through one choke point, enforced by a source-scanning test | `platform/windows/process.rs`, `every_spawn_site_enforces_its_deadline` |
| AP-9 | "forge a card to trigger a Quarantine click" | The card is display only; the action id is validated when the engine handles it | `notify/`, D-013 |
| AP-10 | "read the engine's traffic as another local user" | Was possible through the default `WD`/`AN` read ACEs; **closed** by the explicit pipe ACL below | B2, F-1 (fixed) |
| AP-11 | "redirect traffic through the managed hosts section" | Reversible, audited, shape-validated — but any interactive user may ask (B3) | `PRIVILEGED-OPS.md`, F-2 |
| AP-12 | "kill the engine and stay quiet" | Same-token code can kill it; there is no self-defense or watchdog. The helper service survives, and the UI reconnects and reports the gap | F-8 |

## 6. Residual risks

| # | Risk | Why it is accepted today | Mitigation if we want it |
|---|---|---|---|
| F-2 | **Closed as a distinct-user risk** (F-2a + F-2b): the helper reads the caller's pid, image and token SID, and answers only `mics-engine.exe` running as the account that owns `%PROGRAMDATA%\MICS`. What is left is not another user — it is a process running as the *installing user*, which can already answer a UAC prompt itself (D-007's trade), plus the portable fallback where no account is recorded yet | D-007 removes per-action prompts by accepting that the install owner is the trust anchor | Nothing further for F-2; the portable fallback is the LOW register entry, and a future service-mode engine running as `SYSTEM` would need a new decision |
| F-3 | The update signer is pinned by **subject name** (`CN=MI CS Code Signing`), not by thumbprint — a certificate with that same CN issued by a CA that failed identity validation would still pass | A thumbprint pin would break on every locally re-issued certificate, making the next release refuse its own payload | Pin the thumbprint once a release certificate with a stable lifetime exists, or carry the expected thumbprint inside a separately signed manifest |
| F-4 | Canary decoys detect writes (mtime/size), not reads | NTFS last-access updates are off by default; a read needs a minifilter or handle auditing (kernel, A-9). **The copy no longer overstates it** (alert, card title and incident say "modified", not "accessed") | A read-level detector needs the kernel; keeping the decoy names plausible still makes a read worth attempting |
| F-5 | `vt_api_key` / `nvd_api_key` / `ioc_feed_key` sit in plaintext in `settings.json` | Any local user who can read that file can already read the engine's own state | DPAPI-protect the secret fields (machine or user scope) and show them masked/never in reports |
| F-6 | Quarantine master key is DPAPI **machine** scope: any local process can decrypt the blobs | The point is that a copied blob is useless off-box; local code with the user's rights can read the DB anyway | User-scope DPAPI per machine account, at the cost of breaking "restore after an admin reinstall" |
| F-8 | No self-defense: same-token code can kill the engine, replace binaries, edit `rules\`, or point the engine at another data dir through its environment | Stopping a same-token attacker requires kernel callbacks or a second service — A-9 territory | Run the engine under a watchdog service and verify the package's signature before loading rules |
| F-9 | No memory scanning, no unpacking/emulation, no AMSI, no pre-execution blocking (no minifilter) | Usermode-only and driver-free is a product decision (no driver install, no BSOD risk) | Documented in `PROTECTION-MATRIX.md`; the guard's behaviour rules are the compensating control |
| F-10 | A local admin can turn everything off and delete the evidence | Unavoidable without kernel enforcement | Ship the audit trail to a location the admin cannot reach (a real solution is an external log sink — out of scope) |

**Closed since this document was written.** F-1: the engine pipe now carries an
explicit, protected ACL naming the engine's user, `SYSTEM` and administrators. Two
tests read the DACL back from the live pipe object
(`pipe::tests::the_engine_pipe_grants_only_the_owner_system_and_administrators`
and `::the_pipe_acl_is_protected_and_names_a_real_user_sid`), and
`scripts/verify-pipe-acl.ps1` re-measures both pipes end to end — protected DACL,
three ACEs, no `WD`/`AN`/`IU`, and a same-user JSON-RPC `status` call still
answered over the hardened pipe. **F-2 (both halves)**: the helper reads the caller's
pid, image path and token user SID, and answers only the engine running as the account
that owns `%PROGRAMDATA%\MICS` — measured live: an unnamed PowerShell client is
refused with `this pipe only serves the MI CS engine`, and the owner-vs-token test
reads both SIDs back on this machine. **F-4 (the copy)**: the canary alert now says the decoy was
*modified* — in the event detail, the card title (ar/en) and the incident title —
because mtime/size is all the detector compares. The detection gap itself is not
closed: a pure read is still invisible, and that part stays in the table above.
**F-7 (the rule)**: `AGENTS.md` rule 8 now lists what section B6 measures — the
configured intel sources and the 30 s connectivity probe included — instead of
claiming "nothing leaves the machine except VT/NVD/LM". **F-3's cleartext and
signature halves (F-3a/F-3b)**: `http://` is refused outside loopback, and the
extracted payload must carry an embedded signature Windows trusts before a single
byte is copied over the running install (D-016), and the signer's name must be
`MI CS Code Signing` — a valid signature from another certificate is refused. What
F-3 still carries is the pin's *precision*: subject name, not thumbprint.

## 7. What is proven, and how

| Claim | Proof |
|---|---|
| No external tool can hang a request | `every_spawn_site_enforces_its_deadline` + the source scan for bare `Command::new(` |
| The helper cannot be turned into "run this as SYSTEM" | `PRIVILEGED-OPS.md` + the validation tests + `scripts/verify-helper.ps1` |
| The audit cannot silently claim a section is fine | `tests.rs` (failed collector omitted, partial flagged, merged report keeps the engine-computed score) |
| The engine pipe refuses everyone but its owner, SYSTEM and administrators | the two `pipe::tests` above (the DACL is read back with `GetSecurityInfo`) |
| A card means Windows recorded it | `scripts/verify-toast.ps1` reads the notification history back |
| A release is complete and signed | `scripts/verify-release.ps1` + `scripts/sign.ps1` |
| The two pipe ACLs are what this file says | `scripts/verify-pipe-acl.ps1` — both pipes, real `service` and `helper-console` processes on private names, 18 checks, `RESULT: PASS` |
| The guard's cost | `mics-engine benchmark` (currently 2.97 % against a < 1 % budget — §0.1, not yet met) |

## 8. Open questions

1. Should the helper verify the caller's identity instead of trusting `IU` (F-2)?
   That is the only way to keep D-007's single prompt *and* stop a standard user.
   The engine pipe answered the same question the other way (D-015): an explicit
   ACL, no caller check.
2. Is a watchdog service worth the second moving part (F-8)?
3. Do we ever need `http://` outside loopback (F-3)?
4. Should the engine refuse to start at all when it cannot apply its pipe ACL,
   instead of falling back to the default one with a warning?
