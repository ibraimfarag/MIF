# MI CS — Protection Matrix

What each layer actually sees, detects, blocks and **misses**. The threat model
([`THREAT-MODEL.md`](THREAT-MODEL.md)) says who the adversaries are and where the
trust boundaries sit; this file says what the machinery does about them, layer by
layer, with the code that proves it.

One sentence to read first: **MI CS is a posture, triage and response tool that
leans on Windows' own antivirus for real-time protection.** It is not an EDR, it
is not a kernel product, and nothing here blocks code before it runs.

Three words are used precisely throughout:

| Word | Means |
|---|---|
| **Sees** | the data the layer is given at all (if it is not listed here, the layer is blind to it) |
| **Detects** | raises a finding or an event about it |
| **Blocks** | prevents or undoes it (a detection with no block is still useful — it is the difference between "we told you" and "we stopped it") |

**Layer names.** The `L1`–`L5` numbers are the product's own, the same ones the
README's "five layers" table uses: **L1 Network Gate** (firewall), **L2 Attack
Radar** (name-resolution blocklists), **L3 Response** (guard, canaries,
correlation), **L4 File Engines** (scanner), **L5 Mind** (incident correlation).
The vulnerability, posture, Defender and
delivery rows below are cross-cutting work that does not sit inside a single layer,
so they keep their own names. This sheet's section numbers (§2 scanner, §3 network,
§4 guard) are stable on purpose — other documents cite them.

## 1. The layers at a glance

| Layer | Kind | Runs in | Elevation | Detects | Blocks |
|---|---|---|---|---|---|
| L4 scanner | on-demand static analysis of files | engine job | no | known hashes (IOC feed) + YARA rules, over the tree you point it at | only through quarantine (the file is moved); never pre-execution |
| L2 IDS | DNS-name sinkhole in the hosts file | helper applies, every app consumes | yes (helper) | nothing — it is a pure block | listed domains resolve to `0.0.0.0` |
| L1 firewall | Windows Firewall API (`INetFwPolicy2`) rules | helper | yes (helper) | nothing | outbound default-deny, per-rule allow/block (program/port/IP), one firewall rule per blocked country |
| L1 filtering engine (WFP) | MI CS' own provider, sublayer and persistent filters in the Base Filtering Engine | helper (or the engine when it is elevated) | yes (helper) | nothing | a persistent per-application/port `FWP_ACTION_BLOCK` at the ALE connect layers, enforced by the BFE with MI CS not running — **measured against the real Base Filtering Engine 2026-11-09 (D-042/D-045): `scripts\verify-wfp.ps1` 16 passed, 2 skipped, 0 failed, with Windows' own `netsh wfp show filters` reporting the filter as a persistent Block in `ALE_AUTH_CONNECT_V4`** |
| L1 tamper watch (WFP) | a record of our filter names and sublayer compared against the BFE by a poll (~30 s) | engine | no | our own sublayer or filter leaving the BFE while MI CS did not remove it | nothing — one HIGH incident and card naming what is gone (D-044); it never re-creates the object |
| L3 guard | process-start rules (ETW, or a 2 s poll unelevated) | engine | ETW yes, poll no | process starts matching JSON rules (image, parent, command line) | kills the process tree for rules marked `kill` — after the start |
| L3 canaries | decoy files | engine poll | no | decoys whose mtime/size changed | nothing |
| L3 correlator + noise learner | analysis over guard events | engine | no | kill-chain grouping; mute suggestions for events you keep dismissing | nothing |
| Vulnerability | installed software → NVD 2.0, KEV annotation | engine job | no | known CVEs for the applications it can map | nothing (no patching) |
| Posture | audit (10 checks) + hardening (5 fixes) | engine, helper to apply | to change anything | misconfiguration: Defender, firewall, RDP, SMBv1, UAC, admins, startup, scheduled tasks, hosts, remote-access tools | the five hardening actions, snapshotted and reversible |
| Defender orchestration | Windows' own AV engine | engine/helper | to change preferences | reads Defender's real-time and PUA state | turns PUA protection on; runs a Defender quick scan (`MpCmdRun.exe`) |
| Delivery | cards, Markdown reports, `priv.log`, SQLite | engine | no | nothing | nothing |

## 2. L4 — static file analysis (on demand)

**Sees.** The tree you hand to `scan.start` (one root path, `C:\` if you omit it),
file by file, up to **50 000 files** and **200 MB per file** (`scanner/mod.rs`).
Triage ranks the queue by location × extension × size × age, and archives
(`zip`/`rar`/`7z`) are ranked higher because that is where payloads hide.

**Detects.** Two independent checks per file: SHA-256 against the local IOC cache
(the `ioc_hashes` intel source), then the bundled/hot-loaded YARA rules. Detections
become job findings with a per-job progress stream; `cargo test` pins the resumable
job contract (a restart resumes at the exact file).

**Blocks.** Only if you asked for it: `scan.start {quarantine: true}` moves the file
into the encrypted store (AES-256-GCM, DPAPI machine-scope key) where it can be
restored or deleted. A scan never stops a process or a file from loading.

**Misses — and why.**

- **Anything new.** No unpacking, no emulation, no memory scanning: a packed,
  encrypted or obfuscated payload is a blob of bytes to both checks (F-9).
- **In-memory and script payloads.** PowerShell/JScript evaluated at runtime never
  hit a file scanner. AMSI is not hooked.
- **Archives are ranked, not expanded.** A ZIP is hashed and matched as a file;
  its contents are only seen if they are also on disk somewhere.
- **Files past the limits.** Larger than 200 MB, or the 50 001st file, are counted
  as skipped and reported as such.
- **Only what you point it at.** A scan is what covers a file, and there are two
  ways to get one: the button, or the **scheduled scan** (D-027) — opt-in, off by
  default, every 6..168 h over the folder in `scan_target`, and only while the
  engine is running — and since D-039 the engine's life is the app's, unless
  *Keep running in the background* is on or an autostart entry owns it. A scheduled run is
  **report-only**: it never quarantines, because nobody chose a file while it was
  running. There is still **no real-time file watching**, so a file that appears and
  is deleted between two runs is never seen — that half of the register row is open
  by decision (و2), not by omission.
- **The hash dimension is empty by default.** No key-free SHA-256 feed is left
  (abuse.ch wants an Auth-Key), so `ioc_hashes` reports `not_configured` until a URL
  and key are supplied. There is no VirusTotal client (D-019), so a hash is never
  looked up off-box either: reputation is the local cache plus YARA.
- **Detection content is a starter pack** (6 guard rules, 10 YARA rules). The
  engine is the product; the packs are a demonstration until real content is
  curated. What they catch is **measured, not assumed**: `scripts\verify-rules.ps1`
  holds the pack a package ships to the vectors in `engine\testdata\detection`
  (8 files, each written for one rule, plus a clean control), and every rule the
  pack declares must either be caught by one of them or be named as unreachable
  with its reason. Measured 2026-11-05 on the shipped pack (`starter.yar`,
  sha256 `69899c59…`): **8 of the 10 rules are held to a file** — `Suspicious_HTA_Exec`,
  `Suspicious_BAT_Certutil_Download`, `Suspicious_Cmd_PowerShell_Download`,
  `Suspicious_VBS_Dropper`, `Malicious_Macro_AutoOpen`, `Double_Extension_Emailer`,
  `Ransom_Note_Names`, `Suspicious_Scheduled_Task_Creator` — and 2 are not:
  `EICAR_Test_File` (the string is what Defender itself reacts to, so a committed
  fixture would be quarantined) and `Tiny_Packed_Pe_Installer` (a PE-shaped fixture
  has to be binary). The same table runs in the fast tier as
  `scanner::yara_engine::tests`, so a rule that stops matching fails in seconds
  instead of on a user's machine.
- **The macro rule's reach is one container shape, and no more.** `Malicious_Macro_AutoOpen`
  tests a container by two magic bytes plus substrings, and a real macro document
  **deflates** those substrings into bytes no pattern can read. Measured on a
  `.docm` built for the probe: the literals `AutoOpen`, `CreateObject` and `Shell`
  are absent from the file's bytes (only the entry name `vbaProject` survives).
  Before 2026-11-05 the rule was worse than weak — it compared `uint16(0)` against
  `0x504B`, which little-endian is `"KP"`, so it could never fire on any document
  at all; the shipped constant is `0x4B50` now. Catching a real macro document
  needs an OOXML/OLE parser, which is a decision (D-033), not a rule edit.

## 3. L1/L2 — network and name resolution

### 3.1 Hosts-file IDS (`ids/mod.rs`)

**Sees.** Domain names from the synced blocklist (StevenBlack/hosts by default).
**Blocks.** Every app on the machine: each listed domain is written into the
managed `# BEGIN MICS-IDS` section as `0.0.0.0 <domain>`, and the helper replaces
that section atomically (the caller snapshots first — D-007).

**Misses.** Anything that is not a name resolved through the system resolver: an
IP-only command-and-control address, an application that brings its own DNS (DoH
inside a browser), or a domain that is not on the list. There is no content
inspection, no TLS interception and no per-process decision — it is one machine-wide
sinkhole. The managed section is also writable by any interactive user through the
helper (threat model F-2).

### 3.2 Firewall (`firewall/mod.rs`)

**Sees.** Rules and profiles through the Windows Firewall API (`INetFwPolicy2`,
`INetFwRules`, `INetFwRule`) — typed properties, not console text, so there is no
locale or output-format dependency left in the path (D-028). `scripts\verify-firewall.ps1`
compares what the engine reads with what `Get-NetFirewallProfile` and
`Get-NetFirewallRule` report on the same machine.
**Blocks.** The outbound default-deny toggle for all three profiles, individual
`MICS-*` allow/block rules (program, port, remote IP), and one
`MICS-BLOCK-<CC>` rule built from an installed `<CC>.cidr` country list. The
`MICS-` prefix is owned by the code, so listing and removal never touch rules it did
not create, and every action is reversible through the helper. Every rule carries an
explicit all-profiles mask and the "MI CS" group, so it appears (and can be removed)
in the Windows UI as well as in this app.

**Misses.** Granularity is IP/port/program: no payload inspection, no reputation, no
per-domain rules (that is the hosts layer's job), and no protection against a rule
someone else adds. Country blocking is **IPv4-only** and offline-first: if no
`<CC>.cidr` file is installed, the request is refused instead of guessing (D-012).
Default-deny outbound is a blunt instrument by design — it breaks whatever the user
did not allow.

### 3.3 The filtering engine (`firewall/wfp.rs`, D-042)

**Sees.** MI CS' own objects in the Base Filtering Engine: the provider
`{6D494353-0001-…}`, the sublayer `{6D494353-0002-…}` and every filter under them,
read back through `FwpmFilterEnumByProvider0`. Nothing outside that provider is
enumerated, and an unelevated engine with no helper cannot read the BFE at all — it
says `needs_elevation: true` with the reason instead of showing an empty list.

**Blocks.** One persistent `FWP_ACTION_BLOCK` per application and/or remote port, at
`ALE_AUTH_CONNECT_V4`/`_V6` (connection time, both families), added only through the
helper (D-007). The filter is written with `FWPM_FILTER_FLAG_PERSISTENT`, so the BFE
enforces it with MI CS not running — which is the whole point of having our own
sublayer instead of a Windows Firewall rule: the objects are ours, `MICS-` names them,
and `reset` addresses our provider key, so nothing else on the machine can be deleted
by it. The engine reads the filter list back before reporting a block, and the audit
line records the display name and key but never the directory the application sits in.

**Misses.** This is a *usermode* filter, not a driver: it decides at the ALE layers
for the application path it was given, so traffic that never reaches them — kernel
mode, raw sockets, a callout in a heavier sublayer, or the same binary reached through
a renamed copy — is outside it. The list it is driven from is a **snapshot** of the
kernel's tables, not a push feed: a connection that opens and closes between two reads
is never seen. A deletion of our sublayer or filters is noticed by §3.5 (D-044), and
only on its own poll — a delete-and-re-add inside that window is invisible to it. The
write path is no longer unmeasured (2026-11-09, D-042/D-045): `scripts\verify-wfp.ps1` ran
elevated and read the filter back out of the BFE with Windows' own `netsh wfp show
filters` — `FWP_ACTION_BLOCK`, `FWPM_FILTER_FLAG_PERSISTENT`, at
`FWPM_LAYER_ALE_AUTH_CONNECT_V4`, matching the application path, the remote port and the
protocol it was given, and gone from both our list and Windows' state after the undo. What
is still not composed into evidence: the **enforcement effect** (no connection was opened
through the blocked app and port to watch it be refused), a **survival across a reboot**
(persistence is the flag Windows reports; no reboot was performed), and whether our
sublayer's **weight outranks a permit rule** from the built-in firewall.

### 3.5 The tamper watch (`firewall/watch.rs`, D-044)

**Sees.** Whether the objects §3.3 wrote are still in the Base Filtering Engine: a
record of our filter names and of the sublayer (`meta` row `wfp_baseline`, written
after a successful block, removed by `unblock`, cleared by `reset`) compared against
what the machine holds — `guarded`, `tampered` naming the sublayer and every filter
that is gone, `clear`, `unrecorded` for filters of ours with no record beside them, and
`unknown` when neither this process nor the helper may read the BFE. The comparison
itself is pure, so every one of those states is a unit test. The guard thread polls it
about every 30 s, and `fw.wfp.watch` is the same look on demand.

**Blocks.** Nothing: re-adding what an administrator deleted would fight the machine's
owner, so the alert is the feature. A tamper raises **one** HIGH guard event per
change — an incident titled "MI CS' filtering layer was tampered with", a desktop card
with its own copy and icon, the event in the correlator's timeline — and a repeat poll
of the same loss is silent instead of a drumbeat.

**Misses.** It is a poll, not a subscription, so a delete-and-re-add between two polls
is never seen, and it cannot tell a deliberate administrator cleanup from an attacker:
both read as the same sentence. `unknown` is not "fine" — an unelevated engine with no
helper genuinely cannot read the BFE (D-042), and the watch says so rather than
reporting an empty machine as `guarded`. The record is best-effort by construction: a
crash between the write and the record leaves one filter of ours listed as `extra`,
which is never a false tamper. The machine half is measured (2026-11-09, D-044):
`scripts\verify-wfp-watch.ps1` ran elevated and **34 checks passed, 1 skipped, 0 failed**,
its first part reading the **real** BFE (`state=clear recorded=0 live=0
needs_elevation=false` — and `live=0` is also the proof that the four stray filters the
2026-11-08 run left behind were gone), with the detector and alert parts still driven by an
injected status. What is not measured is the case the feature exists for: a **real** filter
deleted behind the engine's back so that the engine's own bookkeeping is untouched and the
poll is the only thing that can notice, and the guard thread's 30 s tick observed firing on
its own rather than the on-demand call.

### 3.4 Live connections and the one-click block (`windows/conns.rs`, D-043)

**Sees.** Windows' four connection tables in usermode — `TCP_TABLE_OWNER_PID_ALL` and
`UDP_TABLE_OWNER_PID` for IPv4 and IPv6 — each row joined with its owning process (name
from a single `sysinfo` refresh, image path from one `OpenProcess` + 
`QueryFullProcessImageNameW` per pid, cached for the call) and, for TCP peers, the
country of the remote address from the local GeoIP table. IPv6 rows are carried, not
dropped, because a block on `[2001:db8::1]:443` has to be expressible.

**Blocks.** One click on a row sends the spec the **engine** built for it — the row's own
image path, its peer port and its protocol — to `fw.wfp.block`, so the filter matches
exactly what was on screen and nothing wider. The click is confirmed first, and the
confirmation says the filter outlives MI CS. Rows that cannot become a filter say so
instead of offering the button: a UDP socket (Windows keeps no peer for it), a TCP
listener (no peer port), a kernel connection or a process this token may not query (no
image path).

**Misses.** It is a snapshot taken when the screen opens or Refresh is pressed, so it can
be seconds stale by the time a row is clicked — the block is still written, but a
connection that has already moved on will not be caught by it. Its write path *is*
measured — elevated `scripts\verify-connections.ps1` **24 checks passed, 0 skipped, 0
failed** (2026-11-09, D-043: a row's own spec accepted by `fw.wfp.block`, the BFE one
filter heavier, `fw.wfp.unblock` taking the machine back to where it started) — but the
enforcement is not: no connection was opened through that filter to watch it be refused.
There is no per-row
traffic counter, no reverse DNS and no process tree next to a row (the UI shows country,
name and path only), and a block cannot be removed from the list itself: removal is the
Firewall tab's rule list. UDP rows carry no peer at all, which is Windows' limitation,
not a simplification.

## 4. L3 — process guard, canaries, correlation

### 4.1 Process-start rules (`guard/mod.rs`, `guard/etw.rs`)

**Sees.** Process creations: instantly through the ETW kernel Process provider when
the engine runs elevated, otherwise through a **2 s poll** of the process list.
Command lines come from `sysinfo` enrichment (the kernel provider does not carry
them). Rules are JSON, hot-reloaded from `rules\guard\*.json`, and match image name,
parent image and command-line substring, with severity and `action: alert|kill`.

**Blocks.** For a rule whose action is `kill`, the process **tree** is killed with
`taskkill /T /F` (15 s deadline).

**Misses — and why it matters.**

- **The process has already started.** ETW and the poll both report a creation, so
  the first instructions (and any child spawned before the kill lands) already ran.
  This is response, not prevention.
- **Short-lived processes in poll mode.** Unelevated, the poll can step over a
  process that starts and exits between two samples. Only the elevated ETW path sees
  them.
- **Rules are name/cmdline patterns.** Rename the binary or use a different living-
  off-the-land tool and the rule does not fire; there is no file/registry/network
  behaviour in the rule language (`child_cmd_contains` is the only data predicate).
- **The process hash is not checked at start.** Hashing every process creation was
  judged too hot, so the ETW callback does not hash the image (it used to load the
  IOC hash list and drop it; that dead load is gone). The scan job owns the hash
  dimension (scheduled or manual, D-027), and `guard.status` reports the limit as a
  fact — `ioc.hash_checked_at_process_start: false` with its reason — so the
  surface cannot imply coverage this path does not have.
- **Starter content.** Six bundled rules. The shipped pack demonstrates the
  mechanism; it is not a behavioural signature database.

### 4.2 Canaries (`guard/canary.rs`)

**Sees.** mtime, size and **last-access time** of the decoy files (three defaults
under Documents and Desktop, configurable), polled on every guard tick.
**Detects.** A CRITICAL event when a decoy's mtime or size changes (written,
truncated, renamed, deleted), and a separate HIGH `canary_read` event when its
last-access time moved and nothing else did — a read-only open, on its own rule id
(`CANARY_READ`) so reads can be quieted without quieting the writes. A decoy MI CS
has just created is left quiet for 90 s (`READ_SETTLE`): Defender's first look at a
brand-new file is not an alert, and the engine's log says `canary settling` rather
than staying silent about it.
**Blocks.** Nothing.

**Misses.** A read can only be seen on a volume that keeps a last-access time, and
that is measured rather than assumed: when the watchers arm, `read_detection()`
writes a scratch file, reads it back and compares the time, and `guard.status` /
`canary.status` carry `{available, probed_on, detail}` — the Canaries screen prints
the verdict, including the `fsutil behavior set disablelastaccess 0` that turns it
on, instead of implying coverage. The verdict is about the **decoys' own folder** and
is re-measured when they move. The engine cannot name the *reader* without the kernel
event source (pid 0), so a read is evidence that something opened the decoy, not who.
Decoys are also files in obvious places: they catch mass encryption and careless
hands, not a targeted actor.

Measured on this machine, 2026-11-05 (`scripts\verify-canary.ps1`, 20 checks, PASS):
`DisableLastAccess = 2 (System Managed, Last Access Time Updates ENABLED)`, four
reads in a row moved the atime, a read from a *different* process moved it, and fifty
metadata queries in a row moved nothing — which is what lets the poll stat its own
decoys without tripping the trap it arms.

### 4.3 Correlator and noise learner

**Sees.** Guard events and their timestamps. **Detects.** Related events grouped
into one kill-chain timeline; repeated dismissals become a mute suggestion (a
suggestion, not an automatic rule). **Blocks.** Nothing. This layer has no sensors of
its own — its quality is the quality of what the sensors above produced.

## 5. Vulnerability layer (`vulns/`)

**Sees.** Installed software from the registry Uninstall keys (both views) and a
hand-maintained known-app → NVD keyword map.
**Detects.** Matching CVEs from NVD 2.0 (offline cache when the network is absent,
labelled as such) with a KEV badge and remediation date when CISA lists the CVE as
exploited in the wild.
**Blocks.** Nothing. There is no patching, no driver/OS-update check and no
"affected but not installed" reasoning.

**Misses.** The mapping is keyword-based, **not CPE matching** (real CPE matching
was deferred to a later phase), so it produces both false positives and silent
misses. NVD without an API key is rate-limited. KEV says a CVE is exploited
somewhere in the world; it does not say this machine is affected right now.

## 6. Posture layer — audit and hardening

**Detects** ten configuration facts (Defender, firewall profiles, RDP, SMBv1, UAC +
secure desktop, local administrators, startup entries, non-Microsoft scheduled
tasks, hosts file, remote-access tools) and turns them into a 0–100 score. The score
is computed by one function over every finding, a partial run is labelled
`partial`, a merged re-read keeps the full picture, and a collector that cannot
answer reports `Unknown` rather than a comfortable default (D-014).

**Blocks** nothing, but **fixes** five things on request (PUA protection, SMBv1 off,
RDP off, UAC + secure desktop, Defender quick scan). Every change takes a snapshot
first and can be rolled back.

**Misses.** This is configuration hygiene, not a security state: a fully hardened
machine with a running stealer still scores 100. It does not check patch level,
BitLocker, Secure Boot/TPM, AppLocker/WDAC, LSA protection, Office macro policy,
browser settings or ASR rules, and it cannot see what it does not query — the audit
is a list of checks, not a scan of the system.

## 7. Windows Defender orchestration (`hardening/mod.rs`, `dispatcher.rs`)

**Sees.** Defender's own state (`Get-MpComputerStatus` for real-time protection,
`Get-MpPreference` for the PUA setting). **Blocks.** Nothing itself — it enables
**PUA protection** and triggers a Defender **quick scan** through `MpCmdRun.exe`.

This is deliberate: real-time file and behaviour protection on this product is
Windows Defender's job, and the audit tells you loudly when it is off. It also means
Defender's quality is the ceiling for real-time protection, and that tamper
protection can refuse the PUA write even when we are elevated — `hardening.apply`
detects that no-op and points at the Windows Security switch instead of claiming
success (register, MED).

## 8. Delivery and evidence

**Sees.** Everything the layers above emit. **Detects/Blocks.** Nothing.

Cards (AUMID `MICS`, D-013), Markdown reports in `Documents\MICS-Reports`, the JSONL
event stream over the pipe, the SQLite history, and the helper's own audit trail
(`%PROGRAMDATA%\MICS\logs\priv.log`: intent and outcome, never the payload). Cards
follow one policy — CRITICAL/HIGH/MEDIUM become desktop cards, LOW stays in the app,
do-not-disturb keeps only CRITICAL, and a switch turns them off — so "no card" is
never proof that nothing happened. Since D-024 the app window is a destination of its
own: every severity gets a card in its bottom corner (LOW included), the same
do-not-disturb rule applies, the desktop switch does not touch them, and a crash report
raises one carrying its bug id. The in-app card is display too, and it is bounded (three
at a time) — the Guard screen, the incident list and `crash.list` are the record.

Two honest limits: a card is display, not authority (any same-token process can
raise one under our AUMID), and everything above is stored where a local
administrator can delete it (F-10).

## 9. What is not implemented at all

| Missing | Consequence |
|---|---|
| Kernel driver / minifilter | No pre-execution file blocking, no tamper protection for our own files (F-8, F-9). A read-level canary exists now (4.2), but only on a volume that keeps a last-access time — the copy says which, per volume |
| AMSI / script-content inspection | Script and in-memory payloads pass (section 2) |
| ETW-TI (threat-intelligence provider) | No kernel-level event telemetry beyond process creation |
| Memory scanning, unpacking, emulation | Packed/obfuscated malware is invisible to L4 |
| Office macro / document parsing | A macro-bearing document is not parsed: the pack tests a container by two magic bytes plus substrings, and a real `.docm` deflates those substrings out of any pattern's reach (measured, section 2). Closing it needs an OOXML/OLE macro extractor, not another rule |
| Network packet inspection (no Suricata/ET-Open) | No protocol-level detection, no beaconing heuristics |
| Resolver-level DNS filtering | The hosts sinkhole is bypassed by DoH and by IP-only traffic |
| Patch management | Vulnerabilities are reported, never fixed |
| Rollback of malicious changes | Killing a process tree does not undo what it already did |
| Self-defense / watchdog | Same-token code can kill the engine, edit `rules\`, or delete state (F-8) |
| Exploit protection (ASR, DEP/CFG policy) | Windows' defaults apply; MI CS does not manage them |

## 10. How these claims are checked

| Claim | Evidence |
|---|---|
| A hung external tool cannot hold the engine | `every_spawn_site_enforces_its_deadline` + the source scan for bare `Command::new(` |
| The helper cannot be turned into "run anything as SYSTEM" | validation tests + `scripts/verify-helper.ps1` |
| A failed collector never reads as "secure", and a merge keeps the score honest | audit tests (partial, merged, dropped sections) |
| Both pipe ACLs are what the threat model says | `scripts/verify-pipe-acl.ps1` (18 checks, both pipes) |
| A card means Windows recorded it | `scripts/verify-toast.ps1` reads the notification history back |
| A release loads its own rule packs instead of the built-in starter | `scripts/verify-release.ps1` |
| The guard's CPU/RAM cost | `scripts/measure-guard-cpu.ps1` — with the **shipped 6-rule starter pack loaded** (`-RealRules`, four 60 s windows, guard on minus `MICS_NO_GUARD=1`, engine unelevated so the 2 s poll loop is what runs): **0.156–0.521 % of one core, median 0.417 % = 0.0028–0.0093 % of this 56-thread machine, median 0.0074 %**; the guard-off half measured 0.000 % (below the 15.6 ms timer resolution), and the earlier 1.56 % / 3.52 % were the poll loop before two trims. `mics-engine benchmark` reports the engine process itself (`cpu_percent`, `cpu_percent_of_machine`, `budget_ok`) |
| The scanner resumes instead of restarting after a crash | the durable-job tests in `tests.rs` |
| A decoy *read* is detected, and what the decoys cover is a measurement | `scripts\verify-canary.ps1` (20 checks, PASS, 2026-11-05) against a real engine on a private pipe: a decoy MI CS had just written is settled silently inside the 90 s window (and the log records it), a pre-existing decoy raises HIGH `canary_read` with its size and SHA-256 unchanged, one appended byte raises CRITICAL `canary_triggered`, fifty metadata queries move no last-access time and raise nothing, and the engine's `read_detection` verdict equals the same measurement taken independently in PowerShell — including that the verdict names the decoys' own folder |
| Reading and writing are told apart in one place | the six `guard::canary::tests` cases over `classify` (untouched, read-only, read-that-also-writes, deleted, a volume without atime, and the probe leaving nothing behind) |
| What the shipped detection pack *catches*, not that it loads | `scripts\verify-rules.ps1` (**35 checks, PASS, 2026-11-05**) scans the 9 vectors in `engine\testdata\detection` with the pack a package ships and requires each one to be caught under the rule it was written for, the clean control to stay silent, and every declared rule to be either caught or named as unreachable — plus the same table as a unit test (`scanner::yara_engine::tests`, 4 cases), which is what found `Malicious_Macro_AutoOpen` comparing the zip magic against `"KP"`. `verify-release.ps1` runs the probe against the packaged pack with `-InPlace`, so the artifact's own `rules\` is what catches the vectors |
| MI CS' own WFP objects exist, and writing them needs an administrator | `firewall\wfp`'s 8 unit tests: the canonical name, four refusals in `validate`, one spec → one derived key, a known spec → the measured key `B051BA44-F5BF-454C-8D09-B8F1F8D5680E`, two layers → two version-4 GUIDs — and, live on this machine, `FwpmEngineOpen0` succeeding unelevated while `FwpmProviderAdd0` answers `0x80070005`, which the code names as `needs_elevation`. `scripts\verify-wfp.ps1` measured the live surface unelevated (**PASS, 7 checks, 3 skipped**): `fw.wfp.status` answered `sublayer=false filters=0 needs_elevation=true` with the running helper's own refusal as `detail`. **Measured elevated 2026-11-09** against the fixed debug build (`scripts\verify-wfp.ps1` **16 passed, 2 skipped, 0 failed**, D-045): a real persistent filter, its key, its action read back out of Windows' own `netsh wfp show filters` as `FWP_ACTION_BLOCK` (and explicitly not a permit), its conditions (the application path, remote port 65001, protocol 6) in `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, the count going up and the undo taking it out of both our list and Windows' state. The first elevated run of 2026-11-08 produced D-045 instead: `for_each_ours` enumerated with a zero `layerKey` and every call failed `0x80320004`. **Still not measured:** the block's *effect* on a connection, its survival across a reboot, and our sublayer's weight against a built-in permit rule |
| The connection list is Windows' own table, and what a row offers to block is exact | `windows\conns`'s 6 unit tests hold the parts a test can: a spec is offered only with a peer port and an image path, the note is one the helper's validator accepts, and both address families format the way Windows writes them. `scripts\verify-connections.ps1` (new, D-043) measured the live list unelevated against the debug engine: **PASS, 23 checks, 0 skipped, 0 failed** — 490 rows, every row carrying path/protocol/peer port and a block decision, 139 rows offering a spec whose app path, port and protocol match the row (and whose file exists), no row with an empty peer port offering one, Windows agreeing with every owner it names (343 rows had already vanished, 0 contradictions), IPv6 and UDP rows present, and the spec handed to `fw.wfp.block` refused **with a reason** and `fw.wfp.status` unchanged afterwards. **Measured elevated 2026-11-09** (D-043): **24 checks passed, 0 skipped, 0 failed** — 462 rows walked, 147 offering a block and 315 not, every offered spec matching its row and its file, and the write branch taken for a **real row's spec**: accepted by `fw.wfp.block`, the BFE holding one more filter, `fw.wfp.unblock` removing it and the machine back where it started. **Still not measured:** that a row's connection is actually refused once its filter is in — the probe never opens a connection through it |
