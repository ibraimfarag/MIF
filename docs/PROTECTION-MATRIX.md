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
correlation), **L4 File Engines** (scanner), **L5 Mind** (incident correlation and
the optional local-LLM assistant). The vulnerability, posture, Defender and
delivery rows below are cross-cutting work that does not sit inside a single layer,
so they keep their own names. This sheet's section numbers (§2 scanner, §3 network,
§4 guard) are stable on purpose — other documents cite them.

## 1. The layers at a glance

| Layer | Kind | Runs in | Elevation | Detects | Blocks |
|---|---|---|---|---|---|
| L4 scanner | on-demand static analysis of files | engine job | no | known hashes (IOC feed) + YARA rules, over the tree you point it at | only through quarantine (the file is moved); never pre-execution |
| L2 IDS | DNS-name sinkhole in the hosts file | helper applies, every app consumes | yes (helper) | nothing — it is a pure block | listed domains resolve to `0.0.0.0` |
| L1 firewall | Windows Firewall API (`INetFwPolicy2`) rules | helper | yes (helper) | nothing | outbound default-deny, per-rule allow/block (program/port/IP), one firewall rule per blocked country |
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
  engine is running (the logon entry keeps it running). A scheduled run is
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
  curated, and `verify-release.ps1` checks that they *load*, not what they catch.

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
- **The process hash is not checked.** The ETW callback loads the IOC hash list and
  then does nothing with it — hashing every process start was judged too hot
  (`guard/etw.rs`); the scanner owns the hash dimension.
- **Starter content.** Six bundled rules. The shipped pack demonstrates the
  mechanism; it is not a behavioural signature database.

### 4.2 Canaries (`guard/canary.rs`)

**Sees.** mtime and size of the decoy files (three defaults under Documents and
Desktop, configurable).
**Detects.** A CRITICAL event when a decoy's mtime/size changes.
**Blocks.** Nothing.

**Misses.** A **read** leaves mtime and size untouched, and NTFS last-access
updates are off by default, so a stealer that only reads a decoy is invisible. The
copy no longer hides that: the event, the card title and the incident all say
*modified*, and nothing claims "accessed". Decoys are also files in obvious places:
they catch mass encryption and careless hands, not a targeted actor.

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
| Kernel driver / minifilter | No pre-execution file blocking, no read-level canary, no tamper protection for our own files (F-8, F-9) |
| AMSI / script-content inspection | Script and in-memory payloads pass (section 2) |
| ETW-TI (threat-intelligence provider) | No kernel-level event telemetry beyond process creation |
| Memory scanning, unpacking, emulation | Packed/obfuscated malware is invisible to L4 |
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
