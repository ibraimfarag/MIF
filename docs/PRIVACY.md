# Privacy policy — MI CS

**Effective 2026-11-07 · version 1 · applies to every build of MI CS**: the portable
ZIP, the per-machine installer, and any package distributed through the Microsoft
Store.

## In one line

MI CS has **no accounts, no telemetry and no cloud**. Everything it learns about this
computer stays on this computer, except the short list in §3: two public threat feeds
it fetches every six hours by default, one vulnerability lookup you start yourself, a
payload-free connectivity probe, and an update check that has no default address.

## 1. Who is responsible

The MI CS project, published by its maintainer at
<https://github.com/ibraimfarag/MIF>. There is no company behind it, no data
controller beyond the person who publishes the code, and nothing is sold, rented or
shared. Contact:

- ordinary questions and bug reports: <https://github.com/ibraimfarag/MIF/issues>
- security reports, privately: <https://github.com/ibraimfarag/MIF/security/advisories/new>

## 2. What never leaves this computer

- **No telemetry, analytics, crash reporting or "product improvement".** `AGENTS.md`
  rule 8 makes this structural: a new destination is a decision in
  `docs/DECISIONS.md`, not a detail that can slip into a commit. Crash reporting is
  **not implemented** (it is an open item, and it needs a decision before it exists).
- **No account, sign-in, licence key or device identifier.** Nothing to sign up for,
  and no identifier to send.
- **No file, hash, process name, path or scan result is ever sent for reputation.**
  There is no VirusTotal client and no key for one (D-019), so that destination does
  not exist in the code.
- **No cloud backend.** MI CS works fully offline: everything except the optional
  feeds in §3 is local.

## 3. The complete list of outbound traffic

| Destination | What is sent | When |
|---|---|---|
| `raw.githubusercontent.com` (the StevenBlack hosts list, MIT) | a GET; nothing machine-specific | intel sync — **on by default, every 6 hours** |
| `cisa.gov` (Known Exploited Vulnerabilities feed) | a GET | intel sync — **on by default, every 6 hours** |
| `services.nvd.nist.gov` | the installed product identifiers being looked up (CPE/keyword), and an API key if you gave one | a vulnerability scan you start |
| `dns.google` and `1.1.1.1` | a payload-free HEAD/GET probe | the "is this machine online?" check, cached 30 s |
| an LM Studio endpoint (default `http://127.0.0.1:1234`) | the finding text you ask it to explain | only when you press *explain*; loopback by default, so nothing leaves the machine |
| an update-manifest URL | a GET | only if you configure one — **there is no default address today** |

The two feed addresses are built into the engine (`engine/src/sync/mod.rs`), so a
fresh install does fetch them; `sync_interval_hours` sets the interval (6 by default)
and each address can be overridden in the settings file or by the environment
variables the engine documents. The connectivity probe and the NVD lookup are not on a
timer: one runs when the app asks whether the machine is online, the other only when
you start a scan.

TLS uses `rustls` with the Mozilla root store, so an enterprise TLS-inspecting proxy
breaks the feeds **by design** (no corporate CA is trusted). `settings.rs` accepts
`https://` everywhere and `http://` only for loopback. Nothing on this list is hidden:
the same table, with the code behind it, is `docs/THREAT-MODEL.md` §B6.

**What the destinations can see:** the intel feeds see this machine's IP address and
the query, under their own policies (NIST, CISA, GitHub). The NVD lookup is the one
case where **information about this computer** leaves it — the list of products being
checked — and that sentence is the reason this policy has to exist.

## 4. What is stored on this computer, and where

State lives in one directory: `%PROGRAMDATA%\MICS` (machine-wide), or
`%LOCALAPPDATA%\MICS` when that is not writable by the current user; the
`MICS_DATA_DIR` environment variable overrides both. Three paths are resolved from
`%PROGRAMDATA%` on purpose rather than from that directory — the audit log, the
machine-wide blocklists and the hardening snapshots — so the service and the interface
always read and write the same files.

| Path | What |
|---|---|
| `settings.json` | your configuration — no secrets |
| `secrets.dat` | the optional NVD and IOC-feed API keys, encrypted with **DPAPI at machine scope** (any account on this computer can decrypt them: that is the honest limit recorded as F-5) |
| `logs\` | the engine's own logs |
| `Quarantine\` | files you chose to quarantine |
| `%PROGRAMDATA%\MICS\logs\priv.log` | the privileged helper's audit log — one line per privileged operation, written **before** it runs |
| `%PROGRAMDATA%\MICS\blocklists` and `\hardening` | downloaded lists, and the snapshots taken before hardening changes |
| your Reports folder (default `Documents\MICS-Reports`) | the Markdown security reports you generate |

Beyond that, Windows keeps its own records — service registration, event log entries,
firewall rules — because MI CS asks Windows to do those things, not because MI CS
reports anything.

## 5. What a security tool can see, and why that is local

To do its job MI CS reads process lists, network connections, startup entries,
installed software, firewall rules, scheduled tasks and file metadata. That is the
product. All of it is read locally, kept locally, and never uploaded; the only derived
information that can leave is the NVD query in §3 and text you explicitly send to a
local model.

## 6. Privileged changes

Firewall rules, the hosts file and hardening changes are made by a **LocalSystem
service** through a closed operation set. Each operation is written to
`logs\priv.log` **before** it runs, and hardening snapshots the previous state first.
The full list is `docs/PRIVILEGED-OPS.md`; the reversibility story is
`docs/PROTECTION-MATRIX.md`.

## 7. Installing from the Microsoft Store

If you install MI CS from the Microsoft Store, Microsoft handles the download,
installation and updates, and its own telemetry is governed by the
[Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement) — MI CS
itself still does none of the things in §2. Microsoft Store policy 10.5.1 requires
this document to be published at a URL, and the Store listing points here.

## 8. Children

No accounts, no advertising, no data collection of any kind. Nothing is knowingly
collected from anyone, and there is nothing to collect it with.

## 9. Retention and deletion

Nothing is retained anywhere except this computer. Uninstalling removes the program,
the service, the shortcuts and the registry row, and **deliberately keeps the state
folder** so your settings, reports and quarantine survive a reinstall. To remove
everything, delete `%PROGRAMDATA%\MICS` (or `%LOCALAPPDATA%\MICS`) and the Reports
folder — MI CS has no copy, because it has no server.

## 10. Changes to this policy

Every change is a commit in this repository, and the effective date at the top changes
whenever the substance does. If a future feature would send anything that is not in
§3, this file is updated **in the same commit** as that feature — a rule, not a
promise (`AGENTS.md` rule 8).