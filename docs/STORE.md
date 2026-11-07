# The Store submission, in the order it has to happen

This is the operational playbook for route A in [`SIGNING.md`](SIGNING.md) §3 — the free
Microsoft Store re-signing. The *why* lives there and in **D-036** (the two free routes),
**D-037** (a third packaging, not a replacement) and **D-038** (the shape submitted first
declares no service, so it needs no administrator and no restricted-capability approval).
This file is only what to do, in order, and how to know each step worked.

State on 2026-11-07: the artifact exists and is measured
(`scripts\make-msix.ps1 -ServiceMode None` → 75 files, 22.11 MB, `runFullTrust` alone,
registers unelevated in developer mode). Two things are missing and neither is code: the
developer account, and Microsoft's certification.

## 0. What only the owner can do

1. **Create the free individual developer account** at
   <https://storedeveloper.microsoft.com>. It needs a Microsoft account and identity
   verification (a government ID and a selfie/liveness check). There is no fee: the $19
   individual registration fee is waived, and Egypt is in the supported list (researched
   2026-11-07, `SIGNING.md` §3).
2. **Reserve the product name.** Partner Center then assigns four values, and the first
   two are not free-form:
   - **Identity Name** — goes into `Identity/@Name`.
   - **Publisher** (a distinguished name such as `CN=…, O=…, C=…`) — goes into
     `Identity/@Publisher`, and it **must equal the subject of the certificate that signs
     the package**. For a Store submission that certificate is Microsoft's, issued against
     the identity Partner Center assigns, so the value has to be copied from Partner
     Center, never invented.
   - **Publisher display name** — the name users see under "Published by".
   - **Store ID** — the 12-character id in the Store URL.

## 1. Build the package for that identity

```powershell
.\scripts\make-msix.ps1 -ServiceMode None `
    -Identity "<Identity Name from Partner Center>" `
    -Publisher "<Publisher DN from Partner Center>" `
    -Version 0.1.0.0
```

Then check, before uploading: makeappx printed `Package creation succeeded`, the printed
`sha256` was recorded somewhere durable, and unpacking the `.msix` shows exactly one
capability (`runFullTrust`). **Do not sign it** — Microsoft signs the submitted package, and
a self-signed signature would only have to be stripped. `-SelfSigned` exists for local
install tests, not for a submission.

Two things the script refuses on purpose, because Windows does: a three-part version, and a
publisher that does not match the certificate in `-SelfSigned` mode. In submission mode the
match to keep is the one above.

## 2. Listing copy to paste

Partner Center enforces its own character limits; this text is deliberately short enough for
all of them, and written to be true rather than persuasive.

**Short description**

> A defensive security tool for Windows: scans with YARA rules, blocks malicious hosts,
> and shows what it changed.

**Description**

> MI CS scans selected folders with YARA rules, watches for suspicious behaviour, and — only
> when you ask it to — protects the hosts file, adds firewall rules and turns off a few
> Windows settings that malware relies on.
>
> Every privileged change is written to an audit log **before** it happens, and every change
> can be undone from the same screen. The app needs no account, sends no telemetry, and works
> offline: the only outbound requests are the threat-intelligence feeds you can see and
> configure.
>
> To change firewall or hosts settings, the app asks once for permission to install a small
> privileged helper; scanning, detection and reporting work without it.

**What's new in this version**

> First Store release: scanner, host protection, firewall rules, hardening checks and the
> evidence report.

**Links**

- Privacy policy: `https://github.com/ibraimfarag/MIF/blob/main/docs/PRIVACY.md`
- Support: `https://github.com/ibraimfarag/MIF/issues`
- Website: `https://github.com/ibraimfarag/MIF`

The privacy policy is not optional — Store policy 10.5.1 requires a reachable one, and
`docs/PRIVACY.md` was written for exactly this (`SIGNING.md` §3).

## 3. Notes for certification (there is a box for it)

Paste this, adjusted only for the assigned identity. Specific beats vague: a reviewer who
can see what the app does and what it does not do has nothing to guess.

> MI CS is a defensive security tool for Windows. This package declares **no service** and
> requests one capability, `runFullTrust`. Privileged work is done by a separate helper
> service (`MICSHelper`, running as LocalSystem) that the user installs with **one UAC
> prompt** from Settings → Engine → Install helper — the app never installs it silently, and
> nothing privileged works until the user does.
>
> The helper runs a closed operation set: write the hosts file inside its own marked section,
> add/remove firewall rules whose names it owns, and apply a few hardening toggles with a
> snapshot taken before each change. Every operation is appended to
> `%PROGRAMDATA%\MICS\logs\priv.log` **before** it runs, so a crash cannot lose the record.
> All of it can be undone from the app.
>
> The app never disables Windows Defender, never disables SmartScreen, never adds a
> certificate to a trust store, and installs no driver. No telemetry, no account, no cloud:
> the only outbound requests are the intel feeds the user can see and configure (StevenBlack
> hosts, CISA KEV, NVD) and a 30-second connectivity probe to `dns.google`/`1.1.1.1`.
>
> Uninstalling the package leaves the state folder in place on purpose (quarantined files and
> the audit log); the helper is removable from Settings → Engine → Uninstall helper.
> Privacy policy: https://github.com/ibraimfarag/MIF/blob/main/docs/PRIVACY.md

## 4. Screenshots

Four, at the largest window size, on a machine that is not yours:

1. the dashboard with a completed scan;
2. a finding with its severity and the evidence panel;
3. the before/after view of a firewall or hosts change;
4. Settings → Engine, showing the helper's state.

Do not show other applications' names, user names, or paths from a real machine. Partner
Center states its own image limits; the window at its largest size is comfortably inside
them.

## 5. The age-rating questionnaire (IARC)

Answer it as the account holder; it cannot be delegated. The honest answers for this build:
no user-generated content, no ads, no in-app purchases, no location, no personal data
collection, no violence or gambling. A security tool that *describes* malware families is
still not "content" in the questionnaire's sense, but if a screenshot shows a malware family
name, answer accordingly.

## 6. After certification — the part that proves something

Microsoft re-signs the package after certification (`SIGNING.md` §3), and **that** is the
moment the project's oldest claim changes: the download becomes "signed by Microsoft", not
"unknown publisher".

Then measure, on a clean VM as a standard user, because none of this has been observed yet:

1. install from the Store — the expectation is a per-user install with **no UAC prompt**,
   because the package declares no service (D-038);
2. run a scan (works without the helper);
3. install the helper (one UAC prompt) and run one hosts or firewall change;
4. check the change **from outside the app** — `netsh advfirewall firewall show rule` and the
   real `C:\Windows\System32\drivers\etc\hosts` — and confirm `%PROGRAMDATA%\MICS\logs\priv.log`
   has the entry;
5. update the package to a new version and confirm what `SIGNING.md` §3 predicts: the
   helper's registration now points at the folder the update replaced, `helper-status`
   reports `stale`, and installing the helper again fixes it.

Step 5 is the one that was never testable before, and it is why the engine learned to report
`stale` at all.

## 7. What this submission deliberately leaves out

- **ARM64** — no engine target has been built for it yet (`ROADMAP.md`).
- **The `Packaged` shape** (helper inside the package) — it needs an administrator to install
  and two restricted capabilities Microsoft approves per app. It stays the full-product shape
  for a later submission or a direct download (D-037, D-038).
- **The MSI/EXE path** — still needs the account's own CA certificate
  (`SIGNING.md` §2), which is the thing this whole route exists to avoid.
- **Publishing a draft release** — the GitHub `v0.1.0` draft is a separate decision (D-031) and
  does not wait for the Store.

## 8. If certification is refused

Two refusals are possible and they are different:

- **The product category or the security-tool policy** (10.2.x). The fallback already written
  in `SIGNING.md` §3 applies: a read-only edition (scan, canary, guard, IDS reporting, no
  privileged writes) with the full product staying on GitHub. It needs a manifest change, not
  a new product.
- **The package itself** (identity, publisher, capabilities). Fix and resubmit; certification
  took about 2.37 days in the published averages, so a round trip is a working week.

Route B (OSS**ign**, ~2027-04-27) is unaffected either way: it signs the GitHub binaries,
not the Store package.