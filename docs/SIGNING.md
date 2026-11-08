# Signing MI CS without buying anything

Written **2026-11-07**. `docs/COST.md` §2 concluded that a CA-issued certificate is
"the one purchase"; this file is the re-research that follows from the harder
constraint — *the project spends nothing, ever, on anything* — and it changes that
conclusion: **two free routes exist, and one of them is available today.** Every
claim below names the page it was read from and the day it was read, because CA
prices and programme rules move and a stale rule is worse than no rule.

## 1. "Trusted" is three different things

| What a user meets | Who decides it | What it shows | Changed by money? |
|---|---|---|---|
| The Authenticode chain builds | the CA, via Windows' Trusted Root Program | `Unknown publisher` → a publisher name | yes — **unless Microsoft or OSSign signs for you, which is free** |
| SmartScreen reputation ("Windows protected your PC") | Microsoft, per signing identity and download history | the blue wall before the first run | it follows the row above; it is not bought directly |
| Our own manifest self-check (`status.integrity`) | us | `68 listed file(s) match` | already done (D-025), needs nobody's permission |

The certificate row is the one that used to look unbuyable. It is not.

### How the first row is checked, mechanically (measured 2026-11-07)

Whether a stranger's Windows would trust a given file is now a question with an exit code
instead of an opinion: `scripts\verify-trust.ps1`.

```powershell
.\scripts\verify-trust.ps1 -SelfTest                          # prove the instrument
.\scripts\verify-trust.ps1 -Path dist\MICS-0.1.0.0-x64.msix   # judge an artifact
```

Exit code **0 means yes** — the signer was issued by a CA and the chain ends in a root in this
machine's machine-wide store, which is the store AppX and installers read. Everything else
(unsigned, self-signed, a chain that stops at a root nobody trusts, or a file that no longer
matches its own signature) exits non-zero with the reason printed.

It exists because the obvious check is a trap: on this machine `Get-AuthenticodeSignature`
reports **`Valid`** for the engine signed with our own self-signed certificate, because that
certificate sits in the user's trust stores. `Status` alone is therefore never the answer —
the script separates the cases by the certificate's issuer, the chain, and which root store
the chain ends in, and says so out loud when a locally-`Valid` file is judged untrusted.

Both controls, run 2026-11-07, are in `-SelfTest` and both belong there:

| Control | Result |
|---|---|
| this repository's own engine (self-signed) | `self-signed`, exit 1 — *and* the raw status on this machine is `Valid`, which is exactly the trap |
| `C:\Windows\System32\kernel32.dll` (Microsoft) | `public-ca`, exit 0 — chain of 3 to `Microsoft Root Certificate Authority 2010` in `LocalMachine\Root`, timestamped, 364-day validity, inside the 460-day limit |

It reports the release requirements separately from the verdict, because a certificate can be
publicly trusted and still make a bad release signature: the code-signing EKU, whether the
signature carries a timestamp (so it outlives the certificate), and — for certificates issued
on or after 2026-03-01 — the CA/Browser Forum's 460-day validity limit from §5.

Three limits, stated rather than hidden. It never touches the network, so **revocation is not
checked**. It cannot see where the private key lives, so the hardware-module requirement is out
of reach. And for an AppX/MSIX it reads `signtool verify /pa /v`, because .NET's `SignedCms`
refuses the encoding AppX uses (`ASN1 bad tag value met`, measured 2026-11-07); without the
Windows SDK it reports the package as **unjudged**, never as trusted. An unsigned package is
reported as unsigned, and a package signed with our test certificate is reported `self-signed`
even though `make-msix.ps1` prints `trusted for install (CurrentUser\TrustedPeople): True` —
another local-trust signal that is not the question.

## 2. Every route, as read on 2026-11-07

| Route | Cost | Whose name the user sees | Ships where | Status for MI CS |
|---|---|---|---|---|
| **Microsoft Store, MSIX** — Store re-signs after certification | **free** (registration fee waived, "nearly 200 markets worldwide") | the developer's Store identity | the Store | **open now**; needs MSIX packaging + two restricted capabilities approved |
| **OSSign** — certificate is OSSign's, signing is keyless OIDC | **free** | `OSSign` (the project is verified, not the person) | our GitHub release | **blocked by age**: "project ≥ 6 months"; the repo was created 2026-10-27, so ~**2027-04-27**; their applications were *suspended* as of 2026-09 |
| **SignPath Foundation** | free | `SignPath Foundation` | our GitHub release | **closed** — its code of conduct excludes this product category (verbatim in §6), and it separately requires "a certain verifiable reputation" |
| **Certum "Open Source Code Signing"** | €49 cloud / €69 with card+reader | `Open Source Developer <name>` | our GitHub release | the cheapest *real* certificate; excluded by the no-money rule, but a donation makes it a drop-in (D-034: two secrets, no code change) |
| **Azure Artifact Signing** (was Trusted Signing) | ~$9.99/month | our name | our GitHub release | **closed twice over**: it costs money, and Public Trust is limited to organizations in the US/Canada/EU/UK/AU/NZ/JP/KR/SG/CH/NO/IL — individual developers must be in the **US or Canada**. Egypt is not on either list |
| **Store MSI/EXE download-URL path** | free to submit, but the installer must already be signed | — | the Store | **not a signing route**: policy 10.2.9 requires the binary to chain to a Microsoft Trusted Root Program CA, i.e. our own bought certificate |
| **Sigstore / cosign** | free | nothing Windows reads | anywhere | no effect on UAC or SmartScreen — Windows does not consult Fulcio |
| **Self-signed** (`make-release.ps1 -Sign`) | free | `MI CS Code Signing` **only on machines told to trust it** | our GitHub release | what we do today; proves non-tampering, not identity |

## 3. Route A — the Microsoft Store, which is free and available now

Microsoft's own comparison page says it in one line (read 2026-11-07):

> If you publish your app as an **MSIX package** through the Microsoft Store, code
> signing is **free** and handled for you automatically — Microsoft re-signs the
> package after certification and you don't need to purchase or manage a
> certificate.
> — <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options>

Its own table for that row: cost **Free**, availability **Worldwide**, SmartScreen
**"No warnings"**. The same page's MSI/EXE row is the trap: there the *publisher*
must sign with a Trusted Root CA certificate, which is the thing we cannot buy.

The developer account is free as well (page updated 2026-04-17, read 2026-11-07):

> The new onboarding process is now live, allowing individual developers to publish
> apps to the Microsoft Store **without any onboarding fees**. This experience is
> available in **nearly 200 markets worldwide**. … **No registration fee** — the $19
> registration fee is waived in the new flow. … **ID-based verification** — verify
> your identity using a government-issued ID and selfie.
> — <https://learn.microsoft.com/en-us/windows/apps/publish/whats-new-individual-developer>

So there is no payment step and no credit card: a government ID and a selfie, and
the Store's certificate does the signing. Egypt is inside "nearly 200 markets"; the
registration page lists no excluded region.

### What the Store will require from us

Read from the Store Policies, document version **7.20** (published 2026-09-15,
effective 2026-10-22; read 2026-11-07,
<https://learn.microsoft.com/en-us/windows/apps/publish/store-policies>):

| Requirement | Where MI CS stands |
|---|---|
| Certificate acquisition, "unless provided by Microsoft Store signing" (10.2) | this is the free part |
| Product must uninstall cleanly, and remove what it installed (10.2.7) | already measured on 2026-11-07: product, service, shortcuts and registry row all go (the `%PROGRAMDATA%\MICS` state folder is kept on purpose and will be disclosed in the listing) |
| Change Windows settings only through supported methods **and with user consent** (10.2.8) | already true: firewall and hosts changes happen only from an explicit user action in the UI, through documented APIs, and land in `logs\priv.log` |
| A **privacy policy** (10.5.1 names Desktop Bridge and Win32 products) | **written 2026-11-07**: [`docs/PRIVACY.md`](PRIVACY.md) — short and true, because MI CS ships no telemetry (rule 8) — and it is written from `docs/THREAT-MODEL.md` §B6 rather than from marketing. The listing must point at its public URL: <https://github.com/ibraimfarag/MIF/blob/main/docs/PRIVACY.md> |
| A support contact that a stranger can reach | `SECURITY.md` now names both a public issues page and a private advisory channel instead of "contact the maintainers", which was not reachable by anyone outside |
| An IARC age rating (11.11.1) | missing; it is a questionnaire, not a review |
| Individual account only if a consumer would not read the publisher name as a business (10.14) | a naming decision for the user, not a code change |

Average certification time is quoted on the same page as **2.37 days**, so this is
not a months-long path.

### The service is the real question

MI CS's privileged half is a **LocalSystem service**, and MSIX can express that —
the schema is explicit that a packaged service may run as
`localSystem`/`localService`/`networkService` with `StartupType=auto`
(<https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop6-service>,
read 2026-11-07):

```xml
<desktop6:Extension Category="windows.service">
  <desktop6:Service Name="MICSHelper" StartupType="auto"
                   StartAccount="localSystem" Arguments="helper-service" />
</desktop6:Extension>
```

But a LocalSystem service needs the **restricted capabilities**
`packagedServices` **and** `localSystemServices`, and restricted capabilities are
approved per app by Microsoft, not granted by the manifest alone (third-party
build tooling documents the pair and the warning that they are "only needed if your
MSIX project is configured with" the service extension; e.g. Revenera's build
warning 9583, read 2026-11-07). A published how-to from a developer who went
through Store certification requests only `packagedServices` for a service running
as **Local Service** — the milder account — which is exactly the distinction that
matters here: Local Service cannot configure the firewall or rewrite `hosts`.

### What is measured so far (2026-11-07, later the same day)

The first unknown got its **local** half answered by building the package rather than
arguing about it:

- **The artifact exists.** `installer/msix/AppxManifest.xml` is the manifest template
  and `scripts/make-msix.ps1` stages `dist\MICS-portable`, generates the four logo
  assets from `assets\icons\Desktop.png`, substitutes the identity/publisher/version
  (and fails hard if a token survives), packs and optionally signs.
- **Measured numbers.** makeappx 10.0.26100.0 packed **75 payload files** (the 70
  shipped files, the four generated logos and the manifest) into **22.11 MB** in
  **4.3 s**: `sha256 D40AAE90...`. The ZIP holds **79 entries**, including
  `[Content_Types].xml`, `AppxBlockMap.xml` and `AppxSignature.p7x` after signing.
- **The schema accepts the service.** makeappx validated the manifest with
  `desktop6:Service Name="MICSHelper" StartupType="auto" StartAccount="localSystem"
  Arguments="helper-service"` and both restricted capabilities
  (`packagedServices`, `localSystemServices`) and packed it without a warning. So
  **unknown 1's local half is closed**: the declaration is legal and buildable.
  Microsoft's per-app *approval* during certification is still open, and nothing in
  this repository can measure it.
- **The install is blocked twice, and both blocks are measured.**
  1. **Trust.** A signed self-signed package is refused with **0x800B0109** ("the
     root certificate of the signature … must be trusted"). Adding our test
     certificate to the *user's* root store does **not** clear it: AppX deployment
     validates machine trust, so only a machine-wide root (administrator) or a
     certificate that already chains to a public root helps. The Store route does
     not have this problem, because Microsoft's signature chains publicly.
  2. **The service needs an administrator, by Windows' own rule.** With developer
     mode already on (`AllowDevelopmentWithoutDevLicense = 1`, measured),
     registering the **unsigned** staged folder — the path a signature cannot
     influence — fails with **0x80073D28: "Administrator privileges required to
     install packaged service"**. So the manifest is not the problem and no
     manifest change can remove it: **any package that declares a service needs an
     administrator to install**. That is unknown 1's OS half, closed, and it
     carries a product consequence worth writing into the Store listing: the Store
     edition will need an administrator (or the Store's own elevated install), just
     as the NSIS installer needs its single UAC prompt (D-026).
- **So unknown 2 stays unmeasured, but the documentation is now on our side** — see
  the container section below, which narrows the risk to the one thing only an
  administrator's install can decide.
- **Two measured facts that are easy to get wrong.** `Get-AuthenticodeSignature`
  reports `UnknownError` for a *correctly signed* MSIX — the AppX signature is not a
  PE Authenticode signature, so signtool and the deployment API are the tools that
  read it. And adding a certificate to `CurrentUser\Root`: `certutil -user -addstore
  -f Root <file.cer>` completes silently, while the .NET `X509Store` path raises the
  modal **"Security Warning"** that hangs an unattended run (§8 traps 29 and 30 in
  `docs/TODO.md`).

### Two shapes of the same package, and the shape that needs no administrator (measured 2026-11-07)

Everything above is a property of the *manifest*, and this product has two legal
manifest shapes — `scripts\make-msix.ps1 -ServiceMode Packaged|None`:

| | `Packaged` (default) | `None` |
|---|---|---|
| `MICSHelper` | declared: `desktop6:Service`, LocalSystem, auto | not in the package at all |
| Capabilities | `runFullTrust`, `packagedServices`, `localSystemServices` | `runFullTrust` |
| An administrator to install | **required** — 0x80073D28 | **not required** — measured |
| A restricted capability Microsoft must approve | two of them | none |
| What the user gets | the whole product from the Store | the app; privileged work needs a helper installed outside the package — the NSIS installer, or `mics-engine.exe install-helper`, one UAC prompt (D-026) |
| The container questions above | apply to the packaged service | do not arise: the helper runs outside the container, exactly as D-026 already has it |

Measured as an A/B on this machine, minutes apart, against the same staged folder and
the same call — `Add-AppxPackage -Register build\msix-stage\AppxManifest.xml`, developer
mode already on:

- `Packaged` → **0x80073D28**, refused;
- `None` → **registered with no elevation at all**, `Get-AppxPackage` reporting
  `MICS.Desktop 0.1.0.0`, `Status Ok`, `IsDevelopmentMode True`, and one declared
  capability (`runFullTrust`) — then removed cleanly, with no service and no leftover.

That is why **`None` is the shape to submit first** (D-038): it takes the packaged
service — and with it the capability approval and the administrator requirement, the two
things that could have sunk the submission — off the critical path, in exchange for a
first-use UAC prompt the project already ships and documents. `Packaged` stays the shape
for the full product once that first submission is through, and for the direct download.

**What the `None` shape still owes, written down before it is discovered in the field.**
The helper's `binPath` is whichever path the engine ran from — `install-helper` rewrites
it (`engine/src/privileged/service.rs`) — and a package's install location carries its
version, so the helper a Store-edition user installs points into a folder that the next
package update does not keep. The `None` shape therefore has to expect a **re-registration
after every update** (one UAC prompt), or install the helper to a stable location the way
the NSIS installer does. The detection half is closed as of 2026-11-07: `helper-status`
reports `stale` and `bin_path` (`docs/PRIVILEGED-OPS.md`), and the failure message names
the path that is gone and the one fix that works instead of blaming the caller's integrity.
What stays open is that nothing re-registers on its own — the UI shows no badge, so the
user meets it as a failed fix with a clear message — and the stable-location alternative
is still just an option. That is the price of keeping the service out of the package.

### The packaged app, run for real (measured 2026-11-07)

Until now the `None` shape had been **registered** but never **run**. It was run, and the app
half works:

| | |
|---|---|
| how | `scripts\make-msix.ps1 -ServiceMode None -StageDir "$env:LOCALAPPDATA\mics-msix-stage"`, `Add-AppxPackage -Register …\AppxManifest.xml`, then launched through the shell (`shell:AppsFolder\MICS.Desktop_kbrfzxjj0fgk0!MICS`) |
| processes | `mics_app` and, spawned by it, `mics-engine` — **both from the staged package folder** |
| IPC | `\\.\pipe\mics_engine` came up; the engine logged the app's 15-second `ping`/`Ping received` heartbeat and answered `sync.status` |
| self-check | `package integrity: ok - 68 file(s) hash as the manifest says (package 0.1.0)` — the manifest resource and the file hashes are readable **from inside the container** |
| guard | `Guard loop started`, 6 guard rules loaded from the package folder, `Canary watchers armed over 3 decoy file(s)`; `ETW unavailable … Access is denied` and it fell back, which is what an unelevated process should do |
| state | `data=C:\Users\…\AppData\Local\MICS` — the **real** profile path, not a package-private store; `%PROGRAMDATA%\MICS` was not touched (the packaged copy has no elevated install and no installer account) |
| after | package removed, stage deleted, no process and no pipe left behind |

Two limits on that table, stated before anyone reads more into it. First, this was a
**development-mode loose registration**, so it describes the shape's behaviour rather than
promising what a Store-signed install does; the virtualization line above is exactly the kind
of thing to re-measure after certification (`STORE.md` §6). Second, it settles the app half
only — **the helper across the container is still unmeasured**, because installing one needs
an administrator.

Where the package is staged decides whether any of this works, and the failure is silent:
staged inside this workspace (`H:\`, which carries `Mandatory Label\Low Mandatory Level`), the
same package launched, showed nothing, and never started its engine. The portable copy failed
identically, which is how the folder — not the package — was identified as the cause. It is
written up as trap 33 and as a §7 row in [`docs/TODO.md`](TODO.md).

The step-by-step submission playbook — what Partner Center assigns, the listing copy, the
certification notes, and the measurement that follows certification — is
[`docs/STORE.md`](STORE.md). Two smaller facts from the same measurements: Windows refuses
the *unsigned* install path for us — `Add-AppxPackage -AllowUnsigned` exists on this
machine but answers **0x80073D2C**, "its publisher is not in the unsigned namespace", for
both our real subject and a bare `CN=MI CS (dev)` (the publisher has to carry a special OID
marking it unsigned) — and developer-mode *registration* of the staged folder, which is
what the A/B above used, needs no publisher trick, no signature and no administrator.

**What is not verified, and must be measured before anyone promises this route
works:**

1. that Microsoft approves `packagedServices` + `localSystemServices` for a
   defensive security tool — **the local half is closed** (makeappx accepts the
   declaration, and Windows requires an administrator for it: 0x80073D28, measured
   below); Microsoft's per-app approval is the half nobody here can measure — and the
   `None` shape does not need it at all;
2. that a service inside the MSIX container can still write the real
   `C:\Windows\System32\drivers\etc\hosts` and drive the Windows Firewall COM API
   and `netsh` — container redirection is the risk, and our whole privileged op set
   (firewall/hosts/hardening) rides on it. **The documented model says it can**, for
   the reasons in "The container, documented" below; the empirical test is still the
   only proof, and it needs an administrator. In the `None` shape the hosts half of
   this question does not arise — the helper writes from outside the container — and
   what is left to show is only that a packaged app can reach the helper's pipe;
3. that a Store listing for a tool whose job is changing firewall and hosts
   settings passes certification at all.

The honest fallback if (2) fails is a **read-only Store edition** (scan, canary,
guard, IDS reporting — no privileged writes) signed by Microsoft for free, with the
full product staying on GitHub. If (1) fails and (2) has not been tested, this route
closes and OSSign becomes the plan.

### The container, documented (read 2026-11-07)

An MSIX container is not a virtual machine: Windows gives a packaged app a
*virtualized view* of the file system and registry, and how much is virtualized
depends on the trust level the manifest declares. That is why `AppxManifest.xml` now
states it explicitly — `uap10:TrustLevel="mediumIL"` (a full-trust app) and
`uap10:RuntimeBehavior="packagedClassicApp"` (a packaged Win32 app, not an
AppContainer app) — instead of leaving it implied by `EntryPoint`, and why makeappx
accepting those attributes (measured: the re-packed manifest carries both, 75 files,
22.11 MB, 3.9 s) matters. Microsoft's own page divides the behaviour like this
(<https://learn.microsoft.com/en-us/windows/msix/msix-containerization-overview>,
updated 2026-04-15):

| Location | AppContainer app | Full-trust packaged app (ours) |
|---|---|---|
| The package's own install files | writes blocked | writes blocked — a package cannot modify itself |
| System locations, e.g. `C:\Windows\` | **writes blocked** | **not blocked by the container** |
| User profile, `AppData`, `HKCU` | writes redirected to a per-app location | pass through |
| `HKLM\Software` | reads merged with the package's hive; writing a key the package ships is not allowed | allowed, subject to the account's own permissions |

Two consequences, and they let this section be more precise than "unmeasured":

1. **The hosts file is a system-location write**, and the rule that blocks those is
   scoped to AppContainer apps. Our helper is a full-trust LocalSystem service, so
   nothing in the documented model redirects or blocks
   `C:\Windows\System32\drivers\etc\hosts`. The documentation is no longer the risk;
   only the empirical test is left.
2. **The write virtualization that remains governs `HKCU` and `AppData`.** The
   flexible-virtualization feature exists to *exclude* locations from it, and the
   documentation limits what can be excluded to exactly those two ("You can declare
   only file system locations that are within `%USERPROFILE%\AppData`" / "only
   Registry locations that are within **HKCU**",
   <https://learn.microsoft.com/en-us/windows/msix/desktop/flexible-virtualization>,
   read 2026-11-07). Our privileged work happens in `HKLM`, in the firewall's own
   service and in the hosts file — none of it inside that scope — so a hardening
   toggle that writes `HKLM\...` through the helper's allowlisted `reg add` is not the
   classic "silently virtualized registry write" trap. It also means a read-back
   **from inside the packaged process proves nothing**, which is the design rule for
   the test below: write inside, read outside.

**What that test is, exactly, and why it needs an administrator.** The two blocked
installs above (0x800B0109 and 0x80073D28) are both administrator problems, so the
measurement is one elevated command block: build the package with the self-signed
identity, trust it machine-wide, `Add-AppxPackage`, confirm the service exists as
`LocalSystem`/`auto` with its binary inside `C:\Program Files\WindowsApps\...`, then
drive one privileged op through the engine's public RPC — `fw.rules.add` with a name
that does not start with `MICS-` (the double-prefix defect in `docs/TODO.md` §7 makes
a rule named `MICS-…` unremovable), and a `hosts.write` of one probe line — and check
the results **from outside the container**: `netsh advfirewall firewall show rule
name=MICS-<probe>` and the real
`C:\Windows\System32\drivers\etc\hosts`. Anything the packaged service writes is also
visible in `%PROGRAMDATA%\MICS\logs\priv.log`, which is written *before* each op runs.
Then remove both, uninstall the package, and delete the test root.

**Why a hand-rolled pipe client would prove nothing:** the helper identifies its
caller (`engine/src/privileged/server.rs` refuses a client it cannot identify), so the
op has to travel the product's own path — UI → engine → `\\.\pipe\mics_helper` — and a
PowerShell script talking to the pipe would be testing its own privileges, not the
container's. In the `None` shape the same test shrinks to one question, because the
privileged write then happens in a native process: can a packaged app reach the
helper's pipe across the container boundary at all.

## 4. Route B — OSSign, which signs our GitHub binaries

OSSign is a certificate programme plus a signing CLI (`OSSIGN`, Go, built on
Relic) and a GitHub Action, `ossign/ossign-action@v1` (read 2026-11-07 from
<https://github.com/OSSign/OSSign>). What its own site says about scope:

> The primary focus of OSSign is to provide code signing for projects and developers
> that volunteer their time and create free software for other users. We are able to
> consider providing signatures for projects of a commercial nature with an open
> source license, but we do have some requirements around this.

The registry that tracks it (verified there 2026-09-07) records the terms as: free
trusted code signing **of release executables under OSSign's certificate**, wired
into the build pipeline, signatures trusted by major operating systems — for the
**project**, not for an individual maintainer, with requirements *OSI-approved
license, project ≥ 6 months, actively developed, public repository*.

MI CS meets three of the four today: GPL-3.0-or-later (OSI-approved), actively
developed, public. The repository was created **2026-10-27**, so the age condition
is met around **2027-04-27** — unless they waive it. As of September 2026 the site
said new applications were suspended while a backlog was worked through.

The attractive part is how it signs: the CLI's token types are a local certificate,
Azure Key Vault, Azure Artifact Signing, and an **OSSign Server** — described in
their README as keyless, OIDC trusted-publishing in the style of PyPI or npm, where
"the repository needs no secrets at all; a GitHub Actions job only needs
`permissions: id-token: write`". That is a much smaller change than D-034's
PFX/thumbprint secrets, and no private key ever touches this machine or CI.

No "no security tools" clause appeared anywhere in what was read; the stated filter
is *free software for other users*, with commercial-licensed projects considered
case by case.

**What the CLI repository says as of 2026-11-07, and why the date is not only a calendar
question** (read from <https://github.com/OSSign/OSSign>): the roadmap marks PE/COFF, MSI
and PowerShell as signable, with JAR/APK/DMG still open, and its verify command is
documented for PE/COFF, MSI, CAB, **APPX/MSIX** and PowerShell — so the artifacts this
project would hand it (the engine, the app, the MSI) are the ones it was built for. But the
**OSSign Server** path, the one that is free and keyless, is still marked **TBA** for
trusted signing with the GitHub Action, and the documented example uses
`trustedSigningKey: test-certificate` — the tool's own `verify` exits 2 when a file was
signed with an "OSSign Server **test-mode** certificate". So route B needs two things to
line up, not one: this repository to reach six months, **and** OSSign to put the production
server into service. The suspended applications and the TBA marker are consistent with each
other, and neither is under this project's control.

## 5. Route C — a donated certificate

Certum's "Open Source Code Signing" is the only certificate product aimed at an
individual open-source maintainer, and it is **not free**: from **€49** in the
cloud (SimplySign), or **€69** for the card + reader set (registry entry verified
against `shop.certum.eu` on 2026-09-07; a certificate-seller's own 2026-10-22 guide
quotes the same €49). Your name appears behind a fixed "Open Source Developer"
prefix, no company can hold one, and Certum revokes it if it signs commercially
distributed software.

It costs money the project does not have — but it is a **drop-in**, not a project:
`make-release.ps1 -Sign` already reads `MICS_PFX` + `MICS_PFX_PASSWORD`, or
`MICS_CERT_THUMBPRINT` for a certificate in a store (D-034), and SignPath's free
OSS *subscription* is available to a project that **brings its own certificate** —
the "no hacking tools" clause in §6 applies only to certificates *issued by*
SignPath Foundation, not to their free signing service. So a donated certificate is
usable the day it exists, with zero code change.

### The rules a *publicly trusted* certificate now has to follow (CSBR v3.11.0, read 2026-11-07)

Three requirements from the CA/Browser Forum's Code Signing Baseline Requirements —
version **3.11.0, dated 2026-06-16**
(<https://cabforum.org/working-groups/code-signing/requirements/>) — change what
"accept a donated certificate" means, and they are worth knowing *before* one is
offered:

1. **A certificate issued on or after 2026-03-01 is valid for at most 460 days**
   (§6.3.2, ballot CSC-31). A donation is therefore a **~15-month commitment with a
   renewal**, not a one-off.
2. **The subscriber's private key must live in a hardware crypto module**
   (§6.2.7.4.2, in force since 2023-06-01). A publicly trusted certificate can no
   longer arrive as a software `.pfx` at all — which is exactly why Certum sells a
   cloud service and a card+reader set, and why SSL.com sells eSigner.
3. **From 2026-09-15 the certificate must carry exactly one reserved policy OID**
   (ballot CSC-32) — an implementation detail for the CA, but one that means the
   "one certificate, one purpose" reading is now enforced rather than conventional.

**What that changes here, honestly:** D-034's two paths are not equal any more. The
**PFX path is for self-signed and internal certificates only**; a publicly trusted
one must come through `MICS_CERT_THUMBPRINT` — a token, a cloud signing agent, or a
service like OSSign that holds the key itself. That is not a reversal of D-034 (which
still resolves either identity and prints which one it chose), it is the reason the
thumbprint and the keyless route are the ones that matter.

## 6. The closed routes, in their own words

**Every CA's free open-source program is a *website* certificate, not a code-signing
one.** GlobalSign runs the best-known of them — the page is titled *"Free SSL
Certificates for Open Source Projects"*, its requirements include configuring TLS and
passing their SSL Checker, and the certificate it issues is for a site
(<https://www.globalsign.com/en/managed-ssl/ssl-open-source>, read 2026-11-07>).
Certum's equivalent product for code is the paid €49 tier in §5, and no other public
CA in the two independent 2026 surveys read for this document (My-SSL's guide, last
updated 2026-10-22, and comparecheapssl.com's, updated 2026) offers a free
code-signing certificate to open source. Both say so plainly: the free CA-issued
code-signing certificate does not exist, which is the same conclusion this repository
reached from the other direction — by asking *who else can sign for us* (D-036) —
after SignPath's own clause closed the only free code-signing service, below.

**SignPath Foundation** (terms page marked "Draft", read 2026-11-07,
<https://signpath.org/terms>) — this is the clause that closes it, and it describes
our audit screen almost word for word:

> Software must not include features designed to identify or exploit security
> vulnerabilities or circumvent security measures of their execution environment.
> This includes **security diagnosis tools that actively scan for and highlight
> exploitable vulnerabilities, e.g. by identifying unprotected network ports,
> missing password protection** etc.
>
> This clause does not prohibit:
> - features that detect *actual* security breaches, e.g. traces of being hacked,
>   presence of malware or potentially unwanted programs
> - scanning software artifacts during development or testing
>
> We are aware of the utility of white hat security tools, but **cannot sign them**
> using SignPath Foundation certificates at this time.

MI CS is both halves at once: the breach-detection half (scanner, canary, guard,
IDS, quarantine) is explicitly allowed, and the posture-audit half is explicitly
named as excluded. Their signed-projects list confirms the line they draw — it
includes **Fibratus**, a Windows EDR with a kernel driver, and **sniffnet**, a
network monitor: detecting attacks and watching traffic are fine, auditing a machine
for weaknesses is not.

Their terms also require, for a certificate they issue, that the project be
"already released in the form that should be signed", that they can verify "a
certain verifiable reputation" (their wording: they cannot sign "binaries based on
source code that nobody knows"), MFA for every team member, and a published code
signing policy using their exact phrasing. Those are preparable; the code of conduct
is not.

**Azure Artifact Signing** — Microsoft's own prerequisite block (read 2026-11-07,
<https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart>):

> Public Trust certificates are available to organizations in the United States,
> Canada, the European Union, the United Kingdom, Australia, New Zealand, Japan,
> South Korea, Singapore, Switzerland, Norway, and Israel. Individual developers
> must be located in the United States or Canada.

**Egypt is on neither list**, and the service is billed anyway (~$9.99/month), so it
is closed on eligibility and on money at the same time.

## 7. What this changes here

1. **ب5 in `docs/ROADMAP.md` stops being "buy a certificate or do without".** The
   row becomes two free routes with concrete dates and one product decision.
2. **The Store route's artifact is built (D-037)**: `installer/msix/AppxManifest.xml`
   plus `scripts/make-msix.ps1` pack and sign an MSIX from the portable build, with the
   numbers in §3. What is left on this route is a free developer account and Microsoft's
   answers to the two open unknowns; the install measurement that used to need an
   administrator no longer does, because the shape submitted first declares no service
   (the A/B in §3, decided in D-038).
3. **The OSSign route needs a calendar**, not code: eligibility ~2027-04-27.
4. **Until either lands, nothing in the honesty story changes**: the release page
   says the binaries are self-signed, `SHA256SUMS` is published, the engine re-hashes
   its own manifest at start-up, and F-11 (reproducible builds) is the load-bearing
   substitute — and it landed 2026-11-08, so a reader can now rebuild the published
   bytes and compare them (`scripts\verify-reproducible.ps1`, `docs\REPRODUCIBLE.md`).
   What changes is that "no certificate can ever exist" is no longer the
   truth, so no document may say it.

## 8. Sources, all read 2026-11-07

| What | Where |
|---|---|
| Store signing is free, worldwide, no SmartScreen warnings; MSI/EXE path needs a CA certificate | <https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options> |
| Free individual registration, ID + selfie, ~200 markets, $19 waived | <https://learn.microsoft.com/en-us/windows/apps/publish/whats-new-individual-developer> |
| Store policies 7.20 (uninstall, consent, privacy policy, age rating, individual accounts, 2.37-day certification) | <https://learn.microsoft.com/en-us/windows/apps/publish/store-policies> |
| A packaged service may run as localSystem with StartupType=auto | <https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop6-service> |
| Public Trust geography excludes Egypt | <https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart> |
| SignPath's code of conduct, verbatim | <https://signpath.org/terms> |
| SignPath's signed projects (Fibratus, sniffnet …) | <https://signpath.org/projects> |
| OSSign scope and keyless OIDC signing | <https://ossign.org/> and <https://github.com/OSSign/OSSign> (CLI README re-read 2026-11-07: server path TBA, test-mode certificate) |
| OSSign terms as tracked (≥ 6 months, project-level, applications paused) | <https://foropensource.com/company/ossign/> |
| Certum Open Source is €49/€69, not free | <https://foropensource.com/company/certum/> and <https://shop.certum.eu/open-source-code-signing.html> |
| The three-route comparison, including Sigstore's uselessness on Windows | <https://my-ssl.com/learn/open-source-code-signing-certificate> (published 2026-07-23, last updated 2026-10-22) |
| A second, independent 2026 survey reaching the same conclusion: no public CA issues a free code-signing certificate | <https://comparecheapssl.com/free-code-signing-certificate-and-how-to-get-it/> |
| A publicly trusted code-signing certificate is now ≤ **460 days** and its key must be in hardware (CSBR v3.11.0, 2026-06-16: §6.3.2, §6.2.7.4.2, ballots CSC-31/CSC-32) | <https://cabforum.org/working-groups/code-signing/requirements/> |
| GlobalSign's free open-source programme is **SSL**, not code signing | <https://www.globalsign.com/en/managed-ssl/ssl-open-source> |
| What the MSIX container virtualizes, per trust level; system-location writes are blocked only for AppContainer apps | <https://learn.microsoft.com/en-us/windows/msix/msix-containerization-overview> (updated 2026-04-15) |
| Full-trust packaged apps: install location, file system, registry, uninstall; `uap10:RuntimeBehavior` and `uap10:TrustLevel` | <https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes> (updated 2026-09-30) |
| Flexible virtualization — and that only `%USERPROFILE%\AppData` and `HKCU` can be excluded from it | <https://learn.microsoft.com/en-us/windows/msix/desktop/flexible-virtualization> |
| Microsoft's own answer that a packaged service runs inside the container, and that installing one requires admin approval | <https://techcommunity.microsoft.com/discussion/3657086/using-msix-to-install-a-windows-service> |
