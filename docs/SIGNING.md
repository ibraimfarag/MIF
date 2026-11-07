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
- **So unknown 2 stays unmeasured, for a reason that is now precise:** it needs a
  *trusted* package installed *by an administrator* — which arrives either from the
  Store after certification, or from an administrator installing our self-signed test
  package on a machine that trusts our root. Until then, nobody may claim the
  container keeps `hosts` and firewall access.
- **Two measured facts that are easy to get wrong.** `Get-AuthenticodeSignature`
  reports `UnknownError` for a *correctly signed* MSIX — the AppX signature is not a
  PE Authenticode signature, so signtool and the deployment API are the tools that
  read it. And adding a certificate to `CurrentUser\Root`: `certutil -user -addstore
  -f Root <file.cer>` completes silently, while the .NET `X509Store` path raises the
  modal **"Security Warning"** that hangs an unattended run (§8 traps 29 and 30 in
  `docs/TODO.md`).

**What is not verified, and must be measured before anyone promises this route
works:**

1. that Microsoft approves `packagedServices` + `localSystemServices` for a
   defensive security tool — **the local half is closed** (makeappx accepts the
   declaration, and Windows requires an administrator for it: 0x80073D28, measured
   below); Microsoft's per-app approval is the half nobody here can measure;
2. that a service inside the MSIX container can still write the real
   `C:\Windows\System32\drivers\etc\hosts` and drive the Windows Firewall COM API
   and `netsh` — container redirection is the risk, and our whole privileged op set
   (firewall/hosts/hardening) rides on it;
3. that a Store listing for a tool whose job is changing firewall and hosts
   settings passes certification at all.

The honest fallback if (2) fails is a **read-only Store edition** (scan, canary,
guard, IDS reporting — no privileged writes) signed by Microsoft for free, with the
full product staying on GitHub. If (1) fails and (2) has not been tested, this route
closes and OSSign becomes the plan.

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

## 6. The closed routes, in their own words

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
   numbers in §3. What is left on this route is a free developer account, an
   **administrator** for the install measurement (Windows requires one for any packaged
   service: 0x80073D28, measured), and Microsoft's answers to the two open unknowns.
3. **The OSSign route needs a calendar**, not code: eligibility ~2027-04-27.
4. **Until either lands, nothing in the honesty story changes**: the release page
   says the binaries are self-signed, `SHA256SUMS` is published, the engine re-hashes
   its own manifest at start-up, and F-11 (reproducible builds) is the load-bearing
   substitute. What changes is that "no certificate can ever exist" is no longer the
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
| OSSign scope and keyless OIDC signing | <https://ossign.org/> and <https://github.com/OSSign/OSSign> |
| OSSign terms as tracked (≥ 6 months, project-level, applications paused) | <https://foropensource.com/company/ossign/> |
| Certum Open Source is €49/€69, not free | <https://foropensource.com/company/certum/> and <https://shop.certum.eu/open-source-code-signing.html> |
| The three-route comparison, including Sigstore's uselessness on Windows | <https://my-ssl.com/learn/open-source-code-signing-certificate> |
