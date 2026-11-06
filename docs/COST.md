# What MI CS costs — and what it deliberately does not

Written 2026-10-31 as step **ب1b**. The register's row 18 asks to "cheapen the
project + licenses"; this file answers the money half of that once, so no later
session has to re-decide it. Facts here are either measured in this repository or
carry the source they came from; where a figure is a moving target (CA list
prices, cloud-signing eligibility) the file says so instead of guessing, because a
stale price is worse than a pointer.

**2026-11-06:** the purchase section was re-researched against live vendor pages
and Microsoft's own comparison, so it now carries list prices, the publisher name
each route actually prints, and the two rules that changed since this file was
written (a code-signing certificate is now capped at 460 days, and EV stopped
buying a SmartScreen bypass in 2024). Every figure names its source and the day it
was read; re-read the source before spending.

**In one line:** running and shipping MI CS costs **nothing** today, and exactly
**one** thing has to be bought to hand it to strangers — a code-signing
certificate. Everything else in the pipeline is free software, a free service, or
a design decision that also happens to remove a bill.

## 1. What this project pays today: nothing

| Thing | What it costs | Where it stands |
|---|---|---|
| Language/toolchains | free (Flutter, Rust/`cargo`, Dart, PowerShell 5.1) | README "Building from source" |
| Installer/packaging | free (NSIS for the installer step ب3; `Compress-Archive` today) | `scripts/make-release.ps1` |
| Signing locally | free: `make-release.ps1 -Sign` creates a certificate, trusts it in `CurrentUser\Root` + `TrustedPublisher` and signs with `scripts\sign.ps1` — no purchase, no admin | README troubleshooting row, `docs/TODO.md` |
| Timestamping | free RFC 3161 (`http://timestamp.digicert.com`) — already used for every signed build, so published files keep verifying after the certificate expires | `scripts\sign.ps1` |
| Detections | ours: 6 guard rules + 10 YARA rules written here, hot-reloadable; no per-seat rule subscription | `engine/rules/`, PROTECTION-MATRIX §2 |
| Real-time protection | the user's own Windows Defender — MI CS audits it and shouts when it is off, rather than reselling an engine | PROTECTION-MATRIX §2 |
| Symbol/threat intel | the user's own keys and quotas (NVD, an IOC feed URL) | `docs/THREAT-MODEL.md` §B6 |
| Hosting a download | free static hosting (GitHub Releases is the obvious one) — the update manifest is one signed file next to the release (D-016), so there is no server to run | `docs/THREAT-MODEL.md` §B6 |
| The inventory | `tool\sbom.dart` is written here and needs no service: it reads the lockfiles | D-018, `sbom.cdx.json` |

Two of those are design decisions that are also cost decisions, and they are
worth naming as such:

- **No telemetry, no cloud** (rule 8): there is no backend to pay for and no data
  to be liable for. The only outbound traffic is the documented, user-visible list.
- **The engine owns OS access** and uses what Windows already has (Defender,
  FirewallAPI/`netsh`, `hosts`, ETW, the SCM). The alternative — shipping an AV
  engine or a managed EDR backend — is where this kind of product normally starts
  to cost money per seat.

## 2. The one purchase: a CA-issued code-signing certificate

### Why it is needed at all

Without it a stranger's Windows says **Unknown publisher**, and SmartScreen may
block the download ("Windows protected your PC"). That is not a cosmetic problem:
the release probe prints it today, and the README carries a whole troubleshooting
row for it (`signed : NotSigned - Windows will show 'Unknown publisher'...`).
Self-signing fixes this only on a machine that already trusts *our* certificate,
which is exactly the machine of the person who built it.

### What decides the shape of the purchase

Four constraints, all of them checkable before money changes hands:

1. **The private key must be in hardware.** Under the CA/Browser Forum's code
   signing baseline requirements (effective June 2023) a code-signing key has to
   live in a FIPS 140-2 Level 2 / Common Criteria EAL4+ module: a USB token from
   the CA, or a cloud signing service that holds the key for you.
   **Consequence for this repository:** the `-PfxPath`/`-PfxPassword` path in
   `scripts\sign.ps1` (a `.pfx` file on disk) **cannot** be used with a compliant
   certificate. **A token cannot be exported into a CI secret either**, so on a
   GitHub-hosted runner the realistic route is a cloud signing service — and the
   codebase already speaks that dialect: a service that puts the key into the Windows
   certificate store is signed with `scripts\sign.ps1 -Thumbprint <sha1>` (D-034).
   Certum's own cloud-signing manual documents exactly that call
   (`signtool sign /sha1 "<thumbprint>" /tr http://time.certum.pl /td sha256 /fd sha256`
   against the SimplySign virtual card), so that route needs no new signing mode here.
   SSL.com's eSigner Cloud Key Adapter can do the same thing, but SSL.com's own CI/CD
   compatibility matrix rates that route on GitHub Actions as **self-hosted runner
   only** and points at their `CodeSignTool`, their `sslcom/actions-codesigner` action
   or the CSC API instead — so buying there would mean adding a *second* signing path
   next to `-Thumbprint`, not using it. For Certum the unattended half is the open
   question: a fresh runner has to authenticate SimplySign before it can sign, and that
   recipe has to be read and measured before the release job is handed a certificate.
   - **Azure Artifact Signing is not a route for this project at all.** Microsoft's own
     comparison (`ms.date 2026-04-20`) offers public trust to organizations in the USA,
     Canada, the EU and the UK and to **individual developers in the USA and Canada
     only**, and sends everyone else to an OV certificate. An individual in Egypt cannot
     buy it, so its `signtool ... /dlib <Azure.CodeSigning.Dlib.dll> /dmdf
     <metadata.json>` integration is a named gap that only matters if a US/CA/EU/UK
     legal entity ever stands behind the project.

   (This paragraph used to claim the script "already" signed with `signtool /sha1`. It did
   not — both of its paths used `/f` with a PFX — and nothing exercised the difference
   until D-034 added the mode and `scripts\verify-signing.ps1` measured it.)
2. **The certificate expires and has to be renewed.** A release signed while the
   certificate was valid keeps verifying because every file is timestamped — the
   timestamp is what makes an old download still trustworthy, and it is free.
   Since **2026-03-01** this is not even a choice: CA/B ballot CSC-31 (adopted
   2025-11-17, CSCBR 3.10.0) cut the maximum validity from 39 months to **460
   days**, so a "3-year" product is a re-issue schedule rather than one long-lived
   key. Budget the renewal — and the identity validation that comes with it — once
   a year whichever route is bought.
3. **The publisher name is pinned in code, and it cannot stay as it is** (D-016).
   The update path accepts a signer whose subject is `CN=MI CS Code Signing`, and
   the CA/B code-signing baseline requirements make that string **unissuable**:
   CSCBR §9.2.2 makes `subject:commonName` *required* and says it "MUST contain the
   Subject's legal name as verified under Section 11.1.1 or 11.2.1" — the verified
   name of a person or a registered entity, not a product name. The string exists
   only in the certificate `scripts\codesign-cert.ps1` creates locally.
   **Measured consequence:** `update.rs:128` refuses a payload signed by anyone else
   ("is signed by X, not MI CS Code Signing - refusing to use it") and
   `signature.rs:184` classifies it as `Trust::NotOurs`, so the first properly
   signed release would be **refused by our own updater** and shown as foreign by
   the package self-check. Moving the pin is decision (c) in
   `docs/OPEN-DECISIONS.md` (about an hour: a thumbprint setting plus three tests),
   and it sits **before** the purchase, not after it. The ratchet already says so:
   `signature.rs:406` asserts the CN of `dist\MICS-portable\mics-engine.exe`.
4. **The UAC prompt names the publisher** only with a trusted certificate
   (`docs/PRIVILEGED-OPS.md`): the elevated install shows "MI CS" instead of
   "Unknown publisher" — the D-002 consequence for P1.5.

### The options, and what each one actually unlocks

Microsoft's own comparison is the backbone, because the vendor of the thing being
bought is the one whose SmartScreen decides
([Code signing options for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options),
`ms.date 2026-04-20`, read 2026-11-06):

| Microsoft's row | Cost | Availability | SmartScreen | Store |
|---|---|---|---|---|
| Store, MSIX | free | worldwide | no warnings | yes |
| Store, MSI/EXE (publisher signs) | a certificate | worldwide | no SmartScreen prompts during a Store install | yes |
| Azure Artifact Signing | ~$9.99/month | organizations: USA, Canada, EU, UK; **individuals: USA and Canada only** | reputation builds over time, initial warnings expected | no |
| OV certificate | $150–300/year | worldwide | same as Azure | no |
| EV certificate | $400+/year | worldwide | **same as OV since 2024 — no longer an instant bypass** | no |
| self-signed | free | — | blocks installation for the public | no |
| no signature | free | — | strong SmartScreen block | no |

Two rows close two questions this file used to leave open. **EV buys nothing
here**: the instant-reputation bypass was removed in 2024, so the $400+/year
premium would pay for identity validation nobody sees — the old "verify at
purchase" line is answered, don't. And **Azure Artifact Signing is unavailable**:
Microsoft's own advice to an individual outside the USA/Canada is to use an OV
certificate, which is the same place the availability table lands.

That leaves the OV-class purchase. The routes that actually exist for a solo
maintainer with no registered company, in Egypt, read on **2026-11-06** (list
prices move; the source is named so it can be re-read):

| Route | Price seen | Publisher Windows will show | Why it fits / what it wants |
|---|---|---|---|
| **Certum Open Source Code Signing**, cloud via SimplySign | **€49.00 / year** (the certificate is 1 year; the card+reader set is €69 and a card-only "electronic code" €25) on [Certum's own shop](https://shop.certum.eu/code-signing.html) | **`Open Source Developer <name>`** — Certum's words: the "Open Source Developer" phrase is added to the CN and the Organization field is set to it | the only route that puts the *maintainer's* name in the signature. Individual-only (their words: "issued only for individuals"), must stay non-commercial ("if Certum determines that the certificate is being used to sign software distributed commercially, the certificate will be revoked"), and the certificate may not contain domain names or IP addresses. Wants: an identity check — automatic via IDnow, a registration point, a notarial confirmation, or photos holding the ID — plus a utility bill in the subscriber's name and the public project URL. **Egypt looks fine**: it is in the checkout country list, hardware ships there (€63 net), and Egyptian passports are in IDnow's document list; the only published exclusion is the generic "countries where the law of Poland prohibits doing business". ≤5,000 signatures/month, and Certum caps a certificate at **459 days** from 2026-02-27, so their 2–3 year products are free re-issues. **The catch is CI**: Certum's own manual signs with `signtool /sha1` only while SimplySign Desktop holds a logged-in virtual-card session (the login needs a token minted by their phone app); Certum publishes no headless signing agent — their web API is partner-only and SSL-scoped, and CertManager is a lifecycle dashboard — so a GitHub-hosted runner cannot sign unattended with this product |
| **SSL.com IV + eSigner** | **$129/year** (IV) + **$180/year** (eSigner Tier 1, 240 signings) ≈ **$309/year** ([IV](https://www.ssl.com/products/software-integrity/code-signing/iv/), [eSigner pricing](https://www.ssl.com/guide/esigner-pricing-for-code-signing/)) | the individual's verified personal name | "no business registration required" is their own line, and their CP/CPS bars only US-denied entities, so Egypt appears eligible (a "High Risk Region" clause is the one open question). Multi-year terms are re-issues: SSL.com enforces a 458-day maximum. **CI is where this route wins**: they document cloud signing for GitHub-hosted runners through their `sslcom/actions-codesigner` action, `CodeSignTool` or the CSC API — their plain-`signtool` CKA route is the one they list as self-hosted-only |
| **SSL.com EV Sole Proprietor** + EV eSigner | $359/year + $900/year ≈ $1,259/year | the verified personal name, EV-level | their product page says "no business entity required", but their own EV rules and the sole-proprietor form want a *registered* sole proprietorship plus two income/identity documents verified face to face — likely blocked for a non-US individual with no entity. **And EV buys nothing now** (see the Microsoft table above) |
| **Any standard OV certificate** (Certum, SSL.com, DigiCert, Sectigo) | $99–300/year — a reseller and Microsoft's band agree; Certum's own individual OV is **€209/year** in their cloud or **€149** as an electronic-code SKU | the verified legal name | worldwide, and some CAs (Certum, SSL.com) validate individuals rather than only companies. Certum's CPS goes further and bars natural persons from **EV** entirely, so their OV individual is the ceiling |
| **SignPath Foundation** | free | **SignPath Foundation** — verified on a project they signed: `CN=SignPath Foundation, O=SignPath Foundation, L=Lewes, S=Delaware, C=US`, an OV certificate from GlobalSign | **effectively closed to MI CS**, for two independent reasons. Their code of conduct's "No hacking tools" clause says: *"Software must not include features designed to identify or exploit security vulnerabilities or circumvent security measures of their execution environment. This includes security diagnosis tools that actively scan for and highlight exploitable vulnerabilities, e.g. by identifying unprotected network ports, missing password protection etc."* The carve-out is only for *detecting breaches* (malware, traces of being hacked, PUP), which is the guard half of this product and not the audit half. Separately, the project must be "already released" with a verifiable reputation, and this repository has **0 releases** and was created 2026-10-27. Even if accepted: manual approval for every release, MFA for the whole team, GitHub-hosted runners only, and the foundation may revoke at its sole discretion with no arbitration |
| **Microsoft Store (MSIX)** | free | Microsoft | worldwide, Microsoft re-signs and validates the developer identity for free — but distribution is through the Store, and our shape is a portable folder plus a `LocalSystem` helper installed with one prompt |

**The headline is that the free route is not available to this product.** Two
signed projects show the clause is applied by framing rather than by capability —
NETworkManager (GPL-3.0, with a port scanner) and Fibratus (a YARA memory scanner)
are both signed by the foundation — but the honest reading of the clause is that a
tool whose own description is "audit this machine and tell the user what is
misconfigured" is what it excludes. **Reframing the product to slip past that
policy is not on the table**; what is on the table is paying €49–309 a year, or the
Store.

**Not on the list, and why:** a `.pfx` carried around (constraint 1); Azure
(constraint 1's eligibility paragraph); a USB token for CI, because a token cannot
be exported into a runner's secret store — it can only sign on the machine it is
plugged into; and the other free programmes that exist (OSSign is suspended and
excludes "offensive security" tools outright; Necessary Code Signing would put
another company's name on the release and its site did not answer).

### What this leaves to decide

- **Cheap but not CI-native, or CI-native but dearer.** Certum's €49/year Open Source
  certificate prints the maintainer's name and is the only route whose signing call is
  already in `scripts\sign.ps1`, but it signs only while a GUI agent holds a logged-in
  session: it needs a persistent/self-hosted Windows runner (on a public repository that
  is a real security decision, and the reasoning would have to be written down) or a
  signature produced on the maintainer's machine before publishing, which weakens the
  provenance story. SSL.com's ~$309/year combination signs on GitHub-hosted runners
  through their own action or CLI, i.e. inside the workflow that exists today. **The
  price difference is the smaller half of this decision** — and it is the one question
  that can be answered without a live certificate, by reading their two CI pages.
- **Which CN comes back, and is the pin moved first?** Constraint 3: it will not be
  `MI CS Code Signing` — Certum fixes the CN to "Open Source Developer <name>" (OSS) or
  "the name and surname of the subscriber" (OV individual), and SSL.com does the same —
  so decision (c) has to land in the same release as the certificate or the app refuses
  its own update.
- **Does Certum accept an Egyptian applicant?** The evidence is positive rather than
  conclusive: Egypt is in the checkout country list, their shipping table delivers
  hardware there for €63 net, and Egyptian passports are in IDnow's supported-document
  list, while the only published exclusion is the generic "countries where the law of
  Poland prohibits doing business". Nobody has placed an order, so this stays
  unconfirmed until someone does.

## 3. What is deliberately not bought

- **No telemetry or analytics backend** (rule 8) — nothing to host, nothing to
  buy, nothing to leak.
- **No per-seat AV engine or managed EDR service** — Windows Defender is the
  real-time layer, and MI CS audits it instead of reselling it.
- **No cloud sandbox / multi-engine file scanning** — there is no VirusTotal
  client and no key to enter (D-019): file reputation is local (the IOC sha256
  cache your own feed fills, plus YARA).
- **No paid rule feed** — the shipped packs are ours and are hot-reloadable, so
  buying better content later is a content decision, not a licence one.
- **No update server and no CDN** — one signed manifest and the release assets.
- **No certificate for the SBOM, the notices or the QA harness** — they are
  generated and checked locally (D-018, `tool\sbom.dart`).

## 4. What not buying costs

- **For users:** "Unknown publisher" in the UAC prompt, and possibly a SmartScreen
  block on first run — the README documents both, and `verify-release.ps1` prints
  the signature state of the artifact it just checked.
- **For the project:** the honest alternative is "build it yourself", which means
  a Rust toolchain, Flutter 3.47.8 and NSIS on the user's machine. That is a
  legitimate answer for a GPL-3.0 tool, and it is the answer today.
- **And buying does not switch SmartScreen off.** Microsoft marks OV exactly like
  Azure — "reputation builds over time; initial warnings expected" — so what the
  purchase really buys is a named publisher and the *start* of a reputation that
  accrues as people download. The EV row that used to promise an instant bypass was
  retired in 2024. Anyone selling this internally as "the warnings go away on day
  one" is describing the pre-2024 behaviour.

## 5. When the certificate arrives (the ب5 checklist)

The code stopped waiting for it on **2026-11-06 (D-034)**: a release reads its signing
identity from the environment, so the day a certificate exists the change is **two
repository secrets** (`MICS_PFX` + `MICS_PFX_PASSWORD`, or `MICS_CERT_THUMBPRINT`) with no
code edit. What is left is confirming the identity and writing the purchase down.

1. **Done (D-034).** `scripts\sign.ps1` selects the identity with `-SelfSigned`,
   `-PfxPath`/`-PfxPassword`, or `-Thumbprint <sha1>` — the last is what a hardware token
   or a cloud signing service's agent needs, because the key never leaves the device. It
   refuses zero identities or two, and the two production modes accept only a signature
   Windows calls `Valid`. `scripts\verify-signing.ps1` (18 checks) measures that refusal.
2. **Done (D-034).** `scripts\make-release.ps1 -Sign` decides the identity in one place
   and prints it before the build: `-Thumbprint`, then `-PfxPath`, then
   `MICS_CERT_THUMBPRINT`, then `MICS_PFX_B64` + `MICS_PFX_PASSWORD`, then
   `MICS_PFX_PATH` + `MICS_PFX_PASSWORD`, and only then the self-signed development
   certificate. The `Release` workflow already passes those two secrets through, and a PFX
   handed in as base64 is written to a temp file, used by `signtool /f`, and deleted before
   the script returns. Timestamping (RFC 3161) is unchanged, so old releases keep
   verifying after the certificate expires. **Do not put the throwaway certificate here**:
   both production modes accept only a `Valid` signature, so a self-signed PFX in
   `MICS_PFX` fails the build instead of publishing a release that only *looks* signed
   (measured 2026-11-06: seven binaries signed, seven refusals, `nothing was published`).
   Note also §2.1: `MICS_PFX_B64`/`MICS_PFX_PATH` are for a PFX that may legally leave its
   key store (an internal/enterprise CA, a legacy certificate, or a test), while a
   CA-issued public certificate has to keep its key in hardware — so the variable a bought
   certificate will actually use is usually **`MICS_CERT_THUMBPRINT`** (a cloud agent or a
   token on the runner), or the Azure `/dlib` work named in §2.1 — which eligibility, not
   effort, keeps out of reach for an individual in Egypt.
3. **Move the pin before that release, not after.** No publicly trusted CA can issue
   `CN=MI CS Code Signing` (constraint 3), so the string `EXPECTED_SIGNER_CN`
   (`signature.rs:42`) compares against stops matching the moment the certificate is real,
   and `update.rs:128` would then refuse our own update. Decision (c) — a thumbprint
   setting, about an hour — belongs in the **same release** as the certificate;
   `signature.rs:406` fails loudly until it is done. The brief with the cost of each answer
   is `docs/OPEN-DECISIONS.md` item 3.
4. **Check the release gate with a real signature.** `scripts\verify-release.ps1` asserts
   the artifact is signed and prints the signer; a CA-issued signature should pass it
   unchanged, and the expected subject is updated if the CN differs.
5. **Write the publisher down.** Replace the honest "not signed by a publicly trusted
   publisher" lines (the release notes, the README, §1 of this file) with the real
   publisher, and add the purchase date and figure to §2.

