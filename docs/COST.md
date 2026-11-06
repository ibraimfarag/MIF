# What MI CS costs — and what it deliberately does not

Written 2026-10-31 as step **ب1b**. The register's row 18 asks to "cheapen the
project + licenses"; this file answers the money half of that once, so no later
session has to re-decide it. Facts here are either measured in this repository or
carry the source they came from; where a figure is a moving target (CA list
prices, cloud-signing eligibility) the file says so instead of guessing, because a
stale price is worse than a pointer.

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
   certificate. The good news is that the other path already exists: the same
   script signs the self-signed certificate with `signtool /sha1 <thumbprint>`,
   which is exactly what a token in the certificate store needs.
2. **The certificate expires and has to be renewed.** A release signed while the
   certificate was valid keeps verifying because every file is timestamped — the
   timestamp is what makes an old download still trustworthy, and it is free.
3. **The publisher name is pinned in code** (D-016): the update path accepts a
   signer whose subject is `CN=MI CS Code Signing`. The name is supplied during
   the CA's identity validation, so either it is entered exactly like that, or a
   new decision entry replaces the pin. A thumbprint pin would be stronger and is
   deliberately not used while the certificate is re-issued locally.
4. **The UAC prompt names the publisher** only with a trusted certificate
   (`docs/PRIVILEGED-OPS.md`): the elevated install shows "MI CS" instead of
   "Unknown publisher" — the D-002 consequence for P1.5.

### The options, and what each one actually unlocks

| Option | Unlocks | Watch out for |
|---|---|---|
| **OV code-signing certificate** (token or cloud) | A named publisher, and SmartScreen reputation that builds as people download | Identity/business validation, an annual renewal, and hardware/key-holder mechanics to live with |
| **EV code-signing certificate** | The same, with the strictest identity validation — and EV has historically been the *shortest* path to SmartScreen trust | Costs more than OV; whether EV still earns reputation faster than OV in Windows' current SmartScreen is a **verify-at-purchase question**, not something this file asserts |
| **Cloud signing service** (e.g. SSL.com eSigner, Azure's signing service) | No token in a drawer: the key stays in an HSM, CI can sign | A monthly/annual subscription on top of the certificate, and eligibility rules. Microsoft's service is **Artifact Signing** as of 2026 (it was renamed from Trusted Signing — <https://azure.microsoft.com/en-us/pricing/details/artifact-signing/>); its public-trust profiles expect a verifiable business history, so an individual project must check eligibility first |
| **Free signing for open-source projects** (e.g. the SignPath Foundation) | Free signing for qualifying OSS projects | Terms and eligibility change; MI CS is GPL-3.0 (D-001), so it is worth asking, and it must be re-checked before relying on it |
| **Microsoft Store** | Microsoft signs and hosts the package; no certificate to buy | The app must be packaged as MSIX and pass Store policy, and Store signing puts *Microsoft* in the signature. Our layout — a portable folder plus a `LocalSystem` helper service installed with one prompt — would have to be repackaged and re-reviewed |

**Prices are deliberately not quoted here.** They are list prices that move,
they are usually bundled with a token or a cloud subscription, and they depend on
the validation type and the entity behind it. The shape is what is fixed — a
recurring subscription plus a hardware or cloud component — and the current figure
comes from the CA. When it is known, add one line with the date to this file.

### Open questions to settle before paying

- Does EV still buy anything over OV in today's SmartScreen? Ask the CA for the
  current statement, and treat "EV skips reputation" as unverified until then.
- Does the entity qualify for a cloud signing service (or for an OSS signing
  programme)? That decides whether the hardware token is even in play.
- Which CN is entered during validation? D-016's pin is a code change either way,
  but knowing it in advance avoids a release that refuses to update itself.

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
3. **Confirm the subject** is exactly `CN=MI CS Code Signing` (D-016 pins that string), or
   record a decision that replaces the name pin with a thumbprint — the brief, with the
   cost of each answer, is `docs/OPEN-DECISIONS.md` item 3.
4. **Check the release gate with a real signature.** `scripts\verify-release.ps1` asserts
   the artifact is signed and prints the signer; a CA-issued signature should pass it
   unchanged, and the expected subject is updated if the CN differs.
5. **Write the publisher down.** Replace the honest "not signed by a publicly trusted
   publisher" lines (the release notes, the README, §1 of this file) with the real
   publisher, and add the purchase date and figure to §2.

