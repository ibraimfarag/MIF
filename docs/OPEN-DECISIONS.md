# The open decisions, one page each

These are the six answers that stop work which is otherwise ready (`docs/TODO.md` §0.2,
item 3) — **three still wait on you**: (c) was settled by D-035 **and implemented ahead of time by
D-051** (the pin is the certificate the engine carries, and the release name is only what a build
with no signature of its own falls back to), and (f) is answered and
implemented by D-049, and both are left in place rather than deleted. Each brief says **what the code does today** - read out of the source or measured,
not remembered - then the options, what each costs, and what I would pick. Nothing here
needs a meeting: answering in one line per item is enough. For example:

```
1: fetch     2: keep starter + more guard rules     3: thumbprint, with ب5 not after it
4: ip feed, measure the ceiling first               5: not yet     6: permissive + English fallback
```

Two of the six are already answered by the code, D-035 settled (c) — and D-051 did it, so the line
above prints today — and D-049 answered and
implemented (f). They are kept here so the list stays
honest rather than getting quietly shorter.

---

## 1. May licensed GeoIP country lists be bundled? - mostly answered already

**What is blocked.** Country-block firewall rules and the GeoIP half of reports stay empty
on a fresh install until somebody places the lists by hand.

**What the code does today.** `ids::geoip` resolves an IP to a country from
`rules\blocklists\<CC>.cidr`, looked up beside the executable first, then `MICS_RULES_DIR`,
then the working directory, then `%PROGRAMDATA%\MICS\blocklists` (`ids/geoip.rs:27`). There
is no database and no download. The register row is open at LOW for one reason: the public
country-list licences are unclear, so nothing ships in the box (D-012, `docs/DECISIONS.md`).

**The options.**
1. **Bundle** a licensed dataset. Costs money and procurement, needs a redistribution
   licence, and the SBOM/notices grow a redistributed dataset.
2. **Stay user-supplied.** Zero cost, and the feature is invisible until someone finds the
   folder.
3. **Fetch at sync time** from the publisher's own endpoint, crediting them in
   `NOTICES`/README. No redistribution: the user's machine downloads what the publisher
   offers, and `sync` already exists to do it (a source is a registry row, an i18n label
   and a row on the Intel screen - D-012's checklist).

**What I would pick.** (3), falling back to (2). Whether a free list may be *bundled* has to
be read on the publisher's own page and quoted before either option is written down; no
memory of a licence is good enough to ship a dataset on.

**Cost.** (3) is roughly half a day: one sync source, attribution, the Intel row, a test
that a present list resolves and an absent one reports `not_configured`. (1) is money plus
whatever the licence review says.

---

## 2. Detection content: the starter pack, or real rules? - measured 2026-11-05

**What is blocked.** Nothing mechanically: the pack is hot-reloadable and the pipeline is
green. What is missing is *content*.

**What the code does today (measured, D-033).** The pack is 6 behavioural guard rules plus
10 YARA rules. Held to files, **8 of the 10 YARA rules fire as intended**; 2 cannot be
proven by a text file at all (EICAR because Defender quarantines the fixture; the tiny-PE
rule because a PE-shaped fixture has to be binary). One of the 8 - `Malicious_Macro_AutoOpen` -
can only see an **uncompressed** container: a real `.docm` deflates its macro strings, and
the probe measured that `AutoOpen`, `CreateObject` and `Shell` are absent from such a file's
bytes. Before 2026-11-05 it could not fire at all (it compared the zip magic against `"KP"`).

**The options.**
1. **Keep the starter pack** and say so. The engine is the product; the audit already tells
   the user that Defender is the real-time layer.
2. **Author more rules here.** The behavioural guard pack (6 rules) costs nothing but
   thought - no licence, no feed - and it is where a Windows machine's real attacks show
   themselves (Office spawning a shell, `schtasks /create`, `reg add ... Run`, an executable
   launched from `%TEMP%`). Five to ten more rules is a day of work and multiplies the
   behavioural half.
3. **Ship a licensed third-party rule set** (e.g. Neo23x0's signature-base is CC BY-NC, so
   not for a product). Needs a licence or a paid feed, and a delivery mechanism.
4. **Parse documents** (OOXML/OLE macro extraction) so the macro rule's promise becomes
   true. A new subsystem, not a rule edit: 2-4 days, plus a decision about how deep.

**What I would pick.** (2) now - it is free, it is measurable with the gate that exists
today, and it moves the number that matters (how many real behaviours are caught). Then (4)
if you want document-borne malware to be in scope at all; (3) only with a licence.

**Cost.** (2) half a day to a day. (4) 2-4 days. (3) money.

---

## 3. The update pin: certificate name, or thumbprint? (D-016) — **settled and implemented ahead of time (D-051, 2026-11-11)**

**Settled, as recommended here: option (3), "both, in order" — and it landed before ب5 rather than
with it.** The pin is now `signature::Pin`: `Thumbprint` when this build has a certificate of its own
— read out of the engine's **own** image as the thumbprint of the certificate inside its Authenticode
blob, or taken from `MICS_UPDATE_SIGNER_THUMBPRINT` (the environment override D-047 added) — and
`Name(EXPECTED_SIGNER_CN)` only for a build with no signature of its own, which reports `pinned:
false` instead of calling the name check a pin. The payload check, the manifest's `judge()` and
`trust()` all compare that one value, and `require_signed_by` (the name-only entry point) is gone.
Two consequences worth stating plainly: a CA-signed release **recognises itself** instead of refusing
itself at the payload check, and a certificate with the very same CN from somebody else is refused.
Nothing here needs an answer from you any more — buying or being donated a certificate is a drop-in
with no code change. Full entry and numbers: **D-051**; the residual that is *not* a pinning gap (the
pin comes out of the file under question, so a re-signed copy pins its own certificate) is in
`docs/THREAT-MODEL.md` F-3. The brief below is kept as the record of what was decided, with its
line numbers as they were on 2026-11-06.

**What is blocked.** Nothing today - updates work. This is about how much a forged or
mismatched signer can get away with.

**What the code does today (read, not assumed).** `signature.rs:42` pins
`EXPECTED_SIGNER_CN = "MI CS Code Signing"`. `require_signed_by` (`signature.rs:144`) first
requires a signature Windows' own chain accepts, then compares the **display name**
case-insensitively. The update path calls it for both binaries in the payload
(`update.rs:128`), and `trust()` classifies a file as `Ours` / `UntrustedRoot` / `NotOurs`
so the package self-check can tell "not ours" from "ours, root not trusted yet" (D-002).
So the pin is: *any* certificate that chains to something this machine trusts **and** whose
subject CN reads "MI CS Code Signing". A CN is a free-text field; a thumbprint is not.

**New since this brief was written (read 2026-11-06), and it changes the calculus.** The CN
cannot be chosen at all: CA/B CSCBR §9.2.2 makes `subject:commonName` required and says it
"MUST contain the Subject's legal name as verified under Section 11.1.1 or 11.2.1". No
publicly trusted CA will issue "MI CS Code Signing" - that string exists only in the
certificate `scripts\codesign-cert.ps1` creates locally. Every real route replaces it with
the verified name of a person or a registered entity (Certum's OSS product even puts a fixed
"Open Source Developer" prefix in front of it). So option 1 stops being "zero work" the day
a certificate is bought: `update.rs:128` would refuse our own signed release, and
`signature.rs:184` with `selfcheck.rs:192` would show it as a foreign signer. Moving the pin
is part of buying the certificate, not a follow-up to it.

**The options.**
1. **Stay on the CN.** Zero work. The chain check still rejects self-signed impostors.
2. **Pin the thumbprint** - the SHA-1/SHA-256 of the one certificate this project signs
   with. Needs the certificate bytes out of the PKCS#7 (`CryptMsgGetParam` with
   `CMSG_CERT_PARAM`) and their hash; `signer_name` today stops at the display name.
3. **Both, in order**: a configured thumbprint when there is one, the CN otherwise, so the
   change lands before ب5 and the day the certificate exists is a settings line, not a code
   change.

**What I would pick.** (3), and it now has to land **in the same release as ب5** instead of
riding along afterwards: with a real certificate the CN never matches again, so the first
properly signed version would be unable to update itself. It is strictly stronger than
today, it cannot break an existing install (no thumbprint configured means today's
behaviour), and it turns "move the pin" into a settings line for whoever buys the
certificate.

**Cost.** About an hour: the CMSG read, a `update_pin_thumbprint` setting (empty by
default), three tests (right thumbprint accepted, wrong thumbprint refused even with the
right CN, empty setting = today's behaviour), and the docs. It is only worth doing *before*
ب5 if you want the answer pre-wired; otherwise it can ride along with ب5.

**What it cost in the end (measured 2026-11-11, D-051).** A day rather than an hour, and the
difference is instructive: there was no `update_pin_thumbprint` setting to add, because D-047 had
already pinned the *manifest* to the certificate over the engine and an environment override — so the
work was not "add a second pin" but "make the one pin hold both identities and make every check use
it", which meant the payload check, the manifest judge and `trust()` in one pass, and deleting the
name-only entry point. No setting was added at all: the certificate the engine carries is the pin,
which is one fewer thing to configure and one fewer thing to leave empty. The environment override
became a validation with an error instead of a silent fallback. Six new engine cases, a clean clippy,
`verify-update.ps1` 45/0/0, and the fast tier green.

---

## 4. IDS: stop at the DNS blocklist, or go past it?

**What is blocked.** Nothing today. The question is what "IDS" means in the product.

**What the code does today.** The hosts-file IDS writes `0.0.0.0 <domain>` for every domain
in the synced blocklist into a managed section of the hosts file (through the helper, with
a snapshot first - D-007). It is bypassed by anything that does not ask the system resolver:
DoH inside a browser, an IP-only command-and-control address, or a domain nobody listed
(`PROTECTION-MATRIX.md` §3.1). Separately, the **firewall already blocks by IP**: the
country-block path reads `rules\blocklists\<CC>.cidr`, joins the CIDRs into one rule's
`RemoteAddresses`, and applies it through `INetFwPolicy2` (D-028, `firewall/mod.rs:468`).
That code also records, in a comment, that **Windows documents no ceiling for
`RemoteAddresses` and MI CS has never measured what a country-sized list does to the call**
(`firewall/mod.rs:488`).

**The options.**
1. **Stay**: DNS blocklisting only, and keep saying so. Zero risk, zero new coverage.
2. **Extend the IP path to intel feeds** - the same mechanism the country lists already use,
   fed by an IP blocklist from the sync registry instead of a country file. This *blocks*
   (rather than sinkholes) and it covers IP-only traffic, which is the biggest hole in (1).
   Two pieces of work: a feed source, and the `RemoteAddresses` ceiling measurement.
3. **Inline packet inspection** (Suricata/ET-Open). Out of scope by design: it is a
   different product with a driver, a ruleset licence and a CPU budget.

**What I would pick.** (2), but **measure the ceiling first**: it needs the privileged helper
(or an elevated shell), which is the same thing ب5/P1.5 already needs, and it decides how the
list has to be chunked. `verify-firewall.ps1` (23 checks) already proves rule creation and
read-back, so the ceiling test is a straight extension of it.

**Cost.** The ceiling measurement is ~15 minutes once the helper is installed. (2) is 1-2
days including the feed, chunking and tests. (3) is out of scope.

---

## 5. Real-time watching (و2): pay the continuous CPU cost?

**What is blocked.** File-level detection between scans. Today a machine nobody scans has no
hash/YARA coverage at all; Windows Defender is the real-time layer, and the audit says so
loudly when Defender is off.

**What the code does today.** The scheduled scan (`scan_interval_hours`, off by default,
D-027) runs the scanner over `scan_target` every N hours, report-only, and
`scripts\verify-scan-schedule.ps1` proves it starts, finds a planted ransom-note string and
leaves the file in place. The guard's own idle cost is **measured at 0.156-0.521 % of one
core (median 0.417 %)** with the shipped packs loaded and the engine unelevated
(`scripts\measure-guard-cpu.ps1`), so the machine has a known baseline; the cost of a
*watcher* on top of that has **not** been measured, because no watcher exists.

**The options.**
1. **Stay as it is** (schedule + Defender). Zero cost, and the gap is documented.
2. **A bounded USN-journal poll**: read the volume's change journal every N seconds and look
   only at *new* paths, matching extension/location triage, hashing nothing. Cheapest
   mechanism that sees every file event, no per-directory handles, and it can be given a
   hard per-tick budget. Still continuous CPU, and it needs the journal to exist (it does,
   by default, on Windows' system volume) plus a decision about which volumes.
3. **A directory watcher** (`ReadDirectoryChangesW`) on the profile folders only: precise
   events, but it needs a handle per watched tree, misses anything outside them, and buffers
   overflow under load.
4. **A minifilter** (kernel): real enforcement, out of scope by design.

**What I would pick.** (1) for now, and (2) only if you want file coverage between scans to
be a product claim - in which case it must be measured the way the guard was (the same probe
script, four 60 s windows, on this machine) before it ships. (3) is a worse deal than (2)
for the same cost.

**Cost.** (2) is the 6-10 h already estimated, plus an hour of measurement that must be part
of it.

---

## 6. Language tags: how strict? - answered: permissive engine, coherent UI fallback (D-049)

**What is blocked.** Nothing mechanically - `settings.set` works today. This decides what a
tag the product cannot render should do.

**What the code does today (measured 2026-11-05).** The engine accepts any tag that *looks*
like BCP-47: 2-3 lower-case ASCII letters, optionally `-` plus 2-8 alphanumerics - explicitly
**not a closed list**, so a language pack shipping next month needs no engine change
(`settings.rs:622`, and a test pins it: `zh-hant` is accepted, `EN` and `abcd` are refused).
The UI resolves a stored tag by exact code, then by primary subtag (`en-GB` -> `en`), and
anything else becomes **`null`**, which both call sites turn into **Arabic**
(`app_i18n.dart:206`, `:309`). Missing *keys* fall back to **English**, key by key
(`lookup`, `app_i18n.dart:131`). The picker only offers the packs that ship (`ar`, `en`), so
the unresolvable case arrives only from a hand-edited `settings.json` or an external RPC
caller.

**The options.**
1. **Strict engine**: refuse a tag with no shipped pack (a closed list). Simple and honest,
   but it puts the pack list in the engine and makes a new language a release, which is the
   opposite of what the field's comment and test were written for.
2. **Permissive engine, coherent UI fallback**: keep the shape check, and make the UI's
   chain end in English (the language every key already falls back to) instead of Arabic,
   with one line on the Settings screen saying which tag is stored and that no pack exists
   for it. Nothing existing changes for `ar`/`en`/`en-GB`.
3. **Permissive engine, no notice**: the smallest change, but the user sees a different
   language with no explanation.

**What I would pick.** (2). The incoherence is real today: an unresolvable tag renders an
Arabic UI whose missing keys are English, and nobody is told. It is also the only option that
keeps "a pack shipping next month must not need an engine change" true.

**Cost.** About an hour: the fallback chain, two i18n keys, a widget test that a `de` tag
renders English and says so, and the docs. Answer (2) and it can be done without anything
else from you.

**Answered (2) above, and implemented 2026-11-10 (D-049).** The shape check in the engine is
untouched, as the field's own comment and test were written for. The UI's chain
(`AppLang.resolve`) is bundled tag -> bundled pack, absent or empty -> Arabic (the engine's
default), **no pack -> English** (`app_i18n.dart:70`), and it is the same English `lookup`
already fell back to per key (`:147`). `AppSettings` now carries the tag the engine holds
separately from the language it renders (`:171`, `:274`) and writes that tag back rather than
`lang.code` (`:278`), so a hand-edited tag is no longer replaced by the next settings write;
Settings prints one line naming it beside the picker. Six cases pin it - four in
`test/settings_model_test.dart`, one in `test/ui_screens_test.dart`, and the fast tier is green
in the commit that did it.
