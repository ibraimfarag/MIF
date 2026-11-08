# Reproducible builds — how a stranger re-derives the published bytes

This document is the recipe behind **F-11** in [`THREAT-MODEL.md`](THREAT-MODEL.md)
and the reason `scripts\verify-reproducible.ps1` exists. It is written for somebody
who has the published `.zip` and this repository, and wants an answer to one
question: *are these bytes the ones this source produces?*

Why it matters here, in one sentence: the project has **no budget** (D-035), the
certificate is not purchased, and the published `SHA256SUMS` and the signature are
*ours* — so the one claim a user can check without trusting us is that the
published files can be rebuilt from the source we publish.

## 1. The recipe

```powershell
git clone https://github.com/ibraimfarag/MIF
cd MIF
git checkout <the revision printed in the package's VERSION, `built ... (source revision ...)`>
powershell -ExecutionPolicy Bypass -File scripts\verify-reproducible.ps1 -Reference <the published .zip>
```

You do **not** need a certificate, but you do need *a* signing identity, and the
tree mints one for you: `verify-reproducible.ps1` rebuilds with
`make-release.ps1 -Reproducible -Sign`, and `-Sign` with no PFX and no thumbprint
means `sign.ps1 -SelfSigned` — a local self-signed `CN=MI CS Code Signing`
certificate, which is how this project produces its own packages (D-035: nothing
is bought). The release path gates the package on the engine carrying that
signer, so the rebuild has to be signed; and a *different* self-signed key is
exactly the situation this check exists for — the code must match, the signature
must not be expected to. That is what the content-hash comparison and the two
explained rows in §3 are for. Pass `-Built <folder>` instead of letting it build
if you already have your own rebuild, and `-NoBuild` to compare two folders you
produced yourself.

The command prints one row per file and exits `0` only when every file is
identical, content-identical, or explained by the documented reasons in §3.
`-Reproducible` is what makes the comparison meaningful: it takes the build time
from the revision rather than the clock, and it **refuses a tree with uncommitted
changes** — a build nobody else can check out is a build nobody else can
reproduce. (It also means the check needs the *published* revision to be a commit
you can check out — which is why the recipe pins one.)

`verify-reproducible.ps1 -SelfTest` checks the primitives this stands on (the
build time, the deterministic ZIP, the unsigned content hash, the row comparison,
the `VERSION` line comparison) against fixtures in seconds, without building
anything or needing an artifact.

## 2. What "reproducible" means here, exactly

Everything the package ships, **except the Authenticode signatures**. That
exception is not a cop-out, it is arithmetic: Authenticode embeds the signing time
and a random RSA value, so two signatures over the same code never match, while
the code does. Every PE file is therefore compared on its **content hash**: the
file with the certificate table, the optional-header `CheckSum` and the security
data directory taken out. A signed copy and an unsigned copy of the same build
share it; change one byte of code and it changes.

| What | How it is compared | Reproducible? |
|---|---|---|
| `data\app.so` (Dart AOT, obfuscated) | SHA-256, exact | yes |
| `data\icudtl.dat`, `data\flutter_assets\**` | SHA-256, exact | yes |
| `rules\**` (YARA + guard pack) | SHA-256, exact | yes |
| `sbom.cdx.json`, `THIRD-PARTY-NOTICES`, `native_assets.json` (when the build stages it — §6) | SHA-256, exact | yes |
| `mics_app.exe`, `flutter_windows.dll`, the five plugin DLLs | content hash | yes |
| `mics-engine.exe` | content hash | **explained, not equal** — §3 |
| `VERSION` | line by line | **explained, not equal** — §3 (it records the engine's hash) |
| the signature blobs themselves | not compared | no, by design |

## 3. The differences the verifier explains instead of requiring

`mics-engine.exe` carries `MICS_MANIFEST`, the document D-025 describes: the size
and SHA-256 of every other shipped file. The manifest is built **after signing**
(`make-release.ps1`, the package-manifest section), so it records the hashes of the
files *as signed*. A rebuild signed with another key — or not signed at all — has
different hashes in that document and therefore different engine bytes, even though
the code is the same.

The verifier accepts that gap only when it can *prove* the difference is the
signature and nothing else: it reads both engines' `MICS_MANIFEST` resources, and
requires the same file list in the same order and equal hashes for every entry that
is not a PE file. The PE entries are already covered by the content hashes above.
If the two documents disagree about anything else, the row fails and prints what
disagreed.

There is exactly one more file in that position, and for the same reason:
`VERSION` writes down the engine's content hash, so when the manifest moves, that
line moves with it. It is accepted only when it is the *only* line that differs —
the version, the build time, the revision and the app's content hash must all
match character for character, and the check compares them line by line rather
than trusting a pattern. Everything else in the package is either byte-identical or
(for the eight signed PEs) identical once the signature is taken out.

That is the honest state of F-11, and it names its own next step: make the manifest
cover **content** instead of signatures, so the engine becomes byte-reproducible
too. That is a change to the engine's self-check as well as the script (the check
would hash the unsigned payload), so it belongs in its own slice with D-025
revisited — it is written down in `TODO.md` §0.6.

## 4. What makes a build reproducible (and what did not)

Four changes, each with the failure it removes:

1. **One timestamp for the whole build** — `SOURCE_DATE_EPOCH`, the
   [reproducible-builds](https://reproducible-builds.org/docs/source-date-epoch/)
   convention. The value is the revision's own committer date, normalised to UTC
   and truncated to an even second (a ZIP entry cannot store an odd one, so VERSION
   and the archive must agree on what is stored). `VERSION` prints it, so a reader
   knows which revision to check out. Before this, `VERSION` contained
   `(Get-Date)` and no two builds of the same source produced the same file.
2. **`/Brepro` on both linkers** — `link.exe` writes the wall clock into the PE
   `TimeDateStamp` header field. The engine gets it from
   `engine\.cargo\config.toml`, the app and the plugin DLLs from
   `windows\CMakeLists.txt` (set before the Profile copy, so Release *and* Profile
   inherit it and the plugin subdirectories inherit it from the directory).
3. **A deterministic ZIP** — `Compress-Archive` stores each file's own
   `LastWriteTime`, so the same tree zipped twice differed. `New-MicsDeterministicZip`
   writes entries in ordinal path order, with forward slashes, no directory
   entries, and one fixed timestamp per entry.
4. **Content hashes in `VERSION`** — in `-Reproducible` mode, `engine` and `app`
   are the unsigned content hashes rather than the hashes of the signed files, so
   `VERSION` no longer depends on *who* signed the build. It still depends on
   *whether* it was signed, because the engine's content contains a manifest of the
   signed files — which is why `VERSION` is the second row the verifier explains
   (§3) and not a row it requires equal.

## 5. What was measured (2026-11-08)

Every number below is from this machine, with the Windows PowerShell above and the
toolchain this section names. Nothing here is inferred from a flag being present.

**The Dart half was already reproducible.** Two `flutter clean` + build cycles of
the same source produced `data\app.so` = `51c2ab76…` both times — the obfuscated
AOT snapshot does not embed a build time.

**The C++ half was not, and `/Brepro` is the whole fix.** Two from-scratch builds
before the change:

| File | build 1 | build 2 |
|---|---|---|
| `mics_app.exe` | `604152af…` | `03bcfac2…` |
| `audioplayers_windows_plugin.dll` | `87d8346a…` | `260eb24b…` |
| `tray_manager_plugin.dll` | `7a872b4c…` | `052ebd4d…` |
| `data\app.so` | `51c2ab76…` | `51c2ab76…` (identical) |

With `/Brepro`, two further from-scratch builds — the whole 63-file output tree of
`build\windows\x64\runner\Release`, not just the binaries — matched **file for
file**: `mics_app.exe` = `4d5cafba…` both times, every plugin DLL identical, and
`data\flutter_assets\**` (the asset manifest, `NOTICES.Z`, the fonts and the i18n
packs) identical too. The `TimeDateStamp` field is now a hash of the output instead
of the second it was linked.

**The engine carried its link time.** The shipped `mics-engine.exe` in
`dist\MICS-portable` had `TimeDateStamp` = `1794050817` = 2026-11-07T11:26:57Z, its
own link time, and two from-scratch release builds of the same source differed
(`e5c1ef1d…` and `118084ae…`, 24,184,832 bytes each) — so rustc, unlike the CMake
half, ships the wall clock unless it is asked not to. `/Brepro` was added to both
target sections of `engine\.cargo\config.toml`, and two further from-scratch builds
(each preceded by `cargo clean`) then produced **one** file:

| Build | SHA-256 | Bytes | Wall time | `TimeDateStamp` |
|---|---|---|---|---|
| C | `6afc16b7...` | 24,184,832 | 742 s | `3544384635` (`0xD343047B`) |
| D | `6afc16b7...` | 24,184,832 | 696 s | `3544384635` (`0xD343047B`) |

The header value is no longer a plausible clock reading, which is the field saying
it came from the output. (These builds differ from the published engine above
because the manifest inside it records unsigned hashes, and because that published
copy was linked before this change.)

**The packaging half is deterministic.** The same 70-file tree zipped twice by
`New-MicsDeterministicZip` produced one hash, `266B627B…`; the published archive
made by `Compress-Archive` stores per-file times (its first entry reads
`2026-11-06T03:09:16`, the mtime of `data\app.so`), which is why it could not.

**The primitives have a self test.** `verify-reproducible.ps1 -SelfTest` — **17**
checks: build-time precedence, two signatures over the same code hashing equal, a
signed and an unsigned copy hashing equal, a changed code byte hashing differently,
a ZIP that is byte-identical across runs and changes when the content does, the
four verdicts of the row comparison, and the three ways `VERSION` is allowed — or
refused — to differ.

**And then the whole check ran.** A reference package was built the way a release
is built — `make-release.ps1 -Reproducible -Sign -Version 0.1.0-repro -Arch x64`,
**295 s**, 69 files, `built 2026-11-08 13:21:16 +00:00 (revision 238da10)`, engine
content hash `9c98b068...`, app content hash `4d5cafba...` (the same value the
`/Brepro` paragraph above measured for `mics_app.exe` on a different build — the
content hash doing what it says) — and `verify-reproducible.ps1 -Reference
dist\MICS-portable-0.1.0-repro-x64.zip` then rebuilt it from the same source,
signed with its own self-signed key, in **239 s**:

```
  identical, byte for byte : 60
  identical, content only  : 7   (the Authenticode blob differs by design)
  explained                : 2
  RESULT: PASS - 60 identical, 7 content-identical, 2 explained, 0 unexpected
```

Sixty of the sixty-nine files came back byte for byte from a rebuild that never saw
the reference; seven were the signed PEs, identical once the signature was taken
out; two were the engine and the `VERSION` line, proved different for the documented
reason and not accepted on faith. Exit code 0.

## 6. The honest limits

* **A rebuild re-signed with another key is indistinguishable to a local check** —
  its own manifest matches its own bytes. That is F-11's remaining residual, and
  the same sentence the README carries: the manifest makes a changed copy
  *visible*, not impossible.
* **Two rows are explained rather than equal** — `mics-engine.exe` and the `VERSION`
  line that records its hash — for the one reason in §3: the manifest inside the
  engine writes down the other files as *signed*. Nothing else in the package is in
  that position.
* **The `v0.1.0` archive in the draft release predates this change** (built
  2026-11-06, without `/Brepro`, so its PE headers carry link times and its `VERSION`
  records hashes of signed files as a normal build does). It is not the artifact to
  compare with: the first archive this check fits is the next one cut from a
  reproducible build. Its binaries do not match on content hash either, because
  their headers carry link times, so a run against it reports real differences —
  which is the correct answer to the question "is this archive reproducible", and
  `false` is the honest one.
* **One packaged file is Flutter's, and depends on the build's cache state.**
  `native_assets.json` is written by the Dart native-assets step; a
  `flutter clean` + build on this machine did not produce it, so the package came
  out **69** files where the published `v0.1.0` archive (built 2026-11-06 on CI,
  no clean) has **70** — measured by comparing the two file lists, which differ in
  that one name and nothing else. The check compares two builds of the same tree,
  so both sides agree; if a future pair disagrees, the difference appears as an
  `added` or `missing` row rather than passing quietly, which is the behaviour this
  file wants — a packaging difference is a real difference.
* **The numbers above are one machine's.** A different rustc, Flutter SDK or MSVC
  toolset compiles different code; reproducibility is *per toolchain*, which is why
  the revision and this document travel together. What was measured here:
  `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `cargo 1.99.1 (5f94df478 2026-08-27)`,
  `Flutter 3.47.8` stable (`737ba8f885`, Dart 3.13.7), MSVC toolset **14.50.35717**
  (Visual Studio 18 Community), CMake **3.29.2**, Windows PowerShell
  **5.1.26100.9818** (CLR 4.0.30319.42000).
* **The Windows build fetches NuGet at configure time** (`audioplayers_windows`
  needs `Microsoft.Windows.ImplementationLibrary`, and CMake looks for `nuget.exe`
  on `PATH`). That is a network dependency inside the build, and the package
  version is whatever that plugin's `packages.config` pins.
* **The ZIP bytes depend on the .NET runtime's Deflate implementation.** Identical
  across runs on one runtime, as measured; two different .NET versions are two
  different compressions. The file *contents* are unaffected, which is what §2
  compares.
* **`-Reproducible` refuses a dirty tree**, so a package can never claim a revision
  it was not built from. Build with uncommitted work if you like — just not with
  `-Reproducible`.
