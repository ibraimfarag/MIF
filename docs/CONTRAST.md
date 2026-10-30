# Light-mode contrast — measured, not guessed

**What this is.** The light palette is audited against WCAG 2.2 with numbers, so
"it looks fine" is never the answer and a future change cannot quietly make a
label unreadable. **State: measured (أ2, 25 of 36 pairs failed), then fixed
(أ3, 29 of 29 pass) — and every ratio is a test assertion, so it cannot drift
back.**

* **Method:** the WCAG 2.x relative-luminance formula and
  `(lighter + 0.05) / (darker + 0.05)` in `lib/core/theme/contrast.dart`;
  4.5:1 is applied to text (§1.4.3) and 3:1 to boundaries and icons (§1.4.11).
  A tinted banner is measured as the colour it really is, by compositing the
  tint over its surface (`blendOver`), not by measuring the tint colour itself.
* **Subject:** `AppColors.applyLight()` exactly as it ships, plus everything the
  screens colour through it — the coverage test fails if a palette token appears
  in no measured pair, and a second test fails if `AuditFinding.statusColor` /
  `severityColor` or `cvssColor` return anything that is not a palette token (they
  used to return dark-mode literals, which is how "Secure" green reached 1.78:1).
* **Reproduce it:** `flutter test --no-pub test/light_contrast_audit_test.dart`
  prints the table below. The two snackbar rows are not derived from a reading of
  the framework: that test renders the real `SnackBar` and reads the painted
  colour back out of the render tree.
* **Not in scope:** dark mode (measured? no — see the last section), and
  screenshots (the record here is numeric on purpose).

## Before — measured 2026-10-30, Flutter 3.47.8

**25 of 36 pairs are below their WCAG bar.**

### Text on the two surfaces the UI paints

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| body text on the page | 16.61:1 | 4.5 | PASS | `#0F172A` on `#F4F7FB` |
| body text on a card | 17.85:1 | 4.5 | PASS | `#0F172A` on `#FFFFFF` |
| secondary text on the page | 5.07:1 | 4.5 | PASS | `#5B6B7F` on `#F4F7FB` |
| secondary text on a card | 5.45:1 | 4.5 | PASS | `#5B6B7F` on `#FFFFFF` |
| accent text on the page | 3.43:1 | 4.5 | FAIL | `#0891B2` on `#F4F7FB` |
| accent text on a card | 3.68:1 | 4.5 | FAIL | `#0891B2` on `#FFFFFF` |
| success text on the page | 3.51:1 | 4.5 | FAIL | `#059669` on `#F4F7FB` |
| success text on a card | 3.77:1 | 4.5 | FAIL | `#059669` on `#FFFFFF` |
| danger text on the page | 4.37:1 | 4.5 | FAIL | `#E11D48` on `#F4F7FB` |
| danger text on a card | 4.70:1 | 4.5 | PASS | `#E11D48` on `#FFFFFF` |
| warning text on the page | 3.31:1 | 4.5 | FAIL | `#EA580C` on `#F4F7FB` |
| warning text on a card | 3.56:1 | 4.5 | FAIL | `#EA580C` on `#FFFFFF` |

### Boundaries (§1.4.11)

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| card border on the page | 1.19:1 | 3.0 | FAIL | `#DDE4EE` on `#F4F7FB` |
| card border on a card | 1.28:1 | 3.0 | FAIL | `#DDE4EE` on `#FFFFFF` |

### Foreground on an accent fill

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| filled-button label | 3.43:1 | 4.5 | FAIL | `#F4F7FB` on `#0891B2` |
| declared `onPrimary` | 3.68:1 | 4.5 | FAIL | `#FFFFFF` on `#0891B2` |
| declared `onSecondary` | 3.77:1 | 4.5 | FAIL | `#FFFFFF` on `#059669` |
| declared `onError` | 4.70:1 | 4.5 | PASS | `#FFFFFF` on `#E11D48` |
| error snackbar text | 4.70:1 | 4.5 | PASS | `#FFFFFF` on `#E11D48` |
| success snackbar text | 1.00:1 | 4.5 | FAIL | `#FFFFFF` on `#FFFFFF` |

### Icons and the rail indicator (§1.4.11)

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| selected nav-rail icon | 3.08:1 | 3.0 | PASS | `#0891B2` on `#DAEFF3` |
| unselected nav-rail icon | 5.45:1 | 3.0 | PASS | `#5B6B7F` on `#FFFFFF` |

### Text on the tinted banners

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| body text on the success banner | 16.82:1 | 4.5 | PASS | `#0F172A` on `#F3FAF8` |
| error-banner text | 3.14:1 | 4.5 | FAIL | `#EA580C` on `#FDEDF0` |
| block-action badge text | 3.70:1 | 4.5 | FAIL | `#E11D48` on `#FBDDE4` |
| allow-action badge text | 3.14:1 | 4.5 | FAIL | `#059669` on `#DAEFE9` |

### What those tints compose to

| Composed colour | Cause |
|---|---|
| `#F3FAF8` | `AppColors.green` at 5 % over `#FFFFFF` |
| `#FDEDF0` | `AppColors.red` at 8 % over `#FFFFFF` |
| `#FBDDE4` | `AppColors.red` at 15 % over `#FFFFFF` |
| `#DAEFE9` | `AppColors.green` at 15 % over `#FFFFFF` |

### Status and severity colours that bypass the palette

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| status/severity green on the page | 1.79:1 | 4.5 | FAIL | `#34D399` on `#F4F7FB` |
| status/severity green on a card | 1.92:1 | 4.5 | FAIL | `#34D399` on `#FFFFFF` |
| status/severity orange on the page | 2.11:1 | 4.5 | FAIL | `#FB923C` on `#F4F7FB` |
| status/severity orange on a card | 2.26:1 | 4.5 | FAIL | `#FB923C` on `#FFFFFF` |
| status/severity red on the page | 3.42:1 | 4.5 | FAIL | `#F43F5E` on `#F4F7FB` |
| status/severity red on a card | 3.67:1 | 4.5 | FAIL | `#F43F5E` on `#FFFFFF` |
| status/severity slate on the page | 4.43:1 | 4.5 | FAIL | `#64748B` on `#F4F7FB` |
| status/severity slate on a card | 4.76:1 | 4.5 | PASS | `#64748B` on `#FFFFFF` |
| CVSS 4.0–6.9 yellow on the page | 1.78:1 | 4.5 | FAIL | `#EAB308` on `#F4F7FB` |
| CVSS 4.0–6.9 yellow on a card | 1.92:1 | 4.5 | FAIL | `#EAB308` on `#FFFFFF` |

## What the numbers said

1. **One message was literally invisible.** `intel_screen.dart`'s `_snack` set
   `backgroundColor: AppColors.surface` for the success case but left the text
   colour alone, and Material 3's SnackBar default is
   `contentTextStyle ?? onInverseSurface` (`snack_bar.dart:658`), which resolves
   to white in this theme: **1.00:1, white on white**. The same override was used
   by the error case, where the red background rescued it (4.70:1). Step أ3 took
   the second way out: do not override the background at all.
2. **Card and input borders are decoration, not boundaries.** `#DDE4EE` on
   either surface is 1.19–1.28:1, far under the 3:1 a boundary needs, so every
   card edge and text field outline is effectively invisible.
3. **The four status/accent hues are dark-mode dressings.** As small text
   (10–13 px, which is how the UI uses them) cyan, green and orange land at
   3.31–3.77:1 and miss 4.5:1, though they clear the 3:1 large-text bar. The
   filled button has the same problem from the other side: `#F4F7FB` on
   `#0891B2` is 3.43:1.
4. **The severity colours ignore the palette entirely.** `audit_models.dart`
   returns fixed literals (which happen to equal the *dark* tokens), so in light
   mode "Secure" green is 1.79–1.92:1 and the CVSS 4–7 yellow is 1.78–1.92:1 —
   the two worst text colours in the product after the invisible snackbar.
5. **Tinted banners land on the wrong side of the line.** The `red 8 %` error
   banner (orange text, 3.14:1), the `red 15 %` block badge (3.70:1) and the
   `green 15 %` allow badge (3.14:1) all fail for the 10–12 px text they carry.
6. **What already passes, and why it should stay:** primary and secondary text
   (16.6:1, 17.9:1, 5.07:1, 5.45:1), white on the error red (4.70:1), red text on
   a white card (4.70:1), the success banner's body text (16.82:1) and both rail
   icons against their 3:1 bar (3.08:1, 5.45:1).

## The fix (step أ3)

Five changes, in order of how much they mattered:

1. **`intel_screen.dart` stopped recolouring half a pair.** The success snackbar
   overrode `backgroundColor` to the white surface and left Material's default
   text colour (white in this theme) — so the message was invisible. Only the
   failure case recolours the bar now, and its text keeps Material's
   `onInverseSurface`, which is white and clears 6.29:1 on `AppColors.red`.
2. **`border` became a boundary instead of a hairline.** `#DDE4EE` → `#74849B`,
   the value that clears 3:1 on the page (3.54:1) and on a card (3.81:1). This is
   still lighter than Material 3's own `outline`, so a card edge reads as an
   edge, not as a box.
3. **The accent hues moved to their 700/800 shades in light mode** (cyan
   `#0E7490`, green `#065F46`, red `#BE123C`, orange `#B23A0B`) so the 10–13 px
   text they are actually used for clears 4.5:1 on both surfaces — and, in
   passing, the filled button (`#F4F7FB` on cyan) and every white-on-accent
   foreground as well.
4. **`audit_models.dart` and `cvssColor` now read the palette** instead of
   returning dark-mode literals, and the palette gained the one token they were
   missing: `yellow` (`#B45309` in light mode, `#EAB308` in dark, where the old
   literal was correct). Dark mode is pixel-identical to before: the literals it
   was getting *were* the dark tokens.
5. **The table shrank from 36 rows to 29** because ten literal rows collapsed
   into the two palette rows that now cover the same colours; three rows are new
   (`yellow` on both surfaces, and the `settings_screen` translucent-red bar that
   the first audit had not separated out).

## After — measured 2026-10-31, Flutter 3.47.8

**29 of 29 pairs clear their bar.** Each row is an assertion in
`test/light_contrast_audit_test.dart` now, so the column is a floor, not a
report.

| Pair | Before | After | Bar | Result |
|---|--:|--:|:--:|:--:|
| body text on the page | 16.61:1 | 16.61:1 | 4.5 | PASS |
| body text on a card | 17.85:1 | 17.85:1 | 4.5 | PASS |
| secondary text on the page | 5.07:1 | 5.07:1 | 4.5 | PASS |
| secondary text on a card | 5.45:1 | 5.45:1 | 4.5 | PASS |
| accent text on the page | 3.43:1 | **4.99:1** | 4.5 | PASS |
| accent text on a card | 3.68:1 | **5.36:1** | 4.5 | PASS |
| success text on the page | 3.51:1 | **7.15:1** | 4.5 | PASS |
| success text on a card | 3.77:1 | **7.68:1** | 4.5 | PASS |
| danger text on the page | 4.37:1 | **5.85:1** | 4.5 | PASS |
| danger text on a card | 4.70:1 | **6.29:1** | 4.5 | PASS |
| warning text on the page | 3.31:1 | **5.58:1** | 4.5 | PASS |
| warning text on a card | 3.56:1 | **5.99:1** | 4.5 | PASS |
| medium-severity text on the page | 1.78:1 | **4.67:1** | 4.5 | PASS |
| medium-severity text on a card | 1.92:1 | **5.02:1** | 4.5 | PASS |
| card border on the page | 1.19:1 | **3.54:1** | 3.0 | PASS |
| card border on a card | 1.28:1 | **3.81:1** | 3.0 | PASS |
| filled-button label | 3.43:1 | **4.99:1** | 4.5 | PASS |
| declared `onPrimary` | 3.68:1 | **5.36:1** | 4.5 | PASS |
| declared `onSecondary` | 3.77:1 | **7.68:1** | 4.5 | PASS |
| declared `onError` | 4.70:1 | **6.29:1** | 4.5 | PASS |
| error snackbar text | 4.70:1 | **6.29:1** | 4.5 | PASS |
| success snackbar text | **1.00:1** | **21.00:1** | 4.5 | PASS |
| settings error snackbar text | — | **5.19:1** | 4.5 | PASS |
| selected nav-rail icon | 3.08:1 | **4.35:1** | 3.0 | PASS |
| unselected nav-rail icon | 5.45:1 | 5.45:1 | 3.0 | PASS |
| body text on the success banner | 16.82:1 | 16.52:1 | 4.5 | PASS |
| error-banner text | 3.14:1 | **5.23:1** | 4.5 | PASS |
| block-action badge text | 3.70:1 | **4.84:1** | 4.5 | PASS |
| allow-action badge text | 3.14:1 | **6.04:1** | 4.5 | PASS |

The two rows whose ratio went *down* are not regressions: the banner background
is composited from the tint and the (now darker) accent, so a darker green at
5 % is a slightly darker banner (16.82 → 16.52, still 3.6× the bar).

## What still is not measured

* **Dark mode.** Its borders are `#1E293B` on `#0A0E14` — 1.36:1, i.e. the same
  problem light mode just had, and the same 3:1 bar applies. Deliberately left
  alone here so this step did not change the look of the mode the user runs
  today; it is the next thing to measure, not a claim that it passes.
* **Screenshots.** The record is the ratio table, and a picture cannot be checked
  by a test.
