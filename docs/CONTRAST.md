# Contrast — measured, not guessed

**What this is.** Both palettes are audited against WCAG 2.2 with numbers, so
"it looks fine" is never the answer and a future change cannot quietly make a
label unreadable. **State: light measured (أ2, 25 of 36 pairs failed), then fixed
(أ3, 29 of 29 pass); dark measured (small step 4, 7 of 29 pairs failed), then
fixed (29 of 29 pass) — and every ratio in both modes is a test assertion, so
neither palette can drift back.**

* **Method:** the WCAG 2.x relative-luminance formula and
  `(lighter + 0.05) / (darker + 0.05)` in `lib/core/theme/contrast.dart`;
  4.5:1 is applied to text (§1.4.3) and 3:1 to boundaries and icons (§1.4.11).
  A tinted banner is measured as the colour it really is, by compositing the
  tint over its surface (`blendOver`), not by measuring the tint colour itself.
* **Subject:** `AppColors.applyLight()` and `AppColors.applyDark()` exactly as
  they ship, plus everything the screens colour through them — the coverage test
  fails if a palette token appears in no measured pair, and a second test fails
  if `AuditFinding.statusColor` / `severityColor` or `cvssColor` return anything
  that is not a palette token (they used to return dark-mode literals, which is
  how "Secure" green reached 1.78:1 in light mode). Both audits are built from
  one harness, `test/contrast_audit_harness.dart`, so the two modes cannot drift
  apart in what they measure or in how they report it.
* **Reproduce it:** `flutter test --no-pub test/light_contrast_audit_test.dart`
  and `flutter test --no-pub test/dark_contrast_audit_test.dart` print the tables
  below. The snackbar rows are not derived from a reading of the framework:
  both tests render the real `SnackBar` and read the painted colour back out of
  the render tree.
* **Not in scope:** screenshots (the record here is numeric on purpose).

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

## Dark mode — before, measured 2026-10-31, Flutter 3.47.8

**7 of 29 pairs are below their WCAG bar.** The same 29 pairs the light audit
measures, in the same order, with the dark palette: the border and the secondary
text were too dim for what they paint, and five rows involved a bright accent
used as *text* on a dark surface — the mirror image of the light problem, where
the accents were too light for a white page. In dark mode the **card** is the
binding surface, not the page: it is the lighter of the two.

### Text on the two surfaces the UI paints

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| body text on the page | 15.69:1 | 4.5 | PASS | `#E2E8F0` on `#0A0E14` |
| body text on a card | 14.41:1 | 4.5 | PASS | `#E2E8F0` on `#111826` |
| secondary text on the page | 4.06:1 | 4.5 | FAIL | `#64748B` on `#0A0E14` |
| secondary text on a card | 3.73:1 | 4.5 | FAIL | `#64748B` on `#111826` |
| accent text on the page | 10.70:1 | 4.5 | PASS | `#22D3EE` on `#0A0E14` |
| accent text on a card | 9.83:1 | 4.5 | PASS | `#22D3EE` on `#111826` |
| success text on the page | 10.06:1 | 4.5 | PASS | `#34D399` on `#0A0E14` |
| success text on a card | 9.24:1 | 4.5 | PASS | `#34D399` on `#111826` |
| danger text on the page | 5.27:1 | 4.5 | PASS | `#F43F5E` on `#0A0E14` |
| danger text on a card | 4.84:1 | 4.5 | PASS | `#F43F5E` on `#111826` |
| warning text on the page | 8.55:1 | 4.5 | PASS | `#FB923C` on `#0A0E14` |
| warning text on a card | 7.85:1 | 4.5 | PASS | `#FB923C` on `#111826` |
| medium-severity text on the page | 10.08:1 | 4.5 | PASS | `#EAB308` on `#0A0E14` |
| medium-severity text on a card | 9.26:1 | 4.5 | PASS | `#EAB308` on `#111826` |

### Boundaries (§1.4.11)

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| card border on the page | 1.32:1 | 3.0 | FAIL | `#1E293B` on `#0A0E14` |
| card border on a card | 1.21:1 | 3.0 | FAIL | `#1E293B` on `#111826` |

### Foreground on an accent fill

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| filled-button label | 10.70:1 | 4.5 | PASS | `#0A0E14` on `#22D3EE` |
| declared `onPrimary` | 10.70:1 | 4.5 | PASS | `#0A0E14` on `#22D3EE` |
| declared `onSecondary` | 10.06:1 | 4.5 | PASS | `#0A0E14` on `#34D399` |
| declared `onError` | 3.67:1 | 4.5 | FAIL | `#FFFFFF` on `#F43F5E` |
| error snackbar text | 5.10:1 | 4.5 | PASS | `#121212` on `#F43F5E` |
| success snackbar text | 18.73:1 | 4.5 | PASS | `#121212` on `#FFFFFF` |
| settings error snackbar text | 3.92:1 | 4.5 | FAIL | `#121212` on `#D13853` |

### Icons and the rail indicator (§1.4.11)

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| selected nav-rail icon | 7.24:1 | 3.0 | PASS | `#22D3EE` on `#143444` |
| unselected nav-rail icon | 3.73:1 | 3.0 | PASS | `#64748B` on `#111826` |

### Text on the tinted banners

| Pair | Ratio | Bar | Result | Colours |
|---|---|:--:|:--:|---|
| body text on the success banner | 13.26:1 | 4.5 | PASS | `#E2E8F0` on `#13212C` |
| error-banner text | 7.34:1 | 4.5 | PASS | `#FB923C` on `#231B2A` |
| block-action badge text | 4.19:1 | 4.5 | FAIL | `#F43F5E` on `#331E2E` |
| allow-action badge text | 6.90:1 | 4.5 | PASS | `#34D399` on `#163437` |

### What those tints compose to

| Composed colour | Cause |
|---|---|
| `#13212C` | `AppColors.green` at 5 % over `#111826` |
| `#231B2A` | `AppColors.red` at 8 % over `#111826` |
| `#331E2E` | `AppColors.red` at 15 % over `#111826` |
| `#143444` | `AppColors.cyan` at 15 % over `#111826` (the rail indicator) |

## What the dark numbers said

1. **The border was invisible, exactly as in light mode.** The register row named
   `#1E293B` on `#0A0E14` at 1.36:1; measuring the pair the UI actually paints
   gives 1.32:1 on the page and 1.21:1 on a card — every card edge and input
   outline was effectively absent in the mode the user runs.
2. **Secondary text missed the body-text bar on both surfaces.** `#64748B` is
   4.06:1 on the page and 3.73:1 on the card; at the 10–13 px the UI uses it
   needs 4.5:1. Note which surface binds: in light mode it was the page, in dark
   mode it is the card.
3. **A translucent red bar is dim in dark mode.** `settings_screen.dart` paints
   the error bar as `AppColors.red` at 85 % over the page, and Material paints
   the text with `onInverseSurface`, which is `#121212` in dark mode. Over the
   light page the same translucent red is 5.19:1 with white text; over the dark
   page it composed to `#D13853`, and dark text on it is 3.92:1. The pair is not
   wrong — the red was too dim for the bar to carry text in this mode.
4. **`onError` was white on a bright accent.** `#FFFFFF` on `#F43F5E` is 3.67:1:
   white-on-accent is a light-mode convention. In dark mode the accent fills are
   the bright ones, so their foreground has to be the page colour — which is
   what `onPrimary` and `onSecondary` already did.
5. **The block-action badge was the only tinted pair that failed.** Red text on
   red 15 % over the card (`#331E2E`) is 4.19:1. Brightening red raises the text
   faster than it raises the tint it sits on, so the same change fixes it.
6. **Two screens hard-coded their own foreground.** `guard_screen.dart`
   (Start/Stop Guard) and `hardening_screen.dart` (Fix) painted
   `foregroundColor: Colors.white` over `AppColors.green`/`AppColors.red`: white
   on the dark accents is 1.92:1 on green and 2.99:1 on red. No measured pair
   caught it, because those two pairs come from literals in a screen rather than
   from a palette token — the fix list below names them.
7. **What already passes, and why it should stay:** body text (15.69:1,
   14.41:1), the accent hues as text (8.55:1 to 10.70:1), the error snackbar on
   the solid red (5.10:1), the success snackbar (18.73:1), both rail icons
   against their 3:1 bar (7.24:1, 3.73:1), the success banner's body text
   (13.26:1) and the allow-action badge (6.90:1).

## The fix (small step 4)

Five changes: four in the **dark** palette in `lib/core/theme/app_theme.dart`
(the light palette is not touched by any of them) and one in the two screens
that hard-coded white on an accent fill.

| Token | Before | After | Ratio before | Ratio after |
|---|---|---|---|---|
| `border` | `#1E293B` | `#5C6C80` | 1.32:1 page · 1.21:1 card | **3.60:1 page · 3.31:1 card** |
| `muted` | `#64748B` | `#788AA0` | 4.06:1 page · 3.73:1 card | **5.47:1 page · 5.02:1 card** |
| `red` | `#F43F5E` | `#FB5F7B` | 5.27:1 page · 4.84:1 card · 4.19:1 badge · 3.92:1 85 % bar | **6.47:1 · 5.94:1 · 4.91:1 · 4.76:1** |
| `colorScheme.onError` | `#FFFFFF` | `#0A0E14` (the page colour) | 3.67:1 | **6.47:1** |

1. **`border` became a boundary instead of a hairline.** `#1E293B` → `#5C6C80`,
   the dimmest slate that clears 3:1 on the **card** (the lighter of the two
   surfaces, so the binding one): 3.60:1 on the page and 3.31:1 on a card. The
   card and input edges now read as edges, and the hue stays in the slate family
   the rest of the palette uses instead of washing out to a grey line.
2. **`muted` moved up to where secondary text is legible.** `#64748B` →
   `#788AA0`, the dimmest blue-grey that clears 4.5:1 on both surfaces
   (5.47:1 / 5.02:1), so secondary text stays visibly below body text
   (`#E2E8F0`, 15.69:1) instead of being promoted to it.
3. **`red` is a slightly brighter danger hue.** `#F43F5E` → `#FB5F7B`; it stays
   a saturated red, and the change fixes the two rows where red is used *on a
   red tint* (4.19 → 4.91) and *on the 85 % red bar* (3.92 → 4.76) at the same
   time as it lifts danger text to 6.47:1 / 5.94:1.
4. **`onError` follows `onPrimary`/`onSecondary` in dark mode.** White on the
   bright red is 3.67:1; the page colour on it is 6.47:1. Light mode keeps
   `Colors.white` and its 6.29:1 on `#BE123C`.
5. **Two screens stopped hard-coding `Colors.white` on an accent fill.**
   `guard_screen.dart` and `hardening_screen.dart` now use
   `AppColors.background`, which is the token `filledButtonTheme` already puts on
   a filled button. That is the difference between 1.92:1 and 10.06:1 on green
   and between 2.99:1 and 6.47:1 on red in dark mode; in light mode the label
   went from `#FFFFFF` to `#F4F7FB` on the same fills, 7.68 → 7.15 on green and
   6.29 → 5.85 on red, both still well above the bar.
6. **Nothing else moved.** `background` stays `#0A0E14` (so `AppTheme.isDark`,
   which tests for exactly that value, keeps detecting dark mode), and `surface`,
   `cyan`, `green`, `orange`, `yellow` and `text` are unchanged.

## After — dark, measured 2026-10-31, Flutter 3.47.8

**29 of 29 pairs clear their bar.** Each row is an assertion in
`test/dark_contrast_audit_test.dart` now, so the column is a floor, not a
report.

| Pair | Before | After | Bar | Result |
|---|--:|--:|:--:|:--:|
| body text on the page | 15.69:1 | 15.69:1 | 4.5 | PASS |
| body text on a card | 14.41:1 | 14.41:1 | 4.5 | PASS |
| secondary text on the page | 4.06:1 | **5.47:1** | 4.5 | PASS |
| secondary text on a card | 3.73:1 | **5.02:1** | 4.5 | PASS |
| accent text on the page | 10.70:1 | 10.70:1 | 4.5 | PASS |
| accent text on a card | 9.83:1 | 9.83:1 | 4.5 | PASS |
| success text on the page | 10.06:1 | 10.06:1 | 4.5 | PASS |
| success text on a card | 9.24:1 | 9.24:1 | 4.5 | PASS |
| danger text on the page | 5.27:1 | **6.47:1** | 4.5 | PASS |
| danger text on a card | 4.84:1 | **5.94:1** | 4.5 | PASS |
| warning text on the page | 8.55:1 | 8.55:1 | 4.5 | PASS |
| warning text on a card | 7.85:1 | 7.85:1 | 4.5 | PASS |
| medium-severity text on the page | 10.08:1 | 10.08:1 | 4.5 | PASS |
| medium-severity text on a card | 9.26:1 | 9.26:1 | 4.5 | PASS |
| card border on the page | 1.32:1 | **3.60:1** | 3.0 | PASS |
| card border on a card | 1.21:1 | **3.31:1** | 3.0 | PASS |
| filled-button label | 10.70:1 | 10.70:1 | 4.5 | PASS |
| declared `onPrimary` | 10.70:1 | 10.70:1 | 4.5 | PASS |
| declared `onSecondary` | 10.06:1 | 10.06:1 | 4.5 | PASS |
| declared `onError` | 3.67:1 | **6.47:1** | 4.5 | PASS |
| error snackbar text | 5.10:1 | **6.27:1** | 4.5 | PASS |
| success snackbar text | 18.73:1 | 18.73:1 | 4.5 | PASS |
| settings error snackbar text | 3.92:1 | **4.76:1** | 4.5 | PASS |
| selected nav-rail icon | 7.24:1 | 7.24:1 | 3.0 | PASS |
| unselected nav-rail icon | 3.73:1 | **5.02:1** | 3.0 | PASS |
| body text on the success banner | 13.26:1 | 13.26:1 | 4.5 | PASS |
| error-banner text | 7.34:1 | 7.17:1 | 4.5 | PASS |
| block-action badge text | 4.19:1 | **4.91:1** | 4.5 | PASS |
| allow-action badge text | 6.90:1 | 6.90:1 | 4.5 | PASS |

One row moved *down* without failing: the error banner is composited from the
tint and the (now brighter) red, so the surface it sits on is slightly lighter
(7.34 → 7.17, still 1.6× the bar). The block-action badge moved the other way
(4.19 → 4.91) because its text gained more than the tint underneath it did.

## What still is not measured

* **Screenshots.** The record is the ratio table, and a picture cannot be checked
  by a test.
* **Tints that a single screen composes on its own.** Both audits pin the shared
  pairs (the banners, the badges, the snackbars, the rail) and the coverage test
  proves every palette token appears in one of them; a per-screen tint that mixes
  a token with an alpha no audit knows about would have to be added as a pair
  before it is a claim.
* **Literals a screen paints instead of a palette token.** `Colors.white` over
  `AppColors.green` in `guard_screen.dart` was 1.92:1 in dark mode and no pair in
  either table saw it, because a literal is not a palette token the coverage test
  can look for. The two known cases are fixed; a new one would be found by
  reading the screen, not by running the audit. The brand mark in
  `app_shell.dart` (a white shield on a cyan→green gradient) is deliberately left
  as it is: a logotype is exempt from these bars.
