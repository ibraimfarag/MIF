# Light-mode contrast — measured, not guessed

**What this is.** The light palette is audited against WCAG 2.2 with numbers, so
"it looks fine" is never the answer and a future change cannot quietly make a
label unreadable.

* **Method:** the WCAG 2.x relative-luminance formula and
  `(lighter + 0.05) / (darker + 0.05)` in `lib/core/theme/contrast.dart`;
  4.5:1 is applied to text (§1.4.3) and 3:1 to boundaries and icons (§1.4.11).
  A tinted banner is measured as the colour it really is, by compositing the
  tint over its surface (`blendOver`), not by measuring the tint colour itself.
* **Subject:** `AppColors.applyLight()` exactly as it ships, plus the colours
  that bypass the palette (`AuditFinding.statusColor` / `severityColor` and
  `cvssColor`) — the two coverage tests fail if a palette token or a
  status/severity colour appears in no measured pair, so a new colour cannot be
  added without showing up in this table.
* **Reproduce it:** `flutter test --no-pub test/light_contrast_audit_test.dart`
  prints the table below. The "success snackbar" row is not derived from a
  reading of the framework: that test renders the real `SnackBar` and reads the
  painted colour back out of the render tree.
* **Not in scope:** dark mode (it has not been measured either), and screenshots
  (the record here is numeric on purpose).

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

## What the numbers say

1. **One message is literally invisible.** `intel_screen.dart`'s `_snack` sets
   `backgroundColor: AppColors.surface` for the success case but leaves the text
   colour alone, and Material 3's SnackBar default is
   `contentTextStyle ?? onInverseSurface` (`snack_bar.dart:658`), which resolves
   to white in this theme: **1.00:1, white on white**. The same override is used
   by the error case, where the red background rescues it (4.70:1). The decision
   for the fix belongs to step أ3 — set the text colour with the background, or
   do not override the background.
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

## After

The palette fix is step **أ3**. It appends the re-measured column here and turns
each `PASS`/`FAIL` cell into a test assertion, so the numbers above become the
floor the palette has to clear rather than a one-off report.
