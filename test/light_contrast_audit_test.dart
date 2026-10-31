import 'package:flutter/material.dart';
import 'package:mics_app/core/theme/app_theme.dart';
import 'package:mics_app/core/theme/contrast.dart';

import 'contrast_audit_harness.dart';

/// The light-mode contrast audit (steps أ2 and أ3).
///
/// It measures every colour pair the shipped light UI paints — palette tokens,
/// borders, the accent-button foregrounds, the tinted banners — against WCAG
/// 2.2 (4.5:1 body text, 3:1 large text in §1.4.3, 3:1 UI boundaries and
/// graphics in §1.4.11) and prints the table. Step أ2 took the "before"
/// measurement; step أ3 fixed the palette and turned every ratio into an
/// assertion, so the numbers in `docs/CONTRAST.md` are a floor now instead of a
/// report. The dark twin is `test/dark_contrast_audit_test.dart`, and both use
/// the shared machinery in `test/contrast_audit_harness.dart`.
///
/// Reproduce the numbers with:
///   flutter test --no-pub test/light_contrast_audit_test.dart
void main() {
  // The palette is static and mutable (app_theme.dart), so the mode under audit
  // is pinned before a single colour is read: this file is about light mode.
  AppColors.applyLight();
  final theme = AppTheme.lightTheme;
  final scheme = theme.colorScheme;
  // No snackBarTheme is configured, so a SnackBar keeps Material's own colours
  // (`snack_bar.dart`: background `inverseSurface`, text `onInverseSurface`).
  // A screen that recolours the bar must recolour the text with it — that is the
  // bug light mode had.
  final snackText =
      theme.snackBarTheme.contentTextStyle?.color ?? scheme.onInverseSurface;

  final onPage = AppColors.background;
  final onCard = AppColors.surface;
  final surfaces = <(String, Color)>[
    ('the page', onPage),
    ('a card', onCard),
  ];

  final pairs = <ContrastPair>[];

  // Palette tokens as text, on both surfaces the UI paints them on.
  for (final (what, token, color) in <(String, String, Color)>[
    ('body text', 'AppColors.text', AppColors.text),
    ('secondary text', 'AppColors.muted', AppColors.muted),
    ('accent text', 'AppColors.cyan', AppColors.cyan),
    ('success text', 'AppColors.green', AppColors.green),
    ('danger text', 'AppColors.red', AppColors.red),
    ('warning text', 'AppColors.orange', AppColors.orange),
    ('medium-severity text', 'AppColors.yellow', AppColors.yellow),
  ]) {
    for (final (label, bg) in surfaces) {
      pairs.add(ContrastPair('$what on $label', '$token / app_theme.dart', color,
          bg, bodyTextBar));
    }
  }

  // Boundaries: a card or input edge against what it sits on.
  pairs
    ..add(ContrastPair(
        'card border on the page',
        'AppColors.border / app_theme.dart',
        AppColors.border,
        onPage,
        boundaryBar))
    ..add(ContrastPair(
        'card border on a card',
        'AppColors.border / app_theme.dart',
        AppColors.border,
        onCard,
        boundaryBar));

  // Foreground on an accent fill.
  pairs
    ..add(ContrastPair(
        'filled-button label',
        'filledButtonTheme.foregroundColor on primary / app_theme.dart',
        AppColors.background,
        AppColors.cyan,
        bodyTextBar))
    ..add(ContrastPair('declared onPrimary', 'colorScheme.onPrimary on primary',
        scheme.onPrimary, AppColors.cyan, bodyTextBar))
    ..add(ContrastPair(
        'declared onSecondary',
        'colorScheme.onSecondary on secondary',
        scheme.onSecondary,
        AppColors.green,
        bodyTextBar))
    ..add(ContrastPair('declared onError', 'colorScheme.onError on error',
        scheme.onError, AppColors.red, bodyTextBar))
    ..add(ContrastPair('error snackbar text', 'SnackBar text on AppColors.red',
        snackText, AppColors.red, bodyTextBar))
    ..add(ContrastPair(
        'success snackbar text',
        'SnackBar text on the theme bar (inverseSurface) / intel_screen.dart',
        snackText,
        scheme.inverseSurface,
        bodyTextBar))
    ..add(ContrastPair(
        'settings error snackbar text',
        'SnackBar text on AppColors.red at 85 % / settings_screen.dart',
        snackText,
        blendOver(AppColors.red, 0.85, onPage),
        bodyTextBar));

  // Non-text UI: icons and the rail indicator, which WCAG scores at 3:1.
  pairs
    ..add(ContrastPair(
        'selected nav-rail icon',
        'cyan on indicatorColor (cyan 15 % over surface) / app_theme.dart',
        AppColors.cyan,
        blendOver(AppColors.cyan, 0.15, onCard),
        boundaryBar))
    ..add(ContrastPair('unselected nav-rail icon',
        'navigationRailTheme.unselectedIconTheme', AppColors.muted, onCard,
        boundaryBar));

  // Text on the tinted banners, measured as the filled colour they really are.
  pairs
    ..add(ContrastPair(
        'body text on the success banner',
        'text on green 5 % / incidents_screen.dart',
        AppColors.text,
        blendOver(AppColors.green, 0.05, onCard),
        bodyTextBar))
    ..add(ContrastPair(
        'error-banner text',
        'orange on red 8 % / ids_screen.dart, network_monitor_screen.dart',
        AppColors.orange,
        blendOver(AppColors.red, 0.08, onCard),
        bodyTextBar))
    ..add(ContrastPair(
        'block-action badge text',
        'red on red 15 % / network_monitor_screen.dart',
        AppColors.red,
        blendOver(AppColors.red, 0.15, onCard),
        bodyTextBar))
    ..add(ContrastPair(
        'allow-action badge text',
        'green on green 15 % / network_monitor_screen.dart',
        AppColors.green,
        blendOver(AppColors.green, 0.15, onCard),
        bodyTextBar));

  registerFormulaTest();
  registerPaletteIdentityTest(mode: 'light', expected: const {
    'background': Color(0xFFF4F7FB),
    'surface': Color(0xFFFFFFFF),
    'border': Color(0xFF74849B),
    'cyan': Color(0xFF0E7490),
    'green': Color(0xFF065F46),
    'red': Color(0xFFBE123C),
    'orange': Color(0xFFB23A0B),
    'yellow': Color(0xFFB45309),
    'text': Color(0xFF0F172A),
    'muted': Color(0xFF5B6B7F),
  });
  registerCoverageTest(pairs: pairs, tokens: {
    'background': AppColors.background,
    'surface': AppColors.surface,
    'border': AppColors.border,
    'cyan': AppColors.cyan,
    'green': AppColors.green,
    'red': AppColors.red,
    'orange': AppColors.orange,
    'yellow': AppColors.yellow,
    'text': AppColors.text,
    'muted': AppColors.muted,
  });
  registerStatusColourTest();
  registerSnackbarRowTests(pairs: pairs, theme: theme);
  registerWcagTableTest(subject: 'MI CS light palette', pairs: pairs);
}
